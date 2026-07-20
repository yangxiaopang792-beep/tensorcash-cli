#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Scalar format catalogue end-to-end (CFD_GENERALISATION.md §4/§6, Slice 6).

Exercises the RPC byte-order convention + the over-width / canonicality guard:

  * Publishing under any format takes a NUMERIC display-hex value; the node stores the format's WIRE
    bytes (identity for little-endian, byte-reversed for big-endian) and `scalargetfeed` decodes them
    back to the SAME number — so a user keeps one numeric convention across LE and BE.
  * A value that overflows a fixed-width format is rejected at the publish RPC (EncodeScalarToWire
    fails), so a non-canonical, unsettleable feed can never be created through the supported path.

The consensus-side rejection of a hand-crafted non-canonical publication is covered by the unit test
`asset_tests/check_scalar_publication_rules`; the decode/encode round-trip for every format by
`scalar_cfd_payout_tests`.
"""
import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

SCALAR_CFD_HEIGHT = 160
BOND = 5.1
UNLOCK_SATS = 510000000
RAW_U256_LE, RAW_U256_BE = 0x0001, 0x0002
U64_LE, U64_BE = 0x0010, 0x0011
U128_BE = 0x0013


def num_hex(n):
    return f"{n:064x}"


class ScalarFormatTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0", f"-scalarcfdheight={SCALAR_CFD_HEIGHT}", "-txindex"]]
        self.rid = hashlib.sha256(f"{os.getpid()}_{time.time()}_fmt".encode()).hexdigest()[:16]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def register_oracle(self, w, tag):
        aid = hashlib.sha256(f"{tag}_{self.rid}".encode()).hexdigest()
        ticker = (tag.replace("_", "").upper() + "X")[:8]
        w.registerasset(w.getnewaddress(), BOND, aid, 3, 28, UNLOCK_SATS, ticker, 8,
                        {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(aid) is not None)
        return aid

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("issuer")
        w = node.get_wallet_rpc("issuer")
        self.generatetoaddress(node, 130, w.getnewaddress())
        if node.getblockcount() < SCALAR_CFD_HEIGHT:
            self.generatetoaddress(node, SCALAR_CFD_HEIGHT - node.getblockcount(), w.getnewaddress())

        feed = 1
        # (format, tag, numeric value, expect_wire_reversed)
        cases = [
            (RAW_U256_LE, "raw_le", 0x1234, False),
            (RAW_U256_BE, "raw_be", 0x1234, True),
            (U64_LE, "u64_le", 90, False),
            (U64_BE, "u64_be", 90, True),
            (U128_BE, "u128_be", 0xDEADBEEF, True),
        ]
        for fmt, tag, value, is_be in cases:
            aid = self.register_oracle(w, tag)
            pol = node.getassetpolicy(aid)
            w.scalarpublish_raw(pol["icu_txid"], pol["icu_vout"], aid, w.getnewaddress(), BOND,
                                feed, 1, num_hex(value), fmt,
                                {"autofund": True, "broadcast": True, "fee_rate": 10})
            self.generate(node, 1)
            self.wait_until(lambda: node.scalargetfeed(aid, feed)["last_epoch"] == 1)
            r = node.scalargetfeed(aid, feed, 1)
            assert_equal(int(r["scalar"], 16), value)             # numeric decode round-trips, LE or BE
            assert_equal(r["scalar_format_id"], fmt)
            assert_equal(r["scalar_wire"] != r["scalar"], is_be)  # BE stores reversed wire; LE is identity
            self.log.info("format 0x%04x: numeric %d round-trips (wire %s)", fmt, value,
                          "reversed" if is_be else "identity")

        # Over-width: a value that does not fit a fixed-width format is rejected at the publish RPC,
        # so it can never become a non-canonical (unsettleable) feed.
        aid = self.register_oracle(w, "ovf")
        pol = node.getassetpolicy(aid)
        assert_raises_rpc_error(-8, "exceeds scalar_format_id", w.scalarpublish_raw,
                                pol["icu_txid"], pol["icu_vout"], aid, w.getnewaddress(), BOND,
                                feed, 1, num_hex(1 << 64), U64_BE,
                                {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.log.info("over-width publication rejected at the RPC (U64_BE, value 2^64)")

        self.log.info("scalar format catalogue (LE/BE numeric round-trip + over-width guard) OK")


if __name__ == "__main__":
    ScalarFormatTest(__file__).main()
