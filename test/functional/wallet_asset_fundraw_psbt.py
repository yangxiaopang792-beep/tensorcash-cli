#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

ASSET_ID_A = "aa" * 32
ASSET_ID_B = "bb" * 32


def build_asset_tlv(asset_id_hex: str, units: int) -> str:
    asset_bytes = bytes.fromhex(asset_id_hex)
    assert len(asset_bytes) == 32
    amount = units.to_bytes(8, byteorder="little", signed=False)
    payload = asset_bytes + amount
    return "01" + f"{len(payload):02x}" + payload.hex()


class WalletFundRawAssetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        dest = node.getnewaddress()
        raw = node.createrawtransaction([], {dest: Decimal("1.0")})
        tlv = build_asset_tlv(ASSET_ID_A, 10)
        raw = node.rawtxaddoutext(raw, 0, tlv)

        funded = node.fundrawtransaction(raw)
        decoded = node.decoderawtransaction(funded["hex"])

        def vout_matches(vout, address):
            spk = vout["scriptPubKey"]
            addr = spk.get("address")
            if addr is not None:
                return addr == address
            return address in spk.get("addresses", [])

        target_vout = next(vout for vout in decoded["vout"] if vout_matches(vout, dest))
        assert_equal(target_vout["outext"], tlv)

        other = node.getnewaddress()
        raw_multi = node.createrawtransaction([], {dest: Decimal("0.5"), other: Decimal("0.25")})
        raw_multi = node.rawtxaddoutext(raw_multi, 0, tlv)
        raw_multi = node.rawtxaddoutext(raw_multi, 1, build_asset_tlv(ASSET_ID_B, 5))

        assert_raises_rpc_error(-8, "fundrawtransaction does not yet support multiple asset ids", node.fundrawtransaction, raw_multi)


if __name__ == '__main__':
    WalletFundRawAssetTest(__file__).main()
