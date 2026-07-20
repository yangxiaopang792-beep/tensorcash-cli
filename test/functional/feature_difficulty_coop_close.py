#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Cooperative-close (2-of-2 cosign leaf) test for the difficulty CFD.

Two wallets open a CFD, then COOPERATIVELY close one vault early — spending its 2-of-2 cosign leaf
(`<owner_internal> OP_CHECKSIGVERIFY <cp_internal> OP_CHECKSIG`) to a mutually-agreed split, with NO
maturity/burial wait. Each party adds its half with difficulty.sign_coop (the standard wallet signer cannot
sign a covenant input it does not own); the second sign_coop returns {complete:true, hex}, proving the
2-of-2 fully signed across two wallets, and the agreed outputs must land. The unilateral covenant leaf is
unaffected (it remains the trustless fallback)."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

COIN = 100_000_000
DIFFCFD_MATURITY_DEPTH = 100
LAMBDA_SCALE = 1 << 16
RPC_INVALID_PARAMETER = -8


def compact_from_uint256(value: int) -> int:
    if value <= 0:
        return 0
    size = (value.bit_length() + 7) // 8
    compact = value << (8 * (3 - size)) if size <= 3 else value >> (8 * (size - 3))
    compact &= 0x007fffff
    compact |= size << 24
    return compact


def uint256_from_compact(c: int) -> int:
    nbytes = (c >> 24) & 0xFF
    mant = c & 0x007fffff
    return mant >> (8 * (3 - nbytes)) if nbytes <= 3 else mant << (8 * (nbytes - 3))


def sats(amount_btc) -> int:
    return int(round(Decimal(str(amount_btc)) * COIN))


class DifficultyCoopCloseTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]  # STANDARD relay policy

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice", descriptors=True)
        node.createwallet("bob", descriptors=True)
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")
        self.generatetoaddress(node, 130, alice.getnewaddress())
        self.generatetoaddress(node, 130, bob.getnewaddress())
        alice.rescanblockchain()
        bob.rescanblockchain()

        H = node.getblockcount() - 5
        realized_bits = int(node.getblockheader(node.getblockhash(H))["bits"], 16)
        realized_target = uint256_from_compact(realized_bits)
        strike_nbits = compact_from_uint256(realized_target * 95 // 100)
        im_btc = 10
        settle_lock = H + DIFFCFD_MATURITY_DEPTH

        a_long_owner = alice.getnewaddress("", "bech32m")
        a_short_cp = alice.getnewaddress("", "bech32m")
        b_short_owner = bob.getnewaddress("", "bech32m")
        b_long_cp = bob.getnewaddress("", "bech32m")
        econ = {"strike_nbits": strike_nbits, "fixing_height": H, "settle_lock_height": settle_lock,
                "long": {"im": im_btc, "lambda_q": 10 * LAMBDA_SCALE},
                "short": {"im": im_btc, "lambda_q": 10 * LAMBDA_SCALE}}

        offer = alice.difficulty.propose(econ, "long", a_long_owner, a_short_cp)["offer"]
        accepted = bob.difficulty.accept(offer, b_short_owner, b_long_cp, {"confirmed": True})
        cid = accepted["contract_id"]
        alice.difficulty.import_acceptance(offer, accepted["acceptance"])

        # Atomic co-signed open.
        a_open = alice.difficulty.build_open(cid, "long")
        b_open = bob.difficulty.build_open(cid, "short", {"psbt": a_open["psbt"]})
        a_signed = alice.walletprocesspsbt(b_open["psbt"], True)
        b_signed = bob.walletprocesspsbt(a_signed["psbt"], True)
        final = bob.finalizepsbt(b_signed["psbt"])
        assert_equal(final["complete"], True)
        open_txid = node.sendrawtransaction(final["hex"])
        self.generate(node, 1)
        alice.difficulty.record_open(cid, open_txid)
        bob.difficulty.record_open(cid, open_txid)

        # ---- COOPERATIVE CLOSE of the long vault to an agreed split (no maturity wait) ----
        self.log.info("Cooperative close of the long vault (2-of-2 cosign leaf)")
        coop_a = alice.getnewaddress("", "bech32m")
        coop_b = bob.getnewaddress("", "bech32m")
        agreed = [{"address": coop_a, "amount": 6}, {"address": coop_b, "amount": "3.999"}]
        cc = alice.difficulty.build_coop_close(cid, "long", agreed)
        assert_equal(cc["fee"], Decimal("0.001"))  # 10 vault - (6 + 3.999)
        # Each party adds its half of the 2-of-2 via difficulty.sign_coop; the second party gets the
        # completed transaction (walletprocesspsbt cannot sign a covenant input the wallet does not own).
        a_signed = alice.difficulty.sign_coop(cid, "long", cc["psbt"])
        assert_equal(a_signed["complete"], False)
        ccf = bob.difficulty.sign_coop(cid, "long", a_signed["psbt"])
        assert_equal(ccf["complete"], True)
        node.sendrawtransaction(ccf["hex"])
        self.generate(node, 1)
        alice.rescanblockchain()
        bob.rescanblockchain()
        assert_equal(sats(alice.getreceivedbyaddress(coop_a)), sats(6))
        assert_equal(sats(bob.getreceivedbyaddress(coop_b)), sats("3.999"))

        # A single party alone cannot complete the 2-of-2 (only one signature present).
        cc2 = bob.difficulty.build_coop_close(cid, "short",
                                              [{"address": coop_a, "amount": 6}, {"address": coop_b, "amount": "3.999"}])
        only_bob = bob.difficulty.sign_coop(cid, "short", cc2["psbt"])
        assert_equal(only_bob["complete"], False)
        assert "hex" not in only_bob
        # ...but the unilateral covenant settlement of that (still-unspent) short vault still works after burial.
        deficit = settle_lock - node.getblockcount()
        if deficit > 0:
            self.generatetoaddress(node, deficit, alice.getnewaddress())
        ss = bob.difficulty.build_settlement(cid, "short")
        processed = bob.walletprocesspsbt(ss["psbt"], True)
        node.sendrawtransaction(bob.difficulty.finalize_settlement(processed["psbt"])["hex"])
        self.generate(node, 1)

        self.log.info("Difficulty cooperative close (2-of-2) + unilateral fallback succeeded")


if __name__ == '__main__':
    DifficultyCoopCloseTest(__file__).main()
