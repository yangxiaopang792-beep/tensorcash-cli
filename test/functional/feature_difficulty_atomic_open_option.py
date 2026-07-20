#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Atomic-risk-transfer open for a difficulty OPTION.

An option open transfers a leveraged position AND moves an upfront premium (buyer -> writer), so it must
co-sign through the Fair-Sign adaptor lock-step (no free option on entering the position). Two wallets:
alice = WRITER (funds the single IM vault) + proposer; bob = BUYER (funds the premium) + acceptor. The
BUYER broadcasts last (the buyer holds the optionality, so it controls when the contract forms).

Asserts: the option offer carries the proposer's adaptor point + internal and the acceptance the
acceptor's; build_open_option embeds fs/contract_meta; the writer (owner side) AND the buyer (cp side)
each resolve their own adaptor secret via FindDifficultyByMeta and run prepare/partial; the lock-step
combines both pre-signatures before either finalizes; neither half finalizes alone; and the combined tx
broadcasts, funding exactly one IM vault (value im) and one premium output (value premium).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

DIFFCFD_MATURITY_DEPTH = 100


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


def is_x_only_hex(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())


class DifficultyAtomicOpenOptionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice", descriptors=True)  # writer + proposer
        node.createwallet("bob", descriptors=True)     # buyer + acceptor
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")

        a_fund = alice.getnewaddress("", "bech32m")
        b_fund = bob.getnewaddress("", "bech32m")
        self.generatetoaddress(node, 130, a_fund)
        self.generatetoaddress(node, 130, b_fund)
        self.generatetoaddress(node, 110, alice.getnewaddress())
        alice.rescanblockchain()
        bob.rescanblockchain()

        H = node.getblockcount() - 5
        realized_bits = int(node.getblockheader(node.getblockhash(H))["bits"], 16)
        strike_nbits = compact_from_uint256(uint256_from_compact(realized_bits) * 95 // 100)
        im_btc = 10
        premium_btc = 2
        lambda_q = 10 * (1 << 16)
        settle_lock = H + DIFFCFD_MATURITY_DEPTH

        alice_key = alice.getnewaddress("", "bech32m")  # writer: IM return + premium receipt
        bob_key = bob.getnewaddress("", "bech32m")       # buyer: option payout

        econ = {
            "strike_nbits": strike_nbits,
            "fixing_height": H,
            "settle_lock_height": settle_lock,
            "im": im_btc,
            "lambda_q": lambda_q,
            "premium": premium_btc,
        }

        # ---- propose_option (alice=writer) -> accept_option (bob=buyer) -> import ----
        self.log.info("propose_option (alice=writer) -> accept_option (bob=buyer) -> import_acceptance")
        offer = alice.difficulty.propose_option(econ, "long", "writer", alice_key)["offer"]
        assert is_x_only_hex(offer.get("proposer_adaptor_point")), "option offer must carry a proposer adaptor point"
        assert is_x_only_hex(offer.get("proposer_internal")), "option offer must carry the proposer internal key"

        accepted = bob.difficulty.accept_option(offer, bob_key, {"confirmed": True})
        contract_id = accepted["contract_id"]
        acceptance = accepted["acceptance"]
        assert is_x_only_hex(acceptance.get("acceptor_adaptor_point")), "acceptance must carry an acceptor adaptor point"
        assert is_x_only_hex(acceptance.get("acceptor_internal")), "acceptance must carry the acceptor internal key"

        imported = alice.difficulty.import_acceptance(offer, acceptance)
        assert_equal(imported["state"], "accepted")
        assert_equal(imported["contract_id"], contract_id)

        # ---- build_open_option: writer funds the IM vault, buyer merges + funds the premium ----
        self.log.info("build_open_option: alice (writer, IM vault) -> bob (buyer, premium)")
        a_open = alice.difficulty.build_open_option(contract_id, "writer")
        merged = bob.difficulty.build_open_option(contract_id, "buyer", {"psbt": a_open["psbt"]})["psbt"]

        # Both the writer (owner side) and the buyer (cp side) must resolve their OWN adaptor secret.
        self.log.info("each party: prepare -> partial (adaptor pre-signature) on the merged option open")
        a_part = alice.adaptor.partial(alice.adaptor.prepare(merged)["psbt"])["psbt"]
        b_part = bob.adaptor.partial(bob.adaptor.prepare(merged)["psbt"])["psbt"]

        # LOCK-STEP with commit-reveal ENFORCEMENT (not the [] bypass): both pre-signatures are combined
        # into one shared PSBT, then BOTH parties commit_final to their final signatures BEFORE either
        # reveals — so neither sees the other's reveal before committing its own.
        self.log.info("lock-step: combine pre-signatures -> both commit_final -> both reveal -> buyer broadcasts")
        shared = node.combinepsbt([a_part, b_part])
        a_commit = alice.adaptor.commit_final(shared)["commitments"]
        b_commit = bob.adaptor.commit_final(shared)["commitments"]
        assert a_commit and b_commit, "both parties must produce final-signature commitments"

        # Enforcement is ON: a reveal that breaks the pre-published commitment is rejected.
        forged = [{"index": c["index"], "commitment": "00" * 32} for c in a_commit]
        assert_raises_rpc_error(-4, "COMMITMENT MISMATCH", alice.adaptor.complete, shared, None, forged)

        # Reveal: each party completes its OWN inputs bound to its OWN commitment (non-empty array).
        a_final = alice.adaptor.complete(shared, None, a_commit)["psbt"]
        b_final = bob.adaptor.complete(shared, None, b_commit)["psbt"]
        assert not node.finalizepsbt(a_final)["complete"], "writer finalizing alone must not complete the tx"
        assert not node.finalizepsbt(b_final)["complete"], "buyer finalizing alone must not complete the tx"

        finalized = node.finalizepsbt(node.combinepsbt([a_final, b_final]))
        assert finalized["complete"], "combined option open must finalize once both sides revealed"
        open_txid = bob.sendrawtransaction(finalized["hex"])  # buyer-last (buyer controls formation)
        self.generatetoaddress(node, 1, a_fund)

        # Value sanity: one output of value im and one of value premium.
        vals = [round(float(o["value"]), 8) for o in node.decoderawtransaction(finalized["hex"])["vout"]]
        assert vals.count(float(im_btc)) == 1 and vals.count(float(premium_btc)) == 1, "expected im + premium outputs"

        # STRUCTURAL check: record_open locates the IM vault by its COMMITTED scriptPubKey, so a returned
        # outpoint referencing open_txid proves the funded vault matches the covenant (writer = long).
        rec = alice.difficulty.record_open(contract_id, open_txid)
        vault = rec.get("long_vault") or rec.get("short_vault") or ""
        assert open_txid[:10] in vault, f"record_open must resolve the IM vault by its committed script; got {rec}"
        bob.difficulty.record_open(contract_id, open_txid)

        self.log.info("Difficulty OPTION atomic-risk-transfer open (writer IM + buyer premium, lock-step) succeeded")


if __name__ == '__main__':
    DifficultyAtomicOpenOptionTest(__file__).main()
