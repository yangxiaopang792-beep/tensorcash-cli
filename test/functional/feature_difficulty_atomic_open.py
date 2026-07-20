#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Atomic-risk-transfer open for a difficulty CFD.

The open of a difficulty contract transfers a leveraged directional position, so it must be co-signed
through the Fair-Sign adaptor lock-step (adaptor.prepare/partial/complete) — NOT a plain PSBT splice —
so that neither party gets a "free option" on entering the position (completing last after the
underlying moves). This test drives two distinct wallets (alice = long/proposer, bob = short/acceptor)
through propose -> accept -> import_acceptance -> two-leg build_open and asserts that:

  * the offer carries the proposer's adaptor point and the acceptance the acceptor's;
  * difficulty.build_open embeds fs/contract_meta, so adaptor.prepare can LOCATE the contract;
  * BOTH parties can run adaptor.prepare + adaptor.partial on the merged open PSBT — which only works
    if FindDifficultyByMeta resolves the contract, derives THIS wallet's adaptor secret from the
    internal key behind its own payout, and matches it to the stored point;
  * a wallet that holds NEITHER leg (no contract record) cannot prepare the ceremony;
  * lock-step with commit-reveal ENFORCEMENT: both pre-signatures are combined into one shared PSBT,
    then BOTH parties commit_final to their final signatures before either reveals; complete() is called
    with each party's own (non-empty) commitments, so a reveal that breaks the pre-published commitment
    is rejected (the [] bypass is NOT used); neither half finalizes alone, and only the combined
    transaction broadcasts (funding both IM vaults).
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

COIN = 100_000_000
DIFFCFD_MATURITY_DEPTH = 100
LAMBDA_SCALE = 1 << 16


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


class DifficultyAtomicOpenTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice", descriptors=True)  # long / proposer
        node.createwallet("bob", descriptors=True)     # short / acceptor
        node.createwallet("carol", descriptors=True)   # holds neither leg
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")
        carol = node.get_wallet_rpc("carol")

        # Fund both parties with TAPROOT (bech32m) UTXOs — adaptor.prepare signs taproot key-path inputs,
        # so the funding inputs build_open selects must be taproot.
        alice_fund = alice.getnewaddress("", "bech32m")
        bob_fund = bob.getnewaddress("", "bech32m")
        self.generatetoaddress(node, 130, alice_fund)
        self.generatetoaddress(node, 130, bob_fund)
        self.generatetoaddress(node, 110, carol.getnewaddress())  # extra maturity
        alice.rescanblockchain()
        bob.rescanblockchain()

        # Economics (a canonical strike near the current target).
        H = node.getblockcount() - 5
        realized_bits = int(node.getblockheader(node.getblockhash(H))["bits"], 16)
        strike_target = uint256_from_compact(realized_bits) * 95 // 100
        strike_nbits = compact_from_uint256(strike_target)
        im_btc = 10
        lambda_q = 10 * LAMBDA_SCALE
        settle_lock = H + DIFFCFD_MATURITY_DEPTH

        alice_long_owner = alice.getnewaddress("", "bech32m")
        alice_short_cp = alice.getnewaddress("", "bech32m")
        bob_short_owner = bob.getnewaddress("", "bech32m")
        bob_long_cp = bob.getnewaddress("", "bech32m")

        econ = {
            "strike_nbits": strike_nbits,
            "fixing_height": H,
            "settle_lock_height": settle_lock,
            "long": {"im": im_btc, "lambda_q": lambda_q},
            "short": {"im": im_btc, "lambda_q": lambda_q},
        }

        # ---- propose / accept / import_acceptance, asserting the adaptor points flow ----
        self.log.info("propose (alice) -> accept (bob) -> import_acceptance (alice), carrying adaptor points")
        offer = alice.difficulty.propose(econ, "long", alice_long_owner, alice_short_cp)["offer"]
        assert is_x_only_hex(offer.get("proposer_adaptor_point")), "offer must carry a proposer adaptor point"

        accepted = bob.difficulty.accept(offer, bob_short_owner, bob_long_cp, {"confirmed": True})
        contract_id = accepted["contract_id"]
        acceptance = accepted["acceptance"]
        assert is_x_only_hex(acceptance.get("acceptor_adaptor_point")), "acceptance must carry an acceptor adaptor point"
        assert acceptance["acceptor_adaptor_point"] != offer["proposer_adaptor_point"]

        imported = alice.difficulty.import_acceptance(offer, acceptance)
        assert_equal(imported["state"], "accepted")
        assert_equal(imported["contract_id"], contract_id)

        # ---- two-leg build_open (alice funds long, bob merges + funds short) ----
        self.log.info("build_open: alice (long, partial) -> bob (short, merge)")
        a_open = alice.difficulty.build_open(contract_id, "long")
        merged = bob.difficulty.build_open(contract_id, "short", {"psbt": a_open["psbt"]})["psbt"]

        # The merged open must funnel through the adaptor ceremony, not a plain sign. prepare() can ONLY
        # succeed if fs/contract_meta is embedded AND each wallet re-derives + point-matches its secret.
        # Each party prepares its OWN inputs and produces its adaptor PRE-signature.
        self.log.info("each party: prepare -> partial (adaptor pre-signature) on the merged open")
        a_part = alice.adaptor.partial(alice.adaptor.prepare(merged)["psbt"])["psbt"]
        b_part = bob.adaptor.partial(bob.adaptor.prepare(merged)["psbt"])["psbt"]

        # LOCK-STEP with commit-reveal ENFORCEMENT (not the [] bypass): both pre-signatures are combined
        # into ONE shared PSBT, then BOTH parties commit_final to their final signatures BEFORE either
        # reveals — so neither sees the other's reveal before committing its own.
        self.log.info("lock-step: combine pre-signatures -> both commit_final -> both reveal -> broadcast")
        shared = node.combinepsbt([a_part, b_part])
        a_commit = alice.adaptor.commit_final(shared)["commitments"]
        b_commit = bob.adaptor.commit_final(shared)["commitments"]
        assert a_commit and b_commit, "both parties must produce final-signature commitments"

        # Enforcement is ON: a reveal that breaks the pre-published commitment is rejected.
        forged = [{"index": c["index"], "commitment": "00" * 32} for c in a_commit]
        assert_raises_rpc_error(-4, "COMMITMENT MISMATCH", alice.adaptor.complete, shared, None, forged)

        # Reveal: each party completes its OWN inputs bound to its OWN commitment (non-empty array). The tx
        # needs both reveals, so neither half finalizes alone.
        a_final = alice.adaptor.complete(shared, None, a_commit)["psbt"]
        b_final = bob.adaptor.complete(shared, None, b_commit)["psbt"]
        assert not node.finalizepsbt(a_final)["complete"], "alice finalizing alone must not complete the tx"
        assert not node.finalizepsbt(b_final)["complete"], "bob finalizing alone must not complete the tx"

        finalized = node.finalizepsbt(node.combinepsbt([a_final, b_final]))
        assert finalized["complete"], "combined open PSBT must finalize once both sides revealed"
        open_txid = node.sendrawtransaction(finalized["hex"])
        self.generatetoaddress(node, 1, alice_fund)  # confirm (validates through ConnectBlock)

        # Value sanity: two outputs of value im (one per leg).
        decoded = node.decoderawtransaction(finalized["hex"])
        vault_outs = [o for o in decoded["vout"] if abs(float(o["value"]) - im_btc) < 1e-9]
        assert len(vault_outs) == 2, "atomic open must fund both IM vaults in one tx"

        # STRUCTURAL check: record_open locates each IM vault by its COMMITTED scriptPubKey, so returned
        # outpoints referencing open_txid prove both funded vaults match the covenant scripts.
        rec = alice.difficulty.record_open(contract_id, open_txid)
        assert open_txid[:10] in rec.get("long_vault", "") and open_txid[:10] in rec.get("short_vault", ""), \
            f"record_open must resolve both IM vaults by their committed scripts; got {rec}"
        bob.difficulty.record_open(contract_id, open_txid)

        # A wallet that holds NEITHER leg (no contract record at all) cannot locate the contract by meta,
        # so the ceremony refuses to start.
        self.log.info("a wallet holding neither leg cannot prepare the difficulty open")
        assert_raises_rpc_error(-8, "contract", carol.adaptor.prepare, merged)

        self.log.info("Difficulty atomic-risk-transfer open (lock-step, two wallets, broadcast) succeeded")


if __name__ == '__main__':
    DifficultyAtomicOpenTest(__file__).main()
