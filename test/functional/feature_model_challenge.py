#!/usr/bin/env python3
"""Challenge outcomes coverage for model registration."""

from decimal import Decimal
import shutil

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import tx_from_hex
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
    initialize_tensor_block_fields,
    set_block_tick_from_prev,
    update_block_pow_commitment,
)
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal, assert_raises_rpc_error


SUCCESSFUL_COMMITS_THRESHOLD = 50
MODEL_VERIFICATION_BLOCK_COUNT = 100
CHALLENGE_COMMIT_THRESHOLD = 50
MODEL_REGISTER_BURN_TX_VERSION = 7


class ModelChallengeFunctionalTest(BitcoinTestFramework):
    STATUS_ALIASES = {
        "pending_deposit": {"pending_deposit", "pending"},
        "pending_verification": {"pending_verification"},
        "registered": {"registered"},
        "locked": {"locked"},
        "banned": {"banned"},
    }

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.default_wallet_name = "model_challenge_wallet"
        self.wallet_names = [self.default_wallet_name, False]
        mock_args = [
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-full=full_green",
            "-rpcdoccheck=0",
        ]
        self.extra_args = [
            base_args + mock_args,
            base_args + mock_args,
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node] if self.wallet_names else self.default_wallet_name
        rpc = self.nodes[node]
        if not wallet_name:
            return
        rpc.createwallet(wallet_name=wallet_name)

    def run_test(self):
        node0, node1 = self.nodes
        wallet = node0.get_wallet_rpc(self.default_wallet_name)

        self.connect_nodes(0, 1)

        miner_key = node1.get_deterministic_priv_key()
        wallet.importprivkey(privkey=miner_key.key, label="coinbase", rescan=True)
        self.miner_address = miner_key.address

        for node in (node0, node1):
            node.validationmockdefault("quick", "quick_ok_smell_ok")
            node.validationmockdefault("model", "model_ok")
            node.validationmockdefault("full", "full_green")

        default_entry = self._get_default_model_entry(node0)
        default_identifier = self._model_identifier(default_entry)
        self._set_miner_model(node1, default_identifier)

        self.log.info("Mining spendable outputs for deposits and commits")
        self.generatetoaddress(node1, 110, self.miner_address)
        self.sync_all()

        self.log.info("Scenario: Challenge_Fail")
        self._scenario_challenge_fail(node0, node1, wallet, default_identifier)

        self.log.info("Scenario: Challenge_Fail_Partial")
        self._scenario_challenge_fail_partial(node0, node1, wallet, default_identifier)
        wallet = node0.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Scenario: Challenge_OK")
        self._scenario_challenge_ok(node0, node1, wallet, default_identifier)

        # Scenarios A (fork-selection) and C (mined-slashed-spend) live in
        # their own test classes for isolation:
        #   feature_model_challenge_fork_selection.py
        #   feature_model_challenge_mined_spend.py
        # Running them back-to-back in this class poisons wallet UTXO state
        # (mempool / coinbase maturity / fee-estimation) such that
        # _register_model never reaches "registered". The method bodies
        # remain here as the implementation; the subclasses just override
        # run_test to invoke a single scenario with a fresh fixture.

    def _scenario_challenge_fail(self, node, miner, wallet, default_identifier):
        self._set_challenge_mock("challenge_fail")

        ctx = self._register_model(node, miner, wallet, name="tensor/challenge-fail", commit="fail-v1")
        challenged = self._mine_challenged_block(miner, ctx["model_identifier"], default_identifier)

        challenge_ctx = self._issue_challenge(node, miner, wallet, ctx["model_hash"], challenged["block_hash"])

        funding = self._prepare_funding_utxos(
            wallet,
            miner,
            count=CHALLENGE_COMMIT_THRESHOLD,
            exclude_txids={ctx["deposit_txid"], challenge_ctx["challenge_txid"]},
        )
        wallet.createchallengecommits(ctx["model_hash"], CHALLENGE_COMMIT_THRESHOLD, funding)
        self.sync_mempools([node, miner])

        self._mine_blocks(miner, 50)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["challenge_commit_count"], 0)

        verdict_height = status["challenge_verdict_height"]
        self._mine_to_height(miner, verdict_height)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "registered")

        self._assert_chainwork_unchanged(miner, challenged)

    def _scenario_challenge_fail_partial(self, node, miner, wallet, default_identifier):
        self._set_challenge_mock("challenge_ok")

        ctx = self._register_model(node, miner, wallet, name="tensor/challenge-partial", commit="partial-v1")
        challenged = self._mine_challenged_block(miner, ctx["model_identifier"], default_identifier)

        challenge_ctx = self._issue_challenge(node, miner, wallet, ctx["model_hash"], challenged["block_hash"])

        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        self._assert_rpc_error_any(-26, {"bad-model-deposit-spend", "challenge-deposit-locked"}, node.sendrawtransaction, signed["hex"])

        burn_raw, prevtx = self._prepare_challenge_burn(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(burn_raw, prevtx)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "unknown-model-burn", node.sendrawtransaction, signed["hex"])

        self._mine_blocks(miner, 70)
        self.sync_all()

        funding = self._prepare_funding_utxos(
            wallet,
            miner,
            count=CHALLENGE_COMMIT_THRESHOLD,
            exclude_txids={ctx["deposit_txid"], challenge_ctx["challenge_txid"]},
        )
        wallet.createchallengecommits(ctx["model_hash"], CHALLENGE_COMMIT_THRESHOLD, funding)
        self.sync_mempools([node, miner])

        self._mine_blocks(miner, 10)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["challenge_commit_count"], 10)

        verdict_height = status["challenge_verdict_height"]
        self._mine_to_height(miner, verdict_height)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "registered")
        count_after_verdict = status["challenge_commit_count"]

        verdict_block = miner.getblockhash(verdict_height)
        self.disconnect_nodes(0, 1)
        node.invalidateblock(verdict_block)
        self.wait_until(lambda: node.getblockcount() == verdict_height - 1)
        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "challenge-deposit-locked", node.sendrawtransaction, signed["hex"])

        node.reconsiderblock(verdict_block)
        self.wait_until(lambda: node.getblockcount() >= verdict_height)
        self.connect_nodes(0, 1)
        self.sync_all()

        self._mine_blocks(miner, 50)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "registered")
        assert_equal(status["challenge_commit_count"], count_after_verdict)

        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        self._assert_rpc_error_any(-26, {"bad-model-deposit-spend", "challenge-deposit-locked"}, node.sendrawtransaction, signed["hex"])

        self._rebuild_modeldb_from_active_chain(0)
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        self._assert_rpc_error_any(-26, {"bad-model-deposit-spend", "challenge-deposit-burned"}, node.sendrawtransaction, signed["hex"])

        self._assert_chainwork_unchanged(miner, challenged)

    def _scenario_challenge_ok(self, node, miner, wallet, default_identifier):
        self._set_challenge_mock("challenge_ok")

        ctx = self._register_model(node, miner, wallet, name="tensor/challenge-ok", commit="ok-v1")
        challenged = self._mine_challenged_block(miner, ctx["model_identifier"], default_identifier, challenged_index=0)

        challenge_ctx = self._issue_challenge(node, miner, wallet, ctx["model_hash"], challenged["block_hash"])

        funding = self._prepare_funding_utxos(
            wallet,
            miner,
            count=CHALLENGE_COMMIT_THRESHOLD,
            exclude_txids={ctx["deposit_txid"], challenge_ctx["challenge_txid"]},
        )
        wallet.createchallengecommits(ctx["model_hash"], CHALLENGE_COMMIT_THRESHOLD, funding)
        self.sync_mempools([node, miner])

        self._mine_blocks(miner, 10)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["challenge_commit_count"], 10)

        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "challenge-deposit-locked", node.sendrawtransaction, signed["hex"])

        commit_blocks = self._mine_blocks(miner, 40)
        self.sync_all()

        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "banned")
        self._assert_model_blocks_zero_work(miner, challenged)

        ban_block = commit_blocks[-1]
        ban_height = node.getblockheader(ban_block)["height"]
        self.disconnect_nodes(0, 1)
        node.invalidateblock(ban_block)
        self.wait_until(lambda: node.getblockcount() == ban_height - 1)
        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "registered")
        assert_equal(status["challenge_commit_count"], CHALLENGE_COMMIT_THRESHOLD - 1)
        self._assert_model_blocks_chainwork_restored(node, challenged)

        node.reconsiderblock(ban_block)
        self.wait_until(lambda: node.getbestblockhash() == ban_block)
        self.connect_nodes(0, 1)
        self.sync_all()
        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "banned")
        self._assert_model_blocks_zero_work(miner, challenged)

        self._rebuild_modeldb_from_active_chain(1)
        miner = self.nodes[1]
        self._set_miner_model(miner, default_identifier)
        self._assert_model_blocks_zero_work(miner, challenged)

        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "challenge-deposit-locked", node.sendrawtransaction, signed["hex"])

        verdict_height = status["challenge_verdict_height"]
        if verdict_height:
            self._mine_to_height(miner, verdict_height)
            self.sync_all()

        burn_raw, prevtx = self._prepare_challenge_burn(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(burn_raw, prevtx)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "unknown-model-burn", node.sendrawtransaction, signed["hex"])

        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        spend_txid = node.sendrawtransaction(signed["hex"])
        self.sync_mempools([node, miner])
        self._mine_blocks(miner, 1)
        self.sync_all()
        self._wait_confirm(node, spend_txid)

    def _scenario_fork_selection_honest_wins(self, node, miner, wallet, default_identifier):
        """Proves the security invariant: a shorter honest verdict-success
        branch wins by chainwork over a longer raw-work dormant cheater
        branch that used the to-be-banned model_identifier.

        Important framing -- this is the property that bcore's verdict-success
        path *actually* delivers, not the more aggressive "honest 50 demotes
        cheater 1000 even when cheater is the active chain" version of the
        invariant. The latter would require pre-activation side-branch
        challenge-proof processing, which bcore does not implement:
        FindMostWorkChain (validation.cpp:6475) picks the highest-nChainWork
        candidate before any verdict ConnectBlock can fire, so a heavier
        active cheater branch can never be demoted by a lower-raw-work
        honest side branch. The honest verdict must fire while honest is
        either (a) the active chain or (b) at least equal-work-with-cheater-
        as-side-branch, so the verdict-success ConnectBlock runs and triggers
        ApplyModelChallengeZeroWork over the local block index.

        This scenario exercises case (b) -- dormant cheater. Sequence:

          1. Build the 49-commit prefix (status Registered, count 49).
             Snapshot fork_point.
          2. Mine the cheater branch FIRST under ctx["model_identifier"]:
             N blocks of raw work, with no ban applied because no verdict
             has fired yet. cheater_tip is the active chain (higher work
             than fork_point).
          3. invalidateblock(cheater[0]) -- the chain rolls back to
             fork_point. All cheater blocks remain in m_block_index with
             BLOCK_HAVE_DATA set, but are now marked BLOCK_FAILED_* and
             dormant.
          4. Mine the honest 50th-commit block on top of fork_point. The
             in-tx threshold-crossing ban (validation.cpp:5868-5897) fires
             inside the active-chain ConnectBlock and calls
             ApplyModelChallengeZeroWork(model_hash, challenged_height).
             That sweep iterates m_block_index (filters only on nHeight
             and BLOCK_HAVE_DATA -- it does NOT skip BLOCK_FAILED_* entries)
             and reads each candidate's body via ReadBlock. Every dormant
             cheater block matches the banned model_hash, gets
             BLOCK_MODEL_CHALLENGE_ZERO_WORK set, and the subsequent
             RecalculateBlockIndexWorkForFullValidation collapses each
             cheater block's nChainWork to its parent's work.
          5. reconsiderblock(cheater[0]) -- the failure flags clear, the
             dormant cheater branch becomes a candidate again. But its
             nChainWork has been zeroed by the sweep, so cheater_tip's
             work past fork_point is 0 while honest_tip contributes 1 full
             block of work. ActivateBestChain prefers honest_tip.

        Net: honest_tip wins despite cheater having had N blocks of raw
        chainwork advantage at the moment cheater was the active chain.
        The mechanism is the BLOCK_MODEL_CHALLENGE_ZERO_WORK persistence
        + recompute-respects-it pair from the patch.

        Counter-test that would FAIL today: skipping step 3 (leaving
        cheater active when the honest ban tries to fire). The honest
        block would be on a side branch with less raw work than cheater
        and ActivateBestChain would never pick it -- the verdict scheduler
        ConnectBlock wouldn't run, no sweep would happen, cheater would
        keep winning. That counter-scenario is documented in the agent's
        critique and is not implemented by current bcore consensus code.
        """
        # Prior scenarios drained spendable UTXOs (each one consumed ~50
        # commit funding outputs). Mine 110 fresh coinbases so this
        # scenario's _register_model + _prepare_funding_utxos has enough
        # mature coinbases to split into 50 commit-funding outputs.
        self._ensure_spendable_funds(miner)
        self._set_challenge_mock("challenge_ok")

        ctx = self._register_model(node, miner, wallet,
                                   name="tensor/fork-selection",
                                   commit="fork-v1")
        challenged = self._mine_challenged_block(miner, ctx["model_identifier"], default_identifier, challenged_index=0)
        challenge_ctx = self._issue_challenge(node, miner, wallet, ctx["model_hash"], challenged["block_hash"])

        # Create exactly THRESHOLD - 1 commit txs so the mempool is empty
        # after we mine them all. If we created THRESHOLD here, the 50th
        # commit would still be in mempool when cheater blocks are mined
        # (Step 2), and that 50th commit would land in cheater_block[0],
        # tripping the in-block ban path BEFORE we get to engineer the
        # dormant-cheater fork in Step 3.
        commit_count_pre = CHALLENGE_COMMIT_THRESHOLD - 1
        funding = self._prepare_funding_utxos(
            wallet, miner,
            count=commit_count_pre,
            exclude_txids={ctx["deposit_txid"], challenge_ctx["challenge_txid"]},
        )
        wallet.createchallengecommits(ctx["model_hash"], commit_count_pre, funding)
        self.sync_mempools([node, miner])

        # === Step 1: 49 commits, fork_point at count=49, Registered ===
        self._mine_blocks(miner, commit_count_pre)
        self.sync_all()
        status = node.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["challenge_commit_count"], commit_count_pre)
        # Confirm mempool is drained; any leftover commit tx would later
        # land in a cheater block and break the test setup.
        assert_equal(len(miner.getrawmempool()), 0)

        # Pre-stage funding UTXOs for the Step 4 "honest 50th commit" mine.
        # The funding split tx itself needs confirmation, which requires
        # mining + sync_all -- so it has to happen while nodes are still
        # connected. After this, createchallengecommits is deferred to
        # Step 4 (post-disconnect) so the new commit txs don't accidentally
        # land in cheater blocks.
        funding_extra = self._prepare_funding_utxos(
            wallet, miner,
            count=2,
            exclude_txids={ctx["deposit_txid"], challenge_ctx["challenge_txid"]},
        )

        # All fork engineering happens on miner-side; node0 observes the
        # outcome after reconnect.
        self.disconnect_nodes(0, 1)
        fork_point_hash = miner.getbestblockhash()
        fork_point_chainwork = self._chainwork_int(miner, fork_point_hash)

        # === Step 2: build the cheater branch FIRST ===
        # Cheater mines N blocks under ctx["model_identifier"]. No ban
        # exists yet, so each block accepts normally with full chainwork.
        cheater_len = 20  # >> 1 so cheater dominates raw work
        self._set_miner_model(miner, ctx["model_identifier"])
        cheater_blocks = self.generatetoaddress(miner, cheater_len, self.miner_address, sync_fun=self.no_op)
        self._set_miner_model(miner, default_identifier)
        cheater_tip = cheater_blocks[-1]
        cheater_chainwork_pre_invalidate = self._chainwork_int(miner, cheater_tip)
        assert cheater_chainwork_pre_invalidate > fork_point_chainwork, (
            cheater_chainwork_pre_invalidate, fork_point_chainwork)
        # Sanity: cheater is the active tip right now.
        assert_equal(miner.getbestblockhash(), cheater_tip)

        # === Step 3: make cheater dormant ===
        # invalidateblock(cheater[0]) rolls back the active chain to
        # fork_point. Cheater blocks stay in m_block_index with BLOCK_HAVE_DATA
        # but are flagged BLOCK_FAILED_*.
        miner.invalidateblock(cheater_blocks[0])
        self.wait_until(lambda: miner.getbestblockhash() == fork_point_hash, timeout=10)
        status = miner.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "registered")
        assert_equal(status["challenge_commit_count"], CHALLENGE_COMMIT_THRESHOLD - 1)

        # === Step 4: mine honest commits to cross the threshold ===
        # Use the funding pre-staged before the disconnect (Step 1).
        # createchallengecommits requires count >= 2 funding inputs; mining
        # 1 block lands both commit txs, taking commit_count from 49 to 51
        # and tripping the ban path. ConnectBlock for this block calls
        # ApplyModelChallengeZeroWork over the index -- which includes the
        # dormant cheater blocks.
        wallet.createchallengecommits(ctx["model_hash"], 2, funding_extra)
        # Nodes are disconnected; relay the new commit txs from node0 to
        # the miner manually instead of via sync_mempools.
        for txid in set(node.getrawmempool()) - set(miner.getrawmempool()):
            miner.sendrawtransaction(node.getrawtransaction(txid))
        honest_blocks = self.generatetoaddress(miner, 1, self.miner_address, sync_fun=self.no_op)
        honest_tip = honest_blocks[0]
        assert_equal(miner.getbestblockhash(), honest_tip)
        status = miner.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "banned")
        self._assert_model_blocks_zero_work(miner, challenged)

        # fork_point_chainwork was captured pre-ban. After the ban,
        # ApplyModelChallengeZeroWork also zeros the original challenged
        # block (an ancestor of fork_point), so fork_point's cumulative
        # chainwork drops too. Re-read it post-ban for accurate compare.
        fork_point_chainwork_post = self._chainwork_int(miner, fork_point_hash)

        # Dormant cheater blocks must already be zeroed by the sweep, even
        # though they are currently flagged BLOCK_FAILED_* and not eligible
        # for chain selection. The sweep filters only on nHeight + HAVE_DATA.
        # Each cheater block's chainwork should match its parent (fork_point),
        # since its own contribution is now zero.
        for ch in cheater_blocks:
            assert_equal(self._chainwork_int(miner, ch), fork_point_chainwork_post)

        honest_chainwork = self._chainwork_int(miner, honest_tip)
        assert honest_chainwork > fork_point_chainwork_post, (honest_chainwork, fork_point_chainwork_post)

        # === Step 5: bring cheater back as a candidate ===
        # reconsiderblock(cheater[0]) clears BLOCK_FAILED_* on the cheater
        # branch and re-runs ActivateBestChain. Cheater_tip's nChainWork is
        # already at fork_point_chainwork (zeroed in step 4); honest_tip has
        # 1 block of work past fork_point. Honest wins.
        miner.reconsiderblock(cheater_blocks[0])
        # Give chain-selection time to settle.
        self.wait_until(
            lambda: miner.getbestblockhash() in (honest_tip, cheater_tip),
            timeout=20,
        )

        # === The security invariant ===
        # Honest wins despite cheater having had cheater_len blocks of raw
        # chainwork advantage before the ban fired.
        assert_equal(miner.getbestblockhash(), honest_tip)
        for ch in cheater_blocks:
            assert_equal(self._chainwork_int(miner, ch), fork_point_chainwork_post)
        status = miner.getmodelregistrationstatus(ctx["model_hash"])
        assert_equal(status["status"], "banned")
        self._assert_model_blocks_zero_work(miner, challenged)

        # Reconnect and re-sync (honest is canonical on both nodes).
        self.connect_nodes(0, 1)
        self.sync_all()

    def _scenario_mined_slashed_spend_rejected(self, node, miner, wallet, default_identifier):
        """Block-level (ConnectBlock) rejection of a tx that spends a
        slashed challenge_deposit outpoint.

        The existing _scenario_challenge_fail_partial covers the
        mempool-level rejection (sendrawtransaction returns one of
        "bad-model-deposit-spend" / "challenge-deposit-burned" / -locked
        depending on liveness state). This scenario adds the
        consensus-level coverage: a tx with the offending input is
        bundled into a manually-constructed block via the test framework's
        `create_block` + tensorcash field helpers, then submitted via
        `submitblock`. We assert the submitblock result is non-None
        (block rejected) -- proving ConnectBlock catches the slashed-deposit
        spend regardless of whether the mempool would have caught it first.

        Setup mirrors _scenario_challenge_fail_partial up to the point
        where SENTINEL is durably set on the challenger's deposit:
        register model, accuse, issue challenge with NO commits, mine
        past verdict_height, then rebuild modeldb (the same operation
        that converts in-memory "locked" state to on-disk SENTINEL).
        """
        # Replenish spendable UTXOs -- prior scenarios drained the wallet.
        self._ensure_spendable_funds(miner)
        self._set_challenge_mock("challenge_ok")

        ctx = self._register_model(node, miner, wallet,
                                   name="tensor/connect-rejection",
                                   commit="reject-v1")
        challenged = self._mine_challenged_block(miner, ctx["model_identifier"], default_identifier)
        challenge_ctx = self._issue_challenge(node, miner, wallet, ctx["model_hash"], challenged["block_hash"])

        # Mine to verdict_height with NO commits -- challenger forfeits,
        # deposit lock fires. Mine extra blocks to flush the lock window.
        verdict_height = challenge_ctx["verdict_height"]
        self._mine_to_height(miner, verdict_height + 70)
        self.sync_all()

        # Rebuild modeldb to materialize SENTINEL on disk; this is the
        # codepath the production patch fixes (RebuildModelDbFromActiveChain
        # writes SENTINEL on verdict-FAIL). Without this rebuild the live
        # state is "challenge-deposit-locked" (TTL-bound), not "burned".
        self._rebuild_modeldb_from_active_chain(0)
        self._rebuild_modeldb_from_active_chain(1)
        node = self.nodes[0]
        miner = self.nodes[1]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self._set_miner_model(miner, default_identifier)

        # Sanity: mempool-path rejection should now see SENTINEL state.
        spend_raw, prevtx = self._prepare_challenge_spend(wallet, node, challenge_ctx)
        signed = wallet.signrawtransactionwithwallet(spend_raw, prevtx)
        assert signed["complete"]
        self._assert_rpc_error_any(
            -26,
            {"bad-model-deposit-spend", "challenge-deposit-burned", "challenge-deposit-locked"},
            node.sendrawtransaction, signed["hex"],
        )

        # === The new coverage: bypass mempool, submit the tx inside a
        # manually-constructed block, expect submitblock rejection. ===
        spend_tx = tx_from_hex(signed["hex"])

        tip_hash = miner.getbestblockhash()
        tip_info = miner.getblock(tip_hash)
        coinbase = create_coinbase(tip_info["height"] + 1)
        candidate_block = create_block(int(tip_hash, 16), coinbase, tip_info["time"] + 1)
        candidate_block.vtx.append(spend_tx)
        # The signed spend tx carries SegWit witness data; coinbase must
        # include the BIP141 witness commitment or AcceptBlock rejects
        # with "unexpected-witness" before consensus checks like the
        # SENTINEL guard get to fire.
        add_witness_commitment(candidate_block)
        initialize_tensor_block_fields(candidate_block)
        set_block_tick_from_prev(miner, candidate_block, tip_hash)
        candidate_block.pow.model_identifier = default_identifier.encode()
        update_block_pow_commitment(candidate_block, use_merkle=True)
        candidate_block.solve()
        update_block_pow_commitment(candidate_block, use_merkle=True)

        # submitblock returns the rejection reason as the result string
        # (Bitcoin Core convention: None on accept, error string on reject).
        result = miner.submitblock(candidate_block.serialize().hex())
        assert result is not None, "block containing slashed-deposit spend was unexpectedly accepted"
        # ConnectBlock can reject under several related codes depending on
        # whether SENTINEL is hot or the deposit-spend guard fires first.
        # The point of this regression is that block-level rejection
        # happens at all (i.e. the bug doesn't let a mined slashed-spend
        # through silently).
        reject_codes = ("challenge-deposit-burned", "challenge-deposit-locked", "bad-model-deposit-spend")
        assert any(code in str(result) for code in reject_codes), (
            "ConnectBlock did not reject mined slashed-deposit spend with any "
            "expected error; got: %s" % result
        )

        # Tip should be unchanged -- the bad block was rejected.
        assert_equal(miner.getbestblockhash(), tip_hash)

    def _register_model(self, node, miner, wallet, *, name, commit):
        deposit = wallet.createmodeldeposit(name, commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        self.sync_mempools([node, miner])
        self._mine_blocks(miner, 1)
        self.sync_all()

        status = self._wait_for_status(node, model_hash, expected="pending_deposit")
        assert_equal(status["deposit_txid"], deposit_txid)

        funding_utxos = self._prepare_funding_utxos(
            wallet,
            miner,
            count=SUCCESSFUL_COMMITS_THRESHOLD,
            exclude_txids={deposit_txid},
        )
        wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        self.sync_mempools([node, miner])

        self._mine_blocks(miner, MODEL_VERIFICATION_BLOCK_COUNT)
        self.sync_all()

        status = self._wait_for_status(node, model_hash, expected="registered")
        assert status["successful_commit_count"] >= SUCCESSFUL_COMMITS_THRESHOLD

        return {
            "model_hash": model_hash,
            "model_identifier": f"{name}@{commit}",
            "deposit_txid": deposit_txid,
        }

    def _mine_challenged_block(self, miner, model_identifier, default_identifier, challenged_index=-1):
        self._set_miner_model(miner, model_identifier)
        hashes = self.generatetoaddress(miner, 5, self.miner_address)
        self._set_miner_model(miner, default_identifier)
        self.sync_all()

        challenged_block = hashes[challenged_index]
        header = miner.getblockheader(challenged_block)
        parent_hash = header["previousblockhash"]

        return {
            "block_hash": challenged_block,
            "parent_hash": parent_hash,
            "chainwork_before": self._chainwork_int(miner, challenged_block),
            "parent_chainwork": self._chainwork_int(miner, parent_hash),
            "model_blocks": hashes,
            "model_block_chainwork_before": {
                block_hash: self._chainwork_int(miner, block_hash) for block_hash in hashes
            },
        }

    def _issue_challenge(self, node, miner, wallet, model_hash, challenged_block):
        challenge = wallet.createchallengedeposit(challenged_block)
        challenge_txid = challenge["txid"]
        challenge_vout = challenge["deposit_vout"]
        challenge_amount = Decimal(challenge["deposit_amount"])

        self.sync_mempools([node, miner])
        self._mine_blocks(miner, 1)
        self.sync_all()

        self._wait_confirm(node, challenge_txid)
        status = node.getmodelregistrationstatus(model_hash)
        return {
            "challenge_txid": challenge_txid,
            "challenge_vout": challenge_vout,
            "challenge_amount": challenge_amount,
            "verdict_height": status["challenge_verdict_height"],
        }

    def _prepare_challenge_spend(self, wallet, node, ctx):
        payout_addr = wallet.getnewaddress()
        spend_amount = (ctx["challenge_amount"] - Decimal("0.001")).quantize(Decimal("0.00000001"))
        spend_raw = node.createrawtransaction(
            [{"txid": ctx["challenge_txid"], "vout": ctx["challenge_vout"]}],
            {payout_addr: str(spend_amount)},
        )
        prevtx = self._build_challenge_prevtx(wallet, node, ctx)
        return spend_raw, prevtx

    def _prepare_challenge_burn(self, wallet, node, ctx):
        burn_payload = "4348414c4c454e47455f4641494c"  # "CHALLENGE_FAIL" ASCII
        burn_raw = node.createrawtransaction(
            [{"txid": ctx["challenge_txid"], "vout": ctx["challenge_vout"]}],
            [{"data": burn_payload}],
        )
        burn_tx = tx_from_hex(burn_raw)
        burn_tx.version = MODEL_REGISTER_BURN_TX_VERSION
        burn_raw = burn_tx.serialize().hex()
        prevtx = self._build_challenge_prevtx(wallet, node, ctx)
        return burn_raw, prevtx

    def _build_challenge_prevtx(self, wallet, node, ctx):
        tx_info = wallet.gettransaction(ctx["challenge_txid"])
        blockhash = tx_info.get("blockhash")
        if blockhash:
            challenge_tx = node.getrawtransaction(ctx["challenge_txid"], True, blockhash)
        else:
            challenge_tx = node.getrawtransaction(ctx["challenge_txid"], True)
        return [{
            "txid": ctx["challenge_txid"],
            "vout": ctx["challenge_vout"],
            "scriptPubKey": challenge_tx["vout"][ctx["challenge_vout"]]["scriptPubKey"]["hex"],
            "redeemScript": "51",
            "amount": float(ctx["challenge_amount"]),
        }]

    def _prepare_funding_utxos(self, wallet, miner, *, count, exclude_txids=None):
        utxos = wallet.listunspent()
        min_split_amount = Decimal("0.00000001") * count
        candidate = None
        candidate_amount = Decimal("0")
        exclude_txids = exclude_txids or set()
        for entry in utxos:
            if not entry.get("spendable", True):
                continue
            if entry.get("confirmations", 0) == 0:
                continue
            amount = Decimal(str(entry.get("amount", 0)))
            if amount <= 0:
                continue
            if amount < min_split_amount:
                continue
            if entry.get("txid") in exclude_txids:
                continue
            if amount > candidate_amount:
                candidate = entry
                candidate_amount = amount
        if candidate is None:
            raise AssertionError("No spendable UTXO available to fund commit transactions")

        split = wallet.splitutxo(candidate["txid"], candidate["vout"], count)
        split_txid = split["txid"]
        self._confirm_transactions(miner, wallet, [split_txid])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs from splitutxo, got {len(outputs)}")
        return [{"txid": split_txid, "vout": out["vout"]} for out in outputs]

    def _confirm_transactions(self, miner, wallet, txids):
        if isinstance(txids, str):
            pending = {txids}
        else:
            pending = set(txids)
        attempts = 0
        while pending:
            self.generatetoaddress(miner, 1, self.miner_address)
            self.sync_all()
            confirmed = set()
            for txid in list(pending):
                try:
                    tx = wallet.gettransaction(txid, True, True)
                except JSONRPCException:
                    continue
                if tx.get("confirmations", 0) > 0:
                    confirmed.add(txid)
            pending -= confirmed
            attempts += 1
            if attempts > 200 and pending:
                raise AssertionError(f"Transactions failed to confirm: {sorted(pending)}")

    def _mine_blocks(self, miner, count):
        if count <= 0:
            return []
        return self.generatetoaddress(miner, count, self.miner_address, sync_fun=self.no_op)

    def _mine_to_height(self, miner, target_height, batch_size=50):
        current = miner.getblockcount()
        while current < target_height:
            remaining = target_height - current
            step = min(batch_size, remaining)
            self._mine_blocks(miner, step)
            current += step

    def _wait_for_status(self, node, model_hash, expected=None, timeout=240):
        def _fetch():
            try:
                return node.getmodelregistrationstatus(model_hash)
            except JSONRPCException:
                return None

        def _ready():
            status_obj = _fetch()
            if status_obj is None:
                return False
            if expected is None:
                return True
            return self._status_matches(status_obj["status"], expected)

        # Bumped from default 60s -> 240s: validation-api mock work + per-block
        # ModelDB reverse-index writes added by the modeldb-rebuild fix push
        # large-scenario _register_model + verification windows past 60s when
        # 4+ scenarios run back-to-back. Mining itself stays fast; the
        # bottleneck is the single-threaded mock validator queue draining
        # SendApiRequest type=3 (model validation) for the model's 50 commits
        # in sequence.
        self.wait_until(_ready, timeout=timeout)
        status_obj = _fetch()
        assert status_obj is not None
        return status_obj

    def _status_matches(self, actual, expected):
        aliases = self.STATUS_ALIASES.get(expected, {expected})
        return actual in aliases

    def _wait_confirm(self, node, txid):
        self.wait_until(lambda: node.gettransaction(txid, True, True).get("confirmations", 0) > 0)

    def _assert_rpc_error_any(self, code, messages, fun, *args, **kwargs):
        try:
            fun(*args, **kwargs)
        except JSONRPCException as exc:
            assert exc.error.get("code") == code, f"Unexpected code: {exc.error}"
            error_message = exc.error.get("message", "")
            if any(msg in error_message for msg in messages):
                return
            raise AssertionError(
                f"Expected one of {sorted(messages)} in error message, got: {error_message}"
            ) from exc
        raise AssertionError("No exception raised")

    def _ensure_spendable_funds(self, miner, extra_blocks=110):
        """Mine fresh coinbase rewards so subsequent _register_model /
        _prepare_funding_utxos calls have enough mature spendable UTXOs.

        Each scenario consumes ~50 commit funding outputs plus the model
        deposit. After 3 scenarios the wallet's spendable UTXOs are tied
        up in unconfirmed splits / spent. Mining 110 fresh coinbases (>
        coinbase maturity = 100) ensures at least 10 fresh mature
        coinbases are available — each one is a 50 BTC reward, more than
        enough to satisfy _prepare_funding_utxos's min-amount filter.

        Batched at 50 blocks per RPC to stay under the framework's default
        30s RPC timeout; a single 110-block generatetoaddress can exceed
        it once wallet bookkeeping costs grow.
        """
        remaining = extra_blocks
        while remaining > 0:
            step = min(50, remaining)
            self._mine_blocks(miner, step)
            remaining -= step
        self.sync_all()

    def _rebuild_modeldb_from_active_chain(self, node_index):
        self.stop_node(node_index)
        shutil.rmtree(self.nodes[node_index].chain_path / "modeldb", ignore_errors=True)
        self.start_node(node_index, self.extra_args[node_index])
        # bcore does not auto-load wallets on -wallet=startup; the helper used
        # to drop the wallet RPC after restart, which broke any caller that
        # subsequently called wallet.getnewaddress() etc. Reload it explicitly.
        wallet_name = self.wallet_names[node_index] if self.wallet_names else None
        if wallet_name:
            loaded = self.nodes[node_index].listwallets()
            if wallet_name not in loaded:
                self.nodes[node_index].loadwallet(wallet_name)
        self.connect_nodes(0, 1)
        self.sync_all()

    def _get_default_model_entry(self, node):
        models = node.getmodelslist(False)
        assert models, "models list must not be empty"
        return models[0]

    def _model_identifier(self, entry):
        return f"{entry['model_name']}@{entry['model_commit']}"

    def _set_miner_model(self, miner, model_identifier):
        miner.setminermodel(model_identifier)

    def _set_challenge_mock(self, value):
        for node in self.nodes:
            node.validationmockdefault("challenge", value)

    def _chainwork_int(self, node, block_hash):
        return int(node.getblockheader(block_hash)["chainwork"], 16)

    def _assert_chainwork_unchanged(self, miner, challenged):
        current = self._chainwork_int(miner, challenged["block_hash"])
        assert_equal(current, challenged["chainwork_before"])

    def _assert_chainwork_adjusted(self, miner, challenged):
        current = self._chainwork_int(miner, challenged["block_hash"])
        assert_equal(current, challenged["parent_chainwork"])

    def _assert_model_blocks_zero_work(self, miner, challenged):
        expected = challenged["parent_chainwork"]
        for block_hash in challenged["model_blocks"]:
            current = self._chainwork_int(miner, block_hash)
            assert_equal(current, expected)

    def _assert_model_blocks_chainwork_restored(self, miner, challenged):
        for block_hash, expected in challenged["model_block_chainwork_before"].items():
            current = self._chainwork_int(miner, block_hash)
            assert_equal(current, expected)

if __name__ == "__main__":
    ModelChallengeFunctionalTest(__file__).main()
