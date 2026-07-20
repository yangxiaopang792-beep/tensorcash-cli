#!/usr/bin/env python3
"""Crash-consistency regression for the ModelDB per-block undo journal.

Root cause this guards against: ModelDB writes (model records, indexes,
schedules) and its applied-tip marker were persisted per-connect with fsync,
while the chainstate flushes only periodically. After an unclean shutdown the
ModelDB therefore ends up AHEAD of the last-flushed chainstate, and startup
recovery responded by wiping ModelDB and rebuilding from block 1 — which is
impossible (fatal) on a pruned datadir, and on any datadir risks a
`duplicate-model-deposit` rejection when the same deposit block reconnects.

Fix under test: each connected block atomically commits its forward ModelDB
writes + an undo record + the applied-tip marker (CModelDB::CommitBlock).
Startup recovery rewinds the applied tip block-by-block via the undo journal —
needing no historical block bodies — until it rejoins the active chain, then
replays only the shallow remainder. No full rebuild, no block 1 required.

Scenario (mirrors the production incident shape):
  1. Register a model on-chain and mine blocks using it (-> Registered).
  2. Clean-restart so the chainstate is durably flushed to tip T1, with the
     ModelDB applied-tip also at T1.
  3. Mine a few more model-using blocks to T2 WITHOUT a clean flush, so the
     chainstate's durable height stays T1 while the ModelDB advances to T2.
  4. SIGKILL the node (unclean). On reload the chainstate (and block index) are
     at the last durable flush T1, while the ModelDB applied-tip is the orphaned
     T2. In this single-node setup the unflushed T1+1..T2 block-index entries are
     gone for good (no peer to refetch), so the surviving chain is T1 — exactly
     the production shape where ModelDB sat ahead of the survived chain tip.
  5. Restart. Recovery must REWIND the ModelDB via the undo journal from T2 back
     to T1 (not rebuild from block 1, not fatal on the pruned path), leaving the
     ModelDB consistent with the surviving chain: the model stays Registered and
     the chain can be extended using it (which only works if the registry is
     coherent with the tip), with no `duplicate-model-deposit`.

Runs on tensor-reg, where model-registry enforcement is active (same harness as
feature_model_reindex.py).
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal


SUCCESSFUL_COMMITS_THRESHOLD = 50
MODEL_NAME = "tensor/crash-recovery-regression"
MODEL_COMMIT = "crash-recovery-commit"
MODEL_BLOCKS = 8
EXTRA_MODEL_BLOCKS = 6


class ModelCrashRecoveryTest(BitcoinTestFramework):
    STATUS_ALIASES = {
        "pending_deposit": {"pending_deposit", "pending"},
        "pending_verification": {"pending_verification"},
        "registered": {"registered"},
        "locked": {"locked"},
    }

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = "tensor-reg"
        self.rpc_timeout = 240
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.default_wallet_name = "model_crash_recovery"
        self.wallet_names = [self.default_wallet_name]
        # Mock validation defaults are passed as args (not just runtime calls) so
        # they survive restarts, where imported/reconnected blocks re-run checks.
        # A large dbcache keeps the chainstate from auto-flushing under cache
        # pressure, so the only durable chainstate flush is the clean restart in
        # step 2 — making "ModelDB ahead of chainstate" deterministic.
        self.mock_args = [
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-quick=Quick_OK_Smell_OK",
            "-mockval-default-model=Model_OK",
            "-mockval-default-full=full_green",
            "-rpcdoccheck=0",
            "-dbcache=1024",
        ]
        self.node_args = base_args + self.mock_args
        self.extra_args = [self.node_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node] if self.wallet_names else self.default_wallet_name
        if not wallet_name:
            return
        self.nodes[node].createwallet(wallet_name=wallet_name)

    def _reload_wallet(self):
        # bcore does not auto-load wallets after a restart.
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.miner_address = wallet.getnewaddress()

        self.log.info("Mining spendable outputs with the default model")
        self._mine_blocks(node, 101)

        self.log.info("Registering a model on-chain")
        model_hash = self._register_model(node, wallet)

        self.log.info("Mining blocks that USE the registered model")
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, MODEL_BLOCKS)

        # T1: clean restart durably flushes the chainstate AND the ModelDB
        # applied-tip to this height.
        node.setminermodel("", True)
        node.syncwithvalidationinterfacequeue()
        t1_height = node.getblockcount()
        t1_hash = node.getbestblockhash()
        self.log.info(f"Clean restart to flush chainstate at T1={t1_height}")
        self.restart_node(0, extra_args=self.node_args)
        self._reload_wallet()
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        assert_equal(node.getbestblockhash(), t1_hash)
        self._wait_for_status(node, model_hash, expected="registered")

        # T2: advance the ModelDB past the durable chainstate without flushing.
        self.log.info("Mining more model-using blocks (chainstate stays unflushed at T1)")
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, EXTRA_MODEL_BLOCKS)
        node.setminermodel("", True)
        node.syncwithvalidationinterfacequeue()
        t2_height = node.getblockcount()
        t2_hash = node.getbestblockhash()
        assert t2_height > t1_height, "expected to advance past T1"

        # Record where debug.log is now so we only inspect the recovery restart.
        debug_log = node.chain_path / "debug.log"
        log_offset = debug_log.stat().st_size

        self.log.info(f"SIGKILL the node (unclean): ModelDB@{t2_height} ahead of chainstate@{t1_height}")
        node.kill_process()

        self.log.info("Restarting: recovery must rewind via the undo journal, not rebuild from block 1")
        self.start_node(0, extra_args=self.node_args)
        self._reload_wallet()
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        # The surviving chain is T1 (T1+1..T2 block-index entries were unflushed and
        # lost on the unclean kill). ModelDB, durable per-block at T2, must rewind to
        # T1 to stay consistent — never rebuild from block 1.
        self.wait_until(lambda: node.getbestblockhash() == t1_hash, timeout=120)
        assert_equal(node.getblockcount(), t1_height)
        for tip in node.getchaintips():
            assert tip["status"] != "invalid", f"invalid chain tip after crash recovery: {tip}"
        status = self._wait_for_status(node, model_hash, expected="registered")
        assert_equal(status["deposit_block_height"] > 0, True)

        # Liveness + consistency proof: extend the chain USING the registered model.
        # This connects only if the rewound ModelDB is coherent with the tip (the
        # model resolves as Registered and its deposit is not seen as a duplicate).
        self.log.info("Extending the chain with the registered model after recovery")
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, 3)
        node.setminermodel("", True)
        assert_equal(node.getblockcount(), t1_height + 3)
        self._wait_for_status(node, model_hash, expected="registered")

        self.log.info("Asserting recovery used the undo-journal rewind path")
        recovery_log = debug_log.read_text(encoding="utf8", errors="replace")[log_offset:]
        assert "[ModelDB] Rewinding applied tip" in recovery_log, (
            "expected undo-journal rewind during recovery; log tail:\n" + recovery_log[-4000:]
        )
        assert "Full rebuild from active chain" not in recovery_log, (
            "recovery wiped+rebuilt ModelDB instead of rewinding via the undo journal"
        )
        assert "FATAL: full rebuild required on a pruned datadir" not in recovery_log, (
            "recovery hit the pruned-datadir fatal path"
        )
        assert "duplicate-model-deposit" not in recovery_log, (
            "a deposit block re-rejected as duplicate while reconnecting after rewind"
        )
        self.log.info("ModelDB crash-consistency recovery verified")

    # --- helpers (shared shape with feature_model_reindex.py) ---

    def _register_model(self, node, wallet):
        node.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: wallet.getbalance() > Decimal("1"), timeout=60)
        deposit = wallet.createmodeldeposit(MODEL_NAME, MODEL_COMMIT, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        self._confirm_transactions(node, deposit_txid)
        self._wait_for_status(node, model_hash, expected="pending_deposit")

        funding_utxos = self._prepare_commit_funding(wallet, node, exclude_txid=deposit_txid)
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"

        self._confirm_transactions(node, commit_txids)
        status = self._wait_for_status(node, model_hash, expected="pending_verification")

        self._mine_to_height(node, status["verification_event_height"])
        self._wait_for_status(node, model_hash, expected="registered")
        return model_hash

    def _prepare_commit_funding(self, wallet, node, *, exclude_txid=None, count=SUCCESSFUL_COMMITS_THRESHOLD):
        utxos = wallet.listunspent()
        min_split_amount = Decimal("0.00000001") * count
        candidate = None
        candidate_amount = Decimal("0")
        for entry in utxos:
            if not entry.get("spendable", True):
                continue
            if entry.get("confirmations", 0) == 0:
                continue
            amount = Decimal(str(entry.get("amount", 0)))
            if amount <= 0 or amount < min_split_amount:
                continue
            if exclude_txid and entry.get("txid") == exclude_txid:
                continue
            if amount > candidate_amount:
                candidate = entry
                candidate_amount = amount
        if candidate is None:
            raise AssertionError("No spendable UTXO available to fund commit transactions")

        split = wallet.splitutxo(candidate["txid"], candidate["vout"], count)
        split_txid = split["txid"]
        self._confirm_transactions(node, [split_txid])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs from splitutxo, got {len(outputs)}")
        return [{"txid": split_txid, "vout": out["vout"]} for out in outputs]

    def _confirm_transactions(self, node, txids):
        pending = {txids} if isinstance(txids, str) else set(txids)
        attempts = 0
        while pending:
            mempool = set(node.getrawmempool())
            for txid in list(pending):
                if txid in mempool:
                    continue
                try:
                    tx = node.gettransaction(txid, True, True)
                except JSONRPCException:
                    continue
                if tx.get("confirmations", 0) == 0 and tx.get("hex"):
                    try:
                        node.sendrawtransaction(tx["hex"])
                    except JSONRPCException:
                        pass
            self._mine_blocks(node, 1)
            confirmed = set()
            for txid in list(pending):
                try:
                    tx = node.gettransaction(txid, True, True)
                except JSONRPCException:
                    continue
                if tx.get("confirmations", 0) > 0:
                    confirmed.add(txid)
            pending -= confirmed
            attempts += 1
            if attempts > 200 and pending:
                raise AssertionError(f"Transactions failed to confirm: {sorted(pending)}")

    def _mine_blocks(self, node, count):
        if count <= 0:
            return []
        return self.generatetoaddress(node, count, self.miner_address, sync_fun=self.no_op)

    def _mine_to_height(self, node, target_height, batch_size=50):
        current = node.getblockcount()
        while current < target_height:
            step = min(batch_size, target_height - current)
            self._mine_blocks(node, step)
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
            return status_obj["status"] in self.STATUS_ALIASES.get(expected, {expected})

        try:
            self.wait_until(_ready, timeout=timeout)
        except AssertionError:
            self.log.error(f"last model status for {model_hash}: {_fetch()!r}")
            raise
        status_obj = _fetch()
        assert status_obj is not None
        return status_obj


if __name__ == "__main__":
    ModelCrashRecoveryTest(__file__).main()
