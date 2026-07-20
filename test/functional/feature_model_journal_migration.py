#!/usr/bin/env python3
"""Old->new ModelDB journal MIGRATION test.

Validates that a ModelDB written by a PRE-undo-journal binary (no `'u'` undo
records) is loaded soundly by the new binary, and that the node is crash-safe
for blocks connected after the upgrade.

Requires --old-bitcoind pointing at a bitcoind built from the pre-journal source.
The on-disk ModelDB format is unchanged across the upgrade (the journal only ADDS
a `'u'` key prefix), so old and new share one datadir.

Phases:
  1. OLD binary: register a model on-chain + mine blocks using it (-> Registered),
     then clean-stop. The datadir now has model state + a synced-tip marker but
     NO undo records (a genuine pre-journal tip T0).
  2. NEW binary, same datadir: must start cleanly, keep the model Registered, take
     the pre-journal fallback (no full rebuild, no fatal, and crucially NOT
     manufacture an undo record for T0), and clean-restart to flush chainstate@T0.
  3. NEW binary: mine more model-using blocks T0->T2 (these ARE journaled), then
     SIGKILL (ModelDB@T2 ahead of chainstate@T0). On restart, recovery must rewind
     via the undo journal down to the pre-journal tip T0 and STOP there (it never
     needs—or wrongly applies—an undo record for T0), leaving the registry intact
     and the chain extendable with the model. No `duplicate-model-deposit`.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal


SUCCESSFUL_COMMITS_THRESHOLD = 50
MODEL_NAME = "tensor/journal-migration-regression"
MODEL_COMMIT = "journal-migration-commit"
MODEL_BLOCKS = 6
EXTRA_MODEL_BLOCKS = 6


class ModelJournalMigrationTest(BitcoinTestFramework):
    STATUS_ALIASES = {
        "pending_deposit": {"pending_deposit", "pending"},
        "pending_verification": {"pending_verification"},
        "registered": {"registered"},
        "locked": {"locked"},
    }

    def add_options(self, parser):
        parser.add_argument("--old-bitcoind", dest="old_bitcoind", default=None,
                            help="path to a pre-undo-journal bitcoind for phase 1")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = "tensor-reg"
        self.rpc_timeout = 240
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.default_wallet_name = "model_journal_migration"
        self.wallet_names = [self.default_wallet_name]
        self.node_args = base_args + [
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-quick=Quick_OK_Smell_OK",
            "-mockval-default-model=Model_OK",
            "-mockval-default-full=full_green",
            "-rpcdoccheck=0",
            "-dbcache=1024",
        ]
        self.extra_args = [self.node_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        # Phase 1 runs on the OLD (pre-journal) binary; remember the new one to swap in.
        self._new_daemon = self.nodes[0].args[0]
        if not self.options.old_bitcoind:
            raise AssertionError("--old-bitcoind is required for the migration test")
        self.nodes[0].args[0] = self.options.old_bitcoind
        self.log.info(f"Phase 1 binary (old): {self.options.old_bitcoind}")
        self.start_nodes()
        # We override setup_network (to swap in the old binary), so we must run the
        # wallet init that setup_nodes() would normally do.
        self.import_deterministic_coinbase_privkeys()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node] if self.wallet_names else self.default_wallet_name
        if wallet_name:
            self.nodes[node].createwallet(wallet_name=wallet_name)

    def _reload_wallet(self):
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.miner_address = wallet.getnewaddress()

        self.log.info("Phase 1 (old binary): register a model and mine using it")
        self._mine_blocks(node, 101)
        model_hash = self._register_model(node, wallet)
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, MODEL_BLOCKS)
        node.setminermodel("", True)
        node.syncwithvalidationinterfacequeue()
        t0_height = node.getblockcount()
        t0_hash = node.getbestblockhash()
        self.log.info(f"Pre-journal tip established at T0={t0_height}")

        # Sanity: the old binary wrote NO undo records (pre-journal datadir).
        undo_dir = node.chain_path / "modeldb"
        self.stop_node(0)

        self.log.info("Phase 2 (new binary): load the pre-journal datadir")
        node.args[0] = self._new_daemon
        debug_log = node.chain_path / "debug.log"
        log_offset = debug_log.stat().st_size
        self.start_node(0, extra_args=self.node_args)
        self._reload_wallet()
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), t0_hash)
        assert_equal(node.getblockcount(), t0_height)
        self._wait_for_status(node, model_hash, expected="registered")
        load_log = debug_log.read_text(encoding="utf8", errors="replace")[log_offset:]
        assert "Full rebuild from active chain" not in load_log, "new binary wiped+rebuilt a loadable pre-journal ModelDB"
        assert "FATAL" not in load_log, f"fatal during pre-journal load:\n{load_log[-2000:]}"

        # Clean restart to flush chainstate durably at T0 (and let the new binary settle).
        self.restart_node(0, extra_args=self.node_args)
        self._reload_wallet()
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), t0_hash)

        self.log.info("Phase 3 (new binary): mine journaled blocks, then crash")
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, EXTRA_MODEL_BLOCKS)
        node.setminermodel("", True)
        node.syncwithvalidationinterfacequeue()
        t2_height = node.getblockcount()
        assert t2_height > t0_height
        log_offset = debug_log.stat().st_size
        self.log.info(f"SIGKILL: ModelDB@{t2_height} ahead of chainstate@{t0_height} (pre-journal tip)")
        node.kill_process()

        self.log.info("Restart: recovery must rewind via the journal down to T0 and stop")
        self.start_node(0, extra_args=self.node_args)
        self._reload_wallet()
        node = self.nodes[0]
        self.wait_until(lambda: node.getbestblockhash() == t0_hash, timeout=120)
        assert_equal(node.getblockcount(), t0_height)
        status = self._wait_for_status(node, model_hash, expected="registered")
        assert_equal(status["deposit_block_height"] > 0, True)
        recovery_log = debug_log.read_text(encoding="utf8", errors="replace")[log_offset:]
        assert "Rewinding applied tip" in recovery_log, "expected undo-journal rewind of the journaled blocks"
        assert "Full rebuild from active chain" not in recovery_log, "recovery wiped instead of rewinding"
        assert "FATAL" not in recovery_log, f"fatal during migrated crash recovery:\n{recovery_log[-2000:]}"
        assert "duplicate-model-deposit" not in recovery_log, "duplicate deposit on reconnect after migrated crash"

        # Liveness + consistency: extend with the registered model after the migrated crash.
        node.setminermodel(f"{MODEL_NAME}@{MODEL_COMMIT}")
        self._mine_blocks(node, 3)
        node.setminermodel("", True)
        assert_equal(node.getblockcount(), t0_height + 3)
        self._wait_for_status(node, model_hash, expected="registered")
        self.log.info("ModelDB journal migration verified")

    # --- helpers (shared shape with feature_model_reindex.py) ---

    def _register_model(self, node, wallet):
        node.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: wallet.getbalance() > Decimal("1"), timeout=60)
        deposit = wallet.createmodeldeposit(MODEL_NAME, MODEL_COMMIT, 1_000_000)
        deposit_txid, deposit_vout, model_hash = deposit["txid"], deposit["deposit_vout"], deposit["model_hash"]
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
        candidate, candidate_amount = None, Decimal("0")
        for entry in utxos:
            if not entry.get("spendable", True) or entry.get("confirmations", 0) == 0:
                continue
            amount = Decimal(str(entry.get("amount", 0)))
            if amount <= 0 or amount < min_split_amount:
                continue
            if exclude_txid and entry.get("txid") == exclude_txid:
                continue
            if amount > candidate_amount:
                candidate, candidate_amount = entry, amount
        if candidate is None:
            raise AssertionError("No spendable UTXO available to fund commit transactions")
        split = wallet.splitutxo(candidate["txid"], candidate["vout"], count)
        self._confirm_transactions(node, [split["txid"]])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs, got {len(outputs)}")
        return [{"txid": split["txid"], "vout": out["vout"]} for out in outputs]

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
            s = _fetch()
            if s is None:
                return False
            return expected is None or s["status"] in self.STATUS_ALIASES.get(expected, {expected})

        self.wait_until(_ready, timeout=timeout)
        s = _fetch()
        assert s is not None
        return s


if __name__ == "__main__":
    ModelJournalMigrationTest(__file__).main()
