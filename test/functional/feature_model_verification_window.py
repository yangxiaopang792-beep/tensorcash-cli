#!/usr/bin/env python3
"""Verification window coverage for model registration."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal, assert_raises_rpc_error


MODEL_VERIFICATION_BLOCK_COUNT = 100
SUCCESSFUL_COMMITS_THRESHOLD = 50


class ModelVerificationWindowTest(BitcoinTestFramework):
    STATUS_ALIASES = {
        "pending_deposit": {"pending_deposit", "pending"},
        "pending_verification": {"pending_verification"},
        "registered": {"registered"},
        "locked": {"locked"},
    }

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.default_wallet_name = "model_window"
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

        self.log.info("Mining spendable outputs for deposits and commits")
        self.generatetoaddress(node1, 110, self.miner_address)

        self.log.info("Scenario: meets verification threshold")
        self._scenario_meets_threshold(node0, node1, wallet)

        self.log.info("Scenario: below verification threshold")
        self._scenario_below_threshold(node0, node1, wallet)

    def _scenario_meets_threshold(self, node0, node1, wallet):
        model_name = "tensor/window-success"
        model_commit = "window-commit-success"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        self.sync_mempools([node0, node1])
        self.generatetoaddress(node1, 1, self.miner_address)
        status = self._wait_for_status(node0, model_hash, expected="pending_deposit")
        assert_equal(status["deposit_txid"], deposit_txid)

        funding_utxos = self._prepare_commit_funding(
            wallet, node1, count=SUCCESSFUL_COMMITS_THRESHOLD, exclude_txid=deposit_txid
        )
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"

        self.sync_mempools([node0, node1])
        self.generatetoaddress(node1, 10, self.miner_address)
        status = self._wait_for_status(node0, model_hash, expected="pending_verification")
        assert_equal(status["successful_commit_count"], 10)

        self.generatetoaddress(node1, 50, self.miner_address)
        status = self._wait_for_status(node0, model_hash, expected="pending_verification")
        assert_equal(status["successful_commit_count"], 50)

        verification_height = status["verification_event_height"]
        assert verification_height > status["deposit_block_height"]
        self._mine_to_height(node1, verification_height)

        status = self._wait_for_status(node0, model_hash, expected="registered")
        assert_equal(status["burn_txid"], "0" * 64)
        assert_equal(status["burn_ready"], False)

    def _scenario_below_threshold(self, node0, node1, wallet):
        model_name = "tensor/window-failure"
        model_commit = "window-commit-failure"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        self.sync_mempools([node0, node1])
        self.generatetoaddress(node1, 1, self.miner_address)
        status = self._wait_for_status(node0, model_hash, expected="pending_deposit")
        assert_equal(status["deposit_txid"], deposit_txid)
        deposit_block_height = status["deposit_block_height"]

        funding_utxos = self._prepare_commit_funding(
            wallet, node1, count=1, exclude_txid=deposit_txid
        )

        self.disconnect_nodes(0, 1)

        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, 1, funding_utxos)
        commit_entry = commit_info["transactions"][0]
        commit_txid = commit_entry["txid"]
        commit_hex = commit_entry["hex"]
        assert commit_txid in node0.getrawmempool()

        target_height = deposit_block_height + MODEL_VERIFICATION_BLOCK_COUNT
        self._mine_to_height(node1, target_height, sync=False)

        self.connect_nodes(0, 1)
        self.sync_all()

        status = self._wait_for_status(node0, model_hash, expected="locked")
        assert_equal(status["burn_ready"], True)
        assert_equal(status["burn_txid"], deposit_txid)
        assert_equal(status["burn_vout"], deposit_vout)
        assert_equal(status["successful_commit_count"], 0)

        self.wait_until(lambda: commit_txid not in node0.getrawmempool())
        assert_raises_rpc_error(-26, "bad-commit-status", node0.sendrawtransaction, commit_hex)

    def _prepare_commit_funding(self, wallet, miner, *, count, exclude_txid=None):
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
            if amount <= 0:
                continue
            if amount < min_split_amount:
                continue
            if exclude_txid and entry.get("txid") == exclude_txid:
                continue
            if amount > candidate_amount:
                candidate = entry
                candidate_amount = amount
        if candidate is None:
            raise AssertionError("No spendable UTXO available to fund commit transactions")

        if count == 1:
            return [{"txid": candidate["txid"], "vout": candidate["vout"]}]

        split = wallet.splitutxo(candidate["txid"], candidate["vout"], count)
        split_txid = split["txid"]
        self._confirm_transactions(wallet, miner, [split_txid])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs from splitutxo, got {len(outputs)}")
        return [{"txid": split_txid, "vout": out["vout"]} for out in outputs]

    def _confirm_transactions(self, wallet, miner, txids):
        if isinstance(txids, str):
            pending = {txids}
        else:
            pending = set(txids)
        attempts = 0
        while pending:
            self.generatetoaddress(miner, 1, self.miner_address)
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

    def _mine_to_height(self, miner, target_height, *, sync=True, batch_size=200):
        current = miner.getblockcount()
        while current < target_height:
            remaining = target_height - current
            step = min(batch_size, remaining)
            if sync:
                self.generatetoaddress(miner, step, self.miner_address)
            else:
                self.generatetoaddress(miner, step, self.miner_address, sync_fun=self.no_op)
            current += step

    def _wait_for_status(self, node, model_hash, expected=None):
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

        self.wait_until(_ready)
        status_obj = _fetch()
        assert status_obj is not None
        return status_obj

    def _status_matches(self, actual, expected):
        aliases = self.STATUS_ALIASES.get(expected, {expected})
        return actual in aliases


if __name__ == "__main__":
    ModelVerificationWindowTest(__file__).main()
