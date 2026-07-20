#!/usr/bin/env python3
"""Model deposit lock lifecycle coverage."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal, assert_raises_rpc_error


SUCCESSFUL_COMMITS_THRESHOLD = 50
UNLOCK_DELAY = 10000


class ModelDepositLockFunctionalTest(BitcoinTestFramework):
    STATUS_ALIASES = {
        "pending_deposit": {"pending_deposit", "pending"},
        "pending_verification": {"pending_verification"},
        "registered": {"registered"},
        "locked": {"locked"},
    }

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.default_wallet_name = "model_lock"
        self.wallet_names = [self.default_wallet_name]
        self.extra_args = [base_args + [
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-full=full_green",
            "-rpcdoccheck=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node] if self.wallet_names else self.default_wallet_name
        rpc = self.nodes[node]
        if wallet_name is False:
            return
        rpc.createwallet(wallet_name=wallet_name)
        wallet_rpc = rpc.get_wallet_rpc(wallet_name)
        priv = rpc.get_deterministic_priv_key().key
        wallet_rpc.importprivkey(privkey=priv, label="coinbase", rescan=True)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        node.validationmockdefault("quick", "quick_ok_smell_ok")
        node.validationmockdefault("model", "model_ok")
        node.validationmockdefault("full", "full_green")

        self.log.info("Mining spendable outputs for deposits and commits")
        self.generate(node, 301)

        self.log.info("Scenario: model unlocks after threshold commits")
        self._scenario_threshold_unlock(node, wallet)

        self.log.info("Scenario: model with insufficient commits exposes burn path")
        self._scenario_insufficient_commits(node, wallet)

        self.log.info("Scenario: locked model burns after unlock height")
        self._scenario_locked_burn_after_unlock(node, wallet)

    def _scenario_threshold_unlock(self, node, wallet):
        model_name = "tensor/deposit-lock-success"
        model_commit = "lock-commit-success"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        deposit_amount = Decimal(deposit["deposit_amount"])
        model_hash = deposit["model_hash"]

        self.generate(node, 1)
        status = self._wait_for_status(node, model_hash, expected="pending_deposit")
        assert_equal(status["deposit_txid"], deposit_txid)

        funding_utxos = self._prepare_commit_funding(
            wallet, node, exclude_txid=deposit_txid, count=SUCCESSFUL_COMMITS_THRESHOLD
        )
        commit_info = wallet.createmodelcommit(
            deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos
        )
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"
        self._confirm_transactions(node, commit_txids)

        status = self._wait_for_status(node, model_hash, expected="pending_verification")
        verification_height = status["verification_event_height"]
        self._mine_to_height(node, verification_height)

        status = self._wait_for_status(node, model_hash, expected="registered")
        assert status["successful_commit_count"] >= SUCCESSFUL_COMMITS_THRESHOLD

        unlock_height = status["deposit_block_height"] + UNLOCK_DELAY
        pre_unlock_height = max(status["deposit_block_height"], unlock_height - 2)
        self._mine_to_height(node, pre_unlock_height)
        self._attempt_spend(node, wallet, deposit_txid, deposit_vout, deposit_amount, expect_fail=True)
        assert_raises_rpc_error(
            -1,
            "Model deposit is not locked",
            wallet.createmodelburn,
            model_hash,
            False,
        )

        self._mine_to_height(node, unlock_height)
        assert_raises_rpc_error(
            -1,
            "Model deposit is not locked",
            wallet.createmodelburn,
            model_hash,
            False,
        )
        spend_txid = self._attempt_spend(node, wallet, deposit_txid, deposit_vout, deposit_amount, expect_fail=False)
        self._confirm_transactions(node, spend_txid)

    def _scenario_insufficient_commits(self, node, wallet):
        model_name = "tensor/deposit-lock-failure"
        model_commit = "lock-commit-failure"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        deposit_amount = Decimal(deposit["deposit_amount"])
        model_hash = deposit["model_hash"]

        self.generate(node, 1)
        status = self._wait_for_status(node, model_hash, expected="pending_deposit")
        deposit_block_height = status["deposit_block_height"]

        funding_utxos = self._prepare_commit_funding(
            wallet, node, exclude_txid=deposit_txid, count=1
        )
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, 1, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"
        self._confirm_transactions(node, commit_txids)

        status = self._wait_for_status(node, model_hash, expected="pending_verification")
        assert status["verification_event_height"] >= deposit_block_height

        self._mine_to_height(node, status["verification_event_height"])
        status = self._wait_for_status(node, model_hash, expected="locked")

        assert_equal(status["burn_ready"], True)
        assert_equal(status["burn_txid"], deposit_txid)
        assert_equal(status["burn_vout"], deposit_vout)
        assert_equal(status["successful_commit_count"], 1)

        self._attempt_spend(
            node,
            wallet,
            deposit_txid,
            deposit_vout,
            Decimal(deposit["deposit_amount"]),
            expect_fail=True,
            expected_message="bad-model-deposit-spend",
        )

        balances_before_burn = wallet.getbalances()["mine"]
        burn_info = wallet.createmodelburn(model_hash, True)
        assert_equal(burn_info["model_hash"], model_hash)
        assert_equal(burn_info["burn_allowed_height"], status["burn_allowed_height"])
        assert_equal(burn_info["broadcast"], True)
        burn_txid = burn_info["txid"]
        self._confirm_transactions(node, burn_txid)

        burned_status = node.getmodelregistrationstatus(model_hash)
        assert burned_status["burn_block_height"] > 0
        assert node.gettxout(deposit_txid, deposit_vout) is None
        balances_after_burn = wallet.getbalances()["mine"]
        # The deposit is held in `bonded` while the model is in a non-Registered
        # state, so total = trusted + bonded is the invariant that the burn
        # destroys (deposit_amount + a small fee).
        total_before = Decimal(str(balances_before_burn["trusted"])) + Decimal(str(balances_before_burn.get("bonded", 0)))
        total_after = Decimal(str(balances_after_burn["trusted"])) + Decimal(str(balances_after_burn.get("bonded", 0)))
        expected_max = total_before - deposit_amount + Decimal("0.0001")
        expected_min = expected_max - Decimal("0.0002")
        assert expected_min <= total_after <= expected_max, (
            f"unexpected balance drop {total_before - total_after} (deposit={deposit_amount})"
        )
        
    def _scenario_locked_burn_after_unlock(self, node, wallet):
        model_name = "tensor/deposit-lock-burn-after-unlock"
        model_commit = "lock-commit-burn-after-unlock"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        deposit_amount = Decimal(deposit["deposit_amount"])
        model_hash = deposit["model_hash"]

        self.generate(node, 1)
        status = self._wait_for_status(node, model_hash, expected="pending_deposit")
        deposit_block_height = status["deposit_block_height"]

        funding_utxos = self._prepare_commit_funding(
            wallet, node, exclude_txid=deposit_txid, count=1
        )
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, 1, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"
        self._confirm_transactions(node, commit_txids)

        status = self._wait_for_status(node, model_hash, expected="pending_verification")
        self._mine_to_height(node, status["verification_event_height"])
        self._wait_for_status(node, model_hash, expected="locked")

        unlock_height = deposit_block_height + UNLOCK_DELAY
        self._mine_to_height(node, unlock_height)

        self._attempt_spend(
            node,
            wallet,
            deposit_txid,
            deposit_vout,
            deposit_amount,
            expect_fail=True,
            expected_message="bad-model-deposit-spend",
        )

        burn_info = wallet.createmodelburn(model_hash, True)
        assert_equal(burn_info["broadcast"], True)
        burn_txid = burn_info["txid"]
        self._confirm_transactions(node, burn_txid)

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
        self._confirm_transactions(node, [split_txid])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs from splitutxo, got {len(outputs)}")
        return [{"txid": split_txid, "vout": out["vout"]} for out in outputs]

    def _confirm_transactions(self, node, txids):
        if isinstance(txids, str):
            pending = {txids}
        else:
            pending = set(txids)
        attempts = 0
        while pending:
            self.generate(node, 1)
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

    def _mine_to_height(self, node, target_height, batch_size=200):
        current = node.getblockcount()
        while current < target_height:
            remaining = target_height - current
            step = min(batch_size, remaining)
            self.generate(node, step)
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

    def _attempt_spend(self, node, wallet, txid, vout, amount, *, expect_fail, expected_message="model-deposit-locked"):
        payout_addr = node.getnewaddress()
        spend_amount = (amount - Decimal("0.001")).quantize(Decimal("0.00000001"))
        raw = wallet.createrawtransaction(
            [{"txid": txid, "vout": vout}],
            {payout_addr: str(spend_amount)},
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert signed["complete"]
        if expect_fail:
            assert_raises_rpc_error(-26, expected_message, node.sendrawtransaction, signed["hex"])
            return None
        return node.sendrawtransaction(signed["hex"])

    def _calculate_tx_fee(self, node, txid, wallet, blockhash=None):
        tx = node.getrawtransaction(txid, True, blockhash)
        total_out = sum(Decimal(str(vout["value"])) for vout in tx.get("vout", []))
        total_in = Decimal("0")
        for vin in tx.get("vin", []):
            prev_block_hash = None
            try:
                prev_block_hash = wallet.gettransaction(vin["txid"]).get("blockhash")
            except JSONRPCException:
                prev_block_hash = None
            prev_tx = node.getrawtransaction(vin["txid"], True, prev_block_hash)
            prev_vout = prev_tx["vout"][vin["vout"]]
            total_in += Decimal(str(prev_vout["value"]))
        return (total_in - total_out).quantize(Decimal("0.00000001"))


if __name__ == "__main__":
    ModelDepositLockFunctionalTest(__file__).main()
