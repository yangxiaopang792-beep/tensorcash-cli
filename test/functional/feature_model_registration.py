#!/usr/bin/env python3
"""End-to-end model registration lifecycle coverage."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal, assert_raises_rpc_error


SUCCESSFUL_COMMITS_THRESHOLD = 50
MODEL_VERIFICATION_BLOCK_COUNT = 100
UNLOCK_DELAY = 10000


class ModelRegistrationFunctionalTest(BitcoinTestFramework):
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
        self.default_wallet_name = "model_registration"
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

        self.log.info("Mining spendable outputs")
        self.generate(node, 101)

        self.log.info("Scenario: splitutxo auto-select")
        self._scenario_splitutxo_auto_select(node, wallet)

        self.log.info("Scenario: successful registration")
        self._scenario_successful_registration(node, wallet)

        self.log.info("Scenario: failed verification")
        self._scenario_failed_verification(node, wallet)

        self.log.info("Scenario: pending without commits")
        self._scenario_pending_without_commit(node, wallet)

    def _scenario_splitutxo_auto_select(self, node, wallet):
        zero_txid = "0" * 64
        target_amount_sat = 1_500_000_000
        target_amount_btc = Decimal("15")
        count = 3

        assert_raises_rpc_error(
            -8,
            "target_amount_sat is required when txid is zero",
            wallet.splitutxo,
            zero_txid,
            0,
            count,
        )

        addr1 = wallet.getnewaddress()
        addr2 = wallet.getnewaddress()
        funding_txid = wallet.sendmany("", {addr1: Decimal("24"), addr2: Decimal("24")})
        self._confirm_transactions(node, funding_txid)

        split = wallet.splitutxo(zero_txid, 0, count, target_amount_sat)
        outputs = sorted(split["outputs"], key=lambda out: out["vout"])
        additional_outputs = sorted(split["additional_outputs"], key=lambda out: out["vout"])

        assert_equal(len(outputs), count)
        assert_equal(len(additional_outputs), 1)
        assert_equal(additional_outputs[0]["vout"], count)

        assert Decimal(str(outputs[0]["amount"])) > target_amount_btc
        assert_equal(Decimal(str(outputs[1]["amount"])), target_amount_btc)
        assert_equal(Decimal(str(outputs[2]["amount"])), target_amount_btc)
        assert Decimal(str(additional_outputs[0]["amount"])) > Decimal("0")

        tx = node.getrawtransaction(split["txid"], True)
        assert len(tx["vin"]) >= 2
        assert_equal(tx["vout"][count]["value"], additional_outputs[0]["amount"])
        self._confirm_transactions(node, split["txid"])

    def _scenario_successful_registration(self, node, wallet):
        node.validationmockdefault("model", "model_ok")

        model_name = "tensor/registration-success"
        model_commit = "success-commit"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        deposit_amount = Decimal(deposit["deposit_amount"])
        model_hash = deposit["model_hash"]

        self.generate(node, 1)
        status = self._wait_for_status(node, model_hash, expected="pending_deposit")
        assert_equal(status["deposit_txid"], deposit_txid)

        funding_utxos = self._prepare_commit_funding(wallet, node, exclude_txid=deposit_txid, count=SUCCESSFUL_COMMITS_THRESHOLD)
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"

        self.generate(node, 10)
        status = self._wait_for_status(node, model_hash, expected="pending_verification")
        assert_equal(status["successful_commit_count"], 10)

        verification_height = status["verification_event_height"]
        self._mine_to_height(node, verification_height)
        status = self._wait_for_status(node, model_hash, expected="registered")
        assert_equal(status["burn_txid"], "0" * 64)
        assert_equal(status["verification_code"], 0)

        unlock_height = status["deposit_block_height"] + UNLOCK_DELAY
        pre_unlock_height = max(status["deposit_block_height"], unlock_height - 2)
        self._mine_to_height(node, pre_unlock_height)
        self._attempt_spend(node, wallet, deposit_txid, deposit_vout, deposit_amount, expect_fail=True)

        self._mine_to_height(node, unlock_height)
        spend_txid = self._attempt_spend(node, wallet, deposit_txid, deposit_vout, deposit_amount, expect_fail=False)
        self._confirm_transactions(node, spend_txid)

        # assert_raises_rpc_error(-1, "Unknown model deposit", wallet.createmodelcommit, deposit_txid, deposit_vout)

    def _scenario_failed_verification(self, node, wallet):
        node.validationmockdefault("model", "model_fail")

        model_name = "tensor/registration-fail"
        model_commit = "fail-commit"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        self.generate(node, 1)
        self._wait_for_status(node, model_hash, expected="pending_deposit")

        funding_utxos = self._prepare_commit_funding(wallet, node, exclude_txid=deposit_txid, count=SUCCESSFUL_COMMITS_THRESHOLD)
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "expected commit transactions"

        self.generate(node, 10)
        status = self._wait_for_status(node, model_hash, expected="pending_deposit")
        assert_equal(status["successful_commit_count"], 0)

        verification_height = status["verification_event_height"]
        self._mine_to_height(node, verification_height)
        status = self._wait_for_status(node, model_hash, expected="locked")
        assert_equal(status["commit_txid"], "0" * 64)
        assert status["burn_txid"] != "0" * 64
        if "failure_reason" in commit_info:
            assert_equal(status["verification_code"], commit_info["failure_reason"])

        assert_raises_rpc_error(-1, "Unknown model deposit", wallet.createmodelcommit, deposit_txid, deposit_vout)

        # self._burn_model_deposit(node, wallet, model_hash)

    def _scenario_pending_without_commit(self, node, wallet):
        node.validationmockdefault("model", "model_ok")

        model_name = "tensor/registration-pending"
        model_commit = "pending-commit"
        deposit = wallet.createmodeldeposit(model_name, model_commit, 1_000_000)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]

        self.generate(node, 1)
        self._wait_for_status(node, model_hash, expected="pending_deposit")

        self.generate(node, 150)
        status = self._wait_for_status(node, model_hash, expected="locked")

        assert_raises_rpc_error(-1, "Unknown model deposit",
                                wallet.createmodelcommit, deposit_txid, deposit_vout)

        other_wallet_name = "model_registration_other"
        node.createwallet(wallet_name=other_wallet_name)
        other_wallet = node.get_wallet_rpc(other_wallet_name)
        assert_raises_rpc_error(-1, "Unknown model deposit",
                                other_wallet.createmodelcommit, deposit_txid, deposit_vout)

        # self._burn_model_deposit(node, wallet, model_hash, status_hint=status)

    def _burn_model_deposit(self, node, wallet, model_hash, *, status_hint=None):
        status = status_hint or self._wait_for_status(node, model_hash)
        burn_height = status["burn_allowed_height"]
        self._mine_to_height(node, burn_height)
        burn_info = wallet.createmodelburn(model_hash, True)
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

    def _attempt_spend(self, node, wallet, txid, vout, amount, *, expect_fail):
        payout_addr = node.getnewaddress()
        spend_amount = (amount - Decimal("0.001")).quantize(Decimal("0.00000001"))
        raw = wallet.createrawtransaction(
            [{"txid": txid, "vout": vout}],
            {payout_addr: str(spend_amount)},
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert signed["complete"]
        if expect_fail:
            assert_raises_rpc_error(-26, "model-deposit-locked", node.sendrawtransaction, signed["hex"])
            return None
        return node.sendrawtransaction(signed["hex"])


if __name__ == "__main__":
    ModelRegistrationFunctionalTest(__file__).main()
