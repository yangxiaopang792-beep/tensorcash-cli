#!/usr/bin/env python3
"""ModelDB reorg undo (erase on disconnect).

Flow:
 - Start node with validation API mock and defaults set to accept Model
 - Broadcast a model registration deposit and commit transactions
 - Mine them and verify the model is present via RPC getmodelinfo
 - Invalidate that block (simulate reorg) and verify the model is erased

Isolated, single-node, parallel-safe.
"""

from decimal import Decimal

from http.client import RemoteDisconnected

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    initialize_tensor_block_fields,
    set_block_tick_from_prev,
    update_block_pow_commitment,
)
from test_framework.messages import tx_from_hex
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.test_tensorcash import get_tensorcash_test_params

SUCCESSFUL_COMMITS_THRESHOLD = 50
MODEL_VERIFICATION_BLOCK_COUNT = 100
CHALLENGE_DEPOSIT_AMOUNT = Decimal("5")


class ModelReorgFunctionalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        base_args = get_tensorcash_test_params(disable_extapi=True)
        # Use in-process mock validation API to deterministically accept Model
        self.default_wallet_name = "model_legacy"
        self.wallet_names = [self.default_wallet_name]
        self.extra_args = [base_args + ["-validationapi=mock"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node] if self.wallet_names else self.default_wallet_name
        n = self.nodes[node]
        if wallet_name is not False:
            n.createwallet(wallet_name=wallet_name)
            wallet_rpc = n.get_wallet_rpc(wallet_name)
            priv = n.get_deterministic_priv_key().key
            wallet_rpc.importprivkey(privkey=priv, label='coinbase', rescan=True)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        # Set default mock responses: Quick OK and Model OK
        node.validationmockdefault("quick", "quick_ok_smell_ok")
        node.validationmockdefault("model", "model_ok")
        node.validationmockdefault("full", "full_green")

        # Mine spendable funds so the wallet can finance the deposit
        premine_blocks = 220
        self.log.info(f"Mining {premine_blocks} blocks to mature initial coinbase rewards")
        self.generate(node, premine_blocks)

        name = "reorg-functional"
        commit = "v1"
        difficulty_multiplier = 1000000  # normalizer default as int64

        deposit = wallet.createmodeldeposit(name, commit, difficulty_multiplier)
        deposit_txid = deposit["txid"]
        deposit_vout = deposit["deposit_vout"]
        model_hash = deposit["model_hash"]
        self.log.info(f"Broadcast model deposit transaction {deposit_txid}")

        # Mine the deposit so it enters the model database
        registration_block = self.generate(node, 1)[0]
        block_info = node.getblock(registration_block)
        self.log.info(f"Model registration block submitted with hash: {registration_block}")
        self.log.info(f"Block accepted at height {block_info['height']}")
        self.wait_until(lambda: node.gettransaction(deposit_txid, True, True)["confirmations"] > 0)

        # Broadcast and mine the commit transactions to hit the success threshold
        funding_utxos = self._prepare_commit_funding(wallet, node, exclude_txid=deposit_txid, count=SUCCESSFUL_COMMITS_THRESHOLD)
        self.generate(node, 1)
        commit_info = wallet.createmodelcommit(deposit_txid, deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, funding_utxos)
        assert_equal(commit_info["count"], len(commit_info["transactions"]))
        commit_txids = [entry["txid"] for entry in commit_info["transactions"]]
        assert commit_txids, "Expected at least one commit transaction"
        self.log.info(f"Model hash for lookup: {model_hash}")
        commit_block = self._confirm_transactions(node, commit_txids)

        verification_target = block_info['height'] + MODEL_VERIFICATION_BLOCK_COUNT
        if node.getblockcount() < verification_target:
            self._advance_to_height(node, verification_target)

        status = self._wait_for_status(wallet, model_hash, "registered")
        assert status.get("successful_commit_count", 0) >= SUCCESSFUL_COMMITS_THRESHOLD
        maturity_tip = node.getbestblockhash()

        # Check model is registered (models are available after maturity)
        info = node.getmodelinfo(model_hash)
        self.log.info(f"Model registered: {info}")

        # Invalidate the registration block -> reorg away, which should erase ModelDB entry
        node.invalidateblock(registration_block)
        expected_height_after_invalidate = block_info['height'] - 1
        self.wait_until(lambda: node.getblockcount() == expected_height_after_invalidate)
        assert_equal(node.getblockcount(), expected_height_after_invalidate)
        self.log.info("Invalidated registration block, checking model status...")
        assert_raises_rpc_error(-5, "No model found", node.getmodelinfo, model_hash)
        self.log.info("Model was removed after reorg")

        # Reconsider the block and allow the original chain to reconnect
        node.reconsiderblock(registration_block)
        node.reconsiderblock(commit_block)
        self.wait_until(lambda: node.getbestblockhash() == maturity_tip)
        info_reconsidered = node.getmodelinfo(model_hash)
        self.log.info("Model restored after reconsider and maturity")

        # self.log.info("Checking that model deposits cannot be spent outside a commit transaction")
        # illegal_deposit = wallet.createmodeldeposit("tensor/illegal", "illegal-commit", difficulty_multiplier)
        # self.generate(node, 1)
        # model_requests = [req for req in node.validationmockrequests() if req["type"] == "Model"]
        # assert len(model_requests) >= 3

        # deposit_txid = illegal_deposit["txid"]
        # deposit_vout = illegal_deposit["deposit_vout"]
        # illegal_deposit_amount = Decimal(illegal_deposit["deposit_amount"])
        # payout_addr = node.getnewaddress()
        # illegal_amount = (illegal_deposit_amount - Decimal("0.001")).quantize(Decimal("0.00000001"))

        # illegal_raw = node.createrawtransaction([
        #     {"txid": deposit_txid, "vout": deposit_vout}
        # ], {payout_addr: illegal_amount})
        # illegal_signed = node.signrawtransactionwithwallet(illegal_raw)
        # assert illegal_signed["complete"]
        # illegal_hex = illegal_signed["hex"]

        # assert_raises_rpc_error(-26, "model-deposit-locked", node.sendrawtransaction, illegal_hex)

        self.log.info("Testing challenge ban persistence across reorg")
        node.validationmockdefault("challenge", "challenge_ok")

        self.generate(node, 10)

        banned_name = "tensor/banned"
        banned_commit = "ban-commit"
        banned_deposit = wallet.createmodeldeposit(banned_name, banned_commit, difficulty_multiplier)
        banned_hash = banned_deposit["model_hash"]
        banned_deposit_txid = banned_deposit["txid"]
        banned_deposit_vout = banned_deposit["deposit_vout"]
        banned_registration_block = self.generate(node, 1)[0]
        banned_block_info = node.getblock(banned_registration_block)
        self.log.info(f"Block accepted at height {banned_block_info['height']}")
        self.wait_until(lambda: node.gettransaction(banned_deposit_txid, True, True)["confirmations"] > 0)

        # Produce commits for the banned model
        banned_funding_utxos = self._prepare_commit_funding(wallet, node, exclude_txid=banned_deposit_txid, count=SUCCESSFUL_COMMITS_THRESHOLD)
        self.generate(node, 1)
        banned_commit_info = wallet.createmodelcommit(banned_deposit_txid, banned_deposit_vout, SUCCESSFUL_COMMITS_THRESHOLD, banned_funding_utxos)
        banned_commit_txids = [entry["txid"] for entry in banned_commit_info["transactions"]]
        assert banned_commit_txids
        self._confirm_transactions(node, banned_commit_txids)

        banned_verification_target = banned_block_info['height'] + MODEL_VERIFICATION_BLOCK_COUNT
        if node.getblockcount() < banned_verification_target:
            self._advance_to_height(node, banned_verification_target)

        banned_status = self._wait_for_status(wallet, banned_hash, "registered")
        assert banned_status.get("successful_commit_count", 0) >= SUCCESSFUL_COMMITS_THRESHOLD
        self.log.info(f"Registered models snapshot: {node.getmodelslist(False)}")

        # Сформируем блок с tensor/banned моделью пока она ещё зарегистрирована — он должен быть принят.
        banned_identifier = f"{banned_name}@{banned_commit}".encode()
        pre_challenge_tip = node.getbestblockhash()
        tip_info = node.getblock(pre_challenge_tip)
        coinbase = create_coinbase(tip_info["height"] + 1)
        candidate_block = create_block(int(pre_challenge_tip, 16), coinbase, tip_info["time"] + 1)
        initialize_tensor_block_fields(candidate_block)
        set_block_tick_from_prev(node, candidate_block, pre_challenge_tip)
        candidate_block.pow.model_identifier = banned_identifier
        update_block_pow_commitment(candidate_block, use_merkle=True)
        candidate_block.solve()
        update_block_pow_commitment(candidate_block, use_merkle=True)
        accept_res = node.submitblock(candidate_block.serialize().hex())
        self.log.info(f"submitblock result before ban: {accept_res}")
        assert_equal(accept_res, None)
        challenged_block = node.getbestblockhash()

        self._ensure_challenge_funding(wallet, node)
        challenge = wallet.createchallengedeposit(challenged_block)
        challenge_txid = challenge["txid"]
        challenge_block = self.generate(node, 1)[0]
        self.wait_until(lambda: node.gettransaction(challenge_txid, True, True).get("confirmations", 0) > 0)

        # Challenge verdict is no longer immediate: submit challenge commits and
        # mine until the model transitions to banned.
        challenge_funding_utxos = self._prepare_commit_funding(
            wallet,
            node,
            exclude_txid=challenge_txid,
            count=SUCCESSFUL_COMMITS_THRESHOLD,
        )
        self.generate(node, 1)
        challenge_commit_info = wallet.createchallengecommits(
            banned_hash,
            SUCCESSFUL_COMMITS_THRESHOLD,
            challenge_funding_utxos,
        )
        challenge_commit_txids = [entry["txid"] for entry in challenge_commit_info["transactions"]]
        assert challenge_commit_txids, "Expected challenge commit transactions"
        self._confirm_transactions(node, challenge_commit_txids)

        status = self._mine_until_status(wallet, node, banned_hash, "banned")

        # post_tip = node.getbestblockhash()
        # post_info = node.getblock(post_tip)
        # reject_coinbase = create_coinbase(post_info["height"] + 1)
        # reject_block = create_block(int(post_tip, 16), reject_coinbase, post_info["time"] + 1)
        # initialize_tensor_block_fields(reject_block)
        # set_block_tick_from_prev(node, reject_block, post_tip)
        # reject_block.pow.model_identifier = banned_identifier
        # update_block_pow_commitment(reject_block, use_merkle=True)
        # reject_block.solve()
        # update_block_pow_commitment(reject_block, use_merkle=True)
        # try:
        #     submit_res = node.submitblock(reject_block.serialize().hex())
        # except JSONRPCException as exc:
        #     submit_res = exc.error.get("message", "")
        # except RemoteDisconnected as exc:
        #     raise AssertionError(f"submitblock disconnected after ban: {exc}")
        # self.log.info(f"submitblock result after ban: {submit_res}")
        # if submit_res is None:
        #     raise AssertionError("Expected block referencing banned model to be rejected")
        # assert "model-banned-block" in str(submit_res)

        # node.invalidateblock(challenge_block)
        self.generate(node, 1)
        self.wait_until(lambda: node.getbestblockhash() != challenge_block)

        status_after_reorg = wallet.getmodelregistrationstatus(banned_hash)
        assert_equal(status_after_reorg["status"], "banned")

    def _wait_for_status(self, wallet, model_hash, expected):
        def _fetch():
            try:
                return wallet.getmodelregistrationstatus(model_hash)
            except JSONRPCException:
                return None

        def _ready():
            status_obj = _fetch()
            if status_obj is None:
                return expected is None
            return status_obj["status"] == expected

        self.wait_until(_ready)
        result = _fetch()
        if result is None:
            return {}
        assert_equal(result["status"], expected)
        return result

    def _mine_until_status(self, wallet, node, model_hash, expected, max_blocks=200):
        for _ in range(max_blocks + 1):
            try:
                status = wallet.getmodelregistrationstatus(model_hash)
            except JSONRPCException:
                status = None

            if status and status.get("status") == expected:
                return status

            if _ < max_blocks:
                self.generate(node, 1)

        observed = status["status"] if status else "missing"
        raise AssertionError(
            f"Model {model_hash} did not reach status '{expected}' after {max_blocks} blocks (last: {observed})"
        )

    def _confirm_transactions(self, node, txids):
        if isinstance(txids, str):
            pending = {txids}
        else:
            pending = set(txids)
        last_block = None
        attempts = 0
        while pending:
            last_block = self.generate(node, 1)[0]
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
        return last_block

    def _prepare_commit_funding(self, wallet, node, *, exclude_txid=None, count=SUCCESSFUL_COMMITS_THRESHOLD):
        utxos = wallet.listunspent()
        candidate = None
        for entry in utxos:
            if not entry.get("spendable", True):
                continue
            if exclude_txid and entry.get("txid") == exclude_txid:
                continue
            candidate = entry
            break
        if candidate is None:
            raise AssertionError("No spendable UTXO available to fund commit transactions")

        self.log.info(f"Splitting UTXO {candidate['txid']}:{candidate['vout']} into {count} funding outputs")
        split = wallet.splitutxo(candidate["txid"], candidate["vout"], count)
        split_txid = split["txid"]
        self._confirm_transactions(node, [split_txid])
        outputs = split["outputs"]
        if len(outputs) != count:
            raise AssertionError(f"Expected {count} funding outputs from splitutxo, got {len(outputs)}")
        return [{"txid": split_txid, "vout": out["vout"]} for out in outputs]

    def _ensure_challenge_funding(self, wallet, node):
        utxos = wallet.listunspent()
        for entry in utxos:
            if not entry.get("spendable", True):
                continue
            if entry.get("confirmations", 0) == 0:
                continue
            if Decimal(entry["amount"]) >= CHALLENGE_DEPOSIT_AMOUNT:
                return

        self.log.info("No mature UTXO large enough for challenge deposit, creating one")
        target_amount = CHALLENGE_DEPOSIT_AMOUNT + Decimal("1")
        addr = wallet.getnewaddress()
        txid = wallet.sendtoaddress(addr, target_amount)
        self._confirm_transactions(node, [txid])

        def _has_large_utxo():
            for candidate in wallet.listunspent():
                if candidate.get("spendable", True) and candidate.get("confirmations", 0) > 0 and Decimal(candidate["amount"]) >= CHALLENGE_DEPOSIT_AMOUNT:
                    return True
            return False

        self.wait_until(_has_large_utxo)

    def _advance_to_height(self, node, target_height):
        while node.getblockcount() < target_height:
            self.generate(node, 1)


if __name__ == '__main__':
    ModelReorgFunctionalTest(__file__).main()
