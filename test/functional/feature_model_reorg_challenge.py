#!/usr/bin/env python3
"""Functional test for challenge reorg persistence.

Ensures a successful challenge keeps the model banned and burn bookkeeping
intact even if the containing block is disconnected by a reorg.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal


class ModelReorgChallengePersistenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.wallet_names = ["reorg_challenge_wallet"]
        self.extra_args = [
            base_args + [
                "-validationapi=mock",
                "-mockval-force-external=1",
                "-mockval-default-full=full_green",
                "-rpcdoccheck=0",
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node]
        rpc = self.nodes[node]
        rpc.createwallet(wallet_name=wallet_name)
        wallet_rpc = rpc.get_wallet_rpc(wallet_name)
        priv = rpc.get_deterministic_priv_key().key
        wallet_rpc.importprivkey(privkey=priv, label="coinbase", rescan=True)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.wallet_names[0])

        node.validationmockdefault("quick", "quick_ok_smell_ok")
        node.validationmockdefault("model", "model_ok")
        node.validationmockdefault("full", "full_green")

        self.generate(node, 110)

        default_entry = self._get_default_model_entry(node)
        model_hash = default_entry["model_hash"]

        baseline_status = wallet.getmodelregistrationstatus(model_hash)
        assert_equal(baseline_status["status"], "registered")

        node.validationmockdefault("challenge", "challenge_ok")
        ctx = self._issue_challenge(node, wallet)

        banned_status = wallet.getmodelregistrationstatus(model_hash)
        assert_equal(banned_status["status"], "banned")

        burn_snapshot = node.gettxout(banned_status["burn_txid"], banned_status["burn_vout"])
        assert burn_snapshot is not None, "Burn outpoint must remain indexed"
        assert Decimal(str(burn_snapshot["value"])) == ctx["challenge_amount"]
        assert banned_status["burn_block_height"] > 0

        node.invalidateblock(ctx["challenge_block"])
        self.wait_until(lambda: node.getbestblockhash() != ctx["challenge_block"])

        post_reorg_status = wallet.getmodelregistrationstatus(model_hash)
        assert_equal(post_reorg_status["status"], "banned")
        assert_equal(post_reorg_status["burn_txid"], banned_status["burn_txid"])
        assert_equal(post_reorg_status["burn_vout"], banned_status["burn_vout"])
        assert_equal(post_reorg_status["burn_block_height"], banned_status["burn_block_height"])
        assert_equal(post_reorg_status["deposit_txid"], banned_status["deposit_txid"])
        assert_equal(post_reorg_status["deposit_vout"], banned_status["deposit_vout"])

        burn_after_reorg = node.gettxout(post_reorg_status["burn_txid"], post_reorg_status["burn_vout"])
        assert burn_after_reorg == burn_snapshot, "Burn UTXO view must persist across reorg"

        try:
            self.generate(node, 1)
            raise AssertionError("Expected mining to fail on banned model after reorg")
        except JSONRPCException as exc:
            assert "model-banned-block" in exc.error.get("message", "")

    def _issue_challenge(self, node, wallet):
        target_block = node.getbestblockhash()
        challenge = wallet.createchallengedeposit(target_block)
        txid = challenge["txid"]
        vout = challenge["deposit_vout"]
        amount = Decimal(challenge["deposit_amount"])

        challenge_block = self.generate(node, 1)[0]
        self._wait_confirm(node, txid)

        return {
            "challenge_txid": txid,
            "challenge_vout": vout,
            "challenge_amount": amount,
            "challenge_block": challenge_block,
            "target_block": target_block,
        }

    def _wait_confirm(self, node, txid):
        self.wait_until(lambda: node.gettransaction(txid, True, True).get("confirmations", 0) > 0)

    def _get_default_model_entry(self, node):
        models = node.getmodelslist(False)
        assert models, "models list must not be empty"
        return models[0]


if __name__ == "__main__":
    ModelReorgChallengePersistenceTest(__file__).main()
