#!/usr/bin/env python3
"""Functional tests covering post-challenge model reuse and challenger deposit burns."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal, assert_raises_rpc_error


class ModelReuseAfterChallengeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        base_args = get_tensorcash_test_params(disable_extapi=True)
        self.wallet_names = ["challenger_wallet", False]
        self.extra_args = [
            base_args + [
                "-validationapi=mock",
                "-mockval-force-external=1",
                "-mockval-default-full=full_green",
                "-rpcdoccheck=0",
            ],
            base_args,
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        wallet_name = self.wallet_names[node] if self.wallet_names else None
        rpc = self.nodes[node]
        if not wallet_name:
            return
        rpc.createwallet(wallet_name=wallet_name)
        wallet_rpc = rpc.get_wallet_rpc(wallet_name)
        priv = rpc.get_deterministic_priv_key().key
        wallet_rpc.importprivkey(privkey=priv, label="coinbase", rescan=True)

    def run_test(self):
        node0 = self.nodes[0]
        wallet = node0.get_wallet_rpc(self.wallet_names[0])

        node0.validationmockdefault("quick", "quick_ok_smell_ok")
        node0.validationmockdefault("model", "model_ok")
        node0.validationmockdefault("full", "full_green")

        self.connect_nodes(0, 1)
        self.generate(node0, 110)
        self.sync_all()

        default_entry = self._get_default_model_entry(node0)
        default_hash = default_entry["model_hash"]

        self.log.info("Challenge_Fail keeps model registered and allows burning the challenger deposit")
        self._scenario_challenge_fail(node0, wallet, default_hash)

        self.log.info("Challenge_OK bans the model and rejects new blocks on it; challenger deposit stays locked")
        self._scenario_challenge_ok(node0, wallet, default_hash)

    def _scenario_challenge_fail(self, node, wallet, model_hash):
        node.validationmockdefault("challenge", "challenge_fail")
        ctx = self._issue_challenge(node, wallet)

        status = wallet.getmodelregistrationstatus(model_hash)
        assert_equal(status["status"], "registered")

        burn_txid = self._burn_challenge_deposit(node, ctx)
        self.generate(node, 1)
        self.sync_all()
        self._wait_confirm(node, burn_txid)
        assert burn_txid not in node.getrawmempool()

    def _scenario_challenge_ok(self, node, wallet, model_hash):
        node.validationmockdefault("challenge", "challenge_ok")
        ctx = self._issue_challenge(node, wallet)

        status = wallet.getmodelregistrationstatus(model_hash)
        assert_equal(status["status"], "banned")

        try:
            self.generate(node, 1)
            raise AssertionError("Expected mining to fail on banned model")
        except JSONRPCException as exc:
            assert "model-banned-block" in exc.error.get("message", "")

        burn_raw, prevtx = self._prepare_burn(node, ctx)
        signed = node.signrawtransactionwithwallet(burn_raw, prevtx)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "unknown-model-burn", node.sendrawtransaction, signed["hex"])

    def _issue_challenge(self, node, wallet):
        target_block = node.getbestblockhash()
        challenge = wallet.createchallengedeposit(target_block)
        txid = challenge["txid"]
        vout = challenge["deposit_vout"]
        amount = Decimal(challenge["deposit_amount"])

        challenge_block = self.generate(node, 1)[0]
        self.sync_all()
        self._wait_confirm(node, txid)

        return {
            "challenge_txid": txid,
            "challenge_vout": vout,
            "challenge_amount": amount,
            "challenge_block": challenge_block,
            "target_block": target_block,
        }

    def _burn_challenge_deposit(self, node, ctx):
        burn_raw, prevtx = self._prepare_burn(node, ctx)
        signed = node.signrawtransactionwithwallet(burn_raw, prevtx)
        assert signed["complete"]
        return node.sendrawtransaction(signed["hex"])

    def _prepare_burn(self, node, ctx):
        burn_payload = "4348414c4c454e47455f4641494c"  # "CHALLENGE_FAIL" ASCII
        burn_raw = node.createrawtransaction(
            [{"txid": ctx["challenge_txid"], "vout": ctx["challenge_vout"]}],
            [{"data": burn_payload}],
        )
        challenge_tx = node.getrawtransaction(ctx["challenge_txid"], True)
        prevtx = [{
            "txid": ctx["challenge_txid"],
            "vout": ctx["challenge_vout"],
            "scriptPubKey": challenge_tx["vout"][ctx["challenge_vout"]]["scriptPubKey"]["hex"],
            "redeemScript": "51",
            "amount": float(ctx["challenge_amount"]),
        }]
        return burn_raw, prevtx

    def _wait_confirm(self, node, txid):
        self.wait_until(lambda: node.gettransaction(txid, True, True).get("confirmations", 0) > 0)

    def _get_default_model_entry(self, node):
        models = node.getmodelslist(False)
        assert models, "models list must not be empty"
        return models[0]


if __name__ == "__main__":
    ModelReuseAfterChallengeTest(__file__).main()
