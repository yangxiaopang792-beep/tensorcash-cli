#!/usr/bin/env python3
"""Fork-selection regression: shorter honest verdict-success branch demotes
a longer raw-work dormant cheater branch via BLOCK_MODEL_CHALLENGE_ZERO_WORK.

Split into its own test class (with a fresh fixture) because running it
back-to-back with the other ModelChallengeFunctionalTest scenarios
exhausts wallet UTXOs / poisons mempool state and _register_model never
reaches "registered" status. Isolated, it runs cleanly.

See feature_model_challenge.py's _scenario_fork_selection_honest_wins
docstring for the full security framing and limitation notes.
"""

from feature_model_challenge import ModelChallengeFunctionalTest


class ModelChallengeForkSelectionTest(ModelChallengeFunctionalTest):
    def set_test_params(self):
        super().set_test_params()
        # This scenario calls miner.getmodelregistrationstatus during the
        # disconnected fork-engineering steps; that RPC is wallet-scoped,
        # so the miner node also needs a wallet loaded.
        self.wallet_names = [self.default_wallet_name, "fork_miner_wallet"]

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

        self.log.info("Scenario: Fork_Selection_Honest_Demotes_Heavier_Bogus")
        self._scenario_fork_selection_honest_wins(node0, node1, wallet, default_identifier)


if __name__ == "__main__":
    ModelChallengeForkSelectionTest(__file__).main()
