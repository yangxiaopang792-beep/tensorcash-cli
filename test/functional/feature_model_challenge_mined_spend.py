#!/usr/bin/env python3
"""Block-level (ConnectBlock) rejection of a mined tx that spends a
slashed challenge_deposit outpoint.

Counterpart to the mempool-level rejection covered in
feature_model_challenge.py's Challenge_Fail scenarios. Manually
constructs a block via create_block + tensorcash field helpers,
includes the SENTINEL-spending tx, submits via submitblock, asserts
"challenge-deposit-burned" in the rejection reason.

Split into its own test class with a fresh fixture for the same reason
as feature_model_challenge_fork_selection.py.
"""

from feature_model_challenge import ModelChallengeFunctionalTest


class ModelChallengeMinedSpendRejectedTest(ModelChallengeFunctionalTest):
    def set_test_params(self):
        super().set_test_params()

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

        self.log.info("Scenario: Mined_Slashed_Deposit_Spend_Rejected_At_Connect")
        self._scenario_mined_slashed_spend_rejected(node0, node1, wallet, default_identifier)


if __name__ == "__main__":
    ModelChallengeMinedSpendRejectedTest(__file__).main()
