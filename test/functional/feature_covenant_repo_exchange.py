#!/usr/bin/env python3
"""Two-node repo offer/acceptance import-export workflow."""

import copy

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class CovenantRepoExchangeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1", "-assetsheight=0"] for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def run_test(self):
        borrower_node = self.nodes[0]
        lender_node = self.nodes[1]

        borrower_node.createwallet("borrower", descriptors=True)
        lender_node.createwallet("lender", descriptors=True)
        borrower = borrower_node.get_wallet_rpc("borrower")
        lender = lender_node.get_wallet_rpc("lender")

        funding_address = borrower.getnewaddress()
        self.generatetoaddress(borrower_node, 110, funding_address)
        borrower.rescanblockchain()

        maturity_height = borrower_node.getblockcount() + 15
        collateral_sats = 250_000_000
        borrower_address = borrower.getnewaddress(address_type="bech32m")
        lender_address = lender.getnewaddress(address_type="bech32m")

        # LENDER creates the offer (not borrower)
        result = lender.repo.propose({
            "principal_asset_id": "11" * 32,
            "principal_units": 1_000,
            "interest_units": 200,
            "collateral_sats": collateral_sats,
            "maturity_height": maturity_height,
            "borrower_address": borrower_address,
            "lender_address": lender_address,
        })
        offer = result["offer"]
        offer_id = result["offer_id"]

        # Lender exports the offer to share with borrower
        exported_offer = lender.repo.export_offer(offer_id)["offer"]
        assert_equal(exported_offer["id"], offer_id)

        # Test tampering detection
        tampered = copy.deepcopy(exported_offer)
        tampered["commitment"] = "00" * 32
        assert_raises_rpc_error(-8, "Offer commitment mismatch", borrower.repo.import_offer, tampered)

        # Borrower imports the lender's offer
        import_result = borrower.repo.import_offer(exported_offer)
        assert_equal(import_result["offer_id"], offer_id)
        remote_list = borrower.repo.list_offers()
        assert_equal(len(remote_list), 1)
        assert_equal(remote_list[0]["id"], offer_id)

        # Borrower accepts the lender's offer
        acceptance = borrower.repo.accept(offer_id, {"confirmed": True})
        assert "accept_id" in acceptance
        assert "acceptance" in acceptance
        borrower_status = borrower.contract.status(offer_id)
        assert_equal(borrower_status["state"], "accepted")

        exported_acceptance = acceptance["acceptance"]

        # Tamper acceptance to ensure validation fires.
        bad_accept = copy.deepcopy(exported_acceptance)
        bad_accept["salt"] = "ff" * 32
        assert_raises_rpc_error(-8, "Acceptance commitment mismatch", lender.repo.import_acceptance, bad_accept)

        # Lender imports the borrower's acceptance
        import_acceptance = lender.repo.import_acceptance(exported_acceptance)
        assert "accept_id" in import_acceptance
        assert "acceptance" in import_acceptance
        lender_status = lender.contract.status(offer_id)
        assert_equal(lender_status["state"], "accepted")

        # Re-importing the same offer on the lender side should be idempotent and keep acceptance.
        lender.repo.import_offer(exported_offer)
        lender_status_repeat = lender.contract.status(offer_id)
        assert_equal(lender_status_repeat["state"], "accepted")

        # Export after acceptance should now include acceptance fields.
        enriched_offer = borrower.repo.export_offer(offer_id)["offer"]
        assert "acceptance" in enriched_offer
        assert_equal(enriched_offer["acceptance"]["commitment"], acceptance["acceptance"]["commitment"])

        # Borrower can now build the opening PSBT after the acceptance handshake.
        borrower.syncwithvalidationinterfacequeue()
        open_result = borrower.repo.build_open(offer_id)
        assert open_result["principal_output_index"] in (-1, 0), "Principal index should be placeholder (-1) or first output (0)"
        assert open_result["covenant_output_index"] >= 0, "Covenant output index must be present"


if __name__ == "__main__":
    CovenantRepoExchangeTest(__file__).main()
