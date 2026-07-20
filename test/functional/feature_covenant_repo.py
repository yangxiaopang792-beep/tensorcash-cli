#!/usr/bin/env python3
"""Wallet-driven repo covenant happy paths (native principal)."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.address import address_to_scriptpubkey
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.psbt import PSBT


def finalize_psbt(wallet, psbt_b64: str, *, repo_offer_id=None) -> str:
    def try_repo_fallback():
        if repo_offer_id is None:
            return None
        signed = wallet.repo.sign_default_sweep(repo_offer_id, psbt_b64)
        hex_tx = signed.get("hex")
        assert hex_tx, "repo.sign_default_sweep did not return hex"
        return hex_tx

    try:
        processed = wallet.walletprocesspsbt(psbt_b64, sign=True, sighashtype="DEFAULT")
    except JSONRPCException as exc:
        message = exc.error.get("message", "")
        if "multiple asset ids" not in message:
            repo_hex = try_repo_fallback()
            if repo_hex is not None:
                return repo_hex
            raise
        try:
            processed = wallet.walletprocesspsbt(psbt_b64, sign=False, sighashtype="DEFAULT")
            psbt_with_witness = processed["psbt"]
            finalized = wallet.finalizepsbt(psbt_with_witness, extract=True)
            if finalized["complete"]:
                return finalized["hex"]
            raw_hex = finalized.get("hex")
            if not raw_hex:
                psbt_obj = PSBT.from_base64(psbt_with_witness)
                raw_hex = psbt_obj.tx.serialize().hex()
            signed = wallet.signrawtransactionwithwallet(raw_hex)
            if not signed["complete"]:
                print(f"Warning: Multi-asset transaction not fully signed, errors: {signed.get('errors', [])}")
            return signed["hex"]
        except Exception:
            psbt_obj = PSBT.from_base64(psbt_b64)
            raw_hex = psbt_obj.tx.serialize().hex()
            signed = wallet.signrawtransactionwithwallet(raw_hex)
            if not signed["complete"]:
                print(f"Warning: Multi-asset transaction not fully signed, errors: {signed.get('errors', [])}")
            return signed["hex"]

    final = wallet.finalizepsbt(processed["psbt"], extract=True)
    if final.get("complete"):
        return final["hex"]

    repo_hex = try_repo_fallback()
    if repo_hex is not None:
        return repo_hex

    assert final.get("complete"), "Unable to finalize PSBT"
    return final["hex"]


def sign_psbt(wallet, psbt_b64: str) -> dict:
    return wallet.walletprocesspsbt(psbt_b64, sign=True, sighashtype="DEFAULT")


class CovenantRepoWalletFlowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def _init_wallets(self):
        node = self.nodes[0]
        node.createwallet("borrower", descriptors=True)
        node.createwallet("lender", descriptors=True)
        borrower = node.get_wallet_rpc("borrower")
        lender = node.get_wallet_rpc("lender")

        mini = MiniWallet(node)
        self.generate(mini, 101)

        # Initial funding so both wallets can pay fees/collateral.
        for wallet in (borrower, lender):
            addr = wallet.getnewaddress()
            tx = mini.create_self_transfer()
            tx["tx"].vout[0].scriptPubKey = address_to_scriptpubkey(addr)
            tx["tx"].rehash()
            mini.sendrawtransaction(from_node=node, tx_hex=tx["tx"].serialize().hex())
            self.generate(node, 1)
            wallet.rescanblockchain()

        return borrower, lender

    def _propose_and_accept(self, borrower, lender, *, collateral_sats: int, principal_sats: int, interest_sats: int, maturity_delta: int):
        node = self.nodes[0]
        borrower_spk = borrower.getnewaddress(address_type="bech32m")
        lender_spk = lender.getnewaddress(address_type="bech32m")

        # LENDER creates the offer (not borrower)
        result = lender.repo.propose({
            "principal_is_native": True,
            "principal_units": principal_sats,
            "interest_units": interest_sats,
            "collateral_sats": collateral_sats,
            "maturity_height": node.getblockcount() + maturity_delta,
            "borrower_address": borrower_spk,
            "lender_address": lender_spk,
        })

        offer_id = result["offer_id"]
        offer = result["offer"]
        # Borrower imports and accepts the lender's offer
        borrower.repo.import_offer(offer)
        acceptance = borrower.repo.accept(offer_id, {"confirmed": True})
        # Lender imports the borrower's acceptance
        lender.repo.import_acceptance(acceptance["acceptance"])
        return offer_id, offer, acceptance

    def _open_contract(self, wallet, offer_id: str):
        node = self.nodes[0]
        wallet.syncwithvalidationinterfacequeue()
        open_result = wallet.repo.build_open(offer_id)

        # Handle both hot wallet (returns hex) and watch-only wallet (returns psbt)
        if "hex" in open_result:
            # Hot wallet - already signed and complete
            raw_hex = open_result["hex"]
        else:
            # Watch-only wallet - needs signing
            raw_hex = finalize_psbt(wallet, open_result["psbt"])

        txid = node.sendrawtransaction(raw_hex)
        self.generate(node, 1)
        wallet.syncwithvalidationinterfacequeue()
        decoded = node.decoderawtransaction(raw_hex)
        return txid, open_result, decoded

    def _repay_release(self, borrower, offer_id: str, vault_txid: str, vault_vout: int, vault_amount_btc: Decimal):
        node = self.nodes[0]
        borrower.syncwithvalidationinterfacequeue()
        build = borrower.repo.build_repay_release(offer_id, {
            "vault_txid": vault_txid,
            "vault_vout": vault_vout,
            "vault_amount": f"{vault_amount_btc:.8f}",
        })

        # Handle both hot wallet (returns hex) and watch-only wallet (returns psbt)
        if "hex" in build:
            # Hot wallet - already signed and complete
            raw_decoded = node.decoderawtransaction(build["hex"])
            # Wrap in {"tx": ...} format to match decodepsbt structure
            decoded_psbt = {"tx": raw_decoded}
            processed = {"psbt": None, "complete": True, "hex": build["hex"]}
        else:
            # Watch-only wallet - needs signing
            processed = sign_psbt(borrower, build["psbt"])
            decoded_psbt = node.decodepsbt(processed["psbt"])

        return build, processed, decoded_psbt

    def _default_sweep(self, lender, offer_id: str, vault_txid: str, vault_vout: int, vault_amount_btc: Decimal):
        node = self.nodes[0]
        lender.syncwithvalidationinterfacequeue()
        build = lender.repo.build_default_sweep(offer_id, {
            "vault_txid": vault_txid,
            "vault_vout": vault_vout,
            "vault_amount": f"{vault_amount_btc:.8f}",
        })

        # Handle both hot wallet (returns hex) and watch-only wallet (returns psbt)
        if "hex" in build:
            # Hot wallet - already signed and complete
            raw_decoded = node.decoderawtransaction(build["hex"])
            # Wrap in {"tx": ...} format to match decodepsbt structure
            decoded_psbt = {"tx": raw_decoded}
            processed = {"psbt": None, "complete": True, "hex": build["hex"]}
        else:
            # Watch-only wallet - needs signing
            processed = sign_psbt(lender, build["psbt"])
            decoded_psbt = node.decodepsbt(processed["psbt"])

        return build, processed, decoded_psbt

    def run_test(self):
        borrower, lender = self._init_wallets()
        node = self.nodes[0]

        collateral_sats = 2 * COIN
        principal_sats = 100_000_000  # 1 BTC
        interest_sats = 10_000_000    # 0.1 BTC

        # --- Repay path ---
        offer_id, offer, acceptance = self._propose_and_accept(
            borrower,
            lender,
            collateral_sats=collateral_sats,
            principal_sats=principal_sats,
            interest_sats=interest_sats,
            maturity_delta=20,
        )

        open_txid, open_result, decoded_open = self._open_contract(borrower, offer_id)

        covenant_index = open_result["covenant_output_index"]
        vault_vout = decoded_open["vout"][covenant_index]
        assert_equal(vault_vout["scriptPubKey"]["type"], "witness_v1_taproot")
        vault_amount = Decimal(str(vault_vout["value"]))
        assert_equal(int(vault_amount * COIN), collateral_sats)

        repay_build, repay_processed, repay_decoded = self._repay_release(
            borrower,
            offer_id,
            open_txid,
            covenant_index,
            vault_amount,
        )

        repay_vout = repay_decoded["tx"]["vout"][repay_build["repay_output_index"]]
        repay_value = Decimal(str(repay_vout["value"]))
        expected_repay = Decimal(principal_sats + interest_sats) / COIN
        assert_equal(repay_value, expected_repay)

        # After opening the contract, state is "opened" (not "accepted")
        status = borrower.contract.status(offer_id)
        assert_equal(status["state"], "opened")
        assert_equal(status["offer"]["vault"]["txid"], open_txid)

        # --- Default sweep path ---
        offer_id2, offer2, acceptance2 = self._propose_and_accept(
            borrower,
            lender,
            collateral_sats=collateral_sats,
            principal_sats=principal_sats,
            interest_sats=interest_sats,
            maturity_delta=12,
        )

        open_txid2, open_result2, decoded_open2 = self._open_contract(borrower, offer_id2)
        covenant_index2 = open_result2["covenant_output_index"]
        vault_vout2 = decoded_open2["vout"][covenant_index2]
        vault_amount2 = Decimal(str(vault_vout2["value"]))

        maturity_height = offer2["terms"]["maturity_height"]
        blocks_to_maturity = maturity_height - node.getblockcount()
        if blocks_to_maturity > 0:
            self.generate(node, blocks_to_maturity)

        reorg_conf = offer2["terms"]["reorg_conf"]
        if reorg_conf > 0:
            self.generate(node, reorg_conf)

        sweep_build, sweep_processed, sweep_decoded = self._default_sweep(
            lender,
            offer_id2,
            open_txid2,
            covenant_index2,
            vault_amount2,
        )

        sweep_output = sweep_decoded["tx"]["vout"][sweep_build["sweep_output_index"]]
        sweep_value = Decimal(str(sweep_output["value"]))
        assert_greater_than(sweep_value, Decimal(0))


if __name__ == "__main__":
    CovenantRepoWalletFlowTest(__file__).main()
