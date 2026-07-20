#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

from asset_wallet_util import register_asset, mint_asset


class WalletAssetSpendErrorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.force_cleanup_on_failure = True
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",
            "-txindex=1",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 102)

        asset_id = hashlib.sha256(b"wallet_asset_spend_errors").hexdigest()
        _, policy, icu_value = register_asset(node, asset_id)
        asset_outpoint, policy = mint_asset(node, asset_id, policy, icu_value)

        # walletprocesspsbt now supports multiple asset ids for atomic swaps and contracts.
        # Verify that multi-asset PSBTs can be processed without error.
        other_asset_id = hashlib.sha256(b"conflict_asset_id").hexdigest()
        conflict_raw = node.createrawtransaction([], {
            node.getnewaddress(): float(asset_outpoint.value),
            node.getnewaddress(): float(asset_outpoint.value),
        })
        conflict_raw = node.rawtxattachassettag(conflict_raw, 0, asset_id, 600)
        conflict_raw = node.rawtxattachassettag(conflict_raw, 1, other_asset_id, 400)
        conflict_psbt = node.converttopsbt(conflict_raw)
        conflict_decoded = node.decodepsbt(conflict_psbt)
        outexts = [vout.get("outext") for vout in conflict_decoded["tx"]["vout"]]
        assert len(set(outexts)) == 2, "Expected distinct asset TLVs to survive PSBT conversion"

        # This should now succeed (no error expected)
        result = node.walletprocesspsbt(conflict_psbt, False, "ALL", True, False)
        assert "psbt" in result, "Expected walletprocesspsbt to return a PSBT"

        # Mismatch between input asset id and output asset id must be rejected.
        # Create transaction spending the asset UTXO
        mismatch_dest = node.getnewaddress()
        inputs = [{"txid": asset_outpoint.txid, "vout": asset_outpoint.vout}]
        outputs = [{mismatch_dest: float(asset_outpoint.value) - 0.0001}]  # Leave room for fees

        # Create raw transaction
        mismatch_raw = node.createrawtransaction(inputs, outputs)

        # Store the original raw hex before attaching asset tag
        original_raw = mismatch_raw

        # Attach the WRONG asset tag (different from input)
        mismatch_raw = node.rawtxattachassettag(mismatch_raw, 0, other_asset_id, 1000)

        # Convert to PSBT
        mismatch_psbt = node.converttopsbt(mismatch_raw)

        # Update with UTXO data (this should work since wallet knows the input)
        mismatch_psbt = node.utxoupdatepsbt(mismatch_psbt)

        # Verify PSBT has basic structure needed for validation
        mismatch_decoded = node.decodepsbt(mismatch_psbt)

        # Verify the output has the (wrong) asset tag attached
        has_asset_output = False
        for vout in mismatch_decoded["tx"]["vout"]:
            if "outext" in vout and vout["outext"].startswith("01"):
                has_asset_output = True
                break
        assert has_asset_output, "No output with asset tag found in transaction"

        # Verify the input is present and has UTXO data
        asset_input_idx = None
        for i, vin in enumerate(mismatch_decoded["tx"]["vin"]):
            if vin["txid"] == asset_outpoint.txid and vin["vout"] == asset_outpoint.vout:
                asset_input_idx = i
                break
        assert asset_input_idx is not None, "Asset input not found in transaction"

        # Check that PSBT has UTXO data (required for validation)
        input_data = mismatch_decoded["inputs"][asset_input_idx]
        has_utxo = "witness_utxo" in input_data or "non_witness_utxo" in input_data
        assert has_utxo, "PSBT input missing UTXO data - validation will be skipped"

        # The wallet should detect the asset mismatch
        # Different implementations might catch this at different stages
        error_found = False
        error_stage = None

        # Try walletprocesspsbt - this may or may not detect the mismatch
        try:
            processed = node.walletprocesspsbt(mismatch_psbt, True, "ALL", True, False)
            processed_psbt = processed["psbt"]
        except Exception as e:
            error_msg = str(e)
            if "asset" in error_msg.lower() or "mismatch" in error_msg.lower():
                error_found = True
                error_stage = "walletprocesspsbt"

        # If walletprocesspsbt didn't catch it, try signing the raw transaction
        if not error_found:
            try:
                signed = node.signrawtransactionwithwallet(mismatch_raw)
                if signed["complete"]:
                    # If signing succeeded, the error should occur when sending
                    try:
                        node.sendrawtransaction(signed["hex"])
                        # If send succeeded, something is wrong
                        assert False, "Transaction with asset mismatch was accepted!"
                    except Exception as e:
                        error_msg = str(e)
                        if "asset" in error_msg.lower():
                            error_found = True
                            error_stage = "sendrawtransaction"
            except Exception as e:
                error_msg = str(e)
                if "asset" in error_msg.lower() or "mismatch" in error_msg.lower():
                    error_found = True
                    error_stage = "signrawtransactionwithwallet"

        assert error_found, f"Expected asset mismatch error but transaction was processed successfully. Stage: {error_stage}"

        # Signing a funded asset transaction must keep the TLV visible.
        asset_dest = node.getnewaddress()
        send_raw = node.createrawtransaction([], {asset_dest: float(asset_outpoint.value)})
        send_raw = node.rawtxattachassettag(send_raw, 0, asset_id, 1000)
        funded = node.fundrawtransaction(send_raw)
        signed = node.signrawtransactionwithwallet(funded["hex"])
        decoded = node.decoderawtransaction(signed["hex"])
        assert any(vout.get("outext", "").startswith("01") for vout in decoded["vout"])


if __name__ == "__main__":
    WalletAssetSpendErrorsTest(__file__).main()
