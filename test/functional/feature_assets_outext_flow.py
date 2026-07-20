#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end assets flow test.

Build register → mint → transfer → burn using:
- createrawtransaction/fundrawtransaction/signrawtransactionwithwallet/sendrawtransaction
- rawtxattachissuerreg and rawtxattachassettag to attach asset metadata
"""

import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class AssetOutExtFlowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Generate unique test run ID to avoid asset ID conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_outext".encode()).hexdigest()[:16]
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",  # Don't persist mempool between restarts
            "-dbcache=1000",  # Use 1GB cache to keep everything in memory
        ]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def no_op(self):
        """No-op sync function for single node operations."""
        pass

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101, sync_fun=self.no_op)

        # Generate unique asset identifier for this test run
        asset_id = hashlib.sha256(f"outext_flow_asset_{self.test_run_id}".encode()).hexdigest()

        # 1) Register asset
        # Get a UTXO for the registration bond
        utxos = node.listunspent()
        if not utxos:
            self.generate(node, 1, sync_fun=self.no_op)
            utxos = node.listunspent()
        reg_input = utxos[0]
        reg_inputs = [{"txid": reg_input["txid"], "vout": reg_input["vout"]}]
        # Set bond at 5.1 BTC and calculate change
        reg_output_value = 5.1
        input_amount = float(reg_input["amount"])
        # Ensure we have enough funds, otherwise find a bigger UTXO
        if input_amount < reg_output_value + 0.0001:
            # Find a suitable UTXO
            for utxo in utxos:
                if float(utxo["amount"]) >= reg_output_value + 0.0001:
                    reg_input = utxo
                    input_amount = float(utxo["amount"])
                    reg_inputs = [{"txid": reg_input["txid"], "vout": reg_input["vout"]}]
                    break
            else:
                # Generate more blocks if no suitable UTXO
                self.generate(node, 10, sync_fun=self.no_op)
                utxos = node.listunspent()
                reg_input = utxos[0]
                input_amount = float(reg_input["amount"])
                reg_inputs = [{"txid": reg_input["txid"], "vout": reg_input["vout"]}]

        change_value = input_amount - reg_output_value - 0.0001  # Leave room for fee
        reg_outputs = [{node.getnewaddress(): reg_output_value}]
        if change_value > 0.0001:
            reg_outputs.append({node.getnewaddress(): round(change_value, 8)})
        reg_raw = node.createrawtransaction(reg_inputs, reg_outputs)
        reg_tx = node.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28)  # 28 = 0x1C
        # Don't use fundrawtransaction with asset transactions - it can corrupt the outputs
        reg_signed = node.signrawtransactionwithwallet(reg_tx)
        reg_txid = node.sendrawtransaction(reg_signed['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        # Verify registry reflects ICU
        pol = node.getassetpolicy(asset_id)
        assert pol is not None, f"Asset {asset_id} not found in registry"
        assert_equal(pol['asset_id'], asset_id)
        assert_equal(pol['policy_bits'], 3)
        assert_equal(pol['allowed_spk_families'], 28)
        assert_equal(pol['icu_txid'], reg_txid)
        assert_equal(pol['icu_vout'], 0)

        # 2) Mint: spend ICU, rotate ICU and mint assets
        mint_inputs = [{"txid": reg_txid, "vout": 0}]
        mint_outputs = [
            {node.getnewaddress(): 5.1},  # ICU rotation
            {node.getnewaddress(): 0.1}   # Asset output
        ]
        mint_raw = node.createrawtransaction(mint_inputs, mint_outputs)
        # Re-attach ICU to output 0
        mint_tx = node.rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 28)
        # Attach assets to output 1
        mint_tx = node.rawtxattachassettag(mint_tx, 1, asset_id, 500000, 0)
        mint_funded = node.fundrawtransaction(mint_tx)
        mint_signed = node.signrawtransactionwithwallet(mint_funded['hex'])
        mint_txid = node.sendrawtransaction(mint_signed['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        # Find the actual asset output (it might not be at vout 1 after fundrawtransaction)
        # Get the ICU location to exclude it
        pol_after_mint = node.getassetpolicy(asset_id)
        icu_vout_after_mint = pol_after_mint['icu_vout']

        mint_tx_decoded = node.gettransaction(mint_txid, True, True)['decoded']
        asset_vout = None
        for i, out in enumerate(mint_tx_decoded['vout']):
            # Find output with outext that is NOT the ICU
            if 'outext' in out and i != icu_vout_after_mint:
                asset_vout = i
                break
        assert asset_vout is not None, "No asset output found in mint transaction"

        # 3) Transfer (Δ=0): spend asset output
        # Get the actual BTC value of the asset output
        asset_output_value = float(mint_tx_decoded['vout'][asset_vout]['value'])
        xfer_inputs = [{"txid": mint_txid, "vout": asset_vout}]
        # Leave some BTC for fees (max 0.005 BTC)
        xfer_output_value = max(0.001, asset_output_value - 0.005)
        xfer_outputs = [{node.getnewaddress(): xfer_output_value}]
        xfer_raw = node.createrawtransaction(xfer_inputs, xfer_outputs)
        # Transfer the same amount of assets
        xfer_tx = node.rawtxattachassettag(xfer_raw, 0, asset_id, 500000, 0)
        # Don't use fundrawtransaction - we have enough BTC for fees from the input
        xfer_signed = node.signrawtransactionwithwallet(xfer_tx)
        xfer_txid = node.sendrawtransaction(xfer_signed['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        # 4) Burn: spend ICU and asset input, output only ICU (no assets)
        cur = node.getassetpolicy(asset_id)
        burn_inputs = [
            {"txid": cur['icu_txid'], "vout": cur['icu_vout']},
            {"txid": xfer_txid, "vout": 0},
        ]
        burn_outputs = [{node.getnewaddress(): 5.1}]
        burn_raw = node.createrawtransaction(burn_inputs, burn_outputs)
        # Only re-attach ICU, no assets (burn them)
        burn_tx = node.rawtxattachissuerreg(burn_raw, 0, asset_id, 3, 28)
        burn_funded = node.fundrawtransaction(burn_tx)
        burn_signed = node.signrawtransactionwithwallet(burn_funded['hex'])
        burn_txid = node.sendrawtransaction(burn_signed['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        # Registry ICU should rotate to burn_txid (position may vary due to funding)
        pol2 = node.getassetpolicy(asset_id)
        assert_equal(pol2['icu_txid'], burn_txid)

        self.log.info("Asset flow test (register → mint → transfer → burn) passed")


if __name__ == '__main__':
    AssetOutExtFlowTest(__file__).main()