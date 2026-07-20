#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

from asset_wallet_util import register_asset, mint_asset


class WalletAssetCoinSelectionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.force_cleanup_on_failure = True
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 102)

        asset_id = hashlib.sha256(b"wallet_asset_coin_selection").hexdigest()
        _, policy, icu_value = register_asset(node, asset_id)
        asset_outpoint, policy = mint_asset(node, asset_id, policy, icu_value)

        # Asset-tagged UTXOs should not appear in listunspent by default.
        utxos = node.listunspent()
        assert all(
            not (entry["txid"] == asset_outpoint.txid and entry["vout"] == asset_outpoint.vout)
            for entry in utxos
        ), "Asset-tagged UTXOs must be hidden from default listunspent results"

        # BTC-only funding should avoid the asset UTXO entirely.
        btc_dest = node.getnewaddress()
        btc_raw = node.createrawtransaction([], {btc_dest: 1.0})
        btc_funded = node.fundrawtransaction(btc_raw)
        btc_decoded = node.decoderawtransaction(btc_funded["hex"])
        funded_inputs = {(vin["txid"], vin["vout"]) for vin in btc_decoded["vin"]}
        assert (asset_outpoint.txid, asset_outpoint.vout) not in funded_inputs

        # Asset-aware funding: preselect the asset UTXO and ensure its TLV survives.
        asset_dest = node.getnewaddress()
        raw_asset = node.createrawtransaction(
            [{"txid": asset_outpoint.txid, "vout": asset_outpoint.vout}],
            {asset_dest: float(asset_outpoint.value)}
        )
        raw_asset = node.rawtxattachassettag(raw_asset, 0, asset_id, 1000)
        funded_asset = node.fundrawtransaction(raw_asset)
        dec_asset = node.decoderawtransaction(funded_asset["hex"])
        asset_inputs = {(vin["txid"], vin["vout"]) for vin in dec_asset["vin"]}
        assert (asset_outpoint.txid, asset_outpoint.vout) in asset_inputs
        assert any(vout.get("outext", "").startswith("01") for vout in dec_asset["vout"])

        # Confirm the original asset UTXO remains unspent after funding-only calls.
        utxo_after = node.listunspent()
        assert all(
            not (entry["txid"] == asset_outpoint.txid and entry["vout"] == asset_outpoint.vout)
            for entry in utxo_after
        )


if __name__ == "__main__":
    WalletAssetCoinSelectionTest(__file__).main()
