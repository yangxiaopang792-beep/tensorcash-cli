#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from asset_wallet_util import register_asset, mint_asset


class WalletPsbtAssetRoundTripTest(BitcoinTestFramework):
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

        asset_id = hashlib.sha256(b"wallet_psbt_asset_roundtrip").hexdigest()
        _, policy, icu_value = register_asset(node, asset_id)
        asset_outpoint, policy = mint_asset(node, asset_id, policy, icu_value)

        asset_dest = node.getnewaddress()
        raw = node.createrawtransaction(
            [{"txid": asset_outpoint.txid, "vout": asset_outpoint.vout}],
            {asset_dest: float(asset_outpoint.value)}
        )
        raw = node.rawtxattachassettag(raw, 0, asset_id, 1000)
        funded = node.fundrawtransaction(raw)
        funded_dec = node.decoderawtransaction(funded["hex"])
        assert any(vout.get("outext", "").startswith("01") for vout in funded_dec["vout"])

        psbt = node.converttopsbt(funded["hex"])
        processed = node.walletprocesspsbt(psbt, True, "ALL", True, False)
        processed_psbt = processed["psbt"]
        decoded_psbt = node.decodepsbt(processed_psbt)
        assert any(vout.get("outext", "").startswith("01") for vout in decoded_psbt["tx"]["vout"])

        final = node.finalizepsbt(processed_psbt, True)
        assert final["complete"]
        signed_hex = final["hex"]
        signed_dec = node.decoderawtransaction(signed_hex)
        assert any(vout.get("outext", "").startswith("01") for vout in signed_dec["vout"])

        input_pairs = {(vin["txid"], vin["vout"]) for vin in signed_dec["vin"]}
        assert (asset_outpoint.txid, asset_outpoint.vout) in input_pairs


if __name__ == "__main__":
    WalletPsbtAssetRoundTripTest(__file__).main()
