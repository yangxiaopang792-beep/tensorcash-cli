#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license.
"""Ensure issuers cannot flip burn policy from disabled to enabled."""

import hashlib
import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

COIN = 100_000_000


class AssetPolicyBurnImmutabilityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1"]]
        self.force_cleanup_on_failure = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def register_asset(self, node, asset_id: str, amount_btc: Decimal, policy_bits: int, unlock_sats: int):
        icu_address = node.getnewaddress()
        raw = node.createrawtransaction([], [{icu_address: float(amount_btc)}])
        raw = node.rawtxattachissuerreg(raw, 0, asset_id, policy_bits, 28, unlock_sats)
        funded = node.fundrawtransaction(raw)
        signed = node.signrawtransactionwithwallet(funded['hex'])
        txid = node.sendrawtransaction(signed['hex'])
        self.generate(node, 1)
        pol = node.getassetpolicy(asset_id)
        assert_equal(pol["policy_bits"], policy_bits)
        assert_equal(pol["icu_txid"], txid)
        return pol

    def build_icu_rotation(self, node, icu_prev: dict, icu_value: Decimal, asset_id: str, new_policy_bits: int, unlock_sats: int):
        new_addr = node.getnewaddress()
        raw = node.createrawtransaction([icu_prev], {new_addr: float(icu_value)})
        raw = node.rawtxattachissuerreg(raw, 0, asset_id, new_policy_bits, 28, unlock_sats)
        funded = node.fundrawtransaction(raw)
        return node.signrawtransactionwithwallet(funded['hex'], [], "ALL")

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_burn_flip".encode()).hexdigest()[:16]

        # Register asset that starts with burn disabled (policy_bits=1)
        asset_id = hashlib.sha256(f"burn_disabled_{run_id}".encode()).hexdigest()
        pol = self.register_asset(node, asset_id, Decimal("5.1"), 1, 520_000_000)
        icu_prev = {"txid": pol['icu_txid'], "vout": pol['icu_vout']}
        icu_utxo = node.gettxout(icu_prev['txid'], icu_prev['vout'])
        icu_value = Decimal(str(icu_utxo['value']))
        unlock_target = int(icu_value * COIN) + 50_000

        signed = self.build_icu_rotation(node, icu_prev, icu_value, asset_id, 3, unlock_target)
        assert_raises_rpc_error(-26, "asset-policy-burn-flip", node.sendrawtransaction, signed['hex'])
        assert_equal(node.getmempoolinfo()['size'], 0)
        pol_after = node.getassetpolicy(asset_id)
        assert_equal(pol_after['policy_bits'], 1)

        # Register asset with burn enabled, then rotate to disable burn (allowed)
        asset_id2 = hashlib.sha256(f"burn_enabled_{run_id}".encode()).hexdigest()
        pol2 = self.register_asset(node, asset_id2, Decimal("5.5"), 3, 560_000_000)
        icu_prev2 = {"txid": pol2['icu_txid'], "vout": pol2['icu_vout']}
        icu_utxo2 = node.gettxout(icu_prev2['txid'], icu_prev2['vout'])
        icu_value2 = Decimal(str(icu_utxo2['value']))
        unlock_target2 = int(icu_value2 * COIN) + 50_000

        signed2 = self.build_icu_rotation(node, icu_prev2, icu_value2, asset_id2, 1, unlock_target2)
        txid2 = node.sendrawtransaction(signed2['hex'])
        self.generate(node, 1)
        pol2_after = node.getassetpolicy(asset_id2)
        assert_equal(pol2_after['policy_bits'], 1)
        assert_equal(pol2_after['icu_txid'], txid2)


if __name__ == '__main__':
    AssetPolicyBurnImmutabilityTest(__file__).main()
