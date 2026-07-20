#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bond lock validation: unlock_fees_sats >= bond and 95% rotation minimum."""

import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

class AssetBondLockValidationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_bond_validation".encode()).hexdigest()[:16]
        # Enable assets at genesis
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1", "-assetmindustbtc=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing bond lock validation with unlock_fees_sats >= bond requirement...")

        self.test_unlock_below_bond_rejected()
        self.test_unlock_equals_bond_accepted()
        self.test_unlock_above_bond_accepted()
        self.test_rotation_min_sats_95_percent()
        self.test_rpc_default_behavior()

    def test_unlock_below_bond_rejected(self):
        """Test that unlock_fees_sats < bond value is rejected."""
        self.log.info("Testing unlock_fees_sats < bond is rejected...")

        node = self.nodes[0]
        self.generate(node, 110)  # Mature coins

        asset_id = hashlib.sha256(f"below_bond_{self.test_run_id}".encode()).hexdigest()

        # Create raw transaction with 5 BTC bond
        icu_addr = node.getnewaddress()
        raw_tx = node.createrawtransaction([], [{icu_addr: 5.0}])

        # Try to attach IssuerReg with unlock_fees_sats = 4.9 BTC (below bond)
        # This should fail at RPC level
        assert_raises_rpc_error(-8, "unlock_fees_sats",
            node.rawtxattachissuerreg, raw_tx, 0, asset_id, 3, 28, 490000000)  # 4.9 BTC

        self.log.info("✓ unlock_fees_sats < bond correctly rejected")

    def test_unlock_equals_bond_accepted(self):
        """Test that unlock_fees_sats = bond value is accepted."""
        self.log.info("Testing unlock_fees_sats = bond is accepted...")

        node = self.nodes[0]
        asset_id = hashlib.sha256(f"equals_bond_{self.test_run_id}".encode()).hexdigest()

        # Create raw transaction with 5 BTC bond
        icu_addr = node.getnewaddress()
        raw_tx = node.createrawtransaction([], [{icu_addr: 5.0}])

        # Attach IssuerReg with unlock_fees_sats = 5 BTC (equals bond)
        tx_with_reg = node.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28, 500000000)  # 5 BTC

        # Fund and send
        funded = node.fundrawtransaction(tx_with_reg)
        signed = node.signrawtransactionwithwallet(funded['hex'])
        txid = node.sendrawtransaction(signed['hex'])
        self.generate(node, 1)

        # Verify registration
        policy = node.getassetpolicy(asset_id)
        assert_equal(policy['unlock_fees_sats'], 500000000)
        # Rotation min should be 95% of bond (4.75 BTC)
        assert_equal(policy['rotation_min_sats'], 475000000)
        assert_equal(policy['is_unlocked'], False)

        self.log.info("✓ unlock_fees_sats = bond correctly accepted")
        return asset_id

    def test_unlock_above_bond_accepted(self):
        """Test that unlock_fees_sats > bond value is accepted."""
        self.log.info("Testing unlock_fees_sats > bond is accepted...")

        node = self.nodes[0]
        asset_id = hashlib.sha256(f"above_bond_{self.test_run_id}".encode()).hexdigest()

        # Create raw transaction with 5 BTC bond
        icu_addr = node.getnewaddress()
        raw_tx = node.createrawtransaction([], [{icu_addr: 5.0}])

        # Attach IssuerReg with unlock_fees_sats = 10 BTC (above bond)
        tx_with_reg = node.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28, 1000000000)  # 10 BTC

        # Fund and send
        funded = node.fundrawtransaction(tx_with_reg)
        signed = node.signrawtransactionwithwallet(funded['hex'])
        txid = node.sendrawtransaction(signed['hex'])
        self.generate(node, 1)

        # Verify registration
        policy = node.getassetpolicy(asset_id)
        assert_equal(policy['unlock_fees_sats'], 1000000000)  # 10 BTC
        # Rotation min should still be 95% of bond (4.75 BTC), not unlock value
        assert_equal(policy['rotation_min_sats'], 475000000)
        assert_equal(policy['is_unlocked'], False)

        self.log.info("✓ unlock_fees_sats > bond correctly accepted")
        return asset_id

    def test_rotation_min_sats_95_percent(self):
        """Test that rotation_min_sats is 95% of initial bond."""
        self.log.info("Testing rotation_min_sats = 95% of bond...")

        node = self.nodes[0]

        # Test with various bond amounts
        test_cases = [
            (5.0, 475000000),    # 5 BTC bond → 4.75 BTC rotation min
            (10.0, 950000000),   # 10 BTC bond → 9.5 BTC rotation min
            (100.0, 9500000000), # 100 BTC bond → 95 BTC rotation min
        ]

        for bond_btc, expected_rotation_min in test_cases:
            asset_id = hashlib.sha256(f"rotation_{bond_btc}_{self.test_run_id}".encode()).hexdigest()

            # Register with specified bond
            icu_addr = node.getnewaddress()
            raw_tx = node.createrawtransaction([], [{icu_addr: bond_btc}])

            # Use default unlock (will be max(bond, 5 BTC))
            tx_with_reg = node.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28)

            funded = node.fundrawtransaction(tx_with_reg)
            signed = node.signrawtransactionwithwallet(funded['hex'])
            node.sendrawtransaction(signed['hex'])
            self.generate(node, 1)

            # Verify rotation_min_sats
            policy = node.getassetpolicy(asset_id)
            assert_equal(policy['rotation_min_sats'], expected_rotation_min)
            self.log.info(f"  ✓ {bond_btc} BTC bond → {expected_rotation_min/100000000} BTC rotation min")

        self.log.info("✓ rotation_min_sats correctly set to 95% of bond")

    def test_rpc_default_behavior(self):
        """Test RPC default behavior for unlock_fees_sats."""
        self.log.info("Testing RPC default behavior...")

        node = self.nodes[0]

        # Test 1: Small bond (3 BTC) - should default to 5 BTC unlock
        asset_id = hashlib.sha256(f"small_bond_{self.test_run_id}".encode()).hexdigest()
        raw_tx = node.createrawtransaction([], [{node.getnewaddress(): 3.0}])

        # Don't specify unlock_fees_sats - should default to max(3, 5) = 5 BTC
        tx_with_reg = node.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28)

        funded = node.fundrawtransaction(tx_with_reg)
        signed = node.signrawtransactionwithwallet(funded['hex'])
        node.sendrawtransaction(signed['hex'])
        self.generate(node, 1)

        policy = node.getassetpolicy(asset_id)
        assert_equal(policy['unlock_fees_sats'], 500000000)  # 5 BTC (not 3 BTC)
        assert_equal(policy['rotation_min_sats'], 285000000)  # 95% of 3 BTC bond
        self.log.info("  ✓ 3 BTC bond → 5 BTC unlock (default minimum)")

        # Test 2: Large bond (10 BTC) - should default to bond value
        asset_id = hashlib.sha256(f"large_bond_{self.test_run_id}".encode()).hexdigest()
        raw_tx = node.createrawtransaction([], [{node.getnewaddress(): 10.0}])

        # Don't specify unlock_fees_sats - should default to max(10, 5) = 10 BTC
        tx_with_reg = node.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28)

        funded = node.fundrawtransaction(tx_with_reg)
        signed = node.signrawtransactionwithwallet(funded['hex'])
        node.sendrawtransaction(signed['hex'])
        self.generate(node, 1)

        policy = node.getassetpolicy(asset_id)
        assert_equal(policy['unlock_fees_sats'], 1000000000)  # 10 BTC (not 5 BTC)
        assert_equal(policy['rotation_min_sats'], 950000000)   # 95% of 10 BTC bond
        self.log.info("  ✓ 10 BTC bond → 10 BTC unlock (matches bond)")

        self.log.info("✓ RPC default behavior correct")

if __name__ == '__main__':
    AssetBondLockValidationTest().main()