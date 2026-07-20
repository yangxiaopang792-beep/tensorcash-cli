#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test consensus tickers: register, uniqueness, reserved rejection."""

import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

class AssetTickerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Generate unique test run ID to avoid asset ID and ticker conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_ticker".encode()).hexdigest()[:8]
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",  # Don't persist mempool between restarts
            "-dbcache=1000",  # Use 1GB cache to keep everything in memory
        ]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n = self.nodes[0]
        self.generate(n, 101)

        # Generate unique asset identifier and ticker for this test run
        asset_a = hashlib.sha256(f"ticker_asset_a_{self.test_run_id}".encode()).hexdigest()
        # Create unique ticker (must be 3-11 chars, start with letter)
        ticker_unique = f"T{self.test_run_id[:7].upper()}"
        reg_raw = n.createrawtransaction([], {n.getnewaddress(): 5.1})
        # rawtxattachissuerreg hex vout asset_id policy_bits allowed [unlock] [ticker] [decimals]
        tx_hex = n.rawtxattachissuerreg(reg_raw, 0, asset_a, 3, 28, None, ticker_unique, 8)
        funded = n.fundrawtransaction(tx_hex)
        signed = n.signrawtransactionwithwallet(funded['hex'])
        txid_a = n.sendrawtransaction(signed['hex'])
        self.generate(n, 1)

        pol = n.getassetpolicy(asset_a)
        assert pol is not None, f"Asset {asset_a} not found in registry after registration"
        assert_equal(pol['ticker'], ticker_unique)
        assert_equal(pol['decimals'], 8)

        # Attempt to change decimals should be rejected (immutability)
        reg2 = n.createrawtransaction([], {n.getnewaddress(): 5.1})
        tx2 = n.rawtxattachissuerreg(reg2, 0, asset_a, 3, 28, None, ticker_unique, 7)
        f2 = n.fundrawtransaction(tx2)
        s2 = n.signrawtransactionwithwallet(f2['hex'])
        self.log.info("Testing decimals immutability")
        assert_raises_rpc_error(-26, "asset-decimals-change", n.sendrawtransaction, s2['hex'])

        # Generate unique asset identifier for reserved ticker test
        asset_r = hashlib.sha256(f"ticker_reserved_{self.test_run_id}".encode()).hexdigest()
        reg_raw_r = n.createrawtransaction([], {n.getnewaddress(): 5.1})
        bad_hex = n.rawtxattachissuerreg(reg_raw_r, 0, asset_r, 3, 28, None, "TSC")
        bad_f = n.fundrawtransaction(bad_hex)
        bad_s = n.signrawtransactionwithwallet(bad_f['hex'])
        assert_raises_rpc_error(-26, "asset-ticker-reserved", n.sendrawtransaction, bad_s['hex'])

        # Generate unique asset identifier for duplicate ticker test
        asset_b = hashlib.sha256(f"ticker_duplicate_{self.test_run_id}".encode()).hexdigest()
        reg_raw2 = n.createrawtransaction([], {n.getnewaddress(): 5.1})
        # Try to claim the same ticker for a different asset
        hex2 = n.rawtxattachissuerreg(reg_raw2, 0, asset_b, 3, 28, None, ticker_unique)
        f2 = n.fundrawtransaction(hex2)
        s2 = n.signrawtransactionwithwallet(f2['hex'])
        assert_raises_rpc_error(-26, "asset-ticker-duplicate", n.sendrawtransaction, s2['hex'])

if __name__ == '__main__':
    AssetTickerTest(__file__).main()
