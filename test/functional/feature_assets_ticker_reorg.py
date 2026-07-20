#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ticker uniqueness across reorgs with competing claims."""

import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class AssetTickerReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Generate unique test run ID to avoid asset ID and ticker conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_ticker_reorg".encode()).hexdigest()[:8]
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",
            "-dbcache=1000",
        ]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0, n1 = self.nodes
        self.generate(n0, 101)
        self.sync_all()

        # Disconnect nodes BEFORE any ticker registrations
        self.disconnect_nodes(0, 1)

        # Node0: Register asset A with ticker
        asset_a = hashlib.sha256(f"ticker_reorg_a_{self.test_run_id}".encode()).hexdigest()
        ticker_unique = f"R{self.test_run_id[:7].upper()}"
        reg0 = n0.createrawtransaction([], {n0.getnewaddress(): 5.1})
        tx0 = n0.rawtxattachissuerreg(reg0, 0, asset_a, 3, 28, None, ticker_unique, 8)
        f0 = n0.fundrawtransaction(tx0)
        s0 = n0.signrawtransactionwithwallet(f0['hex'])
        n0.sendrawtransaction(s0['hex'])
        self.generate(n0, 1, sync_fun=self.no_op)

        # Node1: Register different asset B with same ticker, mine longer chain
        self.generate(n1, 101, sync_fun=self.no_op)  # fund
        asset_b = hashlib.sha256(f"ticker_reorg_b_{self.test_run_id}".encode()).hexdigest()
        reg1 = n1.createrawtransaction([], {n1.getnewaddress(): 5.1})
        tx1 = n1.rawtxattachissuerreg(reg1, 0, asset_b, 3, 28, None, ticker_unique, 8)
        f1 = n1.fundrawtransaction(tx1)
        s1 = n1.signrawtransactionwithwallet(f1['hex'])
        n1.sendrawtransaction(s1['hex'])
        self.generate(n1, 2, sync_fun=self.no_op)  # make chain1 longer

        # Reconnect and sync; node0 should reorg to node1's longer chain
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Ticker binding should reflect node1's claim
        aid = n0.getassetbyticker(ticker_unique)['asset_id']
        assert_equal(aid, asset_b)

if __name__ == '__main__':
    AssetTickerReorgTest(__file__).main()
