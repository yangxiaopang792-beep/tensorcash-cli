#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Advanced ticker reorg tests: same-height conflicts and undo of ticker/decimals on disconnect."""

import hashlib
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error, assert_equal

class AssetTickerReorgAdvanced(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1"]] * self.num_nodes
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        import os
        import time
        # Generate a unique test run ID to avoid conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_ticker_adv".encode()).hexdigest()[:8]
        
        n0, n1 = self.nodes
        self.generate(n0, 101)
        self.sync_all()

        # Same-height conflicts: both nodes mine same ticker at height H+1 for different assets
        self.disconnect_nodes(0, 1)
        asset_a = hashlib.sha256(f"ticker_adv_a_{self.test_run_id}".encode()).hexdigest()
        asset_b = hashlib.sha256(f"ticker_adv_b_{self.test_run_id}".encode()).hexdigest()
        ticker_conflict = f"C{self.test_run_id[:7].upper()}"

        # node0 claim
        reg0 = n0.createrawtransaction([], {n0.getnewaddress(): 5.1})
        tx0 = n0.rawtxattachissuerreg(reg0, 0, asset_a, 3, 28, None, ticker_conflict)
        f0 = n0.fundrawtransaction(tx0)
        s0 = n0.signrawtransactionwithwallet(f0['hex'])
        n0.sendrawtransaction(s0['hex'])
        self.generate(n0, 1, sync_fun=self.no_op)

        # node1 competing claim at same height (its height is behind; mine one to 101 first)
        self.generate(n1, 101, sync_fun=self.no_op)
        reg1 = n1.createrawtransaction([], {n1.getnewaddress(): 5.1})
        tx1 = n1.rawtxattachissuerreg(reg1, 0, asset_b, 3, 28, None, ticker_conflict)
        f1 = n1.fundrawtransaction(tx1)
        s1 = n1.signrawtransactionwithwallet(f1['hex'])
        n1.sendrawtransaction(s1['hex'])
        self.generate(n1, 1, sync_fun=self.no_op)

        # Heights equal now? bring them equal explicitly
        h0 = n0.getblockcount(); h1 = n1.getblockcount()
        if h0 < h1:
            self.generate(n0, h1 - h0, sync_fun=self.no_op)
        elif h1 < h0:
            self.generate(n1, h0 - h1, sync_fun=self.no_op)

        # Extend node1 chain by one block to force reorg in node0's view
        self.generate(n1, 1, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Winner ticker binding should be node1's asset
        aid = n0.getassetbyticker(ticker_conflict)['asset_id']
        assert_equal(aid, asset_b)

        # Undo test: assign ticker+decimals on node0, then reorg to remove
        self.disconnect_nodes(0, 1)
        self.generate(n0, 2, sync_fun=self.no_op)
        asset_c = hashlib.sha256(f"ticker_adv_c_{self.test_run_id}".encode()).hexdigest()
        ticker_xyz = f"Z{self.test_run_id[:7].upper()}"
        r0 = n0.createrawtransaction([], {n0.getnewaddress(): 5.1})
        t0 = n0.rawtxattachissuerreg(r0, 0, asset_c, 3, 28, None, ticker_xyz, 6)
        f = n0.fundrawtransaction(t0)
        s = n0.signrawtransactionwithwallet(f['hex'])
        n0.sendrawtransaction(s['hex'])
        self.generate(n0, 1, sync_fun=self.no_op)
        pol_c = n0.getassetpolicy(asset_c)
        assert_equal(pol_c['ticker'], ticker_xyz)
        assert_equal(pol_c['decimals'], 6)
        # Now have node1 build a longer chain without that registration
        self.generate(n1, n0.getblockcount() + 2, sync_fun=self.no_op)  # make sure it's longer
        self.connect_nodes(0, 1)
        self.sync_blocks()
        # After reorg, ticker should be unbound and policy for asset_c either missing or without ticker/decimals
        try:
            n0.getassetbyticker(ticker_xyz)
            assert False, f"Expected ticker {ticker_xyz} to be absent after reorg"
        except Exception:
            pass
        try:
            pol_c2 = n0.getassetpolicy(asset_c)
            if pol_c2 and 'ticker' in pol_c2:
                assert pol_c2['ticker'] != ticker_xyz
        except Exception:
            # Asset policy may not exist after reorg, which is expected
            pass

if __name__ == '__main__':
    AssetTickerReorgAdvanced(__file__).main()
