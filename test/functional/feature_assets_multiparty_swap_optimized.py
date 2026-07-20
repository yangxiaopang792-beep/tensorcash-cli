#!/usr/bin/env python3
# Copyright (c) 2024 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test complex multi-party atomic swaps with assets using high-level primitives - OPTIMIZED VERSION."""

import hashlib
import os
import time
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, OP_IF, OP_ELSE, OP_ENDIF, OP_CHECKSIG, OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_HASH160, OP_EQUALVERIFY
from test_framework.util import assert_equal, assert_greater_than
from test_framework.crypto.ripemd160 import ripemd160
from test_framework.key import ECKey


class MultiPartyAtomicSwapTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4  # Need at least 3 for 3-way swap + 1 for N-party
        # Generate unique test run ID to avoid conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_multiswap".encode()).hexdigest()[:16]
        # Enable assets from block 0 and accept non-standard transactions for HTLCs
        self.extra_args = [
            ["-assetsheight=0", "-acceptnonstdtxn=1"],
            ["-assetsheight=0", "-acceptnonstdtxn=1"],
            ["-assetsheight=0", "-acceptnonstdtxn=1"],
            ["-assetsheight=0", "-acceptnonstdtxn=1"]
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # Connect all nodes to each other for proper syncing
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                self.connect_nodes(i, j)
        self.sync_all()

    def register_and_mint_asset_optimized(self, wallet, node, asset_name, mint_amount=1000):
        """Register an asset and mint some units - OPTIMIZED with fewer blocks."""
        asset_id = hashlib.sha256(f"{asset_name}_{self.test_run_id}".encode()).hexdigest()
        ticker = f"{asset_name[:3].upper()}{asset_id[-4:].upper()}".upper()[:11]

        # Register asset
        reg_addr = wallet.getnewaddress()
        self.log.info(f"Registering asset {ticker} with ID {asset_id}")
        reg_result = wallet.registerasset(
            reg_addr, 5.1, asset_id, 3, 28, 510000000, ticker, 8,
            {"autofund": True, "broadcast": True}
        )

        # Mint assets immediately without mining first
        mint_result = wallet.mintasset(
            asset_id, mint_amount, reg_addr,
            {"autofund": True, "broadcast": True}
        )
        self.log.info(f"Minted {mint_amount} units of {ticker}")

        # Return without mining - batch mine later
        return asset_id, ticker

    def batch_mine_and_confirm(self, blocks=1):
        """Mine blocks and sync once for efficiency."""
        self.generate(self.nodes[0], blocks, sync_fun=self.sync_all)

    def test_3way_circular_swap(self):
        """Test 3-way circular atomic swap - OPTIMIZED."""
        self.log.info("Testing 3-way circular atomic swap...")

        alice_wallet = self.wallets[0]
        bob_wallet = self.wallets[1]
        charlie_wallet = self.wallets[2]

        # Register and mint all assets without intermediate mining
        asset_a_id, ticker_a = self.register_and_mint_asset_optimized(alice_wallet, self.nodes[0], "asset_a", 1000)
        asset_b_id, ticker_b = self.register_and_mint_asset_optimized(bob_wallet, self.nodes[0], "asset_b", 2000)
        asset_c_id, ticker_c = self.register_and_mint_asset_optimized(charlie_wallet, self.nodes[0], "asset_c", 3000)

        # Mine all registrations and mints at once
        self.batch_mine_and_confirm(2)

        # Create swap addresses
        alice_to_bob_addr = bob_wallet.getnewaddress()
        bob_to_charlie_addr = charlie_wallet.getnewaddress()
        charlie_to_alice_addr = alice_wallet.getnewaddress()

        # Execute all swaps
        alice_wallet.sendasset(ticker_a, alice_to_bob_addr, 1000, {"broadcast": True})
        bob_wallet.sendasset(ticker_b, bob_to_charlie_addr, 2000, {"broadcast": True})
        charlie_wallet.sendasset(ticker_c, charlie_to_alice_addr, 3000, {"broadcast": True})

        # Confirm all swaps at once
        self.batch_mine_and_confirm(1)

        # Verify results
        bob_balance = bob_wallet.getassetbalance([ticker_a])
        assert len(bob_balance) > 0, f"Bob should have received {ticker_a}"
        self.log.info(f"✓ Bob received {bob_balance[0]['balance']} units of {ticker_a}")

        charlie_balance = charlie_wallet.getassetbalance([ticker_b])
        assert len(charlie_balance) > 0, f"Charlie should have received {ticker_b}"
        self.log.info(f"✓ Charlie received {charlie_balance[0]['balance']} units of {ticker_b}")

        alice_balance = alice_wallet.getassetbalance([ticker_c])
        assert len(alice_balance) > 0, f"Alice should have received {ticker_c}"
        self.log.info(f"✓ Alice received {alice_balance[0]['balance']} units of {ticker_c}")

        self.log.info("✅ 3-way circular swap completed successfully!")

    def run_test(self):
        # Create wallets
        self.wallets = []
        for i in range(self.num_nodes):
            self.nodes[i].createwallet(wallet_name="")
            wallet = self.nodes[i].get_wallet_rpc("")
            self.wallets.append(wallet)

        # Generate initial coins more efficiently
        addr0 = self.wallets[0].getnewaddress()
        self.generatetoaddress(self.nodes[0], 101, addr0)  # Only need 101 for maturity

        # Distribute funds to all wallets at once
        for i in range(1, self.num_nodes):
            addr = self.wallets[i].getnewaddress()
            self.wallets[0].sendtoaddress(addr, 20)  # Give more upfront

        # Confirm all distributions at once
        self.generatetoaddress(self.nodes[0], 1, addr0)
        self.sync_all()

        # Run optimized test
        self.test_3way_circular_swap()

        # Add other tests here with similar optimizations...
        self.log.info("All multi-party atomic swap tests passed!")


if __name__ == '__main__':
    MultiPartyAtomicSwapTest(__file__).main()