#!/usr/bin/env python3
"""
Simple GUI asset test - copy of feature_assets_basic_highlevel that keeps daemons running
and launches GUI instead of terminating.
"""

import hashlib
import os
import sys
import time
import subprocess
import signal

# Add test framework to path
sys.path.insert(0, '/build/bcore/test/functional')

from test_framework.test_framework import BitcoinTestFramework


class GuiAssetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Generate unique test run ID to avoid conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_gui".encode()).hexdigest()[:16]
        # Enable assets at genesis
        self.extra_args = [["-assetsheight=0"], ["-assetsheight=0"]]

        # Override the default temp directory to use a fixed location
        self.options.tmpdir = "/root/tensorcash-gui"

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def run_test(self):
        # Start VNC server if needed
        self.log.info("Starting VNC server...")
        try:
            subprocess.run(["vncserver", "-kill", ":1"], capture_output=True)
        except:
            pass
        subprocess.run(["rm", "-rf", "/tmp/.X1-lock", "/tmp/.X11-unix/X1"], capture_output=True)
        subprocess.run(["vncserver", ":1", "-geometry", "1280x800", "-depth", "24"], check=True)
        os.environ["DISPLAY"] = ":1"
        self.log.info("VNC server started on :1 (port 5901, password: password)")

        # Create wallets for both nodes
        self.nodes[0].createwallet(wallet_name="")
        self.nodes[1].createwallet(wallet_name="")

        # Get wallet RPC interfaces
        self.wallet0 = self.nodes[0].get_wallet_rpc("")
        self.wallet1 = self.nodes[1].get_wallet_rpc("")

        # Mine coins on node1 and fund the asset wallet on node0
        self.log.info("Setting up initial funds...")
        miner_addr = self.wallet1.getnewaddress()
        self.generatetoaddress(self.nodes[1], 120, miner_addr)
        self.sync_all()

        asset_addr = self.wallet0.getnewaddress()
        self.wallet1.sendtoaddress(asset_addr, 85)
        self.generatetoaddress(self.nodes[1], 1, miner_addr)
        self.sync_all()

        self.log.info(f"Initial balance: {self.wallet0.getbalance()} BTC")

        # Register and mint assets (copying from the original test)
        self.log.info("Registering and minting assets...")

        # Asset 1: GOLD
        self.log.info("Registering GOLD...")
        reg_addr = self.wallet0.getnewaddress()
        gold_id = "1111111111111111111111111111111111111111111111111111111111111111"
        self.wallet0.registerasset(
            reg_addr,      # ICU address
            5.1,           # Bond amount (BTC)
            gold_id,       # Asset ID
            3,             # Policy bits (MINT_ALLOWED | BURN_ALLOWED)
            28,            # Allowed families (P2WPKH | P2WSH | P2TR)
            510000000,     # Unlock fees (5.1 BTC in sats)
            "GOLD",        # Ticker symbol
            8,             # Decimals
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()
        self.wait_until(lambda: self.nodes[0].getassetpolicy(gold_id) is not None)

        # Mint GOLD
        self.log.info("Minting 1.0 GOLD...")
        policy = self.nodes[0].getassetpolicy(gold_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()

        self.wallet0.mintasset(
            policy['icu_txid'],
            policy['icu_vout'],
            icu_addr_new,
            5.1,
            asset_addr,
            0.001,
            gold_id,
            100000000,  # 1.0 with 8 decimals
            3,
            28,
            510000000,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()

        # Asset 2: SILVER
        self.log.info("Registering SILVER...")
        reg_addr = self.wallet0.getnewaddress()
        silver_id = "2222222222222222222222222222222222222222222222222222222222222222"
        self.wallet0.registerasset(
            reg_addr, 5.1, silver_id, 3, 28, 510000000, "SILVER", 6,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()
        self.wait_until(lambda: self.nodes[0].getassetpolicy(silver_id) is not None)

        # Mint SILVER
        self.log.info("Minting 500 SILVER...")
        policy = self.nodes[0].getassetpolicy(silver_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()

        self.wallet0.mintasset(
            policy['icu_txid'],
            policy['icu_vout'],
            icu_addr_new,
            5.1,
            asset_addr,
            0.001,
            silver_id,
            500000000,  # 500 with 6 decimals
            3,
            28,
            510000000,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()

        # Asset 3: TEST
        self.log.info("Registering TEST...")
        reg_addr = self.wallet0.getnewaddress()
        test_id = "3333333333333333333333333333333333333333333333333333333333333333"
        self.wallet0.registerasset(
            reg_addr, 5.1, test_id, 3, 28, 510000000, "TEST", 8,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()
        self.wait_until(lambda: self.nodes[0].getassetpolicy(test_id) is not None)

        # Mint TEST
        self.log.info("Minting 0.5 TEST...")
        policy = self.nodes[0].getassetpolicy(test_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()

        self.wallet0.mintasset(
            policy['icu_txid'],
            policy['icu_vout'],
            icu_addr_new,
            5.1,
            asset_addr,
            0.001,
            test_id,
            50000000,  # 0.5 with 8 decimals
            3,
            28,
            510000000,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()

        # Generate a few more blocks to ensure everything is well-confirmed
        self.log.info("Generating additional blocks to ensure confirmations...")
        self.generate(self.nodes[1], 5, sync_fun=self.sync_all)
        self.sync_all()

        # Force chainstate flush and ensure assets are registered
        self.log.info("Flushing chainstate to ensure assets are persisted...")
        for node in self.nodes:
            node.gettxoutsetinfo()

        # Verify assets are properly registered before proceeding
        self.log.info("Verifying asset registrations...")
        gold_info = self.nodes[0].getassetinfo(gold_id)
        self.log.info(f"  GOLD registered: {gold_info['ticker']}")
        silver_info = self.nodes[0].getassetinfo(silver_id)
        self.log.info(f"  SILVER registered: {silver_info['ticker']}")
        test_info = self.nodes[0].getassetinfo(test_id)
        self.log.info(f"  TEST registered: {test_info['ticker']}")

        # Show current state
        self.log.info("Current wallet state:")
        btc_balance = self.wallet0.getbalance()
        self.log.info(f"  BTC Balance: {btc_balance}")

        asset_balances = self.wallet0.getassetbalance()
        self.log.info("  Asset Balances:")
        for asset in asset_balances:
            self.log.info(f"    - {asset['ticker']}: {asset['balance_decimal']}")

        # Now stop node0 and replace with GUI
        self.log.info("Stopping node0 bitcoind to launch GUI...")

        # Get the datadir path for node0
        node0_datadir = self.nodes[0].datadir_path

        # Node1 should be on the standard test framework port
        # In regtest with 2 nodes, node1 is typically on port 18554
        node1_port = 18554
        self.log.info(f"Node1 is listening on port {node1_port}")

        # Stop node0
        self.stop_node(0)
        time.sleep(5)

        # Launch GUI with the same datadir
        self.log.info(f"Launching GUI with datadir: {node0_datadir}")

        gui_cmd = [
            "/build/bcore/build/bin/bitcoin-qt",
            f"-datadir={node0_datadir}",
            "-regtest",
            "-server=1",
            "-listen=1",
            "-port=18444",
            "-rpcport=18443",
            "-rpcuser=test",
            "-rpcpassword=test",
            "-fallbackfee=0.00001",
            "-assetsheight=0",
            "-policymaxassetspertx=100",
            "-wallet=",
            f"-addnode=127.0.0.1:{node1_port}"  # Connect to node1 using actual port
        ]

        self.gui_process = subprocess.Popen(gui_cmd, env={**os.environ, "DISPLAY": ":1"})
        self.log.info(f"GUI started with PID: {self.gui_process.pid}")

        # Give GUI more time to start and sync
        self.log.info("Waiting for GUI to start and sync...")
        time.sleep(15)

        # Mine a block to help GUI sync
        self.log.info("Mining a block to help GUI sync...")
        # Use generate method with no_op sync to avoid sync issues since node0 is now GUI
        self.generate(self.nodes[1], 1, sync_fun=self.no_op)
        time.sleep(2)

        # Start continuous mining
        self.log.info("Starting continuous mining loop...")

        # Store reference to self for the mining thread
        test_framework = self
        mining_node = self.nodes[1]

        def mine_continuously():
            while True:
                try:
                    # Use node1 directly since node0 is now the GUI
                    blockcount = mining_node.getblockcount()
                    test_framework.log.info(f"Mining block {blockcount + 1}...")
                    # Use framework's generate method with no_op sync
                    test_framework.generate(mining_node, 1, sync_fun=test_framework.no_op)
                    time.sleep(10)
                except Exception as e:
                    test_framework.log.error(f"Mining error: {e}")
                    break

        # Start mining in a separate thread
        import threading
        mining_thread = threading.Thread(target=mine_continuously, daemon=True)
        mining_thread.start()

        # Print instructions
        self.log.info("")
        self.log.info("=" * 60)
        self.log.info("GUI ASSET TEST RUNNING")
        self.log.info("=" * 60)
        self.log.info("VNC: Connect to vnc://localhost:5901 (password: password)")
        self.log.info(f"GUI PID: {self.gui_process.pid}")
        self.log.info("Mining node: node1 (generating blocks every 10 seconds)")
        self.log.info("")
        self.log.info("The GUI should show:")
        self.log.info(f"  - BTC: ~{btc_balance} BTC")
        self.log.info("  - GOLD: 1.0")
        self.log.info("  - SILVER: 500")
        self.log.info("  - TEST: 0.5")
        self.log.info("")
        self.log.info("Press Ctrl+C to stop")
        self.log.info("=" * 60)

        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
                if self.gui_process.poll() is not None:
                    self.log.error("GUI process exited unexpectedly")
                    break
        except KeyboardInterrupt:
            self.log.info("Shutting down...")

    def cleanup(self):
        """Override cleanup to properly handle GUI process"""
        if hasattr(self, 'gui_process'):
            self.log.info("Terminating GUI...")
            self.gui_process.terminate()
            try:
                self.gui_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.gui_process.kill()

        # Call parent cleanup
        super().cleanup()


if __name__ == '__main__':
    # Override the temp directory before running
    test = GuiAssetTest(__file__)

    # Signal handler for clean shutdown
    def signal_handler(_signum, _frame):
        print("\nReceived interrupt signal, shutting down...")
        test.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    test.main()