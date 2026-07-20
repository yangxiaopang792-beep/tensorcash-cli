#!/usr/bin/env python3
"""
Clean GUI asset test - GUI runs as a separate third node, receives assets via transfers
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
from test_framework.authproxy import AuthServiceProxy
from test_framework.util import p2p_port


class CleanGuiAssetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2  # node0 and node1 stay as bitcoind
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_gui".encode()).hexdigest()[:16]
        self.extra_args = [["-assetsheight=0"], ["-assetsheight=0"]]
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

        self.wallet0 = self.nodes[0].get_wallet_rpc("")
        self.wallet1 = self.nodes[1].get_wallet_rpc("")

        # Mine initial blocks and fund node0
        self.log.info("Setting up initial funds...")
        miner_addr = self.wallet1.getnewaddress()
        self.generatetoaddress(self.nodes[1], 120, miner_addr)
        self.sync_all()

        # Send funds to node0 in multiple UTXOs for better fee management
        for i in range(5):
            asset_addr = self.wallet0.getnewaddress()
            self.wallet1.sendtoaddress(asset_addr, 20)  # 5x20 = 100 BTC total
        self.generatetoaddress(self.nodes[1], 1, miner_addr)
        self.sync_all()

        self.log.info(f"Node0 balance: {self.wallet0.getbalance()} BTC")

        # Register and mint assets on node0
        self.log.info("Registering and minting assets on node0...")

        # GOLD
        self.log.info("Registering GOLD...")
        reg_addr = self.wallet0.getnewaddress()
        gold_id = "1111111111111111111111111111111111111111111111111111111111111111"
        self.wallet0.registerasset(
            reg_addr, 5.1, gold_id, 3, 28, 510000000, "GOLD", 8,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()
        self.wait_until(lambda: self.nodes[0].getassetpolicy(gold_id) is not None)

        # Mint GOLD
        self.log.info("Minting 10.0 GOLD...")
        policy = self.nodes[0].getassetpolicy(gold_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()
        self.wallet0.mintasset(
            policy['icu_txid'], policy['icu_vout'],
            icu_addr_new, 5.1,
            asset_addr, 0.001,
            gold_id, 1000000000,  # 10.0 with 8 decimals
            3, 28, 510000000,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()

        # SILVER
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
        self.log.info("Minting 1000 SILVER...")
        policy = self.nodes[0].getassetpolicy(silver_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()
        self.wallet0.mintasset(
            policy['icu_txid'], policy['icu_vout'],
            icu_addr_new, 5.1,
            asset_addr, 0.001,
            silver_id, 1000000000,  # 1000 with 6 decimals
            3, 28, 510000000,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()

        # TEST
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
        self.log.info("Minting 5.0 TEST...")
        policy = self.nodes[0].getassetpolicy(test_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()
        self.wallet0.mintasset(
            policy['icu_txid'], policy['icu_vout'],
            icu_addr_new, 5.1,
            asset_addr, 0.001,
            test_id, 500000000,  # 5.0 with 8 decimals
            3, 28, 510000000,
            {"autofund": True, "broadcast": True}
        )
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.sync_all()

        # Generate extra blocks to confirm everything
        self.log.info("Generating confirmation blocks...")
        self.generate(self.nodes[1], 5, sync_fun=self.sync_all)
        self.sync_all()

        # Force chainstate flush after minting (like the original test does)
        self.log.info("Flushing chainstate after asset minting...")
        for node in self.nodes:
            node.gettxoutsetinfo()

        # Verify assets on node0
        self.log.info("Node0 asset balances:")
        asset_balances = self.wallet0.getassetbalance()
        for asset in asset_balances:
            self.log.info(f"  {asset['ticker']}: {asset['balance_decimal']}")

        # NOW LAUNCH GUI AS A THIRD SEPARATE NODE
        self.log.info("")
        self.log.info("Launching GUI as a separate third node...")

        # Clean up any previous GUI instance
        gui_datadir = "/root/tensorcash-gui-wallet"
        subprocess.run(["rm", "-rf", gui_datadir], capture_output=True)
        os.makedirs(gui_datadir, exist_ok=True)

        # Get actual ports being used by node0 and node1
        node0_p2p = p2p_port(0)
        node1_p2p = p2p_port(1)

        # Use a very high port for GUI to avoid any conflicts
        gui_rpc_port = 48556

        self.log.info(f"Node0 P2P port: {node0_p2p}, Node1 P2P port: {node1_p2p}")
        self.log.info(f"GUI will use RPC port: {gui_rpc_port}")

        gui_cmd = [
            "/build/bcore/build/bin/bitcoin-qt",
            f"-datadir={gui_datadir}",
            "-regtest",
            "-server=1",
            "-listen=1",  # Need to listen for proper P2P communication
            f"-port={gui_rpc_port - 100}",  # Use a unique P2P port
            f"-rpcport={gui_rpc_port}",
            "-rpcuser=test",
            "-rpcpassword=test",
            "-fallbackfee=0.00001",
            "-assetsheight=0",
            "-policymaxassetspertx=100",
            f"-addnode=127.0.0.1:{node0_p2p}",  # Connect to node0's actual port
            f"-addnode=127.0.0.1:{node1_p2p}"   # Connect to node1's actual port
        ]

        self.gui_process = subprocess.Popen(gui_cmd, env={**os.environ, "DISPLAY": ":1"})
        self.log.info(f"GUI started with PID: {self.gui_process.pid}")

        # Wait for GUI to start
        self.log.info("Waiting for GUI to start...")
        time.sleep(10)

        # Connect to GUI via RPC
        gui_rpc = AuthServiceProxy(f"http://test:test@127.0.0.1:{gui_rpc_port}", timeout=60)

        # Wait for GUI to sync
        self.log.info("Waiting for GUI to sync with the network...")
        synced = False
        for i in range(30):  # Wait up to 30 seconds
            try:
                info = gui_rpc.getblockchaininfo()
                if info['blocks'] >= self.nodes[1].getblockcount() - 1:
                    synced = True
                    self.log.info(f"GUI synced at block {info['blocks']}")
                    break
            except:
                pass
            time.sleep(1)

        if not synced:
            self.log.warning("GUI may not be fully synced")

        # Verify GUI can see the registered assets
        self.log.info("Checking if GUI recognizes registered assets...")
        try:
            gold_info = gui_rpc.getassetinfo("1111111111111111111111111111111111111111111111111111111111111111")
            self.log.info(f"  GUI sees GOLD: {gold_info['ticker']}")
        except Exception as e:
            self.log.error(f"  GUI cannot see GOLD: {e}")

        try:
            silver_info = gui_rpc.getassetinfo("2222222222222222222222222222222222222222222222222222222222222222")
            self.log.info(f"  GUI sees SILVER: {silver_info['ticker']}")
        except Exception as e:
            self.log.error(f"  GUI cannot see SILVER: {e}")

        # Create wallet in GUI
        self.log.info("Creating wallet in GUI...")
        try:
            gui_rpc.createwallet("")
        except:
            pass  # Wallet might already exist

        # Get GUI address
        gui_addr = gui_rpc.getnewaddress()
        self.log.info(f"GUI wallet address: {gui_addr}")

        # Send some BTC to GUI first
        self.log.info("Sending 10 BTC to GUI wallet...")
        self.wallet0.sendtoaddress(gui_addr, 10)
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        time.sleep(2)

        # Now send assets to GUI
        self.log.info("Sending assets to GUI wallet...")

        # Make sure we have enough BTC for fees
        btc_balance = self.wallet0.getbalance()
        self.log.info(f"Node0 BTC balance: {btc_balance}")

        # Send GOLD - 1.0
        self.log.info("Sending 1.0 GOLD to GUI...")
        try:
            self.wallet0.sendasset("GOLD", gui_addr, 100000000)  # 1.0 with 8 decimals
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send GOLD: {e}")

        # Send SILVER - 500 (this SHOULD work with correct math)
        self.log.info("Sending 500 SILVER to GUI...")
        try:
            self.wallet0.sendasset("SILVER", gui_addr, 500000000)  # 500 with 6 decimals (500 * 10^6)
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send SILVER: {e}")

        # Send TEST - just 0.5
        self.log.info("Sending 0.5 TEST to GUI...")
        try:
            self.wallet0.sendasset("TEST", gui_addr, 50000000)  # 0.5 with 8 decimals
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send TEST: {e}")

        # Generate more blocks to confirm
        self.generate(self.nodes[1], 3, sync_fun=self.sync_all)
        time.sleep(5)

        # Rotate GOLD ICU to GUI wallet via mint
        self.log.info("Rotating GOLD ICU to GUI wallet via mint...")
        try:
            gold_policy = self.nodes[0].getassetpolicy(gold_id)
            # Get a new address from GUI wallet for the ICU
            gui_icu_addr = gui_rpc.getnewaddress()
            gui_asset_addr = gui_rpc.getnewaddress()

            # Mint a small amount to GUI and rotate ICU there
            self.wallet0.mintasset(
                gold_policy['icu_txid'],
                gold_policy['icu_vout'],
                gui_icu_addr,  # ICU goes to GUI wallet
                5.1,           # ICU amount
                gui_asset_addr,  # Asset output also to GUI
                0.001,         # BTC for asset output
                gold_id,
                100000000,     # Mint 1.0 more GOLD (8 decimals)
                3, 28, 510000000,
                {"autofund": True, "broadcast": True}
            )
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)

            # Verify ICU was transferred
            new_policy = gui_rpc.getassetpolicy(gold_id)
            if new_policy and new_policy['icu_address'] == gui_icu_addr:
                self.log.info(f"  GOLD ICU transferred to GUI wallet at {gui_icu_addr}")
            else:
                self.log.warning("  Could not verify ICU transfer")
        except Exception as e:
            self.log.error(f"Failed to transfer GOLD ICU: {e}")

        # Check GUI balances (with error handling)
        self.log.info("Checking GUI wallet balances...")
        try:
            gui_btc = gui_rpc.getbalance()
            self.log.info(f"  BTC: {gui_btc}")

            gui_assets = gui_rpc.getassetbalance()
            self.log.info("  Assets:")
            for asset in gui_assets:
                self.log.info(f"    {asset['ticker']}: {asset['balance_decimal']}")
        except Exception as e:
            self.log.warning(f"Could not get GUI balances: {e}")

        # Start continuous mining
        self.log.info("Starting continuous mining...")
        test_framework = self
        mining_node = self.nodes[1]

        def mine_continuously():
            while True:
                try:
                    blockcount = mining_node.getblockcount()
                    test_framework.log.info(f"Mining block {blockcount + 1}...")
                    test_framework.generate(mining_node, 1, sync_fun=test_framework.no_op)
                    time.sleep(10)
                except Exception as e:
                    test_framework.log.error(f"Mining error: {e}")
                    break

        import threading
        mining_thread = threading.Thread(target=mine_continuously, daemon=True)
        mining_thread.start()

        # Print status
        self.log.info("")
        self.log.info("=" * 60)
        self.log.info("GUI ASSET TEST RUNNING")
        self.log.info("=" * 60)
        self.log.info("VNC: vnc://localhost:5901 (password: password)")
        self.log.info(f"GUI PID: {self.gui_process.pid}")
        self.log.info("")
        self.log.info("GUI should show:")
        self.log.info("  BTC: ~15.1+ (with ICU)")
        self.log.info("  GOLD: 2.00000000 (1.0 sent + 1.0 minted, + ICU control)")
        self.log.info("  SILVER: 500.000000")
        self.log.info("  TEST: 0.50000000")
        self.log.info("")
        self.log.info("Network:")
        self.log.info("  Node0 (asset holder) on port 18444")
        self.log.info("  Node1 (miner) on port 18554")
        self.log.info("  GUI (separate wallet) on port 38555")
        self.log.info("")
        self.log.info("Press Ctrl+C to stop")
        self.log.info("=" * 60)

        # Keep running
        try:
            while True:
                time.sleep(1)
                if self.gui_process.poll() is not None:
                    self.log.error("GUI exited unexpectedly")
                    break
        except KeyboardInterrupt:
            self.log.info("Shutting down...")

    def cleanup(self):
        """Override cleanup to handle GUI"""
        if hasattr(self, 'gui_process'):
            self.log.info("Terminating GUI...")
            self.gui_process.terminate()
            try:
                self.gui_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.gui_process.kill()
        super().cleanup()


if __name__ == '__main__':
    test = CleanGuiAssetTest(__file__)

    def signal_handler(_signum, _frame):
        print("\nShutting down...")
        test.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    test.main()