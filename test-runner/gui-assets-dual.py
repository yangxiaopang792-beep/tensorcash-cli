#!/usr/bin/env python3
"""
Dual GUI asset test - Two separate GUI wallets for testing wallet-to-wallet flows
- Node0 and Node1: bitcoind nodes (mining)
- GUI1: bitcoin-qt on VNC :1 (port 5901)
- GUI2: bitcoin-qt on VNC :2 (port 5902)
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


class DualGuiAssetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2  # node0 and node1 stay as bitcoind
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_dual_gui".encode()).hexdigest()[:16]
        self.extra_args = [["-assetsheight=0"], ["-assetsheight=0"]]
        self.options.tmpdir = "/root/tensorcash-dual-gui"

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def run_test(self):
        # Start VNC server 1 for GUI1
        self.log.info("Starting VNC server :1 for GUI1...")
        try:
            subprocess.run(["vncserver", "-kill", ":1"], capture_output=True)
        except:
            pass
        subprocess.run(["rm", "-rf", "/tmp/.X1-lock", "/tmp/.X11-unix/X1"], capture_output=True)
        subprocess.run(["vncserver", ":1", "-geometry", "1280x800", "-depth", "24", "-localhost", "no"], check=True)
        self.log.info("VNC server :1 started (port 5901)")

        # Start VNC server 2 for GUI2
        self.log.info("Starting VNC server :2 for GUI2...")
        try:
            subprocess.run(["vncserver", "-kill", ":2"], capture_output=True)
        except:
            pass
        subprocess.run(["rm", "-rf", "/tmp/.X2-lock", "/tmp/.X11-unix/X2"], capture_output=True)
        subprocess.run(["vncserver", ":2", "-geometry", "1280x800", "-depth", "24", "-localhost", "no"], check=True)
        self.log.info("VNC server :2 started (port 5902)")

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
        self.log.info("Minting 20.0 GOLD...")
        policy = self.nodes[0].getassetpolicy(gold_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()
        self.wallet0.mintasset(
            policy['icu_txid'], policy['icu_vout'],
            icu_addr_new, 5.1,
            asset_addr, 0.001,
            gold_id, 2000000000,  # 20.0 with 8 decimals
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
        self.log.info("Minting 2000 SILVER...")
        policy = self.nodes[0].getassetpolicy(silver_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()
        self.wallet0.mintasset(
            policy['icu_txid'], policy['icu_vout'],
            icu_addr_new, 5.1,
            asset_addr, 0.001,
            silver_id, 2000000000,  # 2000 with 6 decimals
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
        self.log.info("Minting 10.0 TEST...")
        policy = self.nodes[0].getassetpolicy(test_id)
        icu_addr_new = self.wallet0.getnewaddress()
        asset_addr = self.wallet0.getnewaddress()
        self.wallet0.mintasset(
            policy['icu_txid'], policy['icu_vout'],
            icu_addr_new, 5.1,
            asset_addr, 0.001,
            test_id, 1000000000,  # 10.0 with 8 decimals
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

        # Force chainstate flush
        self.log.info("Flushing chainstate...")
        for node in self.nodes:
            node.gettxoutsetinfo()

        # Verify assets on node0
        self.log.info("Node0 asset balances:")
        asset_balances = self.wallet0.getassetbalance()
        for asset in asset_balances:
            self.log.info(f"  {asset['ticker']}: {asset['balance_decimal']}")

        # Get actual ports being used by node0 and node1
        node0_p2p = p2p_port(0)
        node1_p2p = p2p_port(1)
        self.log.info(f"Node0 P2P port: {node0_p2p}, Node1 P2P port: {node1_p2p}")

        # LAUNCH GUI1
        self.log.info("")
        self.log.info("=" * 60)
        self.log.info("Launching GUI1 (Wallet 1)...")
        self.log.info("=" * 60)

        gui1_datadir = "/root/tensorcash-gui1"
        subprocess.run(["rm", "-rf", gui1_datadir], capture_output=True)
        os.makedirs(gui1_datadir, exist_ok=True)

        gui1_rpc_port = 48556
        gui1_p2p_port = 48456

        gui1_cmd = [
            "/build/bcore/build/bin/bitcoin-qt",
            f"-datadir={gui1_datadir}",
            "-regtest",
            "-server=1",
            "-listen=1",
            f"-port={gui1_p2p_port}",
            f"-rpcport={gui1_rpc_port}",
            "-rpcuser=test",
            "-rpcpassword=test",
            "-fallbackfee=0.00001",
            "-assetsheight=0",
            "-policymaxassetspertx=100",
            "-cosignbridge=/build/bcore/build/bin/cosign-bridge",
            "-guiinstance=0",
            f"-addnode=127.0.0.1:{node0_p2p}",
            f"-addnode=127.0.0.1:{node1_p2p}"
        ]

        self.gui1_process = subprocess.Popen(gui1_cmd, env={**os.environ, "DISPLAY": ":1"})
        self.log.info(f"GUI1 started with PID: {self.gui1_process.pid} on VNC :1 (port 5901)")
        self.log.info(f"GUI1 RPC: {gui1_rpc_port}, P2P: {gui1_p2p_port}")

        # Wait for GUI1 to fully start before launching GUI2
        self.log.info("Waiting for GUI1 to initialize...")
        time.sleep(8)

        # LAUNCH GUI2
        self.log.info("")
        self.log.info("=" * 60)
        self.log.info("Launching GUI2 (Wallet 2)...")
        self.log.info("=" * 60)

        gui2_datadir = "/root/tensorcash-gui2"
        subprocess.run(["rm", "-rf", gui2_datadir], capture_output=True)
        os.makedirs(gui2_datadir, exist_ok=True)

        gui2_rpc_port = 48558
        gui2_p2p_port = 48458

        gui2_cmd = [
            "/build/bcore/build/bin/bitcoin-qt",
            f"-datadir={gui2_datadir}",
            "-regtest",
            "-server=1",
            "-listen=1",
            f"-port={gui2_p2p_port}",
            f"-rpcport={gui2_rpc_port}",
            "-rpcuser=test",
            "-rpcpassword=test",
            "-fallbackfee=0.00001",
            "-assetsheight=0",
            "-policymaxassetspertx=100",
            "-cosignbridge=/build/bcore/build/bin/cosign-bridge",
            "-guiinstance=1",
            f"-addnode=127.0.0.1:{node0_p2p}",
            f"-addnode=127.0.0.1:{node1_p2p}"
        ]

        self.gui2_process = subprocess.Popen(gui2_cmd, env={**os.environ, "DISPLAY": ":2"})
        self.log.info(f"GUI2 started with PID: {self.gui2_process.pid} on VNC :2 (port 5902)")
        self.log.info(f"GUI2 RPC: {gui2_rpc_port}, P2P: {gui2_p2p_port}")

        # Wait for GUI2 to start
        self.log.info("Waiting for GUI2 to initialize...")
        time.sleep(10)

        # Connect to GUIs via RPC
        gui1_rpc = AuthServiceProxy(f"http://test:test@127.0.0.1:{gui1_rpc_port}", timeout=60)
        gui2_rpc = AuthServiceProxy(f"http://test:test@127.0.0.1:{gui2_rpc_port}", timeout=60)

        # Wait for GUI1 to sync
        self.log.info("Waiting for GUI1 to sync...")
        for i in range(30):
            try:
                info = gui1_rpc.getblockchaininfo()
                if info['blocks'] >= self.nodes[1].getblockcount() - 1:
                    self.log.info(f"GUI1 synced at block {info['blocks']}")
                    break
            except:
                pass
            time.sleep(1)

        # Wait for GUI2 to sync
        self.log.info("Waiting for GUI2 to sync...")
        for i in range(30):
            try:
                info = gui2_rpc.getblockchaininfo()
                if info['blocks'] >= self.nodes[1].getblockcount() - 1:
                    self.log.info(f"GUI2 synced at block {info['blocks']}")
                    break
            except:
                pass
            time.sleep(1)

        # Create wallets in both GUIs
        self.log.info("Creating wallets in GUIs...")
        try:
            gui1_rpc.createwallet("")
        except:
            pass
        try:
            gui2_rpc.createwallet("")
        except:
            pass

        # Get addresses from both GUIs - use bech32m for Taproot
        gui1_addr = gui1_rpc.getnewaddress("", "bech32m")
        gui2_addr = gui2_rpc.getnewaddress("", "bech32m")
        self.log.info(f"GUI1 address (bech32m): {gui1_addr}")
        self.log.info(f"GUI2 address (bech32m): {gui2_addr}")

        # Fund both GUI wallets with BTC
        self.log.info("Sending 50 BTC to GUI1...")
        self.wallet0.sendtoaddress(gui1_addr, 50)
        self.log.info("Sending 20 BTC to GUI2...")
        self.wallet0.sendtoaddress(gui2_addr, 20)
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        time.sleep(3)

        # Send assets to GUI1
        self.log.info("Sending assets to GUI1...")
        try:
            self.wallet0.sendasset("GOLD", gui1_addr, 1000000000)  # 10.0 GOLD
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send GOLD to GUI1: {e}")

        try:
            self.wallet0.sendasset("SILVER", gui1_addr, 1000000000)  # 1000 SILVER
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send SILVER to GUI1: {e}")

        try:
            self.wallet0.sendasset("TEST", gui1_addr, 500000000)  # 5.0 TEST
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send TEST to GUI1: {e}")

        # Send assets to GUI2
        self.log.info("Sending assets to GUI2...")
        try:
            self.wallet0.sendasset("GOLD", gui2_addr, 1000000000)  # 10.0 GOLD
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send GOLD to GUI2: {e}")

        try:
            self.wallet0.sendasset("SILVER", gui2_addr, 1000000000)  # 1000 SILVER
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send SILVER to GUI2: {e}")

        try:
            self.wallet0.sendasset("TEST", gui2_addr, 500000000)  # 5.0 TEST
            self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
            time.sleep(2)
        except Exception as e:
            self.log.error(f"Failed to send TEST to GUI2: {e}")

        # Generate more blocks to confirm
        self.generate(self.nodes[1], 3, sync_fun=self.sync_all)
        time.sleep(5)

        # Check GUI1 balances
        self.log.info("Checking GUI1 wallet balances...")
        try:
            gui1_btc = gui1_rpc.getbalance()
            self.log.info(f"  GUI1 BTC: {gui1_btc}")
            gui1_assets = gui1_rpc.getassetbalance()
            self.log.info("  GUI1 Assets:")
            for asset in gui1_assets:
                self.log.info(f"    {asset['ticker']}: {asset['balance_decimal']}")
        except Exception as e:
            self.log.warning(f"Could not get GUI1 balances: {e}")

        # Check GUI2 balances
        self.log.info("Checking GUI2 wallet balances...")
        try:
            gui2_btc = gui2_rpc.getbalance()
            self.log.info(f"  GUI2 BTC: {gui2_btc}")
            gui2_assets = gui2_rpc.getassetbalance()
            self.log.info("  GUI2 Assets:")
            for asset in gui2_assets:
                self.log.info(f"    {asset['ticker']}: {asset['balance_decimal']}")
        except Exception as e:
            self.log.warning(f"Could not get GUI2 balances: {e}")

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
        self.log.info("=" * 70)
        self.log.info("DUAL GUI ASSET TEST RUNNING")
        self.log.info("=" * 70)
        self.log.info("")
        self.log.info("VNC CONNECTIONS:")
        self.log.info("  GUI1: vnc://localhost:5901 (password: password)")
        self.log.info("  GUI2: vnc://localhost:5902 (password: password)")
        self.log.info("")
        self.log.info("PROCESS IDs:")
        self.log.info(f"  GUI1 PID: {self.gui1_process.pid}")
        self.log.info(f"  GUI2 PID: {self.gui2_process.pid}")
        self.log.info("")
        self.log.info("EXPECTED BALANCES:")
        self.log.info("  GUI1 Wallet:")
        self.log.info("    BTC: ~50")
        self.log.info("    GOLD: 10.00000000")
        self.log.info("    SILVER: 1000.000000")
        self.log.info("    TEST: 5.00000000")
        self.log.info("")
        self.log.info("  GUI2 Wallet:")
        self.log.info("    BTC: ~20")
        self.log.info("    GOLD: 10.00000000")
        self.log.info("    SILVER: 1000.000000")
        self.log.info("    TEST: 5.00000000")
        self.log.info("")
        self.log.info("NETWORK TOPOLOGY:")
        self.log.info(f"  Node0 (asset holder): port {node0_p2p}")
        self.log.info(f"  Node1 (miner): port {node1_p2p}")
        self.log.info(f"  GUI1: port {gui1_p2p_port} (RPC: {gui1_rpc_port})")
        self.log.info(f"  GUI2: port {gui2_p2p_port} (RPC: {gui2_rpc_port})")
        self.log.info("")
        self.log.info("TEST SCENARIOS:")
        self.log.info("  - Send assets from GUI1 to GUI2")
        self.log.info("  - Send assets from GUI2 to GUI1")
        self.log.info("  - Both wallets broadcast to the mining nodes")
        self.log.info("  - Transactions are confirmed by continuous mining")
        self.log.info("")
        self.log.info("Press Ctrl+C to stop")
        self.log.info("=" * 70)

        # Keep running
        try:
            while True:
                time.sleep(1)
                if self.gui1_process.poll() is not None:
                    self.log.error("GUI1 exited unexpectedly")
                    break
                if self.gui2_process.poll() is not None:
                    self.log.error("GUI2 exited unexpectedly")
                    break
        except KeyboardInterrupt:
            self.log.info("Shutting down...")

    def cleanup(self):
        """Override cleanup to handle both GUI processes"""
        if hasattr(self, 'gui1_process'):
            self.log.info("Terminating GUI1...")
            self.gui1_process.terminate()
            try:
                self.gui1_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.gui1_process.kill()

        if hasattr(self, 'gui2_process'):
            self.log.info("Terminating GUI2...")
            self.gui2_process.terminate()
            try:
                self.gui2_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.gui2_process.kill()

        # Kill VNC servers
        try:
            subprocess.run(["vncserver", "-kill", ":1"], capture_output=True)
            subprocess.run(["vncserver", "-kill", ":2"], capture_output=True)
        except:
            pass

        super().cleanup()


if __name__ == '__main__':
    test = DualGuiAssetTest(__file__)

    def signal_handler(_signum, _frame):
        print("\nShutting down...")
        test.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    test.main()
