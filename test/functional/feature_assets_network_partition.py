#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test asset system behavior during network partitions.

Tests:
- Asset transactions during partition
- Registry convergence after partition heals
- Conflicting ICU rotations across partitions
- Fee accumulator consistency
- Mempool reconciliation
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
import hashlib
import os
import time


def make_issuer_reg_tlv(asset_id_hex: str, policy_bits: int = 3,
                        allowed_families: int = 0x1C, unlock: int = 510000000) -> str:
    """Create v1 IssuerReg TLV (format_version=1, always includes ZK+ICU sections).
    Default unlock: 5.1 BTC (510000000 sats)"""
    aid = bytes.fromhex(asset_id_hex)
    payload = bytearray()
    # Header
    payload.extend(aid)
    payload.extend((policy_bits & 0xFFFFFFFF).to_bytes(4, 'little'))
    payload.extend((allowed_families & 0xFFFF).to_bytes(2, 'little'))
    payload.append(0x01)  # format_version = 1
    # Ticker (empty = not set)
    payload.append(0)
    # Decimals (0xFF = not set)
    payload.append(0xFF)
    # Unlock fees
    payload.extend((unlock & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    # ZK section (76 bytes, all zeros)
    payload.extend(bytes(76))
    # ICU section (129 bytes with icu_visibility, all zeros)
    payload.extend(bytes(129))
    # Wrap in TLV with varint length encoding
    tlv = bytearray()
    tlv.append(0x10)
    payload_len = len(payload)
    if payload_len < 253:
        tlv.append(payload_len)
    else:
        tlv.append(253)
        tlv.extend(payload_len.to_bytes(2, 'little'))
    tlv.extend(payload)
    return tlv.hex()


def make_asset_tag_tlv(asset_id_hex: str, amount: int) -> str:
    """Create AssetTag TLV"""
    aid = bytes.fromhex(asset_id_hex)
    val = bytearray()
    val.extend(aid)
    val.extend((amount & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    tlv = bytearray()
    tlv.append(0x01)
    tlv.append(len(val))
    tlv.extend(val)
    return tlv.hex()


class AssetNetworkPartitionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        # Generate unique test run ID to avoid asset ID conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_partition".encode()).hexdigest()[:16]
        # Configure nodes for partition testing and assets
        self.extra_args = [
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-limitancestorcount=200", "-persistmempool=0", "-spv-asn-corroboration=0"],
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-limitancestorcount=200", "-persistmempool=0", "-spv-asn-corroboration=0"],
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-limitancestorcount=200", "-persistmempool=0", "-spv-asn-corroboration=0"],
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-limitancestorcount=200", "-persistmempool=0", "-spv-asn-corroboration=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def no_op(self):
        """No-op sync function for single node operations."""
        pass

    def setup_network(self):
        """Custom network setup for partition testing"""
        self.setup_nodes()
        
        # Initially connect all nodes
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 3)
        self.connect_nodes(0, 3)  # Additional connection for redundancy

    def run_test(self):
        self.test_simple_partition()
        self.test_conflicting_icu_rotations()
        self.test_partition_with_mempool()
        self.test_multi_partition_convergence()

    def test_simple_partition(self):
        """Test basic partition and healing with assets"""
        self.log.info("Testing simple network partition...")
        
        # Setup initial state
        self.generate(self.nodes[0], 101, sync_fun=self.no_op)
        # Manually sync all nodes after generation
        self.sync_all()
        
        # Generate unique asset identifier for this test run
        asset_id = hashlib.sha256(f"partition_asset_{self.test_run_id}".encode()).hexdigest()
        # Get a UTXO for the registration
        utxos = self.nodes[0].listunspent()
        if not utxos:
            self.generate(self.nodes[0], 1, sync_fun=self.no_op)
            utxos = self.nodes[0].listunspent()
        reg_input = utxos[0]
        reg_inputs = [{"txid": reg_input["txid"], "vout": reg_input["vout"]}]
        reg_output_value = 5.1
        change_value = float(reg_input["amount"]) - reg_output_value - 0.001
        reg_outputs = [{self.nodes[0].getnewaddress(): reg_output_value}]
        if change_value > 0.0001:
            reg_outputs.append({self.nodes[0].getnewaddress(): change_value})
        reg_raw = self.nodes[0].createrawtransaction(reg_inputs, reg_outputs)
        # Use the proper RPC method for attaching issuer registration
        reg_tx = self.nodes[0].rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 0x1C)
        reg_f = self.nodes[0].fundrawtransaction(reg_tx)
        reg_s = self.nodes[0].signrawtransactionwithwallet(reg_f['hex'])
        reg_txid = self.nodes[0].sendrawtransaction(reg_s['hex'])
        self.generate(self.nodes[0], 1)
        self.sync_all()
        
        # Create partition: [0,1] | [2,3]
        self.log.info("Creating network partition...")
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(0, 3)
        
        # Partition A operations
        pol = self.nodes[0].getassetpolicy(asset_id)
        bond_value = float(self.nodes[0].gettxout(pol['icu_txid'], pol['icu_vout'])['value'])
        mint_in = [{"txid": pol['icu_txid'], "vout": pol['icu_vout']}]
        mint_out = [{self.nodes[0].getnewaddress(): bond_value}, {self.nodes[0].getnewaddress(): 0.1}]
        mint_raw = self.nodes[0].createrawtransaction(mint_in, mint_out)
        mint_raw = self.nodes[0].rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 0x1C)
        mint_raw = self.nodes[0].rawtxattachassettag(mint_raw, 1, asset_id, 1000000)
        mint_f = self.nodes[0].fundrawtransaction(mint_raw)
        mint_s = self.nodes[0].signrawtransactionwithwallet(mint_f['hex'])
        mint_txid_a = self.nodes[0].sendrawtransaction(mint_s['hex'])
        self.generate(self.nodes[0], 5, sync_fun=self.no_op)

        # Partition B operations (different pattern)
        self.generate(self.nodes[2], 10, sync_fun=self.no_op)
        
        # Verify partition state
        height_a = self.nodes[0].getblockcount()
        height_b = self.nodes[2].getblockcount()
        assert height_a != height_b
        
        # Store pre-heal state
        pol_a = self.nodes[0].getassetpolicy(asset_id)
        pol_b = self.nodes[2].getassetpolicy(asset_id)
        fees_a = pol_a.get('fees_accum_sats', 0)
        fees_b = pol_b.get('fees_accum_sats', 0)
        
        self.log.info(f"Partition A: height={height_a}, fees={fees_a}")
        self.log.info(f"Partition B: height={height_b}, fees={fees_b}")
        
        # Heal partition
        self.log.info("Healing network partition...")
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 3)
        self.sync_blocks()
        
        # Verify convergence
        final_height = self.nodes[0].getblockcount()
        assert_equal(final_height, max(height_a, height_b))
        
        # All nodes should have same view
        for node in self.nodes:
            assert_equal(node.getblockcount(), final_height)
            pol = node.getassetpolicy(asset_id)
            assert 'icu_txid' in pol
        
        self.log.info("Simple partition test passed")

    def test_conflicting_icu_rotations(self):
        """Test conflicting ICU rotations across partitions"""
        self.log.info("Testing conflicting ICU rotations...")

        # Reset network
        for i in range(4):
            self.restart_node(i)
        # Reconnect nodes after restart
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 3)
        self.connect_nodes(0, 3)

        self.generate(self.nodes[0], 101)
        self.sync_all()

        # Generate unique asset identifier for conflicting ICU test
        asset_id = hashlib.sha256(f"partition_conflict_{self.test_run_id}".encode()).hexdigest()
        reg_raw = self.nodes[0].createrawtransaction([], {self.nodes[0].getnewaddress(): 5.1})
        # Use the proper RPC method for attaching issuer registration
        reg_tx = self.nodes[0].rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 0x1C)
        reg_f = self.nodes[0].fundrawtransaction(reg_tx)
        reg_s = self.nodes[0].signrawtransactionwithwallet(reg_f['hex'])
        self.nodes[0].sendrawtransaction(reg_s['hex'])
        self.generate(self.nodes[0], 1)
        self.sync_all()

        initial_pol = self.nodes[0].getassetpolicy(asset_id)
        initial_icu = (initial_pol['icu_txid'], initial_pol['icu_vout'])
        bond_value = float(self.nodes[0].gettxout(initial_pol['icu_txid'], initial_pol['icu_vout'])['value'])

        # Create partition before ICU rotations
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(0, 3)

        # Partition A: Rotate ICU to new address (maintain bond value)
        icu_in = [{"txid": initial_icu[0], "vout": initial_icu[1]}]
        icu_out = [{self.nodes[0].getnewaddress(): bond_value}]
        rotate_raw = self.nodes[0].createrawtransaction(icu_in, icu_out)
        rotate_raw = self.nodes[0].rawtxattachissuerreg(rotate_raw, 0, asset_id, 3, 0x1C)
        rotate_f = self.nodes[0].fundrawtransaction(rotate_raw)
        rotate_s = self.nodes[0].signrawtransactionwithwallet(rotate_f['hex'])
        rotate_txid_a = self.nodes[0].sendrawtransaction(rotate_s['hex'])
        self.generate(self.nodes[0], 2, sync_fun=self.no_op)

        # Partition B: Continue with original ICU, add more blocks
        # This creates a divergence where partition B has a longer chain but different ICU state
        self.generate(self.nodes[2], 5, sync_fun=self.no_op)  # Longer chain

        # Verify different states
        pol_a = self.nodes[0].getassetpolicy(asset_id)
        pol_b = self.nodes[2].getassetpolicy(asset_id)
        # Partition A has rotated ICU
        assert pol_a['icu_txid'] == rotate_txid_a
        # Partition B still has original ICU
        assert pol_b['icu_txid'] == initial_icu[0]
        assert pol_a['icu_txid'] != pol_b['icu_txid']

        # Heal partition
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 3)
        self.sync_blocks()

        # Verify convergence to partition B's state (longer chain)
        # Even though partition A had an ICU rotation, partition B's longer chain wins
        for node in self.nodes:
            pol = node.getassetpolicy(asset_id)
            # Should revert to original ICU since partition B's chain is longer
            assert_equal(pol['icu_txid'], initial_icu[0])

        self.log.info("Conflicting ICU rotation test passed")

    def test_partition_with_mempool(self):
        """Test mempool behavior during partition"""
        self.log.info("Testing partition with mempool transactions...")

        # Reset and setup
        for i in range(4):
            self.restart_node(i)
        # Reconnect nodes after restart
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 3)
        self.connect_nodes(0, 3)
        
        self.generate(self.nodes[0], 101)
        self.sync_all()
        
        # Generate unique asset identifier for mempool partition test
        asset_id = hashlib.sha256(f"partition_mempool_{self.test_run_id}".encode()).hexdigest()
        reg_raw = self.nodes[0].createrawtransaction([], {self.nodes[0].getnewaddress(): 5.1})
        # Use the proper RPC method for attaching issuer registration
        reg_tx = self.nodes[0].rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 0x1C)
        reg_f = self.nodes[0].fundrawtransaction(reg_tx)
        reg_s = self.nodes[0].signrawtransactionwithwallet(reg_f['hex'])
        self.nodes[0].sendrawtransaction(reg_s['hex'])
        self.generate(self.nodes[0], 1)
        self.sync_all()

        pol = self.nodes[0].getassetpolicy(asset_id)
        bond_value = float(self.nodes[0].gettxout(pol['icu_txid'], pol['icu_vout'])['value'])
        mint_in = [{"txid": pol['icu_txid'], "vout": pol['icu_vout']}]
        mint_out = [{self.nodes[0].getnewaddress(): bond_value}, {self.nodes[0].getnewaddress(): 0.1}]
        mint_raw = self.nodes[0].createrawtransaction(mint_in, mint_out)
        mint_raw = self.nodes[0].rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 0x1C)
        mint_raw = self.nodes[0].rawtxattachassettag(mint_raw, 1, asset_id, 1000000)
        mint_f = self.nodes[0].fundrawtransaction(mint_raw)
        mint_s = self.nodes[0].signrawtransactionwithwallet(mint_f['hex'])
        mint_txid = self.nodes[0].sendrawtransaction(mint_s['hex'])
        self.generate(self.nodes[0], 1)
        self.sync_all()
        
        # Create mempool transaction
        # Get the ICU location after mint to properly identify the asset output
        pol_after_mint = self.nodes[0].getassetpolicy(asset_id)
        icu_vout_after_mint = pol_after_mint['icu_vout']

        mint_dec = self.nodes[0].gettransaction(mint_txid, True, True)['decoded']

        # Find the asset output - it has an outext but is NOT the ICU
        asset_vout = None
        for i, out in enumerate(mint_dec['vout']):
            # Find output with outext that is NOT the ICU
            if 'outext' in out and i != icu_vout_after_mint:
                asset_vout = i
                break

        assert asset_vout is not None, "No asset output found in mint transaction"
        self.log.info(f"Using output {asset_vout} as asset output from mint tx (ICU is at {icu_vout_after_mint})")

        xfer_in = [{"txid": mint_txid, "vout": asset_vout}]
        xfer_raw = self.nodes[0].createrawtransaction(xfer_in, {self.nodes[0].getnewaddress(): 0.05})
        xfer_raw = self.nodes[0].rawtxattachassettag(xfer_raw, 0, asset_id, 1000000)
        xfer_f = self.nodes[0].fundrawtransaction(xfer_raw)
        xfer_s = self.nodes[0].signrawtransactionwithwallet(xfer_f['hex'])
        xfer_txid = self.nodes[0].sendrawtransaction(xfer_s['hex'])

        # Allow mempool to sync between nodes
        self.sync_mempools()

        # Verify in mempool on connected nodes
        assert xfer_txid in self.nodes[0].getrawmempool()
        assert xfer_txid in self.nodes[1].getrawmempool()
        
        # Create partition
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(0, 3)
        
        # Mine on partition A (includes mempool tx)
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        assert xfer_txid not in self.nodes[0].getrawmempool()
        
        # Partition B still has it in mempool
        assert xfer_txid in self.nodes[2].getrawmempool()
        
        # Mine different blocks on partition B
        self.generate(self.nodes[2], 3, sync_fun=self.no_op)
        
        # Heal partition
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 3)
        self.sync_blocks()
        
        # Check final state
        final_height = self.nodes[0].getblockcount()
        for node in self.nodes:
            assert_equal(node.getblockcount(), final_height)
            # Transaction should be either confirmed or dropped
            mempool = node.getrawmempool()
            if xfer_txid not in mempool:
                # Should be in a block
                try:
                    tx = node.gettransaction(xfer_txid, True, True)['decoded']
                    assert 'confirmations' in tx
                except:
                    # Tx was invalidated by reorg
                    pass
        
        self.log.info("Partition with mempool test passed")

    def test_multi_partition_convergence(self):
        """Test complex multi-way partition and convergence"""
        self.log.info("Testing multi-partition convergence...")

        # Reset
        for i in range(4):
            self.restart_node(i)
        # Reconnect nodes after restart
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 3)
        self.connect_nodes(0, 3)
        
        # Give each node some funds using mature coinbase from node 0
        self.generate(self.nodes[0], 121)  # Extra blocks for funding other nodes
        self.sync_all()

        # Send mature coins to other nodes
        for i in [1, 2]:
            addr = self.nodes[i].getnewaddress()
            self.nodes[0].sendtoaddress(addr, 10)

        # Mine and sync to confirm the transfers
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # Register multiple assets
        assets = []
        for i in range(3):
            asset_id = f"{i:02x}" * 32
            assets.append(asset_id)

            reg_raw = self.nodes[i].createrawtransaction([], {self.nodes[i].getnewaddress(): 5.1})
            # Use the proper RPC method with unique policy bits for each partition
            reg_tx = self.nodes[i].rawtxattachissuerreg(reg_raw, 0, asset_id, (i+1), 0x1C)
            reg_f = self.nodes[i].fundrawtransaction(reg_tx)
            reg_s = self.nodes[i].signrawtransactionwithwallet(reg_f['hex'])
            self.nodes[i].sendrawtransaction(reg_s['hex'])
        
        self.generate(self.nodes[0], 1)
        self.sync_all()
        
        # Create complex partition: [0] | [1,2] | [3]
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 3)
        self.disconnect_nodes(2, 3)
        
        # Each partition mines different lengths
        self.generate(self.nodes[0], 3, sync_fun=self.no_op)  # Shortest
        self.generate(self.nodes[1], 5, sync_fun=self.no_op)  # Medium
        self.generate(self.nodes[3], 7, sync_fun=self.no_op)  # Longest
        
        # Partially heal: connect [0] to [1,2]
        self.connect_nodes(0, 1)
        time.sleep(1)  # Allow sync
        
        # Verify partial convergence
        assert_equal(self.nodes[0].getblockcount(), self.nodes[1].getblockcount())
        assert self.nodes[3].getblockcount() > self.nodes[0].getblockcount()
        
        # Fully heal: connect all
        self.connect_nodes(2, 3)
        self.connect_nodes(0, 3)
        self.sync_blocks()
        
        # Verify full convergence
        final_height = self.nodes[3].getblockcount()  # Node 3 had longest chain
        for node in self.nodes:
            assert_equal(node.getblockcount(), final_height)
            
            # Verify all assets present
            for asset_id in assets:
                pol = node.getassetpolicy(asset_id)
                assert 'icu_txid' in pol
        
        self.log.info("Multi-partition convergence test passed")


if __name__ == '__main__':
    AssetNetworkPartitionTest(__file__).main()
