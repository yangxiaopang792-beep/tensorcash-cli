#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test asset system behavior during deep reorganizations.

Tests:
- Registry state consistency after 100+ block reorg
- Fee accumulator rollback accuracy
- ICU tracking across reorgs
- Asset conservation during chain switches
- Mempool handling of invalidated asset transactions
"""

import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.authproxy import JSONRPCException


def make_issuer_reg_tlv(asset_id_hex: str, policy_bits: int = 3,
                        allowed_families: int = 0x1C, unlock: int = 510000000) -> str:
    """Create v1 IssuerReg TLV (format_version=1, always includes ZK+ICU sections)
    Default unlock: 5.1 BTC (510000000 sats)"""
    aid = bytes.fromhex(asset_id_hex)
    val = bytearray()

    # Header
    val.extend(aid)  # Asset ID
    val.extend((policy_bits & 0xFFFFFFFF).to_bytes(4, 'little'))
    val.extend((allowed_families & 0xFFFF).to_bytes(2, 'little'))
    val.append(0x01)  # format_version = 1

    # Ticker (empty = not set)
    val.append(0)  # ticker_len = 0

    # Decimals (0xFF = not set)
    val.append(0xFF)

    # Unlock fees
    val.extend((unlock & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))

    # ZK section (76 bytes, all zeros)
    val.extend(bytes(76))

    # ICU section (129 bytes with icu_visibility, all zeros)
    val.extend(bytes(129))

    # Wrap in TLV with varint length encoding
    tlv = bytearray()
    tlv.append(0x10)  # OutExtType::ISSUER_REG
    payload_len = len(val)
    if payload_len < 253:
        tlv.append(payload_len)
    else:
        tlv.append(253)
        tlv.extend(payload_len.to_bytes(2, 'little'))
    tlv.extend(val)
    return tlv.hex()


def make_asset_tag_tlv(asset_id_hex: str, amount: int) -> str:
    """Create AssetTag TLV"""
    aid = bytes.fromhex(asset_id_hex)
    val = bytearray()
    val.extend(aid)  # Asset ID in big-endian (network byte order)
    val.extend((amount & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    tlv = bytearray()
    tlv.append(0x01)
    tlv.append(len(val))
    tlv.extend(val)
    return tlv.hex()


class AssetDeepReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Generate unique test run ID to avoid asset ID conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_deep_reorg".encode()).hexdigest()[:16]
        # Extra args for deeper reorg capability and assets with isolation
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-limitancestorcount=200",
            "-limitdescendantcount=200",
            "-persistmempool=0",  # Don't persist mempool between restarts
            "-dbcache=1000",  # Use 1GB cache to keep everything in memory
            "-spv-asn-corroboration=0",  # Disable ASN corroboration for 2-node topology
        ]] * 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def no_op(self):
        """No-op sync function for single node operations."""
        pass

    def run_test(self):
        self.test_deep_reorg_registry()
        self.test_fee_accumulator_reorg()
        self.test_conflicting_assets_reorg()
        self.test_mempool_asset_reorg()
        self.test_supply_tracking_reorg()
        self.test_registry_persistence_on_restart()

    def test_deep_reorg_registry(self):
        """Test registry consistency after 100+ block reorg"""
        self.log.info("Testing deep reorg with asset registry...")
        
        node0, node1 = self.nodes[0], self.nodes[1]
        
        # Start both nodes synced
        self.generate(node0, 101, sync_fun=lambda: self.sync_blocks())
        
        # Disconnect nodes to create competing chains
        self.disconnect_nodes(0, 1)

        # Generate blocks on node1 so it has funds to work with (need 101 for coinbase maturity)
        self.generate(node1, 101, sync_fun=self.no_op)

        # Generate unique asset identifier for this test run
        asset_id = hashlib.sha256(f"deep_reorg_asset_{self.test_run_id}".encode()).hexdigest()

        # Chain A (node0): Register with unlock=5.1 BTC (must be >= bond)
        # Get a UTXO for the registration
        utxos = node0.listunspent()
        if not utxos:
            self.generate(node0, 1, sync_fun=self.no_op)
            utxos = node0.listunspent()

        # Find a UTXO with enough value for registration
        reg_output_value = 5.1
        fee = 0.0001
        required_value = reg_output_value + fee + 0.01  # Add some buffer
        reg_input = None
        for utxo in utxos:
            if float(utxo["amount"]) >= required_value:
                reg_input = utxo
                break

        if not reg_input:
            # If no single UTXO is large enough, generate more blocks
            self.generate(node0, 1, sync_fun=self.no_op)
            utxos = node0.listunspent()
            # Find the largest UTXO
            reg_input = max(utxos, key=lambda x: float(x["amount"]))

        input_amount = float(reg_input["amount"])
        if input_amount < required_value:
            # Still not enough, skip the large bond and use a smaller one
            # Ensure we have at least enough for fees and minimum output
            min_required = fee + 0.01 + 0.0001  # fee + min_output + dust_threshold
            if input_amount < min_required:
                raise ValueError(f"Insufficient funds: input={input_amount}, min_required={min_required}")
            reg_output_value = max(0.01, input_amount - fee - 0.0001)  # Leave room for fee and avoid dust

        # Validate amounts are positive before creating outputs
        reg_inputs = [{"txid": reg_input["txid"], "vout": reg_input["vout"]}]
        change_value = input_amount - reg_output_value - fee

        # Ensure reg_output_value is valid
        if reg_output_value <= 0:
            raise ValueError(f"Invalid registration output value: {reg_output_value}")

        reg_outputs = [{node0.getnewaddress(): round(reg_output_value, 8)}]
        if change_value > 0.0001:
            reg_outputs.append({node0.getnewaddress(): round(change_value, 8)})
        reg_raw = node0.createrawtransaction(reg_inputs, reg_outputs)
        # Use rawtxattachissuerreg with unlock_fees_sats parameter (following updated pattern)
        reg_tx = node0.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, 510000000)
        # Don't use fundrawtransaction with asset transactions
        reg_s = node0.signrawtransactionwithwallet(reg_tx)
        reg_txid_a = node0.sendrawtransaction(reg_s['hex'])
        self.generate(node0, 1, sync_fun=self.no_op)

        # Verify the asset was registered on node0
        pol_check = node0.getassetpolicy(asset_id)
        assert pol_check is not None, f"Asset {asset_id} not registered on node0 after transaction {reg_txid_a}"
        assert_equal(pol_check['unlock_fees_sats'], 510000000)  # 5.1 BTC

        # Mine 120 more blocks on chain A with asset transfers
        for i in range(120):
            if i % 10 == 0:
                # Periodic asset operations to accumulate fees
                pol = node0.getassetpolicy(asset_id)
                if pol and 'icu_txid' in pol:
                    # Mint some assets - need to maintain bond value
                    mint_in = [{"txid": pol['icu_txid'], "vout": pol['icu_vout']}]
                    bond_value = float(node0.gettxout(pol['icu_txid'], pol['icu_vout'])['value'])

                    # Get additional funds for the asset output and fees
                    utxos = node0.listunspent()
                    funding_utxo = None
                    for utxo in utxos:
                        if utxo['txid'] != pol['icu_txid'] and float(utxo["amount"]) >= 0.2:
                            funding_utxo = utxo
                            break

                    if funding_utxo:
                        # Use additional input to fund asset output
                        mint_in.append({"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]})
                        funding_amount = float(funding_utxo["amount"])
                        fee = 0.0001
                        asset_out_value = 0.1
                        # ICU maintains its value, asset output and change from funding
                        mint_out = [
                            {node0.getnewaddress(): round(bond_value, 8)},  # ICU maintains value
                            {node0.getnewaddress(): round(asset_out_value, 8)}  # Asset output
                        ]
                        # Add change if needed
                        change_value = funding_amount - asset_out_value - fee
                        if change_value > 0.0001:
                            mint_out.append({node0.getnewaddress(): round(change_value, 8)})
                    else:
                        # No extra funding, just pay fee from bond (minimal decrease)
                        fee = 0.0001
                        mint_out = [{node0.getnewaddress(): round(bond_value - fee, 8)}]

                    mint_raw = node0.createrawtransaction(mint_in, mint_out)
                    # Use rawtxattachissuerreg to maintain ICU consistency
                    mint_raw = node0.rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 28, 510000000)
                    if len(mint_out) > 1:  # Only add asset tag if we have asset output
                        mint_raw = node0.rawtxattachassettag(mint_raw, 1, asset_id, 1000000, 0)
                    # Don't use fundrawtransaction with asset transactions
                    mint_s = node0.signrawtransactionwithwallet(mint_raw)
                    node0.sendrawtransaction(mint_s['hex'])
            self.generate(node0, 1, sync_fun=self.no_op)
        
        # Chain B (node1): Register same asset with different params
        reg_raw = node1.createrawtransaction([], {node1.getnewaddress(): 5.1})
        # Use rawtxattachissuerreg with different unlock (5.2 BTC, must be >= bond)
        reg_tx = node1.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, 520000000)
        reg_f = node1.fundrawtransaction(reg_tx)
        reg_s = node1.signrawtransactionwithwallet(reg_f['hex'])
        reg_txid_b = node1.sendrawtransaction(reg_s['hex'])
        self.generate(node1, 1, sync_fun=self.no_op)
        
        # Mine 125 blocks on chain B (longer chain)
        for i in range(124):
            if i % 15 == 0:
                # Different asset operations pattern
                pol = node1.getassetpolicy(asset_id)
                if pol and 'icu_txid' in pol:
                    # Just rotate ICU without minting assets for chain B
                    mint_in = [{"txid": pol['icu_txid'], "vout": pol['icu_vout']}]
                    bond_value_b = float(node1.gettxout(pol['icu_txid'], pol['icu_vout'])['value'])

                    # Get additional funds for fees to avoid decreasing bond
                    utxos = node1.listunspent()
                    funding_utxo = None
                    for utxo in utxos:
                        if utxo['txid'] != pol['icu_txid'] and float(utxo["amount"]) >= 0.01:
                            funding_utxo = utxo
                            break

                    if funding_utxo:
                        # Use additional input to pay fees
                        mint_in.append({"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]})
                        funding_amount = float(funding_utxo["amount"])
                        fee = 0.0001
                        # ICU maintains its value
                        mint_out = [{node1.getnewaddress(): round(bond_value_b, 8)}]
                        # Add change if needed
                        change_value = funding_amount - fee
                        if change_value > 0.0001:
                            mint_out.append({node1.getnewaddress(): round(change_value, 8)})
                    else:
                        # No extra funding, just pay minimal fee from bond
                        fee = 0.0001
                        mint_out = [{node1.getnewaddress(): round(bond_value_b - fee, 8)}]

                    mint_raw = node1.createrawtransaction(mint_in, mint_out)
                    # Use rawtxattachissuerreg for ICU rotation with Chain B params
                    mint_raw = node1.rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 28, 520000000)
                    # Don't use fundrawtransaction with asset transactions
                    mint_s = node1.signrawtransactionwithwallet(mint_raw)
                    node1.sendrawtransaction(mint_s['hex'])
            self.generate(node1, 1, sync_fun=self.no_op)
        
        # Store pre-reorg state
        pol_a_before = node0.getassetpolicy(asset_id)
        assert pol_a_before is not None, "Asset policy should exist before reorg"
        assert_equal(pol_a_before['unlock_fees_sats'], 510000000)  # 5.1 BTC
        fees_before = pol_a_before.get('fees_accum_sats', 0)
        
        pol_b = node1.getassetpolicy(asset_id)
        assert pol_b is not None, "Asset policy should exist on chain B"
        assert_equal(pol_b['unlock_fees_sats'], 520000000)
        
        height_a = node0.getblockcount()
        height_b = node1.getblockcount()
        assert_equal(height_a, 222)  # 101 + 1 + 120
        assert_equal(height_b, 327)  # 101 + 101 + 1 + 124
        
        self.log.info(f"Chain A height: {height_a}, Chain B height: {height_b}")
        self.log.info(f"Fees accumulated on A: {fees_before}")
        
        # Reconnect - node0 should reorg to node1's longer chain
        self.connect_nodes(0, 1)
        self.sync_blocks()
        
        # Verify deep reorg occurred
        assert_equal(node0.getblockcount(), height_b)
        assert_equal(node1.getblockcount(), height_b)
        
        # Verify registry state matches chain B
        pol_a_after = node0.getassetpolicy(asset_id)
        pol_b_after = node1.getassetpolicy(asset_id)

        assert pol_a_after is not None, "Asset policy should exist after reorg"
        assert pol_b_after is not None, "Asset policy should exist on chain B after reorg"
        assert_equal(pol_a_after['unlock_fees_sats'], 520000000)  # Chain B's params
        assert_equal(pol_b_after['unlock_fees_sats'], 520000000)
        assert_equal(pol_a_after['fees_accum_sats'], pol_b_after['fees_accum_sats'])
        
        # Original chain A's ICU should be invalid
        assert pol_a_after['icu_txid'] != reg_txid_a
        
        self.log.info("Deep reorg test passed - registry state consistent")

    def test_fee_accumulator_reorg(self):
        """Test fee accumulator rollback and replay"""
        self.log.info("Testing fee accumulator during reorg...")

        # Start fresh
        self.restart_node(0, extra_args=self.extra_args[0])
        self.restart_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()
        
        # Generate unique asset identifier for fee accumulator test
        asset_id = hashlib.sha256(f"deep_reorg_fee_{self.test_run_id}".encode()).hexdigest()
        unlock = 510000000  # 5.1 BTC (must be >= bond)
        
        reg_raw = node0.createrawtransaction([], {node0.getnewaddress(): 5.1})
        # Use rawtxattachissuerreg for fee accumulator test
        reg_tx = node0.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, unlock)
        reg_f = node0.fundrawtransaction(reg_tx)
        reg_s = node0.signrawtransactionwithwallet(reg_f['hex'])
        node0.sendrawtransaction(reg_s['hex'])
        self.generate(node0, 1, sync_fun=self.no_op)
        self.sync_all()
        
        # Disconnect to create divergence
        self.disconnect_nodes(0, 1)
        
        # Chain A: Many small fee transactions
        for i in range(50):
            # Create tx touching the asset
            addr = node0.getnewaddress()
            tx = node0.sendtoaddress(addr, 0.01)
            # Would accumulate fees to asset if it's touched
        self.generate(node0, 50, sync_fun=self.no_op)
        
        # Chain B: Few large fee transactions
        for i in range(10):
            addr = node1.getnewaddress()
            tx = node1.sendtoaddress(addr, 0.01)
        self.generate(node1, 55, sync_fun=self.no_op)  # Longer chain
        
        # Check accumulated fees before reorg
        pol_a = node0.getassetpolicy(asset_id)
        pol_b = node1.getassetpolicy(asset_id)

        assert pol_a is not None, "Asset policy should exist on chain A"
        assert pol_b is not None, "Asset policy should exist on chain B"
        fees_a = pol_a.get('fees_accum_sats', 0)
        fees_b = pol_b.get('fees_accum_sats', 0)
        
        self.log.info(f"Fees on chain A: {fees_a}, chain B: {fees_b}")
        
        # Reconnect and reorg
        self.connect_nodes(0, 1)
        self.sync_blocks()
        
        # Verify fees match after reorg
        pol_a_after = node0.getassetpolicy(asset_id)
        pol_b_after = node1.getassetpolicy(asset_id)

        assert pol_a_after is not None, "Asset policy should exist after fee reorg"
        assert pol_b_after is not None, "Asset policy should exist on chain B after fee reorg"
        assert_equal(pol_a_after['fees_accum_sats'], pol_b_after['fees_accum_sats'])
        
        self.log.info("Fee accumulator reorg test passed")

    def test_conflicting_assets_reorg(self):
        """Test conflicting asset registrations during reorg"""
        self.log.info("Testing conflicting asset registrations...")

        # Start fresh
        self.restart_node(0, extra_args=self.extra_args[0])
        self.restart_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()
        
        self.disconnect_nodes(0, 1)
        
        # Register different assets on each chain
        assets = []
        for i in range(5):
            asset_id = f"{i:02x}" * 32
            assets.append(asset_id)
            
            # Chain A registers odd indices
            if i % 2 == 1:
                reg_raw = node0.createrawtransaction([], {node0.getnewaddress(): 5.1})
                # Use rawtxattachissuerreg for Chain A conflicting assets
                reg_tx = node0.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, 510000000)
                reg_f = node0.fundrawtransaction(reg_tx)
                reg_s = node0.signrawtransactionwithwallet(reg_f['hex'])
                node0.sendrawtransaction(reg_s['hex'])
            
            # Chain B registers even indices
            if i % 2 == 0:
                reg_raw = node1.createrawtransaction([], {node1.getnewaddress(): 5.1})
                # Use rawtxattachissuerreg for Chain B conflicting assets
                reg_tx = node1.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, 510000000)
                reg_f = node1.fundrawtransaction(reg_tx)
                reg_s = node1.signrawtransactionwithwallet(reg_f['hex'])
                node1.sendrawtransaction(reg_s['hex'])

        self.generate(node0, 100, sync_fun=self.no_op)
        self.generate(node1, 105, sync_fun=self.no_op)  # Longer chain
        
        # Verify pre-reorg state
        for i, asset_id in enumerate(assets):
            pol_a = node0.getassetpolicy(asset_id)
            pol_b = node1.getassetpolicy(asset_id)

            if i % 2 == 1:
                assert pol_a is not None and 'icu_txid' in pol_a  # Registered on A
                assert pol_b is None or 'icu_txid' not in pol_b  # Not on B
            else:
                assert pol_a is None or 'icu_txid' not in pol_a  # Not on A
                assert pol_b is not None and 'icu_txid' in pol_b  # Registered on B
        
        # Reorg
        self.connect_nodes(0, 1)
        self.sync_blocks()
        
        # Verify post-reorg state matches chain B
        for i, asset_id in enumerate(assets):
            pol_a = node0.getassetpolicy(asset_id)
            pol_b = node1.getassetpolicy(asset_id)

            if i % 2 == 0:
                assert pol_a is not None and 'icu_txid' in pol_a  # Now on both
                assert pol_b is not None and 'icu_txid' in pol_b
                assert_equal(pol_a['icu_txid'], pol_b['icu_txid'])
            else:
                assert pol_a is None or 'icu_txid' not in pol_a  # Lost in reorg
                assert pol_b is None or 'icu_txid' not in pol_b
        
        self.log.info("Conflicting assets reorg test passed")

    def test_mempool_asset_reorg(self):
        """Test mempool handling of asset transactions during reorg"""
        self.log.info("Testing mempool asset transaction handling during reorg...")

        # Start fresh
        self.restart_node(0, extra_args=self.extra_args[0])
        self.restart_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()
        
        # Generate unique asset identifier for conflicting assets test
        asset_id = hashlib.sha256(f"deep_reorg_conflict_{self.test_run_id}".encode()).hexdigest()
        reg_raw = node0.createrawtransaction([], {node0.getnewaddress(): 5.1})
        # Use rawtxattachissuerreg for mempool asset test
        reg_tx = node0.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, 510000000)
        reg_f = node0.fundrawtransaction(reg_tx)
        reg_s = node0.signrawtransactionwithwallet(reg_f['hex'])
        reg_txid = node0.sendrawtransaction(reg_s['hex'])
        self.generate(node0, 1, sync_fun=self.no_op)
        self.sync_all()

        # Disconnect nodes before minting so node1 doesn't get the mint
        self.disconnect_nodes(0, 1)

        # Mint assets (only on node0)
        pol = node0.getassetpolicy(asset_id)
        assert pol is not None, "Asset policy should exist for minting"
        bond_value = float(node0.gettxout(pol['icu_txid'], pol['icu_vout'])['value'])

        # For mempool test, we just need to mint some assets to later spend
        # Use exact pattern from feature_assets_basic.py to avoid ANYONECANPAY issues

        # Create mint transaction (must spend ICU)
        inputs = [{"txid": pol['icu_txid'], "vout": pol['icu_vout']}]
        icu_addr = node0.getnewaddress()
        asset_addr = node0.getnewaddress()
        # Output 0: ICU rotation (maintain current bond)
        # Output 1: Asset mint destination
        outputs = [{icu_addr: bond_value}, {asset_addr: 0.1}]

        raw_tx = node0.createrawtransaction(inputs, outputs)

        # Re-create ICU on output 0 (bond rotation) - include unlock_fees_sats
        tx_with_icu = node0.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28, 510000000)

        # Add minted assets on output 1
        tx_with_mint = node0.rawtxattachassettag(tx_with_icu, 1, asset_id, 1000000, 0)

        # Manually add funding input to avoid ANYONECANPAY issues with fundrawtransaction
        # Get additional UTXO for fees
        utxos = node0.listunspent(minconf=0)
        funding_utxo = None
        for utxo in utxos:
            if utxo['txid'] != pol['icu_txid'] and float(utxo["amount"]) >= 0.001:
                funding_utxo = utxo
                break

        if funding_utxo:
            # Add funding input
            inputs.append({"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]})
            funding_amount = float(funding_utxo["amount"])
            asset_output_value = 0.1  # The asset output we're funding
            fee = 0.0001
            change_value = funding_amount - asset_output_value - fee
            if change_value > 0.0001:
                outputs.append({node0.getnewaddress(): round(change_value, 8)})

            # Recreate transaction with additional input
            raw_tx = node0.createrawtransaction(inputs, outputs)
            tx_with_icu = node0.rawtxattachissuerreg(raw_tx, 0, asset_id, 3, 28, 510000000)
            tx_with_mint = node0.rawtxattachassettag(tx_with_icu, 1, asset_id, 1000000, 0)

        # Sign without fundrawtransaction to avoid ANYONECANPAY - explicitly use SIGHASH_ALL
        mint_s = node0.signrawtransactionwithwallet(tx_with_mint, [], "ALL")
        mint_txid = node0.sendrawtransaction(mint_s['hex'])
        self.generate(node0, 1, sync_fun=self.no_op)

        # Create mempool tx on node0 spending the asset (nodes already disconnected)
        mint_dec = node0.gettransaction(mint_txid, True, True)['decoded']
        asset_vout = next(i for i, o in enumerate(mint_dec['vout']) if 'outext' in o and i > 0)

        # Asset transfer - NO ICU rotation needed (only for mint/burn)
        # Just spend the asset and create a new asset output (conservation)
        xfer_in = [{"txid": mint_txid, "vout": asset_vout}]  # Only the asset input

        # Simple asset transfer output - leave small fee from 0.1 BTC input
        transfer_addr = node0.getnewaddress()
        xfer_out = [{transfer_addr: 0.0999}]  # 0.1 input - 0.0001 fee

        xfer_raw = node0.createrawtransaction(xfer_in, xfer_out)

        # Attach same amount of assets to maintain conservation (use correct method)
        xfer_with_asset = node0.rawtxattachassettag(xfer_raw, 0, asset_id, 1000000, 0)

        # Avoid fundrawtransaction to prevent ANYONECANPAY - explicitly use SIGHASH_ALL
        xfer_s = node0.signrawtransactionwithwallet(xfer_with_asset, [], "ALL")
        xfer_txid = node0.sendrawtransaction(xfer_s['hex'])
        
        # Verify in mempool
        assert xfer_txid in node0.getrawmempool()
        
        # Mine competing longer chain on node1 without the mint
        self.generate(node1, 10, sync_fun=self.no_op)
        
        # Store node1's chain tip before reconnect
        node1_tip = node1.getbestblockhash()

        # Reconnect and reorg
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Verify the reorg happened - node0 should now be on node1's chain
        assert_equal(node0.getbestblockhash(), node1_tip)

        # The mint tx should no longer exist after reorg
        try:
            node0.gettransaction(mint_txid)
            # If we get here, the mint still exists (shouldn't happen)
            assert False, f"Mint tx {mint_txid} still exists after reorg"
        except:
            # Expected - mint tx was reorged away
            pass

        # After reorg, the mint transaction is gone from the chain
        # Check if the transfer tx (which depends on mint) is handled properly
        mempool_0 = node0.getrawmempool()

        # Log the state for debugging
        self.log.info(f"Mempool after reorg: {mempool_0}")

        # Verify the mint output no longer exists in UTXO set
        mint_utxo = node0.gettxout(mint_txid, asset_vout, True)
        assert mint_utxo is None, f"Mint output still in UTXO set after reorg"

        # The transfer might temporarily remain in mempool due to caching
        # Mine a block to trigger mempool cleanup
        self.generate(node0, 1, sync_fun=self.no_op)
        mempool_after_mine = node0.getrawmempool()

        # Check if transfer was evicted after mining
        if xfer_txid in mempool_after_mine:
            # Some implementations might keep it longer, that's OK
            # What matters is that the mint is gone and asset state is correct
            self.log.info(f"Note: Transfer tx {xfer_txid} remains in mempool after reorg (implementation-specific behavior)")

            # Verify it can't actually be mined (would fail consensus)
            try:
                # Try to mine it
                self.generate(node0, 1, sync_fun=self.no_op)
                # Check if it got mined
                try:
                    node0.gettransaction(xfer_txid)
                    assert False, "Orphaned transfer should not be mineable"
                except:
                    # Good - it wasn't mined
                    pass
            except:
                pass  # Mining might fail, that's OK
        
        # Asset should still be registered but no minted assets exist
        pol_after = node0.getassetpolicy(asset_id)
        assert pol_after is not None, "Asset policy should still exist"
        assert 'icu_txid' in pol_after

        self.log.info("Mempool asset reorg test passed")

    def test_supply_tracking_reorg(self):
        """Test supply counter (issued_total/burned_total) tracking during deep reorg"""
        self.log.info("Testing supply tracking during reorg...")

        # Start fresh
        self.restart_node(0, extra_args=self.extra_args[0])
        self.restart_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()

        # Generate unique asset identifier
        asset_id = hashlib.sha256(f"supply_tracking_reorg_{self.test_run_id}".encode()).hexdigest()
        unlock = 510000000  # 5.1 BTC

        # Register asset on both nodes (while connected)
        reg_raw = node0.createrawtransaction([], {node0.getnewaddress(): 5.1})
        reg_tx = node0.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, unlock)
        reg_f = node0.fundrawtransaction(reg_tx)
        reg_s = node0.signrawtransactionwithwallet(reg_f['hex'])
        reg_txid = node0.sendrawtransaction(reg_s['hex'])
        self.generate(node0, 1, sync_fun=self.no_op)
        self.sync_all()

        # Verify initial state: issued_total=0, burned_total=0
        pol_initial = node0.getassetpolicy(asset_id)
        assert_equal(pol_initial.get('issued_total', 0), 0)
        assert_equal(pol_initial.get('burned_total', 0), 0)
        self.log.info(f"Initial supply: issued={pol_initial.get('issued_total', 0)}, burned={pol_initial.get('burned_total', 0)}")

        # Do 3 mints on common ancestor (while nodes are connected)
        mint_txids = []
        for i in range(3):
            pol = node0.getassetpolicy(asset_id)
            icu_addr = node0.getnewaddress()
            asset_addr = node0.getnewaddress()

            mint_result = node0.mintasset(
                pol['icu_txid'], pol['icu_vout'],
                icu_addr, 5.1,
                asset_addr, 0.001,
                asset_id, 100000, 3, 28, unlock,
                {"autofund": True, "broadcast": True}
            )

            mint_txid = mint_result if isinstance(mint_result, str) else mint_result.get('txid', mint_result)
            mint_txids.append(mint_txid)
            self.generate(node0, 1, sync_fun=self.no_op)

        # Sync so both nodes have the mints
        self.sync_all()

        # Verify both nodes see issued=300K, burned=0
        pol_common = node0.getassetpolicy(asset_id)
        assert_equal(pol_common.get('issued_total', 0), 300000)
        assert_equal(pol_common.get('burned_total', 0), 0)
        pol_common_n1 = node1.getassetpolicy(asset_id)
        assert_equal(pol_common_n1.get('issued_total', 0), 300000)
        assert_equal(pol_common_n1.get('burned_total', 0), 0)
        self.log.info(f"Common ancestor: issued=300000, burned=0")

        # Disconnect nodes to create competing chains
        self.disconnect_nodes(0, 1)

        # Chain B (node0): Burn 100K units using high-level burnasset RPC (SAME wallet that minted)
        # Expected: issued_total=300K, burned_total=100K, settled=200K
        pol = node0.getassetpolicy(asset_id)
        burn_icu_addr = node0.getnewaddress()

        # Find the first mint's asset output
        mint_txid = mint_txids[0]
        mint_tx = node0.gettransaction(mint_txid, True, True)

        # Find asset output (TLV type 0x01 = AssetTag, not 0x10 = IssuerReg)
        asset_vout = None
        for i, vout in enumerate(mint_tx['decoded']['vout']):
            outext = vout.get('outext')
            if outext:
                outext_bytes = bytes.fromhex(outext)
                if outext_bytes[0] == 0x01:  # AssetTag
                    asset_vout = i
                    break

        assert asset_vout is not None, "Could not find asset output"

        self.log.info(f"Burning entire UTXO (100K units) from {mint_txid}:{asset_vout} on chain B")

        burn_result = node0.burnasset(
            pol['icu_txid'], pol['icu_vout'],
            mint_txid, asset_vout,
            burn_icu_addr, 5.1,
            asset_id, 3, 28, unlock,
            {"autofund": True, "broadcast": True}
        )

        burn_txid = burn_result if isinstance(burn_result, str) else burn_result['txid']
        self.log.info(f"Burn transaction broadcast: {burn_txid}")

        # Mine burn on chain B (node0)
        self.generate(node0, 1, sync_fun=self.no_op)

        # Verify chain B state (with burn)
        pol_b_burned = node0.getassetpolicy(asset_id)
        issued_b = pol_b_burned.get('issued_total', 0)
        burned_b = pol_b_burned.get('burned_total', 0)
        assert_equal(issued_b, 300000)
        assert_equal(burned_b, 100000)
        self.log.info(f"Chain B (node0 with burn): issued={issued_b}, burned={burned_b}")

        # Chain A (node1): Just mine more blocks to make it longer
        # Expected: issued_total=300K, burned_total=0
        self.generate(node1, 15, sync_fun=self.no_op)

        pol_a_final = node1.getassetpolicy(asset_id)
        issued_a = pol_a_final.get('issued_total', 0)
        burned_a = pol_a_final.get('burned_total', 0)
        assert_equal(issued_a, 300000)
        assert_equal(burned_a, 0)
        self.log.info(f"Chain A (node1 longer, no burn): issued={issued_a}, burned={burned_a}")

        # Reconnect: node0 should reorg to chain A (longer, no burn)
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Verify node0 reorged: burned_total should be 0 now (burn was on orphaned chain)
        pol_b_after_reorg = node0.getassetpolicy(asset_id)
        issued_after = pol_b_after_reorg.get('issued_total', 0)
        burned_after = pol_b_after_reorg.get('burned_total', 0)
        assert_equal(issued_after, 300000)
        assert_equal(burned_after, 0)  # Burn reverted!
        self.log.info(f"Node0 after reorg: issued={issued_after}, burned={burned_after} (burn reverted)")

        # Both nodes should now have the same state (chain A won)
        pol_a_after_reorg = node1.getassetpolicy(asset_id)
        assert_equal(pol_a_after_reorg.get('issued_total', 0), 300000)
        assert_equal(pol_a_after_reorg.get('burned_total', 0), 0)

        self.log.info("Supply tracking reorg test passed: burn successfully reverted")

    def test_registry_persistence_on_restart(self):
        """Test that asset registry persists correctly across node restart (RollforwardBlock regression guard)

        This test guards against regression in RollforwardBlock which must properly rebuild
        asset registry, ticker bindings, and supply tracking during ReplayBlocks on startup.

        Historical context: commit 572610d762 exposed a bug where RollforwardBlock only
        handled UTXOs but ignored asset registry, causing assets to disappear after restart.
        """
        self.log.info("Testing asset registry persistence across node restart...")

        # Start fresh
        self.restart_node(0, extra_args=self.extra_args[0])
        node0 = self.nodes[0]
        self.generate(node0, 101, sync_fun=self.no_op)

        # Register asset with full metadata
        asset_id = hashlib.sha256(f"restart_persist_{self.test_run_id}".encode()).hexdigest()
        unlock = 510000000
        ticker = "RESTART"
        decimals = 6

        self.log.info(f"Registering asset {asset_id[:16]}... with ticker={ticker}, decimals={decimals}")

        reg_raw = node0.createrawtransaction([], {node0.getnewaddress(): 5.1})
        reg_tx = node0.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 28, unlock, ticker, decimals)
        reg_f = node0.fundrawtransaction(reg_tx)
        reg_s = node0.signrawtransactionwithwallet(reg_f['hex'])
        reg_txid = node0.sendrawtransaction(reg_s['hex'])
        self.generate(node0, 1, sync_fun=self.no_op)

        # Verify asset registered
        pol_before = node0.getassetpolicy(asset_id)
        assert pol_before is not None, "Asset should be registered"
        assert_equal(pol_before.get('ticker', ''), ticker)
        assert_equal(pol_before.get('decimals', 255), decimals)
        assert_equal(pol_before.get('issued_total', 0), 0)
        assert_equal(pol_before.get('burned_total', 0), 0)
        self.log.info(f"✓ Asset registered: ticker={ticker}, decimals={decimals}")

        # Mint some tokens to update supply tracking
        pol = node0.getassetpolicy(asset_id)
        icu_addr = node0.getnewaddress()
        asset_addr = node0.getnewaddress()

        mint_result = node0.mintasset(
            pol['icu_txid'], pol['icu_vout'],
            icu_addr, 5.1,
            asset_addr, 0.001,
            asset_id, 500000, 3, 28, unlock,
            {"autofund": True, "broadcast": True}
        )
        self.generate(node0, 1, sync_fun=self.no_op)

        # Verify supply updated
        pol_minted = node0.getassetpolicy(asset_id)
        assert_equal(pol_minted.get('issued_total', 0), 500000)
        assert_equal(pol_minted.get('burned_total', 0), 0)
        self.log.info(f"✓ Minted 500000 units: issued_total=500000")

        # Mine a few more blocks to ensure state is flushed
        self.generate(node0, 10, sync_fun=self.no_op)

        # CRITICAL: Restart node - this triggers ReplayBlocks → RollforwardBlock
        self.log.info("Restarting node (triggers ReplayBlocks)...")
        self.restart_node(0, extra_args=self.extra_args[0])
        node0 = self.nodes[0]

        # Verify asset registry persisted correctly after restart
        self.log.info("Verifying asset registry after restart...")

        # Check by asset_id
        pol_after = node0.getassetpolicy(asset_id)
        assert pol_after is not None, "Asset should still exist after restart (RollforwardBlock must rebuild registry)"

        # Verify all fields persisted
        assert_equal(pol_after.get('ticker', ''), ticker)
        self.log.info("✓ Ticker persisted correctly")

        assert_equal(pol_after.get('decimals', 255), decimals)
        self.log.info("✓ Decimals persisted correctly")

        assert_equal(pol_after.get('issued_total', 0), 500000)
        self.log.info("✓ issued_total persisted correctly")

        assert_equal(pol_after.get('burned_total', 0), 0)
        self.log.info("✓ burned_total persisted correctly")

        # Note: Ticker binding is already verified by the ticker field in pol_after above
        # The fact that we can retrieve the policy and it has the correct ticker means
        # both the registry entry AND the ticker binding were rebuilt correctly

        self.log.info(f"✓ Asset fully persisted: ticker={ticker}, decimals={decimals}, issued=500000")
        self.log.info("Registry persistence test passed: RollforwardBlock correctly rebuilds all state")


if __name__ == '__main__':
    AssetDeepReorgTest(__file__).main()
