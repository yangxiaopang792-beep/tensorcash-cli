#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Phase 6: ICU-as-bond and fee accumulator functional tests.

Covers:
- Register with unlock_fees_sats
- Fees accumulation per touched asset (observed via getassetpolicy)
- Duplicate registration rejected (policy)
- Bond rotation required before unlock
- Unlock allows ICU withdrawal (registry erased)
"""

import hashlib
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def make_issuer_reg_tlv(asset_id_hex: str, policy_bits: int = 3, allowed_families: int = 0x1C, unlock: int = 510000000) -> str:
    """Create v1 IssuerReg TLV (format_version=1, always includes ZK+ICU sections)."""
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


def make_asset_tag_tlv(asset_id_hex: str, amount: int, flags: int = 0) -> str:
    aid = bytes.fromhex(asset_id_hex)
    val = bytearray()
    val.extend(aid)
    val.extend((amount & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    if flags:
        val.extend((flags & 0xFFFFFFFF).to_bytes(4, 'little'))
    tlv = bytearray()
    tlv.append(0x01)
    tlv.append(len(val))
    tlv.extend(val)
    return tlv.hex()


class AssetBondLockUnlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Generate unique test run ID to avoid asset ID conflicts
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_bond_lock".encode()).hexdigest()[:16]
        # Enable assets at genesis with isolation flags
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",  # Don't persist mempool between restarts
            "-dbcache=1000",  # Use 1GB cache to keep everything in memory
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def no_op(self):
        """No-op sync function for single node operations."""
        pass

    def run_test(self):
        n = self.nodes[0]
        self.generate(n, 101, sync_fun=self.no_op)

        # Use a higher fee so fewer txs are needed to reach unlock
        # settxfee is deprecated, using fee_rate in fundrawtransaction instead

        # Generate unique asset identifier for this test run
        asset_id = hashlib.sha256(f"bond_lock_asset_{self.test_run_id}".encode()).hexdigest()
        unlock = 510000000  # Unlock must be >= bond value (5.1 BTC = 510M sats) - consensus minimum

        # Register with unlock_fees_sats
        # Get a UTXO for the registration bond
        utxos = n.listunspent()
        if not utxos:
            self.generate(n, 1, sync_fun=self.no_op)
            utxos = n.listunspent()
        reg_input = utxos[0]
        reg_inputs = [{"txid": reg_input["txid"], "vout": reg_input["vout"]}]
        # Set bond at 5.1 BTC (consensus minimum) and calculate change
        reg_output_value = 5.1
        change_value = float(reg_input["amount"]) - reg_output_value - 0.001  # Leave room for fee
        reg_outputs = [{n.getnewaddress(): reg_output_value}]
        if change_value > 0.0001:
            reg_outputs.append({n.getnewaddress(): change_value})
        reg_raw = n.createrawtransaction(reg_inputs, reg_outputs)
        # Use the proper RPC method for attaching issuer registration with unlock_fees_sats
        reg_tx = n.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 0x1C, unlock)
        # Don't use fundrawtransaction with asset transactions - it can corrupt the outputs
        reg_s = n.signrawtransactionwithwallet(reg_tx)
        reg_txid = n.sendrawtransaction(reg_s['hex'])
        self.generate(n, 1, sync_fun=self.no_op)

        pol = n.getassetpolicy(asset_id)
        if pol is None:
            raise AssertionError(f"Asset policy not found for {asset_id} after registration")
        assert_equal(pol['asset_id'], asset_id)
        assert_equal(pol['unlock_fees_sats'], unlock)
        assert_equal(pol['fees_accum_sats'], 0)
        icu_txid = pol['icu_txid']
        icu_vout = pol['icu_vout']

        # Mint: spend ICU, attach asset output
        # Add extra inputs first for fees, then attach TLVs to avoid fundrawtransaction issues
        mint_inputs = [{"txid": icu_txid, "vout": icu_vout}]
        # The ICU value is 5.1 BTC as set during registration
        # ICU UTXOs with IssuerReg TLVs don't appear in listunspent()
        icu_value = 5.1

        # Get additional UTXOs for fees
        utxos = n.listunspent()
        fee_utxo = None
        for u in utxos:
            # Find a UTXO for fees (not the ICU)
            if not fee_utxo:
                fee_utxo = u
                break

        # Ensure we have a fee UTXO
        if not fee_utxo:
            self.generate(n, 1, sync_fun=self.no_op)
            utxos = n.listunspent()
            for u in utxos:
                fee_utxo = u
                break

        if not fee_utxo:
            raise AssertionError("Could not find fee UTXO")

        mint_inputs.append({"txid": fee_utxo['txid'], "vout": fee_utxo['vout']})
        total_input = icu_value + float(fee_utxo['amount'])

        # Keep the ICU bond value the same (or it would fail bond-decrease check)
        mint_outputs = [{n.getnewaddress(): icu_value}, {n.getnewaddress(): 0.05}]  # ICU rotation + asset
        total_output = icu_value + 0.05
        fee_amount = 0.001  # Smaller transaction fee

        if total_input > total_output + fee_amount:
            # Add change output for remaining value
            change = total_input - total_output - fee_amount
            if change > 0.0001:
                mint_outputs.append({n.getnewaddress(): round(change, 8)})

        mint_raw = n.createrawtransaction(mint_inputs, mint_outputs)
        # Attach TLVs after all outputs are in place
        mint_raw = n.rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 0x1C, unlock)  # ICU rotation
        mint_raw = n.rawtxattachassettag(mint_raw, 1, asset_id, 100)  # Much smaller asset amount
        # Don't use fundrawtransaction after attaching TLVs
        mint_s = n.signrawtransactionwithwallet(mint_raw)
        mint_txid = n.sendrawtransaction(mint_s['hex'])
        self.generate(n, 1, sync_fun=self.no_op)

        # Verify the mint transaction updated the ICU location
        pol_after_mint = n.getassetpolicy(asset_id)
        self.log.info(f"Policy after mint: {pol_after_mint}")
        assert_equal(pol_after_mint['icu_txid'], mint_txid)
        assert_equal(pol_after_mint['icu_vout'], 0)  # ICU should be at output 0

        # Identify asset output index in mint tx and verify TLVs
        # Output 0 has IssuerReg (ICU), Output 1 has Asset tag
        mint_tx = n.gettransaction(mint_txid, True, True)
        mint_dec = mint_tx['decoded']

        # Verify output 0 has IssuerReg TLV (ICU)
        assert 'outext' in mint_dec['vout'][0], "Output 0 should have TLV extension (IssuerReg)"
        # Verify output 1 has Asset tag TLV
        assert 'outext' in mint_dec['vout'][1], "Output 1 should have TLV extension (Asset tag)"

        # Debug: Log the actual outext values
        self.log.info(f"Mint tx output 0 outext: {mint_dec['vout'][0].get('outext', 'NONE')}")
        self.log.info(f"Mint tx output 1 outext: {mint_dec['vout'][1].get('outext', 'NONE')}")

        asset_vout = 1  # Asset tag was attached to output 1

        # Before unlock: attempt to spend ICU without rotation should fail (policy)
        pol = n.getassetpolicy(asset_id)
        icu_txid = pol['icu_txid']
        icu_vout = pol['icu_vout']

        # Verify this matches what we expect from the mint
        assert_equal(icu_txid, mint_txid)
        assert_equal(icu_vout, 0)

        # Get actual ICU value from the transaction (like feature_assets_basic)
        icu_tx = n.gettransaction(icu_txid, True, True)['decoded']
        icu_utxo_value = float(icu_tx['vout'][icu_vout]['value'])

        # Create transaction WITHOUT ICU rotation (following feature_assets_basic pattern)
        bad_inputs = [{"txid": icu_txid, "vout": icu_vout}]
        bad_outputs = [{n.getnewaddress(): icu_utxo_value}]  # Same value as ICU, no rotation
        bad_raw = n.createrawtransaction(bad_inputs, bad_outputs)
        # Use fundrawtransaction to handle fees automatically (like feature_assets_basic)
        bad_funded = n.fundrawtransaction(bad_raw)
        bad_s = n.signrawtransactionwithwallet(bad_funded['hex'])

        # Debug: Check what we're actually sending
        bad_decoded = n.decoderawtransaction(bad_s['hex'])
        self.log.info(f"Bad tx spending ICU {icu_txid}:{icu_vout}")
        self.log.info(f"Bad tx inputs: {bad_decoded['vin']}")
        self.log.info(f"Bad tx outputs: {bad_decoded['vout']}")

        # This should fail with asset-bond-rotation error
        assert_raises_rpc_error(-26, "asset-bond-rotation", n.sendrawtransaction, bad_s['hex'])

        # Generate many coinbase blocks to create spendable UTXOs for high-fee transactions
        self.log.info("Generating coinbase blocks for fee accumulation...")
        self.generate(n, 200, sync_fun=self.no_op)  # Generate 200 blocks with 50 BTC each

        # Check initial unlock state - should be locked
        pol_before = n.getassetpolicy(asset_id)
        self.log.info(f"Policy before fee accumulation: fees_accum_sats={pol_before['fees_accum_sats']}, is_unlocked={pol_before['is_unlocked']}")
        assert not pol_before['is_unlocked'], "Asset should be locked initially"

        # Accumulate fees: create 10 high-fee transactions to test both paths
        self.log.info("Accumulating fees through high-fee transactions...")
        target_fees = unlock  # Need 510M sats
        fee_per_tx = (target_fees - 100000) // 10  # Distribute remaining fees across 10 txs

        for i in range(10):
            # Get current policy state
            pol = n.getassetpolicy(asset_id)
            accumulated_fees = pol['fees_accum_sats']
            remaining_fees = target_fees - accumulated_fees

            self.log.info(f"Transaction {i+1}/10: Accumulated: {accumulated_fees} sats, Need: {remaining_fees} more sats, Unlocked: {pol['is_unlocked']}")

            if remaining_fees <= 0:
                self.log.info(f"Target reached after {i} transactions")
                break

            # Create high-fee transaction with asset transfer to accumulate fees
            xfer_in = [{"txid": mint_txid, "vout": asset_vout}]

            # Get the actual asset UTXO value from the transaction (won't appear in listunspent due to TLV)
            asset_tx = n.gettransaction(mint_txid, True, True)['decoded']
            asset_utxo_value = float(asset_tx['vout'][asset_vout]['value'])

            # Get additional UTXOs for fees
            utxos = n.listunspent()
            fee_utxos = []

            for u in utxos:
                if u['txid'] != mint_txid and float(u['amount']) > 10:  # Get big UTXOs for fees
                    fee_utxos.append(u)
                    if len(fee_utxos) >= 5:  # Use multiple UTXOs for maximum fee
                        break

            # Add fee UTXOs to inputs
            total_input = asset_utxo_value
            for fee_utxo in fee_utxos[:3]:  # Use up to 3 fee UTXOs
                xfer_in.append({"txid": fee_utxo['txid'], "vout": fee_utxo['vout']})
                total_input += float(fee_utxo['amount'])

            # Calculate fee for this transaction - aim for ~51M sats per tx
            target_fee_btc = min(remaining_fees / 1e8, total_input * 0.8, 0.6)  # Up to 0.6 BTC fee
            if target_fee_btc < 0.1:
                target_fee_btc = min(1.0, total_input * 0.3)  # At least 0.1 BTC fee

            # Asset conservation: preserve the asset amount (100 units), not BTC value
            asset_output_btc = 0.01  # Minimal BTC for asset UTXO
            change_btc = total_input - target_fee_btc - asset_output_btc

            # Ensure change is positive and valid
            if change_btc <= 0:
                target_fee_btc = total_input - asset_output_btc - 0.01
                change_btc = 0.01

            # Ensure all amounts are positive floats
            assert asset_output_btc > 0, f"Asset output must be positive: {asset_output_btc}"
            assert change_btc > 0, f"Change must be positive: {change_btc}"
            assert isinstance(asset_output_btc, (int, float)), f"Asset output must be numeric: {type(asset_output_btc)}"
            assert isinstance(change_btc, (int, float)), f"Change must be numeric: {type(change_btc)}"

            xfer_outputs = [
                {n.getnewaddress(): round(asset_output_btc, 8)},  # Asset destination (100 units)
                {n.getnewaddress(): round(change_btc, 8)}         # Change
            ]

            self.log.info(f"Creating tx {i+1} with {target_fee_btc:.3f} BTC fee from {total_input:.3f} BTC input (asset=100 units)")
            self.log.info(f"Outputs: asset={asset_output_btc:.8f} BTC, change={change_btc:.8f} BTC")
            self.log.info(f"Inputs: {len(xfer_in)} UTXOs - asset UTXO: {mint_txid}:{asset_vout} = {asset_utxo_value} BTC")

            xfer_raw = n.createrawtransaction(xfer_in, xfer_outputs)
            # Attach asset tag to first output (conservation: same amount)
            xfer_raw = n.rawtxattachassettag(xfer_raw, 0, asset_id, 100)
            # Don't use fundrawtransaction after attaching TLVs
            xfer_s = n.signrawtransactionwithwallet(xfer_raw)
            xfer_txid = n.sendrawtransaction(xfer_s['hex'], 0, 100)  # maxfeerate=100 BTC/kb
            self.generate(n, 1, sync_fun=self.no_op)
            mint_txid = xfer_txid
            asset_vout = 0  # Asset is now at output 0

            # If we're not making progress, generate more UTXOs
            if len(fee_utxos) < 3:
                self.log.info("Generating more coinbase UTXOs...")
                self.generate(n, 50, sync_fun=self.no_op)

        # Check final unlock state - should be unlocked
        pol_after = n.getassetpolicy(asset_id)
        self.log.info(f"Policy after fee accumulation: fees_accum_sats={pol_after['fees_accum_sats']}, is_unlocked={pol_after['is_unlocked']}")
        assert pol_after['is_unlocked'], f"Asset should be unlocked: {pol_after['fees_accum_sats']} >= {target_fees}"

        # Now unlock reached: spend ICU with dust rotation should succeed and erase registry
        pol = n.getassetpolicy(asset_id)
        icu_txid = pol['icu_txid']
        icu_vout = pol['icu_vout']
        rotation_min = pol['rotation_min_sats']

        # Get actual ICU value from the transaction (like feature_assets_basic)
        icu_tx = n.gettransaction(icu_txid, True, True)['decoded']
        icu_utxo_value = float(icu_tx['vout'][icu_vout]['value'])

        # Create transaction WITH dust rotation (minimum allowed) - should succeed after unlock
        dust_rotation_btc = round(max(rotation_min / 1e8, 0.00001), 8)  # At least 1000 sats
        withdraw_btc = round(icu_utxo_value - dust_rotation_btc - 0.001, 8)  # Leave room for fees

        # Ensure positive amounts
        if withdraw_btc <= 0:
            dust_rotation_btc = 0.00001
            withdraw_btc = round(icu_utxo_value - dust_rotation_btc - 0.001, 8)

        self.log.info(f"Testing unlocked ICU spend: ICU={icu_utxo_value} BTC, rotation_min={rotation_min} sats, dust_rotation={dust_rotation_btc} BTC")
        self.log.info(f"Outputs: withdraw={withdraw_btc} BTC, rotation={dust_rotation_btc} BTC")

        # Validate amounts before creating transaction
        assert withdraw_btc > 0, f"Withdraw amount must be positive: {withdraw_btc}"
        assert dust_rotation_btc > 0, f"Rotation amount must be positive: {dust_rotation_btc}"
        assert abs((withdraw_btc + dust_rotation_btc) - icu_utxo_value) < 0.01, f"Output sum mismatch: {withdraw_btc + dust_rotation_btc} vs {icu_utxo_value}"

        free_inputs = [{"txid": icu_txid, "vout": icu_vout}]
        free_outputs = [
            {n.getnewaddress(): withdraw_btc},          # Withdraw most of ICU value
            {n.getnewaddress(): dust_rotation_btc}      # Dust rotation (minimum required)
        ]
        free_raw = n.createrawtransaction(free_inputs, free_outputs)
        # Attach IssuerReg TLV to the dust rotation output (index 1) to create new ICU
        free_raw = n.rawtxattachissuerreg(free_raw, 1, asset_id, 3, 0x1C, unlock)
        # Don't use fundrawtransaction with asset transactions - it can corrupt the outputs
        free_s = n.signrawtransactionwithwallet(free_raw)
        free_txid = n.sendrawtransaction(free_s['hex'])
        self.generate(n, 1, sync_fun=self.no_op)

        # After dust rotation, registry should be UPDATED (not erased) - ICU continues at new location
        pol2 = n.getassetpolicy(asset_id)
        assert_equal(pol2['asset_id'], asset_id)
        assert 'icu_txid' in pol2, "Registry should still exist after dust rotation"
        assert pol2['icu_txid'] == free_txid, f"ICU should be updated to new location: {pol2['icu_txid']} vs {free_txid}"
        assert pol2['icu_vout'] == 1, f"ICU should be at output 1: {pol2['icu_vout']}"
        self.log.info(f"✅ Dust rotation successful - ICU moved to {free_txid}:1")

        # Test complete ICU spend (no rotation) - should now FAIL at consensus level
        self.log.info("Testing complete ICU spend (no rotation) - should be rejected")
        complete_icu_tx = n.gettransaction(free_txid, True, True)['decoded']
        complete_icu_value = float(complete_icu_tx['vout'][1]['value'])  # Rotation output is at vout 1

        complete_inputs = [{"txid": free_txid, "vout": 1}]  # Spend the rotation UTXO
        complete_outputs = [{n.getnewaddress(): complete_icu_value}]  # No rotation - spend entire ICU
        complete_raw = n.createrawtransaction(complete_inputs, complete_outputs)
        complete_funded = n.fundrawtransaction(complete_raw)
        complete_signed = n.signrawtransactionwithwallet(complete_funded['hex'])

        # This should fail with asset-bond-rotation error (ICU spend always requires new ICU)
        assert_raises_rpc_error(-26, "asset-bond-rotation", n.sendrawtransaction, complete_signed['hex'])
        self.log.info("✅ Complete ICU spend correctly rejected")

        # Test dust rotation to burn address (legitimate asset retirement method)
        self.log.info("Testing dust rotation to burn address for asset retirement")
        burn_address = n.getnewaddress()  # Generate a valid regtest address as burn address
        dust_amount = 0.00001  # 1000 sats > 546 dust threshold

        retire_inputs = [{"txid": free_txid, "vout": 1}]  # Spend the rotation UTXO
        retire_outputs = [
            {n.getnewaddress(): complete_icu_value - dust_amount - 0.001},  # Return most to issuer
            {burn_address: dust_amount}  # Dust rotation to burn address
        ]
        retire_raw = n.createrawtransaction(retire_inputs, retire_outputs)
        # Attach IssuerReg to burn address output (asset retirement)
        retire_raw = n.rawtxattachissuerreg(retire_raw, 1, asset_id, 3, 0x1C, unlock)
        retire_signed = n.signrawtransactionwithwallet(retire_raw)
        retire_txid = n.sendrawtransaction(retire_signed['hex'])
        self.generate(n, 1, sync_fun=self.no_op)

        # Registry should still exist but ICU is now at burn address (asset retired)
        pol3 = n.getassetpolicy(asset_id)
        assert_equal(pol3['asset_id'], asset_id)
        assert 'icu_txid' in pol3, "Registry should still exist after dust rotation"
        assert pol3['icu_txid'] == retire_txid, "ICU should be at burn address"
        self.log.info("✅ Asset retirement via dust rotation to burn address successful")

        # SECURITY IMPROVEMENT: Mandatory ICU rotation prevents:
        # 1. Zombie UTXOs: Asset holders can still transfer/burn tokens
        # 2. Asset ID hijacking: Registry remains alive, preventing re-registration
        # 3. UTXO pollution: Assets can be properly burned even after retirement
        # Asset retirement via burn address rotation is the safe alternative

        # Test new asset registration (different asset_id since original registry persists after dust rotation)
        # With mandatory ICU rotation, the original registry remains active at burn address
        new_asset_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        utxos = n.listunspent()
        if not utxos:
            self.generate(n, 1, sync_fun=self.no_op)
            utxos = n.listunspent()
        reg2_input = utxos[0]
        reg2_inputs = [{"txid": reg2_input["txid"], "vout": reg2_input["vout"]}]
        reg2_output_value = 5.1
        reg2_outputs = [{n.getnewaddress(): reg2_output_value}]
        reg2_raw = n.createrawtransaction(reg2_inputs, reg2_outputs)
        # Use the proper RPC method for registering new asset
        reg2_tx = n.rawtxattachissuerreg(reg2_raw, 0, new_asset_id, 3, 0x1C, unlock)
        # Use fundrawtransaction to handle fees (like feature_assets_basic)
        reg2_funded = n.fundrawtransaction(reg2_tx)
        reg2_s = n.signrawtransactionwithwallet(reg2_funded['hex'])
        reg2_txid = n.sendrawtransaction(reg2_s['hex'])
        self.generate(n, 1, sync_fun=self.no_op)

        pol3 = n.getassetpolicy(new_asset_id)
        assert_equal(pol3['icu_txid'], reg2_txid)

        # Now try a duplicate registration in mempool (without spending ICU) -> policy reject
        utxos = n.listunspent()
        dup_input = None
        for u in utxos:
            if u['txid'] != reg2_txid or u['vout'] != 0:  # Not the current ICU
                dup_input = u
                break
        if not dup_input:
            self.generate(n, 1, sync_fun=self.no_op)
            utxos = n.listunspent()
            for u in utxos:
                if u['txid'] != reg2_txid or u['vout'] != 0:
                    dup_input = u
                    break
        dup_inputs = [{"txid": dup_input["txid"], "vout": dup_input["vout"]}]
        dup_output_value = 5.1
        dup_outputs = [{n.getnewaddress(): dup_output_value}]
        dup_raw = n.createrawtransaction(dup_inputs, dup_outputs)
        # Try to register the same asset_id again (should fail)
        dup_tx = n.rawtxattachissuerreg(dup_raw, 0, asset_id, 3, 0x1C, unlock)
        # Use fundrawtransaction to handle fees (like feature_assets_basic)
        dup_funded = n.fundrawtransaction(dup_tx)
        dup_s = n.signrawtransactionwithwallet(dup_funded['hex'])
        assert_raises_rpc_error(-26, "asset-duplicate-registration", n.sendrawtransaction, dup_s['hex'])

        self.log.info("Phase 6 bond/fees tests passed")


if __name__ == '__main__':
    AssetBondLockUnlockTest(__file__).main()
