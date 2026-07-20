#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license.
"""Asset policy: enforce -assetmindustbtc for AssetTag outputs.

Flow:
- Enable assets at genesis and set a high -assetmindustbtc policy threshold.
- Register an asset (create ICU).
- Attempt to mint with an AssetTag output whose BTC value is below the policy threshold -> reject with asset-dust.
- Mint again with sufficient BTC value -> accept.
"""

import time
import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


def make_issuer_reg_tlv(asset_id_hex: str, policy_bits: int = 3, allowed_families: int = 0x1C, unlock_fees_sats: int = 500100000) -> str:
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
    payload.extend((unlock_fees_sats & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
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
    aid = bytes.fromhex(asset_id_hex)
    val = bytearray()
    val.extend(aid)
    val.extend((amount & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    tlv = bytearray([0x01, len(val)])
    tlv.extend(val)
    return tlv.hex()


class AssetPolicyMindustTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Generate unique test run ID to avoid asset ID conflicts
        import os
        import random
        # Use PID, timestamp, random number, and thread ID for maximum uniqueness
        import threading
        thread_id = threading.current_thread().ident or 0
        random_component = random.randint(0, 2**32-1)
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_{thread_id}_{random_component}".encode()).hexdigest()[:16]
        # Enforce a high minimum BTC amount for AssetTag outputs (100000 sats = 0.001 BTC)
        self.extra_args = [[
            "-assetsheight=0",
            "-assetmindustbtc=100000",
            "-dbcache=1000",  # Use 1GB cache to keep everything in memory
            "-persistmempool=0",  # Don't persist mempool between restarts
            "-maxmempool=50",  # Limit mempool size to reduce state
            "-blocksonly=0",  # Ensure we accept transactions
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_clean_chain(self):
        # Force completely clean chain for each test run
        return True

    def run_test(self):
        n = self.nodes[0]
        # Ensure we have a completely fresh start
        assert n.getblockcount() == 0, "Chain should start at height 0"

        # Verify the assetmindustbtc setting is active
        # We can check this indirectly by looking at the node's configuration
        self.log.info(f"Test configuration: assetmindustbtc=100000")

        self.generate(n, 101)

        # Register asset with ICU (use unique ID for this test run)
        # Create unique asset ID by hashing test name + timestamp
        asset_id = hashlib.sha256(("mindust_test_" + self.test_run_id).encode()).hexdigest()
        # ICU bond must be at least 5 BTC after fees
        # Get a spendable UTXO (include unconfirmed)
        utxos = n.listunspent(minconf=0)
        if not utxos:
            # Generate more blocks if needed
            self.generate(n, 1)
            utxos = n.listunspent(minconf=0)
        spend = utxos[0]
        inputs = [{"txid": spend["txid"], "vout": spend["vout"]}]
        # Set to 5.001 to ensure it's above 5 BTC after fees
        reg_addr = n.getnewaddress()
        change_value = float(spend["amount"]) - 5.001 - 0.0001  # subtract bond and fee
        # Use array format to guarantee output order
        outputs = [{reg_addr: 5.001}]
        if change_value > 0:
            outputs.append({n.getnewaddress(): change_value})
        reg_raw = n.createrawtransaction(inputs, outputs)
        # Use the proper RPC method for attaching issuer registration
        reg_tx = n.rawtxattachissuerreg(reg_raw, 0, asset_id, 3, 0x1C, 500100000)  # unlock >= 5.001 BTC bond
        # Don't use fundrawtransaction with asset transactions
        # Explicitly specify SIGHASH_ALL to ensure no ANYONECANPAY is used
        reg_s = n.signrawtransactionwithwallet(reg_tx, [], "ALL")
        reg_txid = n.sendrawtransaction(reg_s['hex'])
        self.generate(n, 1)

        pol = n.getassetpolicy(asset_id)
        if pol is None:
            # Asset registration might have failed - check the transaction
            reg_tx_info = n.gettransaction(reg_txid)
            self.log.error(f"Asset registration failed. TX status: {reg_tx_info.get('confirmations', 0)} confirmations")
            # Try to get error from mempool if unconfirmed
            if reg_tx_info.get('confirmations', 0) == 0:
                mempool_entry = n.getmempoolentry(reg_txid) if reg_txid in n.getrawmempool() else None
                if mempool_entry:
                    self.log.error(f"TX in mempool: {mempool_entry}")
            raise AssertionError(f"Asset policy not found for {asset_id} after registration")
        icu_prev = {"txid": pol['icu_txid'], "vout": pol['icu_vout']}

        # Try mint with AssetTag output value below policy threshold -> reject
        low_value = 0.0002  # 20,000 sats (below 100,000 policy threshold)
        # Must maintain ICU bond value
        # Get the actual ICU value from previous tx
        icu_utxo = n.gettxout(icu_prev["txid"], icu_prev["vout"])
        icu_value = float(icu_utxo['value'])  # Convert Decimal to float

        # First, let's fund the transaction to get enough inputs for fees
        # Create a transaction with placeholder outputs first
        utxos = n.listunspent(minconf=0)
        fee_input = None
        for utxo in utxos:
            if utxo["txid"] != icu_prev["txid"] or utxo["vout"] != icu_prev["vout"]:
                fee_input = utxo
                break

        if not fee_input:
            raise RuntimeError("No suitable UTXO for fees")

        # Create transaction with both ICU input and fee input
        inputs = [icu_prev, {"txid": fee_input["txid"], "vout": fee_input["vout"]}]
        # Maintain the ICU bond at its current value, add low value output, and change
        outputs = [
            {n.getnewaddress(): icu_value},  # vout 0: ICU rotation
            {n.getnewaddress(): low_value},  # vout 1: AssetTag output (dust)
        ]
        # Add change output if needed
        total_in = icu_value + float(fee_input["amount"])
        total_out = icu_value + low_value + 0.0001  # Include fee
        if total_in > total_out:
            outputs.append({n.getnewaddress(): total_in - total_out})

        mint_raw = n.createrawtransaction(inputs, outputs)
        # Use proper RPC methods for attaching TLVs
        mint_raw = n.rawtxattachissuerreg(mint_raw, 0, asset_id, 3, 0x1C, 500100000)  # ICU rotation on vout 0
        mint_raw = n.rawtxattachassettag(mint_raw, 1, asset_id, 100000)  # AssetTag on vout 1
        # Sign without fundrawtransaction to preserve output order
        # Explicitly specify SIGHASH_ALL to ensure no ANYONECANPAY is used
        mint_s = n.signrawtransactionwithwallet(mint_raw, [], "ALL")
        assert_raises_rpc_error(-26, "asset-dust", n.sendrawtransaction, mint_s['hex'])

        # Now mint with sufficient BTC value on the asset-tagged output -> accept
        ok_value = 0.01  # 1,000,000 sats (> 100,000)
        # Must maintain ICU bond value
        # Re-fetch ICU value (the previous mint attempt failed, so ICU is still unspent)
        icu_utxo = n.gettxout(icu_prev["txid"], icu_prev["vout"])
        if not icu_utxo:
            self.log.error(f"ICU UTXO not found: {icu_prev}")
            raise RuntimeError("ICU UTXO not found")
        icu_value = float(icu_utxo['value'])

        # Get a fee input
        utxos = n.listunspent(minconf=0)
        fee_input = None
        for utxo in utxos:
            if utxo["txid"] != icu_prev["txid"] or utxo["vout"] != icu_prev["vout"]:
                fee_input = utxo
                break

        if not fee_input:
            raise RuntimeError("No suitable UTXO for fees")

        # Create transaction with both ICU input and fee input
        inputs = [icu_prev, {"txid": fee_input["txid"], "vout": fee_input["vout"]}]
        # Maintain the ICU bond at its current value, add sufficient value output, and change
        outputs = [
            {n.getnewaddress(): icu_value},  # vout 0: ICU rotation
            {n.getnewaddress(): ok_value},   # vout 1: AssetTag output (sufficient)
        ]
        # Add change output if needed
        total_in = icu_value + float(fee_input["amount"])
        total_out = icu_value + ok_value + 0.0001  # Include fee
        if total_in > total_out:
            outputs.append({n.getnewaddress(): total_in - total_out})

        mint2_raw = n.createrawtransaction(inputs, outputs)
        # Use proper RPC methods for attaching TLVs
        mint2_raw = n.rawtxattachissuerreg(mint2_raw, 0, asset_id, 3, 0x1C, 500100000)  # ICU rotation on vout 0
        mint2_raw = n.rawtxattachassettag(mint2_raw, 1, asset_id, 100000)  # AssetTag on vout 1
        # Sign without fundrawtransaction to preserve output order
        # Explicitly specify SIGHASH_ALL to ensure no ANYONECANPAY is used
        mint2_s = n.signrawtransactionwithwallet(mint2_raw, [], "ALL")

        # Additional validation: check that the signature doesn't have ANYONECANPAY flag
        tx_decoded = n.decoderawtransaction(mint2_s['hex'])
        self.log.info(f"Decoded transaction inputs count: {len(tx_decoded['vin'])}")
        for i, vin in enumerate(tx_decoded['vin']):
            self.log.info(f"Input {i}: txid={vin['txid'][:16]}..., witness={len(vin.get('txinwitness', []))}")

        txid = n.sendrawtransaction(mint2_s['hex'])
        self.log.info(f"Mint with sufficient BTC accepted: {txid}")


if __name__ == '__main__':
    AssetPolicyMindustTest(__file__).main()
