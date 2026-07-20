#!/usr/bin/env python3
# Copyright (c) 2025 TensorCash
# Distributed under the MIT software license.
"""Asset policy: enforce -assetminmultitouchfee for transactions touching >= 2 assets.

Flow:
- Enable assets at genesis and set -assetminmultitouchfee.
- Register & mint two distinct assets.
- Build a single transaction that touches both assets (two AssetTag inputs/outputs, Δ=0).
- With low fee -> reject (asset-multitouch-fee). With higher fee -> accept.
"""

import time
import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


def reg_tlv(asset_id_hex: str, policy_bits: int = 3, families: int = 0x1C) -> str:
    aid = bytes.fromhex(asset_id_hex)
    v = bytearray(aid)
    v.extend((policy_bits & 0xFFFFFFFF).to_bytes(4, 'little'))
    v.extend((families & 0xFFFF).to_bytes(2, 'little'))
    tlv = bytearray([0x10, len(v)])
    tlv.extend(v)
    return tlv.hex()


def tag_tlv(asset_id_hex: str, amount: int) -> str:
    aid = bytes.fromhex(asset_id_hex)
    v = bytearray(aid)
    v.extend((amount & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
    tlv = bytearray([0x01, len(v)])
    tlv.extend(v)
    return tlv.hex()


class AssetPolicyMultiTouchFee(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Generate unique test run ID to avoid asset ID conflicts
        import os
        # Use PID and timestamp for true uniqueness even in parallel runs
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}".encode()).hexdigest()[:8]
        # Require 10000 sats per touched asset; touching 2 assets -> need >= 20000 sats base fee
        self.extra_args = [[
            "-assetsheight=0",
            "-assetminmultitouchfee=10000",
            "-acceptnonstdtxn=1",
            "-dbcache=1000",  # Use 1GB cache to keep everything in memory
            "-persistmempool=0",  # Don't persist mempool between restarts
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def register_asset(self, n, asset_id: str):
        # Get a fresh spendable UTXO for this registration
        utxos = n.listunspent(minconf=0)
        if not utxos or len(utxos) < 2:
            # Generate more blocks if needed
            self.generate(n, 10)
            utxos = n.listunspent(minconf=0)
        # Find a UTXO with enough value for the 5 BTC bond
        spend = None
        for utxo in utxos:
            if float(utxo["amount"]) >= 5.002:
                spend = utxo
                break
        if not spend:
            # No single UTXO big enough, need to combine
            spend = utxos[0]
        inputs = [{"txid": spend["txid"], "vout": spend["vout"]}]
        # Set bond at 5.001 BTC
        reg_addr = n.getnewaddress()
        change_value = float(spend["amount"]) - 5.001 - 0.0001  # subtract bond and fee
        # Use array format to guarantee output order
        outputs = [{reg_addr: 5.001}]
        if change_value > 0:
            outputs.append({n.getnewaddress(): change_value})
        raw = n.createrawtransaction(inputs, outputs)
        # Use the proper RPC method for attaching issuer registration
        raw = n.rawtxattachissuerreg(raw, 0, asset_id, 3, 0x1C)  # policy_bits=3, allowed_families=0x1C
        # Don't use fundrawtransaction with asset transactions
        signed = n.signrawtransactionwithwallet(raw)
        txid = n.sendrawtransaction(signed['hex'])
        self.generate(n, 1)
        return txid

    def mint_asset(self, n, icu_txid: str, icu_vout: int, asset_id: str, amount: int, asset_btc: float):
        # Get the ICU value to maintain bond
        icu_utxo = n.gettxout(icu_txid, icu_vout)
        icu_value = float(icu_utxo['value'])

        inputs = [{"txid": icu_txid, "vout": icu_vout}]
        # Maintain the ICU bond at its current value
        outs = [{n.getnewaddress(): icu_value}, {n.getnewaddress(): asset_btc}]
        raw = n.createrawtransaction(inputs, outs)
        # Use proper RPC methods for attaching TLVs
        raw = n.rawtxattachissuerreg(raw, 0, asset_id, 3, 0x1C)  # ICU rotation at vout 0
        raw = n.rawtxattachassettag(raw, 1, asset_id, amount)  # Asset at vout 1
        # Use fundrawtransaction to add inputs for fees
        funded = n.fundrawtransaction(raw)
        signed = n.signrawtransactionwithwallet(funded['hex'])
        txid = n.sendrawtransaction(signed['hex'])
        self.generate(n, 1)

        # Find the actual asset output location after fundrawtransaction
        policy = n.getassetpolicy(asset_id)
        icu_vout_after = policy['icu_vout']
        mint_tx = n.gettransaction(txid, True, True)['decoded']
        asset_vout = None
        for i, out in enumerate(mint_tx['vout']):
            if 'outext' in out and i != icu_vout_after:
                asset_vout = i
                break
        assert asset_vout is not None, "No asset output found"
        return txid, asset_vout, amount

    def setup_clean_chain(self):
        # Force completely clean chain for each test run
        return True

    def run_test(self):
        n = self.nodes[0]
        # Ensure we have a completely fresh start
        assert n.getblockcount() == 0, "Chain should start at height 0"
        self.generate(n, 101)

        # Register two assets (use unique IDs for this test run)
        a1 = hashlib.sha256(("multitouch_asset1_" + self.test_run_id).encode()).hexdigest()
        a2 = hashlib.sha256(("multitouch_asset2_" + self.test_run_id).encode()).hexdigest()
        self.register_asset(n, a1)
        self.register_asset(n, a2)

        pol1 = n.getassetpolicy(a1)
        if pol1 is None:
            raise AssertionError(f"Asset 1 policy not found after registration")
        pol2 = n.getassetpolicy(a2)
        if pol2 is None:
            raise AssertionError(f"Asset 2 policy not found after registration")

        # Mint both assets
        tx1, vout1, amt1 = self.mint_asset(n, pol1['icu_txid'], pol1['icu_vout'], a1, 100000, 0.1)
        tx2, vout2, amt2 = self.mint_asset(n, pol2['icu_txid'], pol2['icu_vout'], a2, 200000, 0.1)

        # Build a transfer tx that touches both assets (Δ=0 for each)
        inputs = [{"txid": tx1, "vout": vout1}, {"txid": tx2, "vout": vout2}]

        # Get a UTXO for fees (low fee attempt)
        fee_utxos = n.listunspent()
        # Find a suitable fee UTXO
        fee_utxo_low = None
        for utxo in fee_utxos:
            if float(utxo["amount"]) >= 0.001:  # Need enough for outputs and fee
                fee_utxo_low = utxo
                break
        if not fee_utxo_low:
            raise AssertionError("No suitable UTXO for fees")

        inputs_low = inputs + [{"txid": fee_utxo_low["txid"], "vout": fee_utxo_low["vout"]}]

        # Low fee (0.00001 BTC = 1000 sats) - should fail as we need 20000 sats for 2 assets
        low_fee = 0.00001
        # Total input from the fee UTXO needs to cover both asset outputs (0.1 BTC each) plus change
        # The asset outputs already have 0.1 BTC each from minting
        # We just need to preserve those values
        outs_low = [{n.getnewaddress(): 0.1}, {n.getnewaddress(): 0.1}]
        # Add change output for remaining from fee UTXO
        change_low = float(fee_utxo_low["amount"]) - low_fee
        if change_low > 0.0001:
            outs_low.append({n.getnewaddress(): change_low})

        raw_low = n.createrawtransaction(inputs_low, outs_low)
        # Attach the same amounts back to outputs to conserve each asset
        raw_low = n.rawtxattachassettag(raw_low, 0, a1, amt1)
        raw_low = n.rawtxattachassettag(raw_low, 1, a2, amt2)

        # Don't use fundrawtransaction with asset transactions
        signed_low = n.signrawtransactionwithwallet(raw_low)
        assert_raises_rpc_error(-26, "asset-multitouch-fee", n.sendrawtransaction, signed_low['hex'])

        # Higher fee rate: should accept
        # Get a fresh UTXO for fees (high fee attempt)
        fee_utxo_high = fee_utxos[1] if len(fee_utxos) > 1 else fee_utxos[0]
        inputs_high = [{"txid": tx1, "vout": vout1}, {"txid": tx2, "vout": vout2},
                       {"txid": fee_utxo_high["txid"], "vout": fee_utxo_high["vout"]}]

        # High fee (0.0003 BTC = 30000 sats > 20000 required for 2 assets)
        high_fee = 0.0003
        change_high = float(fee_utxo_high["amount"]) - high_fee
        # Keep the base BTC amounts identical to the inputs so the only fee
        # contribution comes from the fee UTXO. Otherwise we'd burn asset BTC
        # value and unintentionally exceed the wallet's max fee limit.
        outs_high = [{n.getnewaddress(): 0.1}, {n.getnewaddress(): 0.1}]
        if change_high > 0.0001:
            outs_high.append({n.getnewaddress(): change_high})

        raw_high = n.createrawtransaction(inputs_high, outs_high)
        # Attach the same amounts back to outputs to conserve each asset
        raw_high = n.rawtxattachassettag(raw_high, 0, a1, amt1)
        raw_high = n.rawtxattachassettag(raw_high, 1, a2, amt2)

        # Don't use fundrawtransaction with asset transactions
        signed_high = n.signrawtransactionwithwallet(raw_high)
        txid = n.sendrawtransaction(signed_high['hex'])
        self.log.info(f"Multi-touch fee satisfied, tx accepted: {txid}")


if __name__ == '__main__':
    AssetPolicyMultiTouchFee(__file__).main()
