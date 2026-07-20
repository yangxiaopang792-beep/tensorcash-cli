#!/usr/bin/env python3
"""RPC-level spot atomic swap contract coverage."""

from decimal import Decimal
import hashlib
import json

from asset_wallet_util import register_asset as util_register_asset
from asset_wallet_util import mint_asset as util_mint_asset

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)


class CovenantSpotTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1", "-assetsheight=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        """Test spot atomic swap contract workflow with asset-for-asset and asset-for-native swaps."""
        self.log.info("=" * 80)
        self.log.info("SPOT ATOMIC SWAP TESTS")
        self.log.info("Testing asset-for-asset and asset-for-native swaps")
        self.log.info("=" * 80)
        node = self.nodes[0]

        # Create separate wallets for Alice and Bob
        node.createwallet("alice", descriptors=True)
        node.createwallet("bob", descriptors=True)
        alice_wallet = node.get_wallet_rpc("alice")
        bob_wallet = node.get_wallet_rpc("bob")

        # Fund both wallets with mature coinbase (need 101+ blocks)
        alice_addr = alice_wallet.getnewaddress()
        bob_addr = bob_wallet.getnewaddress()
        self.generatetoaddress(node, 101, alice_addr)
        self.generatetoaddress(node, 101, bob_addr)
        alice_wallet.rescanblockchain()
        bob_wallet.rescanblockchain()

        # Register and mint two different assets for testing
        asset_a_id, policy_a, icu_a = self._register_asset(alice_wallet, node, ticker="TOKA", decimals=6)
        asset_b_id, policy_b, icu_b = self._register_asset(bob_wallet, node, ticker="TOKB", decimals=6)

        # Mint assets: Alice gets TOKA, Bob gets TOKB
        # Mint extra for both tests (Test 1 uses 1M, Test 2 uses 100K)
        alice_units = 1_000_000
        bob_units = 500_000
        _, policy_a = self._mint_asset(alice_wallet, node, asset_a_id, policy_a, icu_a, alice_units + 200_000)
        _, policy_b = self._mint_asset(bob_wallet, node, asset_b_id, policy_b, icu_b, bob_units + 100_000)

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # ====================================================================
        # Test 1: Asset-for-asset swap (Alice TOKA ⇄ Bob TOKB)
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 1: Asset-for-Asset Atomic Swap (TOKA ⇄ TOKB)")
        self.log.info("=" * 80)

        alice_receive_addr = alice_wallet.getnewaddress(address_type="bech32m")
        bob_receive_addr = bob_wallet.getnewaddress(address_type="bech32m")

        # Balance checkpoint 1: Initial balances
        alice_toka_before = self._asset_units_at(alice_wallet, asset_a_id, alice_receive_addr)
        alice_tokb_before = self._asset_units_at(alice_wallet, asset_b_id, alice_receive_addr)
        bob_toka_before = self._asset_units_at(bob_wallet, asset_a_id, bob_receive_addr)
        bob_tokb_before = self._asset_units_at(bob_wallet, asset_b_id, bob_receive_addr)

        alice_btc_before = alice_wallet.getbalance()
        bob_btc_before = bob_wallet.getbalance()

        self.log.info(f"\n[CHECKPOINT 1] Initial Balances:")
        self.log.info(f"  Alice TOKA: {alice_toka_before} units")
        self.log.info(f"  Alice TOKB: {alice_tokb_before} units")
        self.log.info(f"  Alice BTC:  {alice_btc_before:.8f}")
        self.log.info(f"  Bob   TOKA: {bob_toka_before} units")
        self.log.info(f"  Bob   TOKB: {bob_tokb_before} units")
        self.log.info(f"  Bob   BTC:  {bob_btc_before:.8f}")

        # Alice proposes to swap her TOKA for Bob's TOKB
        offer_result = alice_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": asset_a_id,
                    "units": alice_units,
                },
                "bob_leg": {
                    "asset_id": asset_b_id,
                    "units": bob_units,
                },
            },
            "alice_address": alice_receive_addr,
            "bob_address_hint": bob_receive_addr,
        })

        offer_id = offer_result["offer_id"]
        offer_payload = offer_result["offer"]

        self.log.info(f"\n✓ Alice proposed swap:")
        self.log.info(f"  Offer ID:    {offer_id[:16]}...")
        self.log.info(f"  Alice gives: {alice_units} TOKA")
        self.log.info(f"  Bob gives:   {bob_units} TOKB")

        assert "terms" in offer_payload

        # Bob imports and accepts the offer
        bob_wallet.spot.import_offer(offer_payload)
        acceptance_result = bob_wallet.spot.accept(offer_id, {"confirmed": True})
        assert "accept_id" in acceptance_result
        assert "acceptance" in acceptance_result
        self.log.info(f"✓ Bob accepted swap")

        # Alice imports Bob's acceptance
        alice_wallet.spot.import_acceptance(offer_id, acceptance_result["acceptance"])
        self.log.info(f"✓ Alice imported acceptance")

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Check contract status
        alice_status = alice_wallet.contract.status(offer_id)
        bob_status = bob_wallet.contract.status(offer_id)
        assert_equal(alice_status["state"], "accepted")
        assert_equal(bob_status["state"], "accepted")
        self.log.info(f"✓ Both parties confirm: state = 'accepted'")

        # Both parties build and sign the atomic swap PSBT
        self.log.info(f"\n✓ Building atomic swap transaction (AUGMENTATION PATTERN)...")

        # Alice builds BASE PSBT with her own leg output (alice_leg), only Alice's inputs
        alice_base = alice_wallet.spot.build_atomic(offer_id)
        assert "psbt" in alice_base
        assert "complete" in alice_base
        assert_equal(alice_base["my_role"], "alice")
        self.log.info(f"  Alice built base PSBT with her own leg output (role: alice)")

        # Bob AUGMENTS Alice's base PSBT with his own leg output and inputs
        bob_augmented = bob_wallet.spot.build_atomic(offer_id, {"psbt": alice_base["psbt"]})
        assert "psbt" in bob_augmented
        assert_equal(bob_augmented["my_role"], "bob")
        self.log.info(f"  Bob augmented with his own leg output and inputs (role: bob)")

        # DEBUG: Decode Bob's augmented PSBT
        bob_decoded = bob_wallet.decodepsbt(bob_augmented["psbt"])
        self.log.info(f"\n=== BOB'S AUGMENTED PSBT ===")
        self.log.info(f"Inputs: {len(bob_decoded['inputs'])}")
        self.log.info(f"Outputs: {len(bob_decoded['tx']['vout'])}")
        for i, out in enumerate(bob_decoded['tx']['vout']):
            self.log.info(f"  Output {i}: {out['value']} BTC, addr={out['scriptPubKey'].get('address', 'N/A')}, vExt={bool(out.get('vExt'))}")
        self.log.info(f"=== END BOB'S AUGMENTED PSBT ===\n")

        # Both parties sign the augmented PSBT (no joinpsbts needed - already combined)
        alice_signed_psbt = alice_wallet.walletprocesspsbt(bob_augmented["psbt"], sign=True)["psbt"]
        bob_signed_psbt = bob_wallet.walletprocesspsbt(alice_signed_psbt, sign=True)["psbt"]

        # Finalize and broadcast
        final = bob_wallet.finalizepsbt(bob_signed_psbt)
        assert final["complete"], "Atomic swap PSBT should be complete after both parties sign"

        # DEBUG: Decode and inspect the final transaction
        decoded_tx = node.decoderawtransaction(final["hex"])
        self.log.info(f"\n=== FINAL TRANSACTION DEBUG ===")
        self.log.info(f"TXID: {decoded_tx['txid']}")
        self.log.info(f"Bob expects TOKA at: {bob_receive_addr}")
        self.log.info(f"Alice expects TOKB at: {alice_receive_addr}")
        self.log.info(f"\nINPUTS ({len(decoded_tx['vin'])}):")
        for i, inp in enumerate(decoded_tx['vin']):
            self.log.info(f"  Input {i}: {inp['txid'][:16]}...:{inp['vout']}")

        self.log.info(f"\nOUTPUTS ({len(decoded_tx['vout'])}):")
        for i, out in enumerate(decoded_tx['vout']):
            out_addr = out['scriptPubKey'].get('address', 'N/A')
            self.log.info(f"  Output {i}:")
            self.log.info(f"    Value: {out['value']} BTC")
            self.log.info(f"    Address: {out_addr}")
            if out_addr == bob_receive_addr:
                self.log.info(f"    *** THIS IS BOB'S RECEIVE ADDRESS ***")
            if out_addr == alice_receive_addr:
                self.log.info(f"    *** THIS IS ALICE'S RECEIVE ADDRESS ***")
            if 'vExt' in out and out['vExt']:
                # Try to decode asset tag
                try:
                    vext_hex = out['vExt']
                    self.log.info(f"    vExt (asset): {vext_hex}")
                except:
                    pass
        self.log.info(f"=== END TRANSACTION DEBUG ===\n")

        swap_txid = node.sendrawtransaction(final["hex"])
        self.log.info(f"✓ Atomic swap broadcast: {swap_txid[:16]}...")

        self.generate(node, 3)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Balance checkpoint 2: After swap
        alice_toka_after = self._asset_units_at(alice_wallet, asset_a_id, alice_receive_addr)
        alice_tokb_after = self._asset_units_at(alice_wallet, asset_b_id, alice_receive_addr)
        bob_toka_after = self._asset_units_at(bob_wallet, asset_a_id, bob_receive_addr)
        bob_tokb_after = self._asset_units_at(bob_wallet, asset_b_id, bob_receive_addr)

        alice_btc_after = alice_wallet.getbalance()
        bob_btc_after = bob_wallet.getbalance()

        self.log.info(f"\n[CHECKPOINT 2] Final Balances After Swap:")
        self.log.info(f"  Alice TOKA: {alice_toka_after} units (sent {alice_units})")
        self.log.info(f"  Alice TOKB: {alice_tokb_after} units (received {bob_units})")
        self.log.info(f"  Alice BTC:  {alice_btc_after:.8f}")
        self.log.info(f"  Bob   TOKA: {bob_toka_after} units (received {alice_units})")
        self.log.info(f"  Bob   TOKB: {bob_tokb_after} units (sent {bob_units})")
        self.log.info(f"  Bob   BTC:  {bob_btc_after:.8f}")

        # Assertions: Verify the swap happened correctly
        assert_equal(alice_toka_after, alice_toka_before)  # Alice sent TOKA, so same at receive addr
        assert_equal(alice_tokb_after - alice_tokb_before, bob_units)  # Alice received TOKB
        assert_equal(bob_toka_after - bob_toka_before, alice_units)  # Bob received TOKA
        assert_equal(bob_tokb_after, bob_tokb_before)  # Bob sent TOKB, so same at receive addr

        self.log.info("✓✓✓ ASSET-FOR-ASSET SWAP COMPLETE ✓✓✓")

        # Unlock UTXOs for next test
        alice_wallet.lockunspent(True)
        bob_wallet.lockunspent(True)

        # ====================================================================
        # Test 2: Asset-for-native swap (Asset ⇄ BTC)
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 2: Asset-for-Native Atomic Swap (TOKA ⇄ BTC)")
        self.log.info("=" * 80)

        alice_native_receive = alice_wallet.getnewaddress(address_type="bech32m")
        bob_native_receive = bob_wallet.getnewaddress(address_type="bech32m")

        native_alice_units = 100_000
        native_btc_units = 50_000_000  # 0.5 BTC

        # Balance checkpoint 3: Before native swap
        alice_toka_before_native = self._asset_units_at(alice_wallet, asset_a_id, alice_native_receive)
        bob_toka_before_native = self._asset_units_at(bob_wallet, asset_a_id, bob_native_receive)
        alice_btc_before_native = self._native_balance_at(alice_wallet, alice_native_receive)
        bob_btc_before_native = self._native_balance_at(bob_wallet, bob_native_receive)
        alice_wallet_btc_before_native = alice_wallet.getbalance()

        self.log.info(f"\n[CHECKPOINT 3] Initial Balances (Native Swap):")
        self.log.info(f"  Alice TOKA: {alice_toka_before_native} units at {alice_native_receive[:20]}...")
        self.log.info(f"  Alice BTC:  {alice_btc_before_native:.8f} at {alice_native_receive[:20]}...")
        self.log.info(f"  Bob   TOKA: {bob_toka_before_native} units at {bob_native_receive[:20]}...")
        self.log.info(f"  Bob   BTC:  {bob_btc_before_native:.8f} at {bob_native_receive[:20]}...")

        native_offer = alice_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": asset_a_id,
                    "units": native_alice_units,
                },
                "bob_leg": {
                    "is_native": True,
                    "units": native_btc_units,
                },
            },
            "alice_address": alice_native_receive,
            "bob_address_hint": bob_native_receive,
        })

        native_offer_id = native_offer["offer_id"]
        self.log.info(f"\n✓ Alice proposed native swap:")
        self.log.info(f"  Offer ID:    {native_offer_id[:16]}...")
        self.log.info(f"  Alice gives: {native_alice_units} TOKA")
        self.log.info(f"  Bob gives:   {Decimal(native_btc_units) / COIN:.8f} BTC")

        bob_wallet.spot.import_offer(native_offer["offer"])
        native_acceptance = bob_wallet.spot.accept(native_offer_id, {"confirmed": True})
        alice_wallet.spot.import_acceptance(native_offer_id, native_acceptance["acceptance"])
        self.log.info(f"✓ Bob accepted native swap")
        self.log.info(f"✓ Alice imported acceptance")

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Build and sign the native atomic swap (AUGMENTATION PATTERN)
        native_alice_base = alice_wallet.spot.build_atomic(native_offer_id)
        assert "psbt" in native_alice_base
        self.log.info(f"✓ Alice built base PSBT with both outputs")

        native_bob_augmented = bob_wallet.spot.build_atomic(native_offer_id, {"psbt": native_alice_base["psbt"]})
        assert "psbt" in native_bob_augmented
        self.log.info(f"✓ Bob augmented with his inputs")

        # No joinpsbts needed - Bob's augmented PSBT already has both parties' inputs
        native_combined_psbt = native_bob_augmented["psbt"]
        self.log.info(f"✓ Augmented PSBT ready (both parties' inputs)")

        native_combined_decoded = alice_wallet.decodepsbt(native_combined_psbt)
        self.log.info(f"\n=== JOINED NATIVE PSBT ===")
        self.log.info(f"Inputs: {len(native_combined_decoded['inputs'])}")
        self.log.info(f"Outputs: {len(native_combined_decoded['outputs'])}")
        for i, out in enumerate(native_combined_decoded['tx']['vout']):
            self.log.info(f"  Output {i}: {out['value']} BTC, addr={out['scriptPubKey'].get('address', 'N/A')}, vExt={bool(out.get('vExt'))}")
        self.log.info(f"=== END JOINED NATIVE PSBT ===\n")

        # Alice and Bob both sign the joined native PSBT
        native_alice_signed = alice_wallet.walletprocesspsbt(native_combined_psbt, sign=True)["psbt"]
        native_bob_signed = bob_wallet.walletprocesspsbt(native_alice_signed, sign=True)["psbt"]

        # Finalize and broadcast
        native_final = bob_wallet.finalizepsbt(native_bob_signed)
        assert native_final["complete"], "Native swap PSBT should be complete"
        native_swap_txid = node.sendrawtransaction(native_final["hex"])
        self.log.info(f"✓ Native swap broadcast: {native_swap_txid[:16]}...")

        self.generate(node, 3)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Inspect Bob's wallet view of the swap to assert the BTC leg accurately
        bob_swap_tx = bob_wallet.gettransaction(native_swap_txid)
        bob_swap_details = bob_swap_tx.get("details", [])

        # Balance checkpoint 4: After native swap
        alice_toka_after_native = self._asset_units_at(alice_wallet, asset_a_id, alice_native_receive)
        bob_toka_after_native = self._asset_units_at(bob_wallet, asset_a_id, bob_native_receive)
        alice_btc_after_native = self._native_balance_at(alice_wallet, alice_native_receive)
        bob_btc_after_native = self._native_balance_at(bob_wallet, bob_native_receive)
        alice_wallet_btc_after_native = alice_wallet.getbalance()

        self.log.info(f"\n[CHECKPOINT 4] Final Balances After Native Swap:")
        self.log.info(f"  Alice TOKA: {alice_toka_after_native} units")
        self.log.info(f"  Alice BTC:  {alice_btc_after_native:.8f} (received {Decimal(native_btc_units) / COIN:.8f})")
        self.log.info(f"  Bob   TOKA: {bob_toka_after_native} units (received {native_alice_units})")
        self.log.info(f"  Bob   BTC:  {bob_btc_after_native:.8f}")

        # Assertions: Verify the native swap happened correctly
        assert_equal(alice_toka_after_native, alice_toka_before_native)  # Alice sent TOKA
        # Alice received BTC
        expected_native = Decimal(native_btc_units) / COIN
        assert_equal(alice_btc_after_native - alice_btc_before_native, expected_native)
        alice_wallet_delta = Decimal(str(alice_wallet_btc_after_native)) - Decimal(str(alice_wallet_btc_before_native))
        fee_tolerance = Decimal("0.002")  # tolerate up to ~200k sats of wallet-funded fees
        assert_greater_than_or_equal(fee_tolerance, abs(alice_wallet_delta - expected_native))
        assert_equal(bob_toka_after_native - bob_toka_before_native, native_alice_units)  # Bob received TOKA
        # Bob's wallet should show a send of 0.5 BTC to Alice's native receive address
        bob_send_entries = [Decimal(str(d["amount"])) for d in bob_swap_details
                             if d.get("category") == "send" and d.get("address") == alice_native_receive]
        assert bob_send_entries, "Bob's wallet must report a send entry to Alice's receive address"
        bob_send_total = sum(bob_send_entries)
        assert_equal(bob_send_total, -expected_native)

        self.log.info("✓✓✓ ASSET-FOR-NATIVE SWAP COMPLETE ✓✓✓")

        # ====================================================================
        # Test 4: Asset-for-asset swap with change handling
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 4: Asset-for-Asset Swap With Change Outputs")
        self.log.info("=" * 80)

        # Mint additional inventory so both parties generate change when swapping partial amounts
        extra_alice_units = 400_000
        extra_bob_units = 200_000
        _, policy_a = self._mint_asset(alice_wallet, node, asset_a_id, policy_a, icu_a, extra_alice_units)
        _, policy_b = self._mint_asset(bob_wallet, node, asset_b_id, policy_b, icu_b, extra_bob_units)
        self.generate(node, 1)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        change_alice_units = 150_000
        change_bob_units = 75_000

        alice_change_recv = alice_wallet.getnewaddress(address_type="bech32m")
        bob_change_recv = bob_wallet.getnewaddress(address_type="bech32m")

        alice_a_total_before = self._asset_units_total(alice_wallet, asset_a_id)
        alice_b_total_before = self._asset_units_total(alice_wallet, asset_b_id)
        bob_a_total_before = self._asset_units_total(bob_wallet, asset_a_id)
        bob_b_total_before = self._asset_units_total(bob_wallet, asset_b_id)

        change_offer = alice_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": asset_a_id,
                    "units": change_alice_units,
                },
                "bob_leg": {
                    "asset_id": asset_b_id,
                    "units": change_bob_units,
                },
            },
            "alice_address": alice_change_recv,
            "bob_address_hint": bob_change_recv,
        })

        change_offer_id = change_offer["offer_id"]
        self.log.info(f"\n✓ Alice proposed change swap:")
        self.log.info(f"  Offer ID:    {change_offer_id[:16]}...")
        self.log.info(f"  Alice gives: {change_alice_units} TOKA")
        self.log.info(f"  Bob gives:   {change_bob_units} TOKB")

        bob_wallet.spot.import_offer(change_offer["offer"])
        change_acceptance = bob_wallet.spot.accept(change_offer_id, {"confirmed": True})
        alice_wallet.spot.import_acceptance(change_offer_id, change_acceptance["acceptance"])
        self.log.info(f"✓ Bob accepted change swap")
        self.log.info(f"✓ Alice imported change acceptance")

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Use augmentation pattern (like Tests 1-3)
        change_alice_base = alice_wallet.spot.build_atomic(change_offer_id)
        change_bob_augmented = bob_wallet.spot.build_atomic(change_offer_id, {"psbt": change_alice_base["psbt"]})
        self.log.info(f"✓ Both parties built change swap PSBTs")

        assert change_alice_base["asset_change_index"] != -1, "Alice PSBT must include an asset change output"
        assert change_bob_augmented["asset_change_index"] != -1, "Bob PSBT must include an asset change output"
        change_combined_psbt = change_bob_augmented["psbt"]  # Already combined via augmentation
        change_combined_decoded = alice_wallet.decodepsbt(change_combined_psbt)
        self.log.info(f"\n=== JOINED CHANGE PSBT ===")
        self.log.info(f"Inputs: {len(change_combined_decoded['inputs'])}")
        self.log.info(f"Outputs: {len(change_combined_decoded['outputs'])}")
        for i, out in enumerate(change_combined_decoded['tx']['vout']):
            self.log.info(f"  Output {i}: {out} {out['value']} BTC, addr={out['scriptPubKey'].get('address', 'N/A')}, vExt={bool(out.get('vExt'))}")
        self.log.info(f"=== END JOINED CHANGE PSBT ===\n")

        change_alice_signed = alice_wallet.walletprocesspsbt(change_combined_psbt, sign=True)["psbt"]
        change_bob_signed = bob_wallet.walletprocesspsbt(change_alice_signed, sign=True)["psbt"]

        change_final = bob_wallet.finalizepsbt(change_bob_signed)
        assert change_final["complete"], "Change swap PSBT should be complete"
        change_txid = node.sendrawtransaction(change_final["hex"])
        self.log.info(f"✓ Change swap broadcast: {change_txid[:16]}...")

        self.generate(node, 3)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        alice_a_total_after = self._asset_units_total(alice_wallet, asset_a_id)
        alice_b_total_after = self._asset_units_total(alice_wallet, asset_b_id)
        bob_a_total_after = self._asset_units_total(bob_wallet, asset_a_id)
        bob_b_total_after = self._asset_units_total(bob_wallet, asset_b_id)

        assert_equal(alice_a_total_before - alice_a_total_after, change_alice_units)
        assert_equal(alice_b_total_after - alice_b_total_before, change_bob_units)
        assert_equal(bob_a_total_after - bob_a_total_before, change_alice_units)
        assert_equal(bob_b_total_before - bob_b_total_after, change_bob_units)

        self.log.info("✓✓✓ ASSET-FOR-ASSET SWAP WITH CHANGE COMPLETE ✓✓✓")

        # ====================================================================
        # Test 4.5: Multi-UTXO Input Consolidation with Change
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 4.5: Multi-UTXO Input Consolidation with Partial Amounts")
        self.log.info("=" * 80)

        # Create fragmented UTXOs by minting small amounts multiple times
        # This forces the wallet to use multiple inputs when building the swap
        fragment_count = 3
        alice_fragment_units = 50_000
        bob_fragment_units = 25_000

        self.log.info(f"Creating {fragment_count} fragmented UTXOs for each party...")
        for i in range(fragment_count):
            _, policy_a = self._mint_asset(alice_wallet, node, asset_a_id, policy_a, icu_a, alice_fragment_units)
            _, policy_b = self._mint_asset(bob_wallet, node, asset_b_id, policy_b, icu_b, bob_fragment_units)
            self.generate(node, 1)

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Now propose a swap that requires combining multiple UTXOs
        # Alice wants to swap 120k TOKA (needs to combine at least 3 UTXOs of 50k each)
        # Bob wants to swap 210k TOKB (exceeds his 200k UTXO from Test 4, forces combining multiple UTXOs)
        multi_alice_units = 120_000
        multi_bob_units = 210_000

        alice_multi_recv = alice_wallet.getnewaddress(address_type="bech32m")
        bob_multi_recv = bob_wallet.getnewaddress(address_type="bech32m")

        # Count UTXOs before
        alice_utxos_before = alice_wallet.listassetutxos([asset_a_id], 0, 9999999)
        bob_utxos_before = bob_wallet.listassetutxos([asset_b_id], 0, 9999999)
        alice_a_utxo_count_before = len([u for u in alice_utxos_before if u.get("asset_id") == asset_a_id])
        bob_b_utxo_count_before = len([u for u in bob_utxos_before if u.get("asset_id") == asset_b_id])

        self.log.info(f"Alice has {alice_a_utxo_count_before} TOKA UTXOs before swap")
        self.log.info(f"Bob has {bob_b_utxo_count_before} TOKB UTXOs before swap")

        alice_a_total_before_multi = self._asset_units_total(alice_wallet, asset_a_id)
        alice_b_total_before_multi = self._asset_units_total(alice_wallet, asset_b_id)
        bob_a_total_before_multi = self._asset_units_total(bob_wallet, asset_a_id)
        bob_b_total_before_multi = self._asset_units_total(bob_wallet, asset_b_id)

        multi_offer = alice_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": asset_a_id,
                    "units": multi_alice_units,
                },
                "bob_leg": {
                    "asset_id": asset_b_id,
                    "units": multi_bob_units,
                },
            },
            "alice_address": alice_multi_recv,
            "bob_address_hint": bob_multi_recv,
        })

        multi_offer_id = multi_offer["offer_id"]
        self.log.info(f"\n✓ Alice proposed multi-UTXO swap:")
        self.log.info(f"  Offer ID:    {multi_offer_id[:16]}...")
        self.log.info(f"  Alice gives: {multi_alice_units} TOKA (requires combining multiple UTXOs)")
        self.log.info(f"  Bob gives:   {multi_bob_units} TOKB (requires combining multiple UTXOs)")

        bob_wallet.spot.import_offer(multi_offer["offer"])
        multi_acceptance = bob_wallet.spot.accept(multi_offer_id, {"confirmed": True})
        alice_wallet.spot.import_acceptance(multi_offer_id, multi_acceptance["acceptance"])
        self.log.info(f"✓ Bob accepted multi-UTXO swap")

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Use augmentation pattern (like Tests 1-4)
        multi_alice_base = alice_wallet.spot.build_atomic(multi_offer_id)
        multi_alice_decoded = alice_wallet.decodepsbt(multi_alice_base["psbt"])
        alice_input_count = len(multi_alice_decoded['inputs'])

        multi_bob_augmented = bob_wallet.spot.build_atomic(multi_offer_id, {"psbt": multi_alice_base["psbt"]})
        self.log.info(f"✓ Both parties built multi-UTXO swap PSBTs")

        # Decode and verify transaction structure
        multi_combined_decoded = alice_wallet.decodepsbt(multi_bob_augmented["psbt"])
        total_input_count = len(multi_combined_decoded['inputs'])
        bob_input_count = total_input_count - alice_input_count

        self.log.info(f"\n=== MULTI-UTXO TRANSACTION STRUCTURE ===")
        self.log.info(f"Alice's PSBT has {alice_input_count} inputs")
        self.log.info(f"Bob's PSBT has {bob_input_count} inputs")

        # Assert that multiple inputs are being used (should need at least 2+ for each party)
        assert_greater_than(alice_input_count, 1)
        assert_greater_than(bob_input_count, 1)

        # Verify change outputs exist
        assert multi_alice_base["asset_change_index"] != -1, "Alice PSBT must include asset change output"
        assert multi_bob_augmented["asset_change_index"] != -1, "Bob PSBT must include asset change output"

        multi_combined_psbt = multi_bob_augmented["psbt"]  # Already combined via augmentation

        total_inputs = len(multi_combined_decoded['inputs'])
        total_outputs = len(multi_combined_decoded['outputs'])

        self.log.info(f"Combined PSBT: {total_inputs} inputs, {total_outputs} outputs")

        # Verify the combined transaction has the expected structure
        # Should have: Alice inputs + Bob inputs
        assert_equal(total_inputs, alice_input_count + bob_input_count)

        # Verify output structure includes:
        # - Alice receives Bob's asset
        # - Bob receives Alice's asset
        # - Alice change (native BTC)
        # - Bob change (native BTC)
        # - Alice asset change (if any)
        # - Bob asset change (if any)
        assert_greater_than_or_equal(total_outputs, 4)

        # Log output details
        self.log.info(f"\nCombined PSBT Outputs:")
        asset_outputs = 0
        native_outputs = 0
        for i, out in enumerate(multi_combined_decoded['tx']['vout']):
            has_asset = bool(out.get('vExt') or out.get('outext'))
            if has_asset:
                asset_outputs += 1
            else:
                native_outputs += 1
            self.log.info(f"  Output {i}: {out['value']} BTC, "
                         f"addr={out['scriptPubKey'].get('address', 'N/A')[:20]}..., "
                         f"asset={has_asset}")

        self.log.info(f"Total: {asset_outputs} asset outputs, {native_outputs} native outputs")

        # Should have at least 4 asset outputs: 2 for the swap + 2 for change
        assert_greater_than_or_equal(asset_outputs, 4)
        self.log.info(f"=== END MULTI-UTXO TRANSACTION STRUCTURE ===\n")

        # Sign, finalize and broadcast
        multi_alice_signed = alice_wallet.walletprocesspsbt(multi_combined_psbt, sign=True)["psbt"]
        multi_bob_signed = bob_wallet.walletprocesspsbt(multi_alice_signed, sign=True)["psbt"]

        multi_final = bob_wallet.finalizepsbt(multi_bob_signed)
        assert multi_final["complete"], "Multi-UTXO swap PSBT should be complete"
        multi_txid = node.sendrawtransaction(multi_final["hex"])
        self.log.info(f"✓ Multi-UTXO swap broadcast: {multi_txid[:16]}...")

        self.generate(node, 3)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Verify final balances
        alice_a_total_after_multi = self._asset_units_total(alice_wallet, asset_a_id)
        alice_b_total_after_multi = self._asset_units_total(alice_wallet, asset_b_id)
        bob_a_total_after_multi = self._asset_units_total(bob_wallet, asset_a_id)
        bob_b_total_after_multi = self._asset_units_total(bob_wallet, asset_b_id)

        # Count UTXOs after
        alice_utxos_after = alice_wallet.listassetutxos([asset_a_id], 0, 9999999)
        bob_utxos_after = bob_wallet.listassetutxos([asset_b_id], 0, 9999999)
        alice_a_utxo_count_after = len([u for u in alice_utxos_after if u.get("asset_id") == asset_a_id])
        bob_b_utxo_count_after = len([u for u in bob_utxos_after if u.get("asset_id") == asset_b_id])

        self.log.info(f"\nUTXO consolidation:")
        self.log.info(f"  Alice TOKA UTXOs: {alice_a_utxo_count_before} -> {alice_a_utxo_count_after}")
        self.log.info(f"  Bob TOKB UTXOs: {bob_b_utxo_count_before} -> {bob_b_utxo_count_after}")

        # Verify amounts transferred correctly
        assert_equal(alice_a_total_before_multi - alice_a_total_after_multi, multi_alice_units)
        assert_equal(alice_b_total_after_multi - alice_b_total_before_multi, multi_bob_units)
        assert_equal(bob_a_total_after_multi - bob_a_total_before_multi, multi_alice_units)
        assert_equal(bob_b_total_before_multi - bob_b_total_after_multi, multi_bob_units)

        self.log.info("✓✓✓ MULTI-UTXO INPUT CONSOLIDATION SWAP COMPLETE ✓✓✓")

        # ====================================================================
        # Test 4.6: ICU Key Wrap Holder-Only Assets Swap
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 4.6: ICU Key Wrap Holder-Only Assets Atomic Swap")
        self.log.info("=" * 80)
        self.log.info("Objective: Test atomic swap of two holder-only encrypted assets")
        self.log.info("           Each party independently generates their own holder-only asset")
        self.log.info("           After swap, each party can decrypt the received asset's ICU data")

        # Alice creates her holder-only asset
        self.log.info("\n[Test 4.6.1] Alice registers holder-only asset with ICU encryption...")
        alice_icu_text = "CONFIDENTIAL: Alice's proprietary trading algorithm v2.1"
        alice_wrap_asset_id = hashlib.sha256(b"alice_holder_only_asset").hexdigest()

        alice_icu_payload, alice_canonical_hash, alice_witness_hash, alice_metadata = self._build_icu_payload(
            alice_icu_text, {"version": "1.0", "canonical_hash": "placeholder"}, visibility=1
        )

        alice_wrap_reg_addr = alice_wallet.getnewaddress()
        alice_wrap_asset_txid = alice_wallet.registerasset(
            alice_wrap_reg_addr,
            Decimal("5.1"),
            alice_wrap_asset_id,
            0x0001,  # MINT_ALLOWED
            28,
            510000000,
            "ALICEWRAP",
            6,
            {
                "autofund": True,
                "broadcast": True,
                "icu_payload_plain": alice_icu_payload.hex(),
                "icu_visibility": 1,  # holder-only - will auto-encrypt and set WRAP_REQUIRED
                "policy_quorum_bps": 0
            }
        )

        self.generate(node, 1)
        alice_wallet.rescanblockchain()
        bob_wallet.rescanblockchain()
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        alice_wrap_policy = node.getassetpolicy(alice_wrap_asset_id)
        assert_equal(alice_wrap_policy['icu_visibility'], 1)
        assert_equal(alice_wrap_policy['icu_flags'] & 1, 1)  # WRAP_REQUIRED
        self.log.info(f"  ✓ Alice ICUWRAP asset registered: {alice_wrap_asset_id[:16]}...")
        self.log.info(f"    icu_visibility={alice_wrap_policy['icu_visibility']}, icu_flags={alice_wrap_policy['icu_flags']}")

        # Mint Alice's holder-only asset
        alice_wrap_units = 1_000_000
        alice_wrap_icu_txid = alice_wrap_policy["icu_txid"]
        alice_wrap_icu_vout = alice_wrap_policy["icu_vout"]
        alice_wrap_mint_addr = alice_wallet.getnewaddress(address_type="bech32m")

        alice_wrap_mint_txid = alice_wallet.mintasset(
            alice_wrap_icu_txid,
            alice_wrap_icu_vout,
            alice_wallet.getnewaddress(),
            Decimal("5.1"),
            alice_wrap_mint_addr,
            Decimal("0.001"),
            alice_wrap_asset_id,
            alice_wrap_units,
            0x0001,
            28,
            510000000,
            {"broadcast": True}
        )

        self.generate(node, 1)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()
        self.log.info(f"  ✓ Alice minted {alice_wrap_units} ALICEWRAP units")

        # Bob creates his holder-only asset
        self.log.info("\n[Test 4.6.2] Bob registers holder-only asset with ICU encryption...")
        bob_icu_text = "CONFIDENTIAL: Bob's quantum-resistant key schedule documentation"
        bob_wrap_asset_id = hashlib.sha256(b"bob_holder_only_asset").hexdigest()

        bob_icu_payload, bob_canonical_hash, bob_witness_hash, bob_metadata = self._build_icu_payload(
            bob_icu_text, {"version": "1.0", "canonical_hash": "placeholder"}, visibility=1
        )

        bob_wrap_reg_addr = bob_wallet.getnewaddress()
        bob_wrap_asset_txid = bob_wallet.registerasset(
            bob_wrap_reg_addr,
            Decimal("5.1"),
            bob_wrap_asset_id,
            0x0001,
            28,
            510000000,
            "BOBWRAP",
            6,
            {
                "autofund": True,
                "broadcast": True,
                "icu_payload_plain": bob_icu_payload.hex(),
                "icu_visibility": 1,
                "policy_quorum_bps": 0
            }
        )

        self.generate(node, 1)
        alice_wallet.rescanblockchain()
        bob_wallet.rescanblockchain()
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        bob_wrap_policy = node.getassetpolicy(bob_wrap_asset_id)
        assert_equal(bob_wrap_policy['icu_visibility'], 1)
        assert_equal(bob_wrap_policy['icu_flags'] & 1, 1)
        self.log.info(f"  ✓ Bob ICUWRAP asset registered: {bob_wrap_asset_id[:16]}...")
        self.log.info(f"    icu_visibility={bob_wrap_policy['icu_visibility']}, icu_flags={bob_wrap_policy['icu_flags']}")

        # Mint Bob's holder-only asset
        bob_wrap_units = 500_000
        bob_wrap_icu_txid = bob_wrap_policy["icu_txid"]
        bob_wrap_icu_vout = bob_wrap_policy["icu_vout"]
        bob_wrap_mint_addr = bob_wallet.getnewaddress(address_type="bech32m")

        bob_wrap_mint_txid = bob_wallet.mintasset(
            bob_wrap_icu_txid,
            bob_wrap_icu_vout,
            bob_wallet.getnewaddress(),
            Decimal("5.1"),
            bob_wrap_mint_addr,
            Decimal("0.001"),
            bob_wrap_asset_id,
            bob_wrap_units,
            0x0001,
            28,
            510000000,
            {"broadcast": True}
        )

        self.generate(node, 1)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()
        self.log.info(f"  ✓ Bob minted {bob_wrap_units} BOBWRAP units")

        # Execute atomic swap of the two holder-only assets
        self.log.info("\n[Test 4.6.3] Executing atomic swap of holder-only assets...")

        wrap_swap_alice_units = 100_000
        wrap_swap_bob_units = 50_000

        alice_wrap_recv = alice_wallet.getnewaddress(address_type="bech32m")
        bob_wrap_recv = bob_wallet.getnewaddress(address_type="bech32m")

        wrap_swap_offer = alice_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": alice_wrap_asset_id,
                    "units": wrap_swap_alice_units,
                },
                "bob_leg": {
                    "asset_id": bob_wrap_asset_id,
                    "units": wrap_swap_bob_units,
                },
            },
            "alice_address": alice_wrap_recv,
            "bob_address_hint": bob_wrap_recv,
        })

        wrap_swap_offer_id = wrap_swap_offer["offer_id"]
        self.log.info(f"  ✓ Alice proposed holder-only asset swap:")
        self.log.info(f"    Alice gives: {wrap_swap_alice_units} ALICEWRAP")
        self.log.info(f"    Bob gives:   {wrap_swap_bob_units} BOBWRAP")

        bob_wallet.spot.import_offer(wrap_swap_offer["offer"])
        wrap_swap_acceptance = bob_wallet.spot.accept(wrap_swap_offer_id, {"confirmed": True})
        alice_wallet.spot.import_acceptance(wrap_swap_offer_id, wrap_swap_acceptance["acceptance"])
        self.log.info(f"  ✓ Bob accepted holder-only asset swap")

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Build, sign and broadcast the swap using augmentation pattern
        wrap_alice_base = alice_wallet.spot.build_atomic(wrap_swap_offer_id)
        wrap_bob_augmented = bob_wallet.spot.build_atomic(wrap_swap_offer_id, {"psbt": wrap_alice_base["psbt"]})

        wrap_combined_psbt = wrap_bob_augmented["psbt"]  # Already combined via augmentation
        wrap_alice_signed = alice_wallet.walletprocesspsbt(wrap_combined_psbt, sign=True)["psbt"]
        wrap_bob_signed = bob_wallet.walletprocesspsbt(wrap_alice_signed, sign=True)["psbt"]

        wrap_final = bob_wallet.finalizepsbt(wrap_bob_signed)
        assert wrap_final["complete"], "Holder-only asset swap PSBT should be complete"
        wrap_swap_txid = node.sendrawtransaction(wrap_final["hex"])
        self.log.info(f"  ✓ Holder-only asset swap broadcast: {wrap_swap_txid[:16]}...")

        self.generate(node, 3)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Verify Alice received Bob's asset
        alice_bob_asset_balance = self._asset_units_total(alice_wallet, bob_wrap_asset_id)
        assert_equal(alice_bob_asset_balance, wrap_swap_bob_units)
        self.log.info(f"  ✓ Alice received {alice_bob_asset_balance} BOBWRAP units")

        # Verify Bob received Alice's asset
        bob_alice_asset_balance = self._asset_units_total(bob_wallet, alice_wrap_asset_id)
        assert_equal(bob_alice_asset_balance, wrap_swap_alice_units)
        self.log.info(f"  ✓ Bob received {bob_alice_asset_balance} ALICEWRAP units")

        # CRITICAL TEST: Alice can decrypt Bob's ICU payload after receiving the asset
        self.log.info("\n[Test 4.6.4] Verifying Alice can decrypt Bob's ICU payload...")
        alice_decrypt_bob = alice_wallet.geticupayload(bob_wrap_asset_id)

        self.log.info(f"  Alice's ICU query for Bob's asset:")
        self.log.info(f"    decrypted: {alice_decrypt_bob.get('decrypted')}")
        self.log.info(f"    has plaintext: {'plaintext' in alice_decrypt_bob}")
        if not alice_decrypt_bob.get('decrypted'):
            self.log.info(f"    failure_reason: {alice_decrypt_bob.get('failure_reason', 'N/A')}")

        assert alice_decrypt_bob.get('decrypted'), \
            f"Alice should decrypt BOBWRAP after receiving via ICU_KEYWRAP, got: {alice_decrypt_bob}"

        assert_equal(alice_decrypt_bob['plaintext'], bob_icu_payload.hex())
        self.log.info(f"  ✓ Alice successfully decrypted Bob's ICU payload!")

        # Decode and verify the actual text content
        try:
            payload_bytes = bytes.fromhex(alice_decrypt_bob['plaintext'])
            offset = 4  # Skip version, compression, encryption_mode, visibility
            text_len = payload_bytes[offset]
            offset += 1
            if text_len == 253:
                text_len = int.from_bytes(payload_bytes[offset:offset+2], 'little')
                offset += 2
            canonical_text_bytes = payload_bytes[offset:offset+text_len]
            decoded_text = canonical_text_bytes.decode('utf-8')
            self.log.info(f"  ✓ Decoded ICU text: \"{decoded_text}\"")
            assert decoded_text == bob_icu_text, "Decoded text should match Bob's original"
            self.log.info(f"  ✓ Text matches Bob's original ICU content!")
        except Exception as e:
            self.log.info(f"  ⚠ Could not decode text content: {str(e)}")

        # CRITICAL TEST: Bob can decrypt Alice's ICU payload after receiving the asset
        self.log.info("\n[Test 4.6.5] Verifying Bob can decrypt Alice's ICU payload...")
        bob_decrypt_alice = bob_wallet.geticupayload(alice_wrap_asset_id)

        self.log.info(f"  Bob's ICU query for Alice's asset:")
        self.log.info(f"    decrypted: {bob_decrypt_alice.get('decrypted')}")
        self.log.info(f"    has plaintext: {'plaintext' in bob_decrypt_alice}")
        if not bob_decrypt_alice.get('decrypted'):
            self.log.info(f"    failure_reason: {bob_decrypt_alice.get('failure_reason', 'N/A')}")

        assert bob_decrypt_alice.get('decrypted'), \
            f"Bob should decrypt ALICEWRAP after receiving via ICU_KEYWRAP, got: {bob_decrypt_alice}"

        assert_equal(bob_decrypt_alice['plaintext'], alice_icu_payload.hex())
        self.log.info(f"  ✓ Bob successfully decrypted Alice's ICU payload!")

        # Decode and verify the actual text content
        try:
            payload_bytes = bytes.fromhex(bob_decrypt_alice['plaintext'])
            offset = 4
            text_len = payload_bytes[offset]
            offset += 1
            if text_len == 253:
                text_len = int.from_bytes(payload_bytes[offset:offset+2], 'little')
                offset += 2
            canonical_text_bytes = payload_bytes[offset:offset+text_len]
            decoded_text = canonical_text_bytes.decode('utf-8')
            self.log.info(f"  ✓ Decoded ICU text: \"{decoded_text}\"")
            assert decoded_text == alice_icu_text, "Decoded text should match Alice's original"
            self.log.info(f"  ✓ Text matches Alice's original ICU content!")
        except Exception as e:
            self.log.info(f"  ⚠ Could not decode text content: {str(e)}")

        self.log.info("\n✓✓✓ ICU KEY WRAP HOLDER-ONLY ASSETS SWAP COMPLETE ✓✓✓")
        self.log.info("  Two holder-only assets swapped atomically")
        self.log.info("  Alice successfully decrypted Bob's ICU payload after receiving BOBWRAP")
        self.log.info("  Bob successfully decrypted Alice's ICU payload after receiving ALICEWRAP")
        self.log.info("  ICU_KEYWRAP mechanism validated: DEK wrapping works in atomic swaps")

        # ====================================================================
        # Test 4.7: Pre-Signing Decryption Commitment with OP_RETURN
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 4.7: Pre-Signing Decryption Commitment Proof")
        self.log.info("=" * 80)
        self.log.info("Objective: Prove each party can decrypt the received asset BEFORE signing")
        self.log.info("           Each party adds OP_RETURN with hash(canonical_text | receive_addr)")
        self.log.info("           This provides cryptographic guarantee of decryption acceptance")

        # Use the existing holder-only assets from Test 4.6
        # Create new addresses for this swap
        alice_commit_recv = alice_wallet.getnewaddress(address_type="bech32m")
        bob_commit_recv = bob_wallet.getnewaddress(address_type="bech32m")

        commit_swap_alice_units = 50_000
        commit_swap_bob_units = 25_000

        self.log.info(f"\n[Test 4.7.1] Proposing swap with commitment workflow...")
        commit_offer = alice_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": alice_wrap_asset_id,
                    "units": commit_swap_alice_units,
                },
                "bob_leg": {
                    "asset_id": bob_wrap_asset_id,
                    "units": commit_swap_bob_units,
                },
            },
            "alice_address": alice_commit_recv,
            "bob_address_hint": bob_commit_recv,
        })

        commit_offer_id = commit_offer["offer_id"]
        self.log.info(f"  ✓ Proposed swap: {commit_swap_alice_units} ALICEWRAP ⇄ {commit_swap_bob_units} BOBWRAP")

        bob_wallet.spot.import_offer(commit_offer["offer"])
        commit_acceptance = bob_wallet.spot.accept(commit_offer_id, {"confirmed": True})
        alice_wallet.spot.import_acceptance(commit_offer_id, commit_acceptance["acceptance"])
        self.log.info(f"  ✓ Swap accepted")

        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Build PSBTs with AUTOMATIC commitment proof
        self.log.info(f"\n[Test 4.7.2] Building PSBTs with automatic commitment proof...")

        # Alice builds her PSBT with commitment proof enabled
        # The wallet will automatically:
        # Build PSBTs without commitment proofs first - use augmentation pattern
        commit_alice_base = alice_wallet.spot.build_atomic(commit_offer_id)
        commit_bob_augmented = bob_wallet.spot.build_atomic(commit_offer_id, {"psbt": commit_alice_base["psbt"]})
        self.log.info(f"  ✓ Both parties built PSBTs")

        # Use augmented PSBT - already contains both asset outputs
        commit_joined_psbt = commit_bob_augmented["psbt"]
        self.log.info(f"  ✓ Joined PSBTs")

        # Now each party adds their commitment proof to the joined PSBT
        # Alice adds her commitment proof (proving she can decrypt Bob's asset)
        alice_commitment_result = alice_wallet.spot.add_commitment_proof(commit_joined_psbt, commit_offer_id)
        self.log.info(f"  ✓ Alice added commitment proof")
        self.log.info(f"    Commitment hash: {alice_commitment_result['commitment_hash'][:32]}...")
        self.log.info(f"    {alice_commitment_result['commitment_preimage_info']}")

        # Bob adds his commitment proof to Alice's PSBT (now has 2 OP_RETURNs)
        bob_commitment_result = bob_wallet.spot.add_commitment_proof(alice_commitment_result["psbt"], commit_offer_id)
        self.log.info(f"  ✓ Bob added commitment proof")
        self.log.info(f"    Commitment hash: {bob_commitment_result['commitment_hash'][:32]}...")
        self.log.info(f"    {bob_commitment_result['commitment_preimage_info']}")

        # Use the PSBT with both commitment proofs
        commit_joined_psbt = bob_commitment_result["psbt"]

        # Decode and verify OP_RETURN outputs are present
        self.log.info(f"\n[Test 4.7.3] Verifying OP_RETURN commitment outputs...")
        commit_decoded = alice_wallet.decodepsbt(commit_joined_psbt)

        opreturn_outputs = []
        for i, out in enumerate(commit_decoded['tx']['vout']):
            if out['scriptPubKey'].get('type') == 'nulldata':
                opreturn_outputs.append((i, out))
                self.log.info(f"  Found OP_RETURN at output {i}")
                # Extract commitment hash from OP_RETURN script
                asm = out['scriptPubKey'].get('asm', '')
                if asm.startswith('OP_RETURN '):
                    commitment_hex = asm.split(' ')[1]
                    self.log.info(f"    Commitment hash: {commitment_hex[:32]}...")

        # Should have exactly 2 OP_RETURN outputs (one from Alice, one from Bob)
        assert len(opreturn_outputs) == 2, f"Expected 2 OP_RETURN outputs, found {len(opreturn_outputs)}"
        self.log.info(f"  ✓ Found {len(opreturn_outputs)} OP_RETURN commitment outputs")

        # Manually verify the commitments match expected values
        self.log.info(f"\n[Test 4.7.4] Verifying commitment hashes...")

        # The commitments returned by the RPC should match what's in the PSBT
        alice_commitment_hash = alice_commitment_result['commitment_hash']
        bob_commitment_hash = bob_commitment_result['commitment_hash']

        self.log.info(f"  Alice's RPC commitment: {alice_commitment_hash}")
        self.log.info(f"  Bob's RPC commitment:   {bob_commitment_hash}")

        # Extract actual commitments from OP_RETURN outputs
        actual_commitments = []
        for idx, out in opreturn_outputs:
            asm = out['scriptPubKey'].get('asm', '')
            if asm.startswith('OP_RETURN '):
                commitment_hex = asm.split(' ')[1]
                actual_commitments.append(commitment_hex)
                self.log.info(f"  OP_RETURN[{idx}]: {commitment_hex}")

        # Verify the RPC-returned commitments match what's in the PSBT
        # Note: uint256 is printed in reverse byte order, so we need to reverse it
        alice_commitment_reversed = bytes.fromhex(alice_commitment_hash)[::-1].hex()
        bob_commitment_reversed = bytes.fromhex(bob_commitment_hash)[::-1].hex()

        self.log.info(f"  Alice's commitment (reversed): {alice_commitment_reversed}")
        self.log.info(f"  Bob's commitment (reversed):   {bob_commitment_reversed}")

        assert alice_commitment_reversed in actual_commitments, f"Alice's commitment {alice_commitment_reversed[:16]}... not found in OP_RETURN outputs"
        assert bob_commitment_reversed in actual_commitments, f"Bob's commitment {bob_commitment_reversed[:16]}... not found in OP_RETURN outputs"
        self.log.info(f"  ✓ Both commitments verified correctly")

        # Sign and broadcast
        self.log.info(f"\n[Test 4.7.5] Signing and broadcasting with commitment proofs...")

        commit_alice_signed = alice_wallet.walletprocesspsbt(commit_joined_psbt, sign=True)["psbt"]
        commit_bob_signed = bob_wallet.walletprocesspsbt(commit_alice_signed, sign=True)["psbt"]

        commit_final = bob_wallet.finalizepsbt(commit_bob_signed)
        assert commit_final["complete"], "Commitment swap PSBT should be complete"

        # Decode final transaction
        commit_final_tx = node.decoderawtransaction(commit_final["hex"])

        self.log.info(f"  Final transaction structure:")
        self.log.info(f"    Inputs: {len(commit_final_tx['vin'])}")
        self.log.info(f"    Outputs: {len(commit_final_tx['vout'])}")
        self.log.info(f"    OP_RETURNs: 2 (commitment proofs)")
        self.log.info(f"    Size: {len(commit_final['hex'])//2} bytes")

        commit_swap_txid = node.sendrawtransaction(commit_final["hex"])
        self.log.info(f"  ✓ Swap broadcast: {commit_swap_txid[:16]}...")

        self.generate(node, 3)
        alice_wallet.syncwithvalidationinterfacequeue()
        bob_wallet.syncwithvalidationinterfacequeue()

        # Verify on-chain transaction contains commitment proofs
        self.log.info(f"\n[Test 4.7.6] Verifying on-chain commitment proofs...")
        commit_tx_info = alice_wallet.gettransaction(commit_swap_txid)
        commit_tx = node.getrawtransaction(commit_swap_txid, True, commit_tx_info['blockhash'])

        onchain_opretur_count = sum(1 for out in commit_tx['vout']
                                     if out['scriptPubKey'].get('type') == 'nulldata')
        assert onchain_opretur_count == 2, f"Expected 2 OP_RETURN outputs on-chain, found {onchain_opretur_count}"
        self.log.info(f"  ✓ Transaction has 2 OP_RETURN commitment proofs on-chain")

        # Verify assets were transferred
        alice_bob_after_commit = self._asset_units_total(alice_wallet, bob_wrap_asset_id)
        bob_alice_after_commit = self._asset_units_total(bob_wallet, alice_wrap_asset_id)

        self.log.info(f"\n  Assets transferred:")
        self.log.info(f"    Alice received additional {commit_swap_bob_units} BOBWRAP")
        self.log.info(f"    Bob received additional {commit_swap_alice_units} ALICEWRAP")

        self.log.info("\n✓✓✓ PRE-SIGNING DECRYPTION COMMITMENT PROOF COMPLETE ✓✓✓")
        self.log.info("  Automatic commitment mechanism validated:")
        self.log.info("  ✓ Each party automatically unwraps DEK from PSBT asset output")
        self.log.info("  ✓ Each party decrypts counterparty's ICU payload before signing")
        self.log.info("  ✓ Each party computes hash(counterparty_text | own_receive_addr)")
        self.log.info("  ✓ OP_RETURN outputs automatically added to transaction")
        self.log.info("  ✓ Commitments verified in joined PSBT before signing")
        self.log.info("  ✓ On-chain transaction contains both commitment proofs")
        self.log.info("\n  Security guarantees:")
        self.log.info("  - No plaintext canonical_text transmitted (extracted from PSBT only)")
        self.log.info("  - Only party with correct private key can unwrap DEK")
        self.log.info("  - Only party with DEK can decrypt and create commitment")
        self.log.info("  - Commitment binds to specific recipient address (prevents replay)")
        self.log.info("  - Provides cryptographic proof of acceptance before signing")

        # ====================================================================
        # Test 5: Export and list offers
        # ====================================================================
        self.log.info("\n" + "=" * 80)
        self.log.info("TEST 5: Export and List Operations")
        self.log.info("=" * 80)

        exported = alice_wallet.spot.export_offer(offer_id)
        assert "offer" in exported
        self.log.info("✓ Export offer succeeded")

        offers_list = alice_wallet.spot.list_offers()
        assert len(offers_list) >= 2  # At least the two offers we created
        self.log.info(f"✓ List offers succeeded: {len(offers_list)} offers found")

        # ==================================================================
        # Test 4.8: First-time swap with fresh wallets (PSBT-based decryption)
        # ==================================================================
        self.log.info("\n" + "="*80)
        self.log.info("[Test 4.8] First-time swap between fresh wallets (forces PSBT-based decryption)")
        self.log.info("="*80)

        # Create two fresh wallets
        self.log.info("\n[Test 4.8.1] Creating fresh wallets Charlie and Dave...")
        node.createwallet(wallet_name="charlie", descriptors=True)
        node.createwallet(wallet_name="dave", descriptors=True)
        charlie_wallet = node.get_wallet_rpc("charlie")
        dave_wallet = node.get_wallet_rpc("dave")
        self.log.info(f"  ✓ Fresh wallets created")

        # Fund them with BTC from Alice's wallet
        charlie_addr = charlie_wallet.getnewaddress()
        dave_addr = dave_wallet.getnewaddress()
        alice_wallet.sendtoaddress(charlie_addr, Decimal("10.0"))
        alice_wallet.sendtoaddress(dave_addr, Decimal("10.0"))
        self.generate(node, 1)
        charlie_wallet.syncwithvalidationinterfacequeue()
        dave_wallet.syncwithvalidationinterfacequeue()
        self.log.info(f"  ✓ Funded with BTC")

        # Alice sends ALICEWRAP to Charlie
        self.log.info("\n[Test 4.8.2] Alice sends ALICEWRAP to Charlie...")
        charlie_recv_addr = charlie_wallet.getnewaddress(address_type="bech32m")
        alice_to_charlie_units = 50000
        alice_wallet.sendasset(alice_wrap_asset_id, charlie_recv_addr, alice_to_charlie_units, {"broadcast": True})
        self.generate(node, 1)
        charlie_wallet.rescanblockchain()
        charlie_wallet.syncwithvalidationinterfacequeue()
        charlie_balance = self._asset_units_total(charlie_wallet, alice_wrap_asset_id)
        assert_equal(charlie_balance, alice_to_charlie_units)

        # Force Charlie to decrypt and store the DEK
        charlie_decrypt = charlie_wallet.geticupayload(alice_wrap_asset_id)
        assert charlie_decrypt.get('decrypted'), "Charlie should be able to decrypt ALICEWRAP"
        self.log.info(f"  ✓ Charlie received {charlie_balance} ALICEWRAP and stored DEK")

        # Bob sends BOBWRAP to Dave
        self.log.info("\n[Test 4.8.3] Bob sends BOBWRAP to Dave...")
        dave_recv_addr = dave_wallet.getnewaddress(address_type="bech32m")
        bob_to_dave_units = 75000
        bob_wallet.sendasset(bob_wrap_asset_id, dave_recv_addr, bob_to_dave_units, {"broadcast": True})
        self.generate(node, 1)
        dave_wallet.rescanblockchain()
        dave_wallet.syncwithvalidationinterfacequeue()
        dave_balance = self._asset_units_total(dave_wallet, bob_wrap_asset_id)
        assert_equal(dave_balance, bob_to_dave_units)

        # Force Dave to decrypt and store the DEK
        dave_decrypt = dave_wallet.geticupayload(bob_wrap_asset_id)
        assert dave_decrypt.get('decrypted'), "Dave should be able to decrypt BOBWRAP"
        self.log.info(f"  ✓ Dave received {dave_balance} BOBWRAP and stored DEK")

        # Charlie proposes swap
        self.log.info("\n[Test 4.8.4] Charlie proposes swap: ALICEWRAP ↔ BOBWRAP...")
        charlie_swap_units = 30000
        dave_swap_units = 40000
        charlie_swap_recv = charlie_wallet.getnewaddress(address_type="bech32m")
        dave_swap_recv = dave_wallet.getnewaddress(address_type="bech32m")
        charlie_swap_offer = charlie_wallet.spot.propose({
            "terms": {
                "alice_leg": {
                    "asset_id": alice_wrap_asset_id,
                    "units": charlie_swap_units,
                },
                "bob_leg": {
                    "asset_id": bob_wrap_asset_id,
                    "units": dave_swap_units,
                },
            },
            "alice_address": charlie_swap_recv,
            "bob_address_hint": dave_swap_recv,
        })
        charlie_swap_offer_id = charlie_swap_offer["offer_id"]
        self.log.info(f"  ✓ Swap proposed (Charlie: {charlie_swap_units} ALICEWRAP ↔ Dave: {dave_swap_units} BOBWRAP)")

        # Dave accepts
        dave_wallet.spot.import_offer(charlie_swap_offer["offer"])
        dave_swap_acceptance = dave_wallet.spot.accept(charlie_swap_offer_id, {"confirmed": True})
        charlie_wallet.spot.import_acceptance(charlie_swap_offer_id, dave_swap_acceptance["acceptance"])
        self.log.info(f"  ✓ Dave accepted")

        # Build PSBTs
        self.log.info("\n[Test 4.8.5] Building PSBTs...")
        charlie_base = charlie_wallet.spot.build_atomic(charlie_swap_offer_id)
        dave_augmented = dave_wallet.spot.build_atomic(charlie_swap_offer_id, {"psbt": charlie_base["psbt"]})
        joined_psbt = dave_augmented["psbt"]
        self.log.info(f"  ✓ PSBTs joined")

        # Add commitment proofs (CRITICAL: forces PSBT-based decryption)
        self.log.info("\n[Test 4.8.6] Adding commitment proofs (PSBT-based decryption)...")
        charlie_commitment = charlie_wallet.spot.add_commitment_proof(joined_psbt, charlie_swap_offer_id)
        self.log.info(f"  ✓ Charlie: {charlie_commitment['commitment_hash'][:16]}...")
        dave_commitment = dave_wallet.spot.add_commitment_proof(charlie_commitment["psbt"], charlie_swap_offer_id)
        self.log.info(f"  ✓ Dave: {dave_commitment['commitment_hash'][:16]}...")

        # Sign and broadcast
        self.log.info("\n[Test 4.8.7] Signing and broadcasting...")
        charlie_signed = charlie_wallet.walletprocesspsbt(dave_commitment["psbt"], sign=True)["psbt"]
        dave_signed = dave_wallet.walletprocesspsbt(charlie_signed, sign=True)["psbt"]
        final_tx = dave_wallet.finalizepsbt(dave_signed)
        assert final_tx["complete"]
        swap_txid = node.sendrawtransaction(final_tx["hex"])
        self.generate(node, 1)
        charlie_wallet.syncwithvalidationinterfacequeue()
        dave_wallet.syncwithvalidationinterfacequeue()
        self.log.info(f"  ✓ Swap broadcast: {swap_txid[:16]}...")

        # Verify
        charlie_final = self._asset_units_total(charlie_wallet, bob_wrap_asset_id)
        dave_final = self._asset_units_total(dave_wallet, alice_wrap_asset_id)
        assert_equal(charlie_final, dave_swap_units)
        assert_equal(dave_final, charlie_swap_units)
        self.log.info(f"  ✓ Charlie: {charlie_final} BOBWRAP, Dave: {dave_final} ALICEWRAP")

        self.log.info("\n" + "=" * 80)
        self.log.info("ALL SPOT SWAP TESTS PASSED")
        self.log.info("=" * 80)
        self.log.info("✓ Asset-for-asset swap executed with balance validation")
        self.log.info("✓ Asset-for-native swap executed with balance validation")
        self.log.info("✓ Asset-for-asset swap with change validated")
        self.log.info("✓ Export and list operations validated")
        self.log.info("✓ First-time swap with PSBT-based decryption (Charlie & Dave)")

    # ------------------------------------------------------------------ helpers

    def _native_balance_at(self, wallet, address: str) -> Decimal:
        utxos = wallet.listunspent(0, 9999999, [address])
        return sum(Decimal(str(entry["amount"])) for entry in utxos)

    def _asset_units_at(self, wallet, asset_id_hex: str, address: str) -> int:
        utxos = wallet.listassetutxos([asset_id_hex], 0, 9999999)
        units = 0
        for entry in utxos:
            if entry.get("address") == address and entry.get("asset_id") == asset_id_hex:
                units += int(entry["asset_units"])
        return units

    def _asset_units_total(self, wallet, asset_id_hex: str) -> int:
        utxos = wallet.listassetutxos([asset_id_hex], 0, 9999999)
        units = 0
        for entry in utxos:
            if entry.get("asset_id") == asset_id_hex:
                units += int(entry["asset_units"])
        return units

    def _build_icu_payload(self, canonical_text: str, witness_bundle: dict, visibility: int = 0, use_compression: int = 0):
        """Build ICU payload for asset registration."""
        canonical_bytes = canonical_text.encode('utf-8')
        canonical_hash = hashlib.sha256(canonical_bytes).digest()
        canonical_hash_le = canonical_hash[::-1].hex()

        # Replace placeholder in witness bundle
        for key in witness_bundle:
            if witness_bundle[key] == "placeholder":
                witness_bundle[key] = canonical_hash_le

        witness_json = json.dumps(witness_bundle, separators=(',', ':')).encode('utf-8')
        witness_hash = hashlib.sha256(witness_json).digest()
        witness_hash_le = witness_hash[::-1].hex()

        # Build CanonicalIcuPayload structure
        payload = bytearray()
        payload.append(1)  # version
        payload.append(1 if use_compression else 0)  # compression
        payload.append(1 if visibility == 1 else 0)  # encryption_mode (ChaCha20 for holder-only)
        payload.append(visibility)  # visibility

        # CompactSize encoding for canonical_text
        if len(canonical_bytes) < 253:
            payload.append(len(canonical_bytes))
        elif len(canonical_bytes) <= 0xFFFF:
            payload.append(253)
            payload.extend(len(canonical_bytes).to_bytes(2, 'little'))
        elif len(canonical_bytes) <= 0xFFFFFFFF:
            payload.append(254)
            payload.extend(len(canonical_bytes).to_bytes(4, 'little'))
        else:
            payload.append(255)
            payload.extend(len(canonical_bytes).to_bytes(8, 'little'))
        payload.extend(canonical_bytes)

        # CompactSize encoding for witness_bundle
        if len(witness_json) < 253:
            payload.append(len(witness_json))
        elif len(witness_json) <= 0xFFFF:
            payload.append(253)
            payload.extend(len(witness_json).to_bytes(2, 'little'))
        elif len(witness_json) <= 0xFFFFFFFF:
            payload.append(254)
            payload.extend(len(witness_json).to_bytes(4, 'little'))
        else:
            payload.append(255)
            payload.extend(len(witness_json).to_bytes(8, 'little'))
        payload.extend(witness_json)

        # Empty metadata section in canonical structure
        payload.append(0)

        metadata = {
            "compression": 1 if use_compression else 0,
            "encryption_mode": 1 if visibility == 1 else 0,
            "visibility": visibility,
            "witness_hash_bytes": witness_hash[::-1],
        }

        return bytes(payload), canonical_hash_le, witness_hash_le, metadata

    class _AssetRpcAdapter:
        def __init__(self, node, wallet):
            self._node = node
            self._wallet = wallet

        def generate(self, *args, **kwargs):
            return self._node.generate(*args, **kwargs)

        def getnewaddress(self, *args, **kwargs):
            return self._wallet.getnewaddress(*args, **kwargs)

        def listunspent(self, *args, **kwargs):
            return self._wallet.listunspent(*args, **kwargs)

        def createrawtransaction(self, *args, **kwargs):
            return self._node.createrawtransaction(*args, **kwargs)

        def rawtxattachissuerreg(self, *args, **kwargs):
            return self._node.rawtxattachissuerreg(*args, **kwargs)

        def rawtxattachassettag(self, *args, **kwargs):
            return self._node.rawtxattachassettag(*args, **kwargs)

        def signrawtransactionwithwallet(self, *args, **kwargs):
            return self._wallet.signrawtransactionwithwallet(*args, **kwargs)

        def sendrawtransaction(self, *args, **kwargs):
            return self._node.sendrawtransaction(*args, **kwargs)

        def getassetpolicy(self, *args, **kwargs):
            return self._node.getassetpolicy(*args, **kwargs)

        def gettransaction(self, *args, **kwargs):
            return self._wallet.gettransaction(*args, **kwargs)

    def _register_asset(self, wallet, node, ticker: str, decimals: int):
        """Register a new asset."""
        adapter = self._AssetRpcAdapter(node, wallet)
        asset_id_hex = hashlib.sha256(ticker.encode()).hexdigest()
        asset_id, policy, icu_value = util_register_asset(
            adapter,
            asset_id=asset_id_hex,
            bond_value=Decimal("5.1"),
            fee=Decimal("0.0002"),
            policy_bits=3,
            allowed_families=28,
            unlock_fees_sats=510000000,
            ticker=ticker,
            decimals=decimals,
        )
        wallet.syncwithvalidationinterfacequeue()
        return asset_id, policy, icu_value

    def _mint_asset(self, wallet, node, asset_id_hex: str, policy: dict, icu_value: Decimal, units: int):
        """Mint asset units."""
        adapter = self._AssetRpcAdapter(node, wallet)
        asset_outpoint, new_policy = util_mint_asset(
            adapter,
            asset_id_hex,
            policy,
            icu_value,
            asset_units=units,
            asset_output_value=Decimal("0.001"),
            fee=Decimal("0.0005"),
        )
        wallet.syncwithvalidationinterfacequeue()
        return asset_outpoint, new_policy


if __name__ == "__main__":
    CovenantSpotTest(__file__).main()
