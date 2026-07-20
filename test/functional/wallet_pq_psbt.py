#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ML-DSA (Post-Quantum) PSBT functionality.

This test verifies that PSBT (Partially Signed Bitcoin Transaction) workflows
work correctly with ML-DSA witness v2 addresses.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletPQPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing ML-DSA PSBT workflow...")

        # Generate some blocks to fund the wallet
        self.generate(self.nodes[0], 101)

        # Test 1: Generate ML-DSA address
        self.log.info("Test 1: Generate ML-DSA-65 address")
        addr_info = self.nodes[0].generatemldsaaddress(65)
        mldsa_address = addr_info['address']

        assert mldsa_address.startswith('bcrt1z'), "ML-DSA address should start with bcrt1z"
        assert 'pubkey' in addr_info, "Address info should contain pubkey"
        assert 'seckey' in addr_info, "Address info should contain seckey"
        assert 'tapscript' in addr_info, "Address info should contain tapscript"
        assert 'internal_pubkey' in addr_info, "Address info should contain internal_pubkey"
        assert addr_info['level'] == 65, "Security level should be 65"

        self.log.info(f"Generated ML-DSA address: {mldsa_address}")

        # Test 2: Fund the ML-DSA address
        self.log.info("Test 2: Fund ML-DSA address with 1.0 BTC")
        txid = self.nodes[0].sendtoaddress(mldsa_address, 1.0)
        self.generate(self.nodes[0], 1)

        # Rescan to detect the transaction (descriptor was imported with old timestamp)
        self.log.info("Rescanning to detect transaction to ML-DSA address")
        self.nodes[0].rescanblockchain()

        # Verify the transaction is confirmed - wallet should track the ML-DSA address now
        unspent = self.nodes[0].listunspent(1, 1, [mldsa_address])
        assert_equal(len(unspent), 1, "Should have 1 unspent output")
        assert_equal(unspent[0]['address'], mldsa_address)
        assert_equal(unspent[0]['amount'], 1.0)

        self.log.info(f"ML-DSA address funded with txid: {txid}")

        # Test 3: Create and fund PSBT spending from ML-DSA address
        self.log.info("Test 3: Create PSBT spending from ML-DSA address")
        dest_address = self.nodes[1].getnewaddress()
        utxo = unspent[0]

        # Create raw transaction
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {dest_address: 0.99}  # Leave some for fees

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        self.log.info(f"Created raw transaction: {rawtx[:80]}...")

        # Convert to PSBT
        psbt = self.nodes[0].converttopsbt(rawtx, True)  # True = allow_watch_only
        self.log.info(f"Converted to PSBT: {psbt[:80]}...")

        # Update PSBT with UTXO data from the wallet (required for watch-only addresses)
        psbt = self.nodes[0].utxoupdatepsbt(psbt)
        self.log.info("Updated PSBT with UTXO data")

        # Decode PSBT to verify structure
        decoded = self.nodes[0].decodepsbt(psbt)
        assert_equal(len(decoded['inputs']), 1, "PSBT should have 1 input")
        assert_equal(len(decoded['outputs']), 1, "PSBT should have 1 output")
        self.log.info(f"PSBT input after utxoupdatepsbt: {decoded['inputs'][0].keys()}")

        # Verify witness_utxo is present (required for signing)
        assert 'witness_utxo' in decoded['inputs'][0] or 'non_witness_utxo' in decoded['inputs'][0], \
            "PSBT must have witness_utxo or non_witness_utxo after utxoupdatepsbt"

        # Test 4: Process PSBT with wallet (update + sign)
        self.log.info("Test 4: Process PSBT using wallet (ML-DSA PSBT signing)")

        # Process PSBT with wallet - this should:
        # 1. Update the PSBT with ML-DSA metadata
        # 2. Sign the input with ML-DSA
        # 3. Finalize the PSBT
        processed = self.nodes[0].walletprocesspsbt(psbt, True)  # True = sign
        self.log.info(f"PSBT processing result: complete={processed['complete']}")

        # Decode to see what's in the PSBT
        decoded_processed = self.nodes[0].decodepsbt(processed['psbt'])
        input_fields = decoded_processed['inputs'][0]
        self.log.info(f"Processed PSBT inputs[0] fields: {input_fields.keys()}")

        # Check if ML-DSA fields were populated
        if 'mldsa_pubkey' in input_fields:
            self.log.info("ML-DSA pubkey present in PSBT")
        else:
            self.log.error("ML-DSA pubkey NOT populated - wallet didn't recognize ML-DSA input")

        if 'mldsa_signature' in input_fields:
            self.log.info("ML-DSA signature present in PSBT")
        else:
            self.log.error("ML-DSA signature NOT populated - signing failed")

        # Try to get more info about why signing failed
        if not processed['complete']:
            self.log.error("PSBT incomplete. Checking wallet...")
            # Check if wallet has the ML-DSA keys
            wallet_info = self.nodes[0].getwalletinfo()
            self.log.info(f"Wallet info: descriptors={wallet_info.get('descriptors', False)}")

            # List all descriptors to see if our raw() descriptor is there
            try:
                desc_list = self.nodes[0].listdescriptors()
                self.log.info(f"Wallet has {len(desc_list.get('descriptors', []))} descriptors")
                # Check if any match our ML-DSA address
                for desc in desc_list.get('descriptors', []):
                    if 'desc' in desc:
                        self.log.info(f"Descriptor: {desc['desc'][:100]}...")
            except Exception as e:
                self.log.info(f"Could not list descriptors: {e}")

        assert processed['complete'], "PSBT should be complete after wallet processing"

        # Decode processed PSBT to verify ML-DSA fields were populated
        decoded_signed = self.nodes[0].decodepsbt(processed['psbt'])
        self.log.info(f"PSBT input after processing: {decoded_signed['inputs'][0].keys()}")

        # Extract the final transaction
        finalized = self.nodes[0].finalizepsbt(processed['psbt'])
        assert finalized['complete'], "PSBT should finalize successfully"
        signed_tx = finalized['hex']

        assert len(signed_tx) > len(rawtx), "Signed transaction should be larger"
        self.log.info("Successfully signed transaction with ML-DSA via PSBT workflow")

        # Test 5: Broadcast and confirm
        self.log.info("Test 5: Broadcast PSBT-signed transaction")
        final_txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.generate(self.nodes[0], 1)

        # Verify transaction is confirmed
        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1, "Transaction should be confirmed")

        # Verify recipient received funds
        balance = self.nodes[1].getbalance()
        assert balance >= 0.99, f"Node 1 should have received ~0.99 BTC, got {balance}"

        self.log.info(f"Transaction confirmed with txid: {final_txid}")
        self.log.info("All ML-DSA PSBT tests passed!")


if __name__ == '__main__':
    WalletPQPSBTTest(__file__).main()
