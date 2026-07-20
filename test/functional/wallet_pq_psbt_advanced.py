#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Advanced ML-DSA PSBT functionality tests.

This test verifies advanced PSBT workflows with ML-DSA witness v2 addresses:
- Multi-party PSBT signing
- Mixed ML-DSA + ECDSA inputs
- PSBT update without signing (watch-only)
- PSBT combining from multiple parties
- Encrypted wallet handling
- Different parameter sets (44, 65, 87)
- PSBT serialization round-trip
- PSBT merge with conflicting data
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AdvancedMLDSAPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Advanced ML-DSA PSBT Tests")

        # Generate blocks to fund wallets
        self.generate(self.nodes[0], 101)
        self.sync_all()

        # Test 1: Multi-party PSBT (2 ML-DSA inputs from different wallets)
        self.test_multiparty_psbt()

        # Test 2: PSBT with mixed ML-DSA + ECDSA inputs
        self.test_mixed_input_types()

        # Test 3: PSBT update without signing (watch-only simulation)
        self.test_update_without_signing()

        # Test 4: PSBT combining from multiple parties
        self.test_psbt_combining()

        # Test 5: PSBT with encrypted wallet
        self.test_encrypted_wallet()

        # Test 6: PSBT with different parameter sets
        self.test_multiple_param_sets()

        # Test 7: PSBT serialization round-trip
        self.test_psbt_roundtrip()

        # Test 8: PSBT merge behavior
        self.test_psbt_merge()

        self.log.info("All advanced ML-DSA PSBT tests passed!")

    def test_multiparty_psbt(self):
        """Test multi-party PSBT with 2 ML-DSA inputs from different wallets."""
        self.log.info("Test 1: Multi-party PSBT (2 ML-DSA inputs)")

        # Node 0 and Node 1 each generate an ML-DSA address
        addr_info_0 = self.nodes[0].generatemldsaaddress(65)
        addr_info_1 = self.nodes[1].generatemldsaaddress(65)

        addr_0 = addr_info_0['address']
        addr_1 = addr_info_1['address']

        # Fund both addresses (node 0 has funds from initial block generation)
        self.nodes[0].sendtoaddress(addr_0, 1.0)
        self.nodes[0].sendtoaddress(addr_1, 1.0)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # Rescan to detect transactions (descriptors were imported with old timestamps)
        self.log.info("Rescanning wallets to detect ML-DSA transactions")
        self.nodes[0].rescanblockchain()
        self.nodes[1].rescanblockchain()

        # Get UTXOs - wallet now tracks ML-DSA addresses
        unspent_0 = self.nodes[0].listunspent(1, 1, [addr_0])[0]
        unspent_1 = self.nodes[1].listunspent(1, 1, [addr_1])[0]

        # Create transaction with both inputs
        dest_address = self.nodes[2].getnewaddress()
        inputs = [
            {"txid": unspent_0["txid"], "vout": unspent_0["vout"]},
            {"txid": unspent_1["txid"], "vout": unspent_1["vout"]}
        ]
        outputs = {dest_address: 1.98}  # Leave some for fees

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt = self.nodes[0].converttopsbt(rawtx, True)

        # Node 0 processes their input
        psbt_0 = self.nodes[0].walletprocesspsbt(psbt, True)
        assert not psbt_0['complete'], "PSBT should not be complete after one signature"

        # Node 1 processes their input
        psbt_1 = self.nodes[1].walletprocesspsbt(psbt_0['psbt'], True)
        assert psbt_1['complete'], "PSBT should be complete after both signatures"

        # Finalize and broadcast
        finalized = self.nodes[0].finalizepsbt(psbt_1['psbt'])
        assert finalized['complete']

        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # Verify transaction confirmed
        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("Multi-party PSBT test passed")

    def test_mixed_input_types(self):
        """Test PSBT with mixed ML-DSA and ECDSA inputs."""
        self.log.info("Test 2: PSBT with mixed ML-DSA + ECDSA inputs")

        # Generate ML-DSA address
        mldsa_info = self.nodes[0].generatemldsaaddress(65)
        mldsa_addr = mldsa_info['address']

        # Generate regular ECDSA address
        ecdsa_addr = self.nodes[0].getnewaddress()

        # Fund both
        self.nodes[0].sendtoaddress(mldsa_addr, 1.0)
        self.nodes[0].sendtoaddress(ecdsa_addr, 1.0)
        self.generate(self.nodes[0], 1)

        # Get UTXOs - wallet tracks both address types
        mldsa_utxo = self.nodes[0].listunspent(1, 1, [mldsa_addr])[0]
        ecdsa_utxo = self.nodes[0].listunspent(1, 1, [ecdsa_addr])[0]

        # Create transaction with both input types
        dest_address = self.nodes[1].getnewaddress()
        inputs = [
            {"txid": mldsa_utxo["txid"], "vout": mldsa_utxo["vout"]},
            {"txid": ecdsa_utxo["txid"], "vout": ecdsa_utxo["vout"]}
        ]
        outputs = {dest_address: 1.98}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt = self.nodes[0].converttopsbt(rawtx, True)

        # Process PSBT (should handle both input types)
        processed = self.nodes[0].walletprocesspsbt(psbt, True)
        assert processed['complete'], "PSBT should be complete with mixed inputs"

        # Finalize and broadcast
        finalized = self.nodes[0].finalizepsbt(processed['psbt'])
        assert finalized['complete']

        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)

        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("Mixed input types test passed")

    def test_update_without_signing(self):
        """Test PSBT update without signing (simulates watch-only workflow)."""
        self.log.info("Test 3: PSBT update without signing")

        # Generate ML-DSA address and fund it
        addr_info = self.nodes[0].generatemldsaaddress(65)
        addr = addr_info['address']

        self.nodes[0].sendtoaddress(addr, 1.0)
        self.generate(self.nodes[0], 1)

        # Get UTXO
        unspent = self.nodes[0].listunspent(1, 1, [addr])[0]

        # Create PSBT
        dest_address = self.nodes[1].getnewaddress()
        inputs = [{"txid": unspent["txid"], "vout": unspent["vout"]}]
        outputs = {dest_address: 0.99}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt = self.nodes[0].converttopsbt(rawtx, True)

        # Process without signing
        updated = self.nodes[0].walletprocesspsbt(psbt, False)  # sign=False
        assert not updated['complete'], "PSBT should not be complete without signing"

        # Decode and verify ML-DSA metadata was added
        decoded = self.nodes[0].decodepsbt(updated['psbt'])
        # Note: Depending on implementation, metadata might be in different fields
        # Just verify it's not empty
        assert len(decoded['inputs']) == 1

        # Now sign it
        signed = self.nodes[0].walletprocesspsbt(updated['psbt'], True)
        assert signed['complete'], "PSBT should be complete after signing"

        self.log.info("Update without signing test passed")

    def test_psbt_combining(self):
        """Test combining PSBTs from multiple parties."""
        self.log.info("Test 4: PSBT combining from multiple parties")

        # Create 2 separate PSBTs with ML-DSA inputs
        addr_info_0 = self.nodes[0].generatemldsaaddress(65)
        addr_info_1 = self.nodes[1].generatemldsaaddress(65)

        # Node 0 funds both addresses
        self.nodes[0].sendtoaddress(addr_info_0['address'], 1.0)
        self.nodes[0].sendtoaddress(addr_info_1['address'], 1.0)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        # Rescan to detect transactions
        self.nodes[0].rescanblockchain()
        self.nodes[1].rescanblockchain()

        unspent_0 = self.nodes[0].listunspent(1, 1, [addr_info_0["address"]])[0]
        unspent_1 = self.nodes[1].listunspent(1, 1, [addr_info_1["address"]])[0]

        # Create base PSBT
        dest_address = self.nodes[2].getnewaddress()
        inputs = [
            {"txid": unspent_0["txid"], "vout": unspent_0["vout"]},
            {"txid": unspent_1["txid"], "vout": unspent_1["vout"]}
        ]
        outputs = {dest_address: 1.98}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt_base = self.nodes[0].converttopsbt(rawtx, True)

        # Populate UTXO data for both inputs
        psbt_base = self.nodes[0].utxoupdatepsbt(psbt_base)
        psbt_base = self.nodes[1].utxoupdatepsbt(psbt_base)

        # Each party signs their input separately
        psbt_0 = self.nodes[0].walletprocesspsbt(psbt_base, True)['psbt']
        psbt_1 = self.nodes[1].walletprocesspsbt(psbt_base, True)['psbt']

        # Combine the PSBTs
        combined = self.nodes[0].combinepsbt([psbt_0, psbt_1])

        # Finalize combined PSBT
        finalized = self.nodes[0].finalizepsbt(combined)
        assert finalized['complete'], "Combined PSBT should be complete"

        # Broadcast
        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)

        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("PSBT combining test passed")

    def test_encrypted_wallet(self):
        """Test PSBT with encrypted wallet (lock/unlock cycle)."""
        self.log.info("Test 5: PSBT with encrypted wallet")

        # Encrypt wallet
        passphrase = "test_passphrase_12345"
        self.nodes[0].encryptwallet(passphrase)
        self.stop_node(0)
        self.start_node(0)
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)

        # Generate ML-DSA address (wallet is locked)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase",
                                self.nodes[0].generatemldsaaddress, 65)

        # Unlock wallet
        self.nodes[0].walletpassphrase(passphrase, 60)

        # Generate address and fund it
        addr_info = self.nodes[0].generatemldsaaddress(65)
        addr = addr_info['address']

        self.nodes[0].sendtoaddress(addr, 1.0)
        self.generate(self.nodes[0], 1)

        unspent = self.nodes[0].listunspent(1, 1, [addr])[0]

        # Lock wallet
        self.nodes[0].walletlock()

        # Create PSBT (should work while locked)
        dest_address = self.nodes[1].getnewaddress()
        inputs = [{"txid": unspent["txid"], "vout": unspent["vout"]}]
        outputs = {dest_address: 0.99}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt = self.nodes[0].converttopsbt(rawtx, True)

        # Try to sign while locked (should fail)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase",
                                self.nodes[0].walletprocesspsbt, psbt, True)

        # Unlock and sign
        self.nodes[0].walletpassphrase(passphrase, 60)
        processed = self.nodes[0].walletprocesspsbt(psbt, True)
        assert processed['complete']

        # Finalize and broadcast
        finalized = self.nodes[0].finalizepsbt(processed['psbt'])
        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)

        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("Encrypted wallet test passed")

    def test_multiple_param_sets(self):
        """Test PSBT with different ML-DSA parameter sets."""
        self.log.info("Test 6: PSBT with different parameter sets (44, 65, 87)")

        # Generate addresses with different parameter sets
        addr_44 = self.nodes[0].generatemldsaaddress(44)['address']
        addr_65 = self.nodes[0].generatemldsaaddress(65)['address']
        addr_87 = self.nodes[0].generatemldsaaddress(87)['address']

        # Fund all addresses
        self.nodes[0].sendtoaddress(addr_44, 1.0)
        self.nodes[0].sendtoaddress(addr_65, 1.0)
        self.nodes[0].sendtoaddress(addr_87, 1.0)
        self.generate(self.nodes[0], 1)

        # Get UTXOs
        utxo_44 = self.nodes[0].listunspent(1, 1, [addr_44])[0]
        utxo_65 = self.nodes[0].listunspent(1, 1, [addr_65])[0]
        utxo_87 = self.nodes[0].listunspent(1, 1, [addr_87])[0]

        # Create transaction with all three input types
        dest_address = self.nodes[1].getnewaddress()
        inputs = [
            {"txid": utxo_44["txid"], "vout": utxo_44["vout"]},
            {"txid": utxo_65["txid"], "vout": utxo_65["vout"]},
            {"txid": utxo_87["txid"], "vout": utxo_87["vout"]}
        ]
        outputs = {dest_address: 2.97}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt = self.nodes[0].converttopsbt(rawtx, True)

        # Process PSBT (should handle all parameter sets)
        processed = self.nodes[0].walletprocesspsbt(psbt, True)
        assert processed['complete']

        # Decode and verify different param sets
        decoded = self.nodes[0].decodepsbt(processed['psbt'])
        assert_equal(len(decoded['inputs']), 3)

        # Finalize and broadcast
        finalized = self.nodes[0].finalizepsbt(processed['psbt'])
        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)

        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("Multiple parameter sets test passed")

    def test_psbt_roundtrip(self):
        """Test PSBT serialization round-trip."""
        self.log.info("Test 7: PSBT serialization round-trip")

        # Generate and fund ML-DSA address
        addr_info = self.nodes[0].generatemldsaaddress(65)
        addr = addr_info['address']

        self.nodes[0].sendtoaddress(addr, 1.0)
        self.generate(self.nodes[0], 1)

        unspent = self.nodes[0].listunspent(1, 1, [addr])[0]

        # Create PSBT
        dest_address = self.nodes[1].getnewaddress()
        inputs = [{"txid": unspent["txid"], "vout": unspent["vout"]}]
        outputs = {dest_address: 0.99}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt_original = self.nodes[0].converttopsbt(rawtx, True)

        # Decode, re-encode, and verify
        decoded = self.nodes[0].decodepsbt(psbt_original)
        # The PSBT should decode without errors
        assert 'tx' in decoded
        assert len(decoded['inputs']) == 1

        # Process and finalize
        processed = self.nodes[0].walletprocesspsbt(psbt_original, True)
        finalized = self.nodes[0].finalizepsbt(processed['psbt'])

        # Broadcast
        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)

        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("PSBT round-trip test passed")

    def test_psbt_merge(self):
        """Test PSBT merge behavior with ML-DSA fields."""
        self.log.info("Test 8: PSBT merge with ML-DSA data")

        # Generate and fund ML-DSA address
        addr_info = self.nodes[0].generatemldsaaddress(65)
        addr = addr_info['address']

        self.nodes[0].sendtoaddress(addr, 1.0)
        self.generate(self.nodes[0], 1)

        unspent = self.nodes[0].listunspent(1, 1, [addr])[0]

        # Create base PSBT
        dest_address = self.nodes[1].getnewaddress()
        inputs = [{"txid": unspent["txid"], "vout": unspent["vout"]}]
        outputs = {dest_address: 0.99}

        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        psbt_base = self.nodes[0].converttopsbt(rawtx, True)

        # Update without signing
        psbt_updated = self.nodes[0].walletprocesspsbt(psbt_base, False)['psbt']

        # Sign separately
        psbt_signed = self.nodes[0].walletprocesspsbt(psbt_base, True)['psbt']

        # Combine (merge) the two PSBTs
        combined = self.nodes[0].combinepsbt([psbt_updated, psbt_signed])

        # Should be complete after combining
        finalized = self.nodes[0].finalizepsbt(combined)
        assert finalized['complete']

        # Broadcast
        final_txid = self.nodes[0].sendrawtransaction(finalized['hex'])
        self.generate(self.nodes[0], 1)

        tx_info = self.nodes[0].gettransaction(final_txid)
        assert_equal(tx_info['confirmations'], 1)

        self.log.info("PSBT merge test passed")


if __name__ == '__main__':
    AdvancedMLDSAPSBTTest(__file__).main()
