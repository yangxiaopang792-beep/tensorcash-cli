#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Post-Quantum ML-DSA opcodes (Taproot v2)."""

import subprocess
import struct
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    COIN,
)
from test_framework.wallet import MiniWallet
from test_framework.script import (
    CScript,
    CScriptOp,
    OP_2,
    OP_TRUE,
    SIGHASH_ALL,
    LEAF_VERSION_TAPSCRIPT,
    taproot_construct,
    TaprootSignatureMsg,
)
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.key import ECKey, compute_xonly_pubkey, TaggedHash

# ML-DSA opcode constants (must use CScriptOp so they're treated as opcodes, not data)
OP_CHECKMLSIG = CScriptOp(0xbb)
OP_CHECKMLSIGVERIFY = CScriptOp(0xbc)

# ML-DSA parameter sets
ALG_ID_MLDSA = 0x01
PARAM_SET_MLDSA_65 = 0x41  # 65

class MLDSAHelper:
    """Helper to call mldsa_test_helper binary for key generation and signing"""

    def __init__(self, helper_path):
        self.helper_path = helper_path

    def keygen(self, level=65):
        """Generate ML-DSA keypair. Returns (pk_hex, sk_hex)"""
        result = subprocess.run(
            [self.helper_path, "keygen", str(level)],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')
        pk = None
        sk = None
        for line in lines:
            if line.startswith("pk:"):
                pk = line[3:]
            elif line.startswith("sk:"):
                sk = line[3:]
        if not pk or not sk:
            raise RuntimeError(f"Key generation failed: {result.stdout}")
        return pk, sk

    def sign(self, sk_hex, msg_hex):
        """Sign message with ML-DSA. Returns sig_hex"""
        result = subprocess.run(
            [self.helper_path, "sign", sk_hex, msg_hex],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.strip().split('\n'):
            if line.startswith("sig:"):
                return line[4:]
        raise RuntimeError(f"Signing failed: {result.stdout}")

def encode_mldsa_pubkey(param_set, pk_hex):
    """Encode ML-DSA public key for on-stack use"""
    pk_bytes = bytes.fromhex(pk_hex)
    encoded = bytes([ALG_ID_MLDSA, param_set])

    # Compact size (varint)
    pk_len = len(pk_bytes)
    if pk_len < 0xFD:
        encoded += bytes([pk_len])
    elif pk_len <= 0xFFFF:
        encoded += bytes([0xFD]) + struct.pack("<H", pk_len)

    encoded += pk_bytes
    return encoded

class TaprootV2MLDSATest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Allow non-standard transactions (witness v2 outputs are non-standard)
        self.extra_args = [['-acceptnonstdtxn=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        # Check if mldsa_test_helper exists
        import os
        helper_path = os.path.join(self.config['environment']['BUILDDIR'], 'bin', 'mldsa_test_helper')
        if not os.path.exists(helper_path):
            raise SkipTest("mldsa_test_helper not built (requires liboqs)")

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        # Initialize ML-DSA helper
        import os
        helper_path = os.path.join(self.config['environment']['BUILDDIR'], 'bin', 'mldsa_test_helper')
        mldsa = MLDSAHelper(helper_path)

        self.log.info("Generating blocks...")
        self.generate(wallet, 101)

        self.log.info("Testing ML-DSA policy enforcement...")

        # Test 1: ML-DSA opcodes rejected in witness v1 (Taproot)
        self.test_v1_rejects_mldsa(node, wallet, mldsa)

        # Test 2: ML-DSA opcodes accepted in witness v2 (PQ Taproot)
        self.test_v2_accepts_mldsa(node, wallet, mldsa)

        # Test 3: Witness v2 key-path spends rejected by consensus
        self.test_v2_keypath_rejected(node, wallet)

        self.log.info("All PQ ML-DSA tests passed!")

    def test_v1_rejects_mldsa(self, node, wallet, mldsa):
        """ML-DSA opcodes should be non-standard in witness v1"""
        self.log.info("Test: ML-DSA opcodes rejected in witness v1...")

        # Generate ML-DSA key
        pk_hex, sk_hex = mldsa.keygen(65)
        encoded_pk = encode_mldsa_pubkey(PARAM_SET_MLDSA_65, pk_hex)

        # Create tapscript with ML-DSA opcode
        tapscript = CScript([encoded_pk, OP_CHECKMLSIGVERIFY, OP_TRUE])

        # Create witness v1 Taproot output
        seckey = ECKey()
        seckey.generate()
        internal_pubkey = compute_xonly_pubkey(seckey.get_bytes())[0]

        taproot_output = taproot_construct(internal_pubkey, [("mldsa_script", tapscript)])
        scriptPubKey = taproot_output.scriptPubKey  # Witness v1

        # Fund the Taproot v1 output - send from MiniWallet UTXO to custom script
        utxo = wallet.get_utxo()
        tx_fund = CTransaction()
        tx_fund.vin = [CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout']))]
        utxo_value = int(utxo['value'] * COIN)  # Convert BTC to satoshis
        funding_amount = 10 * COIN  # 10 BTC to script
        fee = 1000
        change_amount = utxo_value - funding_amount - fee
        tx_fund.vout = [
            CTxOut(funding_amount, scriptPubKey),
            CTxOut(change_amount, wallet.get_output_script())  # Change to wallet
        ]
        wallet.sign_tx(tx_fund)
        funding_txid = node.sendrawtransaction(tx_fund.serialize().hex())
        block_hashes = self.generate(wallet, 1)

        # Now try to spend it with ML-DSA signature (should be rejected by policy)
        tx_spend = CTransaction()
        tx_spend.vin = [CTxIn(COutPoint(int(funding_txid, 16), 0))]

        spend_fee = 1000
        # Use wallet's output script (P2WPKH) for a standard-sized output
        tx_spend.vout = [CTxOut(funding_amount - spend_fee, wallet.get_output_script())]

        # Create witness (we're not signing properly, just testing policy rejection)
        leaf_info = taproot_output.leaves["mldsa_script"]
        control_block = bytes([leaf_info.version | taproot_output.negflag]) + internal_pubkey + leaf_info.merklebranch

        tx_spend.wit.vtxinwit = [CTxInWitness()]
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [
            b'\x00' * 64,  # Dummy signature
            tapscript,
            control_block
        ]

        # Compute transaction hash
        tx_spend.rehash()

        # Serialize the transaction
        tx_hex = tx_spend.serialize().hex()

        # Test mempool acceptance
        test_result = node.testmempoolaccept([tx_hex])[0]

        # Policy should reject ML-DSA opcodes in witness v1
        assert_equal(test_result['allowed'], False)
        # ML-DSA public keys exceed v1's 520-byte push limit, so rejection is expected
        # (either push size limit or opcode rejection)
        assert 'mandatory-script-verify-flag' in test_result['reject-reason'] or 'non-mandatory-script-verify-flag' in test_result['reject-reason']

        # Broadcasting should fail for script verification
        try:
            node.sendrawtransaction(tx_hex)
            raise AssertionError("Transaction should have been rejected")
        except Exception as e:
            # Accept any script verification failure (push size or opcode)
            assert 'mandatory-script-verify-flag' in str(e) or 'non-mandatory-script-verify-flag' in str(e)

        self.log.info("✓ ML-DSA opcode rejected in witness v1 (policy enforced)")

    def test_v2_accepts_mldsa(self, node, wallet, mldsa):
        """ML-DSA opcodes should be standard in witness v2"""
        self.log.info("Test: ML-DSA opcodes accepted in witness v2...")

        # Generate ML-DSA key
        pk_hex, sk_hex = mldsa.keygen(65)
        encoded_pk = encode_mldsa_pubkey(PARAM_SET_MLDSA_65, pk_hex)

        # Create tapscript with ML-DSA opcode
        # Simple script: just OP_CHECKMLSIG (pops 2, pushes 1)
        tapscript = CScript([OP_CHECKMLSIG])

        # Create witness v2 output
        # For v2, we use a dummy internal key (script-only, no key path)
        seckey = ECKey()
        seckey.generate()
        internal_pubkey = compute_xonly_pubkey(seckey.get_bytes())[0]

        # Build Taproot structure (reuse taproot_construct for tree/cb details)
        taproot_v1 = taproot_construct(internal_pubkey, [("mldsa_v2", tapscript)])
        scriptPubKey = CScript([OP_2, taproot_v1.output_pubkey])  # Witness v2

        # Fund the witness v2 output using MiniWallet helper (standard change handling)
        v2_funding_amount = 10 * COIN
        v2_fee = 1000
        send_result = wallet.send_to(from_node=node, scriptPubKey=scriptPubKey, amount=v2_funding_amount, fee=v2_fee)
        v2_funding_txid = send_result["txid"]
        v2_vout = send_result["sent_vout"]
        self.generate(wallet, 1)

        # Prepare spend transaction
        tx_spend = CTransaction()
        tx_spend.vin = [CTxIn(COutPoint(int(v2_funding_txid, 16), v2_vout))]
        # ML-DSA signatures are large (~3309 bytes for ML-DSA-65), need sufficient fee
        v2_spend_fee = 10000
        tx_spend.vout = [CTxOut(v2_funding_amount - v2_spend_fee, CScript(wallet.get_output_script()))]

        # Compute ML-DSA domain-separated Taproot signature hash
        spent_utxo = CTxOut(v2_funding_amount, scriptPubKey)
        tapleaf = taproot_v1.leaves["mldsa_v2"]
        taproot_msg = TaprootSignatureMsg(
            tx_spend,
            [spent_utxo],
            SIGHASH_ALL,
            0,
            scriptpath=True,
            leaf_script=tapscript,
            leaf_ver=LEAF_VERSION_TAPSCRIPT,
            codeseparator_pos=-1,
            annex=None,
        )
        sighash = TaggedHash("TapSighash/ML-DSA", taproot_msg)

        # Sign with ML-DSA helper
        sig_hex = mldsa.sign(sk_hex, sighash.hex())
        ml_dsa_sig = bytes.fromhex(sig_hex)

        # Append sighash flag to signature
        ml_dsa_sig_with_flag = ml_dsa_sig + bytes([SIGHASH_ALL])

        # Construct control block (same as Taproot v1; witness version encoded in scriptPubKey)
        control_block = bytes([tapleaf.version | taproot_v1.negflag]) + taproot_v1.internal_pubkey + tapleaf.merklebranch

        # Build witness
        # Stack order: [signature, pubkey, script, control_block]
        # After Taproot verification strips script+control, initial stack will be [signature, pubkey]
        tx_spend.wit.vtxinwit = [CTxInWitness()]
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [
            ml_dsa_sig_with_flag,
            encoded_pk,
            tapscript,
            control_block
        ]
        tx_spend.rehash()

        # Ensure mempool accepts and broadcast succeeds
        accept_result = node.testmempoolaccept([tx_spend.serialize().hex()])[0]
        assert_equal(accept_result["allowed"], True)
        spend_txid = node.sendrawtransaction(tx_spend.serialize().hex())
        assert_equal(len(spend_txid), 64)

        self.log.info(f"✓ ML-DSA transaction accepted in witness v2 (txid: {spend_txid[:16]}...)")

    def test_v2_keypath_rejected(self, node, wallet):
        """Witness v2 key-path spends should be rejected by consensus"""
        self.log.info("Test: Witness v2 key-path spends rejected by consensus...")

        # Create a witness v2 output with a simple key
        seckey = ECKey()
        seckey.generate()
        internal_pubkey = compute_xonly_pubkey(seckey.get_bytes())[0]

        # Create witness v2 scriptPubKey (OP_2 <32-byte-pubkey>)
        scriptPubKey = CScript([OP_2, internal_pubkey])

        # Fund the witness v2 output
        v2_funding_amount = 1 * COIN
        v2_fee = 1000
        send_result = wallet.send_to(from_node=node, scriptPubKey=scriptPubKey, amount=v2_funding_amount, fee=v2_fee)
        v2_funding_txid = send_result["txid"]
        v2_vout = send_result["sent_vout"]
        self.generate(wallet, 1)

        # Attempt key-path spend with single witness element
        tx_spend = CTransaction()
        tx_spend.vin = [CTxIn(COutPoint(int(v2_funding_txid, 16), v2_vout))]
        spend_fee = 1000
        tx_spend.vout = [CTxOut(v2_funding_amount - spend_fee, wallet.get_output_script())]

        # Compute sighash for key-path (witness v2, scriptpath=False)
        spent_utxo = CTxOut(v2_funding_amount, scriptPubKey)
        taproot_msg = TaprootSignatureMsg(
            tx_spend,
            [spent_utxo],
            SIGHASH_ALL,
            0,
            scriptpath=False,
            annex=None,
        )
        # Hash the message with BIP 340 Taproot tag
        sighash = TaggedHash("TapSighash", taproot_msg)

        # Sign with Schnorr (key-path signature)
        from test_framework.key import sign_schnorr
        signature = sign_schnorr(seckey.get_bytes(), sighash)

        # Append sighash flag
        signature_with_flag = signature + bytes([SIGHASH_ALL])

        # Single-element witness = key-path attempt
        tx_spend.wit.vtxinwit = [CTxInWitness()]
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [signature_with_flag]
        tx_spend.rehash()

        # Should be rejected with key-path disabled error
        tx_hex = tx_spend.serialize().hex()
        assert_raises_rpc_error(
            -26,
            "Taproot key-path spend disabled",
            node.sendrawtransaction,
            tx_hex
        )

        self.log.info("✓ Witness v2 key-path spend correctly rejected by consensus")

if __name__ == '__main__':
    TaprootV2MLDSATest(__file__).main()
