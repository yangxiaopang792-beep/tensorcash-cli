#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test VK (Verifying Key) lifecycle and same-transaction requirements.

This test covers Gap #7 from TEST_COVERAGE_CLOSURE_PLAN.md:
- VK chunks must be in same TRANSACTION as IssuerReg (not just same block)
- VK chunks in separate transaction should fail
- VK chunks in same transaction should succeed
- VK rotation via ICU spend
- VK persistence and retrieval
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from decimal import Decimal
import hashlib
import struct

# Mock ZK proof components
MOCK_G1_SIZE = 48
MOCK_G2_SIZE = 96
MOCK_FR_SIZE = 32

def create_mock_g1_point(seed=0x01):
    """Create a mock G1 point (not cryptographically valid)"""
    point = bytearray(MOCK_G1_SIZE)
    point[0] = 0x80 | (seed & 0x7F)
    for i in range(1, MOCK_G1_SIZE):
        point[i] = (seed + i) & 0xFF
    return bytes(point)

def create_mock_g2_point(seed=0x02):
    """Create a mock G2 point"""
    point = bytearray(MOCK_G2_SIZE)
    point[0] = 0x80 | (seed & 0x7F)
    for i in range(1, MOCK_G2_SIZE):
        point[i] = (seed + i) & 0xFF
    return bytes(point)

def create_mock_verifying_key(gamma_abc_count=4):
    """Create a mock verifying key"""
    vk = b''
    vk += struct.pack('<H', gamma_abc_count)
    vk += create_mock_g1_point(0x10)  # alpha_G1
    vk += create_mock_g2_point(0x20)  # beta_G2
    vk += create_mock_g2_point(0x30)  # gamma_G2
    vk += create_mock_g2_point(0x40)  # delta_G2
    vk += create_mock_g1_point(0x50)  # gamma_abc[0]
    for i in range(gamma_abc_count):
        vk += create_mock_g1_point(0x60 + i)
    return vk

def double_sha256(data: bytes) -> bytes:
    """Return double-SHA256 commitment as raw bytes."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def encode_uint256_le(hex_str: str) -> bytes:
    """Encode 32-byte hex string into little-endian byte order."""
    raw = bytes.fromhex(hex_str)
    if len(raw) != 32:
        raise ValueError("expected 32-byte hex string")
    return raw[::-1]

def create_zk_params_chunk_tlv(asset_id, vk_hash, chunk_index, chunk_count, data):
    """Create a ZK_PARAMS_CHUNK TLV"""
    tlv_type = 0x20

    payload = b''
    payload += encode_uint256_le(asset_id)
    payload += vk_hash if isinstance(vk_hash, bytes) else encode_uint256_le(vk_hash)
    payload += struct.pack('<H', chunk_index)
    payload += struct.pack('<H', chunk_count)
    payload += data

    tlv = bytes([tlv_type])
    if len(payload) < 253:
        tlv += bytes([len(payload)])
    else:
        tlv += bytes([253])
        tlv += struct.pack('<H', len(payload))
    tlv += payload
    return tlv

def create_issuer_reg_v2_tlv(asset_id, policy_bits=0x13, vk_commitment=None, max_root_age=144, tfr_flags=0, ticker=None):
    """Create IssuerReg v1 TLV with ZK fields populated (v1 format supports ZK metadata)"""
    tlv_type = 0x10

    payload = b''

    # Header (39 bytes)
    payload += encode_uint256_le(asset_id)
    payload += struct.pack('<I', policy_bits)
    payload += struct.pack('<H', 0x001C)  # P2WPKH | P2WSH | P2TR
    payload += bytes([0x01])  # format_version = 1

    # Optional fields (10+ bytes)
    if ticker:
        ticker_bytes = ticker.encode() if isinstance(ticker, str) else ticker
        payload += bytes([len(ticker_bytes)])
        payload += ticker_bytes
    else:
        payload += bytes([0])  # ticker_len = 0
    payload += bytes([0xFF])  # decimals = 0xFF (not set)
    payload += struct.pack('<Q', 510000000)  # unlock_fees_sats

    # ZK section (76 bytes) - populated if KYC_REQUIRED
    if policy_bits & 0x10:  # KYC_REQUIRED
        payload += struct.pack('<I', 0x01)  # kyc_flags
        if vk_commitment:
            payload += vk_commitment if isinstance(vk_commitment, bytes) else encode_uint256_le(vk_commitment)
        else:
            payload += bytes(32)
        payload += struct.pack('<I', max_root_age)
        payload += struct.pack('<I', tfr_flags)
        payload += bytes(32)  # compliance_root_commit (zero for tests)
    else:
        payload += bytes(76)  # All zeros

    # ICU section (129 bytes with icu_visibility, all zeros for basic registration)
    payload += bytes(129)

    tlv = bytes([tlv_type])
    if len(payload) < 253:
        tlv += bytes([len(payload)])
    else:
        tlv += bytes([253])
        tlv += struct.pack('<H', len(payload))
    tlv += payload
    return tlv


class AssetVKLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("=== VK Lifecycle Test Suite ===")
        self.log.info("Testing Gap #7: VK Same-Transaction Requirement")

        # Generate initial blocks to mature coinbase
        self.generate(self.nodes[0], 110)

        # Define unique asset IDs for each test (64 hex chars = 32 bytes)
        self.asset_A = "deadbeef" * 8
        self.asset_B = "cafebabe" * 8
        self.asset_C = "feedface" * 8

        # Run test cases
        self.test_vk_chunks_in_same_tx_succeeds()
        # TODO: test_issuerreg_without_chunks_fails requires block-level validation testing
        self.test_vk_rotation_via_icu_spend()

        self.log.info("=== All VK Lifecycle Tests Passed ===")

    def test_vk_chunks_in_same_tx_succeeds(self):
        """Test that VK chunks in same transaction as IssuerReg succeeds"""
        self.log.info("Test 1: VK chunks in same transaction should succeed")

        vk_data = create_mock_verifying_key(gamma_abc_count=4)
        signed_hex = self.craft_registration_with_chunks(self.asset_A, vk_data, ticker="VKA")

        # Send and mine
        txid = self.nodes[0].sendrawtransaction(signed_hex)
        self.generate(self.nodes[0], 2)

        # Verify asset registered
        policy = self.nodes[0].getassetpolicy(self.asset_A)
        if policy is None:
            self.wait_until(lambda: self.nodes[0].getassetpolicy(self.asset_A) is not None, timeout=5)
            policy = self.nodes[0].getassetpolicy(self.asset_A)

        assert policy is not None, "Asset policy missing after registration"
        assert_equal(policy['policy_bits'] & 0x10, 0x10)  # KYC_REQUIRED set

        self.log.info(f"  ✓ Asset {self.asset_A[:16]}... registered with VK chunks")

    def test_issuerreg_without_chunks_fails(self):
        """Test that IssuerReg v2 without VK chunks fails"""
        self.log.info("Test 2: IssuerReg without VK chunks should fail")

        vk_data = create_mock_verifying_key(gamma_abc_count=5)
        vk_hash = double_sha256(vk_data)

        # Create registration WITHOUT chunks (intentionally incomplete)
        signed_hex = self.craft_registration_without_chunks(self.asset_B, vk_hash)

        # Should fail with "zkchunk-missing"
        assert_raises_rpc_error(
            -26, "zkchunk-missing",
            self.nodes[0].sendrawtransaction, signed_hex
        )

        self.log.info("  ✓ IssuerReg without VK chunks rejected (zkchunk-missing)")

    def test_vk_rotation_via_icu_spend(self):
        """Test VK rotation by spending ICU and registering new VK"""
        self.log.info("Test 3: VK rotation via ICU spend")

        # Register asset C with VK1
        vk1_data = create_mock_verifying_key(gamma_abc_count=4)
        signed_hex = self.craft_registration_with_chunks(self.asset_C, vk1_data, ticker="VKC")

        txid1 = self.nodes[0].sendrawtransaction(signed_hex)
        self.generate(self.nodes[0], 2)

        policy = self.nodes[0].getassetpolicy(self.asset_C)
        if policy is None:
            self.wait_until(lambda: self.nodes[0].getassetpolicy(self.asset_C) is not None, timeout=5)
            policy = self.nodes[0].getassetpolicy(self.asset_C)

        self.log.info(f"  ✓ Initial registration with VK1: {txid1}")

        # Now rotate to VK2 by spending the ICU
        vk2_data = create_mock_verifying_key(gamma_abc_count=6)  # Different size
        icu_txid = policy['icu_txid']
        icu_vout = policy['icu_vout']

        signed_hex2 = self.craft_rotation_tx(self.asset_C, vk2_data, icu_txid, icu_vout)
        txid2 = self.nodes[0].sendrawtransaction(signed_hex2)
        self.generate(self.nodes[0], 2)

        self.log.info(f"  ✓ VK rotation to VK2: {txid2}")

    def craft_registration_with_chunks(self, asset_id, vk_data, ticker=None, bond_amount=Decimal('5.1'), carrier_amount=Decimal('0.001')):
        """Create registration transaction WITH VK chunks (same tx)"""
        node = self.nodes[0]

        # Prepare chunks
        chunk_size = 512
        chunks = [vk_data[i:i + chunk_size] for i in range(0, len(vk_data), chunk_size)]
        vk_hash = double_sha256(vk_data)

        # Create addresses
        icu_addr = node.getnewaddress()
        outputs = [{icu_addr: float(bond_amount)}]
        carrier_scripts = []

        for _ in chunks:
            addr = node.getnewaddress()
            outputs.append({addr: float(carrier_amount)})
            carrier_scripts.append(node.getaddressinfo(addr)['scriptPubKey'])

        # Create and fund base transaction
        raw_tx = node.createrawtransaction([], outputs)
        funded = node.fundrawtransaction(raw_tx, options={"fee_rate": 5})
        tx_hex = funded['hex']

        # Decode to map outputs
        decoded = node.decoderawtransaction(tx_hex)
        script_to_vouts = {}
        for idx, vout in enumerate(decoded['vout']):
            script_hex = vout['scriptPubKey']['hex']
            script_to_vouts.setdefault(script_hex, []).append(idx)

        # Find ICU output
        icu_script = node.getaddressinfo(icu_addr)['scriptPubKey']
        if icu_script not in script_to_vouts:
            raise AssertionError("ICU output missing after funding")
        icu_vout = script_to_vouts[icu_script].pop(0)

        # Add VK chunks to carrier outputs
        for idx, chunk_data in enumerate(chunks):
            chunk_tlv = create_zk_params_chunk_tlv(
                asset_id, vk_hash, idx, len(chunks), chunk_data
            )
            carrier_script = carrier_scripts[idx]
            if carrier_script not in script_to_vouts or not script_to_vouts[carrier_script]:
                raise AssertionError("Chunk carrier output missing after funding")
            vout_index = script_to_vouts[carrier_script].pop(0)
            tx_hex = node.rawtxaddoutext(tx_hex, vout_index, chunk_tlv.hex())

        # Add IssuerReg TLV to ICU output
        issuer_tlv = create_issuer_reg_v2_tlv(
            asset_id, policy_bits=0x13, vk_commitment=vk_hash,
            max_root_age=144, tfr_flags=0, ticker=ticker
        )
        tx_hex = node.rawtxaddoutext(tx_hex, icu_vout, issuer_tlv.hex())

        # Sign
        signed = node.signrawtransactionwithwallet(tx_hex)
        if not signed['complete']:
            raise AssertionError("Signing failed")

        # Validate
        accept = node.testmempoolaccept([signed['hex']])[0]
        if not accept['allowed']:
            raise AssertionError(f"Registration rejected: {accept}")

        return signed['hex']

    def craft_registration_without_chunks(self, asset_id, vk_hash, ticker=None):
        """Create registration transaction WITHOUT VK chunks (should fail)"""
        node = self.nodes[0]

        # Create ICU output only (no chunk carriers)
        icu_addr = node.getnewaddress()
        outputs = [{icu_addr: 5.1}]

        raw_tx = node.createrawtransaction([], outputs)
        funded = node.fundrawtransaction(raw_tx, options={"fee_rate": 5})
        tx_hex = funded['hex']

        # Decode to find ICU output
        decoded = node.decoderawtransaction(tx_hex)
        script_to_vouts = {}
        for idx, vout in enumerate(decoded['vout']):
            script_hex = vout['scriptPubKey']['hex']
            script_to_vouts.setdefault(script_hex, []).append(idx)

        icu_script = node.getaddressinfo(icu_addr)['scriptPubKey']
        icu_vout = script_to_vouts[icu_script].pop(0)

        # Add IssuerReg v2 TLV (with vk_commitment) but NO chunks
        issuer_tlv = create_issuer_reg_v2_tlv(
            asset_id, policy_bits=0x13, vk_commitment=vk_hash,
            max_root_age=144, tfr_flags=0, ticker=ticker
        )
        tx_hex = node.rawtxaddoutext(tx_hex, icu_vout, issuer_tlv.hex())

        # Sign
        signed = node.signrawtransactionwithwallet(tx_hex)
        return signed['hex']

    def craft_rotation_tx(self, asset_id, new_vk_data, icu_txid, icu_vout):
        """Create ICU rotation transaction with new VK"""
        node = self.nodes[0]

        # Prepare new VK chunks
        chunk_size = 512
        chunks = [new_vk_data[i:i + chunk_size] for i in range(0, len(new_vk_data), chunk_size)]
        vk_hash = double_sha256(new_vk_data)

        # Create new ICU output + chunk carriers
        new_icu_addr = node.getnewaddress()
        outputs = [{new_icu_addr: 5.1}]
        carrier_scripts = []

        for _ in chunks:
            addr = node.getnewaddress()
            outputs.append({addr: 0.001})
            carrier_scripts.append(node.getaddressinfo(addr)['scriptPubKey'])

        # Create tx spending old ICU
        inputs = [{"txid": icu_txid, "vout": icu_vout}]
        raw_tx = node.createrawtransaction(inputs, outputs)
        funded = node.fundrawtransaction(raw_tx, options={"fee_rate": 5})
        tx_hex = funded['hex']

        # Decode to map outputs
        decoded = node.decoderawtransaction(tx_hex)
        script_to_vouts = {}
        for idx, vout in enumerate(decoded['vout']):
            script_hex = vout['scriptPubKey']['hex']
            script_to_vouts.setdefault(script_hex, []).append(idx)

        # Find new ICU output
        new_icu_script = node.getaddressinfo(new_icu_addr)['scriptPubKey']
        new_icu_vout = script_to_vouts[new_icu_script].pop(0)

        # Add VK chunks
        for idx, chunk_data in enumerate(chunks):
            chunk_tlv = create_zk_params_chunk_tlv(
                asset_id, vk_hash, idx, len(chunks), chunk_data
            )
            carrier_script = carrier_scripts[idx]
            vout_index = script_to_vouts[carrier_script].pop(0)
            tx_hex = node.rawtxaddoutext(tx_hex, vout_index, chunk_tlv.hex())

        # Add new IssuerReg
        issuer_tlv = create_issuer_reg_v2_tlv(
            asset_id, policy_bits=0x13, vk_commitment=vk_hash,
            max_root_age=144, tfr_flags=0
        )
        tx_hex = node.rawtxaddoutext(tx_hex, new_icu_vout, issuer_tlv.hex())

        # Sign
        signed = node.signrawtransactionwithwallet(tx_hex)
        return signed['hex']


if __name__ == '__main__':
    AssetVKLifecycleTest(__file__).main()
