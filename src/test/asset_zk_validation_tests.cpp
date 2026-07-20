// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>
#include <script/script.h>
#include <script/solver.h>
#include <primitives/transaction.h>
#include <addresstype.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <uint256.h>
#include <assets/asset.h>

#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>

#include <boost/test/unit_test.hpp>

using namespace Consensus;

BOOST_FIXTURE_TEST_SUITE(asset_zk_validation_tests, BasicTestingSetup)

// Test: KYC assets require witness script types
BOOST_AUTO_TEST_CASE(witness_script_type_validation)
{
    // Witness script types (VALID for KYC)
    CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(uint160()));
    CScript p2wsh = GetScriptForDestination(WitnessV0ScriptHash(uint256()));
    CScript p2tr = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey()));

    BOOST_CHECK(IsWitnessScriptType(p2wpkh));
    BOOST_CHECK(IsWitnessScriptType(p2wsh));
    BOOST_CHECK(IsWitnessScriptType(p2tr));

    // Non-witness script types (INVALID for KYC)
    CScript p2pkh = GetScriptForDestination(PKHash(uint160()));
    CScript p2sh = GetScriptForDestination(ScriptHash(uint160()));
    CScript op_return = CScript() << OP_RETURN << std::vector<unsigned char>(20, 0x42);

    BOOST_CHECK(!IsWitnessScriptType(p2pkh));
    BOOST_CHECK(!IsWitnessScriptType(p2sh));
    BOOST_CHECK(!IsWitnessScriptType(op_return));
}

// Test: Witness stack validation with TLV-based proofs
// Witness now contains only standard spend elements (sig + pubkey)
BOOST_AUTO_TEST_CASE(witness_stack_layout_validation)
{
    // VALID: Standard P2WPKH witness (sig + pubkey)
    {
        CScriptWitness witness;
        witness.stack.push_back(std::vector<unsigned char>(71, 0x30)); // DER signature
        witness.stack.push_back(std::vector<unsigned char>(33, 0x02)); // compressed pubkey
        BOOST_CHECK(HasValidZkWitnessLayout(witness));
    }

    // VALID: Standard P2WSH 2-of-2 multisig witness
    {
        CScriptWitness witness;
        witness.stack.push_back(std::vector<unsigned char>()); // OP_0 for multisig
        witness.stack.push_back(std::vector<unsigned char>(71, 0x30)); // sig1
        witness.stack.push_back(std::vector<unsigned char>(71, 0x31)); // sig2
        witness.stack.push_back(std::vector<unsigned char>(105, 0x52)); // redeemScript (2-of-2)
        BOOST_CHECK(HasValidZkWitnessLayout(witness));
    }

    // VALID: Standard Taproot key-path spend
    {
        CScriptWitness witness;
        witness.stack.push_back(std::vector<unsigned char>(64, 0x40)); // Schnorr signature
        BOOST_CHECK(HasValidZkWitnessLayout(witness));
    }

    // INVALID: Empty witness stack (no signature)
    {
        CScriptWitness witness;
        BOOST_CHECK(!HasValidZkWitnessLayout(witness));
    }
}

// Test: Proof count must be within per-transaction limit
BOOST_AUTO_TEST_CASE(proof_count_limit_validation)
{
    // VALID: Within limit (MAX_ZK_PROOFS_PER_TX = 2)
    BOOST_CHECK(IsProofCountWithinLimit(0));
    BOOST_CHECK(IsProofCountWithinLimit(1));
    BOOST_CHECK(IsProofCountWithinLimit(2));

    // INVALID: Exceeds limit
    BOOST_CHECK(!IsProofCountWithinLimit(3));
    BOOST_CHECK(!IsProofCountWithinLimit(10));
    BOOST_CHECK(!IsProofCountWithinLimit(100));
}

// Test: ZK_PROOF_PAYLOAD TLV parsing and size validation
BOOST_AUTO_TEST_CASE(zk_proof_payload_parsing)
{
    uint256 asset_id;
    asset_id.SetNull();
    asset_id.begin()[0] = 0xAA;

    // VALID: Correct proof size (192 bytes) and public_inputs size (128 bytes)
    {
        std::vector<unsigned char> proof(assets::GROTH16_PROOF_SIZE, 0x01);
        std::vector<unsigned char> inputs(assets::GROTH16_MIN_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE, 0x02);
        auto tlv = test_util::BuildZkProofPayload(asset_id, proof, inputs);

        auto parsed = assets::ParseZkProofPayload(tlv);
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK(parsed->asset_id == asset_id);
        BOOST_CHECK_EQUAL(parsed->proof.size(), assets::GROTH16_PROOF_SIZE);
        BOOST_CHECK_EQUAL(parsed->public_inputs.size(), assets::GROTH16_MIN_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE);
    }

    // VALID: Parse succeeds with non-standard sizes (consensus will reject)
    {
        std::vector<unsigned char> proof(100, 0x01); // Wrong size
        std::vector<unsigned char> inputs(64, 0x02); // Wrong size
        auto tlv = test_util::BuildZkProofPayload(asset_id, proof, inputs);

        auto parsed = assets::ParseZkProofPayload(tlv);
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK_EQUAL(parsed->proof.size(), 100);
        BOOST_CHECK_EQUAL(parsed->public_inputs.size(), 64);
    }

    // Proof count at exact limit
    BOOST_CHECK(IsProofCountWithinLimit(assets::MAX_ZK_PROOFS_PER_TX));
    BOOST_CHECK(!IsProofCountWithinLimit(assets::MAX_ZK_PROOFS_PER_TX + 1));
}

// Test: ZK_PROOF_PAYLOAD asset_id binding and roundtrip
BOOST_AUTO_TEST_CASE(zk_proof_payload_asset_binding)
{
    uint256 asset_A, asset_B;
    asset_A.SetNull(); asset_A.begin()[0] = 0xAA;
    asset_B.SetNull(); asset_B.begin()[0] = 0xBB;

    std::vector<unsigned char> proof(assets::GROTH16_PROOF_SIZE, 0x01);
    std::vector<unsigned char> inputs(assets::GROTH16_MIN_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE, 0x02);

    // Build TLV for asset_A
    auto tlv_A = test_util::BuildZkProofPayload(asset_A, proof, inputs);

    // Parse and verify asset_id binding
    auto parsed = assets::ParseZkProofPayload(tlv_A);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->asset_id == asset_A);
    BOOST_CHECK(parsed->asset_id != asset_B); // Different asset

    // Verify proof data roundtrip
    BOOST_CHECK(parsed->proof == proof);
    BOOST_CHECK(parsed->public_inputs == inputs);
}

BOOST_AUTO_TEST_CASE(zk_proof_payload_hdv1_is_standard)
{
    uint256 asset_id;
    asset_id.SetNull();
    asset_id.begin()[0] = 0xCC;

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));

    CTxOut proof_output;
    proof_output.nValue = 0;
    proof_output.scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{0x00};
    proof_output.vExt = test_util::BuildZkProofPayload(
        asset_id,
        std::vector<unsigned char>(assets::GROTH16_PROOF_SIZE, 0x11),
        std::vector<unsigned char>(assets::GROTH16_HDV1_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE, 0x22));
    tx.vout.push_back(std::move(proof_output));

    std::string reason;
    CFeeRate dust_relay_fee{DUST_RELAY_TX_FEE};
    BOOST_CHECK_MESSAGE(
        IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, /*permit_bare_multisig=*/true, dust_relay_fee, reason),
        "HDv1 ZK_PROOF_PAYLOAD should be standard, got reason: " << reason);
}

BOOST_AUTO_TEST_SUITE_END()
