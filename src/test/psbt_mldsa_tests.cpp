// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <mldsakey.h>
#include <node/psbt_mldsa.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <iomanip>
#include <ostream>

using namespace util::hex_literals;

// Make std::vector<unsigned char> printable for Boost Test
namespace std {
    ostream& operator<<(ostream& os, const vector<unsigned char>& vec) {
        os << "vector(" << vec.size() << ")[";
        for (size_t i = 0; i < std::min(vec.size(), size_t(16)); ++i) {
            if (i > 0) os << " ";
            os << std::hex << std::setw(2) << std::setfill('0') << (int)vec[i];
        }
        if (vec.size() > 16) os << " ...";
        os << "]" << std::dec;
        return os;
    }
}

BOOST_FIXTURE_TEST_SUITE(psbt_mldsa_tests, BasicTestingSetup)

// Test PSBT field serialization/deserialization
BOOST_AUTO_TEST_CASE(serialize_mldsa_fields)
{
    // Create a PSBTInput with ML-DSA fields
    PSBTInput input;

    // Set ML-DSA pubkey (1952 bytes for ML-DSA-65)
    input.m_mldsa_pubkey.resize(1952);
    for (size_t i = 0; i < input.m_mldsa_pubkey.size(); i++) {
        input.m_mldsa_pubkey[i] = static_cast<uint8_t>(i % 256);
    }

    // Set ML-DSA signature (3309 bytes for ML-DSA-65)
    input.m_mldsa_signature.resize(3309);
    for (size_t i = 0; i < input.m_mldsa_signature.size(); i++) {
        input.m_mldsa_signature[i] = static_cast<uint8_t>((i * 7) % 256);
    }

    // Set param set and parity
    input.m_mldsa_param_set = 65;
    input.m_v2_tap_parity = 1;

    // Serialize
    DataStream ss_serialize{};
    ss_serialize << input;

    // Deserialize
    PSBTInput input_deserialized;
    ss_serialize >> input_deserialized;

    // Verify all fields match
    BOOST_CHECK_EQUAL(input_deserialized.m_mldsa_pubkey, input.m_mldsa_pubkey);
    BOOST_CHECK_EQUAL(input_deserialized.m_mldsa_signature, input.m_mldsa_signature);
    BOOST_CHECK(input_deserialized.m_mldsa_param_set == 65);
    BOOST_CHECK(input_deserialized.m_v2_tap_parity == 1);
}

// Test PSBT merge logic with ML-DSA fields
BOOST_AUTO_TEST_CASE(merge_mldsa_fields)
{
    PSBTInput input1, input2;

    // Input1 has pubkey and param_set
    input1.m_mldsa_pubkey.resize(1952, 0xAA);
    input1.m_mldsa_param_set = 65;

    // Input2 has signature and parity
    input2.m_mldsa_signature.resize(3309, 0xBB);
    input2.m_v2_tap_parity = 1;

    // Merge input2 into input1
    input1.Merge(input2);

    // Verify merged result has all fields
    BOOST_CHECK_EQUAL(input1.m_mldsa_pubkey.size(), 1952);
    BOOST_CHECK_EQUAL(input1.m_mldsa_signature.size(), 3309);
    BOOST_CHECK(input1.m_mldsa_param_set == 65);
    BOOST_CHECK(input1.m_v2_tap_parity == 1);
}

// Test IsNull with ML-DSA fields
BOOST_AUTO_TEST_CASE(isnull_with_mldsa)
{
    PSBTInput input;

    // Empty input should be null
    BOOST_CHECK(input.IsNull());

    // Add ML-DSA pubkey
    input.m_mldsa_pubkey.resize(1952, 0x00);
    BOOST_CHECK(!input.IsNull());

    // Clear and add signature
    input.m_mldsa_pubkey.clear();
    input.m_mldsa_signature.resize(3309, 0x00);
    BOOST_CHECK(!input.IsNull());

    // Clear and add param_set
    input.m_mldsa_signature.clear();
    input.m_mldsa_param_set = 65;
    BOOST_CHECK(!input.IsNull());

    // Clear and add parity
    input.m_mldsa_param_set = std::nullopt;
    input.m_v2_tap_parity = 1;
    BOOST_CHECK(!input.IsNull());
}

// Test ML-DSA input detection
BOOST_AUTO_TEST_CASE(detect_mldsa_input)
{
    PartiallySignedTransaction psbt;
    psbt.tx = CMutableTransaction();

    // Add an input
    psbt.tx->vin.resize(1);
    psbt.inputs.resize(1);

    // Create witness v2 scriptPubKey (OP_2 <32 bytes>)
    CScript witness_v2_script;
    witness_v2_script << OP_2 << std::vector<uint8_t>(32, 0xAA);

    // Set witness_utxo with witness v2
    psbt.inputs[0].witness_utxo = CTxOut(1000000, witness_v2_script);

    // Should detect as ML-DSA input
    BOOST_CHECK(node::IsMLDSAInput(psbt, 0));

    // Create witness v1 scriptPubKey (OP_1 <32 bytes>)
    CScript witness_v1_script;
    witness_v1_script << OP_1 << std::vector<uint8_t>(32, 0xBB);
    psbt.inputs[0].witness_utxo = CTxOut(1000000, witness_v1_script);

    // Should NOT detect as ML-DSA input
    BOOST_CHECK(!node::IsMLDSAInput(psbt, 0));
}

#ifdef ENABLE_MLDSA
// Test ML-DSA key generation and usage
BOOST_AUTO_TEST_CASE(mldsa_key_operations)
{
    // Test ML-DSA-65 key generation
    CMLDSAKey key65;
    BOOST_CHECK(key65.MakeNewKey(mldsa::ParamSet::MLDSA_65));
    BOOST_CHECK(key65.IsValid());

    // Check key sizes
    BOOST_CHECK_EQUAL(key65.GetSecretKey().size(), 4032);  // ML-DSA-65 SK size
    BOOST_CHECK_EQUAL(key65.GetPubKey().size(), 1952);     // ML-DSA-65 PK size

    // Test signing
    uint256 msg = m_rng.rand256();
    std::vector<uint8_t> signature;
    BOOST_CHECK(key65.Sign(msg, signature));
    BOOST_CHECK_EQUAL(signature.size(), 3309);  // ML-DSA-65 signature size

    // Test GetEncodedPubKey
    std::vector<uint8_t> encoded_pk = key65.GetEncodedPubKey();
    BOOST_CHECK(!encoded_pk.empty());
    BOOST_CHECK_EQUAL(encoded_pk[0], mldsa::ALG_ID_MLDSA);  // Algorithm ID
    BOOST_CHECK_EQUAL(encoded_pk[1], static_cast<uint8_t>(mldsa::ParamSet::MLDSA_65));  // Param set

    // Test ML-DSA-44
    CMLDSAKey key44;
    BOOST_CHECK(key44.MakeNewKey(mldsa::ParamSet::MLDSA_44));
    BOOST_CHECK_EQUAL(key44.GetSecretKey().size(), 2560);
    BOOST_CHECK_EQUAL(key44.GetPubKey().size(), 1312);

    // Test ML-DSA-87
    CMLDSAKey key87;
    BOOST_CHECK(key87.MakeNewKey(mldsa::ParamSet::MLDSA_87));
    BOOST_CHECK_EQUAL(key87.GetSecretKey().size(), 4896);
    BOOST_CHECK_EQUAL(key87.GetPubKey().size(), 2592);
}

// Test SetPublicKey
BOOST_AUTO_TEST_CASE(mldsa_set_public_key)
{
    // Generate a full key
    CMLDSAKey full_key;
    BOOST_CHECK(full_key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    // Extract public and secret keys
    std::vector<uint8_t> pubkey = full_key.GetPubKey();
    std::vector<uint8_t> seckey(full_key.GetSecretKey().begin(), full_key.GetSecretKey().end());

    // Create new key and set components separately
    CMLDSAKey reconstructed_key;
    BOOST_CHECK(reconstructed_key.SetSecretKey(seckey, mldsa::ParamSet::MLDSA_65));
    BOOST_CHECK(reconstructed_key.SetPublicKey(pubkey));

    // Verify reconstructed key works
    BOOST_CHECK(reconstructed_key.IsValid());
    BOOST_CHECK_EQUAL(reconstructed_key.GetPubKey().size(), pubkey.size());

    // Test signing with reconstructed key
    uint256 msg = m_rng.rand256();
    std::vector<uint8_t> sig;
    BOOST_CHECK(reconstructed_key.Sign(msg, sig));
    BOOST_CHECK_EQUAL(sig.size(), 3309);
}

// Test PSBT update with mock provider
BOOST_AUTO_TEST_CASE(update_mldsa_psbt)
{
    // Create ML-DSA key
    CMLDSAKey key;
    BOOST_CHECK(key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    XOnlyPubKey output_key{std::vector<uint8_t>(32, 0xAA)};

    // Create signing provider with ML-DSA key
    FlatSigningProvider provider;
    provider.mldsa_keys[output_key] = key;

    // Create TaprootSpendData
    TaprootSpendData spenddata;
    spenddata.internal_key = XOnlyPubKey{std::vector<uint8_t>(32, 0xBB)};
    spenddata.merkle_root = uint256::FromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();

    provider.mldsa_taproot_data[output_key] = std::make_pair(spenddata, 1);

    // Create PSBT with witness v2 input
    PartiallySignedTransaction psbt;
    psbt.tx = CMutableTransaction();
    psbt.tx->vin.resize(1);
    psbt.inputs.resize(1);

    // Create witness v2 scriptPubKey with output_key
    CScript script_pubkey;
    script_pubkey << OP_2 << std::vector<uint8_t>(output_key.begin(), output_key.end());
    psbt.inputs[0].witness_utxo = CTxOut(1000000, script_pubkey);

    // Update PSBT
    BOOST_CHECK(node::UpdatePSBTInputMLDSA(provider, psbt, 0));

    // Verify ML-DSA fields populated
    BOOST_CHECK(!psbt.inputs[0].m_mldsa_pubkey.empty());
    BOOST_CHECK(psbt.inputs[0].m_mldsa_param_set == 65);
    BOOST_CHECK(psbt.inputs[0].m_v2_tap_parity == 1);
}

// Test PSBT signing
BOOST_AUTO_TEST_CASE(sign_mldsa_psbt)
{
    // Generate ML-DSA key and create tapscript
    CMLDSAKey key;
    BOOST_CHECK(key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    XOnlyPubKey output_key{std::vector<uint8_t>(32, 0xAA)};
    XOnlyPubKey internal_key{std::vector<uint8_t>(32, 0xBB)};

    // Create tapscript: <encoded_pk> OP_CHECKMLSIGVERIFY OP_TRUE
    std::vector<uint8_t> encoded_pk = key.GetEncodedPubKey();
    CScript tapscript;
    tapscript << encoded_pk << OP_CHECKMLSIGVERIFY << OP_TRUE;

    // Create signing provider
    FlatSigningProvider provider;
    provider.mldsa_keys[output_key] = key;

    TaprootSpendData spenddata;
    spenddata.internal_key = internal_key;
    spenddata.merkle_root = uint256::FromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();

    // Add tapscript
    std::pair<std::vector<unsigned char>, int> leaf_script{
        {tapscript.begin(), tapscript.end()}, 0xc0
    };
    std::vector<unsigned char> control_block{0xc1};  // leaf_version | parity
    // Copy internal_key bytes to avoid compiler warning about potential overread
    std::vector<unsigned char> internal_key_bytes(internal_key.begin(), internal_key.end());
    control_block.insert(control_block.end(), internal_key_bytes.begin(), internal_key_bytes.end());
    spenddata.scripts[leaf_script].insert(control_block);

    provider.mldsa_taproot_data[output_key] = std::make_pair(spenddata, 1);

    // Create PSBT
    PartiallySignedTransaction psbt;
    psbt.tx = CMutableTransaction();
    psbt.tx->vin.resize(1);
    psbt.tx->vin[0].prevout = COutPoint(Txid::FromUint256(m_rng.rand256()), 0);
    psbt.tx->vout.resize(1);
    psbt.tx->vout[0] = CTxOut(900000, CScript() << OP_TRUE);
    psbt.inputs.resize(1);

    // Set witness_utxo
    CScript script_pubkey;
    script_pubkey << OP_2 << std::vector<uint8_t>(output_key.begin(), output_key.end());
    psbt.inputs[0].witness_utxo = CTxOut(1000000, script_pubkey);

    // Update first
    BOOST_CHECK(node::UpdatePSBTInputMLDSA(provider, psbt, 0));

    // Create precomputed transaction data
    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs = {psbt.inputs[0].witness_utxo};
    txdata.Init(*psbt.tx, std::move(spent_outputs), true);

    // Sign
    BOOST_CHECK(node::SignPSBTInputMLDSA(provider, psbt, 0, &txdata, SIGHASH_ALL));

    // Verify signature was added
    BOOST_CHECK(!psbt.inputs[0].m_mldsa_signature.empty());
    BOOST_CHECK_EQUAL(psbt.inputs[0].m_mldsa_signature.size(), 3309);
}

// Test PSBT finalization
BOOST_AUTO_TEST_CASE(finalize_mldsa_psbt)
{
    // Create a signed PSBT input
    PSBTInput input;

    // Set ML-DSA signature
    input.m_mldsa_signature.resize(3309, 0xCC);

    // Set param set
    input.m_mldsa_param_set = 65;

    // Set internal key (required for finalization)
    std::array<unsigned char, 32> internal_key_bytes;
    std::fill(internal_key_bytes.begin(), internal_key_bytes.end(), 0xAA);
    input.m_tap_internal_key = XOnlyPubKey(internal_key_bytes);

    // Create tapscript
    std::vector<uint8_t> encoded_pk(1952, 0xDD);
    CScript tapscript;
    tapscript << encoded_pk << OP_CHECKMLSIGVERIFY << OP_TRUE;

    // Add to m_tap_scripts
    std::pair<std::vector<unsigned char>, int> leaf_script{
        {tapscript.begin(), tapscript.end()}, 0xc0
    };
    std::vector<unsigned char> control_block{0xc1};  // leaf_version | parity
    control_block.insert(control_block.end(), 32, 0xBB);  // internal_key
    input.m_tap_scripts[leaf_script].insert(control_block);

    // Finalize
    BOOST_CHECK(node::FinalizePSBTInputMLDSA(input, SIGHASH_ALL));

    // Verify witness stack
    BOOST_CHECK_EQUAL(input.final_script_witness.stack.size(), 3);
    BOOST_CHECK_EQUAL(input.final_script_witness.stack[0].size(), 3310);  // signature + sighash byte
    BOOST_CHECK_EQUAL(input.final_script_witness.stack[1], std::vector<uint8_t>(tapscript.begin(), tapscript.end()));  // tapscript
    BOOST_CHECK_EQUAL(input.final_script_witness.stack[2].size(), 33);  // control block
}

#endif // ENABLE_MLDSA

BOOST_AUTO_TEST_SUITE_END()
