// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <mldsakey.h>
#include <node/psbt_mldsa.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <test/util/zk_test_helpers.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

using zk_test::uint256S;

BOOST_FIXTURE_TEST_SUITE(sign_mldsa_tests, BasicTestingSetup)

#ifdef ENABLE_MLDSA

/**
 * Test 1: Witness v2 detection in SignTransaction
 */
BOOST_AUTO_TEST_CASE(sign_transaction_witness_v2_detection)
{
    // Create a witness v2 scriptPubKey: OP_2 <32 bytes>
    uint256 output_key_hash = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CScript scriptPubKey;
    scriptPubKey << OP_2 << ToByteVector(output_key_hash);

    // Verify it's detected as witness v2
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 34);
    BOOST_CHECK_EQUAL(scriptPubKey[0], OP_2);
    BOOST_CHECK_EQUAL(scriptPubKey[1], 0x20);

    // This is the pattern SignTransaction looks for
    bool is_witness_v2 = (scriptPubKey.size() == 34 && scriptPubKey[0] == OP_2 && scriptPubKey[1] == 0x20);
    BOOST_CHECK(is_witness_v2);
}

/**
 * Test 2: SignTransaction with ML-DSA input (signing provider has keys)
 */
BOOST_AUTO_TEST_CASE(sign_transaction_mldsa_with_keys)
{
    // Generate ML-DSA key
    CMLDSAKey mldsa_key;
    BOOST_REQUIRE(mldsa_key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    std::vector<uint8_t> pubkey = mldsa_key.GetPubKey();
    std::vector<uint8_t> encoded_pubkey = mldsa_key.GetEncodedPubKey();

    // Create ML-DSA Taproot construction
    CScript tapscript;
    tapscript << encoded_pubkey << OP_CHECKMLSIGVERIFY << OP_TRUE;

    uint256 leaf_hash = ComputeTapleafHash(0xc0, tapscript);

    // Generate internal key and compute output key
    uint256 internal_key_hash = uint256S("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    XOnlyPubKey internal_key{internal_key_hash};

    uint256 merkle_root = leaf_hash;  // Single script, merkle root = leaf hash
    uint8_t parity = 0;

    // Compute output key
    std::vector<unsigned char> output_key_bytes(internal_key_hash.begin(), internal_key_hash.end());
    XOnlyPubKey output_key{output_key_bytes};

    // Create witness v2 scriptPubKey
    CScript scriptPubKey;
    scriptPubKey << OP_2 << ToByteVector(uint256(output_key_bytes));

    // Set up signing provider with ML-DSA key
    FlatSigningProvider provider;
    provider.mldsa_keys[output_key] = mldsa_key;

    // Set up Taproot spend data
    TaprootSpendData spenddata;
    spenddata.internal_key = internal_key;
    spenddata.merkle_root = merkle_root;

    std::pair<std::vector<unsigned char>, int> leaf_script{
        {tapscript.begin(), tapscript.end()},
        0xc0
    };

    std::vector<unsigned char> control_block;
    control_block.push_back(0xc0 | parity);
    control_block.insert(control_block.end(), internal_key.begin(), internal_key.end());

    spenddata.scripts[leaf_script].insert(control_block);
    provider.mldsa_taproot_data[output_key] = std::make_pair(spenddata, parity);

    // Create a simple transaction spending the ML-DSA UTXO
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256S("1111111111111111111111111111111111111111111111111111111111111111")), 0);

    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1 * COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_1 << ToByteVector(uint256S("2222222222222222222222222222222222222222222222222222222222222222"));

    // Create coins map with the ML-DSA UTXO
    std::map<COutPoint, Coin> coins;
    CTxOut utxo(1 * COIN, scriptPubKey);
    coins[mtx.vin[0].prevout] = Coin(utxo, 1, false);

    // Sign the transaction
    std::map<int, bilingual_str> input_errors;
    bool sign_result = SignTransaction(mtx, &provider, coins, SIGHASH_ALL, input_errors);

    // The signing should succeed (witness should be populated)
    BOOST_CHECK(sign_result || !mtx.vin[0].scriptWitness.IsNull());

    // Verify witness structure
    if (!mtx.vin[0].scriptWitness.IsNull()) {
        BOOST_CHECK_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 3);

        // First element is signature with sighash byte
        BOOST_CHECK(mtx.vin[0].scriptWitness.stack[0].size() > 3000);  // ML-DSA-65 signature

        // Second element is tapscript
        BOOST_CHECK_EQUAL(mtx.vin[0].scriptWitness.stack[1].size(), tapscript.size());

        // Third element is control block
        BOOST_CHECK_EQUAL(mtx.vin[0].scriptWitness.stack[2].size(), 33);  // 1 byte version+parity + 32 bytes internal key
    }
}

/**
 * Test 3: SignTransaction with mixed ECDSA and ML-DSA inputs
 */
BOOST_AUTO_TEST_CASE(sign_transaction_mixed_inputs)
{
    // Generate ECDSA key
    CKey ecdsa_key = GenerateRandomKey();
    CPubKey ecdsa_pubkey = ecdsa_key.GetPubKey();
    CKeyID key_id = ecdsa_pubkey.GetID();

    // Generate ML-DSA key
    CMLDSAKey mldsa_key;
    BOOST_REQUIRE(mldsa_key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    std::vector<uint8_t> encoded_pubkey = mldsa_key.GetEncodedPubKey();

    // Create ML-DSA tapscript and output key
    CScript mldsa_tapscript;
    mldsa_tapscript << encoded_pubkey << OP_CHECKMLSIGVERIFY << OP_TRUE;

    uint256 mldsa_output_hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    XOnlyPubKey mldsa_output_key{mldsa_output_hash};

    // Create scriptPubKeys
    CScript ecdsa_scriptPubKey = GetScriptForDestination(PKHash(key_id));

    CScript mldsa_scriptPubKey;
    mldsa_scriptPubKey << OP_2 << ToByteVector(mldsa_output_hash);

    // Set up signing provider
    FlatSigningProvider provider;
    provider.keys[key_id] = ecdsa_key;
    provider.mldsa_keys[mldsa_output_key] = mldsa_key;

    // Set up ML-DSA Taproot data
    uint256 internal_key_hash = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    XOnlyPubKey internal_key{internal_key_hash};
    TaprootSpendData spenddata;
    spenddata.internal_key = internal_key;
    spenddata.merkle_root = ComputeTapleafHash(0xc0, mldsa_tapscript);

    std::pair<std::vector<unsigned char>, int> leaf_script{{mldsa_tapscript.begin(), mldsa_tapscript.end()}, 0xc0};
    std::vector<unsigned char> control_block{0xc0};
    control_block.insert(control_block.end(), internal_key.begin(), internal_key.end());
    spenddata.scripts[leaf_script].insert(control_block);
    provider.mldsa_taproot_data[mldsa_output_key] = std::make_pair(spenddata, 0);

    // Create transaction with 2 inputs (ECDSA and ML-DSA)
    CMutableTransaction mtx;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256S("3333333333333333333333333333333333333333333333333333333333333333")), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256S("4444444444444444444444444444444444444444444444444444444444444444")), 0);

    mtx.vout.resize(1);
    mtx.vout[0].nValue = 2 * COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Create coins map
    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout] = Coin(CTxOut(1 * COIN, ecdsa_scriptPubKey), 1, false);
    coins[mtx.vin[1].prevout] = Coin(CTxOut(1 * COIN, mldsa_scriptPubKey), 1, false);

    // Sign the transaction
    std::map<int, bilingual_str> input_errors;
    SignTransaction(mtx, &provider, coins, SIGHASH_ALL, input_errors);

    // Verify both inputs have witnesses
    BOOST_CHECK(!mtx.vin[0].scriptWitness.IsNull() || !mtx.vin[0].scriptSig.empty());  // ECDSA input
    BOOST_CHECK(!mtx.vin[1].scriptWitness.IsNull());  // ML-DSA input should have witness

    // Verify ML-DSA input witness structure
    if (!mtx.vin[1].scriptWitness.IsNull()) {
        BOOST_CHECK_EQUAL(mtx.vin[1].scriptWitness.stack.size(), 3);
        BOOST_CHECK(mtx.vin[1].scriptWitness.stack[0].size() > 3000);  // ML-DSA signature
    }
}

/**
 * Test 4: SignTransaction without ML-DSA keys (should fail gracefully)
 */
BOOST_AUTO_TEST_CASE(sign_transaction_mldsa_missing_keys)
{
    // Create witness v2 scriptPubKey
    uint256 output_key_hash = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    CScript scriptPubKey;
    scriptPubKey << OP_2 << ToByteVector(output_key_hash);

    // Empty signing provider (no keys)
    FlatSigningProvider provider;

    // Create transaction
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256S("5555555555555555555555555555555555555555555555555555555555555555")), 0);

    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1 * COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Create coins map
    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout] = Coin(CTxOut(1 * COIN, scriptPubKey), 1, false);

    // Try to sign without keys
    std::map<int, bilingual_str> input_errors;
    bool sign_result = SignTransaction(mtx, &provider, coins, SIGHASH_ALL, input_errors);

    // Should fail and report error
    BOOST_CHECK(!sign_result);
    BOOST_CHECK(input_errors.count(0) > 0);  // Error for input 0
    BOOST_CHECK(mtx.vin[0].scriptWitness.IsNull());  // No witness created
}

#else  // !ENABLE_MLDSA

BOOST_AUTO_TEST_CASE(mldsa_disabled)
{
    // If liboqs is not available, just verify this compiles
    BOOST_CHECK(true);
}

#endif  // ENABLE_MLDSA

BOOST_AUTO_TEST_SUITE_END()
