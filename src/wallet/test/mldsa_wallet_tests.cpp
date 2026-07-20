// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <hash.h>
#include <key_io.h>
#include <mldsakey.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <test/util/zk_test_helpers.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

using zk_test::uint256S;  // Import uint256S helper for test hex strings

BOOST_FIXTURE_TEST_SUITE(mldsa_wallet_tests, TestingSetup)

#ifdef ENABLE_MLDSA

//
// Test 1: ML-DSA Key Generation and Storage
//
BOOST_AUTO_TEST_CASE(mldsa_key_generation)
{
    // Create a test wallet
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    BOOST_REQUIRE(wallet != nullptr);

    // Generate ML-DSA-65 keypair
    CMLDSAKey key;
    BOOST_CHECK(key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    // Verify key sizes (FIPS 204 standard sizes for ML-DSA-65)
    std::vector<uint8_t> pubkey = key.GetPubKey();
    const MLDSASecretKey& secure_seckey = key.GetSecretKey();

    BOOST_CHECK_EQUAL(pubkey.size(), 1952);  // ML-DSA-65 public key
    BOOST_CHECK_EQUAL(secure_seckey.size(), 4032);  // ML-DSA-65 secret key

    // Verify encoded public key format (alg_id + param_set + varint + pubkey)
    std::vector<uint8_t> encoded = key.GetEncodedPubKey();
    BOOST_CHECK_EQUAL(encoded[0], 0x01);  // ALG_ID_MLDSA
    BOOST_CHECK_EQUAL(encoded[1], 0x41);  // PARAM_SET_MLDSA_65 (65 decimal = 0x41)
}

//
// Test 2: Wallet Database Storage (Unencrypted)
//
BOOST_AUTO_TEST_CASE(mldsa_wallet_storage_unencrypted)
{
    // Create test wallet
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);

    // Generate ML-DSA key
    CMLDSAKey key;
    BOOST_REQUIRE(key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    std::vector<uint8_t> pubkey = key.GetPubKey();
    const MLDSASecretKey& secure_seckey = key.GetSecretKey();
    std::vector<uint8_t> seckey(secure_seckey.begin(), secure_seckey.end());

    // Compute pk_hash (used as database index)
    uint256 pk_hash = Hash(pubkey);

    // Create metadata
    CKeyMetadata metadata;
    metadata.nCreateTime = GetTime();
    metadata.nVersion = CKeyMetadata::CURRENT_VERSION;

    // Store key in wallet database
    WalletBatch batch(wallet->GetDatabase());
    BOOST_CHECK(batch.WriteMLDSAKey(pk_hash, pubkey, seckey, 0x41, metadata));

    // Note: ML-DSA uses separate MLDSA_KEYMETA key (not in LEGACY_TYPES)
    // to avoid conflicts with descriptor wallet validation.
    // Full persistence testing in functional tests (wallet_pq_mldsa.py).
}

//
// Test 3: Bech32m Witness V2 Address Encoding
//
BOOST_AUTO_TEST_CASE(witness_v2_bech32m_encoding)
{
    SelectParams(ChainType::REGTEST);

    // Create a 32-byte output pubkey (simulating Taproot output)
    uint256 output_pubkey_hash = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    WitnessV2Taproot tap;
    std::copy(output_pubkey_hash.begin(), output_pubkey_hash.end(), tap.begin());

    // Encode to bech32m address
    std::string address = EncodeDestination(tap);

    // Verify address format
    BOOST_CHECK(address.find("bcrt1z") == 0);  // regtest witness v2 prefix (z = version 2)
    BOOST_CHECK_EQUAL(address.length(), 64);    // bech32m v2 address length

    // Decode address
    CTxDestination decoded = DecodeDestination(address);
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(decoded));

    // Verify roundtrip
    WitnessV2Taproot decoded_tap = std::get<WitnessV2Taproot>(decoded);
    BOOST_CHECK(decoded_tap == tap);
}

//
// Test 4: Bech32m Witness V2 Address Decoding
//
BOOST_AUTO_TEST_CASE(witness_v2_bech32m_decoding)
{
    SelectParams(ChainType::REGTEST);

    // Create a witness v2 destination with all zeros
    uint256 expected_zeros = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
    WitnessV2Taproot tap;
    std::copy(expected_zeros.begin(), expected_zeros.end(), tap.begin());

    // Encode to bech32m address
    std::string test_address = EncodeDestination(tap);
    BOOST_CHECK(test_address.find("bcrt1z") == 0);  // Verify it's a witness v2 address

    // Decode the address we just created
    CTxDestination decoded = DecodeDestination(test_address);
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(decoded));

    // Verify it's 32 bytes
    WitnessV2Taproot decoded_tap = std::get<WitnessV2Taproot>(decoded);
    BOOST_CHECK_EQUAL(decoded_tap.size(), 32);

    // Verify roundtrip: decoded value matches original
    std::vector<uint8_t> tap_bytes(decoded_tap.begin(), decoded_tap.end());
    std::vector<uint8_t> expected_bytes(expected_zeros.begin(), expected_zeros.end());
    BOOST_CHECK(tap_bytes == expected_bytes);
}

//
// Test 5: Script Solver Recognition
//
BOOST_AUTO_TEST_CASE(witness_v2_solver)
{
    // Create witness v2 scriptPubKey: OP_2 <32-byte-program>
    uint256 program = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    CScript scriptPubKey;
    scriptPubKey << OP_2 << ToByteVector(program);

    // Solve script
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(scriptPubKey, solutions);

    // Verify it's recognized as WITNESS_V2_TAPROOT
    BOOST_CHECK(type == TxoutType::WITNESS_V2_TAPROOT);
    BOOST_CHECK_EQUAL(solutions.size(), 1);
    BOOST_CHECK_EQUAL(solutions[0].size(), 32);
}

//
// Test 6: GetScriptForDestination
//
BOOST_AUTO_TEST_CASE(witness_v2_get_script)
{
    // Create WitnessV2Taproot destination
    uint256 hash = uint256S("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    WitnessV2Taproot tap;
    std::copy(hash.begin(), hash.end(), tap.begin());

    // Get scriptPubKey
    CScript script = GetScriptForDestination(tap);

    // Verify format: OP_2 <32-byte-program>
    BOOST_CHECK_EQUAL(script.size(), 34);  // 1 (OP_2) + 1 (push 32) + 32 (data)
    BOOST_CHECK_EQUAL(script[0], OP_2);
    BOOST_CHECK_EQUAL(script[1], 32);  // Push 32 bytes
}

//
// Test 7: ExtractDestination
//
BOOST_AUTO_TEST_CASE(witness_v2_extract_destination)
{
    // Create witness v2 scriptPubKey
    uint256 program = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    CScript scriptPubKey;
    scriptPubKey << OP_2 << ToByteVector(program);

    // Extract destination
    CTxDestination dest;
    BOOST_CHECK(ExtractDestination(scriptPubKey, dest));
    BOOST_CHECK(std::holds_alternative<WitnessV2Taproot>(dest));

    // Verify extracted value matches original
    WitnessV2Taproot extracted = std::get<WitnessV2Taproot>(dest);
    std::vector<uint8_t> extracted_bytes(extracted.begin(), extracted.end());
    std::vector<uint8_t> program_bytes(program.begin(), program.end());
    BOOST_CHECK(extracted_bytes == program_bytes);
}

//
// Test 8: IsValidDestination
//
BOOST_AUTO_TEST_CASE(witness_v2_is_valid_destination)
{
    uint256 hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    WitnessV2Taproot tap;
    std::copy(hash.begin(), hash.end(), tap.begin());

    CTxDestination dest = tap;
    BOOST_CHECK(IsValidDestination(dest));
}

//
// Test 9: Different Parameter Sets
//
BOOST_AUTO_TEST_CASE(mldsa_parameter_sets)
{
    // Test ML-DSA-44
    {
        CMLDSAKey key;
        BOOST_CHECK(key.MakeNewKey(mldsa::ParamSet::MLDSA_44));
        BOOST_CHECK_EQUAL(key.GetPubKey().size(), 1312);
        BOOST_CHECK_EQUAL(key.GetSecretKey().size(), 2560);
    }

    // Test ML-DSA-65
    {
        CMLDSAKey key;
        BOOST_CHECK(key.MakeNewKey(mldsa::ParamSet::MLDSA_65));
        BOOST_CHECK_EQUAL(key.GetPubKey().size(), 1952);
        BOOST_CHECK_EQUAL(key.GetSecretKey().size(), 4032);
    }

    // Test ML-DSA-87
    {
        CMLDSAKey key;
        BOOST_CHECK(key.MakeNewKey(mldsa::ParamSet::MLDSA_87));
        BOOST_CHECK_EQUAL(key.GetPubKey().size(), 2592);
        BOOST_CHECK_EQUAL(key.GetSecretKey().size(), 4896);
    }
}

//
// Test 10: Mainnet vs Regtest Address Encoding
//
BOOST_AUTO_TEST_CASE(witness_v2_network_prefixes)
{
    uint256 hash = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    WitnessV2Taproot tap;
    std::copy(hash.begin(), hash.end(), tap.begin());

    // Test regtest
    SelectParams(ChainType::REGTEST);
    std::string regtest_addr = EncodeDestination(tap);
    BOOST_CHECK(regtest_addr.find("bcrt1z") == 0);  // v2 uses 'z'

    // Test mainnet
    SelectParams(ChainType::MAIN);
    std::string mainnet_addr = EncodeDestination(tap);
    BOOST_CHECK(mainnet_addr.find("bc1z") == 0);  // v2 uses 'z'

    // Addresses should have same data, but different checksums (checksums depend on HRP)
    // Bech32m checksum is last 6 chars, so compare data only (excluding prefix and checksum)
    // "bcrt1z" = 6 chars, "bc1z" = 4 chars
    BOOST_CHECK(regtest_addr.substr(6, regtest_addr.length() - 12) ==
                mainnet_addr.substr(4, mainnet_addr.length() - 10));
}

//
// Test 11: ML-DSA Key Encryption
//
BOOST_AUTO_TEST_CASE(mldsa_key_encryption)
{
    // Create test wallet
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);

    // Verify wallet is not encrypted initially
    BOOST_CHECK(!wallet->IsCrypted());

    // Generate ML-DSA key before encryption
    CMLDSAKey key;
    BOOST_REQUIRE(key.MakeNewKey(mldsa::ParamSet::MLDSA_65));

    std::vector<uint8_t> pubkey = key.GetPubKey();
    const MLDSASecretKey& secure_seckey = key.GetSecretKey();
    std::vector<uint8_t> seckey(secure_seckey.begin(), secure_seckey.end());

    // Compute pk_hash
    uint256 pk_hash = Hash(pubkey);

    // Create metadata
    CKeyMetadata metadata;
    metadata.nCreateTime = GetTime();
    metadata.nVersion = CKeyMetadata::CURRENT_VERSION;

    // Store key in wallet database (unencrypted)
    WalletBatch batch(wallet->GetDatabase());
    BOOST_CHECK(batch.WriteMLDSAKey(pk_hash, pubkey, seckey, 0x41, metadata));

    // Verify unencrypted key can be loaded
    std::string err;
    DataStream key_ds, value_ds;
    key_ds << DBKeys::MLDSA_KEY << pk_hash;
    std::pair<std::vector<unsigned char>, uint256> key_data;
    BOOST_CHECK(batch.ReadFromBatch(std::make_pair(DBKeys::MLDSA_KEY, pk_hash), key_data));

    // Encrypt wallet
    CKeyingMaterial master_key;
    master_key.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(master_key);

    // Create encrypted batch
    WalletBatch encrypted_batch(wallet->GetDatabase());
    BOOST_CHECK(encrypted_batch.TxnBegin());

    // Encrypt the ML-DSA key
    CKeyingMaterial secret{seckey.begin(), seckey.end()};
    std::vector<unsigned char> crypted_secret;
    uint256 pk_hash_for_iv = Hash(pubkey);
    BOOST_CHECK(EncryptSecret(master_key, secret, pk_hash_for_iv, crypted_secret));

    // Write encrypted key
    BOOST_CHECK(encrypted_batch.WriteCryptedMLDSAKey(pk_hash, pubkey, crypted_secret, 0x41, metadata));
    BOOST_CHECK(encrypted_batch.TxnCommit());

    // Verify encrypted key exists
    std::pair<std::vector<unsigned char>, uint256> encrypted_key_data;
    BOOST_CHECK(encrypted_batch.ReadFromBatch(std::make_pair(DBKeys::CRYPTED_MLDSA_KEY, pk_hash), encrypted_key_data));

    // Verify encrypted key has different content than original
    BOOST_CHECK(encrypted_key_data.first != key_data.first);

    // Verify encrypted key is longer (includes encryption overhead)
    // ML-DSA-65 seckey is 4032 bytes, encrypted version should be larger
    // Parse to verify structure
    const auto& encrypted_vchData = encrypted_key_data.first;
    BOOST_CHECK(encrypted_vchData.size() > 9);  // At least: level + pk_len + some pubkey

    size_t pos = 0;
    uint8_t level = encrypted_vchData[pos++];
    BOOST_CHECK_EQUAL(level, 0x41);

    // Read public key length
    uint32_t pk_len = static_cast<uint32_t>(encrypted_vchData[pos]) |
                     (static_cast<uint32_t>(encrypted_vchData[pos + 1]) << 8) |
                     (static_cast<uint32_t>(encrypted_vchData[pos + 2]) << 16) |
                     (static_cast<uint32_t>(encrypted_vchData[pos + 3]) << 24);
    pos += 4;
    BOOST_CHECK_EQUAL(pk_len, 1952);  // ML-DSA-65 public key

    // Verify public key is still plaintext
    std::vector<uint8_t> stored_pubkey(encrypted_vchData.begin() + pos, encrypted_vchData.begin() + pos + pk_len);
    BOOST_CHECK(stored_pubkey == pubkey);
    pos += pk_len;

    // Remaining data should be encrypted secret key
    size_t encrypted_sk_len = encrypted_vchData.size() - pos;
    BOOST_CHECK(encrypted_sk_len > 0);
    BOOST_CHECK(encrypted_sk_len != seckey.size());  // Should be different due to encryption

    // Verify original unencrypted key was erased (WriteCryptedMLDSAKey should erase it)
    std::pair<std::vector<unsigned char>, uint256> erased_check;
    BOOST_CHECK(!encrypted_batch.ReadFromBatch(std::make_pair(DBKeys::MLDSA_KEY, pk_hash), erased_check));
}

#else  // !ENABLE_MLDSA

BOOST_AUTO_TEST_CASE(mldsa_disabled)
{
    // If liboqs is not available, just verify this compiles
    BOOST_CHECK(true);
}

#endif  // ENABLE_MLDSA

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
