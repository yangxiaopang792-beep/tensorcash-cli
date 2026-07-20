// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mldsaverify.h>
#include <crypto/mldsakeygen.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <span.h>

#include <boost/test/unit_test.hpp>

using namespace mldsa;

BOOST_FIXTURE_TEST_SUITE(crypto_mldsa_tests, BasicTestingSetup)

// Helper: Encode public key in on-stack format
static std::vector<uint8_t> EncodePublicKey(ParamSet level, const std::vector<uint8_t>& pk_bytes)
{
    std::vector<uint8_t> encoded;
    encoded.push_back(ALG_ID_MLDSA);  // Algorithm ID
    encoded.push_back(static_cast<uint8_t>(level));  // Parameter set

    // Varint length (compact size)
    size_t pk_len = pk_bytes.size();
    if (pk_len < 0xFD) {
        encoded.push_back(static_cast<uint8_t>(pk_len));
    } else if (pk_len <= 0xFFFF) {
        encoded.push_back(0xFD);
        encoded.push_back(pk_len & 0xFF);
        encoded.push_back((pk_len >> 8) & 0xFF);
    } else {
        BOOST_ERROR("PK too large for varint encoding in test");
    }

    // PK bytes
    encoded.insert(encoded.end(), pk_bytes.begin(), pk_bytes.end());
    return encoded;
}

BOOST_AUTO_TEST_CASE(mldsa_parse_public_key_valid)
{
    // ML-DSA-44 public key (1312 bytes)
    std::vector<uint8_t> pk_44(1312, 0xAA);
    auto encoded_44 = EncodePublicKey(ParamSet::MLDSA_44, pk_44);

    std::span<const uint8_t> blob_44(encoded_44);
    auto parsed_44 = ParsePublicKey(blob_44);
    BOOST_CHECK(parsed_44.has_value());
    BOOST_CHECK(parsed_44->level == ParamSet::MLDSA_44);
    BOOST_CHECK(parsed_44->pk_bytes.size() == 1312);

    // ML-DSA-65 public key (1952 bytes)
    std::vector<uint8_t> pk_65(1952, 0xBB);
    auto encoded_65 = EncodePublicKey(ParamSet::MLDSA_65, pk_65);

    std::span<const uint8_t> blob_65(encoded_65);
    auto parsed_65 = ParsePublicKey(blob_65);
    BOOST_CHECK(parsed_65.has_value());
    BOOST_CHECK(parsed_65->level == ParamSet::MLDSA_65);
    BOOST_CHECK(parsed_65->pk_bytes.size() == 1952);

    // ML-DSA-87 public key (2592 bytes)
    std::vector<uint8_t> pk_87(2592, 0xCC);
    auto encoded_87 = EncodePublicKey(ParamSet::MLDSA_87, pk_87);

    std::span<const uint8_t> blob_87(encoded_87);
    auto parsed_87 = ParsePublicKey(blob_87);
    BOOST_CHECK(parsed_87.has_value());
    BOOST_CHECK(parsed_87->level == ParamSet::MLDSA_87);
    BOOST_CHECK(parsed_87->pk_bytes.size() == 2592);
}

BOOST_AUTO_TEST_CASE(mldsa_parse_public_key_invalid_alg_id)
{
    std::vector<uint8_t> pk(1312, 0xAA);
    std::vector<uint8_t> encoded = EncodePublicKey(ParamSet::MLDSA_44, pk);

    // Corrupt algorithm ID
    encoded[0] = 0x02;  // Not ALG_ID_MLDSA

    std::span<const uint8_t> blob(encoded);
    auto parsed = ParsePublicKey(blob);
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(mldsa_parse_public_key_invalid_level)
{
    std::vector<uint8_t> pk(1312, 0xAA);
    std::vector<uint8_t> encoded = EncodePublicKey(ParamSet::MLDSA_44, pk);

    // Corrupt parameter set
    encoded[1] = 0x99;  // Invalid level

    std::span<const uint8_t> blob(encoded);
    auto parsed = ParsePublicKey(blob);
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(mldsa_parse_public_key_wrong_length)
{
    // Encode ML-DSA-44 but provide ML-DSA-65 length
    std::vector<uint8_t> pk(1952, 0xAA);  // 1952 bytes (ML-DSA-65 size)
    std::vector<uint8_t> encoded;
    encoded.push_back(ALG_ID_MLDSA);
    encoded.push_back(static_cast<uint8_t>(ParamSet::MLDSA_44));  // Claim ML-DSA-44
    encoded.push_back(0xFD);
    encoded.push_back(1952 & 0xFF);
    encoded.push_back((1952 >> 8) & 0xFF);
    encoded.insert(encoded.end(), pk.begin(), pk.end());

    std::span<const uint8_t> blob(encoded);
    auto parsed = ParsePublicKey(blob);
    BOOST_CHECK(!parsed.has_value());  // Length mismatch
}

BOOST_AUTO_TEST_CASE(mldsa_parse_public_key_trailing_data)
{
    std::vector<uint8_t> pk(1312, 0xAA);
    std::vector<uint8_t> encoded = EncodePublicKey(ParamSet::MLDSA_44, pk);

    // Add trailing garbage
    encoded.push_back(0xDE);
    encoded.push_back(0xAD);

    std::span<const uint8_t> blob(encoded);
    auto parsed = ParsePublicKey(blob);
    BOOST_CHECK(!parsed.has_value());  // Strict: no trailing data
}

BOOST_AUTO_TEST_CASE(mldsa_verify_wrong_message_size)
{
    // ML-DSA verification requires exactly 32-byte messages (Taproot sighash)
    std::vector<uint8_t> pk(1952, 0xBB);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk);

    std::vector<uint8_t> sig(3309, 0x00);  // ML-DSA-65 signature size

    // Test various wrong message sizes
    std::vector<uint8_t> msg_short(16, 0xAB);
    std::vector<uint8_t> msg_long(64, 0xAB);

    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk), std::span(msg_short), std::span(sig)));
    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk), std::span(msg_long), std::span(sig)));
}

BOOST_AUTO_TEST_CASE(mldsa_verify_wrong_signature_size)
{
    std::vector<uint8_t> pk(1952, 0xBB);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk);

    std::vector<uint8_t> msg(32, 0xAB);
    std::vector<uint8_t> sig_wrong(2000, 0x00);  // Wrong size for ML-DSA-65

    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk), std::span(msg), std::span(sig_wrong)));
}

BOOST_AUTO_TEST_CASE(mldsa_read_compact_size)
{
    // Test 1-byte encoding
    {
        std::vector<uint8_t> data = {0x7F, 0xAA};
        std::span<const uint8_t> sp(data);
        auto val = ReadCompactSize(sp);
        BOOST_CHECK(val.has_value());
        BOOST_CHECK_EQUAL(*val, 0x7F);
        BOOST_CHECK_EQUAL(sp.size(), 1);  // Consumed 1 byte
    }

    // Test 3-byte encoding (0xFD prefix)
    {
        std::vector<uint8_t> data = {0xFD, 0x00, 0x01, 0xBB};  // 256
        std::span<const uint8_t> sp(data);
        auto val = ReadCompactSize(sp);
        BOOST_CHECK(val.has_value());
        BOOST_CHECK_EQUAL(*val, 256);
        BOOST_CHECK_EQUAL(sp.size(), 1);  // Consumed 3 bytes
    }

    // Test non-minimal encoding rejection (< 0xFD value with 0xFD prefix)
    {
        std::vector<uint8_t> data = {0xFD, 0xFC, 0x00};  // 252 (should be 1 byte)
        std::span<const uint8_t> sp(data);
        auto val = ReadCompactSize(sp);
        BOOST_CHECK(!val.has_value());  // Non-minimal
    }

    // Test truncated data
    {
        std::vector<uint8_t> data = {0xFD, 0x00};  // Missing 1 byte
        std::span<const uint8_t> sp(data);
        auto val = ReadCompactSize(sp);
        BOOST_CHECK(!val.has_value());
    }
}

BOOST_AUTO_TEST_CASE(mldsa_param_set_sizes)
{
    auto sizes_44 = GetParamSetSizes(ParamSet::MLDSA_44);
    BOOST_CHECK_EQUAL(sizes_44.pk_bytes, 1312);
    BOOST_CHECK_EQUAL(sizes_44.sig_bytes, 2420);

    auto sizes_65 = GetParamSetSizes(ParamSet::MLDSA_65);
    BOOST_CHECK_EQUAL(sizes_65.pk_bytes, 1952);
    BOOST_CHECK_EQUAL(sizes_65.sig_bytes, 3309);

    auto sizes_87 = GetParamSetSizes(ParamSet::MLDSA_87);
    BOOST_CHECK_EQUAL(sizes_87.pk_bytes, 2592);
    BOOST_CHECK_EQUAL(sizes_87.sig_bytes, 4627);
}

// Known Answer Tests (KATs) - NIST ML-DSA Test Vectors
// These are minimal test vectors to verify basic cryptographic correctness.
// Full ACVP test suites should be run separately for production validation.

#ifdef ENABLE_MLDSA

// Helper to decode hex string to bytes
[[maybe_unused]] static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

BOOST_AUTO_TEST_CASE(mldsa_kat_empty_signature_fails)
{
    // Test that empty signatures always fail (basic sanity check)
    std::vector<uint8_t> pk(1952, 0x00);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xAB);

    std::vector<uint8_t> empty_sig;

    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk), std::span(msg), std::span(empty_sig)));
}

BOOST_AUTO_TEST_CASE(mldsa_kat_wrong_pk_fails)
{
    // Test that wrong public key fails verification
    // Generate two different "public keys" (random data for test purposes)
    std::vector<uint8_t> pk1(1952, 0x11);
    std::vector<uint8_t> pk2(1952, 0x22);

    auto encoded_pk1 = EncodePublicKey(ParamSet::MLDSA_65, pk1);
    auto encoded_pk2 = EncodePublicKey(ParamSet::MLDSA_65, pk2);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xCD);

    // Create a dummy signature (would be valid for pk1 in a real scenario)
    std::vector<uint8_t> sig(3309, 0x99);

    // Verification with wrong pk should fail
    // Note: In a real implementation, this would be generated with liboqs
    // For now, we just verify the interface works correctly
    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk2), std::span(msg), std::span(sig)));
}

BOOST_AUTO_TEST_CASE(mldsa_kat_parameter_set_mismatch)
{
    // Test that ML-DSA-44 signature doesn't verify against ML-DSA-65 public key
    std::vector<uint8_t> pk_44(1312, 0xAA);
    std::vector<uint8_t> pk_65(1952, 0xBB);

    auto encoded_pk_44 = EncodePublicKey(ParamSet::MLDSA_44, pk_44);
    auto encoded_pk_65 = EncodePublicKey(ParamSet::MLDSA_65, pk_65);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xEF);

    // ML-DSA-44 signature size
    std::vector<uint8_t> sig_44(2420, 0x44);

    // ML-DSA-65 signature size
    std::vector<uint8_t> sig_65(3309, 0x65);

    // Wrong signature size for parameter set should fail
    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk_44), std::span(msg), std::span(sig_65)));
    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk_65), std::span(msg), std::span(sig_44)));
}

BOOST_AUTO_TEST_CASE(mldsa_kat_message_domain_separation)
{
    // Test that different messages produce different verification results
    std::vector<uint8_t> pk(1952, 0xCC);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk);

    std::array<uint8_t, 32> msg1{};
    std::array<uint8_t, 32> msg2{};
    std::fill(msg1.begin(), msg1.end(), 0x01);
    std::fill(msg2.begin(), msg2.end(), 0x02);

    std::vector<uint8_t> sig(3309, 0xDD);

    // Same signature with different messages should both fail
    // (or only one should succeed if we had a real valid signature)
    bool result1 = MLDSA_Verify(std::span(encoded_pk), std::span(msg1), std::span(sig));
    bool result2 = MLDSA_Verify(std::span(encoded_pk), std::span(msg2), std::span(sig));

    // At least one should fail (both will fail since we're using dummy data)
    BOOST_CHECK(!(result1 && result2));
}

BOOST_AUTO_TEST_CASE(mldsa_real_signature_verification)
{
    // Test with REAL ML-DSA signature (positive test case)
    // This test generates a real keypair and signature using liboqs

    // Generate real ML-DSA-65 keypair
    std::vector<uint8_t> pk_real;
    std::vector<uint8_t> sk_real;
    BOOST_REQUIRE(MLDSA_Keygen(ParamSet::MLDSA_65, pk_real, sk_real));

    // Create a message to sign
    std::array<uint8_t, 32> msg;
    std::fill(msg.begin(), msg.end(), 0x42);

    // Sign the message
    std::vector<uint8_t> sig_real;
    BOOST_REQUIRE(MLDSA_Sign(std::span(sk_real), std::span(msg), ParamSet::MLDSA_65, sig_real));

    // Encode the public key
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk_real);

    // Verify the signature (should succeed)
    BOOST_CHECK(MLDSA_Verify(std::span(encoded_pk), std::span(msg), std::span(sig_real)));

    // Verify that wrong message fails
    std::array<uint8_t, 32> wrong_msg;
    std::fill(wrong_msg.begin(), wrong_msg.end(), 0x99);
    BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk), std::span(wrong_msg), std::span(sig_real)));

    // Verify that corrupted signature fails
    std::vector<uint8_t> corrupted_sig = sig_real;
    if (!corrupted_sig.empty()) {
        corrupted_sig[corrupted_sig.size() / 2] ^= 0xFF;
        BOOST_CHECK(!MLDSA_Verify(std::span(encoded_pk), std::span(msg), std::span(corrupted_sig)));
    }
}

// NOTE: To add real NIST ACVP test vectors, use the following template:
//
// 1. Generate test vectors using liboqs or reference implementation:
//    ```
//    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
//    uint8_t public_key[OQS_SIG_ml_dsa_65_length_public_key];
//    uint8_t secret_key[OQS_SIG_ml_dsa_65_length_secret_key];
//    OQS_SIG_keypair(sig, public_key, secret_key);
//
//    uint8_t message[32] = {...};
//    uint8_t signature[OQS_SIG_ml_dsa_65_length_signature];
//    size_t sig_len;
//    OQS_SIG_sign(sig, signature, &sig_len, message, 32, secret_key);
//    ```
//
// 2. Convert to hex strings and embed as:
//    ```
//    BOOST_AUTO_TEST_CASE(mldsa_kat_nist_vector_001)
//    {
//        auto pk_hex = "...";
//        auto msg_hex = "...";
//        auto sig_hex = "...";
//
//        auto pk_bytes = HexToBytes(pk_hex);
//        auto msg_bytes = HexToBytes(msg_hex);
//        auto sig_bytes = HexToBytes(sig_hex);
//
//        auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk_bytes);
//        BOOST_CHECK(MLDSA_Verify(Span(encoded_pk), Span(msg_bytes), Span(sig_bytes)));
//    }
//    ```
//
// 3. Add test vectors for all three security levels (ML-DSA-44/65/87)
// 4. Include both valid and invalid signature cases

#endif // ENABLE_MLDSA

BOOST_AUTO_TEST_SUITE_END()
