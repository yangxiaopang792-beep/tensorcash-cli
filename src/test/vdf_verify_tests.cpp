// Basic test for VDF verification wrapper using a known-good vector.

#include <boost/test/unit_test.hpp>

#include <vdf/VdfVerify.h>
#include <util/strencodings.h>
#include <cstring>  // for std::memcpy

BOOST_AUTO_TEST_SUITE(vdf_verify_tests)

static std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    return ParseHex<uint8_t>(hex);
}

BOOST_AUTO_TEST_CASE(verify_known_vector)
{
    // Challenge: 32 zero bytes (as used in python chia_test)
    uint256 prev_hash{uint256()};

    // Proof and tick from services/verification-api/src/tests/chia_test.py
    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";
    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);
    BOOST_REQUIRE(!proof.empty());

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(ok);
}

BOOST_AUTO_TEST_CASE(verify_wrong_tick_low)
{
    // Using the same valid proof but with incorrect (lower) tick count
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    // const uint64_t correct_tick = 1998848ULL;  // Reference value
    const uint64_t wrong_tick_low = 1000000ULL;  // Too low

    auto proof = HexToBytes(vdf_hex);

    // Should fail with lower tick count
    const bool ok_low = vdf::VerifyAgainstPrevHash(prev_hash, proof, wrong_tick_low, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok_low);
}

BOOST_AUTO_TEST_CASE(verify_wrong_tick_high)
{
    // Using the same valid proof but with incorrect (higher) tick count
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    // const uint64_t correct_tick = 1998848ULL;  // Reference value
    const uint64_t wrong_tick_high = 2500000ULL;  // Too high

    auto proof = HexToBytes(vdf_hex);

    // Should fail with higher tick count
    const bool ok_high = vdf::VerifyAgainstPrevHash(prev_hash, proof, wrong_tick_high, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok_high);
}

BOOST_AUTO_TEST_CASE(verify_corrupted_proof_single_bit)
{
    // Corrupt a single bit in the proof
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);
    BOOST_REQUIRE(proof.size() > 50);

    // Flip a bit in the middle of the proof
    proof[50] ^= 0x01;

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_corrupted_proof_multiple_bytes)
{
    // Corrupt multiple bytes in different parts of the proof
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);
    BOOST_REQUIRE(proof.size() > 100);

    // Corrupt multiple locations
    proof[10] = 0xFF;
    proof[30] = 0x00;
    proof[60] = 0xAA;
    proof[90] = 0x55;

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_truncated_proof)
{
    // Test with truncated proof (missing bytes at the end)
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);
    BOOST_REQUIRE(proof.size() > 20);

    // Truncate the proof by removing last 20 bytes
    proof.resize(proof.size() - 20);

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_empty_proof)
{
    // Test with completely empty proof
    uint256 prev_hash{uint256()};
    const uint64_t tick = 1998848ULL;

    std::vector<uint8_t> empty_proof;

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, empty_proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_wrong_challenge)
{
    // Test with correct proof but wrong challenge (different prev_hash)
    // Create a different hash by parsing hex bytes
    const std::string wrong_hash_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    auto wrong_hash_bytes = HexToBytes(wrong_hash_hex);
    uint256 wrong_prev_hash;
    std::memcpy(wrong_prev_hash.begin(), wrong_hash_bytes.data(), 32);

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);

    // Should fail with wrong challenge
    const bool ok = vdf::VerifyAgainstPrevHash(wrong_prev_hash, proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_wrong_discriminant_size)
{
    // Test with wrong discriminant size
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);

    // Should fail with wrong discriminant size (proof was generated with 1024)
    const bool ok_2048 = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/2048, /*recursion=*/0);
    BOOST_CHECK(!ok_2048);

    const bool ok_512 = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/512, /*recursion=*/0);
    BOOST_CHECK(!ok_512);
}

BOOST_AUTO_TEST_CASE(verify_malformed_proof_random_data)
{
    // Test with completely random data as proof
    uint256 prev_hash{uint256()};
    const uint64_t tick = 1998848ULL;

    // Create random bytes of similar length to a real proof
    std::vector<uint8_t> random_proof(200);
    for (size_t i = 0; i < random_proof.size(); ++i) {
        random_proof[i] = static_cast<uint8_t>(i * 17 + 42);  // Pseudo-random pattern
    }

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, random_proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_zero_tick)
{
    // Test with tick = 0 (should fail as no work was done)
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    auto proof = HexToBytes(vdf_hex);

    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, 0, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(verify_oversized_proof)
{
    // Test with an oversized proof (padded with extra bytes)
    uint256 prev_hash{uint256()};

    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";

    const uint64_t tick = 1998848ULL;

    auto proof = HexToBytes(vdf_hex);

    // Add extra garbage bytes at the end
    for (int i = 0; i < 50; ++i) {
        proof.push_back(0xFF);
    }

    // Depending on VDF implementation, this might fail or ignore extra bytes
    // Most implementations should fail with malformed proof
    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/1024, /*recursion=*/0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_SUITE_END()
