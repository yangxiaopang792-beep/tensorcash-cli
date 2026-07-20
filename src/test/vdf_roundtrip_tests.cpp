// VDF roundtrip tests: generate a proof in C++ and verify it

#include <boost/test/unit_test.hpp>

#include <vdf/VdfGenerate.h>
#include <vdf/VdfVerify.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstring>

BOOST_AUTO_TEST_SUITE(vdf_roundtrip_tests)

static uint256 HexToU256(const std::string& hex)
{
    uint256 out;
    auto bytes = ParseHex<uint8_t>(hex);
    if (bytes.size() >= 32) std::memcpy(out.begin(), bytes.data(), 32);
    return out;
}

// Generate a small proof and verify successfully
BOOST_AUTO_TEST_CASE(roundtrip_generate_and_verify_basic)
{
    // Fixed challenge (random-looking constant for determinism)
    const uint256 prev = HexToU256("00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100");
    const uint64_t tick = 200; // small for fast tests

    std::vector<uint8_t> proof = vdf::GenerateProofForTesting(prev, tick, /*discr_bits=*/1024);
    BOOST_REQUIRE_MESSAGE(!proof.empty(), "Generated VDF proof is empty");

    const bool ok = vdf::VerifyAgainstPrevHash(prev, proof, tick, /*discr_bits=*/1024, /*rec=*/0);
    BOOST_CHECK(ok);
}

// Negative: wrong tick should fail verification
BOOST_AUTO_TEST_CASE(roundtrip_wrong_tick_fails)
{
    const uint256 prev = HexToU256("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    const uint64_t tick = 150;

    std::vector<uint8_t> proof = vdf::GenerateProofForTesting(prev, tick, 1024);
    BOOST_REQUIRE(!proof.empty());

    const bool ok_low = vdf::VerifyAgainstPrevHash(prev, proof, tick - 1, 1024, 0);
    const bool ok_high = vdf::VerifyAgainstPrevHash(prev, proof, tick + 1, 1024, 0);
    BOOST_CHECK(!ok_low);
    BOOST_CHECK(!ok_high);
}

// Negative: wrong challenge should fail verification
BOOST_AUTO_TEST_CASE(roundtrip_wrong_prevhash_fails)
{
    const uint256 prev = HexToU256("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    const uint64_t tick = 120;
    std::vector<uint8_t> proof = vdf::GenerateProofForTesting(prev, tick, 1024);
    BOOST_REQUIRE(!proof.empty());

    const uint256 other = HexToU256("ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000");
    const bool ok = vdf::VerifyAgainstPrevHash(other, proof, tick, 1024, 0);
    BOOST_CHECK(!ok);
}

// Negative: tamper a byte in the proof and expect failure
BOOST_AUTO_TEST_CASE(roundtrip_tamper_proof_fails)
{
    const uint256 prev = HexToU256("00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff");
    const uint64_t tick = 180;
    std::vector<uint8_t> proof = vdf::GenerateProofForTesting(prev, tick, 1024);
    BOOST_REQUIRE(proof.size() > 10);

    proof[10] ^= 0x01;
    const bool ok = vdf::VerifyAgainstPrevHash(prev, proof, tick, 1024, 0);
    BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_SUITE_END()

