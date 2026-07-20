#include <crypto/groth16.h>
#include <test/util/zk_test_helpers.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

using namespace groth16;
using namespace zk_test;

BOOST_AUTO_TEST_SUITE(groth16_tests)

BOOST_AUTO_TEST_CASE(groth16_invalid_proof_format)
{
    VerificationContext ctx{.max_root_age = 0, .current_height = 0};
    auto vk = MockVerifyingKey(3);
    auto public_inputs = MockPublicInputs().Serialize();

    // Test with empty proof
    std::vector<unsigned char> empty_proof;
    auto result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(empty_proof),
        Span<const unsigned char>(public_inputs),
        Span<const unsigned char>(vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidProofFormat);

    // Test with wrong size proof
    std::vector<unsigned char> wrong_size_proof(100, 0x42);
    result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(wrong_size_proof),
        Span<const unsigned char>(public_inputs),
        Span<const unsigned char>(vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidProofFormat);

    // Test with correct size but invalid data (would fail subgroup checks in real impl)
    std::vector<unsigned char> invalid_proof(GROTH16_PROOF_SIZE, 0x00);
    result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(invalid_proof),
        Span<const unsigned char>(public_inputs),
        Span<const unsigned char>(vk),
        ctx
    );
    // This will fail with InvalidProofFormat due to invalid curve points
    BOOST_CHECK(result == VerifyError::InvalidProofFormat);
}

BOOST_AUTO_TEST_CASE(groth16_invalid_verifying_key)
{
    VerificationContext ctx{.max_root_age = 0, .current_height = 0};
    auto proof = MockGroth16Proof();
    auto public_inputs = MockPublicInputs().Serialize();

    // Empty VK
    std::vector<unsigned char> empty_vk;
    auto result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(public_inputs),
        Span<const unsigned char>(empty_vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidVerifyingKey);

    // VK too short
    std::vector<unsigned char> short_vk{0x01, 0x00}; // Just count, no data
    result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(public_inputs),
        Span<const unsigned char>(short_vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidVerifyingKey);

    // VK with too many gamma_abc elements
    auto big_vk = MockVerifyingKey(GROTH16_MAX_PUBLIC_INPUTS + 1);
    result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(public_inputs),
        Span<const unsigned char>(big_vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidVerifyingKey);
}

BOOST_AUTO_TEST_CASE(groth16_invalid_public_inputs)
{
    VerificationContext ctx{.max_root_age = 0, .current_height = 0};
    auto proof = MockGroth16Proof();
    auto vk = MockVerifyingKey(4); // Expects 4 public inputs

    // Empty public inputs
    std::vector<unsigned char> empty_inputs;
    auto result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(empty_inputs),
        Span<const unsigned char>(vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidPublicInputs);

    // Wrong number of inputs (3 instead of 4)
    std::vector<unsigned char> wrong_count_inputs;
    wrong_count_inputs.insert(wrong_count_inputs.end(), FR_SIZE * 3, 0x00);
    result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(wrong_count_inputs),
        Span<const unsigned char>(vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidPublicInputs);

    // Invalid size (not multiple of FR_SIZE)
    std::vector<unsigned char> invalid_size_inputs(FR_SIZE * 4 + 5, 0x00);
    result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(invalid_size_inputs),
        Span<const unsigned char>(vk),
        ctx
    );
    BOOST_CHECK(result == VerifyError::InvalidPublicInputs);
}

BOOST_AUTO_TEST_CASE(groth16_root_age_enforcement)
{
    auto proof = MockGroth16Proof();
    auto vk = MockVerifyingKey(4);

    // Test 1: Root too old
    {
        const int current_height = 2000;
        const uint32_t root_height = 1500;
        const uint32_t max_age = 400; // Delta = 500, exceeds max

        VerificationContext ctx{
            .max_root_age = max_age,
            .current_height = current_height
        };

        MockPublicInputs inputs;
        inputs.root_height = root_height;
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        BOOST_CHECK(result == VerifyError::RootTooOld);
    }

    // Test 2: Root within acceptable age
    {
        const int current_height = 2000;
        const uint32_t root_height = 1700;
        const uint32_t max_age = 400; // Delta = 300, within max

        VerificationContext ctx{
            .max_root_age = max_age,
            .current_height = current_height
        };

        MockPublicInputs inputs;
        inputs.root_height = root_height;
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        // Would fail at pairing check with mock data
        BOOST_CHECK(result == VerifyError::InvalidProofFormat || result == VerifyError::PairingFailed);
    }

    // Test 3: Root in future (invalid)
    {
        const int current_height = 2000;
        const uint32_t root_height = 2500;
        const uint32_t max_age = 400;

        VerificationContext ctx{
            .max_root_age = max_age,
            .current_height = current_height
        };

        MockPublicInputs inputs;
        inputs.root_height = root_height;
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        BOOST_CHECK(result == VerifyError::RootTooOld);
    }

    // Test 4: No age check when max_root_age = 0
    {
        const int current_height = 2000;
        const uint32_t root_height = 100; // Very old

        VerificationContext ctx{
            .max_root_age = 0, // Disabled
            .current_height = current_height
        };

        MockPublicInputs inputs;
        inputs.root_height = root_height;
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        // Should not fail with RootTooOld
        BOOST_CHECK(result != VerifyError::RootTooOld);
    }
}

BOOST_AUTO_TEST_CASE(groth16_tfr_anchor_enforcement)
{
    auto proof = MockGroth16Proof();
    auto vk = MockVerifyingKey(4);
    const int current_height = 2000;

    // Test 1: Anchor mismatch
    {
        auto expected_anchor = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");

        VerificationContext ctx{
            .max_root_age = 0,
            .current_height = current_height,
            .anchor_commitment = MakeUCharSpan(expected_anchor)
        };

        MockPublicInputs inputs;
        inputs.tfr_anchor = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        BOOST_CHECK(result == VerifyError::AnchorMismatch);
    }

    // Test 2: Anchor matches
    {
        auto expected_anchor = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

        VerificationContext ctx{
            .max_root_age = 0,
            .current_height = current_height,
            .anchor_commitment = MakeUCharSpan(expected_anchor)
        };

        MockPublicInputs inputs;
        inputs.tfr_anchor = expected_anchor; // Matching anchor
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        // Should not fail with AnchorMismatch
        BOOST_CHECK(result != VerifyError::AnchorMismatch);
    }

    // Test 3: No anchor check when not set
    {
        VerificationContext ctx{
            .max_root_age = 0,
            .current_height = current_height
            // No anchor_commitment set
        };

        MockPublicInputs inputs;
        inputs.tfr_anchor = uint256S("0x4444444444444444444444444444444444444444444444444444444444444444");
        auto pub_inputs_bytes = inputs.Serialize();

        auto result = VerifyGroth16WithPolicy(
            Span<const unsigned char>(proof),
            Span<const unsigned char>(pub_inputs_bytes),
            Span<const unsigned char>(vk),
            ctx
        );
        // Should not fail with AnchorMismatch
        BOOST_CHECK(result != VerifyError::AnchorMismatch);
    }
}

BOOST_AUTO_TEST_CASE(groth16_public_inputs_extraction)
{
    // Test that we correctly extract root height from element 2
    MockPublicInputs inputs;
    inputs.root_height = 0xDEADBEEF;
    auto serialized = inputs.Serialize();

    // Verify the root height is in the correct position (element 2, last 4 bytes)
    BOOST_CHECK_EQUAL(serialized.size(), FR_SIZE * 4);

    // Check element 2 (offset FR_SIZE * 2)
    const unsigned char* element2 = serialized.data() + FR_SIZE * 2;

    // Should be big-endian encoded in last 4 bytes
    uint32_t extracted = (static_cast<uint32_t>(element2[FR_SIZE - 4]) << 24) |
                        (static_cast<uint32_t>(element2[FR_SIZE - 3]) << 16) |
                        (static_cast<uint32_t>(element2[FR_SIZE - 2]) << 8) |
                        static_cast<uint32_t>(element2[FR_SIZE - 1]);

    BOOST_CHECK_EQUAL(extracted, 0xDEADBEEF);

    // Test TFR anchor is in element 3
    inputs.tfr_anchor = uint256S("0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");
    serialized = inputs.Serialize();

    const unsigned char* element3 = serialized.data() + FR_SIZE * 3;
    BOOST_CHECK(std::equal(inputs.tfr_anchor.begin(), inputs.tfr_anchor.end(), element3));
}

BOOST_AUTO_TEST_CASE(groth16_context_combined_validation)
{
    auto proof = MockGroth16Proof();
    auto vk = MockVerifyingKey(4);

    // Test with both root age and anchor enforcement
    const int current_height = 5000;
    const uint32_t root_height = 4900;
    const uint32_t max_age = 200; // Delta = 100, within range
    auto expected_anchor = uint256S("0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321");

    VerificationContext ctx{
        .max_root_age = max_age,
        .current_height = current_height,
        .anchor_commitment = MakeUCharSpan(expected_anchor)
    };

    MockPublicInputs inputs;
    inputs.root_height = root_height;
    inputs.tfr_anchor = expected_anchor;
    auto pub_inputs_bytes = inputs.Serialize();

    auto result = VerifyGroth16WithPolicy(
        Span<const unsigned char>(proof),
        Span<const unsigned char>(pub_inputs_bytes),
        Span<const unsigned char>(vk),
        ctx
    );

    // Should pass context validation and only fail at pairing (mock data)
    BOOST_CHECK(result == VerifyError::InvalidProofFormat || result == VerifyError::PairingFailed);
    BOOST_CHECK(result != VerifyError::RootTooOld);
    BOOST_CHECK(result != VerifyError::AnchorMismatch);
}

BOOST_AUTO_TEST_SUITE_END()