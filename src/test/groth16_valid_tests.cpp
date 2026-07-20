#include <crypto/groth16.h>
#include <crypto/groth16_testable.h>
#include <test/util/zk_valid_test_helpers.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

using namespace groth16;
using namespace zk_valid_test;

BOOST_FIXTURE_TEST_SUITE(groth16_valid_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valid_curve_points_parsing)
{
    // Test that our valid test helpers actually produce parseable data
    auto vk = ValidVerifyingKey(4);
    auto proof = ValidButFailingProof();
    auto inputs = ValidPublicInputs{}.Serialize();

    VerificationContext ctx{.max_root_age = 0, .current_height = 0};

    // Should parse successfully but fail at pairing
    auto result = VerifyGroth16WithPolicy(
        std::span<const unsigned char>(proof.data(), proof.size()),
        std::span<const unsigned char>(inputs.data(), inputs.size()),
        std::span<const unsigned char>(vk.data(), vk.size()),
        ctx
    );

    // Should get past parsing to actual pairing failure
    BOOST_CHECK(result == VerifyError::PairingFailed);
}

BOOST_AUTO_TEST_CASE(context_validation_root_age)
{
    // Test root age validation with valid cryptographic data
    auto vk = ValidVerifyingKey(4);
    auto proof = ValidButFailingProof();

    // Test case 1: Root too old
    {
        ValidPublicInputs inputs;
        inputs.root_height = 500;
        auto pub_bytes = inputs.Serialize();

        VerificationContext ctx{
            .max_root_age = 100,
            .current_height = 1000  // Delta = 500, exceeds max
        };

        auto result = VerifyGroth16WithPolicy(
            std::span<const unsigned char>(proof.data(), proof.size()),
            std::span<const unsigned char>(pub_bytes.data(), pub_bytes.size()),
            std::span<const unsigned char>(vk.data(), vk.size()),
            ctx
        );

        BOOST_CHECK(result == VerifyError::RootTooOld);
    }

    // Test case 2: Root within acceptable age
    {
        ValidPublicInputs inputs;
        inputs.root_height = 950;
        auto pub_bytes = inputs.Serialize();

        VerificationContext ctx{
            .max_root_age = 100,
            .current_height = 1000  // Delta = 50, within max
        };

        auto result = VerifyGroth16WithPolicy(
            std::span<const unsigned char>(proof.data(), proof.size()),
            std::span<const unsigned char>(pub_bytes.data(), pub_bytes.size()),
            std::span<const unsigned char>(vk.data(), vk.size()),
            ctx
        );

        // Should proceed to pairing (which will fail with test data)
        BOOST_CHECK(result == VerifyError::PairingFailed);
    }
}

BOOST_AUTO_TEST_CASE(context_validation_tfr_anchor)
{
    auto vk = ValidVerifyingKey(4);
    auto proof = ValidButFailingProof();

    // Test case 1: Anchor mismatch
    {
        ValidPublicInputs inputs;
        inputs.tfr_anchor = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
        auto pub_bytes = inputs.Serialize();

        auto expected_anchor = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");

        VerificationContext ctx{
            .max_root_age = 0,
            .current_height = 1000,
            .anchor_commitment = std::span<const unsigned char>(expected_anchor.begin(), expected_anchor.end())
        };

        auto result = VerifyGroth16WithPolicy(
            std::span<const unsigned char>(proof.data(), proof.size()),
            std::span<const unsigned char>(pub_bytes.data(), pub_bytes.size()),
            std::span<const unsigned char>(vk.data(), vk.size()),
            ctx
        );

        BOOST_CHECK(result == VerifyError::AnchorMismatch);
    }

    // Test case 2: Anchor matches
    {
        ValidPublicInputs inputs;
        inputs.tfr_anchor = uint256S("0x0000000000000000000000000000000000000000000000000000000000000003");
        auto pub_bytes = inputs.Serialize();

        VerificationContext ctx{
            .max_root_age = 0,
            .current_height = 1000,
            .anchor_commitment = std::span<const unsigned char>(inputs.tfr_anchor.begin(), inputs.tfr_anchor.end())
        };

        auto result = VerifyGroth16WithPolicy(
            std::span<const unsigned char>(proof.data(), proof.size()),
            std::span<const unsigned char>(pub_bytes.data(), pub_bytes.size()),
            std::span<const unsigned char>(vk.data(), vk.size()),
            ctx
        );

        // Should proceed to pairing
        BOOST_CHECK(result == VerifyError::PairingFailed);
    }
}

BOOST_AUTO_TEST_CASE(invalid_public_inputs_count)
{
    auto proof = ValidButFailingProof();
    auto vk = ValidVerifyingKey(4);  // Expects 4 inputs

    // Provide 3 inputs instead of 4
    std::vector<unsigned char> wrong_count;
    for (int i = 0; i < 3; ++i) {
        auto elem = ValidFieldElement(i);
        wrong_count.insert(wrong_count.end(), elem.begin(), elem.end());
    }

    VerificationContext ctx{.max_root_age = 0, .current_height = 0};

    auto result = VerifyGroth16WithPolicy(
        std::span<const unsigned char>(proof.data(), proof.size()),
        std::span<const unsigned char>(wrong_count.data(), wrong_count.size()),
        std::span<const unsigned char>(vk.data(), vk.size()),
        ctx
    );

    BOOST_CHECK(result == VerifyError::InvalidPublicInputs);
}

BOOST_AUTO_TEST_CASE(field_element_overflow)
{
    auto proof = ValidButFailingProof();
    auto vk = ValidVerifyingKey(4);

    // Create public inputs with field element >= modulus
    std::vector<unsigned char> bad_inputs;

    // Element 0: Valid
    auto elem0 = ValidFieldElement(1);
    bad_inputs.insert(bad_inputs.end(), elem0.begin(), elem0.end());

    // Element 1: Valid
    auto elem1 = ValidFieldElement(2);
    bad_inputs.insert(bad_inputs.end(), elem1.begin(), elem1.end());

    // Element 2: Invalid (all 0xFF exceeds modulus)
    std::vector<unsigned char> overflow_elem(32, 0xFF);
    bad_inputs.insert(bad_inputs.end(), overflow_elem.begin(), overflow_elem.end());

    // Element 3: Valid
    auto elem3 = ValidFieldElement(4);
    bad_inputs.insert(bad_inputs.end(), elem3.begin(), elem3.end());

    VerificationContext ctx{.max_root_age = 0, .current_height = 0};

    auto result = VerifyGroth16WithPolicy(
        std::span<const unsigned char>(proof.data(), proof.size()),
        std::span<const unsigned char>(bad_inputs.data(), bad_inputs.size()),
        std::span<const unsigned char>(vk.data(), vk.size()),
        ctx
    );

    BOOST_CHECK(result == VerifyError::InvalidPublicInputs);
}

BOOST_AUTO_TEST_CASE(combined_validation_valid_data)
{
    // Test the full flow with valid cryptographic data
    auto test_vector = Groth16TestVector::GenerateValid();

    ValidPublicInputs inputs;
    inputs.root_height = 950;
    inputs.tfr_anchor = uint256S("0x0000000000000000000000000000000000000000000000000000000000ABCDEF");
    auto pub_bytes = inputs.Serialize();

    VerificationContext ctx{
        .max_root_age = 100,
        .current_height = 1000,
        .anchor_commitment = std::span<const unsigned char>(inputs.tfr_anchor.begin(), inputs.tfr_anchor.end())
    };

    auto result = VerifyGroth16WithPolicy(
        std::span<const unsigned char>(test_vector.proof.data(), test_vector.proof.size()),
        std::span<const unsigned char>(pub_bytes.data(), pub_bytes.size()),
        std::span<const unsigned char>(test_vector.verifying_key.data(), test_vector.verifying_key.size()),
        ctx
    );

    // With valid test data that doesn't actually prove the statement,
    // we expect PairingFailed (not any earlier error)
    BOOST_CHECK(result == VerifyError::PairingFailed);
}

BOOST_AUTO_TEST_SUITE_END()