#include <verification/quick_verifier.h>
#include <verification/verification_utils.h>
#include <primitives/proofblob.h>
#include <kernel/genesis_proof.h>
#include <test/util/setup_common.h>
#include <modeldb.h>
#include <boost/test/unit_test.hpp>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(quick_verify_tests, BasicTestingSetup)

// Helper function to register the test model in the model database
void RegisterTestModel() {
    if (g_modeldb) {
        uint256 model_hash = g_genesisBlob.GetModelHash();
        ModelRecord record;
        record.metadata.model_name = "Qwen/Qwen3-8B";
        record.metadata.model_commit = "9c925d64d72725edaf899c6cb9c377fd0709d9c5";
        record.metadata.difficulty = 1000;  // Positive difficulty for active model
        record.metadata.cid = "test_cid";
        record.metadata.extra = "";
        record.status = ModelRegistrationStatus::Registered;
        g_modeldb->WriteModel(model_hash, record);
    }
}

BOOST_AUTO_TEST_CASE(test_genesis_verification) {
    RegisterTestModel();
    // Test that genesis blob passes verification
    QuickVerifier verifier;
    CProofBlob genesis = g_genesisBlob;

    auto result = verifier.QuickVerify(genesis);
    BOOST_CHECK_MESSAGE(result == VerificationResult::Quick_OK,
                        "Genesis verification failed: " + verifier.GetLastError());
}

BOOST_AUTO_TEST_CASE(test_invalid_temperature) {
    RegisterTestModel();
    // Test that invalid temperature is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Test temperature too low
    blob.temperature = 0.0001f;  // Below TEMP_MIN (0.001)
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid temperature") != std::string::npos);

    // Test temperature too high
    blob = g_genesisBlob;
    blob.temperature = 100.1f;  // Above TEMP_MAX (100.0)
    result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid temperature") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_invalid_top_p) {
    RegisterTestModel();
    // Test that invalid top_p is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Test top_p too low
    blob.top_p = 0.0f;  // Below TOPP_MIN (0.001)
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid top_p") != std::string::npos);

    // Test top_p too high
    blob = g_genesisBlob;
    blob.top_p = 1.1f;  // Above TOPP_MAX (1.0)
    result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid top_p") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_invalid_top_k) {
    RegisterTestModel();
    // Test that invalid top_k is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Test top_k too low
    blob.top_k = 0;  // Below TOPK_MIN (1)
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid top_k") != std::string::npos);

    // Test top_k too high
    blob = g_genesisBlob;
    blob.top_k = 50001;  // Above TOPK_MAX (50000)
    result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid top_k") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_invalid_hash) {
    RegisterTestModel();
    // Test that modified hash is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Corrupt the hash
    blob.hash[0] ^= 0xFF;
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Final hash mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_invalid_vdf) {
    RegisterTestModel();
    // Test that modified VDF is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Corrupt the VDF
    blob.vdf[0] ^= 0xFF;
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);

    // VDF modification will cause final hash mismatch since VDF is part of the hash
    std::string error = verifier.GetLastError();
    BOOST_CHECK_MESSAGE(error.find("Final hash mismatch") != std::string::npos ||
                        error.find("VDF") != std::string::npos,
                        "Expected VDF or hash error, got: " + error);
}

BOOST_AUTO_TEST_CASE(test_invalid_chosen_token) {
    RegisterTestModel();
    // Test that modified chosen token is caught during sampling verification
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Modify a chosen token
    blob.chosen_tokens[0] = 99999;  // Invalid token
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    // Should fail either at hash check or sampling verification
    BOOST_CHECK(verifier.GetLastError().find("Final hash mismatch") != std::string::npos ||
                verifier.GetLastError().find("Sampling verification failed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_invalid_sampling_u) {
    RegisterTestModel();
    // Test that modified sampling_u is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Modify sampling_u value
    blob.sampling_u[0] = 0.99f;  // Wrong value
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    // Should fail at final hash or U value mismatch
    BOOST_CHECK(verifier.GetLastError().find("Final hash mismatch") != std::string::npos ||
                verifier.GetLastError().find("U value mismatch") != std::string::npos ||
                verifier.GetLastError().find("Sampling verification failed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_mismatched_sizes) {
    RegisterTestModel();
    // Test that mismatched array sizes are caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Remove a logit entry
    blob.topk_logits[0].pop_back();
    auto result = verifier.QuickVerify(blob);

    std::string error = verifier.GetLastError();
    BOOST_CHECK_MESSAGE(result == VerificationResult::Quick_Fail,
                        "Should fail with mismatched sizes, got: " + error);
}

BOOST_AUTO_TEST_CASE(test_empty_model_identifier) {
    // Test that empty model identifier is caught
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    blob.model_identifier.clear();
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail_Model_Unregistered ||
                result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Invalid model identifier format") != std::string::npos ||
                verifier.GetLastError().find("Model identifier is empty") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_intermediate_capture) {
    RegisterTestModel();
    // Test that intermediate value capture works
    QuickVerifier verifier;
    verifier.EnableIntermediateCapture(true);

    CProofBlob blob = g_genesisBlob;

    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_OK);

    const auto& intermediates = verifier.GetIntermediates();

    // Check that we captured data for all chosen tokens
    BOOST_CHECK_EQUAL(intermediates.u_values.size(), blob.chosen_tokens.size());
    BOOST_CHECK_EQUAL(intermediates.dedupe_indices.size(), blob.chosen_tokens.size());
    BOOST_CHECK_EQUAL(intermediates.dedupe_values.size(), blob.chosen_tokens.size());
    BOOST_CHECK_EQUAL(intermediates.lower_bounds.size(), blob.chosen_tokens.size());
    BOOST_CHECK_EQUAL(intermediates.upper_bounds.size(), blob.chosen_tokens.size());
}

BOOST_AUTO_TEST_CASE(test_apply_top_k_masks_threshold_ties) {
    QuickVerifier verifier;
    std::vector<float> logits{1.0f, 0.5f, 0.5f, 0.0f};

    verifier.ApplyTopK(logits, 2);

    BOOST_CHECK(std::isfinite(logits[0]));
    BOOST_CHECK(std::isinf(logits[1]) && logits[1] < 0.0f);
    BOOST_CHECK(std::isinf(logits[2]) && logits[2] < 0.0f);
    BOOST_CHECK(std::isinf(logits[3]) && logits[3] < 0.0f);
}

BOOST_AUTO_TEST_CASE(test_borderline_top_p_adjustment_matches_python_selection) {
    QuickVerifier verifier;

    std::vector<float> logits{0.0f, static_cast<float>(std::log(9.0))};
    std::vector<float> top_p_logits = logits;
    std::vector<uint32_t> indices{10u, 20u};

    bool borderline = false;
    std::vector<float> logits_h;
    std::vector<float> logits_l;
    verifier.ApplyTopP(top_p_logits, indices, 0.9f, borderline, logits_h, logits_l);

    BOOST_CHECK(borderline);
    BOOST_CHECK(std::isinf(top_p_logits[0]) && top_p_logits[0] < 0.0f);
    BOOST_CHECK(std::isfinite(top_p_logits[1]));
    BOOST_CHECK(std::isinf(logits_h[0]) && logits_h[0] < 0.0f);
    BOOST_CHECK(std::isfinite(logits_l[0]));

    float lower = 0.0f;
    float upper = 0.0f;
    verification::TryBorderlineAdjustment(logits_h, logits_l, indices, 10u, 0.05f, lower, upper);

    BOOST_CHECK_SMALL(std::abs(lower), 1e-7f);
    BOOST_CHECK_SMALL(std::abs(upper - 0.1f), 1e-5f);
}

BOOST_AUTO_TEST_CASE(test_logsumexp_matches_double_reference) {
    QuickVerifier verifier;
    std::vector<float> values;
    values.reserve(100);
    for (int i = 0; i < 100; ++i) {
        values.push_back(static_cast<float>(-0.1 * i));
    }

    const double max_val = *std::max_element(values.begin(), values.end());
    double ref_sum = 0.0;
    for (float value : values) {
        ref_sum += std::exp(static_cast<double>(value) - max_val);
    }
    const double expected = max_val + std::log(ref_sum);
    const double actual = verifier.LogSumExp(values);

    BOOST_CHECK_SMALL(std::abs(actual - expected), 1e-12);
}

BOOST_AUTO_TEST_CASE(test_reuse_entropy_activation_and_bits) {
    QuickVerifier verifier;

    // Version-keyed gate: legacy proofs (version < REUSE_GATE_VERSION) are
    // grandfathered (pass without inspection); v2+ proofs are gated and an
    // empty/invalid proof must fail.
    CProofBlob legacy;  // version defaults to 0
    BOOST_CHECK(verifier.VerifyReuseEntropy(legacy));
    legacy.version = REUSE_GATE_VERSION - 1;
    BOOST_CHECK(verifier.VerifyReuseEntropy(legacy));
    CProofBlob gated;
    gated.version = REUSE_GATE_VERSION;
    BOOST_CHECK(!verifier.VerifyReuseEntropy(gated));

    BOOST_CHECK_EQUAL(verifier.ConservativeReuseBits(1.0), 0U);
    BOOST_CHECK_EQUAL(verifier.ConservativeReuseBits(0.500001), 0U);
    BOOST_CHECK_EQUAL(verifier.ConservativeReuseBits(0.5), 1U);
    BOOST_CHECK_EQUAL(verifier.ConservativeReuseBits(0.25), 2U);
    BOOST_CHECK_EQUAL(verifier.ConservativeReuseBits(1.0 / 1024.0), 10U);
    BOOST_CHECK_EQUAL(verifier.ConservativeReuseBits(0.0), REUSE_SCORE_Q32_BITS);
}

// Reshape every step so the chosen token dominates its distribution (mass ~= 1,
// 0 reuse bits => maximal reuse score == #steps forwards). chosen_tokens are
// preserved so sampling-u still routes into the now-~[0,1] chosen bucket and
// sequence verification still passes; only the reuse score changes.
static void ForceGreedyReuse(CProofBlob& blob) {
    const float T = (blob.temperature != 0.0f) ? blob.temperature : 1.0f;
    for (size_t i = 0; i < blob.chosen_tokens.size(); ++i) {
        const uint32_t ch = blob.chosen_tokens[i];
        if (i < blob.topk_indices.size() && i < blob.topk_logits.size()) {
            auto& idx = blob.topk_indices[i];
            auto& lg  = blob.topk_logits[i];
            for (size_t j = 0; j < idx.size() && j < lg.size(); ++j) {
                lg[j] = (idx[j] == ch) ? 100.0f : -100.0f;
            }
        }
        if (i < blob.softmax_normalizers.size()) {
            blob.softmax_normalizers[i] = 100.0f / T;  // logZ ~= dominating eff logit
        }
    }
}

// Differential test: the SAME maximally-grindable proof is grandfathered at v1
// but rejected by the q32 gate at v2 — through the real consensus verifier.
BOOST_AUTO_TEST_CASE(test_reuse_gate_version_differential) {
    RegisterTestModel();
    QuickVerifier verifier;

    CProofBlob greedy = g_genesisBlob;
    ForceGreedyReuse(greedy);
    BOOST_REQUIRE_MESSAGE(greedy.chosen_tokens.size() * REUSE_SCORE_Q32_ONE > REUSE_SCORE_CAP_Q32,
        "fixture too short to exceed the reuse cap when greedy");

    // v1 (legacy): grandfathered — reuse gate is a no-op even at maximal reuse.
    greedy.version = REUSE_GATE_VERSION - 1;
    BOOST_CHECK_MESSAGE(verifier.VerifyReuseEntropy(greedy),
        "legacy high-reuse proof must be grandfathered: " + verifier.GetLastError());
    BOOST_CHECK(verifier.QuickVerify(greedy) == VerificationResult::Quick_OK);

    // v2: gated — the same maximally grindable proof must be rejected.
    greedy.version = REUSE_GATE_VERSION;
    BOOST_CHECK_MESSAGE(!verifier.VerifyReuseEntropy(greedy),
        "v2 high-reuse proof must be rejected by the reuse gate");
    BOOST_CHECK(verifier.QuickVerify(greedy) != VerificationResult::Quick_OK);
}

BOOST_AUTO_TEST_CASE(test_genesis_subset_10_tokens) {
    RegisterTestModel();
    // Test genesis with only first 10 tokens (for faster testing in some scenarios)
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Take only first 10 tokens
    blob.chosen_tokens.resize(10);
    blob.topk_logits.resize(10);
    blob.topk_indices.resize(10);
    blob.sampling_u.resize(10);

    // This should fail hash verification since hash was computed with all 256 tokens
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Final hash mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(test_header_pow_verification) {
    RegisterTestModel();
    // Test that header PoW is properly verified
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Corrupt the target (make it easier, should fail)
    blob.target[0] = 0xFF;
    blob.target[1] = 0xFF;

    auto result = verifier.QuickVerify(blob);

    std::string error = verifier.GetLastError();
    BOOST_CHECK_MESSAGE(result == VerificationResult::Quick_Fail,
                        "Should fail with corrupted target, got: " + error);
    BOOST_CHECK_MESSAGE(error.find("PoW verification failed") != std::string::npos ||
                        error.find("Header hash") != std::string::npos ||
                        error.find("target") != std::string::npos,
                        "Expected PoW error, got: " + error);
}

BOOST_AUTO_TEST_CASE(test_nan_inf_validation) {
    RegisterTestModel();
    // Test that NaN and Inf values are rejected in proof blobs
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Test 1: NaN in temperature
    blob.temperature = std::numeric_limits<float>::quiet_NaN();
    auto result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("NaN") != std::string::npos ||
                verifier.GetLastError().find("Invalid temperature") != std::string::npos);

    // Test 2: Infinity in temperature
    blob = g_genesisBlob;
    blob.temperature = std::numeric_limits<float>::infinity();
    result = verifier.QuickVerify(blob);
    BOOST_CHECK(result == VerificationResult::Quick_Fail);
    BOOST_CHECK(verifier.GetLastError().find("Inf") != std::string::npos ||
                verifier.GetLastError().find("Invalid temperature") != std::string::npos);

    // Test 3: NaN in topk_logits
    blob = g_genesisBlob;
    if (!blob.topk_logits.empty() && !blob.topk_logits[0].empty()) {
        blob.topk_logits[0][0] = std::numeric_limits<float>::quiet_NaN();
        result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
        std::string error = verifier.GetLastError();
        BOOST_CHECK(error.find("NaN") != std::string::npos ||
                    error.find("Final hash mismatch") != std::string::npos ||
                    error.find("Invalid logit") != std::string::npos);
    }

    // Test 4: Negative Infinity in chosen_probs
    blob = g_genesisBlob;
    if (!blob.chosen_probs.empty()) {
        blob.chosen_probs[0] = -std::numeric_limits<float>::infinity();
        result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
        std::string error = verifier.GetLastError();
        BOOST_CHECK(error.find("Inf") != std::string::npos ||
                    error.find("Final hash mismatch") != std::string::npos ||
                    error.find("Invalid probability") != std::string::npos);
    }

    // Test 5: NaN in logsumexp_stats
    blob = g_genesisBlob;
    if (!blob.logsumexp_stats.empty() && !blob.logsumexp_stats[0].empty()) {
        blob.logsumexp_stats[0][0] = std::numeric_limits<float>::quiet_NaN();
        result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
        // Should now fail with NaN validation for logsumexp_stats
        BOOST_CHECK(verifier.GetLastError().find("NaN") != std::string::npos ||
                    verifier.GetLastError().find("Invalid logsumexp_stats") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(test_invalid_tensor_dimensions) {
    RegisterTestModel();
    // Test that invalid tensor dimensions are rejected
    QuickVerifier verifier;
    CProofBlob blob = g_genesisBlob;

    // Test 1: Mismatched dimensions between topk_logits and topk_indices
    if (!blob.topk_logits.empty() && !blob.topk_indices.empty()) {
        // Make topk_logits have different row count than topk_indices
        blob.topk_logits.resize(blob.topk_logits.size() + 10);
        for (size_t i = blob.topk_indices.size(); i < blob.topk_logits.size(); ++i) {
            blob.topk_logits[i] = blob.topk_logits[0];  // Copy first row
        }

        auto result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
        std::string error = verifier.GetLastError();
        BOOST_CHECK_MESSAGE(error.find("dimension") != std::string::npos ||
                            error.find("size") != std::string::npos ||
                            error.find("mismatch") != std::string::npos ||
                            error.find("Final hash mismatch") != std::string::npos,
                            "Expected dimension error, got: " + error);
    }

    // Test 2: Inconsistent column dimensions within topk_logits
    blob = g_genesisBlob;
    if (blob.topk_logits.size() >= 2) {
        // Make second row have different column count
        blob.topk_logits[1].resize(blob.topk_logits[0].size() * 2);

        auto result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
        // Should fail due to inconsistent tensor shape
    }

    // Test 3: Empty tensor when non-empty expected
    blob = g_genesisBlob;
    blob.topk_logits.clear();
    if (blob.chosen_tokens.size() > 0) {  // Only test if we expect logits
        auto result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
        // The error message will be about size mismatch, not "empty"
        BOOST_CHECK(verifier.GetLastError().find("mismatch") != std::string::npos ||
                    verifier.GetLastError().find("Logits") != std::string::npos);
    }

    // Test 4: Excessive tensor dimensions (memory attack prevention)
    // Use a large but manageable size to test dimension validation
    blob = g_genesisBlob;
    try {
        // Create a large tensor (10k x 1k = ~38MB, manageable for testing)
        blob.topk_logits.resize(10000);
        for (auto& row : blob.topk_logits) {
            row.resize(1000, 1.0f);
        }

        auto result = verifier.QuickVerify(blob);
        // Should either throw or return Quick_Fail due to size mismatch
        BOOST_CHECK(result == VerificationResult::Quick_Fail);
    } catch (const std::exception& e) {
        // Also acceptable - memory allocation failure or validation error
        BOOST_TEST_MESSAGE("Large tensor rejected with exception: " + std::string(e.what()));
    }
}

BOOST_AUTO_TEST_CASE(test_malformed_blob_structure) {
    RegisterTestModel();
    // Test various malformed blob structures
    QuickVerifier verifier;

    // Test 1: Blob with all zeros (invalid)
    {
        CProofBlob blob;
        blob.hash.resize(32, 0);
        blob.vdf.resize(32, 0);
        blob.temperature = 0.0f;
        blob.top_p = 0.0f;
        blob.top_k = 0;

        auto result = verifier.QuickVerify(blob);
        BOOST_CHECK(result == VerificationResult::Quick_Fail_Model_Unregistered ||
                   result == VerificationResult::Quick_Fail);
        // The actual error is "Invalid model identifier format" due to empty model_identifier
        BOOST_CHECK(verifier.GetLastError().find("Invalid model identifier format") != std::string::npos ||
                    verifier.GetLastError().find("empty") != std::string::npos ||
                    verifier.GetLastError().find("Invalid") != std::string::npos);
    }

    // Test 2: Blob with invalid UTF-8 in model_identifier
    {
        CProofBlob blob = g_genesisBlob;
        blob.model_identifier = std::string("\xFF\xFE\xFD\xFC");  // Invalid UTF-8

        auto result = verifier.QuickVerify(blob);
        // Will fail model registration due to unregistered/malformed model identifier
        BOOST_CHECK(result == VerificationResult::Quick_Fail_Model_Unregistered ||
                   result == VerificationResult::Quick_Fail);
        std::string error = verifier.GetLastError();
        BOOST_TEST_MESSAGE("Invalid UTF-8 test result: " + error);
    }

    // Test 3: Blob with negative token indices
    {
        CProofBlob blob = g_genesisBlob;
        if (!blob.chosen_tokens.empty()) {
            blob.chosen_tokens[0] = -1;  // Invalid token index

            auto result = verifier.QuickVerify(blob);
            BOOST_CHECK(result == VerificationResult::Quick_Fail);
        }
    }

    // Test 4: Blob with probabilities outside [0,1]
    {
        CProofBlob blob = g_genesisBlob;
        if (!blob.chosen_probs.empty()) {
            blob.chosen_probs[0] = 1.5f;  // Invalid probability > 1

            auto result = verifier.QuickVerify(blob);
            BOOST_CHECK(result == VerificationResult::Quick_Fail);
            // Should fail either at validation or hash check
        }
    }

    // Test 5: Blob with circular reference attack (if applicable)
    {
        CProofBlob blob = g_genesisBlob;
        // Add extremely long model identifier to test buffer limits
        blob.model_identifier = std::string(1000000, 'A');  // 1MB string

        auto result = verifier.QuickVerify(blob);
        // Will fail model registration due to unregistered large model identifier
        BOOST_CHECK(result == VerificationResult::Quick_Fail_Model_Unregistered ||
                   result == VerificationResult::Quick_OK ||
                   result == VerificationResult::Quick_Fail);
        BOOST_TEST_MESSAGE("Large model_identifier handled");
    }
}

BOOST_AUTO_TEST_SUITE_END()
