// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/groth16.h>
#include <test/util/golden_vector_loader.h>
#include <span.h>
#include <assets/asset.h>

#include <vector>
#include <iostream>

using namespace groth16;
using namespace golden_vectors;

/**
 * Benchmark Groth16 verification performance to evaluate DoS mitigation limits
 *
 * Current consensus limits:
 * - MAX_ZK_PROOFS_PER_TX = 2
 * - MAX_ZK_PROOFS_PER_BLOCK = 400
 *
 * Target: Understand verification latency and throughput to ensure these limits
 * keep block validation within acceptable bounds (target: <1s per block for 400 proofs)
 */

// Benchmark single Groth16 verification with real BLS12-381 proof
static void Groth16SingleVerification(benchmark::Bench& bench)
{
    // Load real proof from golden vectors
    auto golden_opt = LoadGoldenVector("valid");
    if (!golden_opt.has_value()) {
        return; // Skip benchmark if golden vectors not available
    }

    const auto& golden = golden_opt.value();

    // Setup verification context (minimal - no policy checks)
    VerificationContext ctx{
        .max_root_age = 0,  // Disable root age check
        .current_height = 0,
        .anchor_commitment = std::nullopt
    };

    std::span<const unsigned char> proof_span(golden.proof_bytes);
    std::span<const unsigned char> pub_span(golden.public_inputs_bytes);
    std::span<const unsigned char> vk_span(golden.vk_bytes);

    // Warm up
    auto result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
    if (result != VerifyError::OK) {
        std::cerr << "Benchmark setup failed: proof verification failed with error "
                  << static_cast<int>(result) << std::endl;
        return; // Skip benchmark if setup failed
    }

    // Benchmark single verification
    bench.run([&] {
        VerifyError verify_result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
        // In release mode, this prevents optimization away
        (void)verify_result;
    });
}

// Benchmark batch verification (2 proofs - per-tx limit)
static void Groth16TxBatchVerification(benchmark::Bench& bench)
{
    auto golden_opt = LoadGoldenVector("valid");
    if (!golden_opt.has_value()) {
        return; // Skip benchmark if golden vectors not available
    }

    const auto& golden = golden_opt.value();

    VerificationContext ctx{
        .max_root_age = 0,
        .current_height = 0,
        .anchor_commitment = std::nullopt
    };

    std::span<const unsigned char> proof_span(golden.proof_bytes);
    std::span<const unsigned char> pub_span(golden.public_inputs_bytes);
    std::span<const unsigned char> vk_span(golden.vk_bytes);

    // Verify setup works
    auto result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
    if (result != VerifyError::OK) {
        return; // Skip benchmark if setup failed
    }

    // Benchmark MAX_ZK_PROOFS_PER_TX (2 verifications)
    bench.run([&] {
        for (size_t i = 0; i < assets::MAX_ZK_PROOFS_PER_TX; ++i) {
            VerifyError verify_result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
            (void)verify_result;
        }
    });
}

// Benchmark block verification (400 proofs - per-block limit)
static void Groth16BlockBatchVerification(benchmark::Bench& bench)
{
    auto golden_opt = LoadGoldenVector("valid");
    if (!golden_opt.has_value()) {
        return; // Skip benchmark if golden vectors not available
    }

    const auto& golden = golden_opt.value();

    VerificationContext ctx{
        .max_root_age = 0,
        .current_height = 0,
        .anchor_commitment = std::nullopt
    };

    std::span<const unsigned char> proof_span(golden.proof_bytes);
    std::span<const unsigned char> pub_span(golden.public_inputs_bytes);
    std::span<const unsigned char> vk_span(golden.vk_bytes);

    // Verify setup works
    auto result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
    if (result != VerifyError::OK) {
        return; // Skip benchmark if setup failed
    }

    // Benchmark MAX_ZK_PROOFS_PER_BLOCK (400 verifications)
    bench.run([&] {
        for (size_t i = 0; i < assets::MAX_ZK_PROOFS_PER_BLOCK; ++i) {
            VerifyError verify_result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
            (void)verify_result;
        }
    });
}

// Benchmark verification with policy checks (root age + anchor)
static void Groth16WithPolicyChecks(benchmark::Bench& bench)
{
    auto golden_opt = LoadGoldenVector("valid");
    if (!golden_opt.has_value()) {
        return; // Skip benchmark if golden vectors not available
    }

    const auto& golden = golden_opt.value();

    // Enable all policy checks
    uint32_t root_height = golden.GetRootHeight();
    uint256 tfr_anchor = golden.GetTfrAnchor();

    VerificationContext ctx{
        .max_root_age = 1000,  // Enable root age check
        .current_height = static_cast<int>(root_height + 10),
        .anchor_commitment = std::span<const unsigned char>(tfr_anchor.begin(), tfr_anchor.end())
    };

    std::span<const unsigned char> proof_span(golden.proof_bytes);
    std::span<const unsigned char> pub_span(golden.public_inputs_bytes);
    std::span<const unsigned char> vk_span(golden.vk_bytes);

    // Verify setup works
    auto result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
    if (result != VerifyError::OK) {
        return; // Skip benchmark if setup failed
    }

    // Benchmark with full policy checks
    bench.run([&] {
        VerifyError verify_result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
        (void)verify_result;
    });
}

// Benchmark VK parsing (one-time cost per asset registration)
static void Groth16VKParsing(benchmark::Bench& bench)
{
    auto golden_opt = LoadGoldenVector("valid");
    if (!golden_opt.has_value()) {
        return; // Skip benchmark if golden vectors not available
    }

    const auto& golden = golden_opt.value();
    std::span<const unsigned char> vk_span(golden.vk_bytes);

    // We can't directly benchmark VK parsing as it's private,
    // but we can measure the first verification which includes parsing
    // vs subsequent verifications which would benefit from caching
    VerificationContext ctx{
        .max_root_age = 0,
        .current_height = 0,
        .anchor_commitment = std::nullopt
    };

    std::span<const unsigned char> proof_span(golden.proof_bytes);
    std::span<const unsigned char> pub_span(golden.public_inputs_bytes);

    // Note: Each call re-parses the VK since we don't have persistent state
    bench.run([&] {
        VerifyError verify_result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
        (void)verify_result;
    });
}

// Benchmark proof parsing overhead
static void Groth16ProofParsing(benchmark::Bench& bench)
{
    auto golden_opt = LoadGoldenVector("valid");
    if (!golden_opt.has_value()) {
        return; // Skip benchmark if golden vectors not available
    }

    const auto& golden = golden_opt.value();

    // Just measure the full verification - parsing is included
    // This gives us the total overhead per proof
    VerificationContext ctx{
        .max_root_age = 0,
        .current_height = 0,
        .anchor_commitment = std::nullopt
    };

    std::span<const unsigned char> proof_span(golden.proof_bytes);
    std::span<const unsigned char> pub_span(golden.public_inputs_bytes);
    std::span<const unsigned char> vk_span(golden.vk_bytes);

    bench.run([&] {
        VerifyError verify_result = VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, ctx);
        (void)verify_result;
    });
}

// Register benchmarks with appropriate priority
BENCHMARK(Groth16SingleVerification, benchmark::PriorityLevel::HIGH);
BENCHMARK(Groth16TxBatchVerification, benchmark::PriorityLevel::HIGH);
BENCHMARK(Groth16BlockBatchVerification, benchmark::PriorityLevel::HIGH);
BENCHMARK(Groth16WithPolicyChecks, benchmark::PriorityLevel::HIGH);
BENCHMARK(Groth16VKParsing, benchmark::PriorityLevel::LOW);
BENCHMARK(Groth16ProofParsing, benchmark::PriorityLevel::LOW);
