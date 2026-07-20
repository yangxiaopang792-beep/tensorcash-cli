// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/mldsaverify.h>
#include <random.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <vector>

using namespace mldsa;

#ifdef ENABLE_MLDSA

// Helper: Encode public key in on-stack format
static std::vector<uint8_t> EncodePublicKey(ParamSet level, const std::vector<uint8_t>& pk_bytes)
{
    std::vector<uint8_t> encoded;
    encoded.push_back(ALG_ID_MLDSA);
    encoded.push_back(static_cast<uint8_t>(level));

    // Varint length
    size_t pk_len = pk_bytes.size();
    if (pk_len < 0xFD) {
        encoded.push_back(static_cast<uint8_t>(pk_len));
    } else if (pk_len <= 0xFFFF) {
        encoded.push_back(0xFD);
        encoded.push_back(pk_len & 0xFF);
        encoded.push_back((pk_len >> 8) & 0xFF);
    }

    encoded.insert(encoded.end(), pk_bytes.begin(), pk_bytes.end());
    return encoded;
}

// Benchmark: Public key parsing (ML-DSA-65)
static void MLDSAParsePK65(benchmark::Bench& bench)
{
    std::vector<uint8_t> pk_bytes(1952, 0xAA);
    auto encoded = EncodePublicKey(ParamSet::MLDSA_65, pk_bytes);

    bench.run([&] {
        auto parsed = ParsePublicKey(Span(encoded));
        ankerl::nanobench::doNotOptimizeAway(parsed.has_value());
    });
}

// Benchmark: Public key parsing (ML-DSA-44)
static void MLDSAParsePK44(benchmark::Bench& bench)
{
    std::vector<uint8_t> pk_bytes(1312, 0xBB);
    auto encoded = EncodePublicKey(ParamSet::MLDSA_44, pk_bytes);

    bench.run([&] {
        auto parsed = ParsePublicKey(Span(encoded));
        ankerl::nanobench::doNotOptimizeAway(parsed.has_value());
    });
}

// Benchmark: Public key parsing (ML-DSA-87)
static void MLDSAParsePK87(benchmark::Bench& bench)
{
    std::vector<uint8_t> pk_bytes(2592, 0xCC);
    auto encoded = EncodePublicKey(ParamSet::MLDSA_87, pk_bytes);

    bench.run([&] {
        auto parsed = ParsePublicKey(Span(encoded));
        ankerl::nanobench::doNotOptimizeAway(parsed.has_value());
    });
}

// Benchmark: ML-DSA-44 signature verification
// Note: Uses random data; real benchmark would need valid signatures from liboqs
static void MLDSAVerify44(benchmark::Bench& bench)
{
    std::vector<uint8_t> pk_bytes(1312, 0x11);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_44, pk_bytes);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xAB);

    std::vector<uint8_t> sig(2420, 0x44);  // ML-DSA-44 signature size

    bench.run([&] {
        bool result = MLDSA_Verify(Span(encoded_pk), Span(msg), Span(sig));
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

// Benchmark: ML-DSA-65 signature verification
static void MLDSAVerify65(benchmark::Bench& bench)
{
    std::vector<uint8_t> pk_bytes(1952, 0x22);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk_bytes);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xCD);

    std::vector<uint8_t> sig(3309, 0x65);  // ML-DSA-65 signature size

    bench.run([&] {
        bool result = MLDSA_Verify(Span(encoded_pk), Span(msg), Span(sig));
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

// Benchmark: ML-DSA-87 signature verification
static void MLDSAVerify87(benchmark::Bench& bench)
{
    std::vector<uint8_t> pk_bytes(2592, 0x33);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_87, pk_bytes);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xEF);

    std::vector<uint8_t> sig(4627, 0x87);  // ML-DSA-87 signature size

    bench.run([&] {
        bool result = MLDSA_Verify(Span(encoded_pk), Span(msg), Span(sig));
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

// Benchmark: Batch verification of ML-DSA-65 signatures
static void MLDSAVerifyBatch(benchmark::Bench& bench)
{
    constexpr int BATCH_SIZE = 10;

    std::vector<uint8_t> pk_bytes(1952, 0x99);
    auto encoded_pk = EncodePublicKey(ParamSet::MLDSA_65, pk_bytes);

    std::array<uint8_t, 32> msg{};
    std::fill(msg.begin(), msg.end(), 0xDD);

    std::vector<uint8_t> sig(3309, 0xBB);

    bench.batch(BATCH_SIZE).run([&] {
        for (int i = 0; i < BATCH_SIZE; ++i) {
            // Vary message slightly to simulate different transactions
            msg[0] = static_cast<uint8_t>(i);
            bool result = MLDSA_Verify(Span(encoded_pk), Span(msg), Span(sig));
            ankerl::nanobench::doNotOptimizeAway(result);
        }
    });
}

BENCHMARK(MLDSAParsePK44, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSAParsePK65, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSAParsePK87, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSAVerify44, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSAVerify65, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSAVerify87, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLDSAVerifyBatch, benchmark::PriorityLevel::HIGH);

#endif // ENABLE_MLDSA
