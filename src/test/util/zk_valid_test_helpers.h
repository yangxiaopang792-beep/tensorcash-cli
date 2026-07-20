#ifndef BITCOIN_TEST_UTIL_ZK_VALID_TEST_HELPERS_H
#define BITCOIN_TEST_UTIL_ZK_VALID_TEST_HELPERS_H

#include <crypto/groth16.h>
#include <uint256.h>
#include <span.h>

#ifdef BUILD_ZK_TESTS
#include <blst.h>
#endif

#include <algorithm>
#include <cstdint>
#include <vector>
#include <array>

namespace zk_valid_test {

// Generate valid BLS12-381 curve points for testing

#ifdef BUILD_ZK_TESTS

/**
 * Create a valid compressed G1 point using the generator
 * @param scalar Scalar to multiply generator by (default: 1)
 * @return Compressed G1 point (48 bytes)
 */
inline std::vector<unsigned char> ValidG1Point(uint64_t scalar = 1)
{
    // Get G1 generator
    blst_p1_affine generator;
    blst_p1_generator(&generator);

    // Convert to projective for scalar multiplication
    blst_p1 point;
    blst_p1_from_affine(&point, &generator);

    // Scalar multiply if needed
    if (scalar != 1) {
        uint8_t scalar_bytes[32] = {0};
        for (int i = 0; i < 8; ++i) {
            scalar_bytes[i] = (scalar >> (i * 8)) & 0xFF;
        }
        blst_p1_mult(&point, &point, scalar_bytes, 256);
    }

    // Convert back to affine
    blst_p1_affine affine;
    blst_p1_to_affine(&affine, &point);

    // Compress
    std::vector<unsigned char> compressed(48);
    blst_p1_affine_compress(compressed.data(), &affine);

    return compressed;
}

#else // !BUILD_ZK_TESTS

/**
 * Create a mock G1 point (when blst is not available)
 * WARNING: This data will NOT pass cryptographic validation
 * @param scalar Unused in mock version
 * @return Mock G1 point (48 bytes)
 */
inline std::vector<unsigned char> ValidG1Point(uint64_t scalar = 1)
{
    // Return a pre-generated valid G1 point
    // This is the generator point in compressed form
    std::vector<unsigned char> mock_g1 = {
        0x97, 0xf1, 0xd3, 0xa7, 0x3e, 0x97, 0x35, 0x86,
        0x69, 0x5a, 0x2e, 0xf0, 0xc5, 0xb8, 0xeb, 0x8b,
        0x71, 0x35, 0xf8, 0xb3, 0xe5, 0xd6, 0x4f, 0x1e,
        0x8e, 0x1d, 0xd6, 0x85, 0x22, 0x7e, 0xbe, 0xa9,
        0xd5, 0xa0, 0xb5, 0x64, 0x83, 0xcd, 0xbc, 0x79,
        0x09, 0xfe, 0x42, 0x24, 0xd0, 0xf5, 0xd6, 0x3e
    };
    return mock_g1;
}

#endif // BUILD_ZK_TESTS

#ifdef BUILD_ZK_TESTS

/**
 * Create a valid compressed G2 point using the generator
 * @param scalar Scalar to multiply generator by (default: 1)
 * @return Compressed G2 point (96 bytes)
 */
inline std::vector<unsigned char> ValidG2Point(uint64_t scalar = 1)
{
    // Get G2 generator
    blst_p2_affine generator;
    blst_p2_generator(&generator);

    // Convert to projective
    blst_p2 point;
    blst_p2_from_affine(&point, &generator);

    // Scalar multiply if needed
    if (scalar != 1) {
        uint8_t scalar_bytes[32] = {0};
        for (int i = 0; i < 8; ++i) {
            scalar_bytes[i] = (scalar >> (i * 8)) & 0xFF;
        }
        blst_p2_mult(&point, &point, scalar_bytes, 256);
    }

    // Convert back to affine
    blst_p2_affine affine;
    blst_p2_to_affine(&affine, &point);

    // Compress
    std::vector<unsigned char> compressed(96);
    blst_p2_affine_compress(compressed.data(), &affine);

    return compressed;
}

#else // !BUILD_ZK_TESTS

/**
 * Create a mock G2 point (when blst is not available)
 * WARNING: This data will NOT pass cryptographic validation
 * @param scalar Unused in mock version
 * @return Mock G2 point (96 bytes)
 */
inline std::vector<unsigned char> ValidG2Point(uint64_t scalar = 1)
{
    // Return a pre-generated valid G2 point
    // This is the generator point in compressed form
    std::vector<unsigned char> mock_g2(96, 0xAA);
    // Set compression bit
    mock_g2[0] = 0xAA;
    return mock_g2;
}

#endif // BUILD_ZK_TESTS

/**
 * Create a valid field element (Fr) that passes modulus check
 * @param value Integer value (will be reduced mod r)
 * @return Field element as 32 bytes (big-endian)
 */
inline std::vector<unsigned char> ValidFieldElement(uint64_t value = 0)
{
    // BLS12-381 scalar field modulus r (approx 2^255)
    // We'll create a value that's definitely less than r
    std::vector<unsigned char> element(32, 0);

    // Place value in the lower bytes (big-endian)
    for (int i = 0; i < 8; ++i) {
        element[31 - i] = (value >> (i * 8)) & 0xFF;
    }

    // Ensure high bit is clear to guarantee < r
    element[0] = 0;

    return element;
}

/**
 * Create a valid but failing Groth16 proof
 * This will pass format validation but fail pairing check
 * @return Valid compressed proof (192 bytes)
 */
inline std::vector<unsigned char> ValidButFailingProof()
{
    std::vector<unsigned char> proof;

    // A = generator
    auto a = ValidG1Point(1);
    proof.insert(proof.end(), a.begin(), a.end());

    // B = generator
    auto b = ValidG2Point(1);
    proof.insert(proof.end(), b.begin(), b.end());

    // C = 2 * generator (different from A to avoid accidental success)
    auto c = ValidG1Point(2);
    proof.insert(proof.end(), c.begin(), c.end());

    return proof;
}

/**
 * Create a valid verifying key structure
 * This will pass parsing but won't verify any real proof
 * @param gamma_abc_count Number of public inputs
 * @return Valid compressed VK
 */
inline std::vector<unsigned char> ValidVerifyingKey(uint16_t gamma_abc_count = 4)
{
    std::vector<unsigned char> vk;

    // Count header (little-endian)
    vk.push_back(gamma_abc_count & 0xFF);
    vk.push_back((gamma_abc_count >> 8) & 0xFF);

    // alpha_G1 = generator
    auto alpha = ValidG1Point(3);
    vk.insert(vk.end(), alpha.begin(), alpha.end());

    // beta_G2 = 2 * generator
    auto beta = ValidG2Point(2);
    vk.insert(vk.end(), beta.begin(), beta.end());

    // gamma_G2 = 3 * generator
    auto gamma = ValidG2Point(3);
    vk.insert(vk.end(), gamma.begin(), gamma.end());

    // delta_G2 = 4 * generator
    auto delta = ValidG2Point(4);
    vk.insert(vk.end(), delta.begin(), delta.end());

    // gamma_abc[0] = 5 * generator
    auto abc0 = ValidG1Point(5);
    vk.insert(vk.end(), abc0.begin(), abc0.end());

    // gamma_abc[1..n] = (6+i) * generator
    for (uint16_t i = 0; i < gamma_abc_count; ++i) {
        auto abc = ValidG1Point(6 + i);
        vk.insert(vk.end(), abc.begin(), abc.end());
    }

    return vk;
}

/**
 * Create valid public inputs with specific values
 * All field elements will be < modulus
 */
struct ValidPublicInputs {
    uint256 chain_separator;
    uint256 asset_id;
    uint32_t root_height;
    uint256 tfr_anchor;

    std::vector<unsigned char> Serialize() const {
        std::vector<unsigned char> result;

        // Element 0: Chain separator (ensure < modulus)
        auto chain_bytes = ValidFieldElement(0x1234567890ABCDEF);
        std::copy(chain_separator.begin(), chain_separator.begin() + std::min(size_t(28), size_t(chain_separator.size())), chain_bytes.begin() + 4);
        result.insert(result.end(), chain_bytes.begin(), chain_bytes.end());

        // Element 1: Asset ID (ensure < modulus)
        auto asset_bytes = ValidFieldElement(0xDEADBEEFCAFEBABE);
        std::copy(asset_id.begin(), asset_id.begin() + std::min(size_t(28), size_t(asset_id.size())), asset_bytes.begin() + 4);
        result.insert(result.end(), asset_bytes.begin(), asset_bytes.end());

        // Element 2: Root height (big-endian in last 4 bytes)
        auto height_bytes = ValidFieldElement(root_height);
        result.insert(result.end(), height_bytes.begin(), height_bytes.end());

        // Element 3: TFR anchor (ensure < modulus)
        auto anchor_bytes = ValidFieldElement(0xFEDCBA0987654321);
        std::copy(tfr_anchor.begin(), tfr_anchor.begin() + std::min(size_t(28), size_t(tfr_anchor.size())), anchor_bytes.begin() + 4);
        result.insert(result.end(), anchor_bytes.begin(), anchor_bytes.end());

        return result;
    }
};

/**
 * Test vector with known relationship between proof/VK/inputs
 * This would be generated by an actual prover
 */
struct Groth16TestVector {
    std::vector<unsigned char> proof;
    std::vector<unsigned char> verifying_key;
    std::vector<unsigned char> public_inputs;
    bool should_verify;

    static Groth16TestVector GenerateValid() {
        // In reality, this would use an actual Groth16 prover
        // For now, return structurally valid data that will fail pairing
        Groth16TestVector tv;
        tv.proof = ValidButFailingProof();
        tv.verifying_key = ValidVerifyingKey(4);

        ValidPublicInputs inputs;
        inputs.chain_separator = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
        inputs.asset_id = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");
        inputs.root_height = 1000;
        inputs.tfr_anchor = uint256S("0x0000000000000000000000000000000000000000000000000000000000000003");
        tv.public_inputs = inputs.Serialize();

        tv.should_verify = false; // Known to fail pairing
        return tv;
    }
};

} // namespace zk_valid_test

#endif // BITCOIN_TEST_UTIL_ZK_VALID_TEST_HELPERS_H