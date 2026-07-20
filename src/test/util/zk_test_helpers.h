#ifndef BITCOIN_TEST_UTIL_ZK_TEST_HELPERS_H
#define BITCOIN_TEST_UTIL_ZK_TEST_HELPERS_H

#include <crypto/groth16.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <span.h>

#include <cstdint>
#include <string>
#include <vector>

namespace zk_test {

// Helper to create uint256 from hex string (similar to Bitcoin Core's uint256S)
inline uint256 uint256S(const std::string& hex_str)
{
    // Remove "0x" prefix if present
    std::string hex = hex_str;
    if (hex.size() >= 2 && hex[0] == '0' && hex[1] == 'x') {
        hex = hex.substr(2);
    }

    // Pad to 64 characters (32 bytes)
    if (hex.size() < 64) {
        hex = std::string(64 - hex.size(), '0') + hex;
    }

    // Parse hex and create uint256
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        // Return zero hash on error
        return uint256();
    }

    // uint256 stores in little-endian, hex string is big-endian
    uint256 result;
    for (size_t i = 0; i < 32; ++i) {
        result.data()[31 - i] = bytes[i];
    }
    return result;
}

// Mock curve points for testing (not cryptographically valid)
static constexpr size_t G1_SIZE = groth16::GROTH16_G1_COMPRESSED_SIZE;
static constexpr size_t G2_SIZE = groth16::GROTH16_G2_COMPRESSED_SIZE;
static constexpr size_t FR_SIZE = groth16::GROTH16_FR_SIZE;

// Generate a mock G1 point (compressed format)
// Note: These are NOT valid curve points - only for testing parsing/flow
inline std::vector<unsigned char> MockG1Point(uint8_t discriminator = 0x01)
{
    std::vector<unsigned char> point(G1_SIZE);
    // Set compression flag and fill with deterministic data
    point[0] = 0x80 | (discriminator & 0x7F);
    for (size_t i = 1; i < G1_SIZE; ++i) {
        point[i] = (discriminator + i) & 0xFF;
    }
    return point;
}

// Generate a mock G2 point (compressed format)
inline std::vector<unsigned char> MockG2Point(uint8_t discriminator = 0x02)
{
    std::vector<unsigned char> point(G2_SIZE);
    point[0] = 0x80 | (discriminator & 0x7F);
    for (size_t i = 1; i < G2_SIZE; ++i) {
        point[i] = (discriminator + i) & 0xFF;
    }
    return point;
}

// Generate a mock field element (Fr)
inline std::vector<unsigned char> MockFieldElement(uint32_t value = 0, bool big_endian = true)
{
    std::vector<unsigned char> element(FR_SIZE, 0);
    if (big_endian) {
        element[FR_SIZE - 4] = (value >> 24) & 0xFF;
        element[FR_SIZE - 3] = (value >> 16) & 0xFF;
        element[FR_SIZE - 2] = (value >> 8) & 0xFF;
        element[FR_SIZE - 1] = value & 0xFF;
    } else {
        element[0] = value & 0xFF;
        element[1] = (value >> 8) & 0xFF;
        element[2] = (value >> 16) & 0xFF;
        element[3] = (value >> 24) & 0xFF;
    }
    return element;
}

// Build a mock Groth16 proof (A, B, C points)
inline std::vector<unsigned char> MockGroth16Proof(uint8_t seed = 0x42)
{
    std::vector<unsigned char> proof;
    auto a = MockG1Point(seed);
    auto b = MockG2Point(seed + 1);
    auto c = MockG1Point(seed + 2);

    proof.insert(proof.end(), a.begin(), a.end());
    proof.insert(proof.end(), b.begin(), b.end());
    proof.insert(proof.end(), c.begin(), c.end());

    return proof;
}

// Build a mock verifying key with specified gamma_abc count
inline std::vector<unsigned char> MockVerifyingKey(uint16_t gamma_abc_count = 4)
{
    std::vector<unsigned char> vk;

    // Count header (little-endian)
    vk.push_back(gamma_abc_count & 0xFF);
    vk.push_back((gamma_abc_count >> 8) & 0xFF);

    // Fixed elements: alpha_G1, beta_G2, gamma_G2, delta_G2
    auto alpha = MockG1Point(0x10);
    vk.insert(vk.end(), alpha.begin(), alpha.end());

    auto beta = MockG2Point(0x20);
    vk.insert(vk.end(), beta.begin(), beta.end());

    auto gamma = MockG2Point(0x30);
    vk.insert(vk.end(), gamma.begin(), gamma.end());

    auto delta = MockG2Point(0x40);
    vk.insert(vk.end(), delta.begin(), delta.end());

    // gamma_abc[0] (always present)
    auto abc0 = MockG1Point(0x50);
    vk.insert(vk.end(), abc0.begin(), abc0.end());

    // gamma_abc[1..n]
    for (uint16_t i = 0; i < gamma_abc_count; ++i) {
        auto abc = MockG1Point(0x60 + i);
        vk.insert(vk.end(), abc.begin(), abc.end());
    }

    return vk;
}

// Build mock public inputs with standard layout
struct MockPublicInputs {
    uint256 chain_separator;
    uint256 asset_id;
    uint32_t root_height;
    uint256 tfr_anchor;

    std::vector<unsigned char> Serialize() const {
        std::vector<unsigned char> result;

        // Element 0: Chain separator
        result.insert(result.end(), chain_separator.begin(), chain_separator.end());

        // Element 1: Asset ID
        result.insert(result.end(), asset_id.begin(), asset_id.end());

        // Element 2: Root height (BE encoding in last 4 bytes)
        auto height_element = MockFieldElement(root_height, true);
        result.insert(result.end(), height_element.begin(), height_element.end());

        // Element 3: TFR anchor
        result.insert(result.end(), tfr_anchor.begin(), tfr_anchor.end());

        return result;
    }
};

// Generate VK chunks for ConnectBlock testing
inline std::vector<std::vector<unsigned char>> SplitIntoChunks(
    const std::vector<unsigned char>& data,
    size_t chunk_size = 512)
{
    std::vector<std::vector<unsigned char>> chunks;
    for (size_t i = 0; i < data.size(); i += chunk_size) {
        size_t len = std::min(chunk_size, data.size() - i);
        chunks.emplace_back(data.begin() + i, data.begin() + i + len);
    }
    return chunks;
}

// Create a valid-looking witness stack for testing
inline std::vector<std::vector<unsigned char>> MockWitnessStack(
    bool include_proof = true,
    uint32_t root_height = 1000)
{
    std::vector<std::vector<unsigned char>> stack;

    // Add some dummy witness elements (signatures, etc)
    stack.push_back(std::vector<unsigned char>(71, 0x30)); // Mock signature
    stack.push_back(std::vector<unsigned char>(33, 0x02)); // Mock pubkey

    if (include_proof) {
        // Add ZK proof (second to last)
        stack.push_back(MockGroth16Proof());

        // Add public inputs (last)
        MockPublicInputs inputs;
        inputs.chain_separator = uint256S("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        inputs.asset_id = uint256S("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        inputs.root_height = root_height;
        inputs.tfr_anchor = uint256S("0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe");

        stack.push_back(inputs.Serialize());
    }

    return stack;
}

// Helper to create asset_id from string
inline uint256 AssetIdFromString(const std::string& str)
{
    return uint256S(str);
}

} // namespace zk_test

#endif // BITCOIN_TEST_UTIL_ZK_TEST_HELPERS_H