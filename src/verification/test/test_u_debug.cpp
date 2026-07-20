#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <verification/quick_verifier.h>
#include <kernel/genesis_proof.h>
#include <crypto/sha256.h>

void print_bytes(const std::string& label, const std::vector<uint8_t>& bytes, size_t max_bytes = 32) {
    std::cout << label << " (" << bytes.size() << " bytes): ";
    for (size_t i = 0; i < std::min(bytes.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]) << " ";
    }
    if (bytes.size() > max_bytes) {
        std::cout << "...";
    }
    std::cout << std::dec << std::endl;
}

std::vector<uint8_t> uint32_to_le(uint32_t value) {
    std::vector<uint8_t> result(4);
    result[0] = value & 0xFF;
    result[1] = (value >> 8) & 0xFF;
    result[2] = (value >> 16) & 0xFF;
    result[3] = (value >> 24) & 0xFF;
    return result;
}

std::vector<uint8_t> tok_le_bytes(const std::vector<int64_t>& tokens) {
    std::vector<uint8_t> result;
    result.reserve(tokens.size() * 8);

    for (int64_t token : tokens) {
        // Little-endian conversion
        for (int i = 0; i < 8; ++i) {
            result.push_back((token >> (i * 8)) & 0xFF);
        }
    }
    return result;
}

float digest_to_u(const std::vector<uint8_t>& digest) {
    if (digest.size() < 4) return 0.0f;

    float b0 = static_cast<float>(digest[0]);
    float b1 = static_cast<float>(digest[1]);
    float b2 = static_cast<float>(digest[2]);
    float b3 = static_cast<float>(digest[3]);

    float result = (b0 + b1 * 256.0f + b2 * 65536.0f + b3 * 16777216.0f) / 4294967296.0f;
    return result;
}

int main() {
    std::cout << "=== Genesis U Value Debug Test ===" << std::endl;

    // Get genesis proof
    CProofBlob genesis = g_genesisBlob;

    // Test first step (step 0)
    size_t step = 0;

    // Build context for step 0: just prompt tokens
    std::vector<int64_t> context;
    for (uint32_t token : genesis.prompt_tokens) {
        context.push_back(static_cast<int64_t>(token));
    }

    std::cout << "\n--- Step " << step << " ---" << std::endl;
    std::cout << "Context size: " << context.size() << " tokens" << std::endl;

    // Build window tokens (256 slots for genesis)
    size_t window_size = genesis.chosen_tokens.size();  // 256
    std::vector<int64_t> window_tokens(window_size, 0);

    // Fill from the end
    size_t context_len = std::min(context.size(), window_size);
    if (context_len > 0) {
        size_t start_pos = window_size - context_len;
        for (size_t i = 0; i < context_len; ++i) {
            window_tokens[start_pos + i] = context[i];
        }
    }

    std::cout << "Window tokens (first 10): ";
    for (size_t i = 0; i < 10; ++i) {
        std::cout << window_tokens[i] << " ";
    }
    std::cout << "..." << std::endl;

    std::cout << "Window tokens (last 10): ";
    for (size_t i = window_size - 10; i < window_size; ++i) {
        std::cout << window_tokens[i] << " ";
    }
    std::cout << std::endl;

    // Build message components
    auto ctx_bytes = tok_le_bytes(window_tokens);
    auto j4 = uint32_to_le(static_cast<uint32_t>(step));
    auto T8 = uint32_to_le(static_cast<uint32_t>(genesis.tick));
    std::vector<uint8_t> precision_bytes(genesis.compute_precision.begin(),
                                          genesis.compute_precision.end());

    // Print components
    print_bytes("header_prefix", genesis.header_prefix);
    print_bytes("vdf", genesis.vdf);
    print_bytes("T8 (tick)", T8);
    print_bytes("j4 (step)", j4);
    print_bytes("ctx_bytes (first 32)", ctx_bytes);
    print_bytes("precision", precision_bytes);

    // Build message in correct order
    std::vector<uint8_t> message;
    message.insert(message.end(), genesis.header_prefix.begin(), genesis.header_prefix.end());
    message.insert(message.end(), genesis.vdf.begin(), genesis.vdf.end());
    message.insert(message.end(), T8.begin(), T8.end());
    message.insert(message.end(), j4.begin(), j4.end());
    message.insert(message.end(), ctx_bytes.begin(), ctx_bytes.end());
    message.insert(message.end(), precision_bytes.begin(), precision_bytes.end());

    std::cout << "\nTotal message size: " << message.size() << " bytes" << std::endl;
    print_bytes("Message (first 64 bytes)", message, 64);

    // Compute SHA256
    uint256 hash = Hash(message);
    std::vector<uint8_t> digest(hash.begin(), hash.begin() + 32);

    print_bytes("SHA256 digest", digest);

    // Convert to U
    float u = digest_to_u(digest);

    std::cout << "\nComputed U: " << std::fixed << std::setprecision(9) << u << std::endl;
    std::cout << "Expected U: " << genesis.sampling_u[step] << std::endl;
    std::cout << "Difference: " << std::abs(u - genesis.sampling_u[step]) << std::endl;

    // Test with QuickVerifier's method
    std::cout << "\n--- Using QuickVerifier ---" << std::endl;
    QuickVerifier verifier;

    // Build context with uint32_t
    std::vector<uint32_t> context32;
    for (auto t : genesis.prompt_tokens) {
        context32.push_back(t);
    }

    // This uses the QuickVerifier's internal ComputeUValue - we need to make it public temporarily
    // float verifier_u = verifier.ComputeUValue(context32, step, genesis);
    // std::cout << "QuickVerifier U: " << verifier_u << std::endl;

    return 0;
}