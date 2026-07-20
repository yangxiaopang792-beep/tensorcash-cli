#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <crypto/sha256.h>
#include <kernel/genesis_proof.h>
#include <kernel/chainparams.h>
#include <primitives/block.h>
#include <vdf/VdfGenerate.h>
#include <util/strencodings.h>

void print_hex(const std::string& label, const uint8_t* data, size_t size, size_t max_display = 32) {
    std::cout << label << " (" << size << " bytes): ";
    size_t display_size = std::min(size, max_display);
    for (size_t i = 0; i < display_size; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)data[i];
    }
    if (size > max_display) std::cout << "...";
    std::cout << std::dec << std::endl;
}

std::vector<uint8_t> Uint32ToLittleEndian(uint32_t value) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
    return bytes;
}

int main() {
    std::cout << "=== Genesis Final Hash Debug ===" << std::endl;

    const CProofBlob& genesis = g_genesisBlob;

    std::cout << "\n1. Basic info:" << std::endl;
    std::cout << "   Tick: " << genesis.tick << std::endl;
    std::cout << "   Chosen tokens: " << genesis.chosen_tokens.size() << std::endl;
    std::cout << "   Prompt tokens: " << genesis.prompt_tokens.size() << std::endl;
    std::cout << "   Compute precision: " << genesis.compute_precision << std::endl;

    print_hex("   Expected hash", genesis.hash.data(), genesis.hash.size());
    print_hex("   Header prefix", genesis.header_prefix.data(), genesis.header_prefix.size());
    print_hex("   VDF", genesis.vdf.data(), genesis.vdf.size());
    print_hex("   Target", genesis.target.data(), genesis.target.size());

    std::cout << "\n2. Building message for final hash:" << std::endl;

    // Build message
    std::vector<uint8_t> message;

    // 1. Header prefix (76 bytes)
    message.insert(message.end(), genesis.header_prefix.begin(), genesis.header_prefix.end());
    std::cout << "   After header: " << message.size() << " bytes" << std::endl;

    // 2. VDF
    message.insert(message.end(), genesis.vdf.begin(), genesis.vdf.end());
    std::cout << "   After VDF: " << message.size() << " bytes" << std::endl;

    // 3. Tick as 4-byte little-endian
    auto tick_bytes = Uint32ToLittleEndian(static_cast<uint32_t>(genesis.tick));
    message.insert(message.end(), tick_bytes.begin(), tick_bytes.end());
    print_hex("   Tick bytes", tick_bytes.data(), tick_bytes.size());
    std::cout << "   After tick: " << message.size() << " bytes" << std::endl;

    // 4. Step = 0 as 4-byte little-endian
    auto step_bytes = Uint32ToLittleEndian(0);
    message.insert(message.end(), step_bytes.begin(), step_bytes.end());
    print_hex("   Step bytes", step_bytes.data(), step_bytes.size());
    std::cout << "   After step: " << message.size() << " bytes" << std::endl;

    // 5. Window tokens (256 int64_t values)
    // For genesis with 256 chosen tokens and no prompt, context is just chosen tokens
    std::vector<int64_t> window_tokens(256, 0);

    // Fill window with chosen tokens (they're already 256)
    for (size_t i = 0; i < genesis.chosen_tokens.size(); ++i) {
        window_tokens[i] = static_cast<int64_t>(genesis.chosen_tokens[i]);
    }

    std::cout << "   First 5 window tokens: ";
    for (size_t i = 0; i < 5; ++i) {
        std::cout << window_tokens[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "   Last 5 window tokens: ";
    for (size_t i = 251; i < 256; ++i) {
        std::cout << window_tokens[i] << " ";
    }
    std::cout << std::endl;

    // Convert to bytes (8 bytes each, little-endian)
    for (int64_t token : window_tokens) {
        for (int i = 0; i < 8; ++i) {
            message.push_back((token >> (i * 8)) & 0xFF);
        }
    }
    std::cout << "   After window tokens: " << message.size() << " bytes" << std::endl;

    // 6. Precision string
    std::vector<uint8_t> precision_bytes(genesis.compute_precision.begin(), genesis.compute_precision.end());
    message.insert(message.end(), precision_bytes.begin(), precision_bytes.end());
    print_hex("   Precision bytes", precision_bytes.data(), precision_bytes.size());
    std::cout << "   After precision: " << message.size() << " bytes (total)" << std::endl;

    std::cout << "\n3. Computing SHA256:" << std::endl;
    std::cout << "   Expected size: 76 + " << genesis.vdf.size() << " + 4 + 4 + 2048 + "
              << precision_bytes.size() << " = "
              << (76 + genesis.vdf.size() + 4 + 4 + 2048 + precision_bytes.size()) << std::endl;

    // Compute SHA256
    uint256 computed_hash;
    CSHA256().Write(message.data(), message.size()).Finalize(computed_hash.begin());

    print_hex("   Computed hash", computed_hash.begin(), 32);
    print_hex("   Expected hash", genesis.hash.data(), 32);

    // Check if they match
    bool matches = (memcmp(computed_hash.begin(), genesis.hash.data(), 32) == 0);
    std::cout << "\n   Hashes match: " << (matches ? "YES" : "NO") << std::endl;

    if (!matches) {
        // Show byte-by-byte comparison
        std::cout << "\n   Byte-by-byte comparison:" << std::endl;
        for (size_t i = 0; i < 32; ++i) {
            if (computed_hash.begin()[i] != genesis.hash[i]) {
                std::cout << "     Byte " << i << ": computed="
                          << std::hex << (int)computed_hash.begin()[i]
                          << " expected=" << (int)genesis.hash[i]
                          << std::dec << std::endl;
            }
        }
    }

    // Also test PoW
    std::cout << "\n4. Testing PoW verification:" << std::endl;

    // Extract nonce (first 4 bytes of hash)
    std::vector<uint8_t> nonce(genesis.hash.begin(), genesis.hash.begin() + 4);
    print_hex("   Nonce from hash", nonce.data(), 4);

    // Build 80-byte header
    std::vector<uint8_t> header = genesis.header_prefix;
    header.insert(header.end(), nonce.begin(), nonce.end());
    std::cout << "   Header size: " << header.size() << " bytes" << std::endl;

    // Double SHA256
    uint256 hash1;
    CSHA256().Write(header.data(), header.size()).Finalize(hash1.begin());
    print_hex("   First SHA256", hash1.begin(), 32);

    uint256 hash2;
    CSHA256().Write(hash1.begin(), 32).Finalize(hash2.begin());
    print_hex("   Second SHA256", hash2.begin(), 32);
    print_hex("   Target", genesis.target.data(), 32);

    // Check if hash2 <= target (both in little-endian internally)
    // Note: for display, both are shown as they are stored

    std::cout << "\n\n=== Regtest Genesis VDF Snippet Generator ===" << std::endl;
    try {
        // Build regtest params and copy genesis
        auto reg = CChainParams::RegTest({});
        CBlock g = reg->GenesisBlock();
        const uint64_t tick = 10; // minimal test tick
        std::vector<uint8_t> proof = vdf::GenerateProofForTesting(g.hashPrevBlock, tick, /*discr_bits=*/1024);
        if (proof.empty()) {
            std::cerr << "Failed to generate VDF proof for regtest genesis" << std::endl;
        } else {
            g.pow.tick = tick;
            g.pow.vdf = proof;
            g.cumulative_tick = tick;
            g.hashPoW = g.pow.GetCommitment(/*use_merkle=*/true);

            auto print_hex_list = [](const std::vector<uint8_t>& v, size_t per_line = 16) {
                std::cout << "{\n    ";
                for (size_t i = 0; i < v.size(); ++i) {
                    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned) v[i] << std::dec;
                    if (i + 1 != v.size()) std::cout << ", ";
                    if ((i + 1) % per_line == 0 && i + 1 != v.size()) std::cout << "\n    ";
                }
                std::cout << "\n}";
            };

            std::cout << "\n// Paste into services/core-node/bcore/src/kernel/chainparams.cpp (regtest section)" << std::endl;
            std::cout << "genesis.pow.tick = " << tick << ";\n";
            std::cout << "genesis.pow.vdf = ";
            print_hex_list(proof);
            std::cout << ";\n";
            std::cout << "genesis.cumulative_tick = genesis.pow.tick;\n";
            std::cout << "genesis.hashPoW = uint256{\"" << g.hashPoW.ToString() << "\"};\n";
            std::cout << "consensus.hashGenesisBlock = uint256{\"" << g.GetHash().ToString() << "\"};\n";
            std::cout << "consensus.hashGenesisBlockShort = uint256{\"" << g.GetShortHash().ToString() << "\"};\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Regtest genesis snippet failed: " << e.what() << std::endl;
    }

    return 0;
}
