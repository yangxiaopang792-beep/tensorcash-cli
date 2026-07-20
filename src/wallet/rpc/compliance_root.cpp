// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpc/wallet.h>
#include <rpc/util.h>
#include <hash.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <span.h>
#include <logging.h>
#include <util/fs.h>

#include <univalue.h>
#include <vector>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#ifndef RTLD_LAZY
#define RTLD_LAZY 0
#endif
static void* dlopen(const char* path, int) { return static_cast<void*>(LoadLibraryA(path)); }
static void* dlsym(void* handle, const char* name) {
    FARPROC proc = GetProcAddress(static_cast<HMODULE>(handle), name);
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(proc));
}
static int dlclose(void* handle) { return FreeLibrary(static_cast<HMODULE>(handle)) ? 0 : -1; }
static const char* dlerror() { return "LoadLibrary/GetProcAddress failed"; }
#else
#include <dlfcn.h>
#endif
#include <string>
#include <stdexcept>
#include <secp256k1.h>

namespace wallet {

static void* LoadZkProverLibrary(const char* context = nullptr)
{
    void* handle = dlopen("libzkprover.so", RTLD_LAZY);
    if (handle != nullptr) {
        return handle;
    }

    const fs::path fallback = fs::PathFromString(".") / ".." / ".." / "shared-utils" / "kyc-prover" / "cgo" / "libzkprover.so";
    handle = dlopen(fs::PathToString(fallback).c_str(), RTLD_LAZY);
    if (handle != nullptr) {
        return handle;
    }

    const char* err = dlerror();
    std::string message = "Failed to load libzkprover.so";
    if (context != nullptr && context[0] != '\0') {
        message += " ";
        message += context;
    }
    if (err != nullptr) {
        message += ": ";
        message += err;
    }
    throw std::runtime_error(message);
}

// Helper function to compute leaf hash for KYC identity (SHA256-based for standard circuit)
static uint256 ComputeKYCLeafHash(const std::vector<unsigned char>& master_pubkey_x,
                                  uint16_t country,
                                  uint8_t age)
{
    // Build leaf data: master_pubkey_x || country || age
    std::vector<unsigned char> leaf_data;
    leaf_data.insert(leaf_data.end(), master_pubkey_x.begin(), master_pubkey_x.end());

    // Add country (big-endian, 2 bytes)
    leaf_data.push_back((country >> 8) & 0xFF);
    leaf_data.push_back(country & 0xFF);

    // Add age (1 byte)
    leaf_data.push_back(age);

    // Hash with SHA256
    return Hash(leaf_data);
}

// Compute leaf hash for HDv1 circuit: MiMC(P.x, P.y)
// Binds full parent pubkey to prevent P/-P ambiguity in the pubkey-only design.
static uint256 ComputeKYCLeafHashHDV1(const std::vector<unsigned char>& master_pubkey_x,
                                       const std::vector<unsigned char>& master_pubkey_y)
{
    // Import MiMC bridge function
    typedef struct {
        unsigned char* hash_data;
        int hash_len;
        char* error_msg;
    } MiMCHashResult;
    typedef MiMCHashResult (*ComputeMiMCHashFunc)(const char*, const char*, const char*, const char*);
    typedef void (*FreeMiMCResultFunc)(MiMCHashResult*);

    void* handle = LoadZkProverLibrary("for MiMC leaf hash");

    auto computeHash = (ComputeMiMCHashFunc)dlsym(handle, "Groth16_ComputeMiMCHash");
    auto freeResult = (FreeMiMCResultFunc)dlsym(handle, "Groth16_FreeMiMCResult");

    if (!computeHash || !freeResult) {
        dlclose(handle);
        throw std::runtime_error("Failed to load MiMC functions");
    }

    // Format inputs: P.x and P.y (32 bytes each as 0x-prefixed hex)
    std::string px_hex = "0x" + HexStr(master_pubkey_x);
    std::string py_hex = "0x" + HexStr(master_pubkey_y);

    LogPrintf("ZK_DEBUG [ComputeKYCLeafHashHDV1]: px_hex = %s, py_hex = %s\n", px_hex, py_hex);

    // Compute: MiMC(P.x, P.y) — two inputs, no tag
    MiMCHashResult result = computeHash("", px_hex.c_str(), py_hex.c_str(), nullptr);

    if (result.error_msg != nullptr) {
        std::string error(result.error_msg);
        freeResult(&result);
        dlclose(handle);
        throw std::runtime_error("MiMC leaf hash error: " + error);
    }

    if (result.hash_len != 32) {
        freeResult(&result);
        dlclose(handle);
        throw std::runtime_error("MiMC returned unexpected hash length");
    }

    // MiMC returns bytes in BE format, copy as-is into uint256
    uint256 leaf_hash;
    memcpy(leaf_hash.begin(), result.hash_data, 32);

    LogPrintf("ZK_DEBUG [ComputeKYCLeafHashHDV1]: leaf_hash = 0x%s\n", HexStr(std::span<const unsigned char>(leaf_hash.begin(), uint256::size())));

    freeResult(&result);
    dlclose(handle);

    return leaf_hash;
}

// Helper to hash Merkle tree node using MiMC
static uint256 HashMerkleNodeMiMC(const uint256& left, const uint256& right)
{
    // Load MiMC bridge
    void* handle = LoadZkProverLibrary("for MiMC Merkle node hash");

    typedef struct {
        unsigned char* hash_data;
        int hash_len;
        char* error_msg;
    } MiMCHashResult;
    typedef MiMCHashResult (*ComputeMiMCHashFunc)(const char*, const char*, const char*, const char*);
    typedef void (*FreeMiMCResultFunc)(MiMCHashResult*);

    auto computeHash = (ComputeMiMCHashFunc)dlsym(handle, "Groth16_ComputeMiMCHash");
    auto freeResult = (FreeMiMCResultFunc)dlsym(handle, "Groth16_FreeMiMCResult");

    if (!computeHash || !freeResult) {
        dlclose(handle);
        throw std::runtime_error("Failed to load MiMC functions");
    }

    // Format inputs: left and right as 0x-prefixed hex
    std::string left_hex = "0x" + HexStr(std::span<const unsigned char>(left.begin(), uint256::size()));
    std::string right_hex = "0x" + HexStr(std::span<const unsigned char>(right.begin(), uint256::size()));

    LogPrintf("ZK_DEBUG [HashMerkleNodeMiMC]: left_hex = %s\n", left_hex);
    LogPrintf("ZK_DEBUG [HashMerkleNodeMiMC]: right_hex = %s\n", right_hex);

    // Compute: H(left || right) with empty tag
    MiMCHashResult result = computeHash("", left_hex.c_str(), right_hex.c_str(), nullptr);

    if (result.error_msg != nullptr) {
        std::string error(result.error_msg);
        freeResult(&result);
        dlclose(handle);
        throw std::runtime_error("MiMC Merkle node hash error: " + error);
    }

    if (result.hash_len != 32) {
        freeResult(&result);
        dlclose(handle);
        throw std::runtime_error("MiMC returned unexpected hash length");
    }

    // Copy result
    uint256 node_hash;
    memcpy(node_hash.begin(), result.hash_data, 32);

    LogPrintf("ZK_DEBUG [HashMerkleNodeMiMC]: node_hash = 0x%s\n", HexStr(std::span<const unsigned char>(node_hash.begin(), uint256::size())));

    freeResult(&result);
    dlclose(handle);

    return node_hash;
}

// Build merkle tree and return root
static uint256 BuildMerkleTree(std::vector<uint256>& leaves,
                               std::vector<std::vector<uint256>>& tree_levels,
                               std::map<int, std::vector<uint256>>& merkle_proofs,
                               const std::string& circuit_type)
{
    // Pad to 256 leaves (depth 8)
    const size_t TREE_SIZE = 256;
    leaves.resize(TREE_SIZE, uint256());

    // Store all tree levels for proof extraction
    tree_levels.clear();
    tree_levels.push_back(leaves);

    // Build tree bottom-up
    std::vector<uint256> current_level = leaves;

    while (current_level.size() > 1) {
        std::vector<uint256> next_level;

        for (size_t i = 0; i < current_level.size(); i += 2) {
            uint256 left = current_level[i];
            uint256 right = (i + 1 < current_level.size()) ? current_level[i + 1] : uint256();

            // Hash(left || right) - use MiMC for HD circuits, SHA256 for standard
            uint256 node_hash;
            if (circuit_type == "hd_v1") {
                node_hash = HashMerkleNodeMiMC(left, right);
            } else {
                std::vector<unsigned char> combined;
                combined.insert(combined.end(), left.begin(), left.end());
                combined.insert(combined.end(), right.begin(), right.end());
                node_hash = Hash(combined);
            }

            next_level.push_back(node_hash);
        }

        current_level = next_level;
        tree_levels.push_back(current_level);
    }

    // Extract merkle proofs for each non-zero leaf
    for (size_t leaf_idx = 0; leaf_idx < leaves.size(); ++leaf_idx) {
        if (!leaves[leaf_idx].IsNull()) {
            std::vector<uint256> siblings;
            size_t idx = leaf_idx;

            // Get siblings at each level
            for (size_t level = 0; level < 8; ++level) { // 8 levels for 256 leaves
                size_t sibling_idx = idx ^ 1; // XOR with 1 to get sibling
                if (sibling_idx < tree_levels[level].size()) {
                    siblings.push_back(tree_levels[level][sibling_idx]);
                } else {
                    siblings.push_back(uint256());
                }
                idx = idx / 2; // Move up the tree
            }

            merkle_proofs[leaf_idx] = siblings;
        }
    }

    return tree_levels.back()[0]; // Return root
}

RPCHelpMan generatecomplianceroot()
{
    return RPCHelpMan{
        "generatecomplianceroot",
        "Generate an append-only compliance merkle root from KYC identity data.\n"
        "This RPC handles all cryptographic operations for building the merkle tree.\n"
        "The tree is append-only: new identities can be added at unused indices.\n"
        "To revoke an identity, set revoked=true to replace it with a NUMS value.\n"
        "The issuer can use the returned root in registerasset or rotatezk.\n"
        "\n"
        "Cryptographic algorithms used per circuit type:\n"
        "- 'standard': SHA256 for leaf hashes and Merkle tree nodes\n"
        "- 'hd' / 'hd_v1': MiMC hash for leaf hashes and Merkle tree nodes (BLS12-381 field)",
        {
            {"identities", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of KYC identities",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"master_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                             "Master public key (33-byte compressed or X coordinate only). Use 'NUMS' or omit for revoked entry."},
                            {"country", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                             "ISO 3166-1 numeric country code (omit for revoked)"},
                            {"age", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                             "Age in years (0-255, omit for revoked)"},
                            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO,
                             "Merkle tree index (0-255, REQUIRED for append-only model)"},
                            {"revoked", RPCArg::Type::BOOL, RPCArg::Default{false},
                             "If true, replace this index with NUMS value (revoke identity)"},
                        }
                    }
                }
            },
            {"circuit_type", RPCArg::Type::STR, RPCArg::Default{"hd_v1"},
             "Circuit type for KYC compliance trees. Only 'hd_v1' is supported.\n"
             "                             - 'hd_v1': leaf_hash = MiMC(pubkey_x, pubkey_y), node_hash = MiMC(left || right). Country/age are off-chain issuer policy.\n"
             "                             'standard' (SHA256, 4-input) is RETIRED: its proofs carry no output-key binding and are rejected by consensus (kyc-proof-not-hdv1)."},
            {"existing_tree", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Existing tree to update (append-only)",
                {
                    {"leaf_hashes", RPCArg::Type::ARR, RPCArg::Optional::NO, "Existing leaf hashes",
                        {
                            {"", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Leaf hash at this index (empty string for unused)"}
                        }
                    }
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "compliance_root", "The merkle root for the compliance tree"},
                {RPCResult::Type::ARR, "identities", "Processed identities with merkle proofs",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "index", "Merkle tree index"},
                                {RPCResult::Type::STR_HEX, "leaf_hash", "Computed leaf hash"},
                                {RPCResult::Type::ARR, "merkle_proof", "Merkle proof (sibling hashes)",
                                    {
                                        {RPCResult::Type::STR_HEX, "", "Sibling hash at this level"}
                                    }
                                },
                            }
                        }
                    }
                },
                {RPCResult::Type::ARR, "leaf_hashes", "All leaf hashes in the tree (empty string for unused slots)",
                    {
                        {RPCResult::Type::STR_HEX, "", "Leaf hash at this index (empty for unused)"}
                    }
                },
                {RPCResult::Type::NUM, "tree_depth", "Merkle tree depth"},
                {RPCResult::Type::NUM, "total_identities", "Number of identities in tree"},
            }
        },
        RPCExamples{
            HelpExampleCli("generatecomplianceroot",
                "'[{\"master_pubkey\":\"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\","
                "\"country\":840,\"age\":35,\"index\":0}]'") +
            HelpExampleRpc("generatecomplianceroot",
                "[[{\"master_pubkey\":\"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\","
                "\"country\":840,\"age\":35}]], \"hd_v1\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const UniValue& identities_arr = request.params[0].get_array();
            std::string circuit_type = "hd_v1";
            if (!request.params[1].isNull()) {
                circuit_type = request.params[1].get_str();
            }

            // Validate circuit type (F2: retire 'standard'/'hd').
            // Only the HDv1 (6-input, output-key-bound) family is accepted for KYC
            // compliance trees. Legacy 'standard'/'hd' roots feed proofs that
            // consensus now rejects (kyc-proof-not-hdv1), so generating them is a
            // footgun. The 'standard' leaf/node computation below is retained as
            // dead code (not deleted) but is no longer reachable from this RPC.
            if (circuit_type != "hd_v1") {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Invalid circuit_type. Only 'hd_v1' is supported; 'standard'/'hd' are retired "
                    "(their proofs carry no output-key binding and are rejected by consensus).");
            }

            // Initialize leaves - either from existing tree or empty
            std::vector<uint256> leaves(256); // Initialize with zeros

            // Load existing tree if provided (for append-only updates)
            if (!request.params[2].isNull()) {
                const UniValue& existing = request.params[2].get_obj();
                if (existing.exists("leaf_hashes")) {
                    const UniValue& existing_leaves = existing["leaf_hashes"].get_array();
                    for (size_t i = 0; i < existing_leaves.size() && i < 256; ++i) {
                        std::string leaf_hex = existing_leaves[i].get_str();
                        if (!leaf_hex.empty()) {
                            if (leaf_hex.size() >= 2 && leaf_hex.substr(0, 2) == "0x") {
                                leaf_hex = leaf_hex.substr(2);
                            }
                            auto leaf_bytes = ParseHex(leaf_hex);
                            if (leaf_bytes.size() != 32) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                    strprintf("leaf_hashes[%d] must be exactly 32 bytes", i));
                            }
                            std::memcpy(leaves[i].begin(), leaf_bytes.data(), 32);
                        }
                    }
                }
            }

            std::map<int, UniValue> identity_map;

            // Process identity updates
            for (size_t i = 0; i < identities_arr.size(); ++i) {
                const UniValue& identity = identities_arr[i];

                // Index is REQUIRED in append-only model
                if (!identity.exists("index")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "index is required for each identity in append-only model");
                }

                int index = identity["index"].getInt<int>();
                if (index < 0 || index >= 256) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid index %d (must be 0-255)", index));
                }

                // Check if this is a revocation
                bool revoked = false;
                if (identity.exists("revoked")) {
                    revoked = identity["revoked"].get_bool();
                }

                uint256 leaf_hash;

                if (revoked) {
                    // Use NUMS (Nothing Up My Sleeve) value for revoked entry
                    // Hash("REVOKED" || index) to make it deterministic but unspendable
                    std::string nums_data = strprintf("REVOKED_%d", index);
                    leaf_hash = Hash(std::vector<unsigned char>(nums_data.begin(), nums_data.end()));
                } else {
                    // Normal identity - validate required fields
                    if (!identity.exists("master_pubkey")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("master_pubkey required for identity at index %d", index));
                    }

                    std::string pubkey_hex = identity["master_pubkey"].get_str();

                    // country and age are accepted as optional metadata for audit/display
                    // but do NOT enter the leaf hash computation for hd/hd_v1 circuits
                    int country = 0;
                    int age = 0;
                    if (identity.exists("country")) {
                        country = identity["country"].getInt<int>();
                        if (country < 0 || country > 999) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("Invalid country code %d (must be 0-999)", country));
                        }
                    }
                    if (identity.exists("age")) {
                        age = identity["age"].getInt<int>();
                        if (age < 0 || age > 255) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("Invalid age %d (must be 0-255)", age));
                        }
                    }

                    // Standard circuit requires country and age for the leaf hash
                    if (circuit_type == "standard") {
                        if (!identity.exists("country")) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("country required for identity at index %d (standard circuit)", index));
                        }
                        if (!identity.exists("age")) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("age required for identity at index %d (standard circuit)", index));
                        }
                    }

                    // Parse public key
                    std::vector<unsigned char> pubkey_bytes = ParseHex(pubkey_hex);
                    std::vector<unsigned char> pubkey_x;

                    if (pubkey_bytes.size() == 33) {
                        // Compressed pubkey - extract X coordinate
                        pubkey_x.assign(pubkey_bytes.begin() + 1, pubkey_bytes.end());
                    } else if (pubkey_bytes.size() == 32) {
                        // Already just X coordinate
                        pubkey_x = pubkey_bytes;
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Invalid pubkey length %d (expected 32 or 33 bytes)",
                                      pubkey_bytes.size()));
                    }

                    // Compute leaf hash based on circuit type
                    if (circuit_type == "standard") {
                        // Standard circuit: H(pubkey_x || country || age) using SHA256
                        leaf_hash = ComputeKYCLeafHash(pubkey_x, country, age);
                    } else if (circuit_type == "hd_v1") {
                        // HDv1 circuit: MiMC(P.x, P.y) — full pubkey binding.
                        // Derive Y from the 33-byte compressed pubkey via secp256k1
                        // decompression. Do NOT accept caller-supplied Y.
                        if (pubkey_bytes.size() != 33) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("hd_v1 requires 33-byte compressed pubkey at index %d, got %d bytes",
                                          index, pubkey_bytes.size()));
                        }
                        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
                        secp256k1_pubkey pk;
                        if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bytes.data(), 33)) {
                            secp256k1_context_destroy(ctx);
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("Invalid compressed pubkey at index %d", index));
                        }
                        unsigned char uncompressed[65];
                        size_t unc_len = 65;
                        secp256k1_ec_pubkey_serialize(ctx, uncompressed, &unc_len, &pk, SECP256K1_EC_UNCOMPRESSED);
                        secp256k1_context_destroy(ctx);

                        std::vector<unsigned char> pubkey_y(uncompressed + 33, uncompressed + 65);
                        leaf_hash = ComputeKYCLeafHashHDV1(pubkey_x, pubkey_y);
                    }
                }

                LogPrintf("ZK_DEBUG [generatecomplianceroot]: Computed leaf_hash for index %d: 0x%s\n",
                          index, HexStr(std::span<const unsigned char>(leaf_hash.begin(), uint256::size())));

                // Update leaf at this index (overwrites previous value if any)
                leaves[index] = leaf_hash;

                LogPrintf("ZK_DEBUG [generatecomplianceroot]: Set leaves[%d] = 0x%s\n",
                          index, HexStr(std::span<const unsigned char>(leaves[index].begin(), uint256::size())));

                // Store identity info for result
                UniValue id_info(UniValue::VOBJ);
                id_info.pushKV("index", index);
                id_info.pushKV("leaf_hash", HexStr(std::span<const unsigned char>(leaf_hash.begin(), uint256::size())));
                identity_map[index] = id_info;
            }

            // Debug: Dump first 4 leaves before building tree
            LogPrintf("ZK_DEBUG [generatecomplianceroot]: Leaves array before BuildMerkleTree:\n");
            for (int i = 0; i < 4; ++i) {
                LogPrintf("  leaves[%d] = 0x%s\n",
                          i, HexStr(std::span<const unsigned char>(leaves[i].begin(), uint256::size())));
            }

            // Build merkle tree
            std::vector<std::vector<uint256>> tree_levels;
            std::map<int, std::vector<uint256>> merkle_proofs;
            uint256 root = BuildMerkleTree(leaves, tree_levels, merkle_proofs, circuit_type);

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("compliance_root", HexStr(root));

            // Add identity details with merkle proofs
            UniValue identities_result(UniValue::VARR);
            for (const auto& [index, id_info] : identity_map) {
                UniValue id_result = id_info;

                // Add merkle proof
                UniValue proof_arr(UniValue::VARR);
                if (merkle_proofs.count(index)) {
                    for (const auto& sibling : merkle_proofs.at(index)) {
                        // Use HexStr for BE format (circuit expects BE, GetHex returns LE)
                        proof_arr.push_back("0x" + HexStr(std::span<const unsigned char>(sibling.begin(), uint256::size())));
                    }
                }
                id_result.pushKV("merkle_proof", proof_arr);

                identities_result.push_back(id_result);
            }
            result.pushKV("identities", identities_result);

            // Include full leaf array for append-only model
            UniValue leaf_arr(UniValue::VARR);
            for (const auto& leaf : leaves) {
                if (leaf.IsNull()) {
                    leaf_arr.push_back("");  // Empty string for unused slots
                } else {
                    // Use HexStr for BE format (consistent with circuit expectations)
                    leaf_arr.push_back(HexStr(std::span<const unsigned char>(leaf.begin(), uint256::size())));
                }
            }
            result.pushKV("leaf_hashes", leaf_arr);

            result.pushKV("tree_depth", 8);

            // Count non-null leaves
            int active_count = 0;
            for (const auto& leaf : leaves) {
                if (!leaf.IsNull()) active_count++;
            }
            result.pushKV("total_identities", active_count);

            return result;
        }
    };
}

} // namespace wallet
