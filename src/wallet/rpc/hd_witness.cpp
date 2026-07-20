// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpc/util.h>
#include <wallet/rpc/wallet.h>
#include <wallet/wallet.h>
#include <rpc/util.h>
#include <hash.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <crypto/common.h>
#include <key.h>
#include <pubkey.h>
#include <key_io.h>
#include <span.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
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
#include <array>
#include <string>
#include <stdexcept>

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

// MiMC hash result structure (must match Go bridge)
struct MiMCHashResult {
    unsigned char* hash_data;
    int hash_len;
    char* error_msg;
};

typedef MiMCHashResult (*ComputeMiMCHashFunc)(const char*, const char*, const char*, const char*);
typedef void (*FreeMiMCResultFunc)(MiMCHashResult*);

namespace {

/** Convert uint256 to 0x-prefixed hex string (outputs bytes as stored).
 * Note: MiMC returns bytes in BE format, memcpy stores them as-is in m_data.
 * GetHex() reverses bytes (for number display), but circuit needs BE bytes as-is.
 * So we just output m_data directly without reversing.
 */
std::string Uint256ToBigEndianHex(const uint256& value)
{
    return "0x" + HexStr(std::span<const unsigned char>(value.begin(), uint256::size()));
}

} // namespace

// Helper function to compute MiMC hash via bridge
static uint256 ComputeMiMCHash(const std::string& tag_hex,
                               const std::string& input1_hex,
                               const std::string& input2_hex = "",
                               const std::string& input3_hex = "")
{
    // Load library
    void* handle = LoadZkProverLibrary("for MiMC hashing");

    // Get function pointers
    auto computeHash = (ComputeMiMCHashFunc)dlsym(handle, "Groth16_ComputeMiMCHash");
    auto freeResult = (FreeMiMCResultFunc)dlsym(handle, "Groth16_FreeMiMCResult");

    if (!computeHash || !freeResult) {
        dlclose(handle);
        throw std::runtime_error(strprintf("Failed to load MiMC functions: %s", dlerror()));
    }

    // Call function
    MiMCHashResult result = computeHash(
        tag_hex.c_str(),
        input1_hex.c_str(),
        input2_hex.empty() ? nullptr : input2_hex.c_str(),
        input3_hex.empty() ? nullptr : input3_hex.c_str()
    );

    // Check for error
    if (result.error_msg != nullptr) {
        std::string error(result.error_msg);
        freeResult(&result);
        dlclose(handle);
        throw std::runtime_error(strprintf("MiMC hash error: %s", error));
    }

    // Convert result to uint256
    if (result.hash_len != 32) {
        freeResult(&result);
        dlclose(handle);
        throw std::runtime_error(strprintf("MiMC hash returned unexpected length: %d", result.hash_len));
    }

    // MiMC returns bytes that we'll use directly (not for display, for crypto operations)
    // Copy as-is since secp256k1 expects big-endian bytes
    uint256 hash;
    memcpy(hash.begin(), result.hash_data, 32);

    // Cleanup
    freeResult(&result);
    dlclose(handle);

    return hash;
}

// Helper function to derive HD child key using BIP32-like derivation
static CPubKey DeriveHDChildKey(const CPubKey& master_pubkey,
                                uint32_t account,
                                uint32_t change,
                                uint32_t index,
                                uint32_t salt)
{
    // Build derivation data: "KYCHDV1" || master_pubkey_x || PathVector || Salt
    std::vector<unsigned char> derivation_data;

    // Add tag (must match circuit expectations!)
    std::string tag = "KYCHDV1";
    derivation_data.insert(derivation_data.end(), tag.begin(), tag.end());

    // Extract X coordinate from master pubkey
    std::vector<unsigned char> pubkey_bytes(master_pubkey.begin(), master_pubkey.end());
    std::vector<unsigned char> pubkey_x;

    if (pubkey_bytes.size() == 33) {
        // Compressed pubkey - extract X coordinate (skip first byte)
        pubkey_x.assign(pubkey_bytes.begin() + 1, pubkey_bytes.end());
    } else if (pubkey_bytes.size() == 65) {
        // Uncompressed - extract X coordinate (skip first byte, take next 32)
        pubkey_x.assign(pubkey_bytes.begin() + 1, pubkey_bytes.begin() + 33);
    } else {
        throw std::runtime_error("Invalid public key size");
    }

    derivation_data.insert(derivation_data.end(), pubkey_x.begin(), pubkey_x.end());

    // Pack PathVector: (account << 64) | (change << 32) | index
    arith_uint256 path_vector = arith_uint256(account);
    path_vector <<= 32;
    path_vector |= arith_uint256(change);
    path_vector <<= 32;
    path_vector |= arith_uint256(index);

    // Extract PathVector as 12 bytes (96 bits)
    unsigned char path_vector_bytes[12];
    WriteBE32(path_vector_bytes, (path_vector >> 64).GetLow64() & 0xFFFFFFFF);
    WriteBE32(path_vector_bytes + 4, (path_vector >> 32).GetLow64() & 0xFFFFFFFF);
    WriteBE32(path_vector_bytes + 8, path_vector.GetLow64() & 0xFFFFFFFF);

    // Step 1: Compute derivation commitment = H("KYCHDV1" || P.X || PathVector || Salt)
    std::string tag_hex = "0x4B594348445631";  // "KYCHDV1" in hex
    std::string px_hex = "0x" + HexStr(pubkey_x);  // P.X
    std::string path_hex = "0x" + path_vector.GetHex();  // PathVector
    arith_uint256 salt_value = arith_uint256(salt);
    std::string salt_hex = "0x" + salt_value.GetHex();  // Salt

    LogPrintf("ZK_DEBUG: DeriveHDChildKey called\n");
    LogPrintf("ZK_DEBUG:   px_hex = %s\n", px_hex);
    LogPrintf("ZK_DEBUG:   path_hex = %s (account=%u, change=%u, index=%u)\n",
              path_hex, account, change, index);
    LogPrintf("ZK_DEBUG:   salt_hex = %s (salt=%u)\n", salt_hex, salt);

    uint256 derivation_commitment = ComputeMiMCHash(tag_hex, px_hex, path_hex, salt_hex);

    LogPrintf("ZK_DEBUG:   Step 1 commitment = 0x%s\n", derivation_commitment.GetHex());

    // Step 2: Compute derivation scalar = H(commitment_LE || account || change || index)
    LogPrintf("ZK_DEBUG:   Starting step 2...\n");
    // CRITICAL: Use LE commitment (reversed from BE) for scalar derivation to match libsecp256k1 expectations
    // uint256 stores in LE internally, so reverse to get BE, which is the "LE commitment" in circuit terms
    std::string commitment_hex = Uint256ToBigEndianHex(derivation_commitment);
    LogPrintf("ZK_DEBUG:     Created commitment_hex\n");
    // Send account/change/index as 32-bit values (8 hex chars = 4 bytes), not 256-bit
    char account_buf[16];
    snprintf(account_buf, sizeof(account_buf), "0x%08x", account);
    std::string account_hex = account_buf;
    char change_buf[16];
    snprintf(change_buf, sizeof(change_buf), "0x%08x", change);
    std::string change_hex = change_buf;
    char index_buf[16];
    snprintf(index_buf, sizeof(index_buf), "0x%08x", index);
    std::string index_hex = index_buf;

    LogPrintf("ZK_DEBUG:   Step 2 inputs:\n");
    LogPrintf("ZK_DEBUG:     commitment_hex = %s\n", commitment_hex);
    LogPrintf("ZK_DEBUG:     account_hex = %s\n", account_hex);
    LogPrintf("ZK_DEBUG:     change_hex = %s\n", change_hex);
    LogPrintf("ZK_DEBUG:     index_hex = %s\n", index_hex);

    uint256 derivation_scalar_full = ComputeMiMCHash(commitment_hex, account_hex, change_hex, index_hex);

    LogPrintf("ZK_DEBUG:   Step 2 derivation_scalar = 0x%s\n", derivation_scalar_full.GetHex());

    // Use derivation_scalar_full as the tweak (secp256k1 library will reduce mod order internally)
    uint256 derivation_hash = derivation_scalar_full;

    // Convert to scalar modulo secp256k1 order
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Parse master pubkey
    secp256k1_pubkey master_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &master_pk, pubkey_bytes.data(), pubkey_bytes.size())) {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to parse master public key");
    }

    // Compute Q = P + h·G (child key derivation)
    secp256k1_pubkey child_pk;

    // Add the derivation_hash as a tweak to the master pubkey
    // This is Q = P + h·G where h is the derivation hash
    // MiMC returns BE bytes which are stored as-is in uint256.
    // secp256k1 expects BE bytes, so copy directly (no reversal needed).
    unsigned char tweak[32];
    std::copy(derivation_hash.begin(), derivation_hash.end(), tweak);

    LogPrintf("ZK_DEBUG:   Tweak bytes for secp256k1 (big-endian, should match derivation_scalar): %s\n", HexStr(tweak));

    child_pk = master_pk; // Copy master
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &child_pk, tweak)) {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to derive child public key");
    }

    // Serialize child pubkey (compressed)
    unsigned char child_bytes[33];
    size_t child_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, child_bytes, &child_len, &child_pk, SECP256K1_EC_COMPRESSED);

    LogPrintf("ZK_DEBUG:   Derived child pubkey (compressed) = %s\n", HexStr(child_bytes));

    secp256k1_context_destroy(ctx);

    return CPubKey(child_bytes, child_bytes + child_len);
}

// Deterministic 32-bit salt derived from wallet inputs. Keeps the legacy width while
// eliminating low-entropy defaults so even unattended RPC calls get per-path uniqueness.
static uint32_t DeriveDeterministicSalt(const CPubKey& master_pubkey,
                                        uint32_t account,
                                        uint32_t change,
                                        uint32_t index,
                                        uint32_t merkle_index)
{
    static const std::string kDomain = "TensorCash/KYC-HDv1/Salt";
    CSHA256 hasher;
    hasher.Write(UCharCast(kDomain.data()), kDomain.size());
    hasher.Write(master_pubkey.begin(), master_pubkey.size());

    unsigned char buf[4];
    WriteBE32(buf, account);
    hasher.Write(buf, sizeof(buf));
    WriteBE32(buf, change);
    hasher.Write(buf, sizeof(buf));
    WriteBE32(buf, index);
    hasher.Write(buf, sizeof(buf));
    WriteBE32(buf, merkle_index);
    hasher.Write(buf, sizeof(buf));

    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);

    return ReadBE32(digest);
}

RPCHelpMan generatehdwitnessdata()
{
    return RPCHelpMan{
        "generatehdwitnessdata",
        "Generate witness data for KYC HD zero-knowledge proofs.\n"
        "This RPC creates all the cryptographic data needed for HD proof generation.\n"
        "The HD system allows deriving child keys from a master key for privacy.",
        {
            {"master_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Master public key (33-byte compressed or 65-byte uncompressed)"},
            {"country", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "ISO 3166-1 numeric country code (metadata only, not used in leaf hash)"},
            {"age", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "Age in years 0-255 (metadata only, not used in leaf hash)"},
            {"merkle_index", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Index in the compliance merkle tree (0-255)"},
            {"merkle_proof", RPCArg::Type::ARR, RPCArg::Optional::NO,
             "Merkle proof (sibling hashes from leaf to root)",
                {
                    {"", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Sibling hash at this level"}
                }
            },
            {"derivation", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED,
             "HD derivation path parameters",
                {
                    {"account", RPCArg::Type::NUM, RPCArg::Default{0}, "Account index"},
                    {"change", RPCArg::Type::NUM, RPCArg::Default{0}, "Change index (0=external, 1=internal)"},
                    {"index", RPCArg::Type::NUM, RPCArg::Default{0}, "Address index"},
                    {"salt", RPCArg::Type::NUM, RPCArg::Default{0}, "Random salt for additional entropy"},
                }
            },
            {"compliance_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
             "Expected compliance root (for verification)"},
            {"master_secret", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
             "Master private key (hex). If provided, derives child_secret for wallet import. "
             "Not used by the ZK circuit (pubkey-only design). TESTING ONLY."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "master_pubkey_x", "X coordinate of master public key"},
                {RPCResult::Type::STR_HEX, "master_pubkey_y", "Y coordinate of master public key"},
                {RPCResult::Type::STR_HEX, "child_pubkey", "Derived child public key (compressed)"},
                {RPCResult::Type::STR_HEX, "child_pubkey_x", "X coordinate of child public key"},
                {RPCResult::Type::STR_HEX, "child_pubkey_y", "Y coordinate of child public key"},
                {RPCResult::Type::STR, "child_address", "Taproot (bech32m) address for the child key"},
                {RPCResult::Type::STR_HEX, "child_secret", /*optional=*/true, "Derived child private key for wallet import when master_secret is supplied. TESTING ONLY."},
                {RPCResult::Type::STR_HEX, "leaf_hash", "Merkle tree leaf hash (MiMC, BE hex)"},
                {RPCResult::Type::NUM, "merkle_index", "Index in merkle tree"},
                {RPCResult::Type::ARR, "merkle_proof", "Merkle proof siblings",
                    {
                        {RPCResult::Type::STR_HEX, "", "Sibling hash"}
                    }
                },
                {RPCResult::Type::STR_HEX, "computed_root", "Computed merkle root from proof"},
                {RPCResult::Type::BOOL, "root_matches", /*optional=*/true, "Whether computed root matches provided compliance_root"},
                {RPCResult::Type::OBJ, "path", "Derivation path used",
                    {
                        {RPCResult::Type::NUM, "account", "Account index"},
                        {RPCResult::Type::NUM, "change", "Change index"},
                        {RPCResult::Type::NUM, "index", "Address index"},
                        {RPCResult::Type::NUM, "salt", "Salt value"},
                    }
                },
                {RPCResult::Type::NUM, "country", /*optional*/ "Country code (metadata only, not in leaf hash)"},
                {RPCResult::Type::NUM, "age", /*optional*/ "Age (metadata only, not in leaf hash)"},
                {RPCResult::Type::OBJ, "witness_data", "Witness data for proof generation (V1 packed format, 32-byte padded with 0x prefix)",
                    {
                        {RPCResult::Type::STR_HEX, "master_pubkey_x", "Parent public key X coordinate (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "master_pubkey_y", "Master public key Y coordinate (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "child_pubkey_x", "Child public key X coordinate (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "child_pubkey_y", "Child public key Y coordinate (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "derivation_commitment", "Derivation commitment hash (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "path_vector", "Packed path: account||change||index, padded to 32 bytes (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "salt", "Salt value, padded to 32 bytes (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "output_key_high", "Upper 128 bits of child x-only key (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "output_key_low", "Lower 128 bits of child x-only key (0x + 64 hex chars)"},
                        {RPCResult::Type::STR_HEX, "merkle_path_bits", "Packed merkle index, padded to 32 bytes (0x + 64 hex chars)"},
                        {RPCResult::Type::ARR, "merkle_siblings", "Merkle proof sibling hashes",
                            {
                                {RPCResult::Type::STR_HEX, "", "Sibling hash"}
                            }
                        }
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("generatehdwitnessdata",
                "\"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\" 840 35 0 "
                "'[\"0x1234...\", \"0x5678...\", ...]'") +
            HelpExampleRpc("generatehdwitnessdata",
                "\"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\", 840, 35, 0, "
                "[\"0x1234...\", \"0x5678...\"], {\"account\": 0, \"change\": 0, \"index\": 1, \"salt\": 42}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Parse master public key
            std::string master_pubkey_hex = request.params[0].get_str();
            std::vector<unsigned char> master_pubkey_bytes = ParseHex(master_pubkey_hex);

            if (master_pubkey_bytes.size() != 33 && master_pubkey_bytes.size() != 65) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid master public key size %d (expected 33 or 65)",
                              master_pubkey_bytes.size()));
            }

            CPubKey master_pubkey(master_pubkey_bytes.begin(), master_pubkey_bytes.end());
            if (!master_pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid master public key");
            }

            // Parse optional KYC metadata (not used in leaf hash — off-chain issuer policy)
            int country = 0;
            int age = 0;
            if (!request.params[1].isNull()) {
                country = request.params[1].getInt<int>();
                if (country < 0 || country > 999) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid country code %d (must be 0-999)", country));
                }
            }
            if (!request.params[2].isNull()) {
                age = request.params[2].getInt<int>();
                if (age < 0 || age > 255) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid age %d (must be 0-255)", age));
                }
            }

            // Parse merkle index
            int merkle_index = request.params[3].getInt<int>();
            if (merkle_index < 0 || merkle_index >= 256) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid merkle index %d (must be 0-255)", merkle_index));
            }

            // Parse merkle proof
            std::vector<uint256> merkle_proof;
            const UniValue& proof_arr = request.params[4].get_array();
            for (size_t i = 0; i < proof_arr.size(); ++i) {
                std::string sibling_hex = proof_arr[i].get_str();
                // Remove 0x prefix if present
                if (sibling_hex.substr(0, 2) == "0x") {
                    sibling_hex = sibling_hex.substr(2);
                }
                auto sibling_bytes = ParseHex(sibling_hex);
                if (sibling_bytes.size() == 32) {
                    uint256 sibling;
                    std::memcpy(sibling.begin(), sibling_bytes.data(), 32);
                    merkle_proof.push_back(sibling);
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid merkle proof sibling at index %d", i));
                }
            }

            // Parse derivation path (optional)
            uint32_t path_account = 0;
            uint32_t path_change = 0;
            uint32_t path_index = 0;
            uint32_t salt = 0;
            bool salt_provided = false;

            if (!request.params[5].isNull()) {
                const UniValue& derivation_obj = request.params[5].get_obj();
                if (derivation_obj.exists("account")) {
                    path_account = derivation_obj["account"].getInt<int>();
                }
                if (derivation_obj.exists("change")) {
                    path_change = derivation_obj["change"].getInt<int>();
                }
                if (derivation_obj.exists("index")) {
                    path_index = derivation_obj["index"].getInt<int>();
                }
                if (derivation_obj.exists("salt")) {
                    salt = derivation_obj["salt"].getInt<int>();
                    salt_provided = true;
                }
            }

            if (!salt_provided) {
                salt = DeriveDeterministicSalt(master_pubkey, path_account, path_change, path_index, merkle_index);
                LogPrintf("ZK_DEBUG:   auto-derived deterministic salt (32-bit) = %u\n", salt);
            }

            // Extract master pubkey coordinates
            std::vector<unsigned char> master_x, master_y;
            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
            secp256k1_pubkey master_pk;

            if (!secp256k1_ec_pubkey_parse(ctx, &master_pk, master_pubkey_bytes.data(), master_pubkey_bytes.size())) {
                secp256k1_context_destroy(ctx);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse master public key");
            }

            // Get uncompressed form to extract coordinates
            unsigned char master_uncompressed[65];
            size_t master_len = 65;
            secp256k1_ec_pubkey_serialize(ctx, master_uncompressed, &master_len, &master_pk, SECP256K1_EC_UNCOMPRESSED);

            master_x.assign(master_uncompressed + 1, master_uncompressed + 33);
            master_y.assign(master_uncompressed + 33, master_uncompressed + 65);

            LogPrintf("ZK_DEBUG: Extracted master_pubkey coordinates for witness:\n");
            LogPrintf("ZK_DEBUG:   master_x (witness) = 0x%s\n", HexStr(master_x));
            LogPrintf("ZK_DEBUG:   master_y (witness) = 0x%s\n", HexStr(master_y));

            // Derive child key
            CPubKey child_pubkey = DeriveHDChildKey(master_pubkey, path_account, path_change, path_index, salt);

            // Extract child pubkey coordinates
            std::vector<unsigned char> child_bytes(child_pubkey.begin(), child_pubkey.end());
            secp256k1_pubkey child_pk;

            if (!secp256k1_ec_pubkey_parse(ctx, &child_pk, child_bytes.data(), child_bytes.size())) {
                secp256k1_context_destroy(ctx);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse child public key");
            }

            unsigned char child_uncompressed[65];
            size_t child_len = 65;
            secp256k1_ec_pubkey_serialize(ctx, child_uncompressed, &child_len, &child_pk, SECP256K1_EC_UNCOMPRESSED);

            std::vector<unsigned char> child_x(child_uncompressed + 1, child_uncompressed + 33);
            std::vector<unsigned char> child_y(child_uncompressed + 33, child_uncompressed + 65);

            secp256k1_context_destroy(ctx);

            // Compute leaf hash: MiMC(P.x, P.y) — full pubkey binding
            // Matches ComputeKYCLeafHashHDV1 in compliance_root.cpp
            std::string leaf_px_hex = "0x" + HexStr(master_x);
            std::string leaf_py_hex = "0x" + HexStr(master_y);
            uint256 leaf_hash = ComputeMiMCHash("", leaf_px_hex, leaf_py_hex);

            // Compute merkle root from proof using MiMC node hashing
            // Matches HashMerkleNodeMiMC pattern in compliance_root.cpp
            uint256 current = leaf_hash;
            for (size_t i = 0; i < merkle_proof.size(); ++i) {
                std::string current_hex = Uint256ToBigEndianHex(current);
                std::string sibling_hex = Uint256ToBigEndianHex(merkle_proof[i]);

                // Check bit at position i of merkle_index
                if ((merkle_index >> i) & 1) {
                    // Current node is right child
                    current = ComputeMiMCHash("", sibling_hex, current_hex);
                } else {
                    // Current node is left child
                    current = ComputeMiMCHash("", current_hex, sibling_hex);
                }
            }
            uint256 computed_root = current;

            // Get child address as rawtr Taproot (bcrt1p... / bc1p...)
            XOnlyPubKey xonly_child(child_pubkey);
            WitnessV1Taproot taproot_dest{xonly_child};
            CTxDestination dest = taproot_dest;
            std::string child_address = EncodeDestination(dest);

            // Optional: derive child private key if master_secret provided (TESTING ONLY)
            // child_secret = master_secret + derivation_scalar (mod secp256k1 order)
            bool result_has_child_secret = false;
            std::string child_secret_hex;
            if (!request.params[7].isNull()) {
                std::string master_secret_hex = request.params[7].get_str();
                if (master_secret_hex.size() >= 2 && master_secret_hex.substr(0, 2) == "0x") {
                    master_secret_hex = master_secret_hex.substr(2);
                }
                auto secret_bytes = ParseHex(master_secret_hex);
                if (secret_bytes.size() == 32) {
                    // Recompute derivation scalar (same as DeriveHDChildKey)
                    std::string tag_hex = "0x4B594348445631";
                    std::string px_hex = "0x" + HexStr(master_x);
                    arith_uint256 pv = arith_uint256(path_account);
                    pv <<= 32; pv |= arith_uint256(path_change);
                    pv <<= 32; pv |= arith_uint256(path_index);
                    std::string path_hex = "0x" + pv.GetHex();
                    arith_uint256 sv = arith_uint256(salt);
                    std::string salt_hex = "0x" + sv.GetHex();
                    uint256 commitment = ComputeMiMCHash(tag_hex, px_hex, path_hex, salt_hex);
                    std::string commit_be = Uint256ToBigEndianHex(commitment);
                    char abuf[16], cbuf[16], ibuf[16];
                    snprintf(abuf, sizeof(abuf), "0x%08x", path_account);
                    snprintf(cbuf, sizeof(cbuf), "0x%08x", path_change);
                    snprintf(ibuf, sizeof(ibuf), "0x%08x", path_index);
                    uint256 deriv_scalar = ComputeMiMCHash(commit_be, std::string(abuf), std::string(cbuf), std::string(ibuf));

                    // Compute child_secret = master_secret + tweak (mod secp256k1 order)
                    // Use libsecp256k1: ec_seckey_tweak_add
                    secp256k1_context* sctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
                    unsigned char child_secret[32];
                    std::memcpy(child_secret, secret_bytes.data(), 32);

                    // MiMC bytes were copied into uint256 storage as-is, so begin() already
                    // yields the big-endian tweak bytes secp256k1 expects.
                    unsigned char tweak[32];
                    std::copy(deriv_scalar.begin(), deriv_scalar.end(), tweak);

                    if (secp256k1_ec_seckey_tweak_add(sctx, child_secret, tweak)) {
                        result_has_child_secret = true;
                        child_secret_hex = HexStr(std::span<const unsigned char>(child_secret, 32));
                    }
                    secp256k1_context_destroy(sctx);
                    // Zero sensitive material
                    std::memset(child_secret, 0, 32);
                }
            }

            // Build result — all hashes use BE (HexStr) for consistency with generatecomplianceroot
            UniValue result(UniValue::VOBJ);
            result.pushKV("master_pubkey_x", HexStr(master_x));
            result.pushKV("master_pubkey_y", HexStr(master_y));
            result.pushKV("child_pubkey", HexStr(child_bytes));
            result.pushKV("child_pubkey_x", HexStr(child_x));
            result.pushKV("child_pubkey_y", HexStr(child_y));
            result.pushKV("child_address", child_address);
            if (result_has_child_secret) {
                result.pushKV("child_secret", child_secret_hex);
            }
            result.pushKV("leaf_hash", Uint256ToBigEndianHex(leaf_hash));
            result.pushKV("merkle_index", merkle_index);

            UniValue proof_result(UniValue::VARR);
            for (const auto& sibling : merkle_proof) {
                proof_result.push_back(Uint256ToBigEndianHex(sibling));
            }
            result.pushKV("merkle_proof", proof_result);
            result.pushKV("computed_root", Uint256ToBigEndianHex(computed_root));

            // Compare against provided compliance_root if given (param index 6)
            // Use BE hex (Uint256ToBigEndianHex) — matches generatecomplianceroot output
            if (!request.params[6].isNull()) {
                std::string expected_root_hex = request.params[6].get_str();
                // Remove 0x prefix if present
                if (expected_root_hex.size() >= 2 && expected_root_hex.substr(0, 2) == "0x") {
                    expected_root_hex = expected_root_hex.substr(2);
                }
                std::string computed_root_be = Uint256ToBigEndianHex(computed_root);
                // Strip 0x prefix from computed for comparison
                std::string computed_cmp = computed_root_be;
                if (computed_cmp.size() >= 2 && computed_cmp.substr(0, 2) == "0x") {
                    computed_cmp = computed_cmp.substr(2);
                }
                bool root_matches = (computed_cmp == expected_root_hex);
                result.pushKV("root_matches", root_matches);
                if (!root_matches) {
                    LogPrintf("ZK_DEBUG: compliance_root mismatch: computed=%s expected=%s\n",
                              computed_root_be, expected_root_hex);
                }
            }

            UniValue path_result(UniValue::VOBJ);
            path_result.pushKV("account", (int)path_account);
            path_result.pushKV("change", (int)path_change);
            path_result.pushKV("index", (int)path_index);
            path_result.pushKV("salt", (int)salt);
            result.pushKV("path", path_result);

            if (country > 0) result.pushKV("country", country);
            if (age > 0) result.pushKV("age", age);

            // Build complete witness data structure for proof generation (V1 packed format only)
            // DO NOT include integer fields - assets.cpp will try to pack them incorrectly!
            // All hex values must be padded to 32 bytes with "0x" prefix to match Go BigIntToHex format
            UniValue witness(UniValue::VOBJ);
            witness.pushKV("master_pubkey_x", "0x" + HexStr(master_x));
            witness.pushKV("master_pubkey_y", "0x" + HexStr(master_y));
            witness.pushKV("child_pubkey_x", "0x" + HexStr(child_x));
            witness.pushKV("child_pubkey_y", "0x" + HexStr(child_y));

            // Compute derivation_commitment = H("KYCHDV1" || P.X || PathVector || Salt)
            // Pack path_vector using proper bit shifting: (account << 64) | (change << 32) | index
            arith_uint256 path_vector = arith_uint256(path_account);
            path_vector <<= 32;
            path_vector |= arith_uint256(path_change);
            path_vector <<= 32;
            path_vector |= arith_uint256(path_index);

            // Convert path_vector to bytes for commitment computation
            unsigned char path_vector_bytes[12];
            WriteBE32(path_vector_bytes, (path_vector >> 64).GetLow64() & 0xFFFFFFFF);
            WriteBE32(path_vector_bytes + 4, (path_vector >> 32).GetLow64() & 0xFFFFFFFF);
            WriteBE32(path_vector_bytes + 8, path_vector.GetLow64() & 0xFFFFFFFF);

            unsigned char salt_bytes[4];
            WriteBE32(salt_bytes, salt);

            // Compute MiMC hash: H("KYCHDV1" || P.X || PathVector || Salt)
            std::string commitment_tag_hex = "0x4B594348445631";  // "KYCHDV1" as hex
            std::string master_px_hex = "0x" + HexStr(master_x);  // master_x is already 32 bytes
            std::string path_vector_hex = "0x" + path_vector.GetHex();
            arith_uint256 salt_value = arith_uint256(salt);
            std::string salt_hex = "0x" + salt_value.GetHex();

            LogPrintf("ZK_DEBUG: Computing MiMC commitment for HD v1 witness\n");
            LogPrintf("ZK_DEBUG:   master_px_hex = %s\n", master_px_hex);
            LogPrintf("ZK_DEBUG:   path_vector_hex = %s (account=%u, change=%u, index=%u)\n",
                      path_vector_hex, path_account, path_change, path_index);
            LogPrintf("ZK_DEBUG:   salt_hex = %s (salt=%u)\n", salt_hex, salt);

            uint256 derivation_commitment = ComputeMiMCHash(commitment_tag_hex, master_px_hex, path_vector_hex, salt_hex);

            LogPrintf("ZK_DEBUG:   derivation_commitment = 0x%s\n", derivation_commitment.GetHex());

            // Helper lambda to convert arith_uint256 to 32-byte padded hex with "0x" prefix
            auto uint256ToHex = [](const arith_uint256& val) -> std::string {
                return "0x" + val.GetHex();
            };

            // Helper lambda to pad bytes to 32 bytes with "0x" prefix
            auto bytesToHex = [](const std::vector<unsigned char>& data) -> std::string {
                unsigned char padded[32] = {0};
                size_t offset = 32 - std::min(data.size(), size_t(32));
                std::copy(data.begin(), data.end(), padded + offset);
                return "0x" + HexStr(padded);
            };

            // CRITICAL: Circuit expects BE, but uint256::GetHex() outputs LE
            // Must reverse bytes: LE (GetHex output) → BE (circuit format)
            std::string commitment_be = Uint256ToBigEndianHex(derivation_commitment);
            LogPrintf("ZK_DEBUG:   commitment LE (GetHex) = 0x%s\n", derivation_commitment.GetHex());
            LogPrintf("ZK_DEBUG:   commitment BE (after reverse) = %s\n", commitment_be);
            witness.pushKV("derivation_commitment", commitment_be);
            witness.pushKV("path_vector", uint256ToHex(path_vector));
            witness.pushKV("salt", bytesToHex(std::vector<unsigned char>(salt_bytes, salt_bytes + 4)));

            // Output key binding: split child x-only key into high/low 128-bit halves
            // child_x is 32 bytes BE — high = bytes[0:16], low = bytes[16:32]
            std::vector<unsigned char> output_key_high_bytes(16, 0);
            std::vector<unsigned char> output_key_low_bytes(16, 0);
            if (child_x.size() >= 32) {
                std::copy(child_x.begin(), child_x.begin() + 16, output_key_high_bytes.begin());
                std::copy(child_x.begin() + 16, child_x.begin() + 32, output_key_low_bytes.begin());
            }
            witness.pushKV("output_key_high", bytesToHex(output_key_high_bytes));
            witness.pushKV("output_key_low", bytesToHex(output_key_low_bytes));

            // merkle_path_bits is just the merkle index as a number
            arith_uint256 merkle_path_bits = arith_uint256(merkle_index);
            witness.pushKV("merkle_path_bits", uint256ToHex(merkle_path_bits));

            witness.pushKV("merkle_siblings", proof_result);

            result.pushKV("witness_data", witness);

            return result;
        }
    };
}

} // namespace wallet
