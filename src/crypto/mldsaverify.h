// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MLDSAVERIFY_H
#define BITCOIN_CRYPTO_MLDSAVERIFY_H

#include <span.h>

#include <cstddef>
#include <cstdint>
#include <optional>

namespace mldsa {

/** ML-DSA (FIPS 204) parameter sets */
enum class ParamSet : uint8_t {
    MLDSA_44 = 0x2C,  // Security level 2 (128-bit)
    MLDSA_65 = 0x41,  // Security level 3 (192-bit)
    MLDSA_87 = 0x57,  // Security level 5 (256-bit)
};

/** Algorithm identifier for ML-DSA in on-stack encoding */
static constexpr uint8_t ALG_ID_MLDSA = 0x01;

/** ML-DSA parameter set sizes (FIPS 204) */
struct ParamSetSizes {
    size_t pk_bytes;
    size_t sig_bytes;
};

/** Get sizes for a given parameter set */
constexpr ParamSetSizes GetParamSetSizes(ParamSet level) {
    switch (level) {
        case ParamSet::MLDSA_44:
            return {1312, 2420};
        case ParamSet::MLDSA_65:
            return {1952, 3309};
        case ParamSet::MLDSA_87:
            return {2592, 4627};
    }
    return {0, 0};  // Invalid
}

/**
 * Parsed ML-DSA public key.
 *
 * This struct represents a strictly parsed public key from on-stack encoding:
 *   1 byte alg_id  = 0x01            (ALG_ID_MLDSA)
 *   1 byte level   = 0x2C/0x41/0x57  (ParamSet)
 *   varint pk_len
 *   pk_bytes                         (FIPS 204: 1312/1952/2592 bytes)
 */
struct ParsedPublicKey {
    ParamSet level;
    std::span<const uint8_t> pk_bytes;
};

/**
 * Parse ML-DSA public key from on-stack encoding.
 *
 * Enforces:
 * - Exact algorithm ID (ALG_ID_MLDSA)
 * - Valid parameter set (44/65/87)
 * - Exact length matching parameter set
 * - Minimal varint encoding
 *
 * @param[in] blob  The encoded public key blob
 * @return ParsedPublicKey if valid, std::nullopt otherwise
 */
#ifdef ENABLE_MLDSA
std::optional<ParsedPublicKey> ParsePublicKey(std::span<const uint8_t> blob);
#else
inline std::optional<ParsedPublicKey> ParsePublicKey(std::span<const uint8_t>) { return std::nullopt; }
#endif

/**
 * Verify ML-DSA signature over a 32-byte message digest.
 *
 * This function:
 * - Parses the public key blob (algorithm ID, parameter set, length, pk bytes)
 * - Validates signature length against parameter set
 * - Calls constant-time FIPS 204 verification
 *
 * @param[in] pk_blob  Encoded public key (alg_id || level || varint len || pk)
 * @param[in] msg32    32-byte message digest (e.g., tagged Taproot sighash)
 * @param[in] sig      ML-DSA signature bytes (2420/3309/4627 bytes depending on level)
 * @return true if signature is valid, false otherwise
 *
 * IMPORTANT: This function is consensus-critical. It must:
 * - Reject malformed encodings without exception
 * - Use constant-time verification
 * - Match FIPS 204 specification exactly
 *
 * NOTE: If ENABLE_MLDSA is not defined (no backend compiled), this function
 * is not available and calling code must check for its presence.
 */
#ifdef ENABLE_MLDSA
bool MLDSA_Verify(std::span<const uint8_t> pk_blob, std::span<const uint8_t> msg32, std::span<const uint8_t> sig);
#else
// Stub when ML-DSA backend is not available
// This allows headers to be included even when liboqs is not present
inline bool MLDSA_Verify(std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>) { return false; }
#endif

/**
 * Read a compact varint from a span, advancing the span.
 *
 * Bitcoin-style varint encoding:
 * - 0x00-0xFC: 1 byte (value itself)
 * - 0xFD: 2 bytes following (little-endian uint16_t)
 * - 0xFE: 4 bytes following (little-endian uint32_t)
 * - 0xFF: 8 bytes following (little-endian uint64_t)
 *
 * @param[in,out] sp  Span to read from (advanced past varint on success)
 * @return The decoded value if valid and minimal, std::nullopt otherwise
 */
std::optional<uint64_t> ReadCompactSize(std::span<const uint8_t>& sp);

} // namespace mldsa

#endif // BITCOIN_CRYPTO_MLDSAVERIFY_H
