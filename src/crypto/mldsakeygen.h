// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MLDSAKEYGEN_H
#define BITCOIN_CRYPTO_MLDSAKEYGEN_H

#include <crypto/mldsaverify.h>
#include <vector>

namespace mldsa {

/**
 * ML-DSA secret key sizes (FIPS 204).
 *
 * Secret keys contain:
 * - Seed material (rho, K, tr)
 * - Polynomial coefficients (s1, s2, t0)
 */
constexpr size_t MLDSA_44_SK_BYTES = 2560;
constexpr size_t MLDSA_65_SK_BYTES = 4032;
constexpr size_t MLDSA_87_SK_BYTES = 4896;

/**
 * Get secret key size for a given parameter set.
 */
constexpr size_t GetSecretKeySize(ParamSet level) {
    switch (level) {
        case ParamSet::MLDSA_44: return MLDSA_44_SK_BYTES;
        case ParamSet::MLDSA_65: return MLDSA_65_SK_BYTES;
        case ParamSet::MLDSA_87: return MLDSA_87_SK_BYTES;
    }
    return 0;  // Invalid
}

/**
 * Generate ML-DSA keypair.
 *
 * @param[in]  level    Parameter set (44/65/87)
 * @param[out] pk_out   Public key output (1312/1952/2592 bytes, raw FIPS 204 format)
 * @param[out] sk_out   Secret key output (2560/4032/4896 bytes)
 * @return true on success, false if backend unavailable or generation failed
 *
 * NOTE: This function generates FRESH randomness. Do NOT call for deterministic
 *       key derivation (use HKDF or similar externally if needed).
 *
 * SECURITY: Uses system randomness via liboqs. Ensure adequate entropy.
 */
#ifdef ENABLE_MLDSA
bool MLDSA_Keygen(ParamSet level, std::vector<uint8_t>& pk_out, std::vector<uint8_t>& sk_out);
#else
inline bool MLDSA_Keygen(ParamSet, std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }
#endif

/**
 * Sign a 32-byte message with ML-DSA secret key.
 *
 * @param[in]  sk       Secret key (2560/4032/4896 bytes depending on level)
 * @param[in]  msg32    32-byte message digest (e.g., Taproot sighash)
 * @param[in]  level    Parameter set (must match sk)
 * @param[out] sig_out  Signature output (2420/3309/4627 bytes)
 * @return true on success, false if signing failed
 *
 * IMPORTANT: This function is deterministic per FIPS 204. The same sk + msg32
 *            will produce the same signature (hedged randomness via rng=0).
 *
 * SECURITY: Uses constant-time FIPS 204 signing implementation.
 */
#ifdef ENABLE_MLDSA
bool MLDSA_Sign(std::span<const uint8_t> sk, std::span<const uint8_t> msg32, ParamSet level, std::vector<uint8_t>& sig_out);
#else
inline bool MLDSA_Sign(std::span<const uint8_t>, std::span<const uint8_t>, ParamSet, std::vector<uint8_t>&) { return false; }
#endif

} // namespace mldsa

#endif // BITCOIN_CRYPTO_MLDSAKEYGEN_H
