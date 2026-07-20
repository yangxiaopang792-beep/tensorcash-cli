// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mldsaverify.h>

#include <crypto/common.h>
#include <support/cleanse.h>

#include <algorithm>
#include <cstring>

// ML-DSA backend selection (compile-time)
// Default: USE_LIBOQS (production-ready, battle-tested)
// Alternative: USE_MLDSA_NATIVE (C90, CBMC-proven, but WIP)
#if !defined(USE_LIBOQS) && !defined(USE_MLDSA_NATIVE)
#define USE_LIBOQS 1
#endif

#ifdef USE_LIBOQS
// liboqs ML-DSA API (derived from PQClean/pq-crystals)
extern "C" {
#include <oqs/oqs.h>
}
#endif

#ifdef USE_MLDSA_NATIVE
// mldsa-native FIPS 204 reference implementation
// External-mu mode: accepts prehashed message
extern "C" {
    int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pk);

    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pk);

    int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pk);
}
#endif

namespace mldsa {

std::optional<uint64_t> ReadCompactSize(std::span<const uint8_t>& sp)
{
    if (sp.empty()) return std::nullopt;

    uint64_t val = 0;
    uint8_t first = sp[0];

    if (first < 0xFD) {
        val = first;
        sp = sp.subspan(1);
    } else if (first == 0xFD) {
        if (sp.size() < 3) return std::nullopt;
        val = ReadLE16(sp.data() + 1);
        if (val < 0xFD) return std::nullopt;  // Non-minimal encoding
        sp = sp.subspan(3);
    } else if (first == 0xFE) {
        if (sp.size() < 5) return std::nullopt;
        val = ReadLE32(sp.data() + 1);
        if (val <= 0xFFFF) return std::nullopt;  // Non-minimal encoding
        sp = sp.subspan(5);
    } else {  // 0xFF
        if (sp.size() < 9) return std::nullopt;
        val = ReadLE64(sp.data() + 1);
        if (val <= 0xFFFFFFFF) return std::nullopt;  // Non-minimal encoding
        sp = sp.subspan(9);
    }

    return val;
}

std::optional<ParsedPublicKey> ParsePublicKey(std::span<const uint8_t> blob)
{
    std::span<const uint8_t> sp = blob;

    // Read algorithm ID
    if (sp.empty()) return std::nullopt;
    uint8_t alg_id = sp[0];
    sp = sp.subspan(1);

    if (alg_id != ALG_ID_MLDSA) return std::nullopt;

    // Read parameter set level
    if (sp.empty()) return std::nullopt;
    uint8_t level_byte = sp[0];
    sp = sp.subspan(1);

    ParamSet level;
    switch (level_byte) {
        case static_cast<uint8_t>(ParamSet::MLDSA_44):
            level = ParamSet::MLDSA_44;
            break;
        case static_cast<uint8_t>(ParamSet::MLDSA_65):
            level = ParamSet::MLDSA_65;
            break;
        case static_cast<uint8_t>(ParamSet::MLDSA_87):
            level = ParamSet::MLDSA_87;
            break;
        default:
            return std::nullopt;
    }

    // Read public key length (varint)
    auto pk_len_opt = ReadCompactSize(sp);
    if (!pk_len_opt) return std::nullopt;
    uint64_t pk_len = *pk_len_opt;

    // Validate pk_len matches parameter set
    ParamSetSizes sizes = GetParamSetSizes(level);
    if (pk_len != sizes.pk_bytes) return std::nullopt;

    // Enforce exact size (no trailing data)
    if (sp.size() != pk_len) return std::nullopt;

    // Extract pk_bytes (use entire remaining span)
    std::span<const uint8_t> pk_bytes = sp;

    return ParsedPublicKey{level, pk_bytes};
}

bool MLDSA_Verify(std::span<const uint8_t> pk_blob, std::span<const uint8_t> msg32, std::span<const uint8_t> sig)
{
    // Enforce 32-byte message (Taproot sighash)
    if (msg32.size() != 32) return false;

    // Parse public key
    auto parsed_pk_opt = ParsePublicKey(pk_blob);
    if (!parsed_pk_opt) return false;

    const ParsedPublicKey& parsed_pk = *parsed_pk_opt;
    ParamSetSizes sizes = GetParamSetSizes(parsed_pk.level);

    // Validate signature length
    if (sig.size() != sizes.sig_bytes) return false;

    // Dispatch to backend-specific verification
#ifdef USE_LIBOQS
    // liboqs backend
    OQS_STATUS status = OQS_ERROR;

    switch (parsed_pk.level) {
        case ParamSet::MLDSA_44: {
            OQS_SIG *sig_alg = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
            if (sig_alg) {
                status = OQS_SIG_verify(sig_alg, msg32.data(), msg32.size(),
                                        sig.data(), sig.size(),
                                        parsed_pk.pk_bytes.data());
                OQS_SIG_free(sig_alg);
            }
            break;
        }
        case ParamSet::MLDSA_65: {
            OQS_SIG *sig_alg = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
            if (sig_alg) {
                status = OQS_SIG_verify(sig_alg, msg32.data(), msg32.size(),
                                        sig.data(), sig.size(),
                                        parsed_pk.pk_bytes.data());
                OQS_SIG_free(sig_alg);
            }
            break;
        }
        case ParamSet::MLDSA_87: {
            OQS_SIG *sig_alg = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
            if (sig_alg) {
                status = OQS_SIG_verify(sig_alg, msg32.data(), msg32.size(),
                                        sig.data(), sig.size(),
                                        parsed_pk.pk_bytes.data());
                OQS_SIG_free(sig_alg);
            }
            break;
        }
    }

    return (status == OQS_SUCCESS);

#elif defined(USE_MLDSA_NATIVE)
    // mldsa-native backend (external-mu / prehash mode)
    int result = -1;

    switch (parsed_pk.level) {
        case ParamSet::MLDSA_44:
            result = pqcrystals_dilithium2_ref_verify(
                sig.data(), sig.size(),
                msg32.data(), msg32.size(),
                parsed_pk.pk_bytes.data()
            );
            break;

        case ParamSet::MLDSA_65:
            result = pqcrystals_dilithium3_ref_verify(
                sig.data(), sig.size(),
                msg32.data(), msg32.size(),
                parsed_pk.pk_bytes.data()
            );
            break;

        case ParamSet::MLDSA_87:
            result = pqcrystals_dilithium5_ref_verify(
                sig.data(), sig.size(),
                msg32.data(), msg32.size(),
                parsed_pk.pk_bytes.data()
            );
            break;
    }

    // FIPS 204 reference returns 0 on success, non-zero on failure
    return (result == 0);

#else
    // This should never be reached because mldsaverify.cpp is only compiled when
    // a backend is available (see CMakeLists.txt). If you see this error, check
    // that ENABLE_MLDSA is defined.
    #error "mldsaverify.cpp compiled without a backend. Check CMakeLists.txt configuration."
#endif
}

} // namespace mldsa
