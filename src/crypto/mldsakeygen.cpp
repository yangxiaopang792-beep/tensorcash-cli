// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mldsakeygen.h>

#ifdef ENABLE_MLDSA
extern "C" {
#include <oqs/oqs.h>
}
#endif

namespace mldsa {

#ifdef ENABLE_MLDSA

bool MLDSA_Keygen(ParamSet level, std::vector<uint8_t>& pk_out, std::vector<uint8_t>& sk_out)
{
    const char* alg_name = nullptr;

    switch (level) {
        case ParamSet::MLDSA_44:
            alg_name = OQS_SIG_alg_ml_dsa_44;
            break;
        case ParamSet::MLDSA_65:
            alg_name = OQS_SIG_alg_ml_dsa_65;
            break;
        case ParamSet::MLDSA_87:
            alg_name = OQS_SIG_alg_ml_dsa_87;
            break;
        default:
            return false;
    }

    OQS_SIG* sig = OQS_SIG_new(alg_name);
    if (!sig) return false;

    // Resize output vectors
    pk_out.resize(sig->length_public_key);
    sk_out.resize(sig->length_secret_key);

    // Generate keypair
    OQS_STATUS status = OQS_SIG_keypair(sig, pk_out.data(), sk_out.data());

    OQS_SIG_free(sig);

    return (status == OQS_SUCCESS);
}

bool MLDSA_Sign(std::span<const uint8_t> sk, std::span<const uint8_t> msg32, ParamSet level, std::vector<uint8_t>& sig_out)
{
    // Enforce 32-byte message (Taproot sighash)
    if (msg32.size() != 32) return false;

    // Validate secret key size
    size_t expected_sk_size = GetSecretKeySize(level);
    if (sk.size() != expected_sk_size) return false;

    const char* alg_name = nullptr;

    switch (level) {
        case ParamSet::MLDSA_44:
            alg_name = OQS_SIG_alg_ml_dsa_44;
            break;
        case ParamSet::MLDSA_65:
            alg_name = OQS_SIG_alg_ml_dsa_65;
            break;
        case ParamSet::MLDSA_87:
            alg_name = OQS_SIG_alg_ml_dsa_87;
            break;
        default:
            return false;
    }

    OQS_SIG* sig_obj = OQS_SIG_new(alg_name);
    if (!sig_obj) return false;

    // Allocate signature buffer
    sig_out.resize(sig_obj->length_signature);
    size_t sig_len = 0;

    // Sign the message
    OQS_STATUS status = OQS_SIG_sign(sig_obj, sig_out.data(), &sig_len,
                                     msg32.data(), msg32.size(), sk.data());

    OQS_SIG_free(sig_obj);

    if (status != OQS_SUCCESS) return false;

    // Resize to actual signature length (may be smaller than max)
    sig_out.resize(sig_len);

    return true;
}

#endif // ENABLE_MLDSA

} // namespace mldsa
