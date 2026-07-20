// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MLDSAKEY_H
#define BITCOIN_MLDSAKEY_H

#include <crypto/mldsakeygen.h>
#include <crypto/mldsaverify.h>
#include <pubkey.h>
#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <vector>

/** Secure ML-DSA secret key storage */
using MLDSASecretKey = std::vector<uint8_t, secure_allocator<uint8_t>>;

/**
 * An encapsulated ML-DSA private key.
 *
 * Stores:
 * - Secret key material (2560/4032/4896 bytes depending on parameter set)
 * - Parameter set identifier (44/65/87)
 * - Cached public key (1312/1952/2592 bytes)
 *
 * Similar to CKey but for post-quantum ML-DSA signatures.
 */
class CMLDSAKey
{
private:
    //! Parameter set level (44/65/87)
    mldsa::ParamSet m_level{mldsa::ParamSet::MLDSA_65};

    //! Secret key material (secure allocator)
    MLDSASecretKey m_secret_key;

    //! Cached public key (raw FIPS 204 format)
    std::vector<uint8_t> m_public_key;

    //! Validity flag
    bool m_valid{false};

public:
    CMLDSAKey() = default;

    /**
     * Generate a new ML-DSA keypair.
     *
     * @param level  Parameter set (44/65/87)
     * @return true on success
     */
    bool MakeNewKey(mldsa::ParamSet level);

    /**
     * Set secret key from existing material.
     *
     * @param sk     Secret key bytes
     * @param level  Parameter set
     * @return true if valid
     */
    bool SetSecretKey(const std::vector<uint8_t>& sk, mldsa::ParamSet level);

    /**
     * Set public key from existing material.
     *
     * @param pk     Public key bytes
     * @return true if valid size
     */
    bool SetPublicKey(const std::vector<uint8_t>& pk);

    /**
     * Get the secret key.
     *
     * @return Secret key bytes (empty if invalid)
     */
    const MLDSASecretKey& GetSecretKey() const { return m_secret_key; }

    /**
     * Get the public key (raw FIPS 204 format).
     *
     * @return Public key bytes (empty if invalid)
     */
    const std::vector<uint8_t>& GetPubKey() const { return m_public_key; }

    /**
     * Get the public key in on-stack encoding format.
     *
     * Returns: alg_id (0x01) || param_set || varint(len) || pk_bytes
     */
    std::vector<uint8_t> GetEncodedPubKey() const;

    /**
     * Get parameter set level.
     */
    mldsa::ParamSet GetLevel() const { return m_level; }

    /**
     * Check if key is valid.
     */
    bool IsValid() const { return m_valid; }

    /**
     * Sign a 32-byte message digest.
     *
     * @param msg32  32-byte message (e.g., Taproot sighash)
     * @param sig    Output signature
     * @return true on success
     */
    bool Sign(const uint256& msg32, std::vector<uint8_t>& sig) const;

    /**
     * Clear all key material.
     */
    void Clear();

    /**
     * Comparison operators.
     */
    friend bool operator==(const CMLDSAKey& a, const CMLDSAKey& b)
    {
        return a.m_level == b.m_level &&
               a.m_valid == b.m_valid &&
               a.m_secret_key == b.m_secret_key &&
               a.m_public_key == b.m_public_key;
    }

    friend bool operator!=(const CMLDSAKey& a, const CMLDSAKey& b)
    {
        return !(a == b);
    }

    /**
     * Serialization (for wallet database).
     */
    SERIALIZE_METHODS(CMLDSAKey, obj)
    {
        uint8_t level_byte = static_cast<uint8_t>(obj.m_level);
        READWRITE(level_byte);
        if (ser_action.ForRead()) {
            // Reconstruct ParamSet from byte
            switch (level_byte) {
                case static_cast<uint8_t>(mldsa::ParamSet::MLDSA_44):
                    obj.m_level = mldsa::ParamSet::MLDSA_44;
                    break;
                case static_cast<uint8_t>(mldsa::ParamSet::MLDSA_65):
                    obj.m_level = mldsa::ParamSet::MLDSA_65;
                    break;
                case static_cast<uint8_t>(mldsa::ParamSet::MLDSA_87):
                    obj.m_level = mldsa::ParamSet::MLDSA_87;
                    break;
                default:
                    obj.m_valid = false;
                    return;
            }
        }

        // Serialize secret key (secure_allocator compatible)
        std::vector<uint8_t> sk_vec(obj.m_secret_key.begin(), obj.m_secret_key.end());
        READWRITE(sk_vec);
        if (ser_action.ForRead()) {
            obj.m_secret_key.assign(sk_vec.begin(), sk_vec.end());
        }

        READWRITE(obj.m_public_key);
        READWRITE(obj.m_valid);
    }
};

#endif // BITCOIN_MLDSAKEY_H
