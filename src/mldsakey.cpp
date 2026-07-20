// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mldsakey.h>

#include <crypto/mldsakeygen.h>
#include <support/cleanse.h>

#include <cstring>

bool CMLDSAKey::MakeNewKey(mldsa::ParamSet level)
{
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;

#ifdef ENABLE_MLDSA
    if (!mldsa::MLDSA_Keygen(level, pk, sk)) {
        return false;
    }

    m_level = level;
    m_secret_key.assign(sk.begin(), sk.end());
    m_public_key = std::move(pk);
    m_valid = true;

    // Cleanse temporary sk
    memory_cleanse(sk.data(), sk.size());

    return true;
#else
    return false;
#endif
}

bool CMLDSAKey::SetSecretKey(const std::vector<uint8_t>& sk, mldsa::ParamSet level)
{
    // Validate size
    size_t expected_size = mldsa::GetSecretKeySize(level);
    if (sk.size() != expected_size) {
        return false;
    }

    // Note: We cannot independently derive the public key from SK in ML-DSA
    // (unlike ECDSA where PK = sk*G). The public key must be provided separately
    // or the keypair must be regenerated. For now, mark as invalid if PK is missing.
    // This is intended for use with database loading where PK is serialized.

    m_level = level;
    m_secret_key.assign(sk.begin(), sk.end());
    m_valid = true;

    return true;
}

bool CMLDSAKey::SetPublicKey(const std::vector<uint8_t>& pk)
{
    // Validate size based on current level
    size_t expected_size = mldsa::GetParamSetSizes(m_level).pk_bytes;
    if (pk.size() != expected_size) {
        return false;
    }

    m_public_key = pk;
    return true;
}

std::vector<uint8_t> CMLDSAKey::GetEncodedPubKey() const
{
    if (!m_valid || m_public_key.empty()) {
        return {};
    }

    std::vector<uint8_t> encoded;
    encoded.reserve(m_public_key.size() + 10);  // alg_id + level + varint + pk

    // Algorithm ID
    encoded.push_back(mldsa::ALG_ID_MLDSA);

    // Parameter set
    encoded.push_back(static_cast<uint8_t>(m_level));

    // Compact size (varint) for public key length
    size_t pk_len = m_public_key.size();
    if (pk_len < 0xFD) {
        encoded.push_back(static_cast<uint8_t>(pk_len));
    } else if (pk_len <= 0xFFFF) {
        encoded.push_back(0xFD);
        encoded.push_back(static_cast<uint8_t>(pk_len & 0xFF));
        encoded.push_back(static_cast<uint8_t>((pk_len >> 8) & 0xFF));
    } else {
        // ML-DSA public keys are max 2592 bytes, so we'll never hit this
        encoded.push_back(0xFE);
        encoded.push_back(static_cast<uint8_t>(pk_len & 0xFF));
        encoded.push_back(static_cast<uint8_t>((pk_len >> 8) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((pk_len >> 16) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((pk_len >> 24) & 0xFF));
    }

    // Public key bytes
    encoded.insert(encoded.end(), m_public_key.begin(), m_public_key.end());

    return encoded;
}

bool CMLDSAKey::Sign(const uint256& msg32, std::vector<uint8_t>& sig) const
{
    if (!m_valid || m_secret_key.empty()) {
        return false;
    }

#ifdef ENABLE_MLDSA
    return mldsa::MLDSA_Sign(
        std::span<const uint8_t>(m_secret_key.data(), m_secret_key.size()),
        std::span<const uint8_t>(msg32.begin(), 32),
        m_level,
        sig
    );
#else
    return false;
#endif
}

void CMLDSAKey::Clear()
{
    memory_cleanse(m_secret_key.data(), m_secret_key.size());
    m_secret_key.clear();
    m_public_key.clear();
    m_valid = false;
}
