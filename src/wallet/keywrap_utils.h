#ifndef TENSORCASH_WALLET_KEYWRAP_UTILS_H
#define TENSORCASH_WALLET_KEYWRAP_UTILS_H

#include <array>
#include <optional>
#include <vector>

#include <addresstype.h>
#include <assets/icu_payload.h>
#include <crypto/hkdf_sha256_32.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

namespace wallet::keywrap {

inline constexpr uint8_t KEYWRAP_SUITE_CHACHA20 = 1;

uint256 TapMatchHash(const CScript& spk);
std::array<unsigned char, 12> NonceFromTapMatch(const uint256& spk_hash32);
std::vector<unsigned char> BuildAad(const uint256& asset_id, const uint256& ctxt_hash);

std::array<unsigned char, 32> DeriveECDHSecret(const CKey& priv_key, const XOnlyPubKey& counterparty);
std::array<unsigned char, 32> DeriveWrapKey(
    const std::array<unsigned char, 32>& shared_secret,
    const std::array<unsigned char, 16>& kdf_salt,
    const uint256& asset_id,
    const uint256& ctxt_hash,
    const uint256& spk_hash32);

std::vector<unsigned char> EncryptDek(
    uint8_t suite_id,
    const std::array<unsigned char, 32>& dek,
    const std::array<unsigned char, 32>& wrap_key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad);

std::array<unsigned char, 32> DecryptDek(
    uint8_t suite_id,
    const std::vector<unsigned char>& ciphertext_with_tag,
    const std::array<unsigned char, 32>& wrap_key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad);

std::optional<XOnlyPubKey> ExtractTaprootPubkey(const CTxDestination& dest);

struct WrappedKeyV1 {
    uint8_t version{1};
    uint8_t suite_id{0};
    std::array<unsigned char, 32> sender_ephemeral{};
    std::array<unsigned char, 32> ciphertext{};
    std::array<unsigned char, 16> tag{};
};

std::vector<unsigned char> EncodeWrappedKeyV1(const WrappedKeyV1& fields);
std::optional<WrappedKeyV1> DecodeWrappedKeyV1(const std::vector<unsigned char>& encoded);

} // namespace wallet::keywrap

#endif // TENSORCASH_WALLET_KEYWRAP_UTILS_H
