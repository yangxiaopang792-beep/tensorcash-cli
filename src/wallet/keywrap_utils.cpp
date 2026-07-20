#include <wallet/keywrap_utils.h>

#include <algorithm>
#include <random.h>
#include <crypto/sha256.h>
#include <tinyformat.h>

namespace wallet::keywrap {

uint256 TapMatchHash(const CScript& spk)
{
    static constexpr unsigned char PREFIX[] = {'T','a','p','M','a','t','c','h'};
    uint256 result;
    CSHA256()
        .Write(PREFIX, sizeof(PREFIX))
        .Write(spk.data(), spk.size())
        .Finalize(result.begin());
    return result;
}

std::array<unsigned char, 12> NonceFromTapMatch(const uint256& spk_hash32)
{
    std::array<unsigned char, 12> nonce{};
    std::copy_n(spk_hash32.begin(), nonce.size(), nonce.begin());
    return nonce;
}

std::vector<unsigned char> BuildAad(const uint256& asset_id, const uint256& ctxt_hash)
{
    std::vector<unsigned char> aad;
    aad.reserve(asset_id.size() + ctxt_hash.size());
    aad.insert(aad.end(), asset_id.begin(), asset_id.end());
    aad.insert(aad.end(), ctxt_hash.begin(), ctxt_hash.end());
    return aad;
}

std::array<unsigned char, 32> DeriveECDHSecret(const CKey& priv_key, const XOnlyPubKey& counterparty)
{
    if (!priv_key.IsValid() || counterparty.IsNull() || !counterparty.IsFullyValid()) {
        throw std::runtime_error("Invalid keys for ECDH");
    }

    // Construct compressed pubkey from x-only (Taproot keys have even Y)
    std::array<unsigned char, 33> compressed{};
    compressed[0] = 0x02;
    std::copy(counterparty.begin(), counterparty.end(), compressed.begin() + 1);

    CPubKey pubkey(compressed.begin(), compressed.end());
    if (!pubkey.IsFullyValid()) {
        throw std::runtime_error("Failed to construct pubkey from x-only");
    }

    // Use CKey's ECDH method (wraps secp256k1_ecdh)
    std::array<unsigned char, 32> shared_secret = priv_key.ComputeECDHSecret(pubkey);
    if (std::all_of(shared_secret.begin(), shared_secret.end(), [](unsigned char c) { return c == 0; })) {
        throw std::runtime_error("ECDH computation failed");
    }
    return shared_secret;
}

std::array<unsigned char, 32> DeriveWrapKey(
    const std::array<unsigned char, 32>& shared_secret,
    const std::array<unsigned char, 16>& kdf_salt,
    const uint256& asset_id,
    const uint256& ctxt_hash,
    const uint256& spk_hash32)
{
    const std::string salt(reinterpret_cast<const char*>(kdf_salt.data()), kdf_salt.size());
    std::string info;
    info.reserve(13 + asset_id.size() + ctxt_hash.size() + spk_hash32.size());
    info.append("ICU_KEYWRAP_V2");
    info.append(reinterpret_cast<const char*>(asset_id.begin()), asset_id.size());
    info.append(reinterpret_cast<const char*>(ctxt_hash.begin()), ctxt_hash.size());
    info.append(reinterpret_cast<const char*>(spk_hash32.begin()), spk_hash32.size());

    std::array<unsigned char, 32> wrap_key{};
    CHKDF_HMAC_SHA256_L32 hkdf(shared_secret.data(), shared_secret.size(), salt);
    hkdf.Expand32(info, wrap_key.data());
    return wrap_key;
}

std::vector<unsigned char> EncryptDek(
    uint8_t suite_id,
    const std::array<unsigned char, 32>& dek,
    const std::array<unsigned char, 32>& wrap_key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad)
{
    std::vector<unsigned char> dek_vec(dek.begin(), dek.end());
    switch (suite_id) {
    case KEYWRAP_SUITE_CHACHA20: {
        auto ciphertext = assets::EncryptChaCha20Poly1305(dek_vec, wrap_key, nonce, aad);
        if (!ciphertext) {
            throw std::runtime_error("Failed to encrypt DEK with ChaCha20-Poly1305");
        }
        return *ciphertext;
    }
    default:
        throw std::runtime_error(tfm::format("Unsupported ICU keywrap suite: %u", suite_id));
    }
}

std::array<unsigned char, 32> DecryptDek(
    uint8_t suite_id,
    const std::vector<unsigned char>& ciphertext_with_tag,
    const std::array<unsigned char, 32>& wrap_key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad)
{
    switch (suite_id) {
    case KEYWRAP_SUITE_CHACHA20: {
        auto plaintext = assets::DecryptChaCha20Poly1305(ciphertext_with_tag, wrap_key, nonce, aad);
        if (!plaintext || plaintext->size() != 32) {
            throw std::runtime_error("Failed to decrypt DEK with ChaCha20-Poly1305");
        }
        std::array<unsigned char, 32> dek{};
        std::copy_n(plaintext->begin(), dek.size(), dek.begin());
        return dek;
    }
    default:
        throw std::runtime_error(tfm::format("Unsupported ICU keywrap suite: %u", suite_id));
    }
}

std::optional<XOnlyPubKey> ExtractTaprootPubkey(const CTxDestination& dest)
{
    if (const auto* taproot = std::get_if<WitnessV1Taproot>(&dest)) {
        if (!taproot->IsNull() && taproot->IsFullyValid()) {
            return static_cast<const XOnlyPubKey&>(*taproot);
        }
    }
    return std::nullopt;
}

std::vector<unsigned char> EncodeWrappedKeyV1(const WrappedKeyV1& fields)
{
    static constexpr size_t RAW_LEN = 82;
    std::array<unsigned char, RAW_LEN> raw{};
    raw[0] = fields.version;
    raw[1] = fields.suite_id;
    std::copy(fields.sender_ephemeral.begin(), fields.sender_ephemeral.end(), raw.begin() + 2);
    std::copy(fields.ciphertext.begin(), fields.ciphertext.end(), raw.begin() + 34);
    std::copy(fields.tag.begin(), fields.tag.end(), raw.begin() + 66);
    std::string encoded = EncodeBase64(MakeUCharSpan(raw));
    return {encoded.begin(), encoded.end()};
}

std::optional<WrappedKeyV1> DecodeWrappedKeyV1(const std::vector<unsigned char>& encoded)
{
    static constexpr size_t RAW_LEN = 82;
    std::string encoded_str(encoded.begin(), encoded.end());
    auto decoded_opt = DecodeBase64(encoded_str);
    if (!decoded_opt || decoded_opt->size() != RAW_LEN) {
        return std::nullopt;
    }
    const std::vector<unsigned char>& raw = *decoded_opt;
    WrappedKeyV1 fields;
    fields.version = raw[0];
    fields.suite_id = raw[1];
    std::copy_n(raw.begin() + 2, fields.sender_ephemeral.size(), fields.sender_ephemeral.begin());
    std::copy_n(raw.begin() + 34, fields.ciphertext.size(), fields.ciphertext.begin());
    std::copy_n(raw.begin() + 66, fields.tag.size(), fields.tag.begin());
    return fields;
}

} // namespace wallet::keywrap
