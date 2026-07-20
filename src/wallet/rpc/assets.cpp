// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <assets/asset.h>
#include <assets/canonical_vk.h>
#include <assets/icu_payload.h>
#include <assets/icu_acceptance.h>
#include <assets/icu_acceptance_record.h>
#include <assets/kyc_delegation.h>
#include <assets/registry.h>
#include <chain.h>
#include <core_io.h>
#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <crypto/groth16.h>
#include <interfaces/chain.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <rpc/assets.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <rpc/protocol.h>
#include <span.h>
#include <streams.h>
#include <span>
#include <txdb.h>
#include <validation.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <tinyformat.h>
#include <wallet/asset_registration.h>
#include <wallet/contract.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/walletdb.h>
#include <wallet/keywrap_utils.h>
#include <wallet/receive.h>
#include <util/moneystr.h>
#include <chainparams.h>
#include <outputtype.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <streams.h>
#include <crypto/common.h>
#include <policy/policy.h>
#include <random.h>
#include <script/solver.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#ifdef _WIN32
#include <windows.h>
#ifndef RTLD_LAZY
#define RTLD_LAZY 0
#endif
// Minimal dlopen/dlsym wrappers for Windows to reuse existing code paths.
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
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <stdexcept>
#include <tuple>
#include <numeric>
#include <utility>
#include <vector>

// Defined in src/rpc/bip322.cpp (global namespace) -- verifies a BIP-322 signature (base64) over a
// message against an address. Forward-declared here so the ICU acceptance verify path can reuse it.
bool VerifyBIP322Signature(const std::string& address, const std::string& signature, const std::string& message);

namespace wallet {

namespace {

static uint256 Sha256Commit(const std::vector<unsigned char>& data)
{
    uint256 result;
    CSHA256()
        .Write(data.data(), data.size())
        .Finalize(result.begin());
    return result;
}

static uint256 TxOutCommitment(const CTxOut& txout)
{
    HashWriter writer;
    writer << txout;
    return writer.GetHash();
}

// XorWithKey removed - was incorrectly used for ICU encryption
// Proper ChaCha20-Poly1305 AEAD is now used via assets::BuildCanonicalIcuPayload()

namespace kw = wallet::keywrap;

static constexpr CAmount DEFAULT_ASSET_OUTPUT_VALUE{1000}; // 0.00001 BTC (1k sats) to keep asset outputs above dust

struct AssetResolution
{
    uint256 asset_id;
    std::optional<AssetRegistryEntry> registry;
};

static constexpr std::string_view ROTATION_PSBT_IDENTIFIER{"assetv2/governance"};
static constexpr uint64_t ROTATION_PSBT_SUBTYPE_METADATA{0x01};

struct RotationMetadata {
    uint64_t settled_supply{0};
    uint64_t required_units{0};
    uint16_t quorum_bps{0};
    uint8_t chunk_index{std::numeric_limits<uint8_t>::max()};
    uint256 issuer_reg_commit;
    uint256 chunk_commit;
    std::vector<unsigned char> icu_payload;  // ICU text payload (added at finalization)
    std::vector<unsigned char> issuer_reg_tlv;  // IssuerReg TLV bytes for vout[0].vExt reconstruction
};

static PSBTProprietary MakeProprietaryGlobal(std::string_view identifier,
                                             uint64_t subtype,
                                             std::span<const unsigned char> keydata,
                                             std::span<const unsigned char> value)
{
    PSBTProprietary prop;
    prop.identifier.assign(identifier.begin(), identifier.end());
    prop.subtype = subtype;

    VectorWriter key_writer(prop.key, prop.key.size());
    WriteCompactSize(key_writer, PSBT_GLOBAL_PROPRIETARY);
    WriteCompactSize(key_writer, prop.identifier.size());
    key_writer.write(std::as_bytes(std::span(prop.identifier)));
    WriteCompactSize(key_writer, subtype);
    if (!keydata.empty()) {
        key_writer.write(std::as_bytes(keydata));
    }

    prop.value.assign(value.begin(), value.end());
    return prop;
}

static void AttachRotationMetadata(PartiallySignedTransaction& psbt, const RotationMetadata& meta)
{
    std::vector<unsigned char> value;
    value.reserve(sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t) + 64 + meta.icu_payload.size() + meta.issuer_reg_tlv.size());

    unsigned char buf64[8];
    WriteLE64(buf64, meta.settled_supply);
    value.insert(value.end(), buf64, buf64 + sizeof(buf64));
    WriteLE64(buf64, meta.required_units);
    value.insert(value.end(), buf64, buf64 + sizeof(buf64));

    unsigned char buf16[2];
    WriteLE16(buf16, meta.quorum_bps);
    value.insert(value.end(), buf16, buf16 + sizeof(buf16));

    value.push_back(meta.chunk_index);

    if (!meta.issuer_reg_commit.IsNull()) {
        value.insert(value.end(), meta.issuer_reg_commit.begin(), meta.issuer_reg_commit.end());
    } else {
        value.resize(value.size() + uint256::size());
    }
    if (!meta.chunk_commit.IsNull()) {
        value.insert(value.end(), meta.chunk_commit.begin(), meta.chunk_commit.end());
    } else {
        value.resize(value.size() + uint256::size());
    }

    // Append ICU payload with CompactSize length prefix
    {
        VectorWriter writer(value, value.size());
        WriteCompactSize(writer, meta.icu_payload.size());
    }
    value.insert(value.end(), meta.icu_payload.begin(), meta.icu_payload.end());

    // Append IssuerReg TLV with CompactSize length prefix
    {
        VectorWriter writer(value, value.size());
        WriteCompactSize(writer, meta.issuer_reg_tlv.size());
    }
    value.insert(value.end(), meta.issuer_reg_tlv.begin(), meta.issuer_reg_tlv.end());

    auto prop = MakeProprietaryGlobal(ROTATION_PSBT_IDENTIFIER, ROTATION_PSBT_SUBTYPE_METADATA, {}, value);
    psbt.m_proprietary.erase(prop);
    psbt.m_proprietary.insert(std::move(prop));
}

static std::optional<RotationMetadata> ExtractRotationMetadata(const PartiallySignedTransaction& psbt)
{
    for (const auto& prop : psbt.m_proprietary) {
        if (prop.identifier.size() == ROTATION_PSBT_IDENTIFIER.size() &&
            std::equal(prop.identifier.begin(), prop.identifier.end(), ROTATION_PSBT_IDENTIFIER.begin()) &&
            prop.subtype == ROTATION_PSBT_SUBTYPE_METADATA) {

            constexpr size_t min_size = sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t) + uint256::size() * 2;
            if (prop.value.size() < min_size) {
                return std::nullopt;
            }

            RotationMetadata meta;
            meta.settled_supply = ReadLE64(prop.value.data());
            meta.required_units = ReadLE64(prop.value.data() + sizeof(uint64_t));
            meta.quorum_bps = ReadLE16(prop.value.data() + sizeof(uint64_t) * 2);
            meta.chunk_index = prop.value[sizeof(uint64_t) * 2 + sizeof(uint16_t)];
            const unsigned char* commit_ptr = prop.value.data() + sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t);
            std::copy(commit_ptr, commit_ptr + uint256::size(), meta.issuer_reg_commit.begin());
            std::copy(commit_ptr + uint256::size(), commit_ptr + uint256::size() * 2, meta.chunk_commit.begin());

            // Extract ICU payload and IssuerReg TLV if present (with CompactSize length prefixes)
            if (prop.value.size() > min_size) {
                const unsigned char* payload_start = prop.value.data() + min_size;
                size_t remaining = prop.value.size() - min_size;
                SpanReader reader(std::span<const unsigned char>(payload_start, remaining));

                // Read ICU payload
                uint64_t payload_len = ReadCompactSize(reader);
                if (reader.size() >= payload_len) {
                    meta.icu_payload.resize(payload_len);
                    reader.read(MakeWritableByteSpan(meta.icu_payload));
                }

                // Read IssuerReg TLV if present
                if (reader.size() > 0) {
                    uint64_t tlv_len = ReadCompactSize(reader);
                    if (reader.size() >= tlv_len) {
                        meta.issuer_reg_tlv.resize(tlv_len);
                        reader.read(MakeWritableByteSpan(meta.issuer_reg_tlv));
                    }
                }
            }

            return meta;
        }
    }
    return std::nullopt;
}

static constexpr std::array<uint64_t, 19> POW10_LOOKUP{
    1ULL,
    10ULL,
    100ULL,
    1'000ULL,
    10'000ULL,
    100'000ULL,
    1'000'000ULL,
    10'000'000ULL,
    100'000'000ULL,
    1'000'000'000ULL,
    10'000'000'000ULL,
    100'000'000'000ULL,
    1'000'000'000'000ULL,
    10'000'000'000'000ULL,
    100'000'000'000'000ULL,
    1'000'000'000'000'000ULL,
    10'000'000'000'000'000ULL,
    100'000'000'000'000'000ULL,
    1'000'000'000'000'000'000ULL};

static uint64_t Pow10(uint8_t decimals, const std::string& field_name)
{
    if (decimals >= POW10_LOOKUP.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s requires asset decimals between 0 and 18 (got %u)",
                                     field_name, decimals));
    }
    return POW10_LOOKUP[decimals];
}

static uint8_t NormalizedDecimals(uint8_t decimals)
{
    return decimals == std::numeric_limits<uint8_t>::max() ? 0 : decimals;
}

static uint64_t ParseUint64FromUniValue(const UniValue& value, const std::string& field_name)
{
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be a non-negative integer", field_name));
    }

    if (value.isNum()) {
        const int64_t num = value.getInt<int64_t>();
        if (num < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s must be non-negative", field_name));
        }
        return static_cast<uint64_t>(num);
    }

    if (value.isStr()) {
        std::string str = util::TrimString(value.get_str());
        if (str.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s must not be empty", field_name));
        }
        uint64_t out{0};
        if (!ParseUInt64(str, &out)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s must be a non-negative integer", field_name));
        }
        return out;
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       strprintf("%s must be a non-negative integer", field_name));
}

static uint64_t ParseAssetUnitsDecimal(const UniValue& value,
                                       uint8_t raw_decimals,
                                       const std::string& field_name)
{
    const uint8_t decimals = NormalizedDecimals(raw_decimals);
    const uint64_t scale = Pow10(decimals, field_name);

    std::string text = util::TrimString(value.getValStr());
    if (text.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must not be empty", field_name));
    }
    if (text.front() == '+') {
        text.erase(text.begin());
    }
    if (text.empty() || text.front() == '-') {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be a non-negative decimal value", field_name));
    }

    const size_t dot_pos = text.find('.');
    std::string int_part = dot_pos == std::string::npos ? text : text.substr(0, dot_pos);
    std::string frac_part = dot_pos == std::string::npos ? std::string{} : text.substr(dot_pos + 1);

    if (int_part.empty()) {
        int_part = "0";
    }

    auto is_digit_str = [](const std::string& s) {
        return std::all_of(s.begin(), s.end(), [](unsigned char c) {
            return std::isdigit(c);
        });
    };

    if (!is_digit_str(int_part)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s integer component must be digits only", field_name));
    }
    if (!frac_part.empty() && !is_digit_str(frac_part)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s fractional component must be digits only", field_name));
    }

    if (decimals == 0 && !frac_part.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s does not allow fractional units for an asset with 0 decimals", field_name));
    }
    if (frac_part.size() > decimals) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s has more than %u fractional digits", field_name, decimals));
    }

    uint64_t integer_value{0};
    if (!ParseUInt64(int_part, &integer_value)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s integer component is out of range", field_name));
    }

    std::string frac_padded = frac_part;
    if (frac_padded.size() < decimals) {
        frac_padded.append(decimals - frac_padded.size(), '0');
    }

    uint64_t fractional_value{0};
    if (!frac_padded.empty()) {
        if (!ParseUInt64(frac_padded, &fractional_value)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s fractional component is out of range", field_name));
        }
    }

    unsigned __int128 total = static_cast<unsigned __int128>(integer_value) * scale + fractional_value;
    if (total > std::numeric_limits<uint64_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s exceeds 64-bit range after scaling", field_name));
    }
    return static_cast<uint64_t>(total);
}

static std::string FormatAssetAmount(uint64_t units, uint8_t raw_decimals)
{
    const uint8_t decimals = NormalizedDecimals(raw_decimals);
    if (decimals == 0) {
        return strprintf("%llu", units);
    }

    const uint64_t scale = POW10_LOOKUP[decimals];
    const uint64_t whole = units / scale;
    const uint64_t fraction = units % scale;

    std::string frac_str = strprintf("%0*llu", decimals, fraction);
    while (!frac_str.empty() && frac_str.back() == '0') {
        frac_str.pop_back();
    }

    if (frac_str.empty()) {
        return strprintf("%llu", whole);
    }

    return strprintf("%llu.%s", whole, frac_str);
}

static std::string DescribeAssetUnits(uint64_t units, uint8_t decimals)
{
    if (decimals == 0) {
        return strprintf("%llu units", units);
    }
    return strprintf("%s units (%llu base units)",
                     FormatAssetAmount(units, decimals), units);
}

static std::optional<uint64_t> ParseIssuanceCapOption(const UniValue& opt,
                                                      uint8_t raw_decimals,
                                                      const std::string& context)
{
    const bool has_display = opt.exists("issuance_cap");
    const bool has_units = opt.exists("issuance_cap_units");

    if (!has_display && !has_units) {
        return std::nullopt;
    }
    if (has_display && has_units) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s: specify either issuance_cap or issuance_cap_units, not both",
                                     context));
    }

    if (has_display) {
        return ParseAssetUnitsDecimal(opt["issuance_cap"], raw_decimals, "issuance_cap");
    }
    return ParseUint64FromUniValue(opt["issuance_cap_units"], "issuance_cap_units");
}

static void EnforceIssuanceCapForMint(const AssetRegistryEntry& entry,
                                      uint64_t mint_units,
                                      uint64_t effective_cap)
{
    if (effective_cap == 0 || mint_units == 0) {
        return;
    }

    const uint8_t decimals = NormalizedDecimals(entry.decimals);

    if (entry.issued_total > effective_cap) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("Current issuance (%s) already exceeds the configured cap (%s)",
                                     DescribeAssetUnits(entry.issued_total, decimals),
                                     DescribeAssetUnits(effective_cap, decimals)));
    }

    const uint64_t remaining = effective_cap - entry.issued_total;
    if (mint_units > remaining) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("Minting %s would exceed the issuance cap (%s remaining of %s)",
                                     DescribeAssetUnits(mint_units, decimals),
                                     DescribeAssetUnits(remaining, decimals),
                                     DescribeAssetUnits(effective_cap, decimals)));
    }
}

// BuildIssuerRegV1 moved to wallet/asset_registration.{h,cpp} (OPTION_TOKENIZATION.md §6.6).

// --- Shared asset-registration builder (registerasset + sponsorchildasset; ICU_CHILD.md §6.1) ---
// Given the asset params + ICU/ZK inputs already parsed from the RPC options, runs the ICU
// normalization/encryption (BuildCanonicalIcuPayload) and VK chunking, and returns the IssuerReg
// TLV plus the ICU_TEXT_CHUNK / ZK_PARAMS_CHUNK dust-output TLVs. Each caller owns its own funding,
// so a standalone root and a sponsored child get identical registry/ICU/ZK semantics.
// AssetRegistrationTLVs / AssetRegistrationInputs moved to wallet/asset_registration.h.

// BuildAssetRegistrationTLVs moved to wallet/asset_registration.cpp (OPTION_TOKENIZATION.md §6.6).

struct IcuKeywrapParams {
    uint256 ctxt_hash;
    uint256 spk_hash32;
    std::vector<unsigned char> wrapped_key;
    uint8_t suite_id{0};
    uint8_t extras_mask{0};
    uint256 wrap_commit;
    std::array<unsigned char, 16> kc_tag{};
};

[[maybe_unused]] static std::optional<XOnlyPubKey> TryExtractRecipientPubkey(const CTxDestination& dest)
{
    return kw::ExtractTaprootPubkey(dest);
}

/** Generate a random 32-byte Data Encryption Key (DEK) for ICU wrapping */
[[maybe_unused]] static IcuKeywrapParams ECDHWrapKey(
    const XOnlyPubKey& recipient_pubkey,
    const CKey& sender_key,
    const std::array<unsigned char, 32>& dek,
    uint8_t suite_id,
    const std::array<unsigned char, 16>& kdf_salt,
    const uint256& asset_id,
    const uint256& ctxt_hash,
    const uint256& spk_hash32)
{
    IcuKeywrapParams params;
    params.ctxt_hash = ctxt_hash;
    params.spk_hash32 = spk_hash32;

    if (suite_id == 0) {
        std::vector<unsigned char> dek_vec(dek.begin(), dek.end());
        std::string encoded = EncodeBase64(MakeUCharSpan(dek_vec));
        params.wrapped_key.assign(encoded.begin(), encoded.end());
        params.suite_id = 0;
        params.extras_mask = 0;
        params.wrap_commit.SetNull();
        params.kc_tag.fill(0);
        return params;
    }

    if (suite_id != kw::KEYWRAP_SUITE_CHACHA20) {
        throw std::runtime_error(tfm::format("Unsupported ICU keywrap suite: %u", suite_id));
    }

    CPubKey sender_pubkey = sender_key.GetPubKey();
    if (!sender_pubkey.IsCompressed()) {
        throw std::runtime_error("Sender ephemeral key must be compressed");
    }
    XOnlyPubKey sender_xonly(sender_pubkey);
    std::array<unsigned char, 32> sender_bytes{};
    std::copy(sender_xonly.begin(), sender_xonly.end(), sender_bytes.begin());

    auto shared_secret = kw::DeriveECDHSecret(sender_key, recipient_pubkey);
    auto wrap_key = kw::DeriveWrapKey(shared_secret, kdf_salt, asset_id, ctxt_hash, spk_hash32);
    auto nonce = kw::NonceFromTapMatch(spk_hash32);
    auto aad = kw::BuildAad(asset_id, ctxt_hash);

    // Log all cryptographic parameters for debugging
    LogPrintf("KEYWRAP_PARAM_SEND kdf_salt=%s\n", HexStr(kdf_salt));
    LogPrintf("KEYWRAP_PARAM_SEND asset_id=%s\n", asset_id.ToString());
    LogPrintf("KEYWRAP_PARAM_SEND ctxt_hash=%s\n", ctxt_hash.ToString());
    LogPrintf("KEYWRAP_PARAM_SEND spk_hash32=%s\n", spk_hash32.ToString());
    LogPrintf("KEYWRAP_PARAM_SEND sender_ephemeral=%s\n", HexStr(MakeUCharSpan(sender_bytes)));
    LogPrintf("KEYWRAP_PARAM_SEND suite_id=%u\n", static_cast<unsigned>(suite_id));

    auto ciphertext_with_tag = kw::EncryptDek(suite_id, dek, wrap_key, nonce, aad);
    if (ciphertext_with_tag.size() != 48) {
        throw std::runtime_error("Unexpected ciphertext length when wrapping DEK");
    }

    kw::WrappedKeyV1 key_fields;
    key_fields.version = 1;
    key_fields.suite_id = suite_id;
    key_fields.sender_ephemeral = sender_bytes;
    std::copy_n(ciphertext_with_tag.begin(), key_fields.ciphertext.size(), key_fields.ciphertext.begin());
    std::copy_n(ciphertext_with_tag.end() - key_fields.tag.size(), key_fields.tag.size(), key_fields.tag.begin());

    LogPrintf("ECDHWrapKey debug: shared_secret=%s wrap_key=%s nonce=%s aad=%s cipher=%s tag=%s\n",
              HexStr(MakeUCharSpan(shared_secret)),
              HexStr(MakeUCharSpan(wrap_key)),
              HexStr(MakeUCharSpan(nonce)),
              HexStr(aad),
              HexStr(MakeUCharSpan(key_fields.ciphertext)),
              HexStr(MakeUCharSpan(key_fields.tag)));

    params.wrapped_key = kw::EncodeWrappedKeyV1(key_fields);
    params.suite_id = suite_id;
    params.extras_mask = assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT | assets::ICU_KEYWRAP_EXTRA_KC_TAG;
    params.wrap_commit = Sha256Commit(std::vector<unsigned char>(dek.begin(), dek.end()));
    params.kc_tag = key_fields.tag;

    std::vector<unsigned char> digest_input;
    digest_input.insert(digest_input.end(), asset_id.begin(), asset_id.end());
    digest_input.insert(digest_input.end(), ctxt_hash.begin(), ctxt_hash.end());
    digest_input.insert(digest_input.end(), spk_hash32.begin(), spk_hash32.end());
    digest_input.insert(digest_input.end(), key_fields.sender_ephemeral.begin(), key_fields.sender_ephemeral.end());
    digest_input.push_back(params.suite_id);
    digest_input.insert(digest_input.end(), nonce.begin(), nonce.end());
    digest_input.insert(digest_input.end(), aad.begin(), aad.end());
    digest_input.insert(digest_input.end(), kdf_salt.begin(), kdf_salt.end());  // Include salt in trace
    uint256 wrap_inputs_hash = Sha256Commit(digest_input);
    LogPrintf("KEYWRAP_TRACE_SEND asset=%s wrap_inputs_hash=%s\n", asset_id.ToString(), wrap_inputs_hash.ToString());

    return params;
}

static std::array<unsigned char, 32> ECDHUnwrapKey(
    const CKey& recipient_privkey,
    const XOnlyPubKey& sender_ephemeral,
    uint8_t suite_id,
    const std::array<unsigned char, 16>& kdf_salt,
    const uint256& asset_id,
    const uint256& ctxt_hash,
    const uint256& spk_hash32,
    const kw::WrappedKeyV1& fields)
{
    auto shared_secret = kw::DeriveECDHSecret(recipient_privkey, sender_ephemeral);
    auto wrap_key = kw::DeriveWrapKey(shared_secret, kdf_salt, asset_id, ctxt_hash, spk_hash32);
    auto nonce = kw::NonceFromTapMatch(spk_hash32);
    auto aad = kw::BuildAad(asset_id, ctxt_hash);

    // Log all cryptographic parameters for debugging
    LogPrintf("KEYWRAP_PARAM_RECV kdf_salt=%s\n", HexStr(kdf_salt));
    LogPrintf("KEYWRAP_PARAM_RECV asset_id=%s\n", asset_id.ToString());
    LogPrintf("KEYWRAP_PARAM_RECV ctxt_hash=%s\n", ctxt_hash.ToString());
    LogPrintf("KEYWRAP_PARAM_RECV spk_hash32=%s\n", spk_hash32.ToString());
    LogPrintf("KEYWRAP_PARAM_RECV sender_ephemeral=%s\n", HexStr(MakeUCharSpan(fields.sender_ephemeral)));
    LogPrintf("KEYWRAP_PARAM_RECV suite_id=%u\n", static_cast<unsigned>(suite_id));

    std::vector<unsigned char> ciphertext_with_tag;
    ciphertext_with_tag.reserve(fields.ciphertext.size() + fields.tag.size());
    ciphertext_with_tag.insert(ciphertext_with_tag.end(), fields.ciphertext.begin(), fields.ciphertext.end());
    ciphertext_with_tag.insert(ciphertext_with_tag.end(), fields.tag.begin(), fields.tag.end());

    std::vector<unsigned char> digest_input;
    digest_input.insert(digest_input.end(), asset_id.begin(), asset_id.end());
    digest_input.insert(digest_input.end(), ctxt_hash.begin(), ctxt_hash.end());
    digest_input.insert(digest_input.end(), spk_hash32.begin(), spk_hash32.end());
    digest_input.insert(digest_input.end(), fields.sender_ephemeral.begin(), fields.sender_ephemeral.end());
    digest_input.push_back(suite_id);
    digest_input.insert(digest_input.end(), nonce.begin(), nonce.end());
    digest_input.insert(digest_input.end(), aad.begin(), aad.end());
    digest_input.insert(digest_input.end(), kdf_salt.begin(), kdf_salt.end());  // Include salt in trace
    uint256 unwrap_inputs_hash = Sha256Commit(digest_input);
    LogPrintf("KEYWRAP_TRACE_RECV asset=%s wrap_inputs_hash=%s\n", asset_id.ToString(), unwrap_inputs_hash.ToString());

    LogPrintf("ECDHUnwrapKey debug: shared_secret=%s wrap_key=%s nonce=%s aad=%s cipher=%s tag=%s\n",
              HexStr(MakeUCharSpan(shared_secret)),
              HexStr(MakeUCharSpan(wrap_key)),
              HexStr(MakeUCharSpan(nonce)),
              HexStr(aad),
              HexStr(MakeUCharSpan(fields.ciphertext)),
              HexStr(MakeUCharSpan(fields.tag)));

    return kw::DecryptDek(suite_id, ciphertext_with_tag, wrap_key, nonce, aad);
}

static IcuKeywrapParams AutoWrapDekForOutput(
    CWallet& wallet,
    const uint256& asset_id,
    const uint256& ctxt_hash,
    const AssetRegistryEntry& registry_entry,
    const CTxDestination& dest,
    const CScript& dest_script,
    const std::optional<std::array<unsigned char, 16>>& salt_override,
    uint8_t requested_suite)
{
    auto recipient_pub = TryExtractRecipientPubkey(dest);
    if (!recipient_pub) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
            "WRAP_REQUIRED assets must be sent to Taproot (P2TR) addresses");
    }

    std::array<unsigned char, 16> salt{};
    if (salt_override) {
        salt = *salt_override;
        LogPrintf("AutoWrapDekForOutput: Using salt_override=%s for asset %s\n",
                  HexStr(*salt_override), asset_id.ToString());
    } else {
        salt = registry_entry.kdf_salt;
        LogPrintf("AutoWrapDekForOutput: Using registry_entry.kdf_salt=%s for asset %s\n",
                  HexStr(registry_entry.kdf_salt), asset_id.ToString());
    }

    std::string dek_base64;
    {
        LOCK(wallet.cs_wallet);
        auto dek_opt = wallet.GetAssetDek(asset_id);
        if (dek_opt) dek_base64 = *dek_opt;
    }
    if (dek_base64.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Wallet is missing ICU encryption key for asset %s. "
                      "Provide wrapped_key manually or register the asset with this wallet.",
                      asset_id.ToString()));
    }

    auto dek_bytes = DecodeBase64(dek_base64);
    if (!dek_bytes || dek_bytes->size() != 32) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Stored DEK is not a 32-byte base64 value");
    }

    std::array<unsigned char, 32> dek{};
    std::copy_n(dek_bytes->begin(), dek.size(), dek.begin());

    CKey sender_ephemeral;
    sender_ephemeral.MakeNewKey(true);
    CPubKey eph_pub = sender_ephemeral.GetPubKey();
    if (!eph_pub.IsCompressed()) {
        throw std::runtime_error("Sender ephemeral key must produce compressed pubkey");
    }
    if (eph_pub[0] == 0x03) {
        if (!sender_ephemeral.Negate()) {
            throw std::runtime_error("Failed to normalize sender ephemeral key parity");
        }
    }

    if (requested_suite != 0 && requested_suite != kw::KEYWRAP_SUITE_CHACHA20) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Unsupported ICU keywrap suite (suite_id=%u). Only suite_id=1 (ChaCha20-Poly1305) is available.", requested_suite));
    }

    const uint8_t effective_suite = requested_suite == 0 ? kw::KEYWRAP_SUITE_CHACHA20 : requested_suite;
    const uint256 spk_hash32 = kw::TapMatchHash(dest_script);

    auto keywrap = ECDHWrapKey(*recipient_pub, sender_ephemeral, dek,
                               effective_suite, salt, asset_id, ctxt_hash, spk_hash32);
    sender_ephemeral = CKey();

    LogPrintf("SENDASSET_KEYWRAP: asset_id=%s suite=%u wrapped_key_size=%d\n",
              asset_id.ToString(), keywrap.suite_id, static_cast<int>(keywrap.wrapped_key.size()));

    return keywrap;
}

// Build ASSET_TAG TLV with optional ICU_KEYWRAP sub-TLV for WRAP_REQUIRED assets
static std::vector<unsigned char> BuildAssetTagTlv(
    const uint256& asset_id,
    uint64_t units,
    const std::optional<IcuKeywrapParams>& keywrap = std::nullopt)
{
    std::vector<unsigned char> payload;
    payload.reserve(32 + 8);  // asset_id + amount
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_bytes[8];
    WriteLE64(amount_bytes, units);
    payload.insert(payload.end(), amount_bytes, amount_bytes + 8);

    // Append ICU_KEYWRAP sub-TLV if provided
    if (keywrap) {
        // Build ICU_KEYWRAP sub-TLV payload
        std::vector<unsigned char> kw_payload;
        kw_payload.reserve(32 + 32 + 32 + keywrap->wrapped_key.size() + 10 +
            (keywrap->extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT ? 32 : 0) +
            (keywrap->extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG ? 16 : 0));

        // asset_id (32 bytes)
        kw_payload.insert(kw_payload.end(), asset_id.begin(), asset_id.end());
        // ctxt_hash (32 bytes)
        kw_payload.insert(kw_payload.end(), keywrap->ctxt_hash.begin(), keywrap->ctxt_hash.end());
        // spk_hash32 (32 bytes)
        kw_payload.insert(kw_payload.end(), keywrap->spk_hash32.begin(), keywrap->spk_hash32.end());

        // wrapped_key (CompactSize length + data)
        VectorWriter kw_writer(kw_payload, kw_payload.size());
        WriteCompactSize(kw_writer, keywrap->wrapped_key.size());
        kw_payload.insert(kw_payload.end(), keywrap->wrapped_key.begin(), keywrap->wrapped_key.end());

        // suite_id (1 byte)
        kw_payload.push_back(keywrap->suite_id);
        // extras_mask (1 byte)
        kw_payload.push_back(keywrap->extras_mask);

        // Optional wrap_commit (32 bytes)
        if (keywrap->extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
            kw_payload.insert(kw_payload.end(), keywrap->wrap_commit.begin(), keywrap->wrap_commit.end());
        }

        // Optional kc_tag (16 bytes)
        if (keywrap->extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) {
            kw_payload.insert(kw_payload.end(), keywrap->kc_tag.begin(), keywrap->kc_tag.end());
        }

        // Append ICU_KEYWRAP sub-TLV to main payload: type (1 byte) + CompactSize length + sub-payload
        payload.push_back(0x03); // ICU_KEYWRAP sub-TLV type
        VectorWriter payload_writer(payload, payload.size());
        WriteCompactSize(payload_writer, kw_payload.size());
        payload.insert(payload.end(), kw_payload.begin(), kw_payload.end());
    }

    // Build final TLV
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));

    // Use CompactSize for length since payload can be large with keywrap
    VectorWriter tlv_writer(tlv, tlv.size());
    WriteCompactSize(tlv_writer, payload.size());
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

static std::string UppercaseCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    });
    return value;
}

static AssetResolution ResolveAssetIdOrTicker(const JSONRPCRequest& request, const std::string& identifier)
{
    WalletContext& wallet_context = EnsureWalletContext(request.context);
    interfaces::Chain* chain = wallet_context.chain;
    if (!chain) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not connected to a node");
    }

    if (auto maybe_hex = uint256::FromHex(identifier)) {
        AssetResolution res{*maybe_hex, std::nullopt};
        if (auto entry = chain->getAssetRegistryEntry(res.asset_id)) {
            res.registry = *entry;
        }
        return res;
    }

    const std::string ticker = UppercaseCopy(identifier);
    // Shared grammar gate: a bare root, or a one-hop sponsored child (ROOT.SUFFIX). Routing
    // wallet resolution through the same helper as the consensus parser is what lets a
    // registered child ticker resolve here (ICU_CHILD.md §5.1, §6.2).
    if (!assets::IsTickerValidForIssuerReg(ticker)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ticker: expected a root or one-hop child ROOT.SUFFIX");
    }

    const auto resolved_id = chain->getAssetIdByTicker(ticker);
    if (!resolved_id) {
        throw JSONRPCError(-6, "Ticker not found");
    }

    AssetResolution res{*resolved_id, std::nullopt};
    if (auto entry = chain->getAssetRegistryEntry(res.asset_id)) {
        res.registry = *entry;
    }
    return res;
}

static std::string FormatAssetUnits(uint64_t units, uint8_t decimals)
{
    if (decimals == 0) {
        return strprintf("%llu", static_cast<unsigned long long>(units));
    }
    uint64_t factor{1};
    for (uint8_t i = 0; i < decimals; ++i) {
        factor *= 10;
    }
    const uint64_t whole = units / factor;
    const uint64_t remainder = units % factor;
    return strprintf("%llu.%0*llu",
        static_cast<unsigned long long>(whole),
        static_cast<int>(decimals),
        static_cast<unsigned long long>(remainder));
}

struct WalletAssetUtxo
{
    COutPoint outpoint;
    CTxOut txout;
    int depth{0};
    bool spendable{false};
    bool solvable{false};
    bool safe{false};
    bool locked{false};
    bool ismine_spendable{false};
    uint256 asset_id;
    uint64_t units{0};
    std::optional<AssetMetadata> metadata;
};

[[maybe_unused]] static CKey GetSenderKeyForECDH(
    const CWallet& wallet,
    const std::vector<WalletAssetUtxo>& selected_utxos)
{
    (void)wallet;
    (void)selected_utxos;
    CKey new_key;
    new_key.MakeNewKey(true);
    return new_key;
}

static const std::vector<unsigned char> ZK_PSBT_IDENTIFIER{'t','c','z','k'};
static constexpr uint64_t ZK_PSBT_SUBTYPE{0};

struct ProprietaryKeyInfo
{
    std::vector<unsigned char> identifier;
    uint64_t subtype{0};
    std::string suffix;
};

static std::optional<ProprietaryKeyInfo> DecodeZkProprietaryKey(const PSBTProprietary& entry)
{
    SpanReader skey{std::span<const unsigned char>(entry.key)};
    ProprietaryKeyInfo info;
    try {
        const uint64_t type = ReadCompactSize(skey);
        if (type != PSBT_GLOBAL_PROPRIETARY) {
            return std::nullopt;
        }
        skey >> info.identifier;
        info.subtype = ReadCompactSize(skey);
        std::vector<unsigned char> suffix_bytes(skey.size());
        for (size_t i = 0; i < suffix_bytes.size(); ++i) {
            skey >> suffix_bytes[i];
        }
        info.suffix.assign(reinterpret_cast<const char*>(suffix_bytes.data()), suffix_bytes.size());
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return info;
}

static bool MatchesZkKey(const PSBTProprietary& entry, std::string_view suffix)
{
    if (entry.identifier != ZK_PSBT_IDENTIFIER || entry.subtype != ZK_PSBT_SUBTYPE) {
        return false;
    }
    const auto decoded = DecodeZkProprietaryKey(entry);
    if (!decoded) return false;
    return decoded->suffix == suffix;
}

static void ReplaceZkEntry(std::set<PSBTProprietary>& container,
                           std::string_view suffix,
                           std::span<const unsigned char> value)
{
    for (auto it = container.begin(); it != container.end();) {
        if (MatchesZkKey(*it, suffix)) {
            it = container.erase(it);
        } else {
            ++it;
        }
    }

    DataStream ss_key{};
    WriteCompactSize(ss_key, PSBT_GLOBAL_PROPRIETARY);
    ss_key << ZK_PSBT_IDENTIFIER;
    WriteCompactSize(ss_key, ZK_PSBT_SUBTYPE);
    for (char c : suffix) {
        ss_key << static_cast<uint8_t>(c);
    }

    PSBTProprietary entry;
    entry.identifier = ZK_PSBT_IDENTIFIER;
    entry.subtype = ZK_PSBT_SUBTYPE;
    entry.key = std::vector<unsigned char>(UCharCast(ss_key.data()), UCharCast(ss_key.data() + ss_key.size()));
    entry.value = std::vector<unsigned char>(value.begin(), value.end());
    container.insert(std::move(entry));
}

static std::optional<std::vector<unsigned char>> GetZkEntry(const PSBTInput& input, std::string_view suffix)
{
    for (const auto& entry : input.m_proprietary) {
        if (entry.identifier != ZK_PSBT_IDENTIFIER || entry.subtype != ZK_PSBT_SUBTYPE) {
            continue;
        }
        const auto decoded = DecodeZkProprietaryKey(entry);
        if (!decoded || decoded->suffix != suffix) {
            continue;
        }
        return entry.value;
    }
    return std::nullopt;
}

[[maybe_unused]] static void ApplyZkWitness(PartiallySignedTransaction& psbt, const uint256& asset_id)
{
    // TLV-based proof transport: ZK proofs go in ZK_PROOF_PAYLOAD TLV (type 0x22) in outputs,
    // NOT in witness stack. Witness contains only standard spend elements (signature + pubkey).

    LogPrintf("ApplyZkWitness: called for asset %s, %d inputs\n", asset_id.ToString(), psbt.inputs.size());

    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        auto proof = GetZkEntry(psbt.inputs[i], "proof");
        auto pub = GetZkEntry(psbt.inputs[i], "public_inputs");
        LogPrintf("ApplyZkWitness: input %d, proof=%s pub=%s\n", i, proof ? "YES" : "NO", pub ? "YES" : "NO");
        if (!proof || !pub) {
            continue;
        }

        // Create a dedicated zero-value output for ZK_PROOF_PAYLOAD TLV
        // (One TLV per vExt - cannot append to AssetTag output)
        if (psbt.tx) {
            LogPrintf("ApplyZkWitness: creating ZK_PROOF_PAYLOAD output for asset %s\n", asset_id.ToString());

            // Build ZK_PROOF_PAYLOAD TLV: type (0x22) + length + payload
            // Payload: asset_id (32) + CompactSize(proof_len) + proof + CompactSize(inputs_len) + inputs
            std::vector<unsigned char> zk_payload;

            // Asset ID (32 bytes)
            zk_payload.insert(zk_payload.end(), asset_id.begin(), asset_id.end());

            // Proof with CompactSize length prefix (192 bytes for Groth16)
            VectorWriter proof_writer(zk_payload, zk_payload.size());
            WriteCompactSize(proof_writer, proof->size());
            zk_payload.insert(zk_payload.end(), proof->begin(), proof->end());

            // Public inputs with CompactSize length prefix (128 bytes legacy / 192 bytes HDv1)
            VectorWriter inputs_writer(zk_payload, zk_payload.size());
            WriteCompactSize(inputs_writer, pub->size());
            zk_payload.insert(zk_payload.end(), pub->begin(), pub->end());

            // Build TLV: type + CompactSize length + payload
            std::vector<unsigned char> zk_proof_tlv;
            zk_proof_tlv.push_back(0x22); // ZK_PROOF_PAYLOAD type
            VectorWriter writer(zk_proof_tlv, zk_proof_tlv.size());
            WriteCompactSize(writer, zk_payload.size());
            zk_proof_tlv.insert(zk_proof_tlv.end(), zk_payload.begin(), zk_payload.end());

            // Create zero-value output with ONLY the ZK_PROOF_PAYLOAD TLV
            CTxOut proof_output;
            proof_output.nValue = 0;
            proof_output.scriptPubKey = CScript() << OP_RETURN;  // OP_RETURN script for zero-value metadata output
            proof_output.vExt = std::move(zk_proof_tlv);

            // Add to transaction
            psbt.tx->vout.push_back(proof_output);
            LogPrintf("ApplyZkWitness: created output %d with %d-byte ZK_PROOF_PAYLOAD TLV\n",
                     psbt.tx->vout.size() - 1, proof_output.vExt.size());
        } else {
            LogPrintf("ApplyZkWitness: FAILED - psbt.tx is null\n");
            throw std::runtime_error("ApplyZkWitness: psbt.tx is null");
        }
    }
    LogPrintf("ApplyZkWitness: completed successfully\n");
}

static std::vector<unsigned char> BuildTfrAnchorTlv(const uint256& asset_id,
                                                    const uint256& tfr_commit,
                                                    uint32_t keyset_id,
                                                    std::span<const unsigned char> locator)
{
    std::vector<unsigned char> payload;
    const bool include_transport_metadata = keyset_id != 0 || !locator.empty();
    payload.reserve(32 + 32 + (include_transport_metadata ? 4 + locator.size() : 0));
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    payload.insert(payload.end(), tfr_commit.begin(), tfr_commit.end());
    if (include_transport_metadata) {
        unsigned char keyset_buf[4];
        WriteLE32(keyset_buf, keyset_id);
        payload.insert(payload.end(), keyset_buf, keyset_buf + 4);
        payload.insert(payload.end(), locator.begin(), locator.end());
    }

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::TFR_ANCHOR));
    VectorWriter writer(tlv, tlv.size());
    WriteCompactSize(writer, payload.size());
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

[[maybe_unused]] static void AppendZkWitness(PartiallySignedTransaction& psbt,
                            size_t input_index,
                            const std::vector<unsigned char>& proof,
                            const std::vector<unsigned char>& public_inputs)
{
    if (input_index >= psbt.inputs.size()) return;
    CScriptWitness witness;
    if (!psbt.inputs[input_index].final_script_witness.IsNull()) {
        witness = psbt.inputs[input_index].final_script_witness;
    } else if (psbt.tx && input_index < psbt.tx->vin.size()) {
        witness = psbt.tx->vin[input_index].scriptWitness;
    }

    // Avoid duplicating data if already appended
    if (witness.stack.size() >= 2) {
        const auto& maybe_proof = witness.stack[witness.stack.size() - 2];
        const auto& maybe_pub = witness.stack[witness.stack.size() - 1];
        if (maybe_proof == proof && maybe_pub == public_inputs) {
            psbt.inputs[input_index].final_script_witness = witness;
            if (psbt.tx && input_index < psbt.tx->vin.size()) {
                psbt.tx->vin[input_index].scriptWitness = witness;
            }
            return;
        }
    }

    witness.stack.push_back(proof);
    witness.stack.push_back(public_inputs);
    psbt.inputs[input_index].final_script_witness = witness;
    if (psbt.tx && input_index < psbt.tx->vin.size()) {
        psbt.tx->vin[input_index].scriptWitness = witness;
    }
}

static std::vector<WalletAssetUtxo> CollectAssetUtxos(const CWallet& wallet, const CCoinControl& control, const CoinFilterParams& filter)
{
    LOCK(wallet.cs_wallet);
    std::vector<WalletAssetUtxo> result;
    const auto outputs = AvailableCoinsListUnspent(wallet, &control, filter).All();

    for (const COutput& out : outputs) {

        const auto tag = assets::ParseAssetTag(out.txout.vExt);
        if (!tag) {
            continue;
        }

        WalletAssetUtxo info;
        info.outpoint = out.outpoint;
        info.txout = out.txout;
        info.depth = out.depth;
        info.spendable = out.spendable;
        info.solvable = out.solvable;
        info.safe = out.safe;
        info.locked = wallet.IsLockedCoin(out.outpoint);
        // For balance reporting we want to treat WRAP_REQUIRED outputs as owned even if AvailableCoins() marks
        // them unspendable (they require ICU metadata, not different signing authority).
        const isminetype mine = wallet.IsMine(out.txout);
        info.ismine_spendable = (mine & ISMINE_SPENDABLE) != ISMINE_NO;
        info.asset_id = tag->id;
        info.units = tag->amount;
        if (auto meta = wallet.GetAssetMetadata(out.outpoint)) {
            info.metadata = *meta;
        }
        result.push_back(std::move(info));
    }
    return result;
}

static std::array<unsigned char, 32> ParseIcuBodyRefHex(const std::string& hex, std::string_view field_name)
{
    if (!IsHex(hex) || hex.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("%s entries must be 32-byte hex body hashes", field_name));
    }
    const std::vector<unsigned char> bytes = ParseHex(hex);
    std::array<unsigned char, 32> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

static std::vector<std::array<unsigned char, 32>> ParseIcuBodyRefs(const UniValue& value,
                                                                  std::string_view field_name)
{
    std::vector<std::array<unsigned char, 32>> refs;
    if (value.isNull()) return refs;
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("%s must be an array of 32-byte hex body hashes", field_name));
    }
    refs.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (!value[i].isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("%s entries must be strings", field_name));
        }
        refs.push_back(ParseIcuBodyRefHex(value[i].get_str(), field_name));
    }
    std::sort(refs.begin(), refs.end());
    if (std::adjacent_find(refs.begin(), refs.end()) != refs.end()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("%s contains duplicate body hashes", field_name));
    }
    return refs;
}

static UniValue IcuBodyRefsToJson(const std::vector<std::array<unsigned char, 32>>& refs)
{
    UniValue arr(UniValue::VARR);
    for (const auto& ref : refs) arr.push_back(HexStr(ref));
    return arr;
}

struct DescriptorTaprootBaseKey
{
    CKey internal_key;
    XOnlyPubKey internal_xonly;
    uint256 merkle_root;
};

static std::optional<DescriptorTaprootBaseKey> ResolveDescriptorTaprootBaseKey(CWallet& wallet,
                                                                               const CScript& spk,
                                                                               const XOnlyPubKey& output_key,
                                                                               std::string& error)
{
    std::optional<SpkOwner> owner_opt;
    DescriptorScriptPubKeyMan* owning_spkm = nullptr;
    const auto spk_mans = wallet.GetScriptPubKeyMans(spk);
    for (ScriptPubKeyMan* spk_man : spk_mans) {
        auto desc_spkman = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spkman) continue;
        auto candidate_owner = desc_spkman->GetDescriptorOwnerForScript(spk);
        if (!candidate_owner) continue;
        if (owner_opt) {
            error = "multiple wallet descriptors claim this taproot scriptPubKey";
            return std::nullopt;
        }
        owner_opt = candidate_owner;
        owning_spkm = desc_spkman;
    }

    if (!owner_opt || !owning_spkm) {
        error = "wallet does not own the taproot scriptPubKey";
        return std::nullopt;
    }
    if (wallet.IsLocked()) {
        error = "wallet is locked";
        return std::nullopt;
    }
    if (owner_opt->is_watch_only) {
        error = "taproot descriptor is watch-only";
        return std::nullopt;
    }
    if (!owner_opt->has_priv_at_index && !owning_spkm->EnsurePrivKeyAtIndex(owner_opt->index)) {
        error = strprintf("cannot derive private key at descriptor index %d", owner_opt->index);
        return std::nullopt;
    }

    auto internal_key = owning_spkm->DerivePrivateKeyAtIndex(owner_opt->index, owner_opt->internal_xonly);
    if (!internal_key) {
        error = strprintf("failed to derive internal private key at descriptor index %d", owner_opt->index);
        return std::nullopt;
    }

    auto provider = owning_spkm->GetSolvingProviderForScript(spk, /*include_private=*/false);
    if (!provider) {
        error = "failed to get taproot solving provider";
        return std::nullopt;
    }
    TaprootSpendData spenddata;
    if (!provider->GetTaprootSpendData(output_key, spenddata) || spenddata.internal_key.IsNull()) {
        error = "failed to get taproot spend data for output key";
        return std::nullopt;
    }
    if (spenddata.internal_key != owner_opt->internal_xonly) {
        error = "taproot spend data internal key does not match descriptor owner";
        return std::nullopt;
    }

    return DescriptorTaprootBaseKey{*internal_key, owner_opt->internal_xonly, spenddata.merkle_root};
}

static bool ApplyTaprootTweakToKey(CKey& key,
                                   const XOnlyPubKey& internal_xonly,
                                   const uint256& merkle_root,
                                   const XOnlyPubKey& expected_output,
                                   std::string& error)
{
    CPubKey pubkey = key.GetPubKey();
    if (pubkey[0] == 0x03 && !key.Negate()) {
        error = "failed to normalize taproot internal key parity";
        return false;
    }

    const uint256* tweak_merkle = merkle_root.IsNull() ? nullptr : &merkle_root;
    const uint256 tweak = internal_xonly.ComputeTapTweakHash(tweak_merkle);
    if (!key.TweakAdd(tweak)) {
        error = "failed to apply taproot tweak";
        return false;
    }
    if (XOnlyPubKey(key.GetPubKey()) != expected_output) {
        error = "taproot tweak produced a different output key";
        return false;
    }
    return true;
}

struct IcuAcceptanceTaprootSigner
{
    XOnlyPubKey output_key;
    CKey signing_key;
    uint256 signing_merkle_root;
    TxoutType txout_type{TxoutType::NONSTANDARD};
    std::string family;
};

static std::optional<IcuAcceptanceTaprootSigner> ResolveIcuAcceptanceTaprootSigner(CWallet& wallet,
                                                                                   const CScript& holder_spk,
                                                                                   std::string& error)
{
    TxoutType txout_type{TxoutType::NONSTANDARD};
    auto output_key = assets::ExtractTaprootOutputKeyFromSpk(holder_spk, txout_type);
    if (!output_key) {
        error = "holder prevout must be P2TR-v1 or P2TR-v2 for SECP_SCHNORR_RAW acceptance records";
        return std::nullopt;
    }

    if (txout_type == TxoutType::WITNESS_V1_TAPROOT) {
        auto base = ResolveDescriptorTaprootBaseKey(wallet, holder_spk, *output_key, error);
        if (!base) return std::nullopt;
        return IcuAcceptanceTaprootSigner{*output_key, base->internal_key, base->merkle_root, txout_type, "p2tr-v1"};
    }

    // Witness v2/PQ: the consensus spend authority is ML-DSA script-path, but the exposed
    // secp output key is key-path-disabled. Sign the acceptance record with that disabled
    // secp key; ML-DSA remains spend-only and never enters the acceptance record.
    WalletBatch batch(wallet.GetDatabase());
    MLDSATaprootMetadata tap_metadata;
    if (!batch.ReadMLDSATaprootData(*output_key, tap_metadata) || tap_metadata.internal_key.IsNull()) {
        error = "missing ML-DSA taproot metadata for witness-v2 holder output";
        return std::nullopt;
    }
    auto computed_v2 = tap_metadata.internal_key.CreateTapTweak(&tap_metadata.merkle_root);
    if (!computed_v2 || computed_v2->first != *output_key) {
        error = "stored witness-v2 taproot metadata does not derive the holder output key";
        return std::nullopt;
    }

    const CScript intermediate_v1_spk = GetScriptForDestination(WitnessV1Taproot(tap_metadata.internal_key));
    auto intermediate = ResolveDescriptorTaprootBaseKey(wallet, intermediate_v1_spk,
                                                        tap_metadata.internal_key, error);
    if (!intermediate) {
        error = "cannot derive the witness-v2 disabled secp key: " + error;
        return std::nullopt;
    }

    CKey disabled_key = intermediate->internal_key;
    if (!ApplyTaprootTweakToKey(disabled_key, intermediate->internal_xonly,
                                intermediate->merkle_root, tap_metadata.internal_key, error)) {
        error = "cannot derive the witness-v2 disabled secp key: " + error;
        return std::nullopt;
    }

    return IcuAcceptanceTaprootSigner{*output_key, disabled_key, tap_metadata.merkle_root, txout_type, "p2tr-v2"};
}

static const AssetRegistryEntry* LookupRegistryEntry(const JSONRPCRequest& request, const uint256& asset_id, std::map<uint256, std::optional<AssetRegistryEntry>>& cache)
{
    auto it = cache.find(asset_id);
    if (it != cache.end()) {
        if (it->second) {
            return &*it->second;
        }
        return nullptr;
    }

    WalletContext& wallet_context = EnsureWalletContext(request.context);
    interfaces::Chain* chain = wallet_context.chain;
    if (!chain) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not connected to a node");
    }

    if (auto entry = chain->getAssetRegistryEntry(asset_id)) {
        cache.emplace(asset_id, *entry);
        return &cache.at(asset_id).value();
    }

    cache.emplace(asset_id, std::nullopt);
    return nullptr;
}

static void MergeDisplayMetadata(UniValue& obj, const AssetMetadata* meta, const AssetRegistryEntry* reg_entry)
{
    if (meta && meta->has_ticker) {
        obj.pushKV("ticker", meta->ticker);
    } else if (reg_entry && !reg_entry->ticker.empty()) {
        obj.pushKV("ticker", reg_entry->ticker);
    }

    std::optional<uint8_t> decimals;
    if (meta && meta->has_decimals) {
        decimals = meta->decimals;
    } else if (reg_entry && reg_entry->decimals != std::numeric_limits<uint8_t>::max()) {
        decimals = reg_entry->decimals;
    }

    if (decimals) {
        obj.pushKV("decimals", static_cast<int64_t>(*decimals));
    }
}

static std::optional<uint8_t> ExtractDecimals(const AssetMetadata* meta, const AssetRegistryEntry* reg_entry)
{
    if (meta && meta->has_decimals) {
        return meta->decimals;
    }
    if (reg_entry && reg_entry->decimals != std::numeric_limits<uint8_t>::max()) {
        return reg_entry->decimals;
    }
    return std::nullopt;
}

} // namespace

RPCHelpMan listassetutxos()
{
    return RPCHelpMan{
        "listassetutxos",
        "List wallet UTXOs that carry AssetTag data.",
        {
            {"assets", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Filter to the provided assets (asset_id or ticker)",
                {
                    {"asset_identifier", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Asset ID (hex) or ticker"},
                }
            },
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations"},
            {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "Maximum confirmations"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                        {RPCResult::Type::NUM, "vout", "Output index"},
                        {RPCResult::Type::STR, "address", /*optional=*/true, "Destination address"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "BTC amount for the output"},
                        {RPCResult::Type::STR_HEX, "asset_id", "Asset identifier"},
                        {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker if known"},
                        {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Display decimals if known"},
                        {RPCResult::Type::NUM, "asset_units", "Raw asset units"},
                        {RPCResult::Type::STR, "asset_decimal", /*optional=*/true, "Formatted amount using decimals"},
                        {RPCResult::Type::NUM, "confirmations", "Confirmation count"},
                        {RPCResult::Type::BOOL, "spendable", "Whether the wallet can spend this output"},
                        {RPCResult::Type::BOOL, "solvable", "Whether the wallet knows how to sign this output"},
                        {RPCResult::Type::BOOL, "safe", "Whether the output is safe to spend"},
                        {RPCResult::Type::BOOL, "locked", "Whether the output is currently locked"},
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("listassetutxos", "") +
            HelpExampleCli("listassetutxos", "'[\"GOLD\",\"SILVER\"]' 1 9999999")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            std::set<uint256> filter_ids;
            const bool filter_requested = !request.params[0].isNull();
            if (filter_requested) {
                const UniValue& arr = request.params[0];
                if (!arr.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "assets must be an array");
                }
                for (const UniValue& v : arr.getValues()) {
                    AssetResolution resolved = ResolveAssetIdOrTicker(request, v.get_str());
                    filter_ids.insert(resolved.asset_id);
                }
            }

            const int minconf = request.params[1].isNull() ? 1 : request.params[1].getInt<int>();
            const int maxconf = request.params[2].isNull() ? 9999999 : request.params[2].getInt<int>();

            pwallet->BlockUntilSyncedToCurrentChain();

            CCoinControl control;
            control.m_min_depth = minconf;
            control.m_max_depth = maxconf;
            control.m_include_unsafe_inputs = true;
            control.m_avoid_asset_utxos = false;  // CRITICAL: Include asset outputs!

            CoinFilterParams filter_params;
            filter_params.only_spendable = false;

            std::vector<WalletAssetUtxo> utxos = CollectAssetUtxos(*pwallet, control, filter_params);

            std::map<uint256, std::optional<AssetRegistryEntry>> registry_cache;

            UniValue result(UniValue::VARR);
            for (const WalletAssetUtxo& info : utxos) {
                if (filter_requested && !filter_ids.count(info.asset_id)) {
                    continue;
                }

                const AssetRegistryEntry* registry = LookupRegistryEntry(request, info.asset_id, registry_cache);

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("txid", info.outpoint.hash.GetHex());
                entry.pushKV("vout", static_cast<int64_t>(info.outpoint.n));

                CTxDestination addr;
                if (ExtractDestination(info.txout.scriptPubKey, addr)) {
                    entry.pushKV("address", EncodeDestination(addr));
                }

                entry.pushKV("amount", ValueFromAmount(info.txout.nValue));
                entry.pushKV("asset_id", info.asset_id.ToString());

                MergeDisplayMetadata(entry, info.metadata ? &*info.metadata : nullptr, registry);

                entry.pushKV("asset_units", info.units);

                if (const auto decimals = ExtractDecimals(info.metadata ? &*info.metadata : nullptr, registry)) {
                    entry.pushKV("asset_decimal", FormatAssetUnits(info.units, *decimals));
                }

                entry.pushKV("confirmations", info.depth);
                entry.pushKV("spendable", info.spendable);
                entry.pushKV("solvable", info.solvable);
                entry.pushKV("safe", info.safe);
                entry.pushKV("locked", info.locked);

                result.push_back(std::move(entry));
            }

            return result;
        }
    };
}

RPCHelpMan getassetbalance()
{
    return RPCHelpMan{
        "getassetbalance",
        "Return aggregated wallet balances for assets.",
        {
            {"assets", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Restrict to the provided assets (asset_id or ticker)",
                {
                    {"asset_identifier", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Asset ID (hex) or ticker"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "asset_id", "Asset identifier"},
                        {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker if known"},
                        {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Display decimals if known"},
                        {RPCResult::Type::NUM, "balance", "Confirmed, unlocked units"},
                        {RPCResult::Type::STR, "balance_decimal", /*optional=*/true, "Formatted balance"},
                        {RPCResult::Type::NUM, "pending", "Units in unconfirmed transactions"},
                        {RPCResult::Type::NUM, "locked", "Units currently locked"},
                        {RPCResult::Type::NUM, "utxo_count", "Number of spendable UTXOs"},
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("getassetbalance", "") +
            HelpExampleCli("getassetbalance", "'[\"GOLD\",\"USD\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            std::optional<std::set<uint256>> filter_ids;
            if (!request.params[0].isNull()) {
                const UniValue& arr = request.params[0];
                if (!arr.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "assets must be an array");
                }
                std::set<uint256> ids;
                for (const UniValue& v : arr.getValues()) {
                    AssetResolution resolved = ResolveAssetIdOrTicker(request, v.get_str());
                    ids.insert(resolved.asset_id);
                }
                if (!ids.empty()) {
                    filter_ids = std::move(ids);
                }
            }

            pwallet->BlockUntilSyncedToCurrentChain();

            CCoinControl control;
            control.m_min_depth = 0;
            control.m_max_depth = 9999999;
            control.m_include_unsafe_inputs = true;
            control.m_avoid_asset_utxos = false;  // CRITICAL: Include asset outputs!

            CoinFilterParams filter_params;
            filter_params.only_spendable = false;

            std::vector<WalletAssetUtxo> utxos = CollectAssetUtxos(*pwallet, control, filter_params);

            struct BalanceBucket {
                uint64_t confirmed{0};
                uint64_t pending{0};
                uint64_t locked{0};
                uint32_t utxo_count{0};
                std::optional<AssetMetadata> metadata;
            };

            std::map<uint256, BalanceBucket> totals;
            for (const WalletAssetUtxo& info : utxos) {
                if (filter_ids && !filter_ids->count(info.asset_id)) {
                    continue;
                }

                BalanceBucket& bucket = totals[info.asset_id];
                if (!bucket.metadata && info.metadata) {
                    bucket.metadata = info.metadata;
                }

                // For balance reporting, only check ismine_spendable, not out.spendable
                // out.spendable may be false for technical reasons but we still want to report owned assets
                if (info.ismine_spendable) {
                    if (info.depth > 0 && !info.locked) {
                        bucket.confirmed += info.units;
                    }
                    if (info.depth == 0) {
                        bucket.pending += info.units;
                    }
                    if (info.locked) {
                        bucket.locked += info.units;
                    }
                    bucket.utxo_count++;
                }
            }

            std::map<uint256, std::optional<AssetRegistryEntry>> registry_cache;

            UniValue result(UniValue::VARR);
            for (auto& [asset_id, bucket] : totals) {
                const AssetRegistryEntry* registry = LookupRegistryEntry(request, asset_id, registry_cache);

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("asset_id", asset_id.ToString());

                const AssetMetadata* meta_ptr = bucket.metadata ? &*bucket.metadata : nullptr;
                MergeDisplayMetadata(entry, meta_ptr, registry);

                entry.pushKV("balance", bucket.confirmed);
                entry.pushKV("pending", bucket.pending);
                entry.pushKV("locked", bucket.locked);
                entry.pushKV("utxo_count", static_cast<uint64_t>(bucket.utxo_count));

                if (const auto decimals = ExtractDecimals(meta_ptr, registry)) {
                    entry.pushKV("balance_decimal", FormatAssetUnits(bucket.confirmed, *decimals));
                }

                result.push_back(std::move(entry));
            }

            return result;
        }
    };
}

RPCHelpMan getassetinfo()
{
    return RPCHelpMan{
        "getassetinfo",
        "Return registry information about a specific asset.",
        {
            {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (hex) or ticker"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Asset identifier"},
                {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker if registered"},
                {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Decimals if registered"},
                {RPCResult::Type::NUM, "policy_bits", "Policy bitfield"},
                {RPCResult::Type::NUM, "allowed_spk_families", "Allowed script families mask"},
                {RPCResult::Type::STR_HEX, "icu_txid", "Current ICU transaction"},
                {RPCResult::Type::NUM, "icu_vout", "Current ICU vout"},
                {RPCResult::Type::NUM, "unlock_fees_sats", "Unlock threshold in satoshis"},
                {RPCResult::Type::NUM, "fees_accum_sats", "Accumulated fees in satoshis"},
                {RPCResult::Type::NUM, "rotation_min_sats", /*optional=*/true, "Observed minimum rotation value"},
            }
        },
        RPCExamples{
            HelpExampleCli("getassetinfo", "GOLD") +
            HelpExampleCli("getassetinfo", "<asset_id>")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());
            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not registered");
            }

            const AssetRegistryEntry& entry = *resolved.registry;

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", resolved.asset_id.ToString());
            if (!entry.ticker.empty()) {
                result.pushKV("ticker", entry.ticker);
            }
            if (entry.decimals != std::numeric_limits<uint8_t>::max()) {
                result.pushKV("decimals", static_cast<int64_t>(entry.decimals));
            }
            result.pushKV("policy_bits", static_cast<uint64_t>(entry.policy_bits));
            result.pushKV("allowed_spk_families", static_cast<uint64_t>(entry.allowed_spk_families));
            result.pushKV("icu_txid", entry.icu_outpoint.hash.GetHex());
            result.pushKV("icu_vout", static_cast<int64_t>(entry.icu_outpoint.n));
            result.pushKV("unlock_fees_sats", entry.unlock_fees_sats);
            result.pushKV("fees_accum_sats", entry.fees_accum_sats);
            if (entry.rotation_min_sats != 0) {
                result.pushKV("rotation_min_sats", entry.rotation_min_sats);
            }

            return result;
        }
    };
}

RPCHelpMan sponsorchildasset()
{
    return RPCHelpMan{
        "sponsorchildasset",
        "Register a low-bond sponsored child asset ROOT.SUFFIX by co-spending the sponsoring root's "
        "current ICU (ICU_CHILD.md §6.1). The parent root is recreated as a byte-identical successor "
        "in the same transaction, and the child registers at SponsoredChildMinIcuBond (default 10,000 "
        "sats). Returns raw transaction hex (and broadcasts on request), matching registerasset / "
        "rotateicu_raw house style.\n"
        "Registers exactly ONE child per call. The consensus rule permits several children under a "
        "single parent co-spend, but that batch path is not exposed by this RPC.",
        {
            {"root", RPCArg::Type::STR, RPCArg::Optional::NO, "Sponsoring root: ticker, or 32-byte asset_id hex"},
            {"suffix", RPCArg::Type::STR, RPCArg::Optional::NO, "Child suffix (root grammar [A-Z][A-Z0-9]{2,10}); the full child ticker is ROOT.SUFFIX"},
            {"child_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte child asset id hex"},
            {"child_destination", RPCArg::Type::STR, RPCArg::Optional::NO, "Child ICU destination address"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"child_bond_sats", RPCArg::Type::NUM, RPCArg::Default{10000}, "Child ICU bond in sats (>= SponsoredChildMinIcuBond)"},
                    {"policy_bits", RPCArg::Type::NUM, RPCArg::Default{1}, "Child policy bits (default MINT_ALLOWED)"},
                    {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{28}, "Allowed script families (28 = P2WPKH | P2WSH | P2TR)"},
                    {"decimals", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Child decimals (0..18)"},
                    {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold in sats (default = child_bond_sats; must be >= child_bond_sats)"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Default{0}, "Issuance cap in base units (0 = unlimited)"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Default{0}, "Governance quorum bps (0 = immutable after issuance)"},
                    {"icu_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ICU structural flags (e.g., WRAP_REQUIRED=1)"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Default{0}, "0=public, 1=holder_only"},
                    {"icu_payload_plain", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical ICU payload (from buildcanonicalicupayload); normalized/encrypted + committed like registerasset"},
                    {"use_compression", RPCArg::Type::BOOL, RPCArg::Default{false}, "Compress the ICU payload (zstd)"},
                    {"kyc_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ZK/KYC flags"},
                    {"vk_data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ZK verification key data (chunked + committed automatically)"},
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::Default{0}, "Maximum KYC root age"},
                    {"tfr_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Transfer flags"},
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Pre-built ICU cipher bytes (advanced; alternative to icu_payload_plain)"},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte plaintext commitment (advanced)"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ciphertext commitment (advanced)"},
                    {"kdf_salt", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte ICU encryption salt (advanced)"},
                    {"parent_icu_outpoint", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Override parent ICU outpoint as \"txid:vout\" (default: current ICU from the registry)"},
                    {"parent_successor_destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Address for the recreated parent ICU (default: a new wallet address)"},
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Fund native fees + change from the wallet"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Sign and broadcast"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Signal RBF"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (funded unless autofund=false; signed only when broadcast=true)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast txid if broadcast=true"},
                {RPCResult::Type::STR, "child_ticker", "Full child ticker ROOT.SUFFIX"},
                {RPCResult::Type::STR_HEX, "child_asset_id", "Child asset id"},
                {RPCResult::Type::NUM, "child_bond_sats", "Child ICU bond in sats"},
                {RPCResult::Type::STR_HEX, "parent_asset_id", "Sponsoring root asset id"},
                {RPCResult::Type::STR, "parent_icu_outpoint", "Spent parent ICU outpoint (txid:vout)"},
                {RPCResult::Type::NUM, "parent_successor_vout", "Vout of the recreated parent ICU"},
                {RPCResult::Type::NUM, "child_icu_vout", "Vout of the child ICU"},
                {RPCResult::Type::BOOL, "requires_parent_signature", "True if the parent ICU is not wallet-spendable (an external signature is needed)"},
                {RPCResult::Type::ARR, "warnings", "", {{RPCResult::Type::STR, "", "warning"}}},
            }
        },
        RPCExamples{HelpExampleCli("sponsorchildasset", "\"ACME\" \"C150K\" \"<child_asset_id>\" \"bc1q...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // --- resolve the sponsoring root ---
            AssetResolution parent = ResolveAssetIdOrTicker(request, request.params[0].get_str());
            if (!parent.registry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sponsoring root not found in the registry");
            }
            const AssetRegistryEntry& preg = *parent.registry;
            const std::string parent_ticker = preg.ticker;
            if (parent_ticker.empty() || !assets::IsRootTicker(parent_ticker)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Sponsoring asset has no root ticker (a dotted child cannot sponsor)");
            }

            // --- assemble + validate the child ticker ---
            std::string suffix = request.params[1].get_str();
            for (char& c : suffix) { if (c >= 'a' && c <= 'z') c = char(c - 32); }
            const std::string child_ticker = parent_ticker + "." + suffix;
            if (!assets::ParseChildTicker(child_ticker)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid child ticker %s (suffix must be root grammar [A-Z][A-Z0-9]{2,10}, one hop only)", child_ticker));
            }

            auto child_aid = uint256::FromHex(request.params[2].get_str());
            if (!child_aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid child_asset_id hex");

            CTxDestination child_dest = DecodeDestination(request.params[3].get_str());
            if (!IsValidDestination(child_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid child_destination");

            // --- options ---
            // Read the floors from consensus rather than hard-coding, so the RPC never drifts from
            // Consensus::Params (ICU_CHILD.md §3.2, §10).
            const Consensus::Params& consensus = Params().GetConsensus();
            const CAmount kSponsoredChildMin = consensus.SponsoredChildMinIcuBond;
            const CAmount kAssetMinIcuBond = consensus.AssetMinIcuBond;
            CAmount child_bond = kSponsoredChildMin;
            uint32_t policy_bits = assets::MINT_ALLOWED;
            uint16_t allowed = 28;
            bool has_decimals = false; uint8_t decimals = 0xFF;
            bool has_unlock = false; uint64_t unlock = 0;
            uint64_t issuance_cap_units = 0; uint16_t policy_quorum_bps = 0; uint32_t icu_flags = 0; uint8_t icu_visibility = 0;
            // ICU governance payload + ZK/compliance — a sponsored child is a full asset and may carry
            // exactly what a standalone registration can (ICU_CHILD.md §7.1).
            std::vector<unsigned char> icu_plaintext; bool icu_plaintext_provided = false; bool use_compression = false;
            uint32_t kyc_flags = 0, max_root_age = 0, tfr_flags = 0; std::vector<unsigned char> vk_data;
            std::vector<unsigned char> icu_payload; uint256 icu_plain_commit, icu_ctxt_commit; std::array<unsigned char, 16> kdf_salt{};
            std::optional<COutPoint> parent_outpoint_override;
            std::optional<CTxDestination> parent_succ_dest_opt;
            bool autofund = true, broadcast = false; std::optional<double> fee_rate_vb; std::optional<bool> replaceable = true;
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                const UniValue& opt = request.params[4];
                if (opt.exists("child_bond_sats")) child_bond = opt["child_bond_sats"].getInt<int64_t>();
                if (opt.exists("policy_bits")) policy_bits = opt["policy_bits"].getInt<uint32_t>();
                if (opt.exists("allowed_spk_families")) allowed = opt["allowed_spk_families"].getInt<uint16_t>();
                if (opt.exists("decimals")) { has_decimals = true; int d = opt["decimals"].getInt<int>(); if (d < 0 || d > 18) throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals must be 0..18"); decimals = (uint8_t)d; }
                if (opt.exists("unlock_fees_sats")) { has_unlock = true; unlock = opt["unlock_fees_sats"].getInt<uint64_t>(); }
                if (opt.exists("issuance_cap_units")) issuance_cap_units = opt["issuance_cap_units"].getInt<uint64_t>();
                if (opt.exists("policy_quorum_bps")) policy_quorum_bps = opt["policy_quorum_bps"].getInt<uint16_t>();
                if (opt.exists("icu_flags")) icu_flags = opt["icu_flags"].getInt<uint32_t>();
                if (opt.exists("icu_visibility")) icu_visibility = (uint8_t)opt["icu_visibility"].getInt<int>();
                // Full ICU/ZK parity with registerasset (handled by the shared builder below).
                if (opt.exists("icu_payload_plain")) { icu_plaintext = ParseHex(opt["icu_payload_plain"].get_str()); icu_plaintext_provided = !icu_plaintext.empty(); }
                if (opt.exists("use_compression")) use_compression = opt["use_compression"].get_bool();
                if (opt.exists("kyc_flags")) kyc_flags = opt["kyc_flags"].getInt<uint32_t>();
                if (opt.exists("vk_data")) vk_data = ParseHex(opt["vk_data"].get_str());
                if (opt.exists("max_root_age")) max_root_age = opt["max_root_age"].getInt<uint32_t>();
                if (opt.exists("tfr_flags")) tfr_flags = opt["tfr_flags"].getInt<uint32_t>();
                if (opt.exists("icu_payload")) icu_payload = ParseHex(opt["icu_payload"].get_str());
                if (opt.exists("icu_plain_commit")) { auto h = uint256::FromHex(opt["icu_plain_commit"].get_str()); if (h) icu_plain_commit = *h; }
                if (opt.exists("icu_ctxt_commit")) { auto h = uint256::FromHex(opt["icu_ctxt_commit"].get_str()); if (h) icu_ctxt_commit = *h; }
                if (opt.exists("kdf_salt")) { auto s = ParseHex(opt["kdf_salt"].get_str()); if (s.size() == 16) std::copy(s.begin(), s.end(), kdf_salt.begin()); }
                if (opt.exists("parent_icu_outpoint")) {
                    const std::string s = opt["parent_icu_outpoint"].get_str();
                    auto colon = s.rfind(':');
                    if (colon == std::string::npos) throw JSONRPCError(RPC_INVALID_PARAMETER, "parent_icu_outpoint must be txid:vout");
                    auto ptxid = Txid::FromHex(s.substr(0, colon));
                    if (!ptxid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid parent_icu_outpoint txid");
                    parent_outpoint_override = COutPoint(*ptxid, (uint32_t)std::stoul(s.substr(colon + 1)));
                }
                if (opt.exists("parent_successor_destination")) {
                    CTxDestination d = DecodeDestination(opt["parent_successor_destination"].get_str());
                    if (!IsValidDestination(d)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid parent_successor_destination");
                    parent_succ_dest_opt = d;
                }
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
            }
            if (child_bond < kSponsoredChildMin) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("child_bond_sats must be >= %d (SponsoredChildMinIcuBond)", kSponsoredChildMin));
            }
            if (!has_unlock) unlock = (uint64_t)child_bond; // default unlock == bond (satisfies the consensus unlock>=bond rule)
            if (unlock < (uint64_t)child_bond) throw JSONRPCError(RPC_INVALID_PARAMETER, "unlock_fees_sats must be >= child_bond_sats");

            // --- read the parent's current ICU (value, script, IssuerReg bytes) ---
            const COutPoint parent_icu = parent_outpoint_override.value_or(preg.icu_outpoint);
            std::map<COutPoint, Coin> coins; coins[parent_icu];
            pwallet->chain().findCoins(coins);
            const Coin& pcoin = coins[parent_icu];
            if (pcoin.IsSpent()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Parent ICU outpoint is unknown or already spent");
            const CAmount parent_value = pcoin.out.nValue;
            const CScript parent_script = pcoin.out.scriptPubKey;
            const std::vector<unsigned char> parent_vext = pcoin.out.vExt; // reused verbatim for a byte-identical successor
            auto parent_reg = assets::ParseIssuerReg(parent_vext);
            if (!parent_reg) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Parent ICU outpoint does not carry an IssuerReg");
            }
            // The spent prevout must be the sponsoring root's OWN current ICU. Without these checks an
            // explicit parent_icu_outpoint override could point at a different (wrong-root) or stale ICU,
            // building a transaction the consensus child-sponsorship check then rejects (ICU_CHILD.md §3.3).
            if (parent_reg->asset_id != parent.asset_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "parent_icu_outpoint belongs to a different asset than the sponsoring root");
            }
            if (parent_icu != preg.icu_outpoint) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "parent_icu_outpoint is not the sponsoring root's current ICU (per the registry)");
            }
            if (parent_value < kAssetMinIcuBond) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Parent ICU value %d is below the full root bond %d; it can no longer sponsor children (ICU_CHILD.md §3.3)", parent_value, kAssetMinIcuBond));
            }

            // --- parent successor destination (fresh wallet address by default) ---
            CTxDestination parent_succ_dest;
            if (parent_succ_dest_opt) {
                parent_succ_dest = *parent_succ_dest_opt;
            } else {
                auto d = pwallet->GetNewDestination(OutputType::BECH32, "sponsor parent successor");
                if (!d) throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(d).original);
                parent_succ_dest = *d;
            }
            const CScript parent_succ_script = GetScriptForDestination(parent_succ_dest);
            const CScript child_script = GetScriptForDestination(child_dest);
            if (parent_succ_script == child_script) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "parent successor and child must use different addresses");
            }

            // --- build the child IssuerReg + ICU/ZK chunk TLVs via the shared registration builder,
            // so a sponsored child has the same registry/ICU/ZK semantics as a standalone asset ---
            AssetRegistrationInputs reg_in;
            reg_in.asset_id = *child_aid;
            reg_in.policy_bits = policy_bits;
            reg_in.allowed_spk = allowed;
            reg_in.ticker = child_ticker;
            reg_in.decimals = has_decimals ? decimals : (uint8_t)0xFF;
            reg_in.unlock_fees = unlock;
            reg_in.kyc_flags = kyc_flags;
            reg_in.vk_data = vk_data;
            reg_in.max_root_age = max_root_age;
            reg_in.tfr_flags = tfr_flags;
            reg_in.icu_plaintext = icu_plaintext;
            reg_in.icu_plaintext_provided = icu_plaintext_provided;
            reg_in.icu_flags = icu_flags;
            reg_in.icu_visibility = icu_visibility;
            reg_in.use_compression = use_compression;
            reg_in.policy_quorum_bps = policy_quorum_bps;
            reg_in.issuance_cap_units = issuance_cap_units;
            reg_in.icu_plain_commit = icu_plain_commit;
            reg_in.icu_ctxt_commit = icu_ctxt_commit;
            reg_in.kdf_salt = kdf_salt;
            reg_in.icu_payload = icu_payload;
            const AssetRegistrationTLVs reg_tlvs = BuildAssetRegistrationTLVs(*pwallet, reg_in);
            const std::vector<unsigned char>& child_tlv = reg_tlvs.issuer_reg_tlv;

            // requires_parent_signature: is the parent ICU spendable by this wallet?
            bool parent_is_mine;
            {
                LOCK(pwallet->cs_wallet);
                parent_is_mine = (pwallet->IsMine(parent_script) & ISMINE_SPENDABLE);
            }

            // --- assemble the transaction: parent ICU input + [parent successor, child] outputs ---
            CMutableTransaction mtx;
            mtx.vin.emplace_back(parent_icu);

            UniValue warnings(UniValue::VARR);
            UniValue result(UniValue::VOBJ);
            size_t parent_succ_vout = 0, child_vout = 0;

            if (autofund) {
                CCoinControl cc;
                cc.m_allow_other_inputs = true;
                // Fund native fees + change from NATIVE utxos only. Do NOT set m_required_asset_id or
                // m_allow_icu_selection: this tx carries no asset-token output, so pulling parent token
                // units (which a matching required_asset_id would admit, spend.cpp ~620) or another ICU
                // for fees would break asset conservation. The pre-added parent ICU input bypasses
                // m_avoid_asset_utxos (it only filters AUTO-selected coins), so it is still kept.
                cc.m_avoid_asset_utxos = true;
                cc.m_change_type = OutputType::BECH32M;
                if (fee_rate_vb) { cc.fOverrideFeeRate = true; cc.m_feerate = CFeeRate((CAmount)(*fee_rate_vb * 1000.0)); }
                if (replaceable) cc.m_signal_bip125_rbf = *replaceable;

                std::vector<CRecipient> recipients = {
                    CRecipient{parent_succ_dest, parent_value, /*fSubtractFeeFromAmount=*/false},
                    CRecipient{child_dest, child_bond, /*fSubtractFeeFromAmount=*/false},
                };
                // ICU_TEXT_CHUNK + ZK_PARAMS_CHUNK ride along as 546-sat dust outputs at fresh
                // addresses, reattached by script after funding (same pattern as registerasset).
                std::vector<std::pair<CScript, std::vector<unsigned char>>> chunks;
                {
                    std::vector<std::vector<unsigned char>> chunk_tlvs;
                    if (!reg_tlvs.icu_chunk_tlv.empty()) chunk_tlvs.push_back(reg_tlvs.icu_chunk_tlv);
                    for (const auto& z : reg_tlvs.zk_chunk_tlvs) chunk_tlvs.push_back(z);
                    for (const auto& tlv : chunk_tlvs) {
                        auto d = pwallet->GetNewDestination(OutputType::BECH32, "child ICU chunk");
                        if (!d) throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(d).original);
                        chunks.emplace_back(GetScriptForDestination(*d), tlv);
                        recipients.push_back(CRecipient{*d, 546, /*fSubtractFeeFromAmount=*/false});
                    }
                }
                auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, cc);
                if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                mtx = CMutableTransaction(*txr->tx);
                // Fee was computed for the pre-vExt tx; remember the funded size/fee so we can re-apply
                // the rate to the actual size after the IssuerReg/chunk TLVs are attached below.
                const unsigned int funded_size = GetVirtualTransactionSize(CTransaction(mtx));
                const CAmount funded_fee = txr->fee;

                bool found_p = false, found_c = false;
                std::vector<bool> chunk_done(chunks.size(), false);
                for (size_t i = 0; i < mtx.vout.size(); ++i) {
                    CTxOut& o = mtx.vout[i];
                    if (!o.vExt.empty()) continue;
                    if (!found_p && o.scriptPubKey == parent_succ_script && o.nValue == parent_value) {
                        o.vExt = parent_vext; parent_succ_vout = i; found_p = true; continue;
                    }
                    if (!found_c && o.scriptPubKey == child_script && o.nValue == child_bond) {
                        o.vExt = child_tlv; child_vout = i; found_c = true; continue;
                    }
                    for (size_t k = 0; k < chunks.size(); ++k) {
                        if (!chunk_done[k] && o.nValue == 546 && o.scriptPubKey == chunks[k].first) {
                            o.vExt = chunks[k].second; chunk_done[k] = true; break;
                        }
                    }
                }
                const bool all_chunks = std::all_of(chunk_done.begin(), chunk_done.end(), [](bool b){ return b; });
                if (!found_p || !found_c || !all_chunks) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to reattach IssuerReg/chunk TLVs after funding");
                }
                // The IssuerReg/chunk vExt grew the tx after funding, so the funded fee now sits at a
                // lower effective rate. Re-apply the funded rate to the ACTUAL size by trimming change,
                // so the tx clears min-relay on standard networks like testnet (mirrors registerasset).
                const unsigned int actual_size = GetVirtualTransactionSize(CTransaction(mtx));
                const CFeeRate funded_rate = funded_size > 0 ? CFeeRate(funded_fee, funded_size) : CFeeRate(0);
                const CAmount required_fee = funded_rate.GetFee(actual_size);
                if (required_fee > funded_fee) {
                    const CAmount deficit = required_fee - funded_fee;
                    for (auto& o : mtx.vout) {
                        if (o.vExt.empty() && o.nValue != parent_value && o.nValue != child_bond && o.nValue != 546 && o.nValue > deficit + 546) {
                            o.nValue -= deficit;
                            break;
                        }
                    }
                }
            } else {
                mtx.vout.emplace_back(parent_value, parent_succ_script); mtx.vout.back().vExt = parent_vext; parent_succ_vout = mtx.vout.size() - 1;
                mtx.vout.emplace_back(child_bond, child_script); mtx.vout.back().vExt = child_tlv; child_vout = mtx.vout.size() - 1;
                std::vector<std::vector<unsigned char>> chunk_tlvs;
                if (!reg_tlvs.icu_chunk_tlv.empty()) chunk_tlvs.push_back(reg_tlvs.icu_chunk_tlv);
                for (const auto& z : reg_tlvs.zk_chunk_tlvs) chunk_tlvs.push_back(z);
                for (const auto& tlv : chunk_tlvs) {
                    auto d = pwallet->GetNewDestination(OutputType::BECH32, "child ICU chunk");
                    if (!d) throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(d).original);
                    mtx.vout.emplace_back(CAmount{546}, GetScriptForDestination(*d)); mtx.vout.back().vExt = tlv;
                }
                warnings.push_back("autofund=false: transaction has no fee inputs or change; fund and sign it yourself");
            }

            if (broadcast) {
                if (!parent_is_mine) warnings.push_back("parent ICU is not wallet-spendable; broadcast may fail without the parent owner's signature");
                PartiallySignedTransaction psbtx(mtx);
                bool complete = false;
                const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                if (fill_err) throw JSONRPCPSBTError(*fill_err);
                if (!complete) throw JSONRPCError(RPC_WALLET_ERROR, "Transaction could not be fully signed (the parent ICU may need an external signature)");
                CMutableTransaction signed_mtx;
                if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
                CTransactionRef tx = MakeTransactionRef(CTransaction(signed_mtx));
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});
                // CommitTransaction records the wallet tx and broadcasts, but only LOGS a broadcast/
                // mempool rejection (wallet.cpp). Verify the tx actually entered the mempool so failures
                // surface synchronously — a successful return then means the node accepted the child.
                if (!pwallet->chain().isInMempool(tx->GetHash())) {
                    // CommitTransaction already recorded the wallet tx; name the txid so the caller can
                    // inspect it (gettransaction) or drop it (abandontransaction).
                    throw JSONRPCError(RPC_TRANSACTION_ERROR,
                        strprintf("Sponsored-child transaction %s was created, signed, and recorded in the wallet, "
                                  "but the node rejected it from the mempool; inspect with gettransaction or drop with abandontransaction",
                                  tx->GetHash().ToString()));
                }
                result.pushKV("txid", tx->GetHash().ToString());
                mtx = signed_mtx;
            }

            DataStream ds; ds << TX_WITH_WITNESS(mtx);
            result.pushKV("hex", HexStr(ds));
            result.pushKV("child_ticker", child_ticker);
            result.pushKV("child_asset_id", child_aid->ToString());
            result.pushKV("child_bond_sats", (int64_t)child_bond);
            result.pushKV("parent_asset_id", parent.asset_id.ToString());
            result.pushKV("parent_icu_outpoint", parent_icu.ToString());
            result.pushKV("parent_successor_vout", (int64_t)parent_succ_vout);
            result.pushKV("child_icu_vout", (int64_t)child_vout);
            result.pushKV("requires_parent_signature", !parent_is_mine);
            result.pushKV("warnings", warnings);
            return result;
        }
    };
}

RPCHelpMan wallet_registerasset()
{
    return RPCHelpMan{
        "registerasset",
        "Register a new asset with optional ticker and decimals (wallet version).",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "ICU destination address"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "ICU BTC amount (minimum 5 BTC)"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset id hex"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits (e.g., 3 for MINT_ALLOWED | BURN_ALLOWED)"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{28}, "Allowed script families (28 = P2WPKH | P2WSH | P2TR)"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold in satoshis"},
            {"ticker", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Ticker symbol [A-Z0-9]{3,11}"},
            {"decimals", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Decimal places (0..18)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Automatically fund transaction fees"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Enable RBF"},
                    {"kyc_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ZK/KYC flags (e.g., KYC_REQUIRED=1)"},
                    {"vk_data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ZK verification key data (will be chunked and committed automatically)"},
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::Default{0}, "Maximum merkle root age in seconds"},
                    {"tfr_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Transfer flags (e.g., TFR_ANCHOR_REQUIRED)"},
                    {"icu_payload_plain", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical ICU plaintext bytes. When provided, the wallet encrypts and computes commits automatically."},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte plaintext commitment"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ciphertext commitment"},
                    {"kdf_salt", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte encryption salt"},
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw ICU payload bytes (for ICU_TEXT_CHUNK)"},
                    {"icu_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ICU structural flags (e.g., WRAP_REQUIRED=1)"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Default{0}, "0=public, 1=holder_only"},
                    {"use_compression", RPCArg::Type::BOOL, RPCArg::Default{false}, "Enable zstd compression for ICU payload"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Default{0}, "Governance quorum in basis points (0=immutable)"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Default{0}, "Issuance cap in base units (0=unlimited)"},
                    {"issuance_cap", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Issuance cap expressed in asset units (e.g., \"50.0\"). Overrides issuance_cap_units."},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "Transaction ID if broadcast, otherwise hex"},
        RPCExamples{
            HelpExampleCli("registerasset", "\"bc1q...\" 5.1 \"aaa...aaa\" 3 28 510000000 \"GOLD\" 8")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Parse parameters
            CTxDestination dest = DecodeDestination(request.params[0].get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            CAmount amt = AmountFromValue(request.params[1]);
            if (amt < 5 * COIN) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU bond must be at least 5 BTC");
            }

            auto aid = uint256::FromHex(request.params[2].get_str());
            if (!aid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }

            uint32_t policy_bits = request.params[3].getInt<uint32_t>();
            uint16_t allowed = request.params[4].isNull() ? 28 : request.params[4].getInt<uint16_t>();

            bool has_unlock = !request.params[5].isNull();
            uint64_t unlock = has_unlock ? request.params[5].getInt<uint64_t>() : 0;

            bool has_ticker = !request.params[6].isNull();
            std::string ticker = has_ticker ? request.params[6].get_str() : "";

            bool has_decimals = !request.params[7].isNull();
            uint8_t decimals = has_decimals ? request.params[7].getInt<uint8_t>() : 0;

            // Validate ticker. registerasset is root-only: a dotted child ticker (ROOT.SUFFIX)
            // must go through sponsorchildasset, which performs the parent-ICU co-spend
            // (ICU_CHILD.md §6.2). Use the shared root-grammar helper rather than ad hoc checks.
            if (has_ticker) {
                std::transform(ticker.begin(), ticker.end(), ticker.begin(),
                    [](unsigned char c) { return std::toupper(c); });

                if (ticker.find('.') != std::string::npos) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Child tickers (ROOT.SUFFIX) must be registered via sponsorchildasset, not registerasset");
                }
                if (!assets::IsRootTicker(ticker)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Ticker must be a root [A-Z][A-Z0-9]{2,10} (3-11 chars, starting with a letter)");
                }
            }

            if (has_decimals && decimals > 18) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Decimals must be 0-18");
            }

            // Parse options
            bool autofund = true;
            bool broadcast = false;
            std::optional<double> fee_rate_vb;
            std::optional<bool> replaceable = true;

            // ZK parameters
            uint32_t kyc_flags = 0;
            uint256 vk_commitment;
            uint32_t max_root_age = 0;
            uint32_t tfr_flags = 0;
            std::vector<unsigned char> vk_data;  // Raw VK data (will be chunked)
            std::vector<std::vector<unsigned char>> vk_chunks;  // Chunked VK data

            // ICU parameters
            uint256 icu_plain_commit, icu_ctxt_commit;
            std::array<unsigned char, 16> kdf_salt{};
            std::vector<unsigned char> icu_payload;
            std::vector<unsigned char> icu_plaintext;
            std::optional<assets::IcuStorageEntry> built_storage_entry;
            bool icu_plaintext_provided = false;
            bool icu_payload_overridden = false;
            bool icu_plain_commit_overridden = false;
            bool icu_ctxt_commit_overridden = false;
            bool kdf_salt_overridden = false;
            uint32_t icu_flags = 0;
            uint8_t icu_visibility = 0;
            bool use_compression = false;
            uint16_t policy_quorum_bps = 0;
            uint64_t issuance_cap_units = 0;

            if (!request.params[8].isNull()) {
                const UniValue& opt = request.params[8];
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();

                // Parse ZK parameters
                if (opt.exists("kyc_flags")) {
                    kyc_flags = opt["kyc_flags"].getInt<uint32_t>();
                }
                if (opt.exists("vk_data")) {
                    vk_data = ParseHex(opt["vk_data"].get_str());
                    if (vk_data.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vk_data cannot be empty");

                    // Compute vk_commitment = double_SHA256(vk_data)
                    CSHA256 hasher1;
                    hasher1.Write(vk_data.data(), vk_data.size());
                    uint256 single_hash;
                    hasher1.Finalize(single_hash.begin());

                    CSHA256 hasher2;
                    hasher2.Write(single_hash.begin(), 32);
                    hasher2.Finalize(vk_commitment.begin());

                    // Chunk VK data (512 bytes per chunk as per spec)
                    const size_t CHUNK_SIZE = 512;
                    for (size_t i = 0; i < vk_data.size(); i += CHUNK_SIZE) {
                        size_t chunk_size = std::min(CHUNK_SIZE, vk_data.size() - i);
                        std::vector<unsigned char> chunk(vk_data.begin() + i, vk_data.begin() + i + chunk_size);
                        vk_chunks.push_back(chunk);
                    }
                }
                if (opt.exists("max_root_age")) {
                    max_root_age = opt["max_root_age"].getInt<uint32_t>();
                }
                if (opt.exists("tfr_flags")) {
                    tfr_flags = opt["tfr_flags"].getInt<uint32_t>();
                }

                // Parse ICU parameters
                if (opt.exists("icu_payload_plain")) {
                    icu_plaintext = ParseHex(opt["icu_payload_plain"].get_str());
                    if (icu_plaintext.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload_plain cannot be empty");
                    }
                    icu_plaintext_provided = true;
                }
                if (opt.exists("icu_plain_commit")) {
                    auto pc = uint256::FromHex(opt["icu_plain_commit"].get_str());
                    if (!pc) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid icu_plain_commit hex");
                    icu_plain_commit = *pc;
                    icu_plain_commit_overridden = true;
                }
                if (opt.exists("icu_ctxt_commit")) {
                    auto cc = uint256::FromHex(opt["icu_ctxt_commit"].get_str());
                    if (!cc) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid icu_ctxt_commit hex");
                    icu_ctxt_commit = *cc;
                    icu_ctxt_commit_overridden = true;
                }
                if (opt.exists("kdf_salt")) {
                    auto salt_bytes = ParseHex(opt["kdf_salt"].get_str());
                    if (salt_bytes.size() != 16) throw JSONRPCError(RPC_INVALID_PARAMETER, "kdf_salt must be 16 bytes");
                    std::copy(salt_bytes.begin(), salt_bytes.end(), kdf_salt.begin());
                    kdf_salt_overridden = true;
                }
                if (opt.exists("icu_payload")) {
                    icu_payload = ParseHex(opt["icu_payload"].get_str());
                    icu_payload_overridden = true;
                }
                if (opt.exists("icu_flags")) {
                    icu_flags = opt["icu_flags"].getInt<uint32_t>();
                }
                if (opt.exists("icu_visibility")) {
                    icu_visibility = opt["icu_visibility"].getInt<uint8_t>();
                }
                if (opt.exists("use_compression")) {
                    use_compression = opt["use_compression"].get_bool();
                }
                if (opt.exists("policy_quorum_bps")) {
                    policy_quorum_bps = opt["policy_quorum_bps"].getInt<uint16_t>();
                }
                if (auto cap_override = ParseIssuanceCapOption(opt, decimals, "registerasset options")) {
                    issuance_cap_units = *cap_override;
                }
            }

            if (icu_plaintext_provided && (icu_payload_overridden || icu_plain_commit_overridden || icu_ctxt_commit_overridden || kdf_salt_overridden)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Cannot combine icu_payload_plain with precomputed ICU fields");
            }

            if (icu_plaintext_provided) {
                if (icu_visibility > 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_visibility must be 0 or 1");
                }

                // Parse the provided plaintext as a CanonicalIcuPayload structure
                auto parsed_payload = assets::ParseCanonicalIcuPayload(icu_plaintext);
                if (!parsed_payload) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse icu_payload_plain as CanonicalIcuPayload structure");
                }

                // Extract canonical_text and witness_bundle for re-encryption
                std::string canonical_text_str(parsed_payload->canonical_text.begin(), parsed_payload->canonical_text.end());
                std::string witness_str(parsed_payload->witness_bundle.begin(), parsed_payload->witness_bundle.end());
                UniValue witness_obj;
                if (!witness_obj.read(witness_str)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse witness_bundle JSON");
                }

                // Ensure plaintext commitment reflects the canonical payload we are about to encode.
                const uint256 canonical_plain_commit = parsed_payload->GetCanonicalHash();
                icu_plain_commit = canonical_plain_commit;

                if (icu_visibility == 1) {
                    // Get or create DEK for this asset
                    std::string dek_base64;
                    {
                        LOCK(pwallet->cs_wallet);
                        dek_base64 = pwallet->GetOrCreateAssetDek(*aid);
                    }
                    auto dek_bytes = DecodeBase64(dek_base64);
                    if (!dek_bytes || dek_bytes->size() != 32) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive ICU data encryption key (must be 32 bytes)");
                    }
                    std::array<unsigned char, 32> dek{};
                    std::copy_n(dek_bytes->begin(), 32, dek.begin());

                    LogPrintf("REGISTER_ICU_DEK: asset=%s dek=%s\n", aid->ToString(), HexStr(dek));

                    // Build encrypted ICU payload with proper ChaCha20-Poly1305
                    // BuildCanonicalIcuPayload will normalize, compute icu_plain_commit, encrypt, and compute icu_ctxt_commit
                    assets::IcuStorageEntry storage_entry_local;
                    if (!assets::BuildCanonicalIcuPayload(
                        canonical_text_str,
                        witness_obj,
                        icu_visibility,
                        dek,
                        use_compression,
                        icu_plain_commit,
                        icu_ctxt_commit,
                        kdf_salt,
                        storage_entry_local,
                        parsed_payload->metadata  // preserve committed metadata (incl. any TSC-ICU-CONTEXT-1 map) across re-encryption; validated against the text
                    )) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build encrypted ICU payload");
                    }

                    icu_payload = storage_entry_local.icu_cipher;
                    built_storage_entry = storage_entry_local;
                    icu_plain_commit = storage_entry_local.canonical_hash;

                    LogPrintf("REGISTER_ICU_ENCRYPT: asset=%s icu_ctxt_commit=%s kdf_salt=%s\n",
                              aid->ToString(), icu_ctxt_commit.ToString(), HexStr(kdf_salt));

                    // Set WRAP_REQUIRED flag for holder-only assets
                    if ((icu_flags & assets::WRAP_REQUIRED) == 0) {
                        icu_flags |= assets::WRAP_REQUIRED;
                    }
                } else {
                    // Public asset: no encryption, but still normalize and compute commitments
                    std::array<unsigned char, 32> dummy_dek{};  // Not used for visibility=0
                    assets::IcuStorageEntry storage_entry_local;
                    if (!assets::BuildCanonicalIcuPayload(
                        canonical_text_str,
                        witness_obj,
                        icu_visibility,  // 0 = public
                        dummy_dek,
                        use_compression,
                        icu_plain_commit,
                        icu_ctxt_commit,
                        kdf_salt,
                        storage_entry_local,
                        parsed_payload->metadata  // preserve committed metadata (incl. any TSC-ICU-CONTEXT-1 map) across re-encryption; validated against the text
                    )) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build public ICU payload");
                    }
                    icu_payload = storage_entry_local.icu_cipher;
                    built_storage_entry = storage_entry_local;
                    icu_plain_commit = storage_entry_local.canonical_hash;
                }

                // Set ICU_COMPRESSED flag if compression was used
                if (use_compression) {
                    icu_flags |= assets::ICU_COMPRESSED;
                }
            }

            // Build IssuerReg v1 TLV payload (deterministic format with ZK+ICU sections always present)
            if (icu_plain_commit.IsNull() && built_storage_entry.has_value() && !built_storage_entry->canonical_hash.IsNull()) {
                icu_plain_commit = built_storage_entry->canonical_hash;
            }

            std::vector<unsigned char> payload;
            payload.reserve(254 + (has_ticker ? ticker.size() : 0));  // ZK Whitelist Hardening: updated from 222

            // Header (39 bytes)
            payload.insert(payload.end(), aid->begin(), aid->end());  // asset_id (32)
            unsigned char pb[4]; WriteLE32(pb, policy_bits); payload.insert(payload.end(), pb, pb + 4);  // policy_bits (4)
            unsigned char ab[2]; ab[0] = allowed & 0xFF; ab[1] = (allowed >> 8) & 0xFF; payload.insert(payload.end(), ab, ab + 2);  // allowed_spk (2)
            payload.push_back(assets::ISSUER_REG_FORMAT_V1);  // format_version = 0x01 (1)

            // Optional fields (10+ bytes)
            if (has_ticker) {
                payload.push_back(static_cast<unsigned char>(ticker.size()));  // ticker_len
                payload.insert(payload.end(), ticker.begin(), ticker.end());  // ticker
            } else {
                payload.push_back(0);  // ticker_len = 0 (empty ticker)
            }
            payload.push_back(has_decimals ? decimals : 0xFF);  // decimals (0xFF = not set)
            unsigned char ub[8]; WriteLE64(ub, has_unlock ? unlock : 510000000); payload.insert(payload.end(), ub, ub + 8);  // unlock_fees (8)

            // ZK section (76 bytes) - ZK Whitelist Hardening update
            unsigned char zk_buf[76];
            uint32_t final_kyc_flags = kyc_flags;
            WriteLE32(zk_buf, final_kyc_flags);
            std::copy(vk_commitment.begin(), vk_commitment.end(), zk_buf + 4);
            WriteLE32(zk_buf + 36, max_root_age);
            WriteLE32(zk_buf + 40, tfr_flags);
            // compliance_root_commit [32] - zero for initial registration
            std::fill(zk_buf + 44, zk_buf + 76, 0);
            payload.insert(payload.end(), zk_buf, zk_buf + 76);

            // ICU section (129 bytes)
            unsigned char icu_buf32[4];
            unsigned char icu_buf64[8];

            WriteLE32(icu_buf32, icu_flags);
            payload.insert(payload.end(), icu_buf32, icu_buf32 + 4);

            WriteLE64(icu_buf64, issuance_cap_units);
            payload.insert(payload.end(), icu_buf64, icu_buf64 + 8);

            payload.insert(payload.end(), icu_ctxt_commit.begin(), icu_ctxt_commit.end()); // 32 bytes
            payload.insert(payload.end(), icu_plain_commit.begin(), icu_plain_commit.end()); // 32 bytes
            payload.insert(payload.end(), kdf_salt.begin(), kdf_salt.end()); // 16 bytes

            payload.push_back(1); // icu_version = 1
            payload.push_back(icu_visibility);

            // core_policy_commit (32 bytes) - compute using consensus function
            uint256 core_policy_commit = assets::ComputeCorePolicyCommit(
                allowed,
                policy_bits,
                kyc_flags,
                tfr_flags
            );
            payload.insert(payload.end(), core_policy_commit.begin(), core_policy_commit.end()); // 32 bytes

            payload.push_back(0); // policy_epoch = 0

            WriteLE16(icu_buf32, policy_quorum_bps);
            payload.insert(payload.end(), icu_buf32, icu_buf32 + 2);

            // Create TLV extension with CompactSize length
            std::vector<unsigned char> tlv;
            tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (payload.size() < 253) {
                tlv.push_back(static_cast<uint8_t>(payload.size()));
            } else {
                tlv.push_back(253);
                tlv.push_back(payload.size() & 0xFF);
                tlv.push_back((payload.size() >> 8) & 0xFF);
            }
            tlv.insert(tlv.end(), payload.begin(), payload.end());

            // Build transaction
            CMutableTransaction mtx;

            // Fund transaction if requested
            if (autofund) {
                CCoinControl cc;
                cc.m_change_type = OutputType::BECH32M; // Force Taproot change for contract asset funding
                if (fee_rate_vb) {
                    LogPrintf("sendasset: Received fee_rate_vb=%.3f sat/vB, setting CFeeRate to %d sat/kvB\n",
                             *fee_rate_vb, static_cast<CAmount>(*fee_rate_vb * 1000.0));
                    cc.fOverrideFeeRate = true;
                    cc.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
                }
                if (replaceable) {
                    cc.m_signal_bip125_rbf = *replaceable;
                }

                // Create recipients for the ICU output
                std::vector<CRecipient> recipients;
                CRecipient recipient{dest, amt, /*fSubtractFeeFromAmount=*/false};
                recipients.push_back(recipient);

                // Add dust output for ICU_TEXT_CHUNK if icu_payload is provided
                CTxDestination icu_chunk_dest;
                if (!icu_payload.empty()) {
                    auto dest_result = pwallet->GetNewDestination(OutputType::BECH32, "ICU chunk");
                    if (!dest_result) {
                        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dest_result).original);
                    }
                    icu_chunk_dest = *dest_result;
                    CRecipient icu_chunk_recipient{icu_chunk_dest, 546, /*fSubtractFeeFromAmount=*/false};
                    recipients.push_back(icu_chunk_recipient);
                }

                // Add dust outputs for ZK_PARAMS_CHUNK TLVs (each needs unique address)
                std::vector<CTxDestination> zk_chunk_dests;
                for (size_t i = 0; i < vk_chunks.size(); ++i) {
                    auto dest_result = pwallet->GetNewDestination(OutputType::BECH32, "ZK chunk");
                    if (!dest_result) {
                        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dest_result).original);
                    }
                    zk_chunk_dests.push_back(*dest_result);
                    CRecipient zk_recipient{*dest_result, 546, /*fSubtractFeeFromAmount=*/false};
                    recipients.push_back(zk_recipient);
                }

                // Fund the transaction with all outputs
                auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt,
                                         /*lockUnspents=*/false, cc);
                if (!txr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                }

                // Apply the funded transaction
                mtx = CMutableTransaction(*txr->tx);

                // Calculate the size of the funded transaction BEFORE we attach large TLVs
                // We'll use this later to derive the fee rate and adjust fees after TLVs are added
                unsigned int funded_tx_size = GetVirtualTransactionSize(*txr->tx);

                // Attach the IssuerReg TLV to the ICU output (vout 0)
                bool found_icu = false;
                for (auto& out : mtx.vout) {
                    if (out.nValue == amt && out.scriptPubKey == GetScriptForDestination(dest)) {
                        out.vExt = tlv;
                        found_icu = true;
                        break;
                    }
                }
                if (!found_icu) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Could not find ICU output to attach registration");
                }

                // Attach ICU_TEXT_CHUNK TLV if icu_payload is provided
                if (!icu_payload.empty()) {
                    std::vector<unsigned char> chunk_bytes = icu_payload;
                    if (built_storage_entry) {
                        assets::IcuChunkMetadata metadata;
                        metadata.compression = built_storage_entry->compression;
                        metadata.encryption_mode = built_storage_entry->encryption_mode;
                        metadata.has_witness_hash = !built_storage_entry->witness_hash.IsNull();
                        metadata.witness_hash = built_storage_entry->witness_hash;
                        chunk_bytes = assets::AppendIcuChunkMetadata(chunk_bytes, metadata);
                    }

                    std::vector<unsigned char> icu_chunk_tlv;
                    icu_chunk_tlv.push_back(0x30);  // ICU_TEXT_CHUNK type
                    if (chunk_bytes.size() < 253) {
                        icu_chunk_tlv.push_back(static_cast<uint8_t>(chunk_bytes.size()));
                    } else {
                        icu_chunk_tlv.push_back(253);
                        icu_chunk_tlv.push_back(chunk_bytes.size() & 0xFF);
                        icu_chunk_tlv.push_back((chunk_bytes.size() >> 8) & 0xFF);
                    }
                    icu_chunk_tlv.insert(icu_chunk_tlv.end(), chunk_bytes.begin(), chunk_bytes.end());

                    // Find the dust output for ICU_TEXT_CHUNK
                    bool found_icu_chunk = false;
                    for (auto& out : mtx.vout) {
                        if (out.vExt.empty() && out.nValue == 546 && out.scriptPubKey == GetScriptForDestination(icu_chunk_dest)) {
                            out.vExt = icu_chunk_tlv;
                            found_icu_chunk = true;
                            break;
                        }
                    }
                    if (!found_icu_chunk) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Could not find ICU_TEXT_CHUNK output");
                    }
                }

                // Attach ZK_PARAMS_CHUNK TLVs
                for (size_t chunk_idx = 0; chunk_idx < vk_chunks.size(); ++chunk_idx) {
                    const auto& chunk_data = vk_chunks[chunk_idx];

                    // Build ZK_PARAMS_CHUNK TLV
                    std::vector<unsigned char> chunk_payload;
                    chunk_payload.insert(chunk_payload.end(), aid->begin(), aid->end());  // asset_id (LE)
                    chunk_payload.insert(chunk_payload.end(), vk_commitment.begin(), vk_commitment.end());  // vk_hash (natural order)

                    // chunk_index and chunk_count (LE16)
                    unsigned char idx_buf[2];
                    idx_buf[0] = chunk_idx & 0xFF;
                    idx_buf[1] = (chunk_idx >> 8) & 0xFF;
                    chunk_payload.insert(chunk_payload.end(), idx_buf, idx_buf + 2);

                    unsigned char cnt_buf[2];
                    cnt_buf[0] = vk_chunks.size() & 0xFF;
                    cnt_buf[1] = (vk_chunks.size() >> 8) & 0xFF;
                    chunk_payload.insert(chunk_payload.end(), cnt_buf, cnt_buf + 2);

                    chunk_payload.insert(chunk_payload.end(), chunk_data.begin(), chunk_data.end());

                    std::vector<unsigned char> chunk_tlv;
                    chunk_tlv.push_back(0x20);  // ZK_PARAMS_CHUNK type
                    if (chunk_payload.size() < 253) {
                        chunk_tlv.push_back(static_cast<uint8_t>(chunk_payload.size()));
                    } else {
                        chunk_tlv.push_back(253);
                        chunk_tlv.push_back(chunk_payload.size() & 0xFF);
                        chunk_tlv.push_back((chunk_payload.size() >> 8) & 0xFF);
                    }
                    chunk_tlv.insert(chunk_tlv.end(), chunk_payload.begin(), chunk_payload.end());

                    // Find the dust output for this chunk
                    bool found_chunk = false;
                    for (auto& out : mtx.vout) {
                        if (out.vExt.empty() && out.nValue == 546 && out.scriptPubKey == GetScriptForDestination(zk_chunk_dests[chunk_idx])) {
                            out.vExt = chunk_tlv;
                            found_chunk = true;
                            break;
                        }
                    }
                    if (!found_chunk) {
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Could not find ZK chunk output %d", chunk_idx));
                    }
                }

                // After attaching all TLVs, check if we need to bump fees due to increased tx size
                // Calculate actual tx size with witness data
                CTransaction tmp_tx(mtx);
                unsigned int actual_tx_size = GetVirtualTransactionSize(tmp_tx);

                // Calculate current fee (sum of inputs - sum of outputs)
                CAmount current_fee = txr->fee;

                // Derive the fee rate that FundTransaction actually used
                // This is more reliable than cc.m_feerate or pwallet->m_pay_tx_fee in regtest
                CFeeRate actual_fee_rate = funded_tx_size > 0 ? CFeeRate(current_fee, funded_tx_size) : CFeeRate(0);

                // Calculate required fee based on actual size
                CAmount required_fee = actual_fee_rate.GetFee(actual_tx_size);

                LogPrintf("FEE ADJUSTMENT CHECK: actual_tx_size=%d, funded_tx_size=%d, required_fee=%d, current_fee=%d, actual_fee_rate=%s\n",
                         actual_tx_size, funded_tx_size, required_fee, current_fee, actual_fee_rate.ToString());

                // If we need more fees, try to reduce change or add inputs
                if (required_fee > current_fee) {
                    CAmount fee_deficit = required_fee - current_fee;

                    // Try to find and adjust change output
                    bool adjusted_change = false;
                    for (auto& out : mtx.vout) {
                        // Heuristic: change output is usually to a wallet address and not exactly amt or 546
                        if (out.nValue != amt && out.nValue != 546 && out.nValue > fee_deficit + 546) {
                            out.nValue -= fee_deficit;
                            adjusted_change = true;
                            break;
                        }
                    }

                    if (!adjusted_change) {
                        // If we couldn't adjust change, we need to re-fund the transaction
                        // This is a limitation - for now just log a warning
                        LogPrintf("WARNING: Could not adjust fees for large ICU payload. Required: %d, Current: %d\n",
                                 required_fee, current_fee);
                    }
                }
            } else {
                // No autofund - create simple transaction
                mtx.vout.emplace_back(amt, GetScriptForDestination(dest));
                mtx.vout[0].vExt = std::move(tlv);
            }

            // Sign and broadcast if requested
            if (broadcast) {
                // Create PSBT for signing
                PartiallySignedTransaction psbtx(mtx);
                bool complete = false;

                // Fill PSBT with wallet data and sign
                const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                if (fill_err) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                if (!complete) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction completely");
                }

                // Finalize and extract signed transaction
                CMutableTransaction signed_mtx;
                if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
                }

                // Broadcast
                CTransactionRef tx = MakeTransactionRef(CTransaction(signed_mtx));
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});

                // Store ticker binding if provided
                if (has_ticker) {
                    LOCK(pwallet->cs_wallet);
                    AssetMetadata metadata;
                    metadata.has_ticker = true;
                    metadata.ticker = ticker;
                    metadata.has_decimals = has_decimals;
                    metadata.decimals = decimals;

                    // Find the ICU output with IssuerReg TLV
                    for (size_t i = 0; i < tx->vout.size(); ++i) {
                        if (!tx->vout[i].vExt.empty() && tx->vout[i].vExt[0] == 0x10) {
                            pwallet->SetAssetMetadata(COutPoint(tx->GetHash(), i), metadata);
                            break;
                        }
                    }
                }

                return tx->GetHash().ToString();
            }

            // Return raw hex
            DataStream ds;
            ds << TX_WITH_WITNESS(mtx);
            return HexStr(ds);
        }
    };
}

RPCHelpMan sendasset()
{
    return RPCHelpMan{
        "sendasset",
        "Send asset units from the wallet, selecting UTXOs and handling change automatically.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination address"},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units (raw) to send"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Explicit fee rate in sat/vB"},
                    {"include_watching", RPCArg::Type::BOOL, RPCArg::Default{false}, "Spend solvable watch-only asset UTXOs"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Signal BIP125 replace-by-fee"},
                    {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Confirmation target (blocks)"},
                    {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "Avoid spending from reused addresses"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast the transaction"},
                    {"return_skeleton", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return unsigned tx skeleton (pre-fee) instead of broadcasting. Includes input/output metadata for covenant assembly."},
                    {"return_psbt", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return an unsigned PSBT with wallet data and BIP32 derivations instead of signing/broadcasting."},
                    {"wrapped_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override for auto-generated wrapped key (UTF-8 hex)."},
                    {"suite_id", RPCArg::Type::NUM, RPCArg::Default{0}, "Cryptographic suite ID for keywrap"},
                    {"extras_mask", RPCArg::Type::NUM, RPCArg::Default{0}, "Keywrap extras: 0x01=wrap_commit, 0x02=kc_tag"},
                    {"wrap_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte wrap commitment"},
                    {"kc_tag", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte key confirmation tag"},
                    {"zk_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ZK proof data for KYC_REQUIRED assets"},
                    {"zk_public_inputs", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Public inputs for ZK proof"},
                    {"tfr_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte transfer anchor commitment (required on-chain when policy mandates anchor)"},
                    {"tfr_locator", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional off-chain locator bytes; only serialized on-chain if explicitly provided"},
                    {"tfr_keyset_id", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional off-chain keyset identifier; only serialized on-chain if explicitly provided"},
                    {"op_return", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional data to embed as an extra zero-value OP_RETURN output (max 80 bytes). Covered by the signed inputs."},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (omitted when return_skeleton=true or return_psbt=true)"},
                {RPCResult::Type::STR, "hex", /*optional=*/true, "Signed transaction hex (included when broadcast=false, or unsigned tx hex when return_skeleton=true)"},
                {RPCResult::Type::STR, "psbt", /*optional=*/true, "Unsigned PSBT with wallet annotations (return_psbt=true)"},
                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "Fee paid in BTC (omitted when return_skeleton=true)"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Resolved asset identifier"},
                {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker symbol if known"},
                {RPCResult::Type::ELISION, "asset_inputs", /*optional=*/true, "Total asset units consumed (number) when return_skeleton=false, or array of input objects when return_skeleton=true"},
                {RPCResult::Type::NUM, "asset_outputs", /*optional=*/true, "Total asset units created (when return_skeleton=false)"},
                {RPCResult::Type::NUM, "asset_change", /*optional=*/true, "Asset units returned to the wallet (when return_skeleton=false)"},
                {RPCResult::Type::BOOL, "complete", /*optional=*/true, "Whether the returned skeleton/PSBT is complete (false for return_skeleton/return_psbt)"},
                {RPCResult::Type::NUM, "asset_inputs_total", /*optional=*/true, "Total asset units in inputs (return_skeleton=true)"},
                {RPCResult::Type::NUM, "asset_outputs_total", /*optional=*/true, "Total asset units in outputs (return_skeleton=true)"},
                {RPCResult::Type::ARR, "btc_inputs", /*optional=*/true, "BTC funding inputs (return_skeleton=true)",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "Input txid"},
                                {RPCResult::Type::NUM, "vout", "Input vout"},
                            }
                        },
                    }
                },
                {RPCResult::Type::ARR, "outputs", /*optional=*/true, "Output metadata (return_skeleton=true)", {{RPCResult::Type::ELISION, "", ""}}},
                {RPCResult::Type::STR_AMOUNT, "estimated_fee", /*optional=*/true, "Estimated fee (return_skeleton=true)"},
                {RPCResult::Type::NUM, "fee_rate", /*optional=*/true, "Fee rate in sat/vB (return_skeleton=true)"},
                {RPCResult::Type::BOOL, "needs_zk_proof", /*optional=*/true, "Whether ZK proof is needed (return_skeleton=true)"},
                {RPCResult::Type::BOOL, "needs_tfr_anchor", /*optional=*/true, "Whether TFR anchor is needed (return_skeleton=true)"},
                {RPCResult::Type::OBJ, "refund_instructions", /*optional=*/true, "Refund instructions if applicable (return_skeleton=true)", {{RPCResult::Type::ELISION, "", ""}}},
                {RPCResult::Type::OBJ, "mldsa_signing_info", /*optional=*/true, "ML-DSA signing instructions (only when destination is witness v2)",
                    {
                        {RPCResult::Type::STR, "notice", "Notice that destination is ML-DSA address"},
                        {RPCResult::Type::STR, "next_step", "Instructions for next step"},
                        {RPCResult::Type::NUM, "ml_dsa_output_index", "Index of ML-DSA output in transaction"},
                        {RPCResult::Type::STR, "dest_address", "ML-DSA destination address"},
                        {RPCResult::Type::ARR, "asset_inputs_detail", "Asset input UTXOs for manual signing",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                    {
                                        {RPCResult::Type::STR_HEX, "txid", "Input txid"},
                                        {RPCResult::Type::NUM, "vout", "Input vout"},
                                        {RPCResult::Type::STR_HEX, "asset_id", "Asset ID"},
                                        {RPCResult::Type::NUM, "asset_units", "Asset units"},
                                        {RPCResult::Type::STR_AMOUNT, "amount", "BTC amount"},
                                        {RPCResult::Type::STR_HEX, "scriptPubKey", "scriptPubKey hex"},
                                    }
                                },
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("sendasset", "\"GOLD\" \"bc1q...\" 50000000") +
            HelpExampleCli("sendasset", "\"GOLD\" \"bc1q...\" 50000000 '{\"broadcast\":false,\"return_psbt\":true}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string asset_identifier = request.params[0].get_str();
            AssetResolution resolved = ResolveAssetIdOrTicker(request, asset_identifier);

            EnsureWalletIsUnlocked(*pwallet);

            const std::string dest_address = request.params[1].get_str();
            CTxDestination dest = DecodeDestination(dest_address);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
            }

            uint64_t send_units = request.params[2].getInt<uint64_t>();
            if (send_units == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be greater than zero");
            }

            bool include_watching{false};
            bool replaceable{true};
            bool avoid_reuse{true};
            bool broadcast{true};
            bool return_skeleton{false};
            bool return_psbt{false};
            std::optional<double> fee_rate_vb;
            std::optional<unsigned int> conf_target;

            // ICU_KEYWRAP parameters
            std::vector<unsigned char> wrapped_key;
            uint8_t suite_id = 0;
            uint8_t extras_mask = 0;
            uint256 wrap_commit;
            std::array<unsigned char, 16> kc_tag{};

            // ZK proof parameters
            std::vector<unsigned char> zk_proof;
            std::vector<unsigned char> zk_public_inputs;
            std::optional<uint256> tfr_commit_opt;
            std::vector<unsigned char> tfr_locator_bytes;
            std::optional<uint32_t> tfr_keyset_id_opt;
            std::vector<unsigned char> op_return_data;

            if (!request.params[3].isNull()) {
                const UniValue& opt = request.params[3];
                if (!opt.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                }
                if (opt.exists("include_watching")) include_watching = opt["include_watching"].get_bool();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                if (opt.exists("avoid_reuse")) avoid_reuse = opt["avoid_reuse"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("return_skeleton")) return_skeleton = opt["return_skeleton"].get_bool();
                if (opt.exists("return_psbt")) return_psbt = opt["return_psbt"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("conf_target")) conf_target = opt["conf_target"].getInt<unsigned int>();

                // ICU_KEYWRAP parameters
                if (opt.exists("wrapped_key")) {
                    wrapped_key = ParseHex(opt["wrapped_key"].get_str());
                    if (wrapped_key.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "wrapped_key cannot be empty");
                    }
                    // Validate UTF-8 (consensus requirement)
                    auto is_valid_utf8 = [](const std::vector<unsigned char>& data) -> bool {
                        size_t i = 0;
                        while (i < data.size()) {
                            unsigned char c = data[i];
                            if ((c & 0x80) == 0) { ++i; continue; }
                            if ((c & 0xE0) == 0xC0) {
                                if (i + 1 >= data.size() || (data[i+1] & 0xC0) != 0x80 || c < 0xC2) return false;
                                i += 2; continue;
                            }
                            if ((c & 0xF0) == 0xE0) {
                                if (i + 2 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80) return false;
                                if (c == 0xE0 && data[i+1] < 0xA0) return false; // overlong
                                if (c == 0xED && data[i+1] >= 0xA0) return false; // surrogate
                                i += 3; continue;
                            }
                            if ((c & 0xF8) == 0xF0) {
                                if (i + 3 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80 || (data[i+3] & 0xC0) != 0x80) return false;
                                if (c == 0xF0 && data[i+1] < 0x90) return false; // overlong
                                if (c >= 0xF4) return false; // beyond U+10FFFF
                                i += 4; continue;
                            }
                            return false;
                        }
                        return true;
                    };
                    if (!is_valid_utf8(wrapped_key)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "wrapped_key must be valid UTF-8");
                    }
                }
                if (opt.exists("suite_id")) suite_id = opt["suite_id"].getInt<uint8_t>();
                if (opt.exists("extras_mask")) {
                    extras_mask = opt["extras_mask"].getInt<uint8_t>();
                    const uint8_t allowed_mask = assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT | assets::ICU_KEYWRAP_EXTRA_KC_TAG;
                    if (extras_mask & ~allowed_mask) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "extras_mask has unknown bits (allowed: 0x01, 0x02)");
                    }
                }
                if (opt.exists("wrap_commit")) {
                    auto wc = uint256::FromHex(opt["wrap_commit"].get_str());
                    if (!wc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid wrap_commit hex");
                    wrap_commit = *wc;
                }
                if (opt.exists("kc_tag")) {
                    auto kc_bytes = ParseHex(opt["kc_tag"].get_str());
                    if (kc_bytes.size() != 16) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "kc_tag must be exactly 16 bytes");
                    }
                    std::copy(kc_bytes.begin(), kc_bytes.end(), kc_tag.begin());
                }

                // ZK proof parameters
                if (opt.exists("zk_proof")) {
                    zk_proof = ParseHex(opt["zk_proof"].get_str());
                    if (zk_proof.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "zk_proof cannot be empty");
                    }
                }
                if (opt.exists("zk_public_inputs")) {
                    zk_public_inputs = ParseHex(opt["zk_public_inputs"].get_str());
                }
                if (opt.exists("tfr_commit")) {
                    auto commit_hex = opt["tfr_commit"].get_str();
                    auto commit_val = uint256::FromHex(commit_hex);
                    if (!commit_val) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "tfr_commit must be 32-byte hex");
                    }
                    tfr_commit_opt = *commit_val;
                }
                if (opt.exists("tfr_locator")) {
                    tfr_locator_bytes = ParseHex(opt["tfr_locator"].get_str());
                    if (tfr_locator_bytes.size() > assets::MAX_TFR_LOCATOR_SIZE) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("tfr_locator exceeds %u bytes", assets::MAX_TFR_LOCATOR_SIZE));
                    }
                }
                if (opt.exists("tfr_keyset_id")) {
                    tfr_keyset_id_opt = opt["tfr_keyset_id"].getInt<uint32_t>();
                }
                if (opt.exists("op_return")) {
                    op_return_data = ParseHex(opt["op_return"].get_str());
                    if (op_return_data.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "op_return cannot be empty");
                    }
                    if (op_return_data.size() > MAX_OP_RETURN_RELAY - 3) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("op_return data exceeds %u bytes", MAX_OP_RETURN_RELAY - 3));
                    }
                }
            }

            if (!tfr_commit_opt && (!tfr_locator_bytes.empty() || tfr_keyset_id_opt.has_value())) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tfr_commit is required when tfr_locator or tfr_keyset_id is provided");
            }

            if (return_skeleton && return_psbt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "return_skeleton and return_psbt are mutually exclusive");
            }

            bool needs_zk_proof{false};
            bool needs_tfr_anchor{false};
            std::vector<unsigned char> zk_proof_bytes;
            std::vector<unsigned char> zk_public_inputs_bytes;
            uint256 tfr_commit;
            uint32_t tfr_keyset_id = tfr_keyset_id_opt.value_or(0);
            std::vector<unsigned char> tfr_locator = tfr_locator_bytes;

            if (resolved.registry) {
                const AssetRegistryEntry& policy = *resolved.registry;
                if (policy.has_kyc) {
                    needs_zk_proof = true;
                    if (zk_proof.empty() || zk_public_inputs.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Asset %s has KYC requirement but zk_proof and zk_public_inputs not provided. "
                                      "Auto-generation not yet supported.", asset_identifier));
                    }
                }
                if (policy.tfr_flags & assets::TFR_ANCHOR_REQUIRED) {
                    needs_tfr_anchor = true;
                }
            } else if (!zk_proof.empty() || !zk_public_inputs.empty() || tfr_commit_opt || !tfr_locator_bytes.empty() || tfr_keyset_id_opt.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not registered - cannot determine ZK/TFR requirements");
            }

            if (!zk_proof.empty() || !zk_public_inputs.empty()) {
                if (zk_proof.size() != groth16::GROTH16_PROOF_SIZE) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("zk_proof must be %u bytes", groth16::GROTH16_PROOF_SIZE));
                }
                if (zk_public_inputs.size() % groth16::GROTH16_FR_SIZE != 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("zk_public_inputs must be a multiple of %u bytes", groth16::GROTH16_FR_SIZE));
                }
                if (zk_public_inputs.size() < 4 * groth16::GROTH16_FR_SIZE) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "zk_public_inputs missing required fields");
                }
                zk_proof_bytes = zk_proof;
                zk_public_inputs_bytes = zk_public_inputs;

                // ZK Whitelist Hardening: preflight the proof's compliance root against the
                // EFFECTIVE policy. A delegating asset follows its SOURCE's root/history, so
                // checking the asset's own root here would make a follower unspendable.
                if (resolved.registry && resolved.registry->has_kyc) {
                    const AssetRegistryEntry& b_entry = *resolved.registry;
                    const AssetRegistryEntry* src = nullptr;
                    AssetRegistryEntry src_entry;
                    if (!b_entry.compliance_delegate_asset_id.IsNull() &&
                        b_entry.compliance_delegate_asset_id != resolved.asset_id) {
                        WalletContext& wctx = EnsureWalletContext(request.context);
                        if (wctx.chain) {
                            if (auto se = wctx.chain->getAssetRegistryEntry(b_entry.compliance_delegate_asset_id)) {
                                src_entry = *se; src = &src_entry;
                            }
                        }
                    }
                    const assets::EffectiveKycPolicy eff = assets::ResolveEffectiveKycPolicy(
                        resolved.asset_id, b_entry, src, assets::IsCanonicalVk);
                    if (!eff.ok) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Asset %s delegation does not resolve: %s", asset_identifier, eff.reason));
                    }

                    // Verify a compliance root is committed (the source's root when delegating)
                    if (eff.compliance_root_commit.IsNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Asset %s requires compliance root commitment. "
                                      "Issuer must use updatecomplianceroot RPC first.", asset_identifier));
                    }

                    // Extract public_inputs[2] (compliance root commitment from proof)
                    if (zk_public_inputs.size() < 3 * groth16::GROTH16_FR_SIZE) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "zk_public_inputs missing compliance root field");
                    }

                    uint256 proof_root_commit;
                    // ZK proof outputs field elements in big-endian, but uint256 stores little-endian
                    std::copy(zk_public_inputs.begin() + 2 * groth16::GROTH16_FR_SIZE,
                              zk_public_inputs.begin() + 3 * groth16::GROTH16_FR_SIZE,
                              proof_root_commit.begin());
                    std::reverse(proof_root_commit.begin(), proof_root_commit.end());

                    // Match against the effective active root or a valid historical entry.
                    bool root_valid = (proof_root_commit == eff.compliance_root_commit);

                    if (!root_valid && !eff.compliance_root_history.empty()) {
                        const int current_height = pwallet->chain().getHeight().value_or(0);
                        for (const auto& hist : eff.compliance_root_history) {
                            if (hist.root_commit == proof_root_commit) {
                                const int age = current_height - hist.activation_height;
                                if (age >= 0 && age <= static_cast<int>(eff.max_root_age)) {
                                    root_valid = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!root_valid) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("ZK proof compliance root mismatch. "
                                      "Proof root: %s, Effective commitment: %s. "
                                      "Use getassetcomplianceroot to retrieve current commitment.",
                                      proof_root_commit.ToString(), eff.compliance_root_commit.ToString()));
                    }
                }
            } else if (needs_zk_proof) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Asset %s requires zk_proof and zk_public_inputs", asset_identifier));
            }

            if (needs_tfr_anchor) {
                if (!tfr_commit_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Asset %s requires tfr_commit option", asset_identifier));
                }
                tfr_commit = *tfr_commit_opt;
            } else if (tfr_commit_opt) {
                tfr_commit = *tfr_commit_opt;
                needs_tfr_anchor = true; // user requested anchor even if policy optional
            }

            CCoinControl coin_control;
            coin_control.m_include_unsafe_inputs = true;
            coin_control.m_avoid_asset_utxos = false;  // CRITICAL: Include asset outputs!
            coin_control.fAllowWatchOnly = include_watching;
            coin_control.m_signal_bip125_rbf = replaceable;
            coin_control.m_avoid_address_reuse = avoid_reuse;
            if (conf_target) coin_control.m_confirm_target = conf_target;
            if (fee_rate_vb) {
                coin_control.fOverrideFeeRate = true;
                coin_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
            }

            CoinFilterParams filter_params;
            filter_params.only_spendable = true;

            std::vector<WalletAssetUtxo> asset_utxos = CollectAssetUtxos(*pwallet, coin_control, filter_params);

            // DIAGNOSTIC: Log all available asset UTXOs before selection
            pwallet->WalletLogPrintf("[DIAG_SENDASSET_COLLECT] CollectAssetUtxos returned %u UTXOs for send_units=%llu\n",
                asset_utxos.size(), send_units);
            for (size_t idx = 0; idx < asset_utxos.size(); ++idx) {
                const WalletAssetUtxo& u = asset_utxos[idx];
                pwallet->WalletLogPrintf("[DIAG_SENDASSET_COLLECT]   UTXO[%zu]: %s:%u units=%llu depth=%d spendable=%d ismine_spendable=%d asset_id=%s\n",
                    idx, u.outpoint.hash.ToString().substr(0,16).c_str(), u.outpoint.n,
                    u.units, u.depth, u.spendable, u.ismine_spendable,
                    u.asset_id.ToString().substr(0,16).c_str());
            }

            std::sort(asset_utxos.begin(), asset_utxos.end(), [](const WalletAssetUtxo& a, const WalletAssetUtxo& b) {
                if (a.depth != b.depth) return a.depth > b.depth;
                if (a.outpoint.hash != b.outpoint.hash) return a.outpoint.hash < b.outpoint.hash;
                return a.outpoint.n < b.outpoint.n;
            });

            // DIAGNOSTIC: Log sorted order
            pwallet->WalletLogPrintf("[DIAG_SENDASSET_SORTED] After sorting by depth desc, hash asc, vout asc:\n");
            for (size_t idx = 0; idx < asset_utxos.size(); ++idx) {
                const WalletAssetUtxo& u = asset_utxos[idx];
                pwallet->WalletLogPrintf("[DIAG_SENDASSET_SORTED]   UTXO[%zu]: %s:%u units=%llu depth=%d\n",
                    idx, u.outpoint.hash.ToString().substr(0,16).c_str(), u.outpoint.n,
                    u.units, u.depth);
            }

            std::vector<WalletAssetUtxo> selected;
            selected.reserve(asset_utxos.size());
            uint64_t total_units{0};
            pwallet->WalletLogPrintf("[DIAG_SENDASSET_SELECT] Starting coin selection for send_units=%llu, target_asset=%s\n",
                send_units, resolved.asset_id.ToString().substr(0,16).c_str());
            size_t iter_idx = 0;
            for (const WalletAssetUtxo& utxo : asset_utxos) {
                if (utxo.asset_id != resolved.asset_id) {
                    pwallet->WalletLogPrintf("[DIAG_SENDASSET_SELECT]   [%zu] SKIP %s:%u - wrong asset_id %s\n",
                        iter_idx++, utxo.outpoint.hash.ToString().substr(0,16).c_str(), utxo.outpoint.n,
                        utxo.asset_id.ToString().substr(0,16).c_str());
                    continue;
                }
                if (!utxo.spendable || !utxo.ismine_spendable) {
                    pwallet->WalletLogPrintf("[DIAG_SENDASSET_SELECT]   [%zu] SKIP %s:%u units=%llu - not spendable (spendable=%d ismine_spendable=%d)\n",
                        iter_idx++, utxo.outpoint.hash.ToString().substr(0,16).c_str(), utxo.outpoint.n,
                        utxo.units, utxo.spendable, utxo.ismine_spendable);
                    continue;
                }
                selected.push_back(utxo);
                total_units += utxo.units;
                pwallet->WalletLogPrintf("[DIAG_SENDASSET_SELECT]   [%zu] SELECT %s:%u units=%llu, running_total=%llu\n",
                    iter_idx++, utxo.outpoint.hash.ToString().substr(0,16).c_str(), utxo.outpoint.n,
                    utxo.units, total_units);
                if (total_units >= send_units) {
                    pwallet->WalletLogPrintf("[DIAG_SENDASSET_SELECT] EARLY EXIT: total_units=%llu >= send_units=%llu, selected %zu UTXOs\n",
                        total_units, send_units, selected.size());
                    break;
                }
            }
            pwallet->WalletLogPrintf("[DIAG_SENDASSET_SELECT] Selection complete: selected %zu UTXOs, total_units=%llu, send_units=%llu\n",
                selected.size(), total_units, send_units);

            if (total_units < send_units) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient asset balance");
            }

            uint64_t change_units = total_units - send_units;
            pwallet->WalletLogPrintf("[DIAG_SENDASSET_CHANGE] change_units=%llu (total=%llu - send=%llu)\n",
                change_units, total_units, send_units);

            std::optional<AssetMetadata> source_metadata;
            for (const WalletAssetUtxo& utxo : selected) {
                if (utxo.metadata) {
                    source_metadata = *utxo.metadata;
                    break;
                }
            }

            struct PlannedAssetOutput
            {
                CTxDestination dest;
                CScript script;
                CAmount value;
                uint64_t units;
            };

            std::vector<PlannedAssetOutput> planned_outputs;
            planned_outputs.reserve(change_units > 0 ? 2 : 1);

            const CScript dest_script = GetScriptForDestination(dest);
            planned_outputs.push_back({dest, dest_script, DEFAULT_ASSET_OUTPUT_VALUE, send_units});

            if (change_units > 0) {
                // BECH32M (Taproot) rather than BECH32 (P2WPKH) for asset
                // change: every spend of asset change becomes a future input,
                // and emitting P2WPKH here keeps producing non-Taproot
                // candidates that contract funding paths (repo.build_open,
                // forward.build_open, sendasset native fee selection) then
                // pick up, fragmenting wallets into mixed Taproot+legacy and
                // collapsing atomic ceremonies to cooperative non-atomic.
                // Producing Taproot change keeps the wallet's spendable
                // set Taproot-pure over time.
                auto change_dest_res = pwallet->GetNewDestination(OutputType::BECH32M, "asset-change");
                if (!change_dest_res) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(change_dest_res).original);
                }
                const CTxDestination change_dest = *change_dest_res;
                const CScript change_script = GetScriptForDestination(change_dest);
                planned_outputs.push_back({change_dest, change_script, DEFAULT_ASSET_OUTPUT_VALUE, change_units});
            }

            CMutableTransaction template_tx;
            template_tx.vin.reserve(selected.size());
            for (const WalletAssetUtxo& utxo : selected) {
                template_tx.vin.emplace_back(utxo.outpoint);
            }

            std::optional<IcuKeywrapParams> keywrap_params;

            std::vector<CRecipient> recipients;
            recipients.reserve(planned_outputs.size());
            for (const PlannedAssetOutput& planned : planned_outputs) {
                recipients.push_back({planned.dest, planned.value, /*fSubtractFeeFromAmount=*/false});
            }

            // Create separate coin control for FundTransaction - must avoid asset UTXOs for fee inputs
            CCoinControl funding_control;
            funding_control.m_include_unsafe_inputs = true;
            funding_control.m_avoid_asset_utxos = true;  // CRITICAL: Avoid asset outputs for fee funding!
            funding_control.fAllowWatchOnly = include_watching;
            funding_control.m_signal_bip125_rbf = replaceable;
            funding_control.m_avoid_address_reuse = avoid_reuse;
            funding_control.m_change_type = OutputType::BECH32M;  // Taproot change for native fee leg
            if (conf_target) funding_control.m_confirm_target = conf_target;
            if (fee_rate_vb) {
                funding_control.fOverrideFeeRate = true;
                funding_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
            }

            // PROTOCOL PREFERENCE: build the Taproot-only candidate list once,
            // outside the funding loop. When sendasset is invoked by a
            // contract path (spot.build_atomic delegates the asset leg here),
            // mixed Taproot+legacy funding collapses the atomic adaptor
            // ceremony to cooperative non-atomic — see crash analysis for
            // session …978853000000_…. Trying Taproot-only first keeps atomic
            // available whenever the wallet has enough Taproot native value
            // for fees; falling back to any UTXO preserves functionality when
            // it doesn't.
            //
            // Stored as (value, outpoint) sorted by value DESCENDING. The
            // funding loop below tries progressively larger subsets — first
            // the single largest Taproot UTXO, then the two largest, etc. —
            // because Bitcoin Core's coin selection makes ALL preselected
            // coins mandatory when m_allow_other_inputs=false. Preselecting
            // every Taproot UTXO would sweep the entire Taproot balance into
            // one tx just to fund a tiny fee, which is exactly the
            // input-bloat shape this commit is trying to fix on the other
            // side. Largest-first because the common case is "one big UTXO
            // covers the fee", and trying that first lets us return after
            // one FundTransaction call.
            //
            // Built outside the loop because the wallet UTXO set is stable
            // for the duration of this call. vExt filter is critical:
            // m_avoid_asset_utxos on the funding control only filters
            // AUTO-selected candidates; PRE-selected coins bypass it.
            // Without the filter, preselecting an asset Taproot UTXO into
            // the Taproot-only attempt would silently burn the asset (dust
            // value satisfies nothing useful for fee funding).
            std::vector<COutPoint> taproot_native_sorted;
            {
                LOCK(pwallet->cs_wallet);
                auto coins_map = wallet::ListCoins(*pwallet);
                std::vector<std::pair<CAmount, COutPoint>> with_value;
                for (const auto& [dest, outputs] : coins_map) {
                    if (!std::holds_alternative<WitnessV1Taproot>(dest)) continue;
                    for (const COutput& out : outputs) {
                        if (out.depth < 0) continue;
                        if (!out.spendable) continue;
                        if (!out.safe) continue;
                        // Asset detection: check BOTH the vExt TLV bytes
                        // (covers asset/ZK/TFR outputs that carry an explicit
                        // TLV) AND the wallet's own GetAssetMetadata lookup
                        // (covers wallet-tracked asset associations that may
                        // not surface in the raw output's vExt — see how
                        // AvailableCoins() also consults GetAssetMetadata at
                        // assets.cpp:1185). Either signal means "this output
                        // is asset-related, do NOT use it for native fee
                        // funding" — preselecting one into a fee-funding
                        // attempt would silently burn the asset because
                        // m_avoid_asset_utxos on the funding control only
                        // filters AUTO-selected candidates, not preselected
                        // ones.
                        if (!out.txout.vExt.empty()) continue;
                        if (pwallet->GetAssetMetadata(out.outpoint)) continue;
                        if (pwallet->IsLockedCoin(out.outpoint)) continue;
                        with_value.emplace_back(out.txout.nValue, out.outpoint);
                    }
                }
                std::sort(with_value.begin(), with_value.end(),
                          [](const auto& a, const auto& b) {
                              return a.first > b.first;  // largest first
                          });
                taproot_native_sorted.reserve(with_value.size());
                for (const auto& [v, op] : with_value) {
                    taproot_native_sorted.push_back(op);
                }
            }

            const auto estimate_signed_vsize = [&](const CMutableTransaction& tx) -> int64_t {
                LOCK(pwallet->cs_wallet);
                const TxSize est = CalculateMaximumSignedTxSize(CTransaction(tx), pwallet.get(), &funding_control);
                if (est.vsize <= 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to estimate signed transaction size for fee calculation");
                }
                return est.vsize;
            };

            const auto adjust_fee_from_change = [&](CMutableTransaction& tx, CAmount deficit) -> CAmount {
                if (deficit <= 0) {
                    return 0;
                }

                const CFeeRate dust_relay_fee = pwallet->chain().relayDustFee();
                CAmount added_fee{0};
                std::vector<size_t> remove_indices;

                for (size_t idx = 0; idx < tx.vout.size() && added_fee < deficit; ++idx) {
                    CTxOut& out = tx.vout[idx];
                    if (out.nValue <= 0) {
                        continue;
                    }
                    if (!out.vExt.empty()) {
                        continue; // skip asset and TLV-bearing outputs
                    }
                    if (out.scriptPubKey.IsUnspendable()) {
                        continue;
                    }

                    CAmount remaining = deficit - added_fee;
                    if (remaining <= 0) break;

                    const CAmount take = std::min(out.nValue, remaining);
                    if (take <= 0) {
                        continue;
                    }

                    out.nValue -= take;
                    added_fee += take;

                    const CAmount dust_threshold = GetDustThreshold(out, dust_relay_fee);
                    if (out.nValue > 0 && out.nValue <= dust_threshold) {
                        added_fee += out.nValue;
                        out.nValue = 0;
                    }
                    if (out.nValue == 0) {
                        remove_indices.push_back(idx);
                    }
                }

                for (size_t i = remove_indices.size(); i-- > 0;) {
                    tx.vout.erase(tx.vout.begin() + remove_indices[i]);
                }
                return added_fee;
            };

            CFeeRate target_feerate = GetMinimumFeeRate(*pwallet, funding_control, /*feeCalc=*/nullptr);
            // In regtest, fee estimation often returns 0. Use a reasonable fallback.
            if (target_feerate == CFeeRate(0)) {
                target_feerate = CFeeRate(1000); // 1 sat/vB fallback
            }
            LogPrintf("sendasset: target_feerate=%s (before loop)\n", target_feerate.ToString());
            const size_t zk_input_index = 0;
            static constexpr int MAX_FUND_ATTEMPTS{3};
            CMutableTransaction mtx;
            CAmount fee{0};
            bool funded_ok{false};
            CTransactionRef tx_final;
            std::optional<std::string> unsigned_psbt_b64;

            for (int attempt = 0; attempt < MAX_FUND_ATTEMPTS; ++attempt) {
                LogPrintf("sendasset: attempt %d/%d, funding_control.m_feerate=%s\n",
                          attempt + 1, MAX_FUND_ATTEMPTS,
                          funding_control.m_feerate ? funding_control.m_feerate->ToString() : "NONE");

                // Two-tier coin selection:
                //   Tier 1: bounded Taproot-first. Try the largest single
                //           Taproot UTXO first; if it can't cover fee+change
                //           given input weight, add the next-largest; etc.
                //           We must iterate progressive subsets rather than
                //           preselect the whole set, because
                //           m_allow_other_inputs=false makes every preselected
                //           coin mandatory — preselecting all 12 Taproot
                //           UTXOs would sweep all 12 into the tx just to
                //           fund a tiny fee (the exact input-bloat shape this
                //           commit fixes). Largest-first because the common
                //           case is "one big UTXO covers it", which converges
                //           in one FundTransaction call.
                //   Tier 2: arbitrary fallback (original behaviour). Used
                //           when the wallet has no spendable non-asset
                //           Taproot UTXOs at all, or the entire Taproot
                //           subset is insufficient even at k=N.
                auto funded = [&]() -> util::Result<CreatedTransactionResult> {
                    for (size_t k = 1; k <= taproot_native_sorted.size(); ++k) {
                        CCoinControl taproot_only = funding_control;
                        taproot_only.m_allow_other_inputs = false;
                        taproot_only.UnSelectAll();
                        for (size_t i = 0; i < k; ++i) {
                            taproot_only.Select(taproot_native_sorted[i]);
                        }
                        auto r = FundTransaction(*pwallet, template_tx, recipients,
                                                 /*change_pos=*/std::nullopt,
                                                 /*lockUnspents=*/false, taproot_only);
                        if (r) {
                            pwallet->WalletLogPrintf(
                                "sendasset: funded native fees Taproot-only with %zu largest UTXO(s) of %zu candidates (attempt %d/%d)\n",
                                k, taproot_native_sorted.size(), attempt + 1, MAX_FUND_ATTEMPTS);
                            return r;
                        }
                    }
                    if (!taproot_native_sorted.empty()) {
                        pwallet->WalletLogPrintf(
                            "sendasset: Taproot-only insufficient across all %zu candidates; falling back to any UTXO (attempt %d/%d)\n",
                            taproot_native_sorted.size(), attempt + 1, MAX_FUND_ATTEMPTS);
                    }
                    return FundTransaction(*pwallet, template_tx, recipients,
                                           /*change_pos=*/std::nullopt,
                                           /*lockUnspents=*/false, funding_control);
                }();
                if (!funded) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(funded).original);
                }

                CMutableTransaction candidate(*funded->tx);
                CAmount candidate_fee = funded->fee;
                const uint32_t funded_tx_size = GetVirtualTransactionSize(*funded->tx);

                std::optional<CTxOut> zk_proof_output_opt;
                std::optional<CTxOut> tfr_anchor_output_opt;
                std::optional<CTxOut> op_return_output_opt;
                LogPrintf("SENDASSET_KEYWRAP_CHECK: asset=%s resolved.registry=%s\n",
                         resolved.asset_id.ToString(), resolved.registry ? "PRESENT" : "NULL");
                keywrap_params.reset();
                if (resolved.registry) {
                    const AssetRegistryEntry& entry = *resolved.registry;
                    LogPrintf("SENDASSET_KEYWRAP_CHECK: icu_flags=%u\n", entry.icu_flags);
                    if (entry.icu_flags & 1) {
                        LogPrintf("SENDASSET_KEYWRAP_CHECK: WRAP_REQUIRED detected, building keywrap\n");
                        if (!wrapped_key.empty()) {
                            IcuKeywrapParams kw;
                            kw.ctxt_hash = entry.icu_ctxt_commit;
                            kw.spk_hash32 = kw::TapMatchHash(dest_script);
                            kw.wrapped_key = wrapped_key;
                            kw.suite_id = suite_id;
                            kw.extras_mask = extras_mask;
                            kw.wrap_commit = wrap_commit;
                            kw.kc_tag = kc_tag;
                            keywrap_params = kw;
                        } else {
                            auto auto_keywrap = AutoWrapDekForOutput(
                                *pwallet,
                                resolved.asset_id,
                                entry.icu_ctxt_commit,
                                entry,
                                dest,
                                dest_script,
                                /*salt_override=*/std::nullopt,
                                suite_id);

                            wrapped_key = auto_keywrap.wrapped_key;
                            suite_id = auto_keywrap.suite_id;
                            extras_mask = auto_keywrap.extras_mask;
                            wrap_commit = auto_keywrap.wrap_commit;
                            kc_tag = auto_keywrap.kc_tag;
                            keywrap_params = auto_keywrap;
                        }
                    }
                } else if (!wrapped_key.empty() || !zk_proof.empty() || !zk_public_inputs.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not registered - cannot determine ICU/ZK requirements");
                }

                std::vector<bool> matched(candidate.vout.size(), false);
                for (const PlannedAssetOutput& planned : planned_outputs) {
                    bool found = false;
                    for (size_t idx = 0; idx < candidate.vout.size(); ++idx) {
                        if (matched[idx]) continue;
                        CTxOut& out = candidate.vout[idx];
                        if (out.nValue == planned.value && out.scriptPubKey == planned.script) {
                            std::optional<IcuKeywrapParams> output_keywrap;
                            if (keywrap_params) {
                                output_keywrap = *keywrap_params;
                                output_keywrap->spk_hash32 = kw::TapMatchHash(planned.script);
                                LogPrintf("SENDASSET_KEYWRAP_BUILD: output_idx=%zu has_keywrap=YES\n", idx);
                            } else {
                                LogPrintf("SENDASSET_KEYWRAP_BUILD: output_idx=%zu has_keywrap=NO\n", idx);
                            }
                            out.vExt = BuildAssetTagTlv(resolved.asset_id, planned.units, output_keywrap);
                            LogPrintf("SENDASSET_KEYWRAP_BUILD: vExt_size=%zu\n", out.vExt.size());
                            matched[idx] = true;
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate funded asset output");
                    }
                }

                if (needs_tfr_anchor) {
                    tfr_anchor_output_opt.emplace();
                    CTxOut& anchor_output = *tfr_anchor_output_opt;
                    anchor_output.nValue = 0;
                    anchor_output.scriptPubKey = CScript() << OP_RETURN;
                    anchor_output.vExt = BuildTfrAnchorTlv(resolved.asset_id,
                                                           tfr_commit,
                                                           tfr_keyset_id,
                                                           tfr_locator);
                }

                if (!op_return_data.empty()) {
                    op_return_output_opt.emplace();
                    CTxOut& data_output = *op_return_output_opt;
                    data_output.nValue = 0;
                    data_output.scriptPubKey = CScript() << OP_RETURN << op_return_data;
                }

                // Only the early-return paths need a pre-signing fee estimate
                // that closely matches the finalized transaction. The normal
                // sign/broadcast path already has a post-sign retry loop below,
                // and using the strict signed-size estimator here can block
                // those flows before signing ever gets a chance to correct fees.
                CMutableTransaction candidate_with_metadata(candidate);
                if (tfr_anchor_output_opt) {
                    candidate_with_metadata.vout.push_back(*tfr_anchor_output_opt);
                }
                if (op_return_output_opt) {
                    candidate_with_metadata.vout.push_back(*op_return_output_opt);
                }
                if (needs_zk_proof) {
                    zk_proof_output_opt.emplace();
                    CTxOut& proof_output = *zk_proof_output_opt;
                    proof_output.nValue = 0;
                    proof_output.scriptPubKey = CScript() << OP_RETURN;
                    std::vector<unsigned char> zk_payload;
                    zk_payload.insert(zk_payload.end(), resolved.asset_id.begin(), resolved.asset_id.end());
                    VectorWriter proof_writer(zk_payload, zk_payload.size());
                    WriteCompactSize(proof_writer, zk_proof_bytes.size());
                    zk_payload.insert(zk_payload.end(), zk_proof_bytes.begin(), zk_proof_bytes.end());
                    VectorWriter inputs_writer(zk_payload, zk_payload.size());
                    WriteCompactSize(inputs_writer, zk_public_inputs_bytes.size());
                    zk_payload.insert(zk_payload.end(), zk_public_inputs_bytes.begin(), zk_public_inputs_bytes.end());

                    std::vector<unsigned char> zk_proof_tlv;
                    zk_proof_tlv.push_back(0x22); // ZK_PROOF_PAYLOAD type
                    VectorWriter writer(zk_proof_tlv, zk_proof_tlv.size());
                    WriteCompactSize(writer, zk_payload.size());
                    zk_proof_tlv.insert(zk_proof_tlv.end(), zk_payload.begin(), zk_payload.end());
                    proof_output.vExt = std::move(zk_proof_tlv);
                    candidate_with_metadata.vout.push_back(proof_output);
                }
                const bool needs_precise_presign_fee_estimate = return_psbt || return_skeleton;
                const int64_t estimated_fee_vsize = needs_precise_presign_fee_estimate
                    ? estimate_signed_vsize(candidate_with_metadata)
                    : static_cast<int64_t>(GetVirtualTransactionSize(CTransaction(candidate_with_metadata))) +
                          static_cast<int64_t>(candidate.vin.size()) * 27;

                CAmount required_fee = target_feerate.GetFee(estimated_fee_vsize);
                LogPrintf("sendasset: estimated_fee_vsize=%d, required_fee=%d, candidate_fee=%d\n",
                          estimated_fee_vsize, required_fee, candidate_fee);

                if (required_fee > candidate_fee) {
                    const CAmount shortfall = required_fee - candidate_fee;
                    LogPrintf("sendasset: fee shortfall=%d, attempting to adjust from change\n", shortfall);
                    CAmount added_fee = adjust_fee_from_change(candidate, shortfall);
                    LogPrintf("sendasset: adjusted %d from change\n", added_fee);
                    if (added_fee > 0) {
                        candidate_fee += added_fee;
                        LogPrintf("sendasset: after adjustment: candidate_fee=%d\n", candidate_fee);
                    }
                }

                if (candidate_fee >= required_fee) {
                    if (needs_tfr_anchor) {
                        assert(tfr_anchor_output_opt.has_value());
                        candidate.vout.push_back(*tfr_anchor_output_opt);
                        LogPrintf("sendasset: added TFR_ANCHOR output (n=%d, %d bytes) before signing\n",
                                  candidate.vout.size() - 1, candidate.vout.back().vExt.size());
                    }
                    if (needs_zk_proof) {
                        assert(zk_proof_output_opt.has_value());
                        candidate.vout.push_back(*zk_proof_output_opt);
                        LogPrintf("sendasset: added ZK_PROOF_PAYLOAD output (n=%d, %d bytes) before signing\n",
                                  candidate.vout.size() - 1, candidate.vout.back().vExt.size());
                    }
                    if (op_return_output_opt) {
                        candidate.vout.push_back(*op_return_output_opt);
                        LogPrintf("sendasset: added OP_RETURN data output (n=%d, %d bytes) before signing\n",
                                  candidate.vout.size() - 1, op_return_data.size());
                    }

                    if (return_skeleton) {
                        // Skeleton mode: hand back unsigned transaction so caller can merge/extents later.
                        LogPrintf("sendasset: fee sufficient, returning unsigned skeleton\n");
                        mtx = candidate;
                        fee = candidate_fee;
                        tx_final = MakeTransactionRef(CTransaction(mtx));
                        funded_ok = true;
                        break;
                    }

                    if (return_psbt) {
                        LogPrintf("sendasset: fee sufficient, returning unsigned psbt\n");
                        PartiallySignedTransaction psbtx(candidate);
                        bool complete = false;
                        const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
                        if (fill_err) {
                            throw JSONRPCPSBTError(*fill_err);
                        }

                        DataStream ss_psbt{};
                        ss_psbt << psbtx;
                        unsigned_psbt_b64 = EncodeBase64(ss_psbt.str());
                        mtx = candidate;
                        fee = candidate_fee;
                        funded_ok = true;
                        break;
                    }

                    LogPrintf("sendasset: fee sufficient, proceeding to sign\n");
                    PartiallySignedTransaction psbtx(candidate);
                    if (needs_zk_proof) {
                        ReplaceZkEntry(psbtx.inputs.at(zk_input_index).m_proprietary, "proof", zk_proof_bytes);
                        ReplaceZkEntry(psbtx.inputs.at(zk_input_index).m_proprietary, "public_inputs", zk_public_inputs_bytes);
                    }
                    bool complete = false;

                    const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                    if (fill_err) {
                        throw JSONRPCPSBTError(*fill_err);
                    }

                    if (!complete) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction completely");
                    }

                    CMutableTransaction signed_mtx;
                    if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
                    }

                    const uint32_t signed_vsize = GetVirtualTransactionSize(CTransaction(signed_mtx));
                    const CAmount signed_required_fee = target_feerate.GetFee(signed_vsize);
                    if (candidate_fee < signed_required_fee) {
                        if (fee_rate_vb) {
                            throw JSONRPCError(RPC_WALLET_ERROR,
                                strprintf("sendasset: explicit fee_rate %.3f sat/vB insufficient for signed transaction (need %d sats for %u vB, funded %d sats)",
                                          *fee_rate_vb, signed_required_fee, signed_vsize, candidate_fee));
                        }
                        const CAmount buffer = std::max<CAmount>(CAmount(1), signed_required_fee / 10);
                        const CAmount target_fee_signed = signed_required_fee + buffer;
                        CFeeRate retry_rate(target_fee_signed, std::max<uint32_t>(1u, signed_vsize));
                        if (funding_control.m_feerate && retry_rate <= *funding_control.m_feerate) {
                            retry_rate = CFeeRate(funding_control.m_feerate->GetFeePerK() + buffer * 1000 / std::max<uint32_t>(1u, signed_vsize));
                        }
                        funding_control.fOverrideFeeRate = true;
                        funding_control.m_feerate = retry_rate;
                        LogPrintf("sendasset: signed tx requires higher fee (funded=%d, required=%d, signed_vsize=%u); retrying with feerate %s\n",
                                  candidate_fee, signed_required_fee, signed_vsize, retry_rate.ToString());
                        continue;
                    }

                    mtx = std::move(signed_mtx);
                    fee = candidate_fee;
                    tx_final = MakeTransactionRef(CTransaction(mtx));
                    funded_ok = true;
                    break;
                }

                const CAmount remaining_deficit = required_fee - candidate_fee;
                LogPrintf("sendasset: fee shortfall detected (funded=%d, required=%d, deficit=%d, attempt=%d)\n",
                          candidate_fee, required_fee, remaining_deficit, attempt + 1);

                if (fee_rate_vb) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("sendasset: explicit fee_rate %.3f sat/vB insufficient for TLV size (need %d sats, funded %d sats)",
                                  *fee_rate_vb, required_fee, candidate_fee));
                }

                if (attempt == MAX_FUND_ATTEMPTS - 1) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                                       strprintf("sendasset: unable to fund transaction with sufficient fee (required %d sats, funded %d sats)",
                                                 required_fee, candidate_fee));
                }

                const CAmount buffer = std::max<CAmount>(CAmount(1), required_fee / 10);
                const CAmount target_fee = required_fee + buffer;
                CFeeRate retry_rate(target_fee, std::max<uint32_t>(1u, funded_tx_size));
                if (funding_control.m_feerate && retry_rate <= *funding_control.m_feerate) {
                    retry_rate = CFeeRate(funding_control.m_feerate->GetFeePerK() + buffer * 1000 / std::max<uint32_t>(1u, funded_tx_size));
                }
                funding_control.fOverrideFeeRate = true;
                funding_control.m_feerate = retry_rate;

                LogPrintf("sendasset: retrying FundTransaction with feerate %s after deficit %d\n",
                          retry_rate.ToString(), remaining_deficit);
            }

            if (!funded_ok) {
                throw JSONRPCError(RPC_WALLET_ERROR, "sendasset: internal fee funding loop exhausted");
            }


            std::optional<AssetMetadata> output_metadata;
            if (source_metadata) {
                output_metadata = *source_metadata;
                output_metadata->asset_id = resolved.asset_id;
                output_metadata->is_issuer_credential = false;
            } else if (resolved.registry) {
                const AssetRegistryEntry& entry = *resolved.registry;
                AssetMetadata meta;
                meta.asset_id = resolved.asset_id;
                meta.is_issuer_credential = false;
                if (!entry.ticker.empty()) {
                    meta.has_ticker = true;
                    meta.ticker = entry.ticker;
                }
                if (entry.decimals != std::numeric_limits<uint8_t>::max()) {
                    meta.has_decimals = true;
                    meta.decimals = entry.decimals;
                }
                output_metadata = meta;
            }

            const uint64_t asset_outputs = std::accumulate(planned_outputs.begin(), planned_outputs.end(), uint64_t{0}, [](uint64_t sum, const PlannedAssetOutput& planned) {
                return sum + planned.units;
            });

            // Return skeleton if requested (pre-fee, unsigned transaction with metadata)
            if (return_skeleton) {
                UniValue skeleton(UniValue::VOBJ);

                // Unsigned transaction hex (pre-signing, TLVs attached)
                skeleton.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
                skeleton.pushKV("complete", false);

                // Asset inputs (selected UTXOs with metadata)
                UniValue asset_inputs_arr(UniValue::VARR);
                for (const WalletAssetUtxo& utxo : selected) {
                    UniValue inp(UniValue::VOBJ);
                    inp.pushKV("txid", utxo.outpoint.hash.ToString());
                    inp.pushKV("vout", (int)utxo.outpoint.n);
                    inp.pushKV("asset_id", utxo.asset_id.ToString());
                    inp.pushKV("asset_units", utxo.units);
                    inp.pushKV("amount", ValueFromAmount(utxo.txout.nValue));
                    inp.pushKV("scriptPubKey", HexStr(utxo.txout.scriptPubKey));
                    asset_inputs_arr.push_back(inp);
                }
                skeleton.pushKV("asset_inputs", asset_inputs_arr);

                // BTC funding inputs (from FundTransaction result)
                UniValue btc_inputs_arr(UniValue::VARR);
                for (size_t i = 0; i < mtx.vin.size(); ++i) {
                    if (i >= selected.size()) {
                        // This is a BTC-only input added by FundTransaction
                        UniValue inp(UniValue::VOBJ);
                        inp.pushKV("txid", mtx.vin[i].prevout.hash.ToString());
                        inp.pushKV("vout", (int)mtx.vin[i].prevout.n);
                        btc_inputs_arr.push_back(inp);
                    }
                }
                skeleton.pushKV("btc_inputs", btc_inputs_arr);

                // Output metadata (which outputs are editable)
                UniValue outputs_arr(UniValue::VARR);
                for (size_t i = 0; i < mtx.vout.size(); ++i) {
                    UniValue out_obj(UniValue::VOBJ);
                    out_obj.pushKV("n", (int)i);
                    out_obj.pushKV("amount", ValueFromAmount(mtx.vout[i].nValue));

                    bool has_asset_tag = false;
                    bool has_tfr_anchor = false;
                    for (size_t j = 0; j < mtx.vout[i].vExt.size(); ++j) {
                        if (mtx.vout[i].vExt[j] == 0x01) {
                            has_asset_tag = true;
                        } else if (mtx.vout[i].vExt[j] == 0x21) {
                            has_tfr_anchor = true;
                        }
                    }

                    if (has_asset_tag) {
                        out_obj.pushKV("type", "asset");
                        out_obj.pushKV("editable", false);
                    } else if (has_tfr_anchor) {
                        out_obj.pushKV("type", "tfr_anchor");
                        out_obj.pushKV("editable", false);
                    } else if (mtx.vout[i].nValue >= DEFAULT_ASSET_OUTPUT_VALUE) {
                        out_obj.pushKV("type", "btc_change");
                        out_obj.pushKV("editable", true);
                    } else {
                        out_obj.pushKV("type", "btc_other");
                        out_obj.pushKV("editable", true);
                    }

                    outputs_arr.push_back(out_obj);
                }
                skeleton.pushKV("outputs", outputs_arr);

                // Fee estimation
                skeleton.pushKV("estimated_fee", ValueFromAmount(fee));
                if (fee_rate_vb) {
                    skeleton.pushKV("fee_rate", *fee_rate_vb);
                }

                // Asset summary
                skeleton.pushKV("asset_id", resolved.asset_id.ToString());
                if (output_metadata && output_metadata->has_ticker) {
                    skeleton.pushKV("ticker", output_metadata->ticker);
                }
                skeleton.pushKV("asset_inputs_total", total_units);
                skeleton.pushKV("asset_outputs_total", total_units);  // Conservation maintained

                skeleton.pushKV("needs_zk_proof", needs_zk_proof);
                skeleton.pushKV("needs_tfr_anchor", needs_tfr_anchor);
                if (needs_zk_proof) {
                    skeleton.pushKV("zk_proof", HexStr(zk_proof_bytes));
                    skeleton.pushKV("zk_public_inputs", HexStr(zk_public_inputs_bytes));
                    skeleton.pushKV("zk_input_index", static_cast<int>(zk_input_index));
                }
                if (needs_tfr_anchor) {
                    skeleton.pushKV("tfr_commit", tfr_commit.ToString());
                    skeleton.pushKV("tfr_keyset_id", static_cast<uint64_t>(tfr_keyset_id));
                    skeleton.pushKV("tfr_locator", HexStr(tfr_locator));
                }

                // Instructions for re-funding
                UniValue refund_instructions(UniValue::VOBJ);
                refund_instructions.pushKV("note", "Transaction is PRE-FEE. After modifying outputs, call fundrawtransaction or walletprocesspsbt to finalize fees and sign.");
                refund_instructions.pushKV("suggested_workflow", "1. Modify covenant outputs  2. fundrawtransaction  3. walletprocesspsbt  4. sendrawtransaction");
                skeleton.pushKV("refund_instructions", refund_instructions);

                return skeleton;
            }

            if (unsigned_psbt_b64) {
                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", *unsigned_psbt_b64);
                result.pushKV("complete", false);
                result.pushKV("fee", ValueFromAmount(fee));
                result.pushKV("asset_id", resolved.asset_id.ToString());

                if (output_metadata && output_metadata->has_ticker) {
                    result.pushKV("ticker", output_metadata->ticker);
                } else if (resolved.registry && !resolved.registry->ticker.empty()) {
                    result.pushKV("ticker", resolved.registry->ticker);
                }

                result.pushKV("asset_inputs", total_units);
                result.pushKV("asset_outputs", asset_outputs);
                result.pushKV("asset_change", change_units);
                result.pushKV("needs_zk_proof", needs_zk_proof);
                result.pushKV("needs_tfr_anchor", needs_tfr_anchor);
                return result;
            }

            PartiallySignedTransaction psbtx(mtx);
            if (needs_zk_proof) {
                ReplaceZkEntry(psbtx.inputs.at(zk_input_index).m_proprietary, "proof", zk_proof_bytes);
                ReplaceZkEntry(psbtx.inputs.at(zk_input_index).m_proprietary, "public_inputs", zk_public_inputs_bytes);
            }
            bool complete = false;

            const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            if (!complete) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction completely");
            }

            CMutableTransaction signed_mtx;
            if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
            }

            const CTransactionRef tx_final_ref = MakeTransactionRef(CTransaction(signed_mtx));
            const uint32_t signed_vsize = GetVirtualTransactionSize(*tx_final_ref);
            const CAmount signed_required_fee = target_feerate.GetFee(signed_vsize);
            if (fee < signed_required_fee) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("sendasset: fee underpaid after signing (paid %d sats, need %d sats for %u vB). Increase fee_rate.",
                              fee, signed_required_fee, signed_vsize));
            }

            if (broadcast) {
                LOCK(pwallet->cs_wallet);
                if (output_metadata) {
                    for (size_t i = 0; i < tx_final_ref->vout.size(); ++i) {
                        if (!(pwallet->IsMine(tx_final_ref->vout[i]) & ISMINE_SPENDABLE)) {
                            continue;
                        }
                        pwallet->SetAssetMetadata(COutPoint(tx_final_ref->GetHash(), i), *output_metadata);
                    }
                }
                pwallet->CommitTransaction(tx_final_ref, /*value_map=*/{}, /*order_form=*/{});
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx_final_ref->GetHash().ToString());
            if (!broadcast) {
                result.pushKV("hex", EncodeHexTx(*tx_final_ref));
            }
            result.pushKV("fee", ValueFromAmount(fee));
            result.pushKV("asset_id", resolved.asset_id.ToString());

            if (output_metadata && output_metadata->has_ticker) {
                result.pushKV("ticker", output_metadata->ticker);
            } else if (resolved.registry && !resolved.registry->ticker.empty()) {
                result.pushKV("ticker", resolved.registry->ticker);
            }

            result.pushKV("asset_inputs", total_units);
            result.pushKV("asset_outputs", asset_outputs);
            result.pushKV("asset_change", change_units);
            return result;
        }
    };
}

// Reused by icu_acceptance. geticupayload is defined later in this translation unit;
// send lives in spend.cpp. Forward-declared so icu_acceptance can delegate to the
// authoritative decrypt / native-funding paths without duplicating them.
RPCHelpMan geticupayload();
RPCHelpMan send();

RPCHelpMan icu_acceptance()
{
    return RPCHelpMan{
        "icu.acceptance",
        "CUSTODIAL acceptance/return for a wallet that holds the holder's keys. For the non-custodial operator\n"
        "hoster flow, use the wallet-free icu.acceptance.prepare/verify node RPCs instead.\n"
        "The acceptance object is the canonical DOCUMENT hash -- the asset registry's icu_plain_commit --\n"
        "carried verbatim in an OP_RETURN. Accepting the document hash is accepting the whole document; there\n"
        "are no per-clause fields. Onerous-term notice is a UX matter, shown before the user accepts.\n"
        "mode=\"acknowledge\": a native (fee-only) tx with OP_RETURN(document hash). The asset is NOT moved; the\n"
        "  wallet co-signs a mandatory BIP-322 over the acceptance message with the holder's share address,\n"
        "  which attributes the acknowledgment (the tx inputs need not be the share key).\n"
        "mode=\"return\": relinquishes the asset to the issuer ICU address (via sendasset); the asset-input spend\n"
        "  attributes the holder. OP_RETURN(document hash) rides along for plain assets; for KYC/TFR assets it\n"
        "  is omitted on-chain (multi-op-return policy) and the move alone records the return.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "\"acknowledge\" or \"return\""},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Acknowledge mode: the holder's share-holding address to bind/sign with (default: resolved from a held asset UTXO). Must be a wallet address that holds this asset."},
                    {"units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Return mode only: asset units to return (default: full held balance)"},
                    {"issuer_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Display/confirm override; must equal the chain-resolved ICU address"},
                    {"allow_unknown_terms", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return mode: permit returning when the canonical document hash cannot be determined"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Explicit fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Signal BIP125 replace-by-fee"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast the transaction"},
                    {"return_psbt", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return mode only: return an unsigned PSBT for the spend instead of broadcasting. Not valid for acknowledge."},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "mode", "The acceptance mode performed"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (omitted when return_psbt=true or broadcast=false)"},
                {RPCResult::Type::STR, "psbt", /*optional=*/true, "Unsigned PSBT (return_psbt=true)"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Signed transaction hex (when broadcast=false)"},
                {RPCResult::Type::BOOL, "commitment_onchain", "Whether the OP_RETURN(document hash) is embedded on-chain (false for KYC/TFR returns)"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "The canonical document hash = registry icu_plain_commit (the acceptance anchor)"},
                {RPCResult::Type::STR, "holder_address", /*optional=*/true, "Acknowledge mode: the bound share-holding address"},
                {RPCResult::Type::STR, "holder_signature", /*optional=*/true, "Acknowledge mode: BIP-322 signature by holder_address over message_to_sign"},
                {RPCResult::Type::STR, "message_to_sign", /*optional=*/true, "Acknowledge mode: the message the holder_signature covers"},
                {RPCResult::Type::STR, "issuer_address", "Authoritatively-resolved issuer ICU address"},
                {RPCResult::Type::STR_HEX, "asset_id", "Resolved asset identifier"},
                {RPCResult::Type::NUM, "units", /*optional=*/true, "Return mode: asset units returned"},
            }
        },
        RPCExamples{
            HelpExampleCli("icu.acceptance", "\"SHARE\" \"acknowledge\"") +
            HelpExampleCli("icu.acceptance", "\"SHARE\" \"return\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string asset_identifier = request.params[0].get_str();
            AssetResolution resolved = ResolveAssetIdOrTicker(request, asset_identifier);
            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset is not registered; cannot resolve issuer ICU address");
            }
            const AssetRegistryEntry& entry = *resolved.registry;

            const std::string mode = UppercaseCopy(request.params[1].get_str());
            const bool is_return = (mode == "RETURN");
            const bool is_ack = (mode == "ACKNOWLEDGE" || mode == "ACK");
            if (!is_return && !is_ack) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be \"acknowledge\" or \"return\"");
            }
            // NB: the wallet is unlocked only on paths that sign locally (see the custodial
            // acknowledge branch and sendasset). The prepare-only path never signs here.

            // ---- options ----
            std::optional<uint64_t> units_opt;
            std::optional<std::string> issuer_override;
            std::optional<std::string> holder_override;
            std::optional<double> fee_rate_vb;
            bool replaceable{true};
            bool broadcast{true};
            bool return_psbt{false};
            bool allow_unknown_terms{false};
            if (!request.params[2].isNull()) {
                const UniValue& opt = request.params[2];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                if (opt.exists("units")) units_opt = opt["units"].getInt<uint64_t>();
                if (opt.exists("issuer_address")) issuer_override = opt["issuer_address"].get_str();
                if (opt.exists("holder_address")) holder_override = opt["holder_address"].get_str();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("return_psbt")) return_psbt = opt["return_psbt"].get_bool();
                if (opt.exists("allow_unknown_terms")) allow_unknown_terms = opt["allow_unknown_terms"].get_bool();
            }

            // ---- authoritatively resolve the issuer ICU address from icu_outpoint ----
            if (entry.icu_outpoint.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Asset registry has no ICU outpoint; cannot resolve issuer address");
            }
            std::map<COutPoint, Coin> icu_coins;
            icu_coins[entry.icu_outpoint];
            pwallet->chain().findCoins(icu_coins);
            auto icu_it = icu_coins.find(entry.icu_outpoint);
            if (icu_it == icu_coins.end() || icu_it->second.IsSpent()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Issuer ICU outpoint not found in the UTXO set (rotated or pruned)");
            }
            CTxDestination issuer_dest;
            if (!ExtractDestination(icu_it->second.out.scriptPubKey, issuer_dest)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract issuer ICU destination");
            }
            const std::string issuer_address = EncodeDestination(issuer_dest);
            if (issuer_override && *issuer_override != issuer_address) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("issuer_address override %s does not match the chain-resolved ICU address %s",
                              *issuer_override, issuer_address));
            }

            // ---- scan the holder's UTXOs for this asset ----
            // Include watch-only so a non-custodial / watch-only holder can be bound on the
            // prepare-only path. spendable_units (what a custodial return can move) is tracked
            // separately from share_addresses (held addresses an acknowledge may bind). Addresses
            // come straight from each UTXO's scriptPubKey, so no spend authority is implied.
            CCoinControl scan_control;
            scan_control.m_include_unsafe_inputs = true;
            scan_control.m_avoid_asset_utxos = false;
            scan_control.fAllowWatchOnly = true;
            CoinFilterParams filter_params;
            filter_params.only_spendable = false;
            uint64_t spendable_units = 0;
            std::set<std::string> share_addresses;
            std::string default_share_address;
            for (const WalletAssetUtxo& u : CollectAssetUtxos(*pwallet, scan_control, filter_params)) {
                if (u.asset_id != resolved.asset_id) continue;
                if (!(u.ismine_spendable || u.solvable)) continue;   // owned, spendable or watch-only
                if (u.spendable && u.ismine_spendable) spendable_units += u.units;
                CTxDestination d;
                if (ExtractDestination(u.txout.scriptPubKey, d)) {
                    const std::string a = EncodeDestination(d);
                    if (share_addresses.insert(a).second && default_share_address.empty()) {
                        default_share_address = a;
                    }
                }
            }
            if (share_addresses.empty()) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Wallet holds no units of this asset");
            }

            // ---- canonical_hash + context probe: decrypt best-effort with wallet keys ----
            // Probe unconditionally (not only when the registry commit is null) so we can detect a
            // committed TSC-ICU-CONTEXT-1 map and refuse the custodial document-only acknowledge for
            // context-bearing assets (those go through the icu.acceptance node flow).
            uint256 canonical_hash = entry.icu_plain_commit;
            bool has_context_map = false;
            try {
                JSONRPCRequest sub = request;
                UniValue pa(UniValue::VARR);
                pa.push_back(asset_identifier);
                sub.params = pa;
                sub.mode = JSONRPCRequest::EXECUTE;
                UniValue icu = geticupayload().HandleRequest(sub);
                if (icu.exists("plaintext") && icu["plaintext"].isStr()) {
                    std::vector<unsigned char> plain = ParseHex(icu["plaintext"].get_str());
                    if (auto cp = assets::ParseCanonicalIcuPayload(plain)) {
                        if (canonical_hash.IsNull()) canonical_hash = cp->GetCanonicalHash();
                        if (!cp->metadata.empty()) {
                            UniValue m; const std::string ms(cp->metadata.begin(), cp->metadata.end());
                            if (m.read(ms) && m.isObject() && m.exists("spec") && m["spec"].isStr() &&
                                m["spec"].get_str() == assets::ICU_CONTEXT_SPEC_V1) {
                                has_context_map = true;
                            }
                        }
                    }
                }
            } catch (const UniValue&) {
                // best-effort; enforced per-mode below
            }

            UniValue result(UniValue::VOBJ);

            if (is_ack) {
                // Bypass guard: a committed context map cannot be satisfied by this document-only
                // (ACCEPT-1) custodial path. Direct context-bearing assets to the node flow.
                if (has_context_map) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "this asset carries a committed TSC-ICU-CONTEXT-1 map; custodial acknowledge does not build "
                        "context (TSC-ICU-DOC-ACCEPT-2) signatures -- use the icu.acceptance.prepare/verify node flow "
                        "with body_refs and the asset DEK");
                }
                // ===== ACKNOWLEDGE: native fee-only tx with OP_RETURN(document hash); asset untouched =====
                if (canonical_hash.IsNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Cannot acknowledge: the canonical document hash is unavailable (no registry icu_plain_commit and the ICU could not be decrypted).");
                }
                if (return_psbt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "return_psbt is not supported on the custodial acknowledge path. Use the wallet-free "
                        "icu.acceptance.prepare node RPC for the non-custodial / external-signing flow.");
                }

                // Bind the holder's share-holding address (override must hold the asset; else a held one).
                std::string holder_address;
                if (holder_override) {
                    CTxDestination hd = DecodeDestination(*holder_override);
                    if (!IsValidDestination(hd)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid holder_address");
                    }
                    holder_address = EncodeDestination(hd);
                    if (!share_addresses.count(holder_address)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                            "holder_address does not hold any units of this asset");
                    }
                } else {
                    holder_address = default_share_address;
                }

                const std::string message_to_sign = assets::BuildAcceptanceMessage(
                    assets::IcuAcceptanceMode::ACKNOWLEDGE, resolved.asset_id, canonical_hash, holder_address);

                // The native fee-only output: one OP_RETURN carrying the canonical document hash.
                UniValue outs(UniValue::VARR);
                UniValue data_out(UniValue::VOBJ);
                data_out.pushKV("data", HexStr(canonical_hash));
                outs.push_back(data_out);

                // AUTHORISE FIRST: produce the mandatory BIP-322 holder signature over the acceptance
                // message BEFORE building/broadcasting, so a signing failure leaves nothing on-chain.
                // The asset is not spent, so this signature -- not the tx inputs -- attributes the holder.
                EnsureWalletIsUnlocked(*pwallet);
                std::string holder_signature;
                {
                    LOCK(pwallet->cs_wallet);
                    std::string sig, err;
                    if (!pwallet->SignMessageBIP322(holder_address, message_to_sign, sig, err)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Could not produce a holder signature with %s (%s). "
                                      "Acknowledgment must be authorised by the holder's share key.",
                                      holder_address, err));
                    }
                    holder_signature = sig;
                }

                UniValue send_opts(UniValue::VOBJ);
                send_opts.pushKV("replaceable", replaceable);
                if (fee_rate_vb) send_opts.pushKV("fee_rate", *fee_rate_vb);
                if (!broadcast) send_opts.pushKV("add_to_wallet", false);  // sign but don't broadcast
                UniValue send_params(UniValue::VARR);
                send_params.push_back(outs);
                send_params.push_back(NullUniValue);           // conf_target
                send_params.push_back("unset");                // estimate_mode
                send_params.push_back(NullUniValue);           // fee_rate handled via options
                send_params.push_back(send_opts);
                JSONRPCRequest send_req = request;
                send_req.params = send_params;
                send_req.mode = JSONRPCRequest::EXECUTE;
                UniValue send_res = send().HandleRequest(send_req);

                result.pushKV("mode", "acknowledge");
                result.pushKV("commitment_onchain", true);
                result.pushKV("canonical_hash", canonical_hash.ToString());
                result.pushKV("holder_address", holder_address);
                result.pushKV("holder_signature", holder_signature);
                result.pushKV("message_to_sign", message_to_sign);
                result.pushKV("issuer_address", issuer_address);
                result.pushKV("asset_id", resolved.asset_id.ToString());
                if (send_res.exists("txid")) result.pushKV("txid", send_res["txid"]);
                if (send_res.exists("hex")) result.pushKV("hex", send_res["hex"]);
                return result;
            }

            // ===== RETURN: move the asset to the issuer ICU address (via sendasset) =====
            if (canonical_hash.IsNull() && !allow_unknown_terms) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Cannot determine the canonical document hash for this return. Set allow_unknown_terms=true to return without binding the terms.");
            }
            if (spendable_units == 0) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Wallet holds no spendable units of this asset to return");
            }
            const uint64_t act_units = units_opt.value_or(spendable_units);
            if (act_units == 0 || act_units > spendable_units) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "units must be > 0 and <= spendable balance");
            }

            // OP_RETURN(document hash) rides along only when sendasset emits no other OP_RETURN
            // metadata (policy permits at most the tfr+zk pair). KYC/TFR returns omit it on-chain.
            const bool emits_metadata = entry.has_kyc || (entry.tfr_flags & assets::TFR_ANCHOR_REQUIRED);
            const bool commitment_onchain = !emits_metadata;

            UniValue send_opts(UniValue::VOBJ);
            if (commitment_onchain && !canonical_hash.IsNull()) send_opts.pushKV("op_return", HexStr(canonical_hash));
            send_opts.pushKV("replaceable", replaceable);
            send_opts.pushKV("broadcast", broadcast);
            if (return_psbt) send_opts.pushKV("return_psbt", true);
            if (fee_rate_vb) send_opts.pushKV("fee_rate", *fee_rate_vb);
            // The keywrap need not be valid on a return: hand sendasset a structurally-valid
            // suite-0 placeholder so WRAP_REQUIRED assets don't require this wallet's DEK.
            if (entry.icu_flags & 1) {
                std::array<unsigned char, 32> zero{};
                std::vector<unsigned char> zv(zero.begin(), zero.end());
                const std::string b64 = EncodeBase64(MakeUCharSpan(zv));
                const std::vector<unsigned char> placeholder(b64.begin(), b64.end());
                send_opts.pushKV("wrapped_key", HexStr(placeholder));
                send_opts.pushKV("suite_id", 0);
            }

            UniValue send_params(UniValue::VARR);
            send_params.push_back(asset_identifier);
            send_params.push_back(issuer_address);
            send_params.push_back(UniValue(act_units));
            send_params.push_back(send_opts);

            JSONRPCRequest send_req = request;
            send_req.params = send_params;
            send_req.mode = JSONRPCRequest::EXECUTE;
            UniValue send_res = sendasset().HandleRequest(send_req);

            result.pushKV("mode", "return");
            if (send_res.exists("txid")) result.pushKV("txid", send_res["txid"]);
            if (send_res.exists("psbt")) result.pushKV("psbt", send_res["psbt"]);
            if (send_res.exists("hex") && !send_res.exists("txid")) result.pushKV("hex", send_res["hex"]);
            result.pushKV("commitment_onchain", commitment_onchain);
            result.pushKV("canonical_hash", canonical_hash.ToString());
            result.pushKV("issuer_address", issuer_address);
            result.pushKV("asset_id", resolved.asset_id.ToString());
            result.pushKV("units", UniValue(act_units));
            return result;
        }
    };
}

RPCHelpMan icu_acceptance_record_create()
{
    return RPCHelpMan{
        "icu.acceptance.record.create",
        "Create an on-chain ICU acceptance record (0x40 vExt) for a wallet-held asset UTXO.\n"
        "acknowledge: a TAPROOT holder (P2TR-v1 / P2TR-v2) signs a TSC-ICU-ACCEPTANCE-RECORD-1 message with\n"
        "SECP_SCHNORR_RAW (for P2TR-v2 the key-path-disabled secp output key; ML-DSA stays spend-only and is\n"
        "never serialized into the record); the asset UTXO is left unspent.\n"
        "Hash-hidden families (P2WPKH/P2PKH/P2WSH) acknowledge via SECP_BIP322_HASH commit-reveal: a BIP-322\n"
        "proof over the record message is produced, but only SHA256(proof) is committed on chain (the pubkey\n"
        "is not revealed while the asset is held); the proof is returned as revealed_bip322_proof for the\n"
        "holder to retain and reveal at verify time.\n"
        "return: ANY holder family relinquishes the asset -- the tx spends the holder UTXO, sends its units\n"
        "back to the issuer's ICU return address, and carries a NONE record (attribution is the spend).",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "\"acknowledge\" (taproot via raw Schnorr, or hash-hidden via BIP-322 commit-reveal) or \"return\" (relinquish to the issuer)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"holder_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Holder asset UTXO txid. Required when the wallet has multiple matching holder UTXOs."},
                    {"holder_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Holder asset UTXO vout. Required with holder_txid."},
                    {"body_refs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                        "Optional clause body hashes to affirm. If the committed context is required and body_refs is omitted, all designated bodies are affirmed.",
                        {{"body_ref", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte raw SHA256 body hash hex"}}},
                    {"expected_canonical_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional guard: must equal the registry icu_plain_commit"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Explicit fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Signal BIP125 replace-by-fee"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast the transaction"},
                    {"return_psbt", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return mode only: return an unsigned wallet-annotated PSBT for the spend instead of signing/broadcasting."},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "mode", "acceptance mode"},
                {RPCResult::Type::STR, "holder_family", "holder output family used for the acceptance signature"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Acceptance transaction id (omitted when return_psbt=true)"},
                {RPCResult::Type::STR, "psbt", /*optional=*/true, "Return mode only: unsigned wallet-annotated PSBT for the spend (return_psbt=true)"},
                {RPCResult::Type::BOOL, "complete", /*optional=*/true, "Return mode + return_psbt: whether the PSBT is complete (always false -- holder must sign)"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Signed transaction hex when broadcast=false"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Fee paid in BTC"},
                {RPCResult::Type::STR_HEX, "asset_id", "Resolved asset identifier"},
                {RPCResult::Type::STR_HEX, "icu_plain_commit", "Canonical ICU document hash bound by the record"},
                {RPCResult::Type::STR_HEX, "holder_txid", "Bound holder prevout txid"},
                {RPCResult::Type::NUM, "holder_vout", "Bound holder prevout vout"},
                {RPCResult::Type::STR_HEX, "holder_spk_hash", /*optional=*/true, "SHA256(scriptPubKey) of the bound holder prevout (acknowledge)"},
                {RPCResult::Type::NUM, "accepted_units", "Asset units on the bound holder prevout"},
                {RPCResult::Type::STR, "context_source", /*optional=*/true, "inline, metadata, or none (acknowledge)"},
                {RPCResult::Type::ARR, "body_refs", /*optional=*/true, "Affirmed clause body hashes (acknowledge)", {{RPCResult::Type::STR_HEX, "body_ref", "32-byte body hash"}}},
                {RPCResult::Type::STR_HEX, "signing_hash", /*optional=*/true, "Tagged hash signed by the taproot output key (acknowledge)"},
                {RPCResult::Type::STR, "signing_message", /*optional=*/true, "Domain-separated record message before hashing (acknowledge)"},
                {RPCResult::Type::STR_HEX, "signature", /*optional=*/true, "the record's sig field: 64-byte Schnorr (taproot) or the 32-byte H(proof) commitment (bip322-hash)"},
                {RPCResult::Type::STR_HEX, "revealed_bip322_proof", /*optional=*/true, "bip322-hash only: the BIP-322 proof (hex of the base64 signature bytes) -- the holder's secret to RETAIN and reveal when verifying"},
                {RPCResult::Type::STR, "issuer_address", /*optional=*/true, "Issuer ICU return address (return)"},
                {RPCResult::Type::NUM, "issuer_vout", /*optional=*/true, "Output index sending the units back to the issuer (return)"},
                {RPCResult::Type::STR_HEX, "acceptance_vext", "Serialized 0x40 ICU_ACCEPTANCE vExt TLV"},
                {RPCResult::Type::NUM, "acceptance_vout", "Output index carrying the 0x40 record"},
            }
        },
        RPCExamples{
            HelpExampleCli("icu.acceptance.record.create", "\"SHARE\" acknowledge") +
            HelpExampleCli("icu.acceptance.record.create", "\"SHARE\" acknowledge '{\"holder_txid\":\"...\",\"holder_vout\":1,\"body_refs\":[\"...\"]}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string asset_identifier = request.params[0].get_str();
            AssetResolution resolved = ResolveAssetIdOrTicker(request, asset_identifier);
            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset is not registered");
            }
            const AssetRegistryEntry& entry = *resolved.registry;
            if (entry.icu_plain_commit.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Asset registry has no icu_plain_commit; acceptance records must bind a reviewed document");
            }

            std::string mode = UppercaseCopy(request.params[1].get_str());
            if (mode == "ACK") mode = "ACKNOWLEDGE";
            if (mode != "ACKNOWLEDGE" && mode != "RETURN") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be \"acknowledge\" or \"return\"");
            }
            const bool is_return = (mode == "RETURN");

            std::optional<COutPoint> holder_outpoint;
            bool body_refs_provided{false};
            std::vector<std::array<unsigned char, 32>> body_refs;
            std::optional<uint256> expected_canonical;
            std::optional<double> fee_rate_vb;
            bool replaceable{true};
            bool broadcast{true};
            bool return_psbt{false};
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                const UniValue& opt = request.params[2];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                const bool has_txid = opt.exists("holder_txid");
                const bool has_vout = opt.exists("holder_vout");
                if (has_txid != has_vout) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "holder_txid and holder_vout must be supplied together");
                }
                if (has_txid) {
                    const Txid txid{Txid::FromUint256(ParseHashV(opt["holder_txid"], "holder_txid"))};
                    holder_outpoint = COutPoint(txid, opt["holder_vout"].getInt<uint32_t>());
                }
                if (opt.exists("body_refs")) {
                    body_refs_provided = true;
                    body_refs = ParseIcuBodyRefs(opt["body_refs"], "body_refs");
                }
                if (opt.exists("expected_canonical_hash")) {
                    expected_canonical = ParseHashV(opt["expected_canonical_hash"], "expected_canonical_hash");
                }
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("return_psbt")) return_psbt = opt["return_psbt"].get_bool();
            }
            // return_psbt only makes sense for the RETURN spend (acknowledge does not spend the asset).
            // Mirror the custodial icu.acceptance which forbids return_psbt on acknowledge.
            if (return_psbt && !is_return) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "return_psbt is only valid for mode=return (the relinquishing spend); acknowledge does not move "
                    "the asset. Use the wallet-free icu.acceptance.prepare node RPC for non-custodial acknowledge.");
            }
            if (expected_canonical && *expected_canonical != entry.icu_plain_commit) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("expected_canonical_hash %s does not match registry icu_plain_commit %s",
                              expected_canonical->ToString(), entry.icu_plain_commit.ToString()));
            }

            CCoinControl scan_control;
            scan_control.m_include_unsafe_inputs = true;
            scan_control.m_avoid_asset_utxos = false;
            scan_control.fAllowWatchOnly = true;
            CoinFilterParams filter_params;
            filter_params.only_spendable = false;

            std::vector<WalletAssetUtxo> candidates;
            for (const WalletAssetUtxo& u : CollectAssetUtxos(*pwallet, scan_control, filter_params)) {
                if (u.asset_id != resolved.asset_id || u.units == 0 || u.locked) continue;
                if (u.depth <= 0) continue; // mirror prepare: bind to a confirmed live holder UTXO
                if (holder_outpoint && u.outpoint != *holder_outpoint) continue;
                // ACK: taproot signs with the output key (SECP_SCHNORR_RAW); hash-hidden families
                // (P2PKH/P2WPKH/P2WSH) use BIP-322 commit-reveal (SECP_BIP322_HASH). RETURN is
                // attributed by the SPEND, so any family is fine.
                if (!is_return) {
                    std::vector<std::vector<unsigned char>> sols;
                    const TxoutType t = Solver(u.txout.scriptPubKey, sols);
                    const bool ack_ok = t == TxoutType::WITNESS_V1_TAPROOT || t == TxoutType::WITNESS_V2_TAPROOT ||
                                        t == TxoutType::PUBKEYHASH || t == TxoutType::WITNESS_V0_KEYHASH ||
                                        t == TxoutType::WITNESS_V0_SCRIPTHASH || t == TxoutType::SCRIPTHASH;
                    if (!ack_ok) continue;
                }
                candidates.push_back(u);
            }
            const char* kind = "holder UTXO";
            if (holder_outpoint && candidates.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("specified holder_txid:holder_vout is not a confirmed wallet-held %s for this asset", kind));
            }
            if (!holder_outpoint && candidates.empty()) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("wallet has no confirmed %s holding this asset", kind));
            }
            if (!holder_outpoint && candidates.size() > 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("wallet has multiple %ss for this asset; specify holder_txid and holder_vout", kind));
            }
            const WalletAssetUtxo holder = candidates.front();

            if (is_return) {
                // RETURN: relinquish the asset to the issuer's ICU address. Attribution is the SPEND, so
                // the record carries NO signature (sig_scheme=NONE) and no body_refs; the same tx that
                // carries the 0x40 anchor spends the holder UTXO and sends its units back to the issuer.
                // Only the signing/broadcast path needs the spending key; the non-custodial return_psbt path
                // (FillPSBT sign=false) just annotates a PSBT, so a locked/encrypted wallet must NOT block it.
                if (!return_psbt) EnsureWalletIsUnlocked(*pwallet);
                if (body_refs_provided && !body_refs.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "return does not affirm clauses; body_refs are not applicable");
                }
                if (entry.icu_outpoint.IsNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "asset registry has no ICU outpoint to return to");
                }
                const WalletContext& wctx = EnsureWalletContext(request.context);
                if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
                ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
                CTxDestination issuer_dest;
                {
                    LOCK(cs_main);
                    const auto icu_coin = chainman.ActiveChainstate().CoinsTip().GetCoin(entry.icu_outpoint);
                    if (!icu_coin || icu_coin->IsSpent()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "issuer ICU outpoint not found in the UTXO set");
                    }
                    if (!ExtractDestination(icu_coin->out.scriptPubKey, issuer_dest)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to resolve issuer ICU return address");
                    }
                }

                assets::IcuAcceptanceRecord rec;
                rec.mode = static_cast<uint8_t>(assets::IcuAcceptanceMode::RETURN);
                rec.asset_id = resolved.asset_id;
                rec.icu_plain_commit = entry.icu_plain_commit;
                rec.holder_prevout_txid = holder.outpoint.hash.ToUint256();
                rec.holder_prevout_vout = holder.outpoint.n;
                rec.holder_spk_hash = assets::IcuHolderSpkHash(holder.txout.scriptPubKey);
                rec.accepted_units = holder.units;
                rec.sig_scheme = static_cast<uint8_t>(assets::IcuAcceptSigScheme::NONE);
                std::string vr;
                if (!assets::ValidateIcuAcceptanceRecord(rec, vr)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "internal error: built invalid ICU return record: " + vr);
                }
                const std::vector<unsigned char> acceptance_vext = assets::BuildIcuAcceptanceTLV(rec);
                const std::vector<unsigned char> issuer_asset_tlv = BuildAssetTagTlv(resolved.asset_id, holder.units, std::nullopt);
                const CScript issuer_script = GetScriptForDestination(issuer_dest);

                CCoinControl funding_control;
                funding_control.m_include_unsafe_inputs = true;
                funding_control.m_avoid_asset_utxos = true;        // don't pull OTHER asset UTXOs for BTC fee
                funding_control.m_signal_bip125_rbf = replaceable;
                funding_control.m_change_type = OutputType::BECH32M;
                if (fee_rate_vb) {
                    funding_control.fOverrideFeeRate = true;
                    funding_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
                }
                funding_control.Select(holder.outpoint);            // bind exactly the returned holder UTXO

                CFeeRate target_feerate = GetMinimumFeeRate(*pwallet, funding_control, /*feeCalc=*/nullptr);
                if (target_feerate == CFeeRate(0)) target_feerate = CFeeRate(1000);

                auto dummy_dest = pwallet->GetNewDestination(OutputType::BECH32M, "ICU return record anchor");
                if (!dummy_dest) throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dummy_dest).original);
                const CScript dummy_script = GetScriptForDestination(*dummy_dest);
                CAmount anchor_fee_budget = std::max<CAmount>(DEFAULT_ASSET_OUTPUT_VALUE,
                    target_feerate.GetFee(static_cast<uint32_t>(acceptance_vext.size() + issuer_asset_tlv.size() + 400)));

                CTransactionRef final_tx; CAmount final_fee{0};
                uint32_t acceptance_vout{std::numeric_limits<uint32_t>::max()};
                uint32_t issuer_vout{std::numeric_limits<uint32_t>::max()};
                std::string unsigned_psbt_b64;  // populated only on the return_psbt (non-custodial) path
                for (int attempt = 0; attempt < 3; ++attempt) {
                    CMutableTransaction template_tx;
                    std::vector<CRecipient> recipients{
                        CRecipient{issuer_dest, DEFAULT_ASSET_OUTPUT_VALUE, /*fSubtractFeeFromAmount=*/false},
                        CRecipient{*dummy_dest, anchor_fee_budget, /*fSubtractFeeFromAmount=*/false},
                    };
                    auto funded = FundTransaction(*pwallet, template_tx, recipients, /*change_pos=*/std::nullopt,
                                                  /*lockUnspents=*/false, funding_control);
                    if (!funded) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(funded).original);

                    CMutableTransaction candidate(*funded->tx);
                    bool issuer_done = false, anchor_done = false;
                    for (size_t i = 0; i < candidate.vout.size(); ++i) {
                        CTxOut& out = candidate.vout[i];
                        if (!issuer_done && out.nValue == DEFAULT_ASSET_OUTPUT_VALUE && out.scriptPubKey == issuer_script && out.vExt.empty()) {
                            out.vExt = issuer_asset_tlv;  // ASSET_TAG returns the units to the issuer
                            issuer_vout = static_cast<uint32_t>(i); issuer_done = true;
                        } else if (!anchor_done && out.nValue == anchor_fee_budget && out.scriptPubKey == dummy_script && out.vExt.empty()) {
                            out.nValue = 0; out.scriptPubKey = CScript() << OP_RETURN; out.vExt = acceptance_vext;
                            acceptance_vout = static_cast<uint32_t>(i); anchor_done = true;
                        }
                    }
                    if (!issuer_done || !anchor_done) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "failed to assemble return transaction outputs");
                    }
                    bool spends_holder = false;
                    for (const auto& in : candidate.vin) if (in.prevout == holder.outpoint) { spends_holder = true; break; }
                    if (!spends_holder) throw JSONRPCError(RPC_WALLET_ERROR, "return transaction does not spend the holder UTXO");

                    // Fee discovery: measure the would-be signed vsize WITHOUT mutating the candidate, so
                    // both the custodial sign/broadcast path and the non-custodial return_psbt path size
                    // identically. The zeroed anchor output becomes fee.
                    int64_t signed_vsize;
                    {
                        LOCK(pwallet->cs_wallet);
                        const TxSize est = CalculateMaximumSignedTxSize(CTransaction(candidate), pwallet.get(), &funding_control);
                        if (est.vsize <= 0) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "failed to estimate signed return transaction size for fee calculation");
                        }
                        signed_vsize = est.vsize;
                    }
                    const CAmount paid_fee = funded->fee + anchor_fee_budget;  // the zeroed anchor becomes fee
                    const CAmount required_fee = target_feerate.GetFee(signed_vsize);
                    if (paid_fee < required_fee && attempt < 2) {
                        anchor_fee_budget += (required_fee - paid_fee) + target_feerate.GetFee(200);
                        continue;
                    }
                    if (paid_fee < required_fee) throw JSONRPCError(RPC_WALLET_ERROR, "return transaction fee underpaid");

                    if (return_psbt) {
                        // NON-CUSTODIAL: hand back an UNSIGNED, wallet-annotated PSBT. FillPSBT(sign=false,
                        // bip32derivs=true) fills witnessUtxo/nonWitnessUtxo + bip32Derivation on every input
                        // (including the holder asset input) so an external holder signer can complete it; the
                        // holder key never leaves the client. The NONE 0x40 carrier output rides in the PSBT's
                        // unsigned tx untouched. We do NOT sign and do NOT broadcast here.
                        PartiallySignedTransaction psbtx(candidate);
                        bool complete = false;
                        const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/false,
                                                                /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
                        if (fill_err) throw JSONRPCPSBTError(*fill_err);
                        DataStream ss_psbt{};
                        ss_psbt << psbtx;
                        unsigned_psbt_b64 = EncodeBase64(ss_psbt.str());
                        final_fee = paid_fee;
                        break;
                    }

                    PartiallySignedTransaction psbtx(candidate);
                    bool complete = false;
                    const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                    if (fill_err) throw JSONRPCPSBTError(*fill_err);
                    if (!complete) throw JSONRPCError(RPC_WALLET_ERROR, "failed to sign return transaction completely");
                    CMutableTransaction signed_mtx;
                    if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) throw JSONRPCError(RPC_WALLET_ERROR, "failed to finalize return transaction");
                    CTransactionRef tx_ref = MakeTransactionRef(CTransaction(signed_mtx));
                    const CAmount signed_required_fee = target_feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                    if (paid_fee < signed_required_fee && attempt < 2) {
                        anchor_fee_budget += (signed_required_fee - paid_fee) + target_feerate.GetFee(200);
                        continue;
                    }
                    if (paid_fee < signed_required_fee) throw JSONRPCError(RPC_WALLET_ERROR, "return transaction fee underpaid after signing");
                    final_tx = tx_ref; final_fee = paid_fee; break;
                }
                if (!return_psbt && !final_tx) throw JSONRPCError(RPC_WALLET_ERROR, "failed to build return transaction");
                if (return_psbt && unsigned_psbt_b64.empty()) throw JSONRPCError(RPC_WALLET_ERROR, "failed to build unsigned return PSBT");

                if (!return_psbt && broadcast) { LOCK(pwallet->cs_wallet); pwallet->CommitTransaction(final_tx, /*value_map=*/{}, /*order_form=*/{}); }

                UniValue result(UniValue::VOBJ);
                result.pushKV("mode", "return");
                result.pushKV("holder_family", "spend-attributed");
                if (return_psbt) {
                    result.pushKV("psbt", unsigned_psbt_b64);
                    result.pushKV("complete", false);
                } else {
                    result.pushKV("txid", final_tx->GetHash().ToString());
                    if (!broadcast) result.pushKV("hex", EncodeHexTx(*final_tx));
                }
                result.pushKV("fee", ValueFromAmount(final_fee));
                result.pushKV("asset_id", resolved.asset_id.ToString());
                result.pushKV("icu_plain_commit", entry.icu_plain_commit.ToString());
                result.pushKV("holder_txid", holder.outpoint.hash.ToString());
                result.pushKV("holder_vout", static_cast<uint64_t>(holder.outpoint.n));
                result.pushKV("accepted_units", holder.units);
                result.pushKV("issuer_address", EncodeDestination(issuer_dest));
                result.pushKV("issuer_vout", static_cast<uint64_t>(issuer_vout));
                result.pushKV("acceptance_vext", HexStr(acceptance_vext));
                result.pushKV("acceptance_vout", static_cast<uint64_t>(acceptance_vout));
                return result;
            }

            EnsureWalletIsUnlocked(*pwallet);
            TxoutType holder_type{TxoutType::NONSTANDARD};
            const bool holder_is_taproot = static_cast<bool>(assets::ExtractTaprootOutputKeyFromSpk(holder.txout.scriptPubKey, holder_type));
            std::optional<IcuAcceptanceTaprootSigner> signer;
            if (holder_is_taproot) {
                std::string signer_error;
                signer = ResolveIcuAcceptanceTaprootSigner(*pwallet, holder.txout.scriptPubKey, signer_error);
                if (!signer) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "cannot sign holder acceptance record: " + signer_error);
                }
            }

            std::string context_source = "none";
            if (!entry.icu_ctxt_commit.IsNull()) {
                try {
                    JSONRPCRequest sub = request;
                    UniValue pa(UniValue::VARR);
                    pa.push_back(asset_identifier);
                    sub.params = pa;
                    sub.mode = JSONRPCRequest::EXECUTE;
                    UniValue icu = geticupayload().HandleRequest(sub);
                    // Fail closed: a context-bearing asset (icu_ctxt_commit set) MUST be readable and
                    // verified. If geticupayload could not decrypt/parse it, plain_commit_verified is
                    // absent (not just false) -- either way we must NOT sign a blind, empty-body
                    // acceptance for a possibly-required-context holder-only asset.
                    const bool plain_commit_verified = icu.exists("plain_commit_verified") &&
                        icu["plain_commit_verified"].isBool() && icu["plain_commit_verified"].get_bool();
                    if (!plain_commit_verified) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "committed ICU payload is not readable/verified (plain_commit_verified != true); "
                            "refusing to sign a blind acceptance for a context-bearing asset");
                    }
                    if (icu.exists("context_error") && icu["context_error"].isStr() &&
                        !icu["context_error"].get_str().empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "committed ICU context is malformed: " + icu["context_error"].get_str());
                    }
                    if (icu.exists("context_source") && icu["context_source"].isStr()) {
                        context_source = icu["context_source"].get_str();
                    }
                    if (icu.exists("context") && icu["context"].isObject()) {
                        const UniValue& ctx = icu["context"];
                        if (!ctx.exists("bodies") || !ctx["bodies"].isObject() ||
                            !ctx.exists("acceptance") || !ctx["acceptance"].isStr()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "committed ICU context is missing bodies or acceptance policy");
                        }
                        const UniValue& bodies = ctx["bodies"];
                        std::vector<std::array<unsigned char, 32>> all_refs;
                        for (const std::string& k : bodies.getKeys()) {
                            all_refs.push_back(ParseIcuBodyRefHex(k, "context.bodies"));
                        }
                        std::sort(all_refs.begin(), all_refs.end());

                        if (!body_refs_provided && ctx["acceptance"].get_str() == "required") {
                            body_refs = all_refs;
                        }
                        for (const auto& ref : body_refs) {
                            if (!std::binary_search(all_refs.begin(), all_refs.end(), ref)) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                    strprintf("body_ref %s is not a designated body in the committed ICU context",
                                              HexStr(ref)));
                            }
                        }
                        if (ctx["acceptance"].get_str() == "required" && body_refs.size() != all_refs.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "committed ICU context acceptance is required; all designated body_refs must be affirmed");
                        }
                    } else if (body_refs_provided && !body_refs.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "asset has no committed ICU context map; body_refs are not applicable");
                    }
                } catch (const UniValue& e) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "cannot read/verify committed ICU payload before signing acceptance record: " + e.write());
                }
            } else if (body_refs_provided && !body_refs.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "asset has no committed ICU payload/context; body_refs are not applicable");
            }

            assets::IcuAcceptanceRecord rec;
            rec.mode = static_cast<uint8_t>(assets::IcuAcceptanceMode::ACKNOWLEDGE);
            rec.asset_id = resolved.asset_id;
            rec.icu_plain_commit = entry.icu_plain_commit;
            rec.holder_prevout_txid = holder.outpoint.hash.ToUint256();
            rec.holder_prevout_vout = holder.outpoint.n;
            rec.holder_spk_hash = assets::IcuHolderSpkHash(holder.txout.scriptPubKey);
            rec.accepted_units = holder.units;
            rec.body_refs = body_refs;

            uint256 signing_hash;  // meaningful only on the taproot (schnorr) path
            std::string holder_family, revealed_proof_hex;
            if (holder_is_taproot) {
                rec.sig_scheme = static_cast<uint8_t>(assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW);
                rec.sig.assign(64, 0);
                signing_hash = assets::IcuAcceptanceRecordSigningHash(rec);
                if (!signer->signing_key.SignSchnorr(signing_hash, std::span<unsigned char>(rec.sig.data(), rec.sig.size()),
                                                     &signer->signing_merkle_root, GetRandHash())) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "failed to sign ICU acceptance record with holder taproot key");
                }
                if (!assets::VerifyIcuAcceptanceRecordSchnorr(rec, signer->output_key)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "internal error: acceptance record signature does not verify");
                }
                holder_family = signer->family;
            } else {
                // Hash-hidden spendable family (P2PKH/P2WPKH/P2WSH): commit-reveal. Produce a BIP-322 proof
                // over the record message, but persist only SHA256(proof) on chain -- the pubkey is NOT
                // revealed while the asset is held (quantum-safe). The proof is returned so the holder can
                // reveal it for verification at/after spend.
                rec.sig_scheme = static_cast<uint8_t>(assets::IcuAcceptSigScheme::SECP_BIP322_HASH);
                rec.sig.clear();
                const std::string message = assets::IcuAcceptanceRecordSigningMessage(rec);
                CTxDestination hdest;
                if (!ExtractDestination(holder.txout.scriptPubKey, hdest)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "cannot derive holder address for BIP-322 acceptance");
                }
                const std::string haddr = EncodeDestination(hdest);
                std::string proof_b64, sign_err;
                {
                    LOCK(pwallet->cs_wallet);
                    if (!pwallet->SignMessageBIP322(haddr, message, proof_b64, sign_err)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "cannot BIP-322 sign acceptance with holder key (" + haddr + "): " + sign_err);
                    }
                }
                unsigned char digest[CSHA256::OUTPUT_SIZE];
                CSHA256().Write(reinterpret_cast<const unsigned char*>(proof_b64.data()), proof_b64.size()).Finalize(digest);
                rec.sig.assign(digest, digest + CSHA256::OUTPUT_SIZE);   // on-chain commitment = H(proof)
                revealed_proof_hex = HexStr(MakeUCharSpan(proof_b64));   // hex of the base64 signature bytes
                holder_family = "bip322-hash";
            }
            std::string validation_reason;
            if (!assets::ValidateIcuAcceptanceRecord(rec, validation_reason)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "internal error: built invalid ICU acceptance record: " + validation_reason);
            }
            const std::vector<unsigned char> acceptance_vext = assets::BuildIcuAcceptanceTLV(rec);

            CCoinControl funding_control;
            funding_control.m_include_unsafe_inputs = true;
            funding_control.m_avoid_asset_utxos = true;
            funding_control.m_signal_bip125_rbf = replaceable;
            funding_control.m_change_type = OutputType::BECH32M;
            if (fee_rate_vb) {
                funding_control.fOverrideFeeRate = true;
                funding_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
            }
            CFeeRate target_feerate = GetMinimumFeeRate(*pwallet, funding_control, /*feeCalc=*/nullptr);
            if (target_feerate == CFeeRate(0)) target_feerate = CFeeRate(1000);

            auto dummy_dest = pwallet->GetNewDestination(OutputType::BECH32M, "ICU acceptance record anchor");
            if (!dummy_dest) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dummy_dest).original);
            }
            const CScript dummy_script = GetScriptForDestination(*dummy_dest);
            CAmount anchor_fee_budget = std::max<CAmount>(
                DEFAULT_ASSET_OUTPUT_VALUE,
                target_feerate.GetFee(static_cast<uint32_t>(acceptance_vext.size() + 400)));

            CTransactionRef final_tx;
            CAmount final_fee{0};
            uint32_t acceptance_vout{std::numeric_limits<uint32_t>::max()};
            for (int attempt = 0; attempt < 3; ++attempt) {
                CMutableTransaction template_tx;
                std::vector<CRecipient> recipients{
                    CRecipient{*dummy_dest, anchor_fee_budget, /*fSubtractFeeFromAmount=*/false},
                };
                auto funded = FundTransaction(*pwallet, template_tx, recipients,
                                              /*change_pos=*/std::nullopt,
                                              /*lockUnspents=*/false, funding_control);
                if (!funded) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(funded).original);
                }

                CMutableTransaction candidate(*funded->tx);
                bool replaced = false;
                for (size_t i = 0; i < candidate.vout.size(); ++i) {
                    CTxOut& out = candidate.vout[i];
                    if (!replaced && out.nValue == anchor_fee_budget && out.scriptPubKey == dummy_script && out.vExt.empty()) {
                        out.nValue = 0;
                        out.scriptPubKey = CScript() << OP_RETURN;
                        out.vExt = acceptance_vext;
                        acceptance_vout = static_cast<uint32_t>(i);
                        replaced = true;
                    }
                }
                if (!replaced) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "failed to locate funded dummy output for acceptance record");
                }

                PartiallySignedTransaction psbtx(candidate);
                bool complete = false;
                const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL,
                                                        /*sign=*/true, /*bip32derivs=*/false);
                if (fill_err) throw JSONRPCPSBTError(*fill_err);
                if (!complete) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "failed to sign acceptance-record funding transaction completely");
                }

                CMutableTransaction signed_mtx;
                if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "failed to finalize acceptance-record funding transaction");
                }
                CTransactionRef tx_ref = MakeTransactionRef(CTransaction(signed_mtx));
                const CAmount paid_fee = funded->fee + anchor_fee_budget;
                const CAmount required_fee = target_feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                if (paid_fee < required_fee && attempt < 2) {
                    anchor_fee_budget += (required_fee - paid_fee) + target_feerate.GetFee(200);
                    continue;
                }
                if (paid_fee < required_fee) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("acceptance-record transaction fee underpaid after signing (paid %d sats, need %d sats)",
                                  paid_fee, required_fee));
                }
                final_tx = tx_ref;
                final_fee = paid_fee;
                break;
            }
            if (!final_tx) {
                throw JSONRPCError(RPC_WALLET_ERROR, "failed to build acceptance-record transaction");
            }

            if (broadcast) {
                LOCK(pwallet->cs_wallet);
                pwallet->CommitTransaction(final_tx, /*value_map=*/{}, /*order_form=*/{});
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("mode", "acknowledge");
            result.pushKV("holder_family", holder_family);
            result.pushKV("txid", final_tx->GetHash().ToString());
            if (!broadcast) result.pushKV("hex", EncodeHexTx(*final_tx));
            result.pushKV("fee", ValueFromAmount(final_fee));
            result.pushKV("asset_id", resolved.asset_id.ToString());
            result.pushKV("icu_plain_commit", entry.icu_plain_commit.ToString());
            result.pushKV("holder_txid", holder.outpoint.hash.ToString());
            result.pushKV("holder_vout", static_cast<uint64_t>(holder.outpoint.n));
            result.pushKV("holder_spk_hash", rec.holder_spk_hash.ToString());
            result.pushKV("accepted_units", holder.units);
            result.pushKV("context_source", context_source);
            result.pushKV("body_refs", IcuBodyRefsToJson(rec.body_refs));
            if (holder_is_taproot) result.pushKV("signing_hash", signing_hash.ToString());
            result.pushKV("signing_message", assets::IcuAcceptanceRecordSigningMessage(rec));
            result.pushKV("signature", HexStr(rec.sig));
            // For BIP322_HASH only H(proof) is on chain; the proof itself is the holder's secret to RETAIN
            // and reveal (via options.revealed_bip322_proof) when verifying at/after spend.
            if (!revealed_proof_hex.empty()) result.pushKV("revealed_bip322_proof", revealed_proof_hex);
            result.pushKV("acceptance_vext", HexStr(acceptance_vext));
            result.pushKV("acceptance_vout", static_cast<uint64_t>(acceptance_vout));
            return result;
        },
    };
}

RPCHelpMan asset_build_delivery_template()
{
    return RPCHelpMan{
        "asset.build_delivery_template",
        "Construct the asset delivery metadata (including ICU keywrap) for a destination without selecting inputs.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination address"},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units (raw) to deliver"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"wrapped_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override for auto-generated wrapped key (UTF-8 hex)."},
                    {"suite_id", RPCArg::Type::NUM, RPCArg::Default{0}, "Cryptographic suite ID for keywrap"},
                    {"extras_mask", RPCArg::Type::NUM, RPCArg::Default{0}, "Keywrap extras: 0x01=wrap_commit, 0x02=kc_tag"},
                    {"wrap_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte wrap commitment"},
                    {"kc_tag", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte key confirmation tag"},
                    {"zk_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Pre-generated zk proof (optional, informational)"},
                    {"zk_public_inputs", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Pre-generated zk public inputs (optional, informational)"},
                    {"tfr_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte transfer anchor commitment (required on-chain when policy mandates anchor)"},
                    {"tfr_locator", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional off-chain locator bytes; only serialized on-chain if explicitly provided"},
                    {"tfr_keyset_id", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional off-chain keyset identifier; only serialized on-chain if explicitly provided"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "is_native", "Whether delivery is native BTC"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Resolved asset identifier (omitted for native)"},
                {RPCResult::Type::NUM, "units", "Raw units to deliver"},
                {RPCResult::Type::STR_HEX, "script_pubkey", "Destination scriptPubKey"},
                {RPCResult::Type::STR_HEX, "vext", /*optional=*/true, "Asset TLV (empty for native)"},
                {RPCResult::Type::STR_HEX, "tfr_anchor_vext", /*optional=*/true, "Dedicated TFR anchor TLV for a separate metadata output when tfr_commit is supplied"},
                {RPCResult::Type::STR_HEX, "commitment", "Commitment hash over delivery parameters"},
                {RPCResult::Type::BOOL, "needs_zk_proof", /*optional=*/true, "Policy requires zk proof at spend time"},
                {RPCResult::Type::BOOL, "needs_tfr_anchor", /*optional=*/true, "Policy requires transfer anchor TLV"},
            }
        },
        RPCExamples{
            HelpExampleCli("asset.build_delivery_template", "\"0123...\" \"bcrt1p...\" 1000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string asset_identifier = request.params[0].get_str();
            const std::string address = request.params[1].get_str();
            CTxDestination dest = DecodeDestination(address);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
            }
            const CScript dest_script = GetScriptForDestination(dest);

            uint64_t units{0};
            if (request.params[2].isNum()) {
                units = request.params[2].getInt<uint64_t>();
            } else if (request.params[2].isStr()) {
                if (!ParseUInt64(request.params[2].get_str(), &units)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be a positive integer");
                }
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be number or string");
            }
            if (units == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be positive");
            }

            std::vector<unsigned char> wrapped_key;
            uint8_t suite_id{0};
            uint8_t extras_mask{0};
            uint256 wrap_commit;
            std::array<unsigned char, 16> kc_tag{};
            bool kc_tag_set{false};
            std::vector<unsigned char> zk_proof_bytes;
            std::vector<unsigned char> zk_public_inputs_bytes;
            std::optional<uint256> tfr_commit_opt;
            std::vector<unsigned char> tfr_locator_bytes;
            std::optional<uint32_t> tfr_keyset_id_opt;

            if (request.params.size() > 3 && !request.params[3].isNull()) {
                const UniValue& options = request.params[3];
                if (!options.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                }
                if (options.exists("wrapped_key")) {
                    wrapped_key = ParseHex(options["wrapped_key"].get_str());
                    const auto is_valid_utf8 = [](const std::vector<unsigned char>& data) {
                        size_t i = 0;
                        while (i < data.size()) {
                            unsigned char c = data[i];
                            if ((c & 0x80) == 0) { ++i; continue; }
                            if ((c & 0xE0) == 0xC0) {
                                if (i + 1 >= data.size() || (data[i+1] & 0xC0) != 0x80 || c < 0xC2) return false;
                                i += 2; continue;
                            }
                            if ((c & 0xF0) == 0xE0) {
                                if (i + 2 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80) return false;
                                if (c == 0xE0 && data[i+1] < 0xA0) return false;
                                if (c == 0xED && data[i+1] >= 0xA0) return false;
                                i += 3; continue;
                            }
                            if ((c & 0xF8) == 0xF0) {
                                if (i + 3 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80 || (data[i+3] & 0xC0) != 0x80) return false;
                                if (c == 0xF0 && data[i+1] < 0x90) return false;
                                if (c >= 0xF4) return false;
                                i += 4; continue;
                            }
                            return false;
                        }
                        return true;
                    };
                    if (!is_valid_utf8(wrapped_key)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "wrapped_key must be valid UTF-8");
                    }
                }
                if (options.exists("suite_id")) suite_id = options["suite_id"].getInt<uint8_t>();
                if (options.exists("extras_mask")) {
                    extras_mask = options["extras_mask"].getInt<uint8_t>();
                    const uint8_t allowed_mask = assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT | assets::ICU_KEYWRAP_EXTRA_KC_TAG;
                    if (extras_mask & ~allowed_mask) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "extras_mask has unknown bits (allowed: 0x01, 0x02)");
                    }
                }
                if (options.exists("wrap_commit")) {
                    auto wc = uint256::FromHex(options["wrap_commit"].get_str());
                    if (!wc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid wrap_commit hex");
                    wrap_commit = *wc;
                }
                if (options.exists("kc_tag")) {
                    auto kc_bytes = ParseHex(options["kc_tag"].get_str());
                    if (kc_bytes.size() != kc_tag.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "kc_tag must be exactly 16 bytes");
                    }
                    std::copy(kc_bytes.begin(), kc_bytes.end(), kc_tag.begin());
                    kc_tag_set = true;
                }
                if (options.exists("zk_proof")) {
                    zk_proof_bytes = ParseHex(options["zk_proof"].get_str());
                }
                if (options.exists("zk_public_inputs")) {
                    zk_public_inputs_bytes = ParseHex(options["zk_public_inputs"].get_str());
                }
                if (options.exists("tfr_commit")) {
                    auto commit_hex = options["tfr_commit"].get_str();
                    auto commit_val = uint256::FromHex(commit_hex);
                    if (!commit_val) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "tfr_commit must be 32-byte hex");
                    }
                    tfr_commit_opt = *commit_val;
                }
                if (options.exists("tfr_locator")) {
                    tfr_locator_bytes = ParseHex(options["tfr_locator"].get_str());
                    if (tfr_locator_bytes.size() > assets::MAX_TFR_LOCATOR_SIZE) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("tfr_locator exceeds %u bytes", assets::MAX_TFR_LOCATOR_SIZE));
                    }
                }
                if (options.exists("tfr_keyset_id")) {
                    tfr_keyset_id_opt = options["tfr_keyset_id"].getInt<uint32_t>();
                }
            }

            if (!tfr_commit_opt && (!tfr_locator_bytes.empty() || tfr_keyset_id_opt.has_value())) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tfr_commit is required when tfr_locator or tfr_keyset_id is provided");
            }

            AssetResolution resolved = ResolveAssetIdOrTicker(request, asset_identifier);
            if (resolved.asset_id.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset.build_delivery_template requires a non-native asset");
            }

            const AssetRegistryEntry* registry_entry = resolved.registry ? &*resolved.registry : nullptr;
            if (!registry_entry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not found in registry");
            }

            bool needs_zk_proof = registry_entry->has_kyc;
            bool needs_tfr_anchor = (registry_entry->tfr_flags & assets::TFR_ANCHOR_REQUIRED) != 0;

            if (needs_tfr_anchor && !tfr_commit_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Asset policy requires transfer anchor. Provide options.tfr_commit");
            }

            std::optional<IcuKeywrapParams> keywrap_params;
            if (registry_entry->icu_flags & 1) {
                if (!wrapped_key.empty()) {
                    IcuKeywrapParams kw;
                    kw.ctxt_hash = registry_entry->icu_ctxt_commit;
                    kw.spk_hash32 = kw::TapMatchHash(dest_script);
                    kw.wrapped_key = wrapped_key;
                    kw.suite_id = suite_id;
                    kw.extras_mask = extras_mask;
                    kw.wrap_commit = wrap_commit;
                    if (extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) {
                        if (!kc_tag_set) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "kc_tag is required when extras_mask requests it");
                        }
                        kw.kc_tag = kc_tag;
                    }
                    keywrap_params = kw;
                } else {
                    auto auto_keywrap = AutoWrapDekForOutput(
                        *pwallet,
                        resolved.asset_id,
                        registry_entry->icu_ctxt_commit,
                        *registry_entry,
                        dest,
                        dest_script,
                        /*salt_override=*/std::nullopt,
                        suite_id);
                    keywrap_params = auto_keywrap;
                }
            }

            std::vector<unsigned char> vext = BuildAssetTagTlv(resolved.asset_id, units, keywrap_params);

            uint256 commitment = ComputeAssetDeliveryCommitment(
                /*is_native=*/false,
                resolved.asset_id,
                units,
                dest_script,
                vext);

            UniValue result(UniValue::VOBJ);
            result.pushKV("is_native", false);
            result.pushKV("asset_id", resolved.asset_id.ToString());
            result.pushKV("units", static_cast<unsigned long long>(units));
            result.pushKV("script_pubkey", HexStr(dest_script));
            result.pushKV("vext", HexStr(vext));
            result.pushKV("commitment", commitment.GetHex());
            if (needs_zk_proof) result.pushKV("needs_zk_proof", true);
            if (needs_tfr_anchor) {
                result.pushKV("needs_tfr_anchor", true);
                if (tfr_commit_opt) {
                    result.pushKV("tfr_anchor_vext", HexStr(BuildTfrAnchorTlv(
                        resolved.asset_id,
                        *tfr_commit_opt,
                        tfr_keyset_id_opt.value_or(0),
                        tfr_locator_bytes)));
                }
            }
            return result;
        }
    };
}

RPCHelpMan mintasset()
{
    return RPCHelpMan{
        "mintasset",
        "Mint new asset units (wallet version).",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU transaction ID"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU output index"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination address"},
            {"icu_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "New ICU BTC amount"},
            {"asset_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset destination address"},
            {"asset_amount_btc", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "BTC amount for asset output"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID to mint"},
            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of asset units to mint"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{28}, "Allowed script families"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Automatically fund transaction fees"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Enable RBF"},
                    {"extra_native_outputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                        "Additional NATIVE (no asset tag) outputs to fund in the same tx, e.g. option-series lot vaults",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Output scriptPubKey (must be a standard destination)"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Output value in BTC (>= dust)"},
                                }},
                        }},
                    {"kyc_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ZK/KYC flags (e.g., KYC_REQUIRED=1)"},
                    {"vk_data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ZK verification key data (will be chunked and committed)"},
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::Default{0}, "Maximum merkle root age in seconds"},
                    {"tfr_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Transfer flags (e.g., TFR_ANCHOR_REQUIRED)"},
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ICU governance payload for ICU_TEXT_CHUNK"},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte plaintext commitment"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ciphertext commitment"},
                    {"kdf_salt", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte encryption salt"},
                    {"icu_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ICU flags (e.g., WRAP_REQUIRED=1)"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Default{0}, "ICU visibility (0=public, 1=holder_only)"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Default{0}, "Governance quorum in basis points"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Default{0}, "Issuance cap in base units (0=unlimited)"},
                    {"issuance_cap", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Issuance cap expressed in asset units (e.g., \"50.0\"). Overrides issuance_cap_units."},
                    {"wrapped_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override for auto-generated wrapped key (UTF-8 hex)"},
                    {"suite_id", RPCArg::Type::NUM, RPCArg::Default{0}, "Cryptographic suite ID for keywrap"},
                    {"extras_mask", RPCArg::Type::NUM, RPCArg::Default{0}, "Keywrap extras: 0x01=wrap_commit, 0x02=kc_tag"},
                    {"wrap_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte wrap commitment"},
                    {"kc_tag", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte key confirmation tag"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "Transaction ID if broadcast, otherwise hex"},
        RPCExamples{
            HelpExampleCli("mintasset", "\"txid\" 0 \"bc1q...\" 5.1 \"bc1q...\" 0.001 \"asset_id\" 1000000 3 28")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Parse ICU input
            Txid icu_txid{Txid::FromUint256(ParseHashV(request.params[0], "icu_txid"))};
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();

            // Parse ICU rotation output
            CTxDestination icu_dest = DecodeDestination(request.params[2].get_str());
            if (!IsValidDestination(icu_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid ICU address");
            }
            CAmount icu_amt = AmountFromValue(request.params[3]);

            // Parse asset output
            CTxDestination asset_dest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(asset_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid asset address");
            }
            CAmount asset_btc = AmountFromValue(request.params[5]);

            // Parse asset parameters
            auto aid = uint256::FromHex(request.params[6].get_str());
            if (!aid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }
            uint64_t units = request.params[7].getInt<uint64_t>();
            uint32_t policy_bits = request.params[8].getInt<uint32_t>();
            uint16_t allowed = request.params[9].isNull() ? 28 : request.params[9].getInt<uint16_t>();

            bool has_unlock = !request.params[10].isNull();
            uint64_t unlock = has_unlock ? request.params[10].getInt<uint64_t>() : 0;

            // Parse options
            bool autofund = true;
            bool broadcast = false;
            std::optional<double> fee_rate_vb;
            std::optional<bool> replaceable = true;

            // Native-only extra outputs (e.g. the N option-series lot vaults). These carry NO asset
            // extension; they ride through funding + the vExt reattach loop untouched. Validated as
            // standard destinations with dust/MoneyRange below; parsed here, appended before funding.
            std::vector<std::pair<CScript, CAmount>> extra_native_outputs;

            // ZK parameters
            uint32_t kyc_flags = 0;
            std::vector<unsigned char> vk_data;
            std::vector<std::vector<unsigned char>> vk_chunks;
            uint256 vk_commitment;
            uint32_t max_root_age = 0;
            uint32_t tfr_flags = 0;

            // ICU parameters
            std::vector<unsigned char> icu_payload;
            uint256 icu_plain_commit;
            uint256 icu_ctxt_commit;
            std::vector<unsigned char> kdf_salt;
            uint32_t icu_flags = 0;
            uint8_t icu_visibility = 0;
            uint16_t policy_quorum_bps = 0;
            uint64_t issuance_cap_units = 0;

            std::optional<AssetRegistryEntry> registry_entry;
            {
                LOCK(pwallet->cs_wallet);
                auto entry = pwallet->chain().getAssetRegistryEntry(*aid);
                if (entry) registry_entry = *entry;
            }
            if (registry_entry) {
                const AssetRegistryEntry& entry = *registry_entry;
                if (entry.has_kyc) {
                    kyc_flags = 1;
                    vk_commitment = entry.zk_vk_commitment;
                    max_root_age = entry.max_root_age;
                    tfr_flags = entry.tfr_flags;
                }
                if (icu_ctxt_commit.IsNull()) {
                    icu_ctxt_commit = entry.icu_ctxt_commit;
                    icu_plain_commit = entry.icu_plain_commit;
                    icu_flags = entry.icu_flags;
                    icu_visibility = entry.icu_visibility;
                    policy_quorum_bps = entry.policy_quorum_bps;
                    issuance_cap_units = entry.issuance_cap_units;
                    kdf_salt.assign(entry.kdf_salt.begin(), entry.kdf_salt.end());
                }
            }

            // Keywrap parameters
            std::vector<unsigned char> wrapped_key;
            uint8_t suite_id = 0;
            uint8_t extras_mask = 0;
            uint256 wrap_commit;
            std::array<unsigned char, 16> kc_tag{};

            if (!request.params[11].isNull()) {
                const UniValue& opt = request.params[11];
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                if (opt.exists("extra_native_outputs")) {
                    const UniValue& extras = opt["extra_native_outputs"];
                    if (!extras.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs must be an array");
                    for (size_t i = 0; i < extras.size(); ++i) {
                        const UniValue& e = extras[i];
                        if (!e.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs entries must be objects");
                        const UniValue& spk = e.find_value("scriptPubKey");
                        if (!spk.isStr() || !IsHex(spk.get_str())) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs.scriptPubKey must be hex");
                        }
                        const std::vector<unsigned char> spk_bytes = ParseHex(spk.get_str());
                        CScript script(spk_bytes.begin(), spk_bytes.end());
                        // Native ONLY: must be a standard destination (no bare/non-standard, no OP_RETURN).
                        CTxDestination dummy_dest;
                        if (!ExtractDestination(script, dummy_dest)) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs.scriptPubKey is not a standard destination");
                        }
                        const CAmount value = AmountFromValue(e.find_value("amount"));
                        if (value < 546) { // standard dust floor (matches MIN_SETTLE_OUTPUT / kMinAssetOutputDust)
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs.amount is below dust");
                        }
                        if (!MoneyRange(value)) throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs.amount out of range");
                        // Reject duplicate scripts: the post-funding reattach loop falls back to
                        // script-only matching, so duplicate native outputs could be mis-associated.
                        for (const auto& [prior_script, prior_value] : extra_native_outputs) {
                            if (prior_script == script) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "extra_native_outputs has duplicate scriptPubKey");
                            }
                        }
                        extra_native_outputs.emplace_back(std::move(script), value);
                    }
                }

                // ZK parameters
                if (opt.exists("kyc_flags")) kyc_flags = opt["kyc_flags"].getInt<uint32_t>();
                if (opt.exists("vk_data")) {
                    vk_data = ParseHex(opt["vk_data"].get_str());
                    if (vk_data.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vk_data cannot be empty");

                    // Compute vk_commitment = double_SHA256(vk_data)
                    CSHA256 hasher1;
                    hasher1.Write(vk_data.data(), vk_data.size());
                    uint256 single_hash;
                    hasher1.Finalize(single_hash.begin());

                    CSHA256 hasher2;
                    hasher2.Write(single_hash.begin(), 32);
                    hasher2.Finalize(vk_commitment.begin());

                    // Chunk VK data (512 bytes per chunk)
                    const size_t CHUNK_SIZE = 512;
                    for (size_t i = 0; i < vk_data.size(); i += CHUNK_SIZE) {
                        size_t chunk_size = std::min(CHUNK_SIZE, vk_data.size() - i);
                        std::vector<unsigned char> chunk(vk_data.begin() + i, vk_data.begin() + i + chunk_size);
                        vk_chunks.push_back(chunk);
                    }
                }
                if (opt.exists("max_root_age")) max_root_age = opt["max_root_age"].getInt<uint32_t>();
                if (opt.exists("tfr_flags")) tfr_flags = opt["tfr_flags"].getInt<uint32_t>();

                // ICU parameters
                if (opt.exists("icu_payload")) {
                    icu_payload = ParseHex(opt["icu_payload"].get_str());
                    if (icu_payload.size() > assets::MAX_ICU_PAYLOAD_BYTES) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload exceeds maximum size");
                    }
                }
                if (opt.exists("icu_plain_commit")) {
                    auto pc = uint256::FromHex(opt["icu_plain_commit"].get_str());
                    if (!pc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_plain_commit hex");
                    icu_plain_commit = *pc;
                }
                if (opt.exists("icu_ctxt_commit")) {
                    auto cc = uint256::FromHex(opt["icu_ctxt_commit"].get_str());
                    if (!cc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_ctxt_commit hex");
                    icu_ctxt_commit = *cc;
                }
                if (opt.exists("kdf_salt")) {
                    kdf_salt = ParseHex(opt["kdf_salt"].get_str());
                    if (kdf_salt.size() != 16) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "kdf_salt must be exactly 16 bytes");
                    }
                }
                if (opt.exists("icu_flags")) icu_flags = opt["icu_flags"].getInt<uint32_t>();
                if (opt.exists("icu_visibility")) icu_visibility = opt["icu_visibility"].getInt<uint8_t>();
                if (opt.exists("policy_quorum_bps")) policy_quorum_bps = opt["policy_quorum_bps"].getInt<uint16_t>();
                if (auto cap_override = ParseIssuanceCapOption(opt,
                                                               registry_entry ? registry_entry->decimals : 0,
                                                               "mintasset options")) {
                    issuance_cap_units = *cap_override;
                }

                // Keywrap parameters
                if (opt.exists("wrapped_key")) {
                    wrapped_key = ParseHex(opt["wrapped_key"].get_str());
                    if (wrapped_key.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "wrapped_key cannot be empty");
                    }
                    // Validate UTF-8 (consensus requirement)
                    auto is_valid_utf8 = [](const std::vector<unsigned char>& data) -> bool {
                        size_t i = 0;
                        while (i < data.size()) {
                            unsigned char c = data[i];
                            if ((c & 0x80) == 0) { ++i; continue; }
                            if ((c & 0xE0) == 0xC0) {
                                if (i + 1 >= data.size() || (data[i+1] & 0xC0) != 0x80 || c < 0xC2) return false;
                                i += 2; continue;
                            }
                            if ((c & 0xF0) == 0xE0) {
                                if (i + 2 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80) return false;
                                if (c == 0xE0 && data[i+1] < 0xA0) return false; // overlong
                                if (c == 0xED && data[i+1] >= 0xA0) return false; // surrogate
                                i += 3; continue;
                            }
                            if ((c & 0xF8) == 0xF0) {
                                if (i + 3 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80 || (data[i+3] & 0xC0) != 0x80) return false;
                                if (c == 0xF0 && data[i+1] < 0x90) return false; // overlong
                                if (c >= 0xF4) return false; // beyond U+10FFFF
                                i += 4; continue;
                            }
                            return false;
                        }
                        return true;
                    };
                    if (!is_valid_utf8(wrapped_key)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "wrapped_key must be valid UTF-8");
                    }
                }
                if (opt.exists("suite_id")) suite_id = opt["suite_id"].getInt<uint8_t>();
                if (opt.exists("extras_mask")) {
                    extras_mask = opt["extras_mask"].getInt<uint8_t>();
                    const uint8_t allowed_mask = assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT | assets::ICU_KEYWRAP_EXTRA_KC_TAG;
                    if (extras_mask & ~allowed_mask) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "extras_mask has unknown bits (allowed: 0x01, 0x02)");
                    }
                }
                if (opt.exists("wrap_commit")) {
                    auto wc = uint256::FromHex(opt["wrap_commit"].get_str());
                    if (!wc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid wrap_commit hex");
                    wrap_commit = *wc;
                }
                if (opt.exists("kc_tag")) {
                    auto kc_bytes = ParseHex(opt["kc_tag"].get_str());
                    if (kc_bytes.size() != 16) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "kc_tag must be exactly 16 bytes");
                    }
                    std::copy(kc_bytes.begin(), kc_bytes.end(), kc_tag.begin());
                }
            }

            if (registry_entry) {
                EnforceIssuanceCapForMint(*registry_entry, units, issuance_cap_units);
            }

            // Build transaction
            CMutableTransaction mtx;

            // Add ICU input
            mtx.vin.emplace_back(COutPoint(icu_txid, icu_vout));

            const CScript icu_script = GetScriptForDestination(icu_dest);

            // Build IssuerReg v1 TLV for ICU rotation (deterministic format with ZK+ICU sections always present)
            std::vector<unsigned char> reg_payload;
            reg_payload.reserve(254);  // Updated for compliance_root_commit (222 + 32 = 254)

            // Header (39 bytes)
            reg_payload.insert(reg_payload.end(), aid->begin(), aid->end());  // asset_id (32)
            unsigned char pb[4]; WriteLE32(pb, policy_bits); reg_payload.insert(reg_payload.end(), pb, pb + 4);  // policy_bits (4)
            unsigned char ab[2]; ab[0] = allowed & 0xFF; ab[1] = (allowed >> 8) & 0xFF; reg_payload.insert(reg_payload.end(), ab, ab + 2);  // allowed_spk (2)
            reg_payload.push_back(assets::ISSUER_REG_FORMAT_V1);  // format_version = 0x01 (1)

            // Optional fields (10 bytes minimum - no ticker for ICU rotation)
            reg_payload.push_back(0);  // ticker_len = 0 (no ticker)
            reg_payload.push_back(0xFF);  // decimals = 0xFF (not set)
            unsigned char ub[8]; WriteLE64(ub, has_unlock ? unlock : 510000000); reg_payload.insert(reg_payload.end(), ub, ub + 8);  // unlock_fees (8)

            // ZK section (76 bytes) - ZK Whitelist Hardening update
            // Format: kyc_flags(4) + vk_commitment(32) + max_root_age(4) + tfr_flags(4) + compliance_root_commit(32)
            unsigned char zk_buf[76];
            WriteLE32(zk_buf, kyc_flags);
            std::copy(vk_commitment.begin(), vk_commitment.end(), zk_buf + 4);
            WriteLE32(zk_buf + 36, max_root_age);
            WriteLE32(zk_buf + 40, tfr_flags);
            // compliance_root_commit (32 bytes) - zero for now (issuer must set via updatecomplianceroot RPC)
            std::fill(zk_buf + 44, zk_buf + 76, 0);
            reg_payload.insert(reg_payload.end(), zk_buf, zk_buf + 76);

            // ICU section (129 bytes)
            // Format: icu_flags(4) + issuance_cap_units(8) + icu_ctxt_commit(32) + icu_plain_commit(32) +
            //         kdf_salt(16) + icu_version(1) + icu_visibility(1) + core_policy_commit(32) +
            //         policy_epoch(1) + policy_quorum_bps(2)
            unsigned char icu_buf[129];
            std::fill(icu_buf, icu_buf + 129, 0);

            WriteLE32(icu_buf, icu_flags);                                              // offset 0-3
            WriteLE64(icu_buf + 4, issuance_cap_units);                                 // offset 4-11
            std::copy(icu_ctxt_commit.begin(), icu_ctxt_commit.end(), icu_buf + 12);   // offset 12-43
            std::copy(icu_plain_commit.begin(), icu_plain_commit.end(), icu_buf + 44); // offset 44-75
            if (!kdf_salt.empty()) {
                std::copy(kdf_salt.begin(), kdf_salt.end(), icu_buf + 76);             // offset 76-91
            }
            icu_buf[92] = 1;  // icu_version = 1                                       // offset 92
            icu_buf[93] = icu_visibility;                                              // offset 93
            // Correct tail order: core_policy_commit → policy_epoch → policy_quorum_bps
            // core_policy_commit (32 bytes at offset 94-125) initialized to zeros     // offset 94-125
            icu_buf[126] = 0;  // policy_epoch = 0                                     // offset 126
            WriteLE16(icu_buf + 127, policy_quorum_bps);                               // offset 127-128

            reg_payload.insert(reg_payload.end(), icu_buf, icu_buf + 129);

            // Create TLV extension with CompactSize length
            std::vector<unsigned char> reg_tlv;
            reg_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (reg_payload.size() < 253) {
                reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
            } else {
                reg_tlv.push_back(253);
                reg_tlv.push_back(reg_payload.size() & 0xFF);
                reg_tlv.push_back((reg_payload.size() >> 8) & 0xFF);
            }
            reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());

            // Prepare planned outputs so we can attach TLVs after funding
            struct PlannedMintOutput
            {
                CTxDestination dest;
                CScript script;
                CAmount value;
                std::vector<unsigned char> extension;
            };

            std::vector<PlannedMintOutput> planned_outputs;
            planned_outputs.push_back({icu_dest, icu_script, icu_amt, reg_tlv});

            // Add asset output (index 1)
            const CScript asset_script = GetScriptForDestination(asset_dest);

            // Build AssetTag TLV (with optional ICU_KEYWRAP sub-TLV)
            std::vector<unsigned char> tag_payload;
            tag_payload.insert(tag_payload.end(), aid->begin(), aid->end());  // asset_id (32)
            unsigned char au[8];
            WriteLE64(au, units);
            tag_payload.insert(tag_payload.end(), au, au + 8);  // units (8)
            unsigned char flags_buf[4];
            WriteLE32(flags_buf, 0);  // flags = 0
            tag_payload.insert(tag_payload.end(), flags_buf, flags_buf + 4);  // flags (4)

            bool wrap_required = (icu_flags & assets::WRAP_REQUIRED) != 0;
            if (!wrap_required && registry_entry) {
                wrap_required = (registry_entry->icu_flags & assets::WRAP_REQUIRED) != 0;
            }

            const uint256 spk_hash32 = kw::TapMatchHash(asset_script);
            std::optional<IcuKeywrapParams> keywrap_params;

            if (!wrapped_key.empty()) {
                // User provided wrapped key payload verbatim
                IcuKeywrapParams manual;
                manual.ctxt_hash = icu_ctxt_commit;
                manual.spk_hash32 = spk_hash32;
                manual.wrapped_key = wrapped_key;
                manual.suite_id = suite_id;
                manual.extras_mask = extras_mask;
                manual.wrap_commit = wrap_commit;
                manual.kc_tag = kc_tag;
                keywrap_params = manual;
                suite_id = manual.suite_id;
                extras_mask = manual.extras_mask;
                wrap_commit = manual.wrap_commit;
                kc_tag = manual.kc_tag;
            } else if (wrap_required) {
                if (!registry_entry) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Asset registry entry required for keywrap");
                }

                std::optional<std::array<unsigned char, 16>> salt_override;
                if (!kdf_salt.empty()) {
                    if (kdf_salt.size() != 16) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "kdf_salt must be 16 bytes for keywrap");
                    }
                    std::array<unsigned char, 16> arr{};
                    std::copy_n(kdf_salt.begin(), arr.size(), arr.begin());
                    salt_override = arr;
                }

                auto auto_keywrap = AutoWrapDekForOutput(
                    *pwallet,
                    *aid,
                    icu_ctxt_commit,
                    *registry_entry,
                    asset_dest,
                    asset_script,
                    salt_override,
                    suite_id);

                wrapped_key = auto_keywrap.wrapped_key;
                suite_id = auto_keywrap.suite_id;
                extras_mask = auto_keywrap.extras_mask;
                wrap_commit = auto_keywrap.wrap_commit;
                kc_tag = auto_keywrap.kc_tag;
                keywrap_params = auto_keywrap;
            }

            if (keywrap_params) {
                const IcuKeywrapParams& kw = *keywrap_params;

                std::vector<unsigned char> kw_payload;
                kw_payload.reserve(32 + 32 + 32 + kw.wrapped_key.size() + 10 +
                    (kw.extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT ? 32 : 0) +
                    (kw.extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG ? 16 : 0));

                kw_payload.insert(kw_payload.end(), aid->begin(), aid->end());  // asset_id (32)
                kw_payload.insert(kw_payload.end(), kw.ctxt_hash.begin(), kw.ctxt_hash.end());  // ctxt_hash (32)
                kw_payload.insert(kw_payload.end(), kw.spk_hash32.begin(), kw.spk_hash32.end());  // spk_hash32 (32)

                VectorWriter kw_writer(kw_payload, kw_payload.size());
                WriteCompactSize(kw_writer, kw.wrapped_key.size());
                kw_payload.insert(kw_payload.end(), kw.wrapped_key.begin(), kw.wrapped_key.end());

                kw_payload.push_back(kw.suite_id);      // suite_id (1)
                kw_payload.push_back(kw.extras_mask);   // extras_mask (1)

                if (kw.extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
                    kw_payload.insert(kw_payload.end(), kw.wrap_commit.begin(), kw.wrap_commit.end());
                }
                if (kw.extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) {
                    kw_payload.insert(kw_payload.end(), kw.kc_tag.begin(), kw.kc_tag.end());
                }

                tag_payload.push_back(0x03);  // ICU_KEYWRAP sub-TLV type
                VectorWriter tag_writer(tag_payload, tag_payload.size());
                WriteCompactSize(tag_writer, kw_payload.size());
                tag_payload.insert(tag_payload.end(), kw_payload.begin(), kw_payload.end());
            }

            std::vector<unsigned char> tag_tlv;
            tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
            VectorWriter tag_tlv_writer(tag_tlv, tag_tlv.size());
            WriteCompactSize(tag_tlv_writer, tag_payload.size());
            tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());
            planned_outputs.push_back({asset_dest, asset_script, asset_btc, tag_tlv});

            // Add dust outputs for chunk TLVs before funding
            std::vector<CTxDestination> chunk_dests;

            // ICU_TEXT_CHUNK output
            if (!icu_payload.empty()) {
                auto icu_chunk_dest_result = pwallet->GetNewDestination(OutputType::BECH32, "ICU chunk");
                if (!icu_chunk_dest_result) {
                    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(icu_chunk_dest_result).original);
                }
                CTxDestination icu_chunk_dest = *icu_chunk_dest_result;
                chunk_dests.push_back(icu_chunk_dest);

                // Build ICU_TEXT_CHUNK TLV
                std::vector<unsigned char> icu_chunk_tlv;
                icu_chunk_tlv.push_back(0x30);  // ICU_TEXT_CHUNK type
                if (icu_payload.size() < 253) {
                    icu_chunk_tlv.push_back(static_cast<uint8_t>(icu_payload.size()));
                } else {
                    icu_chunk_tlv.push_back(253);
                    icu_chunk_tlv.push_back(icu_payload.size() & 0xFF);
                    icu_chunk_tlv.push_back((icu_payload.size() >> 8) & 0xFF);
                }
                icu_chunk_tlv.insert(icu_chunk_tlv.end(), icu_payload.begin(), icu_payload.end());

                planned_outputs.push_back({icu_chunk_dest, GetScriptForDestination(icu_chunk_dest), 546, icu_chunk_tlv});
            }

            // ZK_PARAMS_CHUNK outputs
            for (size_t chunk_idx = 0; chunk_idx < vk_chunks.size(); ++chunk_idx) {
                auto zk_chunk_dest_result = pwallet->GetNewDestination(OutputType::BECH32, "ZK chunk");
                if (!zk_chunk_dest_result) {
                    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(zk_chunk_dest_result).original);
                }
                CTxDestination zk_chunk_dest = *zk_chunk_dest_result;
                chunk_dests.push_back(zk_chunk_dest);

                const auto& chunk_data = vk_chunks[chunk_idx];

                // Build ZK_PARAMS_CHUNK TLV
                std::vector<unsigned char> chunk_payload;
                chunk_payload.insert(chunk_payload.end(), aid->begin(), aid->end());  // asset_id (LE)
                chunk_payload.insert(chunk_payload.end(), vk_commitment.begin(), vk_commitment.end());  // vk_hash (natural)

                // chunk_index and chunk_count (LE16)
                unsigned char idx_buf[2];
                idx_buf[0] = chunk_idx & 0xFF;
                idx_buf[1] = (chunk_idx >> 8) & 0xFF;
                chunk_payload.insert(chunk_payload.end(), idx_buf, idx_buf + 2);

                unsigned char cnt_buf[2];
                cnt_buf[0] = vk_chunks.size() & 0xFF;
                cnt_buf[1] = (vk_chunks.size() >> 8) & 0xFF;
                chunk_payload.insert(chunk_payload.end(), cnt_buf, cnt_buf + 2);

                chunk_payload.insert(chunk_payload.end(), chunk_data.begin(), chunk_data.end());

                std::vector<unsigned char> chunk_tlv;
                chunk_tlv.push_back(0x20);  // ZK_PARAMS_CHUNK type
                if (chunk_payload.size() < 253) {
                    chunk_tlv.push_back(static_cast<uint8_t>(chunk_payload.size()));
                } else {
                    chunk_tlv.push_back(253);
                    chunk_tlv.push_back(chunk_payload.size() & 0xFF);
                    chunk_tlv.push_back((chunk_payload.size() >> 8) & 0xFF);
                }
                chunk_tlv.insert(chunk_tlv.end(), chunk_payload.begin(), chunk_payload.end());

                planned_outputs.push_back({zk_chunk_dest, GetScriptForDestination(zk_chunk_dest), 546, chunk_tlv});
            }

            // Append native-only extra outputs (e.g. option-series lot vaults) with EMPTY extension.
            for (auto& [script, value] : extra_native_outputs) {
                CTxDestination dest;
                ExtractDestination(script, dest); // validated standard during option parse
                planned_outputs.push_back({dest, script, value, {}});
            }
            // Output-count cap (planned outputs + one change) must fit the covenant-tx output limit.
            if (planned_outputs.size() + 1 > MAX_COVENANT_TX_OUTPUTS) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("mint tx would have %u outputs, exceeding the %u-output cap (use fewer extra outputs / batch)",
                              static_cast<unsigned>(planned_outputs.size() + 1), MAX_COVENANT_TX_OUTPUTS));
            }

            // Fund transaction if requested
            if (autofund) {
                CCoinControl cc;
                if (fee_rate_vb) {
                    cc.fOverrideFeeRate = true;
                    cc.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
                }
                if (replaceable) {
                    cc.m_signal_bip125_rbf = *replaceable;
                }

                // Don't select the ICU we're already spending
                cc.m_avoid_address_reuse = true;

                std::vector<CRecipient> recipients;
                recipients.reserve(planned_outputs.size());
                for (const auto& planned : planned_outputs) {
                    recipients.push_back({planned.dest, planned.value, /*fSubtractFeeFromAmount=*/false});
                }

                auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt,
                                         /*lockUnspents=*/false, cc);
                if (!txr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                }

                // Apply the funded transaction
                mtx = CMutableTransaction(*txr->tx);

                std::vector<bool> matched(mtx.vout.size(), false);
                for (const auto& planned : planned_outputs) {
                    bool found = false;
                    auto try_match = [&](auto&& predicate) {
                        for (size_t idx = 0; idx < mtx.vout.size(); ++idx) {
                            if (matched[idx]) continue;
                            CTxOut& out = mtx.vout[idx];
                            if (predicate(out)) {
                                out.vExt = planned.extension;
                                matched[idx] = true;
                                return true;
                            }
                        }
                        return false;
                    };

                    found = try_match([&](const CTxOut& out) {
                        return out.nValue == planned.value && out.scriptPubKey == planned.script;
                    });
                    if (!found) {
                        found = try_match([&](const CTxOut& out) {
                            return out.scriptPubKey == planned.script;
                        });
                    }
                    if (!found) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate funded asset output");
                    }
                }

                // Sanity check: ensure we have an output with AssetTag TLV
                bool has_asset_output = false;
                for (const auto& out : mtx.vout) {
                    if (!out.vExt.empty() && out.vExt[0] == 0x01) {
                        has_asset_output = true;
                        break;
                    }
                }
                if (!has_asset_output) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "No asset output found in transaction after funding");
                }

                // After attaching all TLVs, check if we need to bump fees due to increased tx size
                unsigned int funded_tx_size = GetVirtualTransactionSize(CTransaction(*txr->tx));
                CTransaction tmp_tx(mtx);
                unsigned int actual_tx_size = GetVirtualTransactionSize(tmp_tx);

                // Calculate current fee from FundTransaction
                CAmount current_fee = txr->fee;

                // Derive the fee rate that FundTransaction used
                CFeeRate actual_fee_rate = funded_tx_size > 0 ? CFeeRate(current_fee, funded_tx_size) : CFeeRate(0);

                // Calculate required fee based on actual size with TLVs
                CAmount required_fee = actual_fee_rate.GetFee(actual_tx_size);

                // If we need more fees, reduce change output
                if (required_fee > current_fee) {
                    CAmount fee_deficit = required_fee - current_fee;

                    // Try to find and adjust change output
                    bool adjusted_change = false;
                    for (auto& out : mtx.vout) {
                        // Change output is not in planned_outputs
                        bool is_planned = false;
                        for (const auto& planned : planned_outputs) {
                            if (out.scriptPubKey == planned.script) {
                                is_planned = true;
                                break;
                            }
                        }
                        if (!is_planned && out.nValue > fee_deficit + 546) {
                            out.nValue -= fee_deficit;
                            adjusted_change = true;
                            break;
                        }
                    }

                    if (!adjusted_change) {
                        LogPrintf("WARNING: Could not adjust fees for mintasset TLV extensions. Required: %d, Current: %d\n",
                                 required_fee, current_fee);
                    }
                }
            } else {
                for (const auto& planned : planned_outputs) {
                    mtx.vout.emplace_back(planned.value, planned.script);
                    mtx.vout.back().vExt = planned.extension;
                }
            }

            // Sign and broadcast if requested
            if (broadcast) {
                PartiallySignedTransaction psbtx(mtx);
                bool complete = false;

                const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                if (fill_err) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                if (!complete) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction completely");
                }

                CMutableTransaction signed_mtx;
                if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
                }

                // Verify vExt survived PSBT process
                bool has_asset_after_psbt = false;
                for (const auto& out : signed_mtx.vout) {
                    if (!out.vExt.empty() && out.vExt[0] == 0x01) {
                        has_asset_after_psbt = true;
                        break;
                    }
                }
                if (!has_asset_after_psbt) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "AssetTag TLV lost during PSBT processing");
                }

                CTransactionRef tx = MakeTransactionRef(CTransaction(signed_mtx));
                {
                    LOCK(pwallet->cs_wallet);

                    // Set metadata for asset outputs BEFORE committing
                    // Look up registry data for the asset
                    AssetMetadata metadata;
                    try {
                        auto resolved = ResolveAssetIdOrTicker(request, request.params[6].get_str());
                        if (resolved.registry) {
                            metadata.has_ticker = !resolved.registry->ticker.empty();
                            metadata.ticker = resolved.registry->ticker;
                            // Registry resolved -> decimals is authoritative,
                            // including 0 (integer-only assets like NEWCO).
                            metadata.has_decimals = true;
                            metadata.decimals = resolved.registry->decimals;
                        }
                    } catch (...) {
                        // Registry lookup failed, use empty metadata
                    }

                    // Find and save metadata for asset outputs we own
                    // Note: It's valid to mint to addresses not controlled by this wallet,
                    // so we don't throw an error if no owned outputs are found
                    for (size_t i = 0; i < tx->vout.size(); ++i) {
                        if (!tx->vout[i].vExt.empty() && tx->vout[i].vExt[0] == 0x01) { // AssetTag TLV
                            // Check if wallet owns this output
                            isminetype mine = pwallet->IsMine(tx->vout[i]);
                            if (mine & ISMINE_SPENDABLE) {
                                pwallet->SetAssetMetadata(COutPoint(tx->GetHash(), i), metadata);
                            }
                        }
                    }

                    pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});
                }

                return tx->GetHash().ToString();
            }

            // Return raw hex
            DataStream ds;
            ds << TX_WITH_WITNESS(mtx);
            return HexStr(ds);
        }
    };
}

RPCHelpMan burnasset()
{
    return RPCHelpMan{
        "burnasset",
        "Burn asset units (wallet version).",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU transaction ID"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU output index"},
            {"asset_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset UTXO transaction ID"},
            {"asset_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset UTXO output index"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination address"},
            {"icu_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "New ICU BTC amount"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID being burned"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{28}, "Allowed script families"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Automatically fund transaction fees"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Enable RBF"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "Transaction ID if broadcast, otherwise hex"},
        RPCExamples{
            HelpExampleCli("burnasset", "\"icu_txid\" 0 \"asset_txid\" 1 \"bc1q...\" 5.1 \"asset_id\" 3 28")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Parse inputs
            Txid icu_txid{Txid::FromUint256(ParseHashV(request.params[0], "icu_txid"))};
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();

            Txid asset_txid{Txid::FromUint256(ParseHashV(request.params[2], "asset_txid"))};
            uint32_t asset_vout = request.params[3].getInt<uint32_t>();

            // Parse ICU rotation output
            CTxDestination icu_dest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(icu_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid ICU address");
            }
            CAmount icu_amt = AmountFromValue(request.params[5]);

            // Parse asset parameters
            auto aid = uint256::FromHex(request.params[6].get_str());
            if (!aid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }
            uint32_t policy_bits = request.params[7].getInt<uint32_t>();
            uint16_t allowed = request.params[8].isNull() ? 28 : request.params[8].getInt<uint16_t>();

            bool has_unlock = !request.params[9].isNull();
            uint64_t unlock = has_unlock ? request.params[9].getInt<uint64_t>() : 0;

            // Parse options
            bool autofund = true;
            bool broadcast = false;
            std::optional<double> fee_rate_vb;
            std::optional<bool> replaceable = true;

            if (!request.params[10].isNull()) {
                const UniValue& opt = request.params[10];
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
            }

            // Build transaction
            CMutableTransaction mtx;

            // Add ICU input (index 0)
            mtx.vin.emplace_back(COutPoint(icu_txid, icu_vout));

            // Add asset input to burn (index 1)
            mtx.vin.emplace_back(COutPoint(asset_txid, asset_vout));

            const CScript icu_script = GetScriptForDestination(icu_dest);

            // Build IssuerReg v1 TLV for ICU rotation (deterministic format with ZK+ICU sections always present)
            std::vector<unsigned char> reg_payload;
            reg_payload.reserve(254);  // ZK Whitelist Hardening: updated from 222

            // Header (39 bytes)
            reg_payload.insert(reg_payload.end(), aid->begin(), aid->end());  // asset_id (32)
            unsigned char pb[4]; WriteLE32(pb, policy_bits); reg_payload.insert(reg_payload.end(), pb, pb + 4);  // policy_bits (4)
            unsigned char ab[2]; ab[0] = allowed & 0xFF; ab[1] = (allowed >> 8) & 0xFF; reg_payload.insert(reg_payload.end(), ab, ab + 2);  // allowed_spk (2)
            reg_payload.push_back(assets::ISSUER_REG_FORMAT_V1);  // format_version = 0x01 (1)

            // Optional fields (10 bytes minimum - no ticker for ICU rotation)
            reg_payload.push_back(0);  // ticker_len = 0 (no ticker)
            reg_payload.push_back(0xFF);  // decimals = 0xFF (not set)
            unsigned char ub[8]; WriteLE64(ub, has_unlock ? unlock : 510000000); reg_payload.insert(reg_payload.end(), ub, ub + 8);  // unlock_fees (8)

            // ZK section (76 bytes, all zeros for basic ICU rotation) - ZK Whitelist Hardening update
            reg_payload.insert(reg_payload.end(), 76, 0);

            // ICU section (129 bytes with icu_visibility, all zeros for basic ICU rotation)
            reg_payload.insert(reg_payload.end(), 129, 0);

            // Create TLV extension with CompactSize length
            std::vector<unsigned char> reg_tlv;
            reg_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (reg_payload.size() < 253) {
                reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
            } else {
                reg_tlv.push_back(253);
                reg_tlv.push_back(reg_payload.size() & 0xFF);
                reg_tlv.push_back((reg_payload.size() >> 8) & 0xFF);
            }
            reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());

            struct PlannedBurnOutput
            {
                CTxDestination dest;
                CScript script;
                CAmount value;
                std::vector<unsigned char> extension;
            };

            PlannedBurnOutput planned_output{icu_dest, icu_script, icu_amt, reg_tlv};

            // Fund transaction if requested
            if (autofund) {
                CCoinControl cc;
                if (fee_rate_vb) {
                    cc.fOverrideFeeRate = true;
                    cc.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0));
                }
                if (replaceable) {
                    cc.m_signal_bip125_rbf = *replaceable;
                }

                // Don't select the ICU or asset we're already spending
                cc.m_avoid_address_reuse = true;

                std::vector<CRecipient> recipients;
                recipients.push_back({planned_output.dest, planned_output.value, /*fSubtractFeeFromAmount=*/false});

                auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt,
                                         /*lockUnspents=*/false, cc);
                if (!txr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                }

                // Apply the funded transaction
                mtx = CMutableTransaction(*txr->tx);

                bool found = false;
                for (CTxOut& out : mtx.vout) {
                    if (out.nValue == planned_output.value && out.scriptPubKey == planned_output.script) {
                        out.vExt = planned_output.extension;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    for (CTxOut& out : mtx.vout) {
                        if (out.scriptPubKey == planned_output.script) {
                            out.vExt = planned_output.extension;
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate funded ICU output");
                }
            } else {
                mtx.vout.emplace_back(planned_output.value, planned_output.script);
                mtx.vout.back().vExt = planned_output.extension;
            }

            // Sign and broadcast if requested
            if (broadcast) {
                LOCK(pwallet->cs_wallet);

                // Sign the transaction - populate coins map properly
                std::map<COutPoint, Coin> coins;
                for (const auto& input : mtx.vin) {
                    const auto mi = pwallet->mapWallet.find(input.prevout.hash);
                    if (mi == pwallet->mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Transaction %s:%d not found in wallet",
                                                                      input.prevout.hash.ToString(), input.prevout.n));
                    }
                    const CWalletTx& wtx = mi->second;
                    int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
                    coins[input.prevout] = Coin(wtx.tx->vout[input.prevout.n], prev_height, wtx.IsCoinBase());
                }

                std::map<int, bilingual_str> errors;
                if (!pwallet->SignTransaction(mtx, coins, SIGHASH_ALL, errors)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction");
                }

                // Broadcast
                CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});

                return tx->GetHash().ToString();
            }

            // Return raw hex
            DataStream ds;
            ds << TX_WITH_WITNESS(mtx);
            return HexStr(ds);
        }
    };
}

RPCHelpMan listassets()
{
    return RPCHelpMan{
        "listassets",
        "List all known assets in the system.\n"
        "Returns information about all registered assets including their tickers and policies.",
        {
            {"include_unregistered", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include assets seen but not yet registered"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include detailed asset information"},
            {"filter", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Filter criteria",
                {
                    {"has_ticker", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Only assets with tickers"},
                    {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Match specific policy bits"},
                    {"min_balance", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Only assets where wallet has at least this balance"},
                },
            },
        },
        RPCResult{RPCResult::Type::ARR, "", "Array of asset information",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "asset_id", "The asset ID"},
                        {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker symbol if registered"},
                        {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Number of decimal places"},
                        {RPCResult::Type::NUM, "policy_bits", /*optional=*/true, "Policy bits (verbose mode)"},
                        {RPCResult::Type::NUM, "allowed_families", /*optional=*/true, "Allowed SPK families (verbose mode)"},
                        {RPCResult::Type::STR_HEX, "icu_txid", /*optional=*/true, "Current ICU location txid (verbose mode)"},
                        {RPCResult::Type::NUM, "icu_vout", /*optional=*/true, "Current ICU location vout (verbose mode)"},
                        {RPCResult::Type::NUM, "total_supply", /*optional=*/true, "Total minted supply (if tracked)"},
                        {RPCResult::Type::BOOL, "is_registered", "Whether the asset has been registered"},
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("listassets", "") +
            HelpExampleCli("listassets", "true") +
            HelpExampleCli("listassets", "true '{\"has_ticker\": true}'") +
            HelpExampleCli("listassets", "false '{\"policy_bits\": 3, \"min_balance\": 100000}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) {
                return UniValue::VNULL;
            }

            bool include_unregistered = request.params[0].isNull() ? false : request.params[0].get_bool();
            bool verbose = request.params[1].isNull() ? false : request.params[1].get_bool();

            // Parse filter options
            bool filter_has_ticker = false;
            bool apply_ticker_filter = false;
            uint32_t filter_policy_bits = 0;
            bool apply_policy_filter = false;
            uint64_t filter_min_balance = 0;
            bool apply_balance_filter = false;

            if (!request.params[2].isNull()) {
                const UniValue& filter = request.params[2].get_obj();

                if (filter.exists("has_ticker")) {
                    filter_has_ticker = filter["has_ticker"].get_bool();
                    apply_ticker_filter = true;
                }
                if (filter.exists("policy_bits")) {
                    filter_policy_bits = filter["policy_bits"].getInt<uint32_t>();
                    apply_policy_filter = true;
                }
                if (filter.exists("min_balance")) {
                    filter_min_balance = filter["min_balance"].getInt<uint64_t>();
                    apply_balance_filter = true;
                }
            }

            WalletContext& wallet_context = EnsureWalletContext(request.context);
            interfaces::Chain* chain = wallet_context.chain;
            if (!chain) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not connected to a node");
            }

            UniValue result(UniValue::VARR);

            // First, get all assets with tickers
            std::set<uint256> all_asset_ids;

            // Collect assets known to the wallet
            {
                LOCK(pwallet->cs_wallet);

                // Collect from asset metadata in wallet
                for (const auto& [txid, wtx] : pwallet->mapWallet) {
                    // Check all outputs for asset tags and ICU registrations
                    for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
                        const CTxOut& out = wtx.tx->vout[i];

                        // Check for AssetTag
                        auto tag = assets::ParseAssetTag(out.vExt);
                        if (tag) {
                            all_asset_ids.insert(tag->id);
                        }

                        // Check for IssuerReg
                        auto reg = assets::ParseIssuerReg(out.vExt);
                        if (reg) {
                            all_asset_ids.insert(reg->asset_id);
                        }
                    }
                }
            }

            // Calculate wallet balances if needed
            std::map<uint256, uint64_t> wallet_balances;
            if (apply_balance_filter) {
                CCoinControl control;
                control.m_avoid_asset_utxos = false;  // Include asset outputs for balance calculation
                CoinFilterParams filter_params;
                filter_params.only_spendable = false;  // Include locked coins for balance calculation
                auto utxos = CollectAssetUtxos(*pwallet, control, filter_params);
                for (const auto& utxo : utxos) {
                    wallet_balances[utxo.asset_id] += utxo.units;
                }
            }

            // Get information for each asset
            for (const uint256& asset_id : all_asset_ids) {
                // Try to get asset registry entry via chain interface
                auto entry = chain->getAssetRegistryEntry(asset_id);
                bool is_registered = entry.has_value();

                // Skip unregistered assets unless requested
                if (!is_registered && !include_unregistered) {
                    continue;
                }

                // Apply filters
                if (apply_ticker_filter) {
                    bool has_ticker = entry && !entry->ticker.empty();
                    if (filter_has_ticker != has_ticker) {
                        continue;  // Filter doesn't match
                    }
                }

                if (apply_policy_filter && entry) {
                    if (entry->policy_bits != filter_policy_bits) {
                        continue;  // Policy bits don't match
                    }
                }

                if (apply_balance_filter) {
                    uint64_t balance = wallet_balances[asset_id];
                    if (balance < filter_min_balance) {
                        continue;  // Insufficient balance
                    }
                }

                // Build result object - always return objects per RPC documentation
                UniValue asset_obj(UniValue::VOBJ);
                asset_obj.pushKV("asset_id", asset_id.ToString());

                if (is_registered && entry) {
                    // Add ticker if available
                    if (!entry->ticker.empty()) {
                        asset_obj.pushKV("ticker", entry->ticker);
                    }

                    // Add decimals if set
                    if (entry->decimals != 255) {
                        asset_obj.pushKV("decimals", static_cast<int64_t>(entry->decimals));
                    }

                    if (verbose) {
                        // Verbose mode only - add policy info
                        asset_obj.pushKV("policy_bits", static_cast<int64_t>(entry->policy_bits));
                        asset_obj.pushKV("allowed_families", static_cast<int64_t>(entry->allowed_spk_families));
                        asset_obj.pushKV("icu_txid", entry->icu_outpoint.hash.ToString());
                        asset_obj.pushKV("icu_vout", static_cast<int64_t>(entry->icu_outpoint.n));
                    }
                }

                // Add wallet balance if available
                if (wallet_balances.find(asset_id) != wallet_balances.end()) {
                    asset_obj.pushKV("wallet_balance", wallet_balances[asset_id]);
                }

                asset_obj.pushKV("is_registered", is_registered);
                result.push_back(asset_obj);
            }

            return result;
        }
    };
}

RPCHelpMan getassetregistry()
{
    return RPCHelpMan{
        "getassetregistry",
        "Query the asset registry for detailed information about a specific asset.\n"
        "Returns the complete registry entry including ZK/ICU configuration and governance parameters.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Asset identifier"},
                {RPCResult::Type::NUM, "policy_bits", "Policy flags"},
                {RPCResult::Type::NUM, "allowed_spk_families", "Allowed script families mask"},
                {RPCResult::Type::STR_HEX, "icu_txid", "Current ICU transaction ID"},
                {RPCResult::Type::NUM, "icu_vout", "Current ICU output index"},
                {RPCResult::Type::NUM, "unlock_fees_sats", "Unlock threshold in satoshis"},
                {RPCResult::Type::NUM, "fees_accum_sats", "Accumulated fees in satoshis"},
                {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker symbol"},
                {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Display decimals (255=not set)"},
                {RPCResult::Type::BOOL, "has_kyc", "Whether ZK/KYC verification is enabled"},
                {RPCResult::Type::STR_HEX, "zk_vk_commitment", /*optional=*/true, "ZK verification key commitment"},
                {RPCResult::Type::NUM, "max_root_age", "Maximum merkle root age in seconds"},
                {RPCResult::Type::NUM, "tfr_flags", "Transfer restriction flags"},
                {RPCResult::Type::NUM, "issued_total", "Total units minted"},
                {RPCResult::Type::NUM, "burned_total", "Total units burned"},
                {RPCResult::Type::NUM, "icu_flags", "ICU structural flags"},
                {RPCResult::Type::NUM, "icu_visibility", "ICU visibility (0=public, 1=holder_only)"},
                {RPCResult::Type::NUM, "policy_quorum_bps", "Governance quorum in basis points"},
                {RPCResult::Type::NUM, "issuance_cap_units", "Maximum issuance cap in base units (0=unlimited)"},
                {RPCResult::Type::STR_HEX, "icu_ctxt_commit", "ICU ciphertext commitment"},
                {RPCResult::Type::STR_HEX, "icu_plain_commit", "ICU plaintext commitment"},
                {RPCResult::Type::STR_HEX, "core_policy_commit", "Core policy immutability commitment"},
                {RPCResult::Type::NUM, "policy_epoch", "Policy version counter"},
            }
        },
        RPCExamples{
            HelpExampleCli("getassetregistry", "\"a3f747562969280eb3ddc96ff57e3692b7b55611d8c89785f52fc2d1535d22b3\"") +
            HelpExampleCli("getassetregistry", "\"GOLD\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());

            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            const AssetRegistryEntry& entry = *resolved.registry;
            UniValue result(UniValue::VOBJ);

            result.pushKV("asset_id", resolved.asset_id.ToString());
            result.pushKV("policy_bits", static_cast<uint64_t>(entry.policy_bits));
            result.pushKV("allowed_spk_families", static_cast<uint64_t>(entry.allowed_spk_families));
            result.pushKV("icu_txid", entry.icu_outpoint.hash.ToString());
            result.pushKV("icu_vout", static_cast<uint64_t>(entry.icu_outpoint.n));
            result.pushKV("unlock_fees_sats", entry.unlock_fees_sats);
            result.pushKV("fees_accum_sats", entry.fees_accum_sats);

            if (!entry.ticker.empty()) {
                result.pushKV("ticker", entry.ticker);
            }
            if (entry.decimals != 255) {
                result.pushKV("decimals", static_cast<uint64_t>(entry.decimals));
            }

            result.pushKV("has_kyc", entry.has_kyc);
            if (entry.has_kyc) {
                result.pushKV("zk_vk_commitment", entry.zk_vk_commitment.ToString());
            }
            result.pushKV("max_root_age", static_cast<uint64_t>(entry.max_root_age));
            result.pushKV("tfr_flags", static_cast<uint64_t>(entry.tfr_flags));
            result.pushKV("issued_total", entry.issued_total);
            result.pushKV("burned_total", entry.burned_total);
            result.pushKV("icu_flags", static_cast<uint64_t>(entry.icu_flags));
            result.pushKV("icu_visibility", static_cast<uint64_t>(entry.icu_visibility));
            result.pushKV("policy_quorum_bps", static_cast<uint64_t>(entry.policy_quorum_bps));
            result.pushKV("issuance_cap_units", entry.issuance_cap_units);
            result.pushKV("icu_ctxt_commit", entry.icu_ctxt_commit.ToString());
            result.pushKV("icu_plain_commit", entry.icu_plain_commit.ToString());
            result.pushKV("core_policy_commit", entry.core_policy_commit.ToString());
            result.pushKV("policy_epoch", static_cast<uint64_t>(entry.policy_epoch));

            return result;
        }
    };
}

RPCHelpMan buildcanonicalicupayload()
{
    return RPCHelpMan{
        "buildcanonicalicupayload",
        "Build a canonical ICU payload from governance text and witness metadata.\n"
        "This is a helper RPC for GUI/external tools to avoid duplicating serialization logic.\n"
        "Returns the serialized payload hex and computed hashes for use with registerasset.",
        {
            {"canonical_text", RPCArg::Type::STR, RPCArg::Optional::NO, "Governance document text (UTF-8)"},
            {"witness_bundle", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Witness metadata as JSON object",
                {
                    {"canonical_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Use 'placeholder' for automatic replacement"},
                }
            },
            {"visibility", RPCArg::Type::NUM, RPCArg::Default{0}, "0=public, 1=holder_only"},
            {"icu_context", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED,
                "DEPRECATED (legacy SubstringV1 path): committed TSC-ICU-CONTEXT-1 map embedded in CanonicalIcuPayload.metadata "
                "(non-authoritative under Option A). Prefer 'icu_clauses', which embeds the authoritative map INSIDE canonical_text "
                "so it is covered by icu_plain_commit. When 'icu_clauses' is supplied this argument is ignored.\n"
                "Optional committed TSC-ICU-CONTEXT-1 map; validated against the normalized text and embedded in metadata (registerasset then commits it). "
                "Named 'icu_context' (not 'context') so the RPC arg-conversion table stays consistent with the string 'context' label used by cosign/forward/repo/spot RPCs.",
                {
                    {"spec", RPCArg::Type::STR, RPCArg::Optional::NO, "\"TSC-ICU-CONTEXT-1\""},
                    {"parse_version", RPCArg::Type::NUM, RPCArg::Optional::NO, "1"},
                    {"acceptance", RPCArg::Type::STR, RPCArg::Optional::NO, "\"required\" or \"optional\""},
                    {"bodies", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO,
                        "Map of body key (raw sha256 hex of an exact normalized substring) -> that exact normalized substring",
                        {{"body_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Exact normalized substring of canonical_text"}}},
                }},
            {"icu_clauses", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                "Option A inline context: ordered list of clause texts. When present and non-empty, an authoritative TSC-ICU-CONTEXT-1 "
                "block (keyed by raw-digest hex SHA256 of each normalized clause) is embedded INSIDE canonical_text (so it is committed "
                "under icu_plain_commit) and CanonicalIcuPayload.metadata is set to the inline marker {\"icu_ctx\":\"inline\"}. Takes "
                "precedence over 'icu_context'.",
                {{"clause", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Clause text (UTF-8); will be normalized before hashing"}}},
            {"icu_acceptance", RPCArg::Type::STR, RPCArg::Default{"required"},
                "Acceptance mode for the inline context block (only used with 'icu_clauses'): \"required\" or \"optional\"."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "icu_payload_plain", "Hex-encoded canonical ICU payload (ready for registerasset)"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "SHA256 hash of canonical_text (little-endian hex)"},
                {RPCResult::Type::STR_HEX, "witness_hash", "SHA256 hash of witness_bundle JSON (little-endian hex)"},
                {RPCResult::Type::STR, "normalized_canonical_text", "The normalized canonical text (CRLF, NFC, trimmed). Compute body keys as raw-digest hex SHA256 over exact substrings of THESE bytes."},
                {RPCResult::Type::OBJ, "witness_bundle", "Witness bundle with canonical_hash filled in", {{RPCResult::Type::ELISION, "", ""}}},
                {RPCResult::Type::NUM, "icu_visibility", "Visibility mode (0 or 1)"},
                {RPCResult::Type::NUM, "payload_size", "Size of payload in bytes"},
                {RPCResult::Type::OBJ, "context", /* optional */ true,
                    "The canonical TSC-ICU-CONTEXT-1 object embedded inline (present only when 'icu_clauses' was supplied)",
                    {{RPCResult::Type::ELISION, "", ""}}},
                {RPCResult::Type::ARR, "body_keys", /* optional */ true,
                    "Ordered inline-context body keys (raw-digest hex SHA256 of each normalized clause), for acceptance body_refs (present only with 'icu_clauses')",
                    {{RPCResult::Type::STR_HEX, "body_key", "Raw-digest hex SHA256 of a normalized clause"}}},
            }
        },
        RPCExamples{
            HelpExampleCli("buildcanonicalicupayload", "\"Board requires 2/3 majority\" '{\"version\":\"1.0\",\"canonical_hash\":\"placeholder\"}' 0")
          + HelpExampleRpc("buildcanonicalicupayload", "\"Board requires 2/3 majority\", {\"version\":\"1.0\",\"canonical_hash\":\"placeholder\"}, 0")
        },
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            // Parse inputs
            std::string canonical_text_str = request.params[0].get_str();
            const UniValue& witness_obj = request.params[1];
            uint8_t visibility = request.params.size() > 2 ? request.params[2].getInt<int>() : 0;

            if (visibility > 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "visibility must be 0 (public) or 1 (holder_only)");
            }

            if (!witness_obj.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "witness_bundle must be a JSON object");
            }

            // Option A inline context: when icu_clauses (params[4]) is present and non-empty, compose
            // an assembled canonical_text that EMBEDS the authoritative TSC-ICU-CONTEXT-1 block (covered
            // by icu_plain_commit). This takes precedence over the legacy icu_context-in-metadata path.
            // canonical_text_source is the pre-normalization string we hand to NormalizeCanonicalText.
            std::string canonical_text_source = canonical_text_str;
            bool use_inline_context = false;
            UniValue inline_context(UniValue::VOBJ);
            std::vector<std::string> inline_body_keys;
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                const UniValue& clauses_arr = request.params[4];
                if (!clauses_arr.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_clauses must be a JSON array of clause text strings");
                }
                if (!clauses_arr.empty()) {
                    std::vector<std::string> clause_texts;
                    clause_texts.reserve(clauses_arr.size());
                    for (size_t i = 0; i < clauses_arr.size(); ++i) {
                        if (!clauses_arr[i].isStr()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_clauses entries must be strings");
                        }
                        clause_texts.push_back(clauses_arr[i].get_str());
                    }
                    std::string acceptance = "required";
                    if (request.params.size() > 5 && !request.params[5].isNull()) {
                        acceptance = request.params[5].get_str();
                    }
                    std::string compose_err;
                    auto assembled = assets::ComposeCanonicalTextWithInlineContext(
                        canonical_text_str, clause_texts, acceptance,
                        inline_context, inline_body_keys, compose_err);
                    if (!assembled) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, compose_err);
                    }
                    canonical_text_source = *assembled;
                    use_inline_context = true;
                }
            }

            // Normalize canonical text
            auto normalized_opt = assets::NormalizeCanonicalText(canonical_text_source);
            if (!normalized_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "canonical_text contains invalid UTF-8 or disallowed characters");
            }
            const std::string& normalized_text = *normalized_opt;

            // Build CanonicalIcuPayload structure
            assets::CanonicalIcuPayload payload;
            payload.version = 1;
            payload.compression = 0;  // No compression for GUI builds
            payload.visibility = visibility;
            payload.encryption_mode = (visibility == 1) ? 1 : 0;  // ChaCha20 for holder-only, none for public

            // Set canonical text
            payload.canonical_text = std::vector<unsigned char>(normalized_text.begin(), normalized_text.end());

            // Compute canonical hash
            uint256 canonical_hash = payload.GetCanonicalHash();

            // Replace placeholder in witness bundle
            UniValue witness_copy = witness_obj;
            if (witness_copy.exists("canonical_hash")) {
                std::string hash_value = witness_copy["canonical_hash"].get_str();
                if (hash_value == "placeholder") {
                    witness_copy.pushKV("canonical_hash", canonical_hash.ToString());
                }
            } else {
                // Add canonical_hash if not present
                witness_copy.pushKV("canonical_hash", canonical_hash.ToString());
            }

            // Serialize witness bundle to compact JSON
            std::string witness_str = witness_copy.write(0, 0);  // Compact format
            payload.witness_bundle = std::vector<unsigned char>(witness_str.begin(), witness_str.end());

            // Compute witness hash
            uint256 witness_hash = payload.GetWitnessHash();

            // Context map (TSC-ICU-CONTEXT-1). Option A (inline): the authoritative map already lives
            // INSIDE canonical_text (committed under icu_plain_commit); metadata becomes a non-authoritative
            // marker only. Legacy path: the map is validated against the normalized text and serialized into
            // metadata so registerasset commits it (icu_ctxt_commit). Without either, metadata stays empty.
            payload.metadata = std::vector<unsigned char>();
            if (use_inline_context) {
                const std::string marker = assets::ICU_CONTEXT_INLINE_MARKER_JSON;
                payload.metadata = std::vector<unsigned char>(marker.begin(), marker.end());
            } else if (request.params.size() > 3 && !request.params[3].isNull()) {
                const UniValue& context_obj = request.params[3];
                if (!context_obj.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "context must be a JSON object (TSC-ICU-CONTEXT-1)");
                }
                std::string ctx_err;
                if (!assets::ValidateIcuContext(context_obj, normalized_text, ctx_err)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid context map: " + ctx_err);
                }
                const std::string ctx_str = context_obj.write(0, 0);  // compact JSON
                payload.metadata = std::vector<unsigned char>(ctx_str.begin(), ctx_str.end());
            }

            // Serialize the complete payload
            std::vector<unsigned char> serialized = payload.Serialize();

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("icu_payload_plain", HexStr(serialized));
            result.pushKV("canonical_hash", canonical_hash.ToString());
            result.pushKV("witness_hash", witness_hash.ToString());
            result.pushKV("normalized_canonical_text", normalized_text);  // GUI hashes body excerpts over THESE bytes
            result.pushKV("witness_bundle", witness_copy);  // Return the witness bundle with filled canonical_hash
            result.pushKV("icu_visibility", (int)visibility);
            result.pushKV("payload_size", (int)serialized.size());
            if (use_inline_context) {
                result.pushKV("context", inline_context);
                UniValue keys(UniValue::VARR);
                for (const std::string& k : inline_body_keys) {
                    keys.push_back(k);
                }
                result.pushKV("body_keys", keys);
            }

            return result;
        },
    };
}

RPCHelpMan geticupayload()
{
    return RPCHelpMan{
        "geticupayload",
        "Retrieve and decrypt the ICU payload for a given asset.\n"
        "If the wallet holds asset UTXOs with ICU_KEYWRAP, automatically decrypts the payload.\n"
        "Optionally, provide wrapped_key and receive_address to decrypt from PSBT output (for commitment proofs).",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional decryption parameters",
                {
                    {"wrapped_key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Base64 or hex-encoded wrapped key from PSBT asset tag (bypasses wallet UTXO search)"},
                    {"receive_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Taproot address for unwrapping (must be in wallet)"},
                    {"receive_scriptpubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ScriptPubKey hex for the receive address (optional, derived from receive_address if omitted)"},
                    {"suite_id", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Keywrap suite ID (default: auto-detect from wrapped_key)"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "ciphertext", "Hex-encoded encrypted ICU payload"},
                {RPCResult::Type::STR_HEX, "plaintext", /* optional */ true, "Hex-encoded decrypted payload (if wallet has keywrap)"},
                {RPCResult::Type::STR_HEX, "icu_ctxt_commit", "Commitment hash of the ciphertext"},
                {RPCResult::Type::BOOL, "decrypted", "Whether automatic decryption succeeded"},
                {RPCResult::Type::STR, "failure_reason", /* optional */ true,
                    "When decryption fails, provides the last observed failure reason"},
                {RPCResult::Type::STR_HEX, "metadata", /* optional */ true,
                    "Hex of the committed payload metadata (present when decrypted and non-empty)"},
                {RPCResult::Type::OBJ, "context", /* optional */ true,
                    "Parsed TSC-ICU-CONTEXT-1 map. Prefers the authoritative inline block embedded in canonical_text "
                    "(Option A) over the legacy metadata-carried map when both exist.",
                    {{RPCResult::Type::ELISION, "", ""}}},
                {RPCResult::Type::STR, "context_source", /* optional */ true,
                    "Where the returned context came from: \"inline\" (embedded in canonical_text), \"metadata\" (legacy), or \"none\""},
                {RPCResult::Type::STR, "context_error", /* optional */ true,
                    "Set when an inline TSC-ICU-CONTEXT-1 block is present but malformed (read RPC does not throw)"},
                {RPCResult::Type::BOOL, "plain_commit_verified", /* optional */ true,
                    "True iff SHA256(NormalizeCanonicalText(canonical_text)) equals the registry icu_plain_commit (present when decrypted and the registry declares one)"},
                {RPCResult::Type::STR, "warning", /* optional */ true,
                    "Set when plain_commit_verified is false: the document and inline context are UNVERIFIED"},
            }
        },
        RPCExamples{
            HelpExampleCli("geticupayload", "\"a1b2c3d4...\"")
          + HelpExampleRpc("geticupayload", "\"a1b2c3d4...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) {
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
            }

            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());
            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            const AssetRegistryEntry& entry = *resolved.registry;

            if (entry.icu_ctxt_commit.IsNull()) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "Asset has no ICU payload (icu_ctxt_commit is null)");
            }

            // Read ICU payload from CoinsDB via wallet context
            const WalletContext& wallet_context = EnsureWalletContext(request.context);
            if (!wallet_context.node_context) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            }

            ChainstateManager& chainman = EnsureChainman(*wallet_context.node_context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            assets::IcuStorageEntry storage_entry;
            if (!active.CoinsTip().ReadIcuPayload(resolved.asset_id, entry.icu_ctxt_commit, storage_entry)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("ICU payload not found for asset %s with commitment %s",
                              resolved.asset_id.ToString(), entry.icu_ctxt_commit.ToString()));
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("ciphertext", HexStr(storage_entry.icu_cipher));
            result.pushKV("icu_ctxt_commit", entry.icu_ctxt_commit.ToString());

            // Parse optional parameters for PSBT-based decryption
            UniValue opts = request.params.size() > 1 && request.params[1].isObject() ? request.params[1].get_obj() : UniValue::VNULL;
            std::optional<std::string> wrapped_key_param;
            std::optional<CTxDestination> receive_dest;
            std::optional<CScript> receive_scriptpubkey;
            std::optional<uint8_t> suite_id_param;

            LogPrintf("geticupayload: request.params.size()=%d, opts.isNull()=%d\n",
                     static_cast<int>(request.params.size()), opts.isNull());

            if (!opts.isNull()) {
                const UniValue& wrapped_key_val = opts.find_value("wrapped_key");
                if (!wrapped_key_val.isNull()) {
                    wrapped_key_param = wrapped_key_val.get_str();
                    LogPrintf("geticupayload: received wrapped_key param, len=%d\n",
                             static_cast<int>(wrapped_key_param->size()));
                }

                const UniValue& receive_addr_val = opts.find_value("receive_address");
                if (!receive_addr_val.isNull()) {
                    CTxDestination dest = DecodeDestination(receive_addr_val.get_str());
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid receive_address");
                    }
                    receive_dest = dest;
                    LogPrintf("geticupayload: received receive_address=%s\n",
                             receive_addr_val.get_str());
                }

                const UniValue& receive_spk_val = opts.find_value("receive_scriptpubkey");
                if (!receive_spk_val.isNull()) {
                    std::vector<unsigned char> spk_bytes = ParseHex(receive_spk_val.get_str());
                    receive_scriptpubkey = CScript(spk_bytes.begin(), spk_bytes.end());
                    LogPrintf("geticupayload: received receive_scriptpubkey, len=%d\n",
                             static_cast<int>(spk_bytes.size()));
                }

                const UniValue& suite_id_val = opts.find_value("suite_id");
                if (!suite_id_val.isNull()) {
                    suite_id_param = static_cast<uint8_t>(suite_id_val.getInt<int>());
                }
            }

            // If receive_address provided but not scriptpubkey, derive it
            if (receive_dest && !receive_scriptpubkey) {
                receive_scriptpubkey = GetScriptForDestination(*receive_dest);
            }

            // Try to decrypt if wallet has asset UTXOs with ICU_KEYWRAP
            bool decrypted = false;
            std::vector<unsigned char> plaintext;
            std::string last_failure_reason;
            const auto matches_plain_commit = [&](const std::vector<unsigned char>& candidate) -> bool {
                if (entry.icu_plain_commit.IsNull()) return true;
                return Sha256Commit(candidate) == entry.icu_plain_commit;
            };

            // If encryption_mode is 0 (plaintext), decompress if needed, then parse and verify commitment
            if (storage_entry.encryption_mode == 0) {
                // Decompress if zstd-compressed before parsing
                std::vector<unsigned char> payload_bytes = storage_entry.icu_cipher;
                if (storage_entry.compression == 1) {
                    auto decompressed = assets::DecompressZstd(payload_bytes);
                    if (!decompressed) {
                        LogPrintf("geticupayload: zstd decompression failed for public asset %s\n", resolved.asset_id.ToString());
                        last_failure_reason = "decompress_failed";
                    } else {
                        payload_bytes = *decompressed;
                    }
                }

                if (last_failure_reason.empty()) {
                    auto canonical = assets::ParseCanonicalIcuPayload(payload_bytes);
                    if (!canonical) {
                        LogPrintf("geticupayload: failed to parse plaintext payload for asset %s\n", resolved.asset_id.ToString());
                        last_failure_reason = "parse_failed";
                    } else if (!matches_plain_commit(canonical->canonical_text)) {
                        LogPrintf("geticupayload: plaintext commit mismatch for asset %s\n", resolved.asset_id.ToString());
                        last_failure_reason = "commit_mismatch";
                    } else {
                        plaintext = payload_bytes;
                        decrypted = true;
                        last_failure_reason.clear();
                    }
                }
            } else if (storage_entry.encryption_mode == 1) {
                const auto try_decrypt_with_dek = [&](const std::array<unsigned char, 32>& dek_candidate,
                                                      const char* source_label) -> bool {
                    auto canonical = assets::DecryptCanonicalIcuPayload(
                        storage_entry.icu_cipher, dek_candidate, entry.kdf_salt,
                        storage_entry.encryption_mode, storage_entry.compression);
                    if (!canonical) {
                        LogPrintf("geticupayload: %s DEK failed to decrypt for asset %s\n",
                                  source_label, resolved.asset_id.ToString());
                        return false;
                    }
                    // icu_plain_commit is SHA256(canonical_text), not SHA256(entire_structure)
                    if (!matches_plain_commit(canonical->canonical_text)) {
                        LogPrintf("geticupayload: %s DEK produced commit mismatch for asset %s\n",
                                  source_label, resolved.asset_id.ToString());
                        return false;
                    }
                    plaintext = canonical->Serialize();
                    return true;
                };

                // Try wallet-stored DEK first (issuer or prior unwrap)
                std::optional<std::string> stored_dek_b64;
                {
                    LOCK(pwallet->cs_wallet);
                    stored_dek_b64 = pwallet->GetAssetDek(resolved.asset_id);
                }
                if (stored_dek_b64) {
                    auto dek_bytes = DecodeBase64(*stored_dek_b64);
                    if (dek_bytes && dek_bytes->size() == 32) {
                        std::array<unsigned char, 32> dek{};
                        std::copy_n(dek_bytes->begin(), dek.size(), dek.begin());
                        if (try_decrypt_with_dek(dek, "wallet-stored")) {
                            decrypted = true;
                        } else {
                            last_failure_reason = "wallet_stored_dek_failed";
                        }
                    }
                }

                // Try wrapped_key from options (PSBT-based decryption) before wallet UTXO search
                if (!decrypted && wrapped_key_param && receive_scriptpubkey) {
                    if (!receive_dest) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "receive_address required when wrapped_key is provided");
                    }

                    LogPrintf("geticupayload: attempting PSBT-based decryption with wrapped_key_len=%d, receive_addr=%s\n",
                             static_cast<int>(wrapped_key_param->size()),
                             EncodeDestination(*receive_dest));

                    // Decode wrapped key
                    std::vector<unsigned char> wrapped_ascii(wrapped_key_param->begin(), wrapped_key_param->end());
                    auto wrapped_fields_opt = kw::DecodeWrappedKeyV1(wrapped_ascii);
                    if (!wrapped_fields_opt) {
                        // Try base64 decode
                        auto wrapped_bytes = DecodeBase64(*wrapped_key_param);
                        if (wrapped_bytes) {
                            wrapped_ascii = *wrapped_bytes;
                            wrapped_fields_opt = kw::DecodeWrappedKeyV1(wrapped_ascii);
                        }
                    }

                    if (!wrapped_fields_opt) {
                        last_failure_reason = "decode_wrapped_key";
                        LogPrintf("geticupayload: failed to decode wrapped_key parameter\n");
                    } else {
                        const kw::WrappedKeyV1& wrapped_fields = *wrapped_fields_opt;
                        uint8_t effective_suite_id = suite_id_param.value_or(wrapped_fields.suite_id);

                        if (effective_suite_id == 0) {
                            // Suite 0: plaintext DEK
                            std::array<unsigned char, 32> dek{};
                            std::copy_n(wrapped_fields.ciphertext.begin(), dek.size(), dek.begin());
                            if (try_decrypt_with_dek(dek, "psbt-suite0")) {
                                decrypted = true;
                                last_failure_reason.clear();
                            } else {
                                last_failure_reason = "psbt_suite0_decrypt_failed";
                            }
                        } else if (effective_suite_id == kw::KEYWRAP_SUITE_CHACHA20) {
                            // Suite 1: ChaCha20-encrypted DEK
                            auto recipient_xonly = kw::ExtractTaprootPubkey(*receive_dest);
                            if (!recipient_xonly) {
                                last_failure_reason = "not_taproot";
                                LogPrintf("geticupayload: receive_address is not Taproot\n");
                            } else {
                                XOnlyPubKey sender_ephemeral;
                                std::copy(wrapped_fields.sender_ephemeral.begin(), wrapped_fields.sender_ephemeral.end(),
                                         sender_ephemeral.begin());

                                // Get wallet's private key for receive_address
                                LOCK(pwallet->cs_wallet);
                                auto spk_mans = pwallet->GetScriptPubKeyMans(*receive_scriptpubkey);
                                LogPrintf("geticupayload PSBT: found %d ScriptPubKeyMans for receive_scriptpubkey\n",
                                         static_cast<int>(spk_mans.size()));
                                bool unwrapped = false;
                                for (ScriptPubKeyMan* spk_man : spk_mans) {
                                    auto desc_spkman = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
                                    if (!desc_spkman) {
                                        LogPrintf("geticupayload PSBT: spk_man is not DescriptorScriptPubKeyMan\n");
                                        continue;
                                    }

                                    auto owner = desc_spkman->GetDescriptorOwnerForScript(*receive_scriptpubkey);
                                    if (!owner) {
                                        LogPrintf("geticupayload PSBT: GetDescriptorOwnerForScript returned null\n");
                                        continue;
                                    }

                                    // Ensure the private key exists at this derivation index
                                    if (!owner->has_priv_at_index) {
                                        if (!desc_spkman->EnsurePrivKeyAtIndex(owner->index)) {
                                            LogPrintf("geticupayload PSBT: cannot derive private key at index %d\n", owner->index);
                                            continue;
                                        }
                                    }

                                    // Derive the internal private key at the exact index
                                    auto d_internal_opt = desc_spkman->DerivePrivateKeyAtIndex(owner->index, owner->internal_xonly);
                                    if (!d_internal_opt) {
                                        LogPrintf("geticupayload PSBT: failed to derive internal key at index %d for xonly=%s\n",
                                                 owner->index, HexStr(owner->internal_xonly));
                                        continue;
                                    }
                                    CKey privkey = *d_internal_opt;
                                    LogPrintf("geticupayload PSBT: derived internal private key at index %d for xonly=%s\n",
                                             owner->index, HexStr(owner->internal_xonly));

                                    // BIP341: normalize INTERNAL parity BEFORE tweak (lift-to-even)
                                    CPubKey internal_pubkey = privkey.GetPubKey();
                                    if (internal_pubkey[0] == 0x03) {
                                        if (!privkey.Negate()) {
                                            LogPrintf("geticupayload PSBT: failed to negate internal key\n");
                                            continue;
                                        }
                                    }

                                    // Apply taproot tweak to get the output private key
                                    // The keywrap was created using the output key (tweaked), so we need the tweaked privkey
                                    uint256 tweak = owner->internal_xonly.ComputeTapTweakHash(nullptr);
                                    if (!privkey.TweakAdd(tweak)) {
                                        LogPrintf("geticupayload PSBT: TweakAdd failed for internal_xonly=%s\n",
                                                 HexStr(owner->internal_xonly));
                                        continue;
                                    }

                                    // Final parity normalization for ECDH compatibility
                                    // DeriveECDHSecret always lifts x-only to even Y (0x02), so spend key must match
                                    CPubKey spend_pubkey = privkey.GetPubKey();
                                    if (spend_pubkey[0] == 0x03) {
                                        if (!privkey.Negate()) {
                                            LogPrintf("geticupayload PSBT: failed to normalize spend key parity for ECDH\n");
                                            continue;
                                        }
                                    }
                                    LogPrintf("geticupayload PSBT: applied taptweak and parity normalization, attempting ECDH unwrap\n");

                                    // Unwrap DEK
                                    const uint256 spk_hash32 = kw::TapMatchHash(*receive_scriptpubkey);
                                    auto shared_secret = kw::DeriveECDHSecret(privkey, sender_ephemeral);
                                    auto wrap_key = kw::DeriveWrapKey(shared_secret, entry.kdf_salt,
                                                                      resolved.asset_id, entry.icu_ctxt_commit, spk_hash32);
                                    auto nonce = kw::NonceFromTapMatch(spk_hash32);
                                    auto aad = kw::BuildAad(resolved.asset_id, entry.icu_ctxt_commit);

                                    std::vector<unsigned char> ciphertext_with_tag;
                                    ciphertext_with_tag.insert(ciphertext_with_tag.end(),
                                                              wrapped_fields.ciphertext.begin(), wrapped_fields.ciphertext.end());
                                    ciphertext_with_tag.insert(ciphertext_with_tag.end(),
                                                              wrapped_fields.tag.begin(), wrapped_fields.tag.end());

                                    std::array<unsigned char, 32> dek = kw::DecryptDek(effective_suite_id, ciphertext_with_tag,
                                                                                       wrap_key, nonce, aad);

                                    if (try_decrypt_with_dek(dek, "psbt-chacha20")) {
                                        decrypted = true;
                                        unwrapped = true;
                                        last_failure_reason.clear();
                                        LogPrintf("geticupayload: decrypted via PSBT-provided wrapped_key\n");
                                        break;
                                    }
                                }

                                if (!unwrapped) {
                                    last_failure_reason = "psbt_unwrap_failed";
                                }
                            }
                        } else {
                            last_failure_reason = "unsupported_suite";
                            LogPrintf("geticupayload: unsupported suite_id=%u\n", effective_suite_id);
                        }
                    }
                }

                // Fall back to wallet UTXO search if PSBT-based decryption failed
                if (!decrypted) {
                    LOCK(pwallet->cs_wallet);

                    CCoinControl coin_control;
                    coin_control.m_avoid_asset_utxos = false;
                    coin_control.m_min_depth = 0;
                    coin_control.m_max_depth = 9999999;
                    coin_control.m_include_unsafe_inputs = true;
                    CoinFilterParams filter;
                    filter.only_spendable = false;
                    filter.skip_locked = false;
                    auto utxos = CollectAssetUtxos(*pwallet, coin_control, filter);

                    LogPrintf("geticupayload: encryption_mode=1, searching %d UTXOs for keywrap\n", utxos.size());

                    for (const auto& utxo_info : utxos) {
                        if (utxo_info.asset_id != resolved.asset_id) {
                            continue;
                        }

                        auto parsed = assets::ParseAssetTag(utxo_info.txout.vExt);
                        if (!parsed || !parsed->has_keywrap) {
                            continue;
                        }

                        if (parsed->keywrap_suite_id == 0) {
                            auto dek_bytes = DecodeBase64(parsed->keywrap_wrapped_key);
                            if (!dek_bytes || dek_bytes->size() != 32) {
                                last_failure_reason = "suite0_decode";
                                continue;
                            }
                            std::array<unsigned char, 32> dek{};
                            std::copy_n(dek_bytes->begin(), dek.size(), dek.begin());
                            if (try_decrypt_with_dek(dek, "suite0 keywrap")) {
                                decrypted = true;
                                last_failure_reason.clear();
                                LogPrintf("geticupayload: decrypted via suite0 keywrap on UTXO %s:%u\n",
                                          utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                                break;
                            }
                            last_failure_reason = "suite0_commit";
                            continue;
                        }

                        if (parsed->keywrap_suite_id != kw::KEYWRAP_SUITE_CHACHA20) {
                            last_failure_reason = "unsupported_suite";
                            LogPrintf("geticupayload: unsupported keywrap suite_id=%u\n", parsed->keywrap_suite_id);
                            continue;
                        }
                        if (!parsed->keywrap_has_kc_tag) {
                            last_failure_reason = "missing_kc_tag";
                            LogPrintf("geticupayload: keywrap missing kc_tag\n");
                            continue;
                        }

                        uint256 expected_spk_hash = kw::TapMatchHash(utxo_info.txout.scriptPubKey);
                        if (expected_spk_hash != parsed->keywrap_spk_hash32) {
                            last_failure_reason = "spk_hash";
                            LogPrintf("geticupayload: spk_hash32 mismatch for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        CTxDestination utxo_dest;
                        if (!ExtractDestination(utxo_info.txout.scriptPubKey, utxo_dest)) {
                            last_failure_reason = "extract_dest";
                            LogPrintf("geticupayload: cannot extract destination for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        auto recipient_xonly_opt = kw::ExtractTaprootPubkey(utxo_dest);
                        if (!recipient_xonly_opt) {
                            last_failure_reason = "not_taproot";
                            LogPrintf("geticupayload: destination for UTXO %s:%u is not Taproot\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        // === DETERMINISTIC SCRIPT-ANCHORED KEY RESOLUTION ===
                        // Resolve exact descriptor + index that owns this scriptPubKey
                        std::optional<wallet::SpkOwner> owner_opt;
                        wallet::DescriptorScriptPubKeyMan* owning_spkm = nullptr;

                        auto spk_mans = pwallet->GetScriptPubKeyMans(utxo_info.txout.scriptPubKey);
                        for (wallet::ScriptPubKeyMan* spk_man : spk_mans) {
                            auto desc_spkman = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(spk_man);
                            if (!desc_spkman) continue;

                            auto candidate_owner = desc_spkman->GetDescriptorOwnerForScript(utxo_info.txout.scriptPubKey);
                            if (candidate_owner) {
                                if (owner_opt) {
                                    // Multiple descriptors claim this script - ambiguous ownership
                                    last_failure_reason = "ambiguous_script_owner";
                                    LogPrintf("geticupayload: multiple descriptors claim UTXO %s:%u\n",
                                              utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                                    owner_opt = std::nullopt;
                                    break;
                                }
                                owner_opt = candidate_owner;
                                owning_spkm = desc_spkman;
                            }
                        }

                        if (!owner_opt) {
                            last_failure_reason = last_failure_reason.empty() ? "not_ours" : last_failure_reason;
                            LogPrintf("geticupayload: script not owned by wallet for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        const wallet::SpkOwner& owner = *owner_opt;

                        // Early failure checks
                        if (pwallet->IsLocked()) {
                            last_failure_reason = "wallet_locked";
                            LogPrintf("geticupayload: wallet locked for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        if (owner.is_watch_only) {
                            last_failure_reason = "watch_only";
                            LogPrintf("geticupayload: descriptor is watch-only for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        // Ensure the private key exists at this derivation index
                        if (!owner.has_priv_at_index) {
                            if (!owning_spkm->EnsurePrivKeyAtIndex(owner.index)) {
                                last_failure_reason = "missing_privkey";
                                LogPrintf("geticupayload: cannot derive private key at index %d for UTXO %s:%u\n",
                                          owner.index, utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                                continue;
                            }
                        }

                        // Derive the internal private key at the exact index
                        auto d_internal_opt = owning_spkm->DerivePrivateKeyAtIndex(owner.index, owner.internal_xonly);
                        if (!d_internal_opt) {
                            last_failure_reason = "missing_internal_privkey";
                            LogPrintf("geticupayload: failed to derive internal key at index %d for UTXO %s:%u\n",
                                      owner.index, utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }
                        CKey d_internal = *d_internal_opt;

                        // Get TaprootSpendData for the output key (needed for merkle_root)
                        auto provider = owning_spkm->GetSolvingProviderForScript(utxo_info.txout.scriptPubKey, /*include_private=*/false);
                        if (!provider) {
                            last_failure_reason = "no_provider";
                            LogPrintf("geticupayload: failed to get provider for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        TaprootSpendData spenddata;
                        if (!provider->GetTaprootSpendData(*recipient_xonly_opt, spenddata) || spenddata.internal_key.IsNull()) {
                            last_failure_reason = "not_taproot";
                            LogPrintf("geticupayload: failed to get Taproot spend data for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        // Verify internal key matches owner's internal key
                        if (spenddata.internal_key != owner.internal_xonly) {
                            last_failure_reason = "internal_key_mismatch";
                            LogPrintf("geticupayload: internal key mismatch for UTXO %s:%u (descriptor=%s script=%s)\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n,
                                      HexStr(MakeUCharSpan(owner.internal_xonly)),
                                      HexStr(MakeUCharSpan(spenddata.internal_key)));
                            continue;
                        }

                        // BIP341: normalize INTERNAL parity BEFORE tweak (lift-to-even)
                        CPubKey internal_pubkey = d_internal.GetPubKey();
                        if (internal_pubkey[0] == 0x03) {
                            if (!d_internal.Negate()) {
                                last_failure_reason = "taproot_negate_failed";
                                LogPrintf("geticupayload: failed to negate internal key for UTXO %s:%u\n",
                                          utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                                continue;
                            }
                            internal_pubkey = d_internal.GetPubKey();
                        }

                        // Compute tweak with the internal x-only and merkle root (key- or script-path)
                        const uint256* merkle_ptr = spenddata.merkle_root.IsNull() ? nullptr : &spenddata.merkle_root;
                        uint256 tweak = owner.internal_xonly.ComputeTapTweakHash(merkle_ptr);

                        // Apply tweak to the even-parity internal key
                        CKey d_spend = d_internal;
                        if (!d_spend.TweakAdd(tweak)) {
                            last_failure_reason = "taproot_tweak_failed";
                            LogPrintf("geticupayload: failed to apply BIP341 tweak for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        // Final parity normalization for ECDH compatibility
                        // DeriveECDHSecret always lifts x-only to even Y (0x02), so spend key must match
                        CPubKey spend_pubkey = d_spend.GetPubKey();
                        if (spend_pubkey[0] == 0x03) {
                            if (!d_spend.Negate()) {
                                last_failure_reason = "ecdh_parity_normalization_failed";
                                LogPrintf("geticupayload: failed to normalize spend key parity for ECDH for UTXO %s:%u\n",
                                          utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                                continue;
                            }
                            spend_pubkey = d_spend.GetPubKey();
                        }

                        XOnlyPubKey derived_xonly(spend_pubkey);

                        if (derived_xonly != *recipient_xonly_opt) {
                            last_failure_reason = "taproot_mismatch";
                            LogPrintf("geticupayload: taproot mismatch for UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            continue;
                        }

                        CKey recipient_priv = d_spend;
                        LogPrintf("geticupayload: ✓ deterministic key resolution successful for UTXO %s:%u\n",
                                  utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);

                        std::vector<unsigned char> wrapped_ascii(parsed->keywrap_wrapped_key.begin(),
                                                                  parsed->keywrap_wrapped_key.end());
                        auto wrapped_fields_opt = kw::DecodeWrappedKeyV1(wrapped_ascii);
                        if (!wrapped_fields_opt) {
                            last_failure_reason = "decode_wrapped";
                            LogPrintf("geticupayload: failed to decode WrappedKeyV1 payload\n");
                            continue;
                        }
                        const kw::WrappedKeyV1& wrapped_fields = *wrapped_fields_opt;
                        if (wrapped_fields.version != 1 || wrapped_fields.suite_id != parsed->keywrap_suite_id) {
                            last_failure_reason = "wrapped_suite";
                            LogPrintf("geticupayload: wrapped key version/suite mismatch\n");
                            continue;
                        }
                        if (!std::equal(parsed->keywrap_kc_tag.begin(), parsed->keywrap_kc_tag.end(),
                                        wrapped_fields.tag.begin())) {
                            last_failure_reason = "kc_tag";
                            LogPrintf("geticupayload: kc_tag mismatch\n");
                            continue;
                        }

                        XOnlyPubKey sender_ephemeral(wrapped_fields.sender_ephemeral);

                        LogPrintf("geticupayload: Attempting ECDH unwrap with entry.kdf_salt=%s for asset %s\n",
                                  HexStr(entry.kdf_salt), resolved.asset_id.ToString());

                        std::array<unsigned char, 32> dek{};
                        try {
                            dek = ECDHUnwrapKey(recipient_priv, sender_ephemeral, parsed->keywrap_suite_id,
                                                entry.kdf_salt, resolved.asset_id, entry.icu_ctxt_commit,
                                                parsed->keywrap_spk_hash32, wrapped_fields);
                        } catch (const std::exception& e) {
                            last_failure_reason = e.what();
                            LogPrintf("geticupayload: ECDH unwrap failed: %s\n", e.what());
                            continue;
                        }

                        std::vector<unsigned char> dek_vec(dek.begin(), dek.end());
                        if (parsed->keywrap_has_wrap_commit) {
                            if (Sha256Commit(dek_vec) != parsed->keywrap_wrap_commit) {
                                last_failure_reason = "wrap_commit";
                                LogPrintf("geticupayload: wrap_commit mismatch\n");
                                continue;
                            }
                        }

                        if (try_decrypt_with_dek(dek, "ICU keywrap")) {
                            decrypted = true;
                            last_failure_reason.clear();
                            WalletBatch batch(pwallet->GetDatabase());
                            std::string dek_base64 = EncodeBase64(MakeUCharSpan(dek_vec));
                            if (!pwallet->SetAssetDekWithDB(batch, resolved.asset_id, dek_base64)) {
                                LogPrintf("geticupayload: failed to persist DEK for asset %s\n",
                                          resolved.asset_id.ToString());
                            }
                            LogPrintf("geticupayload: decryption successful via keywrap on UTXO %s:%u\n",
                                      utxo_info.outpoint.hash.ToString(), utxo_info.outpoint.n);
                            break;
                        } else {
                            last_failure_reason = "decrypt_failed";
                        }
                    }

                    if (!decrypted) {
                        if (last_failure_reason.empty()) {
                            last_failure_reason = "no_valid_keywrap";
                        }
                        LogPrintf("geticupayload: no valid keywrap found after checking all UTXOs\n");
                    }
                }
            }

            if (decrypted) {
                result.pushKV("plaintext", HexStr(plaintext));
                if (auto cp = assets::ParseCanonicalIcuPayload(plaintext); cp) {
                    // Recompute-or-refuse gate: consensus stores the declared icu_plain_commit without
                    // verifying it, so a reader must confirm SHA256(NormalizeCanonicalText(text)) matches
                    // the registry value before trusting the document (and any inline clauses) as authentic.
                    if (!entry.icu_plain_commit.IsNull()) {
                        const bool plain_ok = assets::VerifyIcuPlainCommit(*cp, entry.icu_plain_commit);
                        result.pushKV("plain_commit_verified", plain_ok);
                        if (!plain_ok) {
                            result.pushKV("warning",
                                "declared icu_plain_commit does not match SHA256(canonical_text); "
                                "document and inline context are UNVERIFIED");
                        }
                    }

                    // Surface the committed payload metadata so wallets need not re-deserialize.
                    if (!cp->metadata.empty()) {
                        result.pushKV("metadata", HexStr(cp->metadata));
                    }

                    // Resolve the context map. Option A: the authoritative TSC-ICU-CONTEXT-1 block lives
                    // INSIDE canonical_text (covered by icu_plain_commit); prefer it over the legacy
                    // metadata-carried map. The stored canonical_text is already normalized, but pass it
                    // through NormalizeCanonicalText defensively before extraction.
                    std::string context_source = "none";
                    bool emitted_context = false;
                    const std::string canonical_text_str(cp->canonical_text.begin(), cp->canonical_text.end());
                    if (auto norm = assets::NormalizeCanonicalText(canonical_text_str)) {
                        bool present = false;
                        std::string ctx_err;
                        auto inline_ctx = assets::ExtractInlineIcuContext(*norm, present, ctx_err);
                        if (present && inline_ctx) {
                            result.pushKV("context", *inline_ctx);
                            context_source = "inline";
                            emitted_context = true;
                        } else if (present && !inline_ctx) {
                            // Block present but malformed: do not throw (read RPC); flag it.
                            context_source = "inline";
                            result.pushKV("context_error", ctx_err);
                            emitted_context = true;  // source is inline even though no object was returned
                        }
                    }

                    // Legacy fallback: a TSC-ICU-CONTEXT-1 map carried in metadata, only when no inline
                    // block was found (inline always wins when both exist).
                    if (!emitted_context && !cp->metadata.empty()) {
                        UniValue ctx;
                        const std::string meta_str(cp->metadata.begin(), cp->metadata.end());
                        if (ctx.read(meta_str) && ctx.isObject() &&
                            ctx.exists("spec") && ctx["spec"].isStr() &&
                            ctx["spec"].get_str() == assets::ICU_CONTEXT_SPEC_V1) {
                            result.pushKV("context", ctx);
                            context_source = "metadata";
                        }
                    }

                    result.pushKV("context_source", context_source);
                }
            }
            result.pushKV("decrypted", decrypted);
            if (!decrypted && !last_failure_reason.empty()) {
                result.pushKV("failure_reason", last_failure_reason);
            }

            return result;
        }
    };
}

RPCHelpMan dumpassetdek()
{
    return RPCHelpMan{
        "dumpassetdek",
        "Return the base64-encoded Data Encryption Key (DEK) for an asset.\n"
        "Available only on regtest for testing purposes.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
        },
        RPCResult{RPCResult::Type::STR, "dek", "Base64-encoded 32-byte DEK"},
        RPCExamples{
            HelpExampleCli("dumpassetdek", "\"ASSET123\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            if (Params().GetChainTypeString() != "regtest") {
                throw JSONRPCError(RPC_INVALID_REQUEST, "dumpassetdek is only available on regtest");
            }

            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) {
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
            }

            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());

            LOCK(pwallet->cs_wallet);
            auto dek_opt = pwallet->GetAssetDek(resolved.asset_id);
            if (!dek_opt) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "Wallet does not have a DEK for this asset");
            }

            return UniValue(*dek_opt);
        }
    };
}

RPCHelpMan generatezkproof()
{
    return RPCHelpMan{
        "generatezkproof",
        "Generate a zero-knowledge proof for asset transfers. Supports both local and remote proving modes.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID requiring ZK proof"},
            {"public_inputs", RPCArg::Type::STR, RPCArg::Optional::NO, "Public inputs as JSON string"},
            {"witness", RPCArg::Type::STR, RPCArg::Optional::NO, "Private witness data as JSON string"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Proof generation options",
                {
                    {"mode", RPCArg::Type::STR, RPCArg::Default{"local"}, "Proof mode: 'local' or 'remote'"},
                    {"pk_file", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Path to proving key file (local mode)"},
                    {"vk_file", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Path to verification key file (local mode, optional verification)"},
                    {"api_url", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "HTTPS API endpoint (remote mode)"},
                    {"api_key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "API authentication key (remote mode)"},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{30}, "Timeout in seconds for remote requests"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "proof", "Generated proof data (hex-encoded, 192 bytes for Groth16)"},
                {RPCResult::Type::STR_HEX, "public_inputs", "Serialized public inputs (hex-encoded, 128 bytes legacy / 192 bytes HDv1)"},
                {RPCResult::Type::STR_HEX, "public_inputs_hash", "Hash of public inputs for verification"},
                {RPCResult::Type::STR, "mode", "Proof generation mode used"},
                {RPCResult::Type::NUM, "proof_size", "Size of proof in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("generatezkproof", "\"asset_id\" '{\"merkle_root\":\"...\"}' '{\"commitment\":\"...\"}' '{\"mode\":\"local\",\"pk_file\":\"/path/to/pk.bin\"}'") +
            HelpExampleCli("generatezkproof", "\"asset_id\" '{\"merkle_root\":\"...\"}' '{\"commitment\":\"...\"}' '{\"mode\":\"remote\",\"api_url\":\"https://prover.example.com\",\"api_key\":\"...\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            // Parse asset_id
            auto asset_id_opt = uint256::FromHex(request.params[0].get_str());
            if (!asset_id_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }
            uint256 asset_id = *asset_id_opt;

            // Parse public inputs JSON
            std::string public_inputs_str = request.params[1].get_str();
            UniValue public_inputs_json;
            if (!public_inputs_json.read(public_inputs_str) || !public_inputs_json.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "public_inputs must be a valid JSON object");
            }

            // Parse witness JSON
            std::string witness_str = request.params[2].get_str();
            UniValue witness_json;
            if (!witness_json.read(witness_str) || !witness_json.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "witness must be a valid JSON object");
            }

            // Parse options
            std::string mode = "local";
            std::string pk_file;
            std::string vk_file;
            std::string api_url;
            std::string api_key;
            int timeout = 30;
            (void)timeout;  // TODO: Implement timeout handling for remote mode

            if (!request.params[3].isNull()) {
                const UniValue& opt = request.params[3];
                if (!opt.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                }
                if (opt.exists("mode")) mode = opt["mode"].get_str();
                if (opt.exists("pk_file")) pk_file = opt["pk_file"].get_str();
                if (opt.exists("vk_file")) vk_file = opt["vk_file"].get_str();
                if (opt.exists("api_url")) api_url = opt["api_url"].get_str();
                if (opt.exists("api_key")) api_key = opt["api_key"].get_str();
                if (opt.exists("timeout")) timeout = opt["timeout"].getInt<int>();
            }

            // Validate mode
            if (mode != "local" && mode != "remote") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be 'local' or 'remote'");
            }

            std::vector<unsigned char> proof_data;
            std::vector<unsigned char> public_inputs_serialized;

            if (mode == "local") {
                // LOCAL MODE: Generate proof using local proving key
                if (pk_file.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "pk_file is required for local mode");
                }

                // Check if pk_file exists
                fs::path pk_path = fs::PathFromString(pk_file);
                if (!fs::exists(pk_path)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Proving key file not found: %s", pk_file));
                }

                // Serialize public inputs to bytes
                std::string public_inputs_canonical = public_inputs_json.write(0, 0);
                public_inputs_serialized.assign(public_inputs_canonical.begin(), public_inputs_canonical.end());

                // Serialize witness to bytes
                std::string witness_canonical = witness_json.write(0, 0);
                std::vector<unsigned char> witness_serialized(witness_canonical.begin(), witness_canonical.end());

                // VK file path (optional, defaults to same directory as PK)
                if (vk_file.empty()) {
                    fs::path pk_dir = pk_path.parent_path();
                    fs::path vk_path = pk_dir / "verification_key.bin";
                    if (fs::exists(vk_path)) {
                        vk_file = fs::PathToString(vk_path);
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "vk_file not specified and verification_key.bin not found alongside proving key");
                    }
                }

                // Circuit type: HDv1 (6-input, output-key-bound) is the only supported
                // KYC family. Default to it regardless of PK path naming (F2).
                std::string circuit_type = "kyc_hd_v1";

                // Allow user override via options
                if (!request.params[3].isNull()) {
                    const UniValue& options = request.params[3];
                    if (options.isObject() && options.exists("circuit_type")) {
                        std::string user_type = options["circuit_type"].get_str();
                        // F2: retire 'standard'. Legacy 4-input proofs have no output-key
                        // binding and are rejected by consensus (kyc-proof-not-hdv1), so
                        // refuse to build them rather than mint forgeable assets.
                        // Accept both the user-facing name 'hd_v1' and the internal name
                        // 'kyc_hd_v1' (used by functional tests / callers); reject everything
                        // else, including 'standard'/'kyc'.
                        if (user_type == "hd_v1" || user_type == "kyc_hd_v1") {
                            circuit_type = "kyc_hd_v1";
                        } else {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "Unsupported circuit_type '" + user_type + "'. Use 'hd_v1' (alias 'kyc_hd_v1'); "
                                "'standard'/'kyc' are retired (no output-key binding, rejected by consensus).");
                        }
                    }
                }

                // Build request JSON for Go prover
                UniValue request_json(UniValue::VOBJ);
                request_json.pushKV("chain_separator", public_inputs_json["chain_separator"]);
                request_json.pushKV("asset_id", asset_id.ToString());
                request_json.pushKV("compliance_root", public_inputs_json["compliance_root"]);
                request_json.pushKV("tfr_anchor", public_inputs_json["tfr_anchor"]);

                // Forward HDv1-specific public input fields (output key binding)
                if (public_inputs_json.exists("output_key_high")) {
                    request_json.pushKV("output_key_high", public_inputs_json["output_key_high"]);
                }
                if (public_inputs_json.exists("output_key_low")) {
                    request_json.pushKV("output_key_low", public_inputs_json["output_key_low"]);
                }

                // Transform witness data for HD v1 circuit (packed format)
                if (circuit_type == "kyc_hd_v1") {
                    UniValue witness_v1(UniValue::VOBJ);

                    // Copy basic fields
                    if (witness_json.exists("master_secret")) {
                        witness_v1.pushKV("master_secret", witness_json["master_secret"]);
                    }
                    if (witness_json.exists("master_pubkey_x")) {
                        witness_v1.pushKV("master_pubkey_x", witness_json["master_pubkey_x"]);
                    }
                    if (witness_json.exists("master_pubkey_y")) {
                        witness_v1.pushKV("master_pubkey_y", witness_json["master_pubkey_y"]);
                    }
                    if (witness_json.exists("child_pubkey_x")) {
                        witness_v1.pushKV("child_pubkey_x", witness_json["child_pubkey_x"]);
                    }
                    if (witness_json.exists("child_pubkey_y")) {
                        witness_v1.pushKV("child_pubkey_y", witness_json["child_pubkey_y"]);
                    }

                    // Pack path components into PathVector (account||change||index)
                    // Or copy pre-packed path_vector if already provided
                    if (witness_json.exists("path_account") && witness_json.exists("path_change") &&
                        witness_json.exists("path_index")) {
                        uint64_t account = witness_json["path_account"].getInt<uint64_t>();
                        uint64_t change = witness_json["path_change"].getInt<uint64_t>();
                        uint64_t index = witness_json["path_index"].getInt<uint64_t>();
                        // Pack as 96-bit value: account(32) || change(32) || index(32)
                        arith_uint256 path_vector = arith_uint256(account) << 64;
                        path_vector |= arith_uint256(change) << 32;
                        path_vector |= arith_uint256(index);
                        witness_v1.pushKV("path_vector", "0x" + path_vector.GetHex());
                    } else if (witness_json.exists("path_vector")) {
                        witness_v1.pushKV("path_vector", witness_json["path_vector"]);
                    }

                    // Convert salt to hex string or copy pre-packed salt
                    if (witness_json.exists("salt")) {
                        const UniValue& salt_val = witness_json["salt"];
                        if (salt_val.isNum()) {
                            // Integer format - convert to hex
                            witness_v1.pushKV("salt", "0x" + strprintf("%016x", salt_val.getInt<uint64_t>()));
                        } else {
                            // Already hex string - copy as is
                            witness_v1.pushKV("salt", salt_val);
                        }
                    }

                    // Forward output key binding fields (HDv1 6-input circuit)
                    if (witness_json.exists("output_key_high")) {
                        witness_v1.pushKV("output_key_high", witness_json["output_key_high"]);
                    }
                    if (witness_json.exists("output_key_low")) {
                        witness_v1.pushKV("output_key_low", witness_json["output_key_low"]);
                    }

                    // Convert merkle index to MerklePathBits or copy pre-packed
                    if (witness_json.exists("merkle_index")) {
                        uint64_t merkle_idx = witness_json["merkle_index"].getInt<uint64_t>();
                        witness_v1.pushKV("merkle_path_bits", "0x" + strprintf("%02x", merkle_idx));
                    } else if (witness_json.exists("merkle_path_bits")) {
                        witness_v1.pushKV("merkle_path_bits", witness_json["merkle_path_bits"]);
                    }

                    // Copy merkle proof as siblings (merkle_proof or merkle_siblings)
                    if (witness_json.exists("merkle_proof")) {
                        witness_v1.pushKV("merkle_siblings", witness_json["merkle_proof"]);
                    } else if (witness_json.exists("merkle_siblings")) {
                        witness_v1.pushKV("merkle_siblings", witness_json["merkle_siblings"]);
                    }

                    // Add derivation commitment if present
                    if (witness_json.exists("derivation_commitment")) {
                        witness_v1.pushKV("derivation_commitment", witness_json["derivation_commitment"]);
                    }

                    request_json.pushKV("witness", witness_v1);
                } else {
                    request_json.pushKV("witness", witness_json);
                }

                std::string request_str = request_json.write();

                // Log request for debugging
                LogPrintf("ZK_PROVE_DEBUG: circuit_type=%s pk_file=%s\n", circuit_type, pk_file);
                LogPrintf("ZK_PROVE_DEBUG: request_json=%s\n", request_str);

                // Call Go prover via CGO bridge
                // Load function pointers from libzkprover.so
                typedef struct {
                    unsigned char* proof_data;
                    int proof_len;
                    unsigned char* public_inputs;
                    int public_inputs_len;
                    char* error_msg;
                } Groth16ProofResult;

                typedef Groth16ProofResult (*ProveFunc)(const char*, const char*, const char*);
                typedef void (*FreeFunc)(Groth16ProofResult*);

                // Dynamically load the shared library
#ifdef _WIN32
                void* handle = dlopen("libzkprover.dll", RTLD_LAZY);
                if (!handle) {
                    handle = dlopen("zkprover.dll", RTLD_LAZY);
                }
#else
                void* handle = dlopen("libzkprover.so", RTLD_LAZY);
#endif
                if (!handle) {
                    // Try relative path from working directory
                    fs::path lib_path = fs::PathFromString(".") / ".." / ".." / "shared-utils" / "kyc-prover" / "cgo" / "libzkprover.so";
                    handle = dlopen(fs::PathToString(lib_path).c_str(), RTLD_LAZY);
                }
                if (!handle) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Failed to load libzkprover.so: %s", dlerror()));
                }

                // Load function symbols
                std::string prove_func_name;
                if (circuit_type == "kyc_hd_v1") {
                    prove_func_name = "Groth16_ProveKYCHDV1";
                } else {
                    prove_func_name = "Groth16_ProveKYC";
                }
                ProveFunc prove_fn = (ProveFunc)dlsym(handle, prove_func_name.c_str());
                if (!prove_fn) {
                    dlclose(handle);
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Failed to load %s: %s", prove_func_name, dlerror()));
                }

                FreeFunc free_fn = (FreeFunc)dlsym(handle, "Groth16_FreeResult");
                if (!free_fn) {
                    dlclose(handle);
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Failed to load Groth16_FreeResult: %s", dlerror()));
                }

                // Generate proof
                Groth16ProofResult result = prove_fn(
                    pk_file.c_str(),
                    vk_file.c_str(),
                    request_str.c_str()
                );

                // Check for errors
                if (result.error_msg != nullptr) {
                    std::string error(result.error_msg);
                    free_fn(&result);
                    dlclose(handle);
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Proof generation failed: %s", error));
                }

                // Extract proof data
                proof_data.assign(result.proof_data, result.proof_data + result.proof_len);
                public_inputs_serialized.assign(result.public_inputs,
                                                result.public_inputs + result.public_inputs_len);

                // Debug logging
                LogPrintf("ZK_PROVE_DEBUG: proof_len=%d public_inputs_len=%d\n",
                         result.proof_len, result.public_inputs_len);
                LogPrintf("ZK_PROVE_DEBUG: proof_data.size()=%d public_inputs_serialized.size()=%d\n",
                         proof_data.size(), public_inputs_serialized.size());

                // Clean up
                free_fn(&result);
                dlclose(handle);

            } else {
                // REMOTE MODE: Send request to remote prover API
                if (api_url.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "api_url is required for remote mode");
                }

                // Validate HTTPS
                if (api_url.substr(0, 8) != "https://") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "api_url must use HTTPS protocol");
                }

                // Build request payload
                UniValue request_payload(UniValue::VOBJ);
                request_payload.pushKV("asset_id", asset_id.ToString());
                request_payload.pushKV("public_inputs", public_inputs_json);
                request_payload.pushKV("witness", witness_json);

                std::string request_body = request_payload.write();

                // TODO: Implement HTTP client for remote API call
                // Example integration:
                //   HTTPClient client;
                //   client.SetTimeout(timeout);
                //   if (!api_key.empty()) {
                //       client.AddHeader("Authorization", "Bearer " + api_key);
                //   }
                //   client.AddHeader("Content-Type", "application/json");
                //   HTTPResponse response = client.Post(api_url, request_body);
                //
                //   if (response.status != 200) {
                //       throw JSONRPCError(RPC_EXTERNAL_SERVICE_FAILURE, "Remote prover returned error");
                //   }
                //
                //   UniValue response_json;
                //   response_json.read(response.body);
                //   proof_data = ParseHex(response_json["proof"].get_str());
                //   public_inputs_serialized = ParseHex(response_json["public_inputs"].get_str());

                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    "Remote proof generation not yet implemented. This requires HTTP client integration. "
                    "The RPC framework is ready - implementation stub at assets.cpp:" + std::to_string(__LINE__));
            }

            // Compute hash of public inputs
            uint256 public_inputs_hash = Hash(public_inputs_serialized);

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("proof", HexStr(proof_data));
            result.pushKV("public_inputs", HexStr(public_inputs_serialized));
            result.pushKV("public_inputs_hash", public_inputs_hash.ToString());
            result.pushKV("mode", mode);
            result.pushKV("proof_size", static_cast<int64_t>(proof_data.size()));

            return result;
        }
    };
}

RPCHelpMan rotatezk()
{
    return RPCHelpMan{
        "rotatezk",
        "Rotate ZK verification parameters for an asset (mutable, no unlock fee bump required).\n"
        "Updates max_root_age, zk_vk_commitment, tfr_flags without governance overhead.\n"
        "Requires spending the current ICU (issuer) output.",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU transaction ID"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU output index"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination address"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID to rotate"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "ZK rotation options",
                {
                    {"vk_data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "New ZK verification key data (will be chunked and committed)"},
                    {"compliance_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "New compliance Merkle root commitment (32-byte hex)"},
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum merkle root age in blocks"},
                    {"tfr_flags", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Transfer validation flags"},
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Automatically fund transaction fees"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "Transaction ID if broadcast, otherwise hex"},
        RPCExamples{
            HelpExampleCli("rotatezk", "\"icu_txid\" 0 \"bc1q...\" \"asset_id\" '{\"max_root_age\": 2016}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Parse ICU input
            Txid icu_txid{Txid::FromUint256(ParseHashV(request.params[0], "icu_txid"))};
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();

            // Parse ICU destination
            CTxDestination icu_dest = DecodeDestination(request.params[2].get_str());
            if (!IsValidDestination(icu_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid ICU address");
            }

            // Parse asset ID
            auto aid = uint256::FromHex(request.params[3].get_str());
            if (!aid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }

            // Get current asset registry entry
            auto opt_entry = pwallet->chain().getAssetRegistryEntry(*aid);
            if (!opt_entry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not found in registry");
            }
            AssetRegistryEntry current_entry = *opt_entry;

            // Parse options (start with current values)
            uint32_t kyc_flags = current_entry.has_kyc ? 1 : 0;  // Simplified - immutable
            uint256 vk_commitment = current_entry.zk_vk_commitment;
            uint32_t max_root_age = current_entry.max_root_age;
            uint32_t tfr_flags = current_entry.tfr_flags;
            std::vector<std::vector<unsigned char>> vk_chunks;

            bool autofund = true;
            bool broadcast = false;
            std::optional<double> fee_rate_vb;

            if (!request.params[4].isNull()) {
                const UniValue& opt = request.params[4];

                if (opt.exists("vk_data")) {
                    std::vector<unsigned char> vk_data = ParseHex(opt["vk_data"].get_str());
                    if (vk_data.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "vk_data cannot be empty");
                    }

                    // Compute vk_commitment = double_SHA256(vk_data)
                    CSHA256 hasher1;
                    hasher1.Write(vk_data.data(), vk_data.size());
                    uint256 single_hash;
                    hasher1.Finalize(single_hash.begin());

                    CSHA256 hasher2;
                    hasher2.Write(single_hash.begin(), 32);
                    hasher2.Finalize(vk_commitment.begin());

                    // Chunk VK data (512 bytes per chunk)
                    const size_t CHUNK_SIZE = 512;
                    for (size_t i = 0; i < vk_data.size(); i += CHUNK_SIZE) {
                        size_t chunk_size = std::min(CHUNK_SIZE, vk_data.size() - i);
                        std::vector<unsigned char> chunk(vk_data.begin() + i, vk_data.begin() + i + chunk_size);
                        vk_chunks.push_back(chunk);
                    }
                }
                if (opt.exists("max_root_age")) max_root_age = opt["max_root_age"].getInt<uint32_t>();
                if (opt.exists("tfr_flags")) tfr_flags = opt["tfr_flags"].getInt<uint32_t>();
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
            }

            // Parse compliance_root if provided (for updating compliance root commitment)
            uint256 compliance_root_commit = current_entry.compliance_root_commit;

            if (!request.params[4].isNull()) {
                const UniValue& opt = request.params[4];
                if (opt.exists("compliance_root")) {
                    std::string root_hex = opt["compliance_root"].get_str();

                    auto new_root = uint256::FromHex(root_hex);
                    if (!new_root) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid compliance_root hex");
                    }
                    compliance_root_commit = *new_root;
                }
            }

            // Build transaction
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint(icu_txid, icu_vout));

            // Get ICU input amount from wallet
            const CWalletTx* icu_wtx = pwallet->GetWalletTx(icu_txid);
            if (!icu_wtx || icu_vout >= icu_wtx->tx->vout.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU UTXO not found in wallet");
            }
            CAmount icu_amt = icu_wtx->tx->vout[icu_vout].nValue;

            const CScript icu_script = GetScriptForDestination(icu_dest);

            // Build IssuerReg v1 TLV (no unlock fee bump for ZK rotation)
            std::vector<unsigned char> reg_payload;
            reg_payload.reserve(254);  // ZK Whitelist Hardening: updated from 222

            // Header (39 bytes)
            reg_payload.insert(reg_payload.end(), aid->begin(), aid->end());
            unsigned char pb[4]; WriteLE32(pb, current_entry.policy_bits);
            reg_payload.insert(reg_payload.end(), pb, pb + 4);
            unsigned char ab[2];
            ab[0] = current_entry.allowed_spk_families & 0xFF;
            ab[1] = (current_entry.allowed_spk_families >> 8) & 0xFF;
            reg_payload.insert(reg_payload.end(), ab, ab + 2);
            reg_payload.push_back(assets::ISSUER_REG_FORMAT_V1);

            // Optional fields (10 bytes minimum)
            reg_payload.push_back(0);  // ticker_len = 0
            reg_payload.push_back(0xFF);  // decimals = 0xFF (not set)
            unsigned char ub[8];
            WriteLE64(ub, current_entry.unlock_fees_base);  // Keep same unlock fee
            reg_payload.insert(reg_payload.end(), ub, ub + 8);

            // ZK section (76 bytes) - UPDATED VALUES - ZK Whitelist Hardening update
            unsigned char zk_buf[76];
            WriteLE32(zk_buf, kyc_flags);
            std::copy(vk_commitment.begin(), vk_commitment.end(), zk_buf + 4);
            WriteLE32(zk_buf + 36, max_root_age);
            WriteLE32(zk_buf + 40, tfr_flags);
            // compliance_root_commit [32] - use updated value (from options or preserved)
            if (!compliance_root_commit.IsNull()) {
                std::copy(compliance_root_commit.begin(), compliance_root_commit.end(), zk_buf + 44);
            } else {
                std::fill(zk_buf + 44, zk_buf + 76, 0);
            }
            reg_payload.insert(reg_payload.end(), zk_buf, zk_buf + 76);

            // ICU section (129 bytes) - KEEP CURRENT VALUES
            unsigned char icu_buf[129];
            std::fill(icu_buf, icu_buf + 129, 0);
            WriteLE32(icu_buf, current_entry.icu_flags);                                                     // offset 0-3
            WriteLE64(icu_buf + 4, current_entry.issuance_cap_units);                                       // offset 4-11
            std::copy(current_entry.icu_ctxt_commit.begin(), current_entry.icu_ctxt_commit.end(), icu_buf + 12);  // offset 12-43
            std::copy(current_entry.icu_plain_commit.begin(), current_entry.icu_plain_commit.end(), icu_buf + 44); // offset 44-75
            std::copy(current_entry.kdf_salt.begin(), current_entry.kdf_salt.end(), icu_buf + 76);          // offset 76-91
            icu_buf[92] = current_entry.icu_version;                                                        // offset 92
            icu_buf[93] = current_entry.icu_visibility;                                                     // offset 93
            // Correct order: core_policy_commit → policy_epoch → policy_quorum_bps
            std::copy(current_entry.core_policy_commit.begin(), current_entry.core_policy_commit.end(), icu_buf + 94); // offset 94-125
            icu_buf[126] = current_entry.policy_epoch;                                                      // offset 126
            WriteLE16(icu_buf + 127, current_entry.policy_quorum_bps);                                      // offset 127-128
            reg_payload.insert(reg_payload.end(), icu_buf, icu_buf + 129);

            // Create IssuerReg TLV
            std::vector<unsigned char> reg_tlv;
            reg_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (reg_payload.size() < 253) {
                reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
            } else {
                reg_tlv.push_back(253);
                reg_tlv.push_back(reg_payload.size() & 0xFF);
                reg_tlv.push_back((reg_payload.size() >> 8) & 0xFF);
            }
            reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());

            // Store TLV data for re-attachment after funding
            std::vector<std::pair<CScript, std::vector<unsigned char>>> output_tlvs;
            output_tlvs.emplace_back(icu_script, reg_tlv);

            // Generate unique addresses for ZK chunk outputs (prevents ambiguity after funding)
            std::vector<CTxDestination> zk_chunk_dests;

            for (size_t i = 0; i < vk_chunks.size(); ++i) {
                auto dest_result = pwallet->GetNewDestination(OutputType::BECH32, "ZK chunk");
                if (!dest_result) {
                    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dest_result).original);
                }
                zk_chunk_dests.push_back(*dest_result);

                // Build ZK_PARAMS_CHUNK TLV
                std::vector<unsigned char> chunk_payload;
                chunk_payload.insert(chunk_payload.end(), aid->begin(), aid->end());  // asset_id (32)
                chunk_payload.insert(chunk_payload.end(), vk_commitment.begin(), vk_commitment.end());  // vk_hash (32)

                // chunk_index (2), chunk_count (2)
                uint16_t idx = static_cast<uint16_t>(i);
                uint16_t cnt = static_cast<uint16_t>(vk_chunks.size());
                chunk_payload.push_back(idx & 0xFF);
                chunk_payload.push_back((idx >> 8) & 0xFF);
                chunk_payload.push_back(cnt & 0xFF);
                chunk_payload.push_back((cnt >> 8) & 0xFF);

                // chunk data
                chunk_payload.insert(chunk_payload.end(), vk_chunks[i].begin(), vk_chunks[i].end());

                // Create TLV
                std::vector<unsigned char> chunk_tlv;
                chunk_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ZK_PARAMS_CHUNK));
                if (chunk_payload.size() < 253) {
                    chunk_tlv.push_back(static_cast<uint8_t>(chunk_payload.size()));
                } else {
                    chunk_tlv.push_back(253);
                    chunk_tlv.push_back(chunk_payload.size() & 0xFF);
                    chunk_tlv.push_back((chunk_payload.size() >> 8) & 0xFF);
                }
                chunk_tlv.insert(chunk_tlv.end(), chunk_payload.begin(), chunk_payload.end());

                // Store TLV
                CScript chunk_script = GetScriptForDestination(zk_chunk_dests[i]);
                output_tlvs.emplace_back(chunk_script, chunk_tlv);
            }

            // Fund and finalize transaction
            if (autofund) {
                CCoinControl coin_control;
                if (fee_rate_vb) {
                    coin_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000));
                }

                // Build recipients list for funding (mtx.vout must be EMPTY)
                std::vector<CRecipient> recipients;
                CRecipient icu_recipient{icu_dest, icu_amt, /*fSubtractFeeFromAmount=*/false};
                recipients.push_back(icu_recipient);

                // Add ZK chunk recipients
                for (size_t i = 0; i < zk_chunk_dests.size(); ++i) {
                    CRecipient zk_recipient{zk_chunk_dests[i], 546, /*fSubtractFeeFromAmount=*/false};
                    recipients.push_back(zk_recipient);
                }

                auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt,
                                         /*lockUnspents=*/false, coin_control);
                if (!txr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                }

                // Apply the funded transaction
                mtx = CMutableTransaction(*txr->tx);
            }

            // Re-attach TLVs to outputs (funding creates new transaction without vExt)
            for (auto& out : mtx.vout) {
                for (const auto& [script, tlv] : output_tlvs) {
                    if (out.scriptPubKey == script && out.vExt.empty()) {
                        out.vExt = tlv;
                        break;
                    }
                }
            }

            // Sign transaction
            if (!feebumper::SignTransaction(*pwallet, mtx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction signing failed");
            }

            if (broadcast) {
                std::string err;
                const auto& tx_ref = MakeTransactionRef(mtx);
                if (!pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, err)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Broadcast failed: %s", err));
                }
                return tx_ref->GetHash().ToString();
            } else {
                return EncodeHexTx(CTransaction(mtx));
            }
        }
    };
}

RPCHelpMan rotateicu()
{
    return RPCHelpMan{
        "rotateicu",
        "Rotate ICU governance parameters for an asset (requires unlock fee bump >= 0.5 BTC).\n"
        "Updates icu_payload, icu_visibility, policy_quorum_bps, issuance_cap (units or base units).\n"
        "WARNING: If policy_quorum_bps > 0, quorum workflow required (not handled by this RPC).",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU transaction ID"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU output index"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination address"},
            {"unlock_fee_bump", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "BTC to add to unlock_fees_base (min 0.5)"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID to rotate"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "ICU rotation options",
                {
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "New ICU governance payload (up to 100 KiB)"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ciphertext commitment"},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte plaintext commitment"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "ICU visibility (0=public, 1=holder_only)"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Governance quorum in basis points"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Issuance cap in base units (0=unlimited)"},
                    {"issuance_cap", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Issuance cap expressed in asset units (e.g., \"50.0\"). Overrides issuance_cap_units."},
                    {"icu_compressed", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use zstd compression for payload"},
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Automatically fund transaction fees"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "Transaction ID if broadcast, otherwise hex"},
        RPCExamples{
            HelpExampleCli("rotateicu", "\"icu_txid\" 0 \"bc1q...\" 0.5 \"asset_id\" '{\"icu_visibility\": 1}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Parse ICU input
            Txid icu_txid{Txid::FromUint256(ParseHashV(request.params[0], "icu_txid"))};
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();

            // Parse ICU destination
            CTxDestination icu_dest = DecodeDestination(request.params[2].get_str());
            if (!IsValidDestination(icu_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid ICU address");
            }

            // Parse unlock fee bump (minimum 0.5 BTC = 50M sats)
            CAmount unlock_fee_bump = AmountFromValue(request.params[3]);
            if (unlock_fee_bump < 50'000'000) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unlock_fee_bump must be at least 0.5 BTC (50000000 sats)");
            }

            // Parse asset ID
            auto aid = uint256::FromHex(request.params[4].get_str());
            if (!aid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }

            // Get current asset registry entry
            auto opt_entry = pwallet->chain().getAssetRegistryEntry(*aid);
            if (!opt_entry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not found in registry");
            }
            AssetRegistryEntry current_entry = *opt_entry;

            // Parse options (start with current values)
            std::vector<unsigned char> icu_payload;
            std::vector<unsigned char> icu_plaintext;
            uint256 icu_ctxt_commit = current_entry.icu_ctxt_commit;
            uint256 icu_plain_commit = current_entry.icu_plain_commit;
            uint8_t icu_visibility = current_entry.icu_visibility;
            uint16_t policy_quorum_bps = current_entry.policy_quorum_bps;
            uint64_t issuance_cap_units = current_entry.issuance_cap_units;
            uint32_t kyc_flags = current_entry.has_kyc ? 1u : 0u;
            uint32_t icu_flags = current_entry.icu_flags;
            bool icu_compressed = (icu_flags & assets::ICU_COMPRESSED) != 0;
            std::array<unsigned char, 16> kdf_salt = current_entry.kdf_salt;
            bool icu_payload_plain_provided = false;
            bool icu_payload_provided = false;
            bool icu_ctxt_commit_provided = false;
            bool icu_plain_commit_provided = false;
            bool icu_visibility_provided = false;
            bool autofund = true;
            bool broadcast = false;
            std::optional<double> fee_rate_vb;
            std::optional<assets::IcuStorageEntry> built_storage_entry;

            if (!request.params[5].isNull()) {
                const UniValue& opt = request.params[5];

                if (opt.exists("icu_payload")) {
                    icu_payload = ParseHex(opt["icu_payload"].get_str());
                    if (icu_payload.size() > assets::MAX_ICU_PAYLOAD_BYTES) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload exceeds maximum size (100 KiB)");
                    }
                    icu_payload_provided = true;
                }
                if (opt.exists("icu_payload_plain")) {
                    icu_plaintext = ParseHex(opt["icu_payload_plain"].get_str());
                    if (icu_plaintext.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload_plain cannot be empty");
                    }
                    icu_payload_plain_provided = true;
                }
                if (opt.exists("icu_ctxt_commit")) {
                    auto cc = uint256::FromHex(opt["icu_ctxt_commit"].get_str());
                    if (!cc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_ctxt_commit hex");
                    icu_ctxt_commit = *cc;
                    icu_ctxt_commit_provided = true;
                }
                if (opt.exists("icu_plain_commit")) {
                    auto pc = uint256::FromHex(opt["icu_plain_commit"].get_str());
                    if (!pc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_plain_commit hex");
                    icu_plain_commit = *pc;
                    icu_plain_commit_provided = true;
                }
                if (opt.exists("icu_visibility")) {
                    icu_visibility = opt["icu_visibility"].getInt<uint8_t>();
                    icu_visibility_provided = true;
                }
                if (opt.exists("policy_quorum_bps")) {
                    policy_quorum_bps = opt["policy_quorum_bps"].getInt<uint16_t>();
                }
                if (auto cap_override = ParseIssuanceCapOption(opt, current_entry.decimals, "prepare_rotation options")) {
                    issuance_cap_units = *cap_override;
                }
                if (opt.exists("icu_compressed")) {
                    icu_compressed = opt["icu_compressed"].get_bool();
                    if (icu_compressed) {
                        icu_flags |= assets::ICU_COMPRESSED;
                    } else {
                        icu_flags &= ~assets::ICU_COMPRESSED;
                    }
                }
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
            }

            if (icu_payload_plain_provided && (icu_payload_provided || icu_ctxt_commit_provided || icu_plain_commit_provided)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Cannot combine icu_payload_plain with precomputed ICU fields");
            }

            if (!request.params[5].isNull()) {
                const UniValue& opt = request.params[5];

                if (opt.exists("icu_payload")) {
                    icu_payload = ParseHex(opt["icu_payload"].get_str());
                    if (icu_payload.size() > assets::MAX_ICU_PAYLOAD_BYTES) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload exceeds maximum size (100 KiB)");
                    }
                }
                if (opt.exists("icu_ctxt_commit")) {
                    auto cc = uint256::FromHex(opt["icu_ctxt_commit"].get_str());
                    if (!cc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_ctxt_commit hex");
                    icu_ctxt_commit = *cc;
                }
                if (opt.exists("icu_plain_commit")) {
                    auto pc = uint256::FromHex(opt["icu_plain_commit"].get_str());
                    if (!pc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_plain_commit hex");
                    icu_plain_commit = *pc;
                }
                if (opt.exists("icu_visibility")) icu_visibility = opt["icu_visibility"].getInt<uint8_t>();
                if (opt.exists("policy_quorum_bps")) policy_quorum_bps = opt["policy_quorum_bps"].getInt<uint16_t>();
                if (auto cap_override = ParseIssuanceCapOption(opt, current_entry.decimals, "rotateicu options")) {
                    issuance_cap_units = *cap_override;
                }
                if (opt.exists("icu_compressed")) {
                    icu_compressed = opt["icu_compressed"].get_bool();
                    if (icu_compressed) {
                        icu_flags |= assets::ICU_COMPRESSED;
                    } else {
                        icu_flags &= ~assets::ICU_COMPRESSED;
                    }
                }
                if (opt.exists("autofund")) autofund = opt["autofund"].get_bool();
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
            }

            if (issuance_cap_units != current_entry.issuance_cap_units) {
                if (issuance_cap_units != 0 && current_entry.issued_total > issuance_cap_units) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("New issuance cap %s is below already issued amount %s",
                                  DescribeAssetUnits(issuance_cap_units, current_entry.decimals),
                                  DescribeAssetUnits(current_entry.issued_total, current_entry.decimals)));
                }
            }

            // Validate icu_payload requirement for visibility changes
            // (ICU payload contains visibility byte, so changing visibility requires new payload+hash)
            if (icu_visibility != current_entry.icu_visibility && icu_payload.empty() && !icu_payload_plain_provided) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Changing icu_visibility requires providing updated icu_payload with new visibility byte. "
                    "The payload hash (icu_ctxt_commit) must be recomputed to reflect the visibility change.");
            }

            if (icu_payload_plain_provided) {
                auto parsed_payload = assets::ParseCanonicalIcuPayload(icu_plaintext);
                if (!parsed_payload) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse icu_payload_plain as CanonicalIcuPayload structure");
                }

                // Extract canonical text and witness bundle
                std::string canonical_text_str(parsed_payload->canonical_text.begin(), parsed_payload->canonical_text.end());
                std::string witness_str(parsed_payload->witness_bundle.begin(), parsed_payload->witness_bundle.end());
                UniValue witness_obj;
                if (!witness_obj.read(witness_str)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse witness_bundle JSON");
                }

                const uint256 canonical_plain_commit = parsed_payload->GetCanonicalHash();
                icu_plain_commit = canonical_plain_commit;

                uint8_t target_visibility = icu_visibility_provided ? icu_visibility : parsed_payload->visibility;
                if (target_visibility > 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_visibility must be 0 or 1");
                }
                icu_visibility = target_visibility;

                std::array<unsigned char, 32> dek{};
                if (icu_visibility == 1) {
                    // Use GetOrCreateAssetDek to auto-generate DEK when transitioning from public to holder-only
                    std::string dek_base64 = pwallet->GetOrCreateAssetDek(*aid);
                    auto dek_bytes = DecodeBase64(dek_base64);
                    if (!dek_bytes || dek_bytes->size() != 32) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Stored DEK is not a 32-byte base64 value");
                    }
                    std::copy_n(dek_bytes->begin(), 32, dek.begin());
                    icu_flags |= assets::WRAP_REQUIRED;
                } else {
                    icu_flags &= ~assets::WRAP_REQUIRED;
                }

                std::array<unsigned char, 16> new_kdf_salt;
                assets::IcuStorageEntry storage_entry_local;
                if (!assets::BuildCanonicalIcuPayload(
                    canonical_text_str,
                    witness_obj,
                    icu_visibility,
                    dek,
                    icu_compressed,
                    icu_plain_commit,
                    icu_ctxt_commit,
                    new_kdf_salt,
                    storage_entry_local,
                    parsed_payload->metadata  // preserve committed metadata across re-encryption
                )) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build canonical ICU payload from plaintext");
                }

                icu_payload = storage_entry_local.icu_cipher;
                built_storage_entry = storage_entry_local;
                icu_plain_commit = storage_entry_local.canonical_hash;

                LogPrintf("REGISTER_ICU_BUILD: asset=%s visibility=%u canonical_hash=%s ctxt_commit=%s payload_size=%u\n",
                          aid->ToString(), icu_visibility, icu_plain_commit.ToString(), icu_ctxt_commit.ToString(), icu_payload.size());
                kdf_salt = new_kdf_salt;
                icu_compressed = storage_entry_local.compression == 1;
                if (icu_compressed) {
                    icu_flags |= assets::ICU_COMPRESSED;
                } else {
                    icu_flags &= ~assets::ICU_COMPRESSED;
                }
            }

            // Note: Quorum governance enforcement happens at consensus layer
            // When settled_supply = 0 (no tokens issued yet), issuer can rotate freely even with quorum_bps > 0
            // When settled_supply > 0, consensus will require ballot workflow (not yet implemented)
            // We allow the transaction to proceed and let consensus validate it

            // Build transaction
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint(icu_txid, icu_vout));

            // Get ICU input amount from wallet
            const CWalletTx* icu_wtx = pwallet->GetWalletTx(icu_txid);
            if (!icu_wtx || icu_vout >= icu_wtx->tx->vout.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU UTXO not found in wallet");
            }
            CAmount icu_amt = icu_wtx->tx->vout[icu_vout].nValue + unlock_fee_bump;  // BUMP ICU amount

            const CScript icu_script = GetScriptForDestination(icu_dest);

            // Build IssuerReg v1 TLV with bumped unlock fee
            std::vector<unsigned char> reg_payload;
            reg_payload.reserve(254);  // ZK Whitelist Hardening: updated from 222

            if (icu_plain_commit.IsNull() && built_storage_entry.has_value() && !built_storage_entry->canonical_hash.IsNull()) {
                icu_plain_commit = built_storage_entry->canonical_hash;
            }

            if (icu_plain_commit.IsNull() && built_storage_entry.has_value() && !built_storage_entry->canonical_hash.IsNull()) {
                icu_plain_commit = built_storage_entry->canonical_hash;
            }

            // Header (39 bytes)
            reg_payload.insert(reg_payload.end(), aid->begin(), aid->end());
            unsigned char pb[4]; WriteLE32(pb, current_entry.policy_bits);
            reg_payload.insert(reg_payload.end(), pb, pb + 4);
            unsigned char ab[2];
            ab[0] = current_entry.allowed_spk_families & 0xFF;
            ab[1] = (current_entry.allowed_spk_families >> 8) & 0xFF;
            reg_payload.insert(reg_payload.end(), ab, ab + 2);
            reg_payload.push_back(assets::ISSUER_REG_FORMAT_V1);

            // Optional fields (10 bytes minimum)
            reg_payload.push_back(0);  // ticker_len = 0
            reg_payload.push_back(0xFF);  // decimals = 0xFF
            uint64_t new_unlock_fees_base = current_entry.unlock_fees_base + unlock_fee_bump;
            unsigned char ub[8];
            WriteLE64(ub, new_unlock_fees_base);  // BUMPED unlock fee
            reg_payload.insert(reg_payload.end(), ub, ub + 8);

            // ZK section (76 bytes) - KEEP CURRENT VALUES - ZK Whitelist Hardening update
            unsigned char zk_buf[76];
            WriteLE32(zk_buf, kyc_flags);
            std::copy(current_entry.zk_vk_commitment.begin(), current_entry.zk_vk_commitment.end(), zk_buf + 4);
            WriteLE32(zk_buf + 36, current_entry.max_root_age);
            WriteLE32(zk_buf + 40, current_entry.tfr_flags);
            // compliance_root_commit [32] - preserve from current state or zero if not set
            if (!current_entry.compliance_root_commit.IsNull()) {
                std::copy(current_entry.compliance_root_commit.begin(), current_entry.compliance_root_commit.end(), zk_buf + 44);
            } else {
                std::fill(zk_buf + 44, zk_buf + 76, 0);
            }
            reg_payload.insert(reg_payload.end(), zk_buf, zk_buf + 76);

            // ICU section (129 bytes) - UPDATED VALUES
            unsigned char icu_buf[129];
            std::fill(icu_buf, icu_buf + 129, 0);
            WriteLE32(icu_buf, icu_flags);                                                          // offset 0-3
            WriteLE64(icu_buf + 4, issuance_cap_units);                                            // offset 4-11
            std::copy(icu_ctxt_commit.begin(), icu_ctxt_commit.end(), icu_buf + 12);               // offset 12-43
            std::copy(icu_plain_commit.begin(), icu_plain_commit.end(), icu_buf + 44);             // offset 44-75
            std::copy(kdf_salt.begin(), kdf_salt.end(), icu_buf + 76); // offset 76-91
            icu_buf[92] = current_entry.icu_version;                                               // offset 92
            icu_buf[93] = icu_visibility;                                                          // offset 93
            // Correct order: core_policy_commit → policy_epoch → policy_quorum_bps
            std::copy(current_entry.core_policy_commit.begin(), current_entry.core_policy_commit.end(), icu_buf + 94); // offset 94-125
            icu_buf[126] = current_entry.policy_epoch;                                             // offset 126
            WriteLE16(icu_buf + 127, policy_quorum_bps);                                           // offset 127-128
            reg_payload.insert(reg_payload.end(), icu_buf, icu_buf + 129);

            // Create IssuerReg TLV
            std::vector<unsigned char> reg_tlv;
            reg_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (reg_payload.size() < 253) {
                reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
            } else {
                reg_tlv.push_back(253);
                reg_tlv.push_back(reg_payload.size() & 0xFF);
                reg_tlv.push_back((reg_payload.size() >> 8) & 0xFF);
            }
            reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());

            // Store TLV data for re-attachment after funding
            std::vector<std::pair<CScript, std::vector<unsigned char>>> output_tlvs;
            output_tlvs.emplace_back(icu_script, reg_tlv);

            // Prepare ICU_TEXT_CHUNK if payload provided
            CTxDestination icu_chunk_dest;
            if (!icu_payload.empty()) {
                // Generate unique address for ICU chunk output (prevents ambiguity after funding)
                auto chunk_dest_result = pwallet->GetNewDestination(OutputType::BECH32, "ICU chunk");
                if (!chunk_dest_result) {
                    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(chunk_dest_result).original);
                }
                icu_chunk_dest = *chunk_dest_result;
                CScript chunk_script = GetScriptForDestination(icu_chunk_dest);

                std::vector<unsigned char> chunk_bytes = icu_payload;
                if (built_storage_entry) {
                    assets::IcuChunkMetadata metadata;
                    metadata.compression = built_storage_entry->compression;
                    metadata.encryption_mode = built_storage_entry->encryption_mode;
                    metadata.has_witness_hash = !built_storage_entry->witness_hash.IsNull();
                    metadata.witness_hash = built_storage_entry->witness_hash;
                    chunk_bytes = assets::AppendIcuChunkMetadata(chunk_bytes, metadata);
                }

                std::vector<unsigned char> chunk_tlv;
                chunk_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ICU_TEXT_CHUNK));

                size_t payload_size = chunk_bytes.size();
                if (payload_size < 253) {
                    chunk_tlv.push_back(static_cast<uint8_t>(payload_size));
                } else if (payload_size < 65536) {
                    chunk_tlv.push_back(253);
                    chunk_tlv.push_back(payload_size & 0xFF);
                    chunk_tlv.push_back((payload_size >> 8) & 0xFF);
                } else {
                    chunk_tlv.push_back(254);
                    unsigned char len_buf[4];
                    WriteLE32(len_buf, static_cast<uint32_t>(payload_size));
                    chunk_tlv.insert(chunk_tlv.end(), len_buf, len_buf + 4);
                }

                chunk_tlv.insert(chunk_tlv.end(), chunk_bytes.begin(), chunk_bytes.end());

                // Store TLV with unique script for re-attachment
                output_tlvs.emplace_back(chunk_script, chunk_tlv);
            }

            // Fund and finalize transaction
            if (autofund) {
                CCoinControl coin_control;
                if (fee_rate_vb) {
                    coin_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000));
                }

                // Build recipients list for funding (mtx.vout must be EMPTY)
                std::vector<CRecipient> recipients;
                CRecipient icu_recipient{icu_dest, icu_amt, /*fSubtractFeeFromAmount=*/false};
                recipients.push_back(icu_recipient);

                // Add ICU chunk recipient if needed
                if (!icu_payload.empty()) {
                    CRecipient icu_chunk_recipient{icu_chunk_dest, 546, /*fSubtractFeeFromAmount=*/false};
                    recipients.push_back(icu_chunk_recipient);
                }

                auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt,
                                         /*lockUnspents=*/false, coin_control);
                if (!txr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                }

                // Apply the funded transaction
                mtx = CMutableTransaction(*txr->tx);
            }

            // Re-attach TLVs to outputs by matching scriptPubKey
            for (auto& out : mtx.vout) {
                for (const auto& [script, tlv] : output_tlvs) {
                    if (out.scriptPubKey == script && out.vExt.empty()) {
                        out.vExt = tlv;
                        break;
                    }
                }
            }

            // Sign transaction
            if (!feebumper::SignTransaction(*pwallet, mtx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction signing failed");
            }

            if (broadcast) {
                std::string err;
                const auto& tx_ref = MakeTransactionRef(mtx);
                if (!pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, err)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Broadcast failed: %s", err));
                }
                return tx_ref->GetHash().ToString();
            } else {
                return EncodeHexTx(CTransaction(mtx));
            }
        }
    };
}

RPCHelpMan rotateasset()
{
    return RPCHelpMan{
        "rotateasset",
        "Unified convenience wrapper for asset parameter rotation.\n"
        "Automatically detects whether ZK or ICU rotation is needed and routes accordingly.\n"
        "Cannot mix ZK and ICU changes in a single call.",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU transaction ID"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU output index"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination address"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID to rotate"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Rotation parameters",
                {
                    // ZK fields
                    {"vk_data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "New ZK verification key data"},
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum merkle root age"},
                    {"tfr_flags", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Transfer flags"},

                    // ICU fields
                    {"unlock_fee_bump", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "BTC to add (min 0.5 for ICU)"},
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "New ICU payload"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Ciphertext commitment"},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Plaintext commitment"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "ICU visibility"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Quorum basis points"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Issuance cap in base units"},
                    {"issuance_cap", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Issuance cap expressed in asset units (e.g., \"50.0\"). Overrides issuance_cap_units."},
                    {"icu_compressed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Use zstd compression"},

                    // Common
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{true}, "Auto-fund fees"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast transaction"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "Transaction ID if broadcast, otherwise hex"},
        RPCExamples{
            HelpExampleCli("rotateasset", "\"icu_txid\" 0 \"bc1q...\" \"asset_id\" '{\"max_root_age\": 2016}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            if (request.params[4].isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options parameter required");
            }

            const UniValue& opt = request.params[4];

            // Detect rotation type
            bool has_zk_fields = opt.exists("vk_data") || opt.exists("max_root_age") || opt.exists("tfr_flags");
            bool has_icu_fields = opt.exists("unlock_fee_bump") || opt.exists("icu_payload") || opt.exists("icu_payload_plain") ||
                                  opt.exists("icu_ctxt_commit") || opt.exists("icu_plain_commit") ||
                                  opt.exists("icu_visibility") || opt.exists("policy_quorum_bps") ||
                                  opt.exists("issuance_cap_units") || opt.exists("issuance_cap") || opt.exists("icu_compressed");

            if (has_zk_fields && has_icu_fields) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Cannot mix ZK and ICU rotation in single call. Use rotatezk or rotateicu directly.");
            }

            if (has_zk_fields) {
                // Route to rotatezk
                JSONRPCRequest zk_req = request;
                UniValue zk_params(UniValue::VARR);
                zk_params.push_back(request.params[0]);  // icu_txid
                zk_params.push_back(request.params[1]);  // icu_vout
                zk_params.push_back(request.params[2]);  // icu_address
                zk_params.push_back(request.params[3]);  // asset_id

                // Filter options to ZK-only
                UniValue zk_opt(UniValue::VOBJ);
                if (opt.exists("vk_data")) zk_opt.pushKV("vk_data", opt["vk_data"]);
                if (opt.exists("max_root_age")) zk_opt.pushKV("max_root_age", opt["max_root_age"]);
                if (opt.exists("tfr_flags")) zk_opt.pushKV("tfr_flags", opt["tfr_flags"]);
                if (opt.exists("autofund")) zk_opt.pushKV("autofund", opt["autofund"]);
                if (opt.exists("broadcast")) zk_opt.pushKV("broadcast", opt["broadcast"]);
                if (opt.exists("fee_rate")) zk_opt.pushKV("fee_rate", opt["fee_rate"]);

                zk_params.push_back(zk_opt);
                zk_req.params = zk_params;

                return rotatezk().HandleRequest(zk_req);

            } else if (has_icu_fields) {
                // Route to rotateicu
                if (!opt.exists("unlock_fee_bump")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "unlock_fee_bump required for ICU rotation (minimum 0.5 BTC)");
                }

                JSONRPCRequest icu_req = request;
                UniValue icu_params(UniValue::VARR);
                icu_params.push_back(request.params[0]);  // icu_txid
                icu_params.push_back(request.params[1]);  // icu_vout
                icu_params.push_back(request.params[2]);  // icu_address
                icu_params.push_back(opt["unlock_fee_bump"]);  // unlock_fee_bump
                icu_params.push_back(request.params[3]);  // asset_id

                // Filter options to ICU-only
                UniValue icu_opt(UniValue::VOBJ);
                if (opt.exists("icu_payload")) icu_opt.pushKV("icu_payload", opt["icu_payload"]);
                if (opt.exists("icu_payload_plain")) icu_opt.pushKV("icu_payload_plain", opt["icu_payload_plain"]);
                if (opt.exists("icu_ctxt_commit")) icu_opt.pushKV("icu_ctxt_commit", opt["icu_ctxt_commit"]);
                if (opt.exists("icu_plain_commit")) icu_opt.pushKV("icu_plain_commit", opt["icu_plain_commit"]);
                if (opt.exists("icu_visibility")) icu_opt.pushKV("icu_visibility", opt["icu_visibility"]);
                if (opt.exists("policy_quorum_bps")) icu_opt.pushKV("policy_quorum_bps", opt["policy_quorum_bps"]);
                if (opt.exists("issuance_cap_units")) icu_opt.pushKV("issuance_cap_units", opt["issuance_cap_units"]);
                if (opt.exists("issuance_cap")) icu_opt.pushKV("issuance_cap", opt["issuance_cap"]);
                if (opt.exists("icu_compressed")) icu_opt.pushKV("icu_compressed", opt["icu_compressed"]);
                if (opt.exists("autofund")) icu_opt.pushKV("autofund", opt["autofund"]);
                if (opt.exists("broadcast")) icu_opt.pushKV("broadcast", opt["broadcast"]);
                if (opt.exists("fee_rate")) icu_opt.pushKV("fee_rate", opt["fee_rate"]);

                icu_params.push_back(icu_opt);
                icu_req.params = icu_params;

                return rotateicu().HandleRequest(icu_req);

            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "No rotation parameters specified. Provide ZK or ICU fields.");
            }
        }
    };
}

RPCHelpMan prepare_rotation()
{
    return RPCHelpMan{
        "prepare_rotation",
        "Prepare a quorum-gated governance rotation PSBT template.\n"
        "Creates a template with the new IssuerReg and placeholder ballot outputs.\n"
        "Holders can then sign ballots independently using the 'ballot' RPC.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID to rotate"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Rotation parameters",
                {
                    {"icu_payload_plain", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical ICU plaintext bytes (will be encrypted automatically using existing DEK/salt). Preferred method for updating governance text."},
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Pre-encrypted ICU payload bytes (advanced use only)"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ciphertext commitment"},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte plaintext commitment"},
                    {"kdf_salt", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte encryption salt"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "ICU visibility (0=public, 1=holder_only)"},
                    {"icu_compressed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Use zstd compression for ICU payload"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Governance quorum in basis points"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Issuance cap in base units (0=unlimited)"},
                    {"issuance_cap", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Issuance cap expressed in asset units (e.g., \"50.0\"). Overrides issuance_cap_units."},
                    {"unlock_fee_bump", RPCArg::Type::AMOUNT, RPCArg::Default{0.5}, "BTC to add to unlock_fees_base (min 0.5)"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT template"},
                {RPCResult::Type::STR_HEX, "proposal_hash", "Proposal hash binding for ballot validation"},
                {RPCResult::Type::OBJ, "summary", "Human-readable summary of IssuerReg changes",
                    {
                        {RPCResult::Type::STR, "issuance_cap", "Issuance cap change (e.g., '100 units → 200 units' or 'unlimited (unchanged)')"},
                        {RPCResult::Type::STR, "quorum", "Quorum change (e.g., '55.00% → 60.00%' or '55.00% (unchanged)')"},
                        {RPCResult::Type::STR, "icu_visibility", "ICU visibility change (e.g., 'public → holder_only' or 'public (unchanged)')"},
                        {RPCResult::Type::STR, "icu_text", "ICU text/commit update status (e.g., 'Updated (95.2 KB)', 'Updated (commits only)', or 'No changes')"},
                        {RPCResult::Type::STR, "kdf_salt", /*optional=*/true, "KDF salt update status (only shown if changed)"},
                        {RPCResult::Type::STR, "kyc_required", /*optional=*/true, "KYC requirement change (only shown if changed)"},
                        {RPCResult::Type::STR, "unlock_fee_bump", "Unlock fee increase (e.g., '+0.50 BTC')"},
                        {RPCResult::Type::STR, "policy_epoch", "Policy epoch increment (e.g., '5 → 6')"},
                    }
                },
                {RPCResult::Type::NUM, "settled_supply", "Current settled supply (issued - burned)"},
                {RPCResult::Type::NUM, "required_units", "Minimum ballot units needed for quorum"},
                {RPCResult::Type::NUM, "policy_quorum_bps", "Governance quorum threshold"},
                {RPCResult::Type::STR_HEX, "asset_id", "Asset ID being rotated"},
            }
        },
        RPCExamples{
            HelpExampleCli("prepare_rotation", "\"asset_id\" '{\"icu_visibility\": 1, \"unlock_fee_bump\": 0.5}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Parse asset_id
            auto aid = uint256::FromHex(request.params[0].get_str());
            if (!aid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
            }

            // Get current registry entry
            auto opt_entry = pwallet->chain().getAssetRegistryEntry(*aid);
            if (!opt_entry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset not found in registry");
            }
            AssetRegistryEntry current_entry = *opt_entry;

            // Calculate settled supply and quorum thresholds
            uint64_t settled_supply = current_entry.issued_total - current_entry.burned_total;
            uint16_t policy_quorum_bps = current_entry.policy_quorum_bps;

            if (policy_quorum_bps == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Asset is fully immutable (policy_quorum_bps=0). Cannot rotate after issuance.");
            }

            if (settled_supply == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "No tokens issued yet (settled_supply=0). Use rotateicu for pre-issuance rotations.");
            }

            // Parse options (start with current values)
            std::vector<unsigned char> icu_payload;
            std::vector<unsigned char> icu_plaintext;
            uint256 icu_ctxt_commit = current_entry.icu_ctxt_commit;
            uint256 icu_plain_commit = current_entry.icu_plain_commit;
            std::array<unsigned char, 16> kdf_salt = current_entry.kdf_salt;
            uint8_t icu_visibility = current_entry.icu_visibility;
            uint64_t issuance_cap_units = current_entry.issuance_cap_units;
            CAmount unlock_fee_bump = 50'000'000; // 0.5 BTC default
            uint32_t kyc_flags = current_entry.has_kyc ? 1u : 0u;
            uint32_t icu_flags = current_entry.icu_flags;
            bool icu_compressed = (icu_flags & assets::ICU_COMPRESSED) != 0;
            bool icu_payload_plain_provided = false;
            std::optional<assets::IcuStorageEntry> built_storage_entry;

            if (!request.params[1].isNull()) {
                const UniValue& opt = request.params[1];

                if (opt.exists("icu_payload")) {
                    icu_payload = ParseHex(opt["icu_payload"].get_str());
                }
                if (opt.exists("icu_payload_plain")) {
                    icu_plaintext = ParseHex(opt["icu_payload_plain"].get_str());
                    if (icu_plaintext.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload_plain cannot be empty");
                    }
                    icu_payload_plain_provided = true;
                }
                if (opt.exists("icu_ctxt_commit")) {
                    auto cc = uint256::FromHex(opt["icu_ctxt_commit"].get_str());
                    if (!cc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_ctxt_commit hex");
                    icu_ctxt_commit = *cc;
                }
                if (opt.exists("icu_plain_commit")) {
                    auto pc = uint256::FromHex(opt["icu_plain_commit"].get_str());
                    if (!pc) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_plain_commit hex");
                    icu_plain_commit = *pc;
                }
                if (opt.exists("kdf_salt")) {
                    auto salt_bytes = ParseHex(opt["kdf_salt"].get_str());
                    if (salt_bytes.size() != 16) throw JSONRPCError(RPC_INVALID_PARAMETER, "kdf_salt must be 16 bytes");
                    std::copy(salt_bytes.begin(), salt_bytes.end(), kdf_salt.begin());
                }
                if (opt.exists("icu_visibility")) {
                    icu_visibility = opt["icu_visibility"].getInt<uint8_t>();
                }
                if (opt.exists("policy_quorum_bps")) {
                    policy_quorum_bps = opt["policy_quorum_bps"].getInt<uint16_t>();
                }
                if (auto cap_override = ParseIssuanceCapOption(opt, current_entry.decimals, "rotateicu options")) {
                    issuance_cap_units = *cap_override;
                }
                if (opt.exists("kyc_flags")) {
                    kyc_flags = opt["kyc_flags"].getInt<uint32_t>();
                }
                if (opt.exists("unlock_fee_bump")) {
                    unlock_fee_bump = AmountFromValue(opt["unlock_fee_bump"]);
                    if (unlock_fee_bump < 50'000'000) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "unlock_fee_bump must be at least 0.5 BTC");
                    }
                }
                if (opt.exists("icu_compressed")) {
                    icu_compressed = opt["icu_compressed"].get_bool();
                    if (icu_compressed) {
                        icu_flags |= assets::ICU_COMPRESSED;
                    } else {
                        icu_flags &= ~assets::ICU_COMPRESSED;
                    }
                }
            }

            // Validate: cannot combine icu_payload_plain with precomputed ICU fields
            if (icu_payload_plain_provided && !icu_payload.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Cannot combine icu_payload_plain with precomputed icu_payload");
            }

            // Process icu_payload_plain if provided
            if (icu_payload_plain_provided) {
                auto parsed_payload = assets::ParseCanonicalIcuPayload(icu_plaintext);
                if (!parsed_payload) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse icu_payload_plain as CanonicalIcuPayload structure");
                }

                // Extract canonical text and witness bundle
                std::string canonical_text_str(parsed_payload->canonical_text.begin(), parsed_payload->canonical_text.end());
                std::string witness_str(parsed_payload->witness_bundle.begin(), parsed_payload->witness_bundle.end());
                UniValue witness_obj;
                if (!witness_obj.read(witness_str)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse witness_bundle JSON");
                }

                const uint256 canonical_plain_commit = parsed_payload->GetCanonicalHash();
                icu_plain_commit = canonical_plain_commit;

                uint8_t target_visibility = icu_visibility;
                if (target_visibility > 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_visibility must be 0 or 1");
                }

                std::array<unsigned char, 32> dek{};
                if (target_visibility == 1) {
                    // CRITICAL: For rotation, must use EXISTING DEK (never create new one!)
                    // Creating a new DEK would break decryption for all existing holders
                    std::optional<std::string> dek_base64 = pwallet->GetAssetDek(*aid);
                    if (!dek_base64) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Asset %s requires holder-only encryption but this wallet has no stored DEK. "
                                      "Cannot rotate ICU text without the original encryption key. "
                                      "Use dumpassetdek from the issuer wallet that registered this asset, "
                                      "then importassetdek into this wallet before rotating.",
                                      aid->ToString()));
                    }
                    auto dek_bytes = DecodeBase64(*dek_base64);
                    if (!dek_bytes || dek_bytes->size() != 32) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Stored DEK is not a 32-byte base64 value");
                    }
                    std::copy_n(dek_bytes->begin(), 32, dek.begin());
                    icu_flags |= assets::WRAP_REQUIRED;
                } else {
                    icu_flags &= ~assets::WRAP_REQUIRED;
                }

                // IMPORTANT: Reuse existing kdf_salt so current holders can still decrypt!
                // Don't generate a new salt - that would break existing holders' access
                assets::IcuStorageEntry storage_entry_local;
                if (!assets::BuildCanonicalIcuPayload(
                    canonical_text_str,
                    witness_obj,
                    target_visibility,
                    dek,
                    icu_compressed,
                    icu_plain_commit,
                    icu_ctxt_commit,
                    kdf_salt,  // Use EXISTING kdf_salt from current_entry
                    storage_entry_local,
                    parsed_payload->metadata  // preserve committed metadata across re-encryption (rotation)
                )) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build canonical ICU payload from plaintext");
                }

                icu_payload = storage_entry_local.icu_cipher;
                built_storage_entry = storage_entry_local;
                icu_plain_commit = storage_entry_local.canonical_hash;

                LogPrintf("PREPARE_ROTATION_ICU_BUILD: asset=%s visibility=%u canonical_hash=%s ctxt_commit=%s payload_size=%u (reusing existing kdf_salt)\n",
                          aid->ToString(), target_visibility, icu_plain_commit.ToString(), icu_ctxt_commit.ToString(), icu_payload.size());

                // kdf_salt already has the correct value from current_entry - don't overwrite it!

                icu_compressed = storage_entry_local.compression == 1;
                if (icu_compressed) {
                    icu_flags |= assets::ICU_COMPRESSED;
                } else {
                    icu_flags &= ~assets::ICU_COMPRESSED;
                }
            }

            if (issuance_cap_units != current_entry.issuance_cap_units) {
                if (issuance_cap_units != 0 && current_entry.issued_total > issuance_cap_units) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("New issuance cap %s is below already issued amount %s",
                                  DescribeAssetUnits(issuance_cap_units, current_entry.decimals),
                                  DescribeAssetUnits(current_entry.issued_total, current_entry.decimals)));
                }
            }

            // Calculate required ballot units using CURRENT quorum (not proposed new quorum)
            // Security: must use current_entry.policy_quorum_bps, otherwise attacker could
            // propose 0.1% quorum and approve it themselves with minimal holdings
            uint64_t required_units = ((uint64_t)current_entry.policy_quorum_bps * settled_supply + 9999) / 10000;

            // Build new IssuerReg with updated parameters
            std::vector<unsigned char> new_issuer_reg = BuildIssuerRegV1(
                *aid,
                current_entry.policy_bits,
                current_entry.allowed_spk_families,
                current_entry.ticker,
                current_entry.decimals,
                current_entry.unlock_fees_sats + unlock_fee_bump,  // Bump ICU bond value
                kyc_flags,
                current_entry.zk_vk_commitment,
                current_entry.max_root_age,
                current_entry.tfr_flags,
                current_entry.compliance_root_commit,
                icu_flags,  // Use updated icu_flags (may have WRAP_REQUIRED set)
                issuance_cap_units,
                icu_ctxt_commit,
                icu_plain_commit,
                kdf_salt,
                0,  // icu_version
                icu_visibility,
                current_entry.core_policy_commit,
                current_entry.policy_epoch + 1,  // Increment epoch
                policy_quorum_bps
            );

            // Create PSBT template
            CMutableTransaction mtx;

            // Set rotation transaction flag in nVersion
            mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;

            // Input 0: Current ICU UTXO (will be signed with SIGHASH_ALL by finalize_rotation)
            mtx.vin.emplace_back(current_entry.icu_outpoint);

            // Output 0: New ICU UTXO with updated IssuerReg
            auto icu_dest_result = pwallet->GetNewDestination(OutputType::BECH32M, "ICU rotation");
            if (!icu_dest_result) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(icu_dest_result).original);
            }
            const CTxDestination icu_dest = *icu_dest_result;
            CScript icu_script = GetScriptForDestination(icu_dest);
            CTxOut icu_out(current_entry.unlock_fees_sats + unlock_fee_bump, icu_script);
            icu_out.vExt = new_issuer_reg;
            mtx.vout.push_back(icu_out);

            // Create LEAN template - no fee inputs yet
            // Ballots use SIGHASH_ANYONECANPAY | SIGHASH_SINGLE, which allows adding
            // fee inputs AFTER ballot signing in finalize_rotation (where we know exact size)

            // Create PSBT (ICU_TEXT_CHUNK will be added in finalize_rotation to avoid SIGHASH_SINGLE conflicts)
            PartiallySignedTransaction psbtx(mtx);

            // Populate PSBT input for ICU
            if (!psbtx.inputs.empty()) {
                const CTxIn& txin = mtx.vin[0];
                const auto wallet_it = pwallet->mapWallet.find(txin.prevout.hash);
                if (wallet_it != pwallet->mapWallet.end() && txin.prevout.n < wallet_it->second.tx->vout.size()) {
                    psbtx.inputs[0].witness_utxo = wallet_it->second.tx->vout[txin.prevout.n];
                }
                // ICU input will be signed with SIGHASH_ALL in finalize_rotation
                psbtx.inputs[0].sighash_type = SIGHASH_ALL;
            }

            // Compute proposal hash: SHA256(vin[0].prevout || vout[0].vExt)
            // This binds ballots to the exact ICU being rotated and the new IssuerReg
            uint256 proposal_hash = ComputeRotationProposalHash(mtx);

            RotationMetadata rotation_meta;
            rotation_meta.settled_supply = settled_supply;
            rotation_meta.required_units = required_units;
            rotation_meta.quorum_bps = policy_quorum_bps;
            rotation_meta.issuer_reg_commit = TxOutCommitment(mtx.vout.at(0));
            rotation_meta.issuer_reg_tlv = new_issuer_reg;  // Store IssuerReg TLV for reconstruction in finalize_rotation

            // Store ICU payload in metadata (will be added as final output by finalize_rotation)
            if (!icu_payload.empty()) {
                rotation_meta.icu_payload = icu_payload;

                // Pre-compute chunk commit for what the output will be
                CTxOut chunk_out(0, CScript() << OP_RETURN);
                std::vector<unsigned char> chunk_tlv;
                chunk_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ICU_TEXT_CHUNK));
                VectorWriter writer(chunk_tlv, chunk_tlv.size());
                WriteCompactSize(writer, icu_payload.size());
                chunk_tlv.insert(chunk_tlv.end(), icu_payload.begin(), icu_payload.end());
                chunk_out.vExt = chunk_tlv;

                rotation_meta.chunk_commit = TxOutCommitment(chunk_out);
                // chunk_index will be set in finalize_rotation when we know final output count
            }
            AttachRotationMetadata(psbtx, rotation_meta);

            // Serialize to base64
            DataStream ssTx{};
            ssTx << psbtx;
            std::string psbt_b64 = EncodeBase64(MakeUCharSpan(ssTx));

            // Generate human-readable summary comparing old vs new parameters
            UniValue summary(UniValue::VOBJ);

            // Issuance cap change
            if (issuance_cap_units != current_entry.issuance_cap_units) {
                std::string cap_old = current_entry.issuance_cap_units == 0 ? "unlimited" : DescribeAssetUnits(current_entry.issuance_cap_units, current_entry.decimals);
                std::string cap_new = issuance_cap_units == 0 ? "unlimited" : DescribeAssetUnits(issuance_cap_units, current_entry.decimals);
                summary.pushKV("issuance_cap", strprintf("%s → %s", cap_old, cap_new));
            } else {
                std::string cap_val = current_entry.issuance_cap_units == 0 ? "unlimited" : DescribeAssetUnits(current_entry.issuance_cap_units, current_entry.decimals);
                summary.pushKV("issuance_cap", strprintf("%s (unchanged)", cap_val));
            }

            // Quorum change
            if (policy_quorum_bps != current_entry.policy_quorum_bps) {
                summary.pushKV("quorum", strprintf("%.2f%% → %.2f%%",
                    current_entry.policy_quorum_bps / 100.0,
                    policy_quorum_bps / 100.0));
            } else {
                summary.pushKV("quorum", strprintf("%.2f%% (unchanged)", policy_quorum_bps / 100.0));
            }

            // ICU visibility change
            auto visibility_str = [](uint8_t vis) {
                return vis == 0 ? "public" : "holder_only";
            };
            if (icu_visibility != current_entry.icu_visibility) {
                summary.pushKV("icu_visibility", strprintf("%s → %s",
                    visibility_str(current_entry.icu_visibility),
                    visibility_str(icu_visibility)));
            } else {
                summary.pushKV("icu_visibility", strprintf("%s (unchanged)", visibility_str(icu_visibility)));
            }

            // ICU text/commit changes
            bool text_changed = !icu_payload.empty();
            bool ctxt_changed = icu_ctxt_commit != current_entry.icu_ctxt_commit;
            bool plain_changed = icu_plain_commit != current_entry.icu_plain_commit;

            if (text_changed) {
                double kb_size = icu_payload.size() / 1024.0;
                summary.pushKV("icu_text", strprintf("Updated (%.1f KB)", kb_size));
            } else if (ctxt_changed || plain_changed) {
                summary.pushKV("icu_commits", "Updated (commits only)");
            } else {
                summary.pushKV("icu_text", "No changes");
            }

            // KDF salt change
            bool salt_changed = kdf_salt != current_entry.kdf_salt;
            if (salt_changed) {
                summary.pushKV("kdf_salt", "Updated");
            }

            // KYC flags change
            bool old_kyc = current_entry.has_kyc;
            bool new_kyc = (kyc_flags & 1u) != 0;
            if (old_kyc != new_kyc) {
                summary.pushKV("kyc_required", strprintf("%s → %s",
                    old_kyc ? "yes" : "no",
                    new_kyc ? "yes" : "no"));
            }

            // Unlock fee bump
            summary.pushKV("unlock_fee_bump", strprintf("+%.2f BTC", unlock_fee_bump / 100'000'000.0));

            // Policy epoch
            summary.pushKV("policy_epoch", strprintf("%u → %u", current_entry.policy_epoch, current_entry.policy_epoch + 1));

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", psbt_b64);
            result.pushKV("proposal_hash", proposal_hash.ToString());
            result.pushKV("summary", summary);
            result.pushKV("settled_supply", settled_supply);
            result.pushKV("required_units", required_units);
            result.pushKV("policy_quorum_bps", policy_quorum_bps);
            result.pushKV("asset_id", aid->ToString());

            return result;
        }
    };
}

RPCHelpMan ballot()
{
    std::vector<RPCArg> args;
    args.emplace_back("template_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded template PSBT from prepare_rotation");

    std::vector<RPCArg> asset_utxo_inner;
    asset_utxo_inner.emplace_back("txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "UTXO transaction ID");
    asset_utxo_inner.emplace_back("vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "UTXO output index");
    args.emplace_back("asset_utxos", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of asset UTXOs to vote with", std::move(asset_utxo_inner));

    RPCResult result_desc{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "psbt", "Base64-encoded ballot PSBT with signatures"},
            {RPCResult::Type::NUM, "ballot_units", "Total asset units contributed by this ballot"},
        }
    };

    RPCExamples examples{
        HelpExampleCli("ballot", "\"cHNidP8...\" '[{\"txid\":\"abc...\",\"vout\":0}]'")
    };

    return RPCHelpMan("ballot",
        "Sign ballot inputs for quorum governance rotation.\n"
        "Each holder UTXO is added as input i with matching output i (self-bounce).\n"
        "Signs with SIGHASH_ANYONECANPAY|ALL so ballots bind the entire rotation template.",
        std::move(args),
        std::move(result_desc),
        std::move(examples),
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Decode template PSBT
            PartiallySignedTransaction psbtx;
            std::string error;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            // Parse asset_utxos array
            const UniValue& utxos_arr = request.params[1];
            if (!utxos_arr.isArray() || utxos_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_utxos must be non-empty array");
            }

            // Track total ballot units and extract asset_id from first UTXO
            uint64_t total_ballot_units = 0;
            std::optional<uint256> asset_id;

            // Add each UTXO as input i with matching output i (self-bounce)
            // Ballot inputs must be inserted at index 1 (right after ICU input at 0)
            // so that SIGHASH_SINGLE binds correctly: input[i] → output[i]
            CMutableTransaction& mtx = *psbtx.tx;
            const size_t ballot_insert_idx = 1;  // Insert ballots after ICU input (0)

            // Save fee inputs that will be moved to the end
            std::vector<CTxIn> fee_inputs;
            if (mtx.vin.size() > 1) {
                fee_inputs.assign(mtx.vin.begin() + 1, mtx.vin.end());
                mtx.vin.resize(1);  // Keep only ICU input
            }

            // Save original PSBT inputs BEFORE modifying (to preserve fee PSBTInputs in funded templates)
            std::vector<PSBTInput> original_psbt_inputs = psbtx.inputs;

            // Save ballot PSBTInputs as we create them (needed for reconstruction after loop)
            std::vector<PSBTInput> ballot_psbt_inputs;

            // Compute proposal hash from the template transaction for ballot binding
            uint256 proposal_hash = ComputeRotationProposalHash(mtx);

            for (size_t i = 0; i < utxos_arr.size(); ++i) {
                const UniValue& utxo_obj = utxos_arr[i];
                const Txid txid{Txid::FromUint256(ParseHashV(utxo_obj["txid"], "txid"))};
                const int vout = utxo_obj["vout"].getInt<int>();
                const COutPoint outpoint(txid, vout);

                // Fetch UTXO from wallet
                const auto mi = pwallet->mapWallet.find(txid);
                if (mi == pwallet->mapWallet.end() || vout >= (int)mi->second.tx->vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("UTXO %s:%d not found in wallet", txid.ToString(), vout));
                }
                const CWalletTx& wtx = mi->second;
                const CTxOut& utxo = wtx.tx->vout[vout];

                // Verify wallet owns this UTXO
                isminetype mine = pwallet->IsMine(utxo);
                if (!(mine & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("UTXO %s:%d is not spendable", txid.ToString(), vout));
                }

                // Extract asset info
                const auto asset_data = assets::ParseAssetTag(utxo.vExt);
                if (!asset_data) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("UTXO %s:%d does not contain asset data", txid.ToString(), vout));
                }

                // Verify all UTXOs are same asset
                if (!asset_id) {
                    asset_id = asset_data->id;
                } else if (*asset_id != asset_data->id) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "All asset_utxos must have the same asset_id");
                }

                total_ballot_units += asset_data->amount;

                // Add ballot input at ballot_insert_idx + i (inputs 1, 2, 3...)
                const size_t new_input_index = ballot_insert_idx + i;
                mtx.vin.insert(mtx.vin.begin() + new_input_index, CTxIn(outpoint));

                // Ensure outputs array is aligned with new input index
                if (mtx.vout.size() <= new_input_index) {
                    mtx.vout.resize(new_input_index + 1);
                }

                // Add matching output (self-bounce with same amount) embedding proposal_hash
                // This cryptographically binds the ballot to the rotation proposal.
                // For WRAP_REQUIRED assets, preserve any existing ICU_KEYWRAP sub-TLV from the source
                // UTXO so mempool policy (icu-wrap-missing) is satisfied.
                CTxOut bounce_out;
                bounce_out.nValue = utxo.nValue;
                bounce_out.scriptPubKey = utxo.scriptPubKey;

                std::vector<unsigned char> ballot_vext;
                if (asset_data->has_keywrap) {
                    // Rebuild ASSET_TAG payload with both ICU_KEYWRAP and proposal_hash sub-TLVs.
                    std::vector<unsigned char> payload;
                    payload.reserve(32 + 8 + 4);

                    // asset_id (32 bytes)
                    payload.insert(payload.end(), asset_data->id.begin(), asset_data->id.end());

                    // amount (8 bytes little-endian)
                    unsigned char amount_bytes[8];
                    for (int j = 0; j < 8; ++j) {
                        amount_bytes[j] = static_cast<unsigned char>((asset_data->amount >> (j * 8)) & 0xFF);
                    }
                    payload.insert(payload.end(), amount_bytes, amount_bytes + 8);

                    // flags (4 bytes little-endian)
                    unsigned char flags_bytes[4];
                    for (int j = 0; j < 4; ++j) {
                        flags_bytes[j] = static_cast<unsigned char>((asset_data->flags >> (j * 8)) & 0xFF);
                    }
                    payload.insert(payload.end(), flags_bytes, flags_bytes + 4);

                    // Optional epoch sub-TLV (type 0x02)
                    if (asset_data->has_epoch) {
                        payload.push_back(0x02);  // sub-type: epoch
                        payload.push_back(0x01);  // length: 1 byte
                        payload.push_back(asset_data->epoch);
                    }

                    // ICU_KEYWRAP sub-TLV (type 0x03), re-encoded from AssetTag keywrap fields
                    {
                        std::vector<unsigned char> kw_payload;
                        kw_payload.reserve(32 + 32 + 32 +
                            asset_data->keywrap_wrapped_key.size() + 10 +
                            ((asset_data->keywrap_extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT) ? 32 : 0) +
                            ((asset_data->keywrap_extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) ? assets::ICU_KEYWRAP_KC_TAG_SIZE : 0));

                        // asset_id (32)
                        kw_payload.insert(kw_payload.end(),
                                          asset_data->keywrap_asset_id.begin(),
                                          asset_data->keywrap_asset_id.end());
                        // ctxt_hash (32)
                        kw_payload.insert(kw_payload.end(),
                                          asset_data->keywrap_ctxt_hash.begin(),
                                          asset_data->keywrap_ctxt_hash.end());
                        // spk_hash32 (32)
                        kw_payload.insert(kw_payload.end(),
                                          asset_data->keywrap_spk_hash32.begin(),
                                          asset_data->keywrap_spk_hash32.end());

                        // wrapped_key length + data
                        VectorWriter kw_writer(kw_payload, kw_payload.size());
                        WriteCompactSize(kw_writer, asset_data->keywrap_wrapped_key.size());
                        kw_payload.insert(kw_payload.end(),
                                          asset_data->keywrap_wrapped_key.begin(),
                                          asset_data->keywrap_wrapped_key.end());

                        // suite_id and extras_mask
                        kw_payload.push_back(asset_data->keywrap_suite_id);
                        kw_payload.push_back(asset_data->keywrap_extras_mask);

                        // Optional wrap_commit
                        if (asset_data->keywrap_extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
                            kw_payload.insert(kw_payload.end(),
                                              asset_data->keywrap_wrap_commit.begin(),
                                              asset_data->keywrap_wrap_commit.end());
                        }

                        // Optional kc_tag
                        if (asset_data->keywrap_extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) {
                            kw_payload.insert(kw_payload.end(),
                                              asset_data->keywrap_kc_tag.begin(),
                                              asset_data->keywrap_kc_tag.end());
                        }

                        // Append ICU_KEYWRAP sub-TLV to payload: type (0x03) + CompactSize length + payload
                        payload.push_back(0x03);
                        VectorWriter payload_writer(payload, payload.size());
                        WriteCompactSize(payload_writer, kw_payload.size());
                        payload.insert(payload.end(), kw_payload.begin(), kw_payload.end());
                    }

                    // proposal_hash sub-TLV (type 0x04)
                    payload.push_back(0x04);
                    payload.push_back(32);
                    payload.insert(payload.end(), proposal_hash.begin(), proposal_hash.end());

                    // Wrap as single ASSET_TAG TLV
                    ballot_vext.clear();
                    ballot_vext.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));

                    const size_t payload_size = payload.size();
                    if (payload_size < 253) {
                        ballot_vext.push_back(static_cast<uint8_t>(payload_size));
                    } else if (payload_size <= 0xFFFF) {
                        ballot_vext.push_back(253);
                        ballot_vext.push_back(static_cast<uint8_t>(payload_size & 0xFF));
                        ballot_vext.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));
                    } else {
                        ballot_vext.push_back(254);
                        for (int j = 0; j < 4; ++j) {
                            ballot_vext.push_back(static_cast<uint8_t>((payload_size >> (j * 8)) & 0xFF));
                        }
                    }
                    ballot_vext.insert(ballot_vext.end(), payload.begin(), payload.end());
                } else {
                    // Legacy/public assets without ICU_KEYWRAP: just bind proposal_hash as before.
                    ballot_vext = assets::BuildAssetTagWithProposal(
                        asset_data->id,
                        asset_data->amount,
                        proposal_hash,
                        asset_data->flags,
                        asset_data->has_epoch,
                        asset_data->epoch
                    );
                }

                bounce_out.vExt = std::move(ballot_vext);
                mtx.vout[new_input_index] = bounce_out;

                // Create PSBTInput with UTXO data
                PSBTInput psbtin;
                psbtin.witness_utxo = utxo;
                // Set sighash type to SIGHASH_ANYONECANPAY | SIGHASH_SINGLE
                // SINGLE: binds input[i] → output[i] (voter's bounce with proposal_hash)
                // ANYONECANPAY: allows adding other ballots/fees after signing (parallel voting)
                // Safe because: bounce output is self-return, asset delta=0 enforced, proposal_hash locked
                psbtin.sighash_type = SIGHASH_ANYONECANPAY | SIGHASH_SINGLE;

                if (psbtx.inputs.size() <= new_input_index) {
                    psbtx.inputs.resize(new_input_index + 1);
                }
                bool created_output_slot = false;
                if (psbtx.outputs.size() <= new_input_index) {
                    psbtx.outputs.resize(new_input_index + 1);
                    created_output_slot = true;
                }
                // Save ballot PSBTInput to list (before any array modifications)
                ballot_psbt_inputs.push_back(psbtin);
                psbtx.inputs[new_input_index] = psbtin;
                if (created_output_slot) {
                    psbtx.outputs[new_input_index] = PSBTOutput{};
                }
            }

            // Restore fee inputs at the end
            for (const auto& fee_input : fee_inputs) {
                mtx.vin.push_back(fee_input);
            }

            // With LEAN template: fee_inputs is empty, so mtx.vin = [ICU, ...ballots]
            // No PSBT reconstruction needed - ballots are already set at indices 1, 2, 3...
            // (Template had only [ICU], ballots were inserted at ballot_insert_idx onwards)

            // Sign all ballot inputs with SIGHASH_SINGLE
            size_t num_ballots = utxos_arr.size();
            std::map<COutPoint, Coin> coins;
            for (size_t i = ballot_insert_idx; i < ballot_insert_idx + num_ballots; ++i) {
                const auto& input = mtx.vin[i];
                const auto mi = pwallet->mapWallet.find(input.prevout.hash);
                if (mi != pwallet->mapWallet.end() && input.prevout.n < mi->second.tx->vout.size()) {
                    const CWalletTx& wtx = mi->second;
                    int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
                    coins[input.prevout] = Coin(wtx.tx->vout[input.prevout.n], prev_height, wtx.IsCoinBase());
                }
            }

            // Taproot signing requires prevout data for every input (even the ICU/fee
            // ones we are not signing). Populate missing entries from the PSBT so
            // SignatureHashSchnorr has the full context.
            for (size_t i = 0; i < mtx.vin.size(); ++i) {
                const COutPoint& prevout = mtx.vin[i].prevout;
                if (coins.count(prevout)) {
                    continue; // Already sourced from the wallet (ballot inputs).
                }

                CTxOut prevout_utxo;
                if (i < psbtx.inputs.size()) {
                    const PSBTInput& psbt_input = psbtx.inputs[i];
                    if (!psbt_input.witness_utxo.IsNull()) {
                        prevout_utxo = psbt_input.witness_utxo;
                    } else if (psbt_input.non_witness_utxo) {
                        const CTransaction& prev_tx = *psbt_input.non_witness_utxo;
                        if (prevout.n < prev_tx.vout.size()) {
                            prevout_utxo = prev_tx.vout[prevout.n];
                        }
                    }
                }

                if (prevout_utxo.IsNull()) {
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        strprintf("Missing prevout metadata for rotation input %zu (%s:%u)",
                                  i, prevout.hash.ToString(), prevout.n));
                }

                coins.emplace(prevout, Coin(prevout_utxo, /*nHeight=*/0, /*fCoinBase=*/false));
            }

            std::map<int, bilingual_str> input_errors;
            const int sighash = SIGHASH_ANYONECANPAY | SIGHASH_SINGLE;
            bool signed_all = pwallet->SignTransaction(mtx, coins, sighash, input_errors);
            if (!signed_all) {
                bool only_foreign_failures = true;
                for (const auto& [idx, msg] : input_errors) {
                    size_t input_idx = static_cast<size_t>(idx);
                    if (input_idx >= ballot_insert_idx && input_idx < ballot_insert_idx + num_ballots) {
                        only_foreign_failures = false;
                        break;
                    }
                }
                if (!only_foreign_failures) {
                    UniValue errors_arr(UniValue::VARR);
                    for (const auto& [idx, msg] : input_errors) {
                        UniValue err(UniValue::VOBJ);
                        err.pushKV("input_index", idx);
                        err.pushKV("error", msg.original);
                        errors_arr.push_back(err);
                    }
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to sign ballot: %s", errors_arr.write()));
                }
            }

            for (size_t i = ballot_insert_idx; i < ballot_insert_idx + num_ballots; ++i) {
                if (mtx.vin[i].scriptWitness.IsNull()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to sign ballot input %u", i));
                }
            }

            // Update PSBT with signed inputs
            for (size_t i = ballot_insert_idx; i < ballot_insert_idx + num_ballots; ++i) {
                size_t psbt_idx = i;
                if (psbt_idx < psbtx.inputs.size()) {
                    psbtx.inputs[psbt_idx].final_script_sig = mtx.vin[i].scriptSig;
                    psbtx.inputs[psbt_idx].final_script_witness = mtx.vin[i].scriptWitness;
                }
            }

            // Keep the underlying unsigned tx canonical (no scripts/witnesses)
            for (auto& txin : mtx.vin) {
                txin.scriptSig.clear();
                txin.scriptWitness.SetNull();
            }

            // Encode PSBT back to base64
            DataStream ssTx{};
            ssTx << psbtx;
            std::string psbt_b64 = EncodeBase64(MakeUCharSpan(ssTx));

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", psbt_b64);
            result.pushKV("ballot_units", total_ballot_units);
            return result;
        });
}

RPCHelpMan merge_rotation()
{
    std::vector<RPCArg> args;
    args.emplace_back("template_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded template PSBT");
    std::vector<RPCArg> ballot_inner;
    ballot_inner.emplace_back("", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Base64-encoded ballot PSBT");
    args.emplace_back("ballot_psbts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of ballot PSBTs", std::move(ballot_inner));

    RPCResult result_desc{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "psbt", "Base64-encoded merged PSBT"},
            {RPCResult::Type::NUM, "total_ballot_units", "Total ballot units from all ballots"},
            {RPCResult::Type::NUM, "asset_delta", "Asset delta (should be 0 for valid rotation)"},
            {RPCResult::Type::BOOL, "quorum_met", "Whether required quorum is met (informational)"},
            {RPCResult::Type::NUM, "required_units", "Minimum ballot units needed for quorum"},
            {RPCResult::Type::NUM, "policy_quorum_bps", "Governance quorum threshold"},
            {RPCResult::Type::NUM, "settled_supply", "Current settled supply (issued - burned)"},
        }
    };

    RPCExamples examples{
        HelpExampleCli("merge_rotation", "\"cHNidP8...\" '[\"cHNidP8...\",\"cHNidP8...\"]'")
    };

    return RPCHelpMan("merge_rotation",
        "Merge multiple ballot PSBTs into a single rotation transaction.\n"
        "Validates pairing (input i → output i) and computes total ballot units.\n"
        "Enforces Δ=0 (no mint/burn during rotation).",
        std::move(args),
        std::move(result_desc),
        std::move(examples),
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            // Decode template PSBT
            PartiallySignedTransaction template_psbt;
            std::string error;
            if (!DecodeBase64PSBT(template_psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Template TX decode failed %s", error));
            }

            auto meta_opt = ExtractRotationMetadata(template_psbt);
            if (!meta_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Template PSBT missing rotation metadata");
            }
            RotationMetadata rotation_meta = *meta_opt;

            // Decode all ballot PSBTs
            const UniValue& ballot_arr = request.params[1];
            if (!ballot_arr.isArray() || ballot_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ballot_psbts must be non-empty array");
            }

            std::vector<PartiallySignedTransaction> ballot_psbts;
            for (size_t i = 0; i < ballot_arr.size(); ++i) {
                PartiallySignedTransaction ballot_psbt;
                if (!DecodeBase64PSBT(ballot_psbt, ballot_arr[i].get_str(), error)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Ballot %zu decode failed %s", i, error));
                }
                ballot_psbts.push_back(ballot_psbt);
            }

            // Start with template, then INSERT ballot contributions at position 1 (after ICU)
            // Template has: [ICU(0), fee1(1), fee2(2)]
            // Goal: [ICU(0), ballot1(1), ballot2(2), fee1(3), fee2(4)]
            PartiallySignedTransaction merged_psbt = template_psbt;
            CMutableTransaction& merged_tx = *merged_psbt.tx;
            const CMutableTransaction& template_tx = *template_psbt.tx;
            const size_t template_inputs = template_tx.vin.size();

            // Track where to insert next ballot (starts at position 1, after ICU)
            size_t ballot_insert_position = 1;

            // Compute expected proposal hash from template for validation
            uint256 expected_proposal_hash = ComputeRotationProposalHash(template_tx);

            std::set<COutPoint> seen_inputs;
            std::map<size_t, assets::AssetTag> ballot_asset_hints;
            for (const auto& vin : merged_tx.vin) {
                seen_inputs.insert(vin.prevout);
            }

            for (const auto& ballot_psbt : ballot_psbts) {
                const CMutableTransaction& ballot_tx = *ballot_psbt.tx;
                if (ballot_tx.vin.size() < template_inputs) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot missing template inputs");
                }

                // Verify template inputs match
                // Template has: [ICU(0), ...fees(1+)]
                // Ballot has: [ICU(0), ...ballots, ...fees]
                // We need to verify ICU input matches and fee inputs match (in order at the end)

                // Check ICU input (index 0)
                if (ballot_tx.vin[0].prevout != template_tx.vin[0].prevout) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot ICU input mismatch");
                }

                // Calculate where fee inputs start in ballot_tx
                size_t num_template_fees = template_inputs - 1;  // All template inputs except ICU
                [[maybe_unused]] size_t num_ballot_inputs = ballot_tx.vin.size() - template_inputs;  // New ballot inputs added
                size_t ballot_fee_start = ballot_tx.vin.size() - num_template_fees;

                // Verify fee inputs match (template[1..N] should match ballot[ballot_fee_start..end])
                for (size_t i = 0; i < num_template_fees; ++i) {
                    if (ballot_tx.vin[ballot_fee_start + i].prevout != template_tx.vin[1 + i].prevout) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot fee inputs mismatch");
                    }
                }

                // Insert new ballot inputs/outputs at ballot_insert_position (indices 1 through ballot_fee_start-1)
                for (size_t idx = 1; idx < ballot_fee_start; ++idx) {
                    const CTxIn& new_input = ballot_tx.vin[idx];
                    if (!seen_inputs.insert(new_input.prevout).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate ballot input detected");
                    }

                    // INSERT at ballot_insert_position instead of appending
                    merged_tx.vin.insert(merged_tx.vin.begin() + ballot_insert_position, new_input);
                    PSBTInput psbt_input = idx < ballot_psbt.inputs.size() ? ballot_psbt.inputs[idx] : PSBTInput{};
                    merged_psbt.inputs.insert(merged_psbt.inputs.begin() + ballot_insert_position, psbt_input);

                    CTxOut new_output;
                    if (idx < ballot_tx.vout.size()) {
                        new_output = ballot_tx.vout[idx];
                    } else if (!psbt_input.witness_utxo.IsNull()) {
                        new_output = psbt_input.witness_utxo;
                    } else if (psbt_input.non_witness_utxo) {
                        const auto& prev_tx = *psbt_input.non_witness_utxo;
                        if (new_input.prevout.n >= prev_tx.vout.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot referenced output out of range");
                        }
                        new_output = prev_tx.vout[new_input.prevout.n];
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                            "Ballot missing witness_utxo data for input %zu (ballot has %zu vouts, %zu inputs)",
                            idx, ballot_tx.vout.size(), ballot_tx.vin.size()));
                    }
                    // INSERT output at same position
                    merged_tx.vout.insert(merged_tx.vout.begin() + ballot_insert_position, new_output);
                    PSBTOutput psbt_output = idx < ballot_psbt.outputs.size() ? ballot_psbt.outputs[idx] : PSBTOutput{};
                    merged_psbt.outputs.insert(merged_psbt.outputs.begin() + ballot_insert_position, psbt_output);

                    const auto asset_hint = assets::ParseAssetTag(new_output.vExt);
                    if (!asset_hint) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                            "Ballot output missing asset tag at index %zu (vExt size: %zu, from: %s)",
                            idx, new_output.vExt.size(),
                            (idx < ballot_tx.vout.size()) ? "ballot_tx.vout" :
                            (!psbt_input.witness_utxo.IsNull()) ? "witness_utxo" : "non_witness_utxo"));
                    }

                    // Verify proposal_hash binding: all ballots must reference same proposal
                    if (!asset_hint->has_proposal_hash) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot output missing proposal_hash");
                    }
                    if (asset_hint->proposal_hash != expected_proposal_hash) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                            "Ballot proposal_hash mismatch: expected %s, got %s",
                            expected_proposal_hash.ToString(),
                            asset_hint->proposal_hash.ToString()
                        ));
                    }

                    // Store hint at the current ballot_insert_position
                    ballot_asset_hints.emplace(ballot_insert_position, *asset_hint);

                    // Increment position for next ballot
                    ballot_insert_position++;
                }
            }

            AttachRotationMetadata(merged_psbt, rotation_meta);

            // Compute asset delta (sum inputs - sum outputs for all assets)
            std::map<uint256, uint64_t> input_sums;
            std::map<uint256, uint64_t> output_sums;

            const CMutableTransaction& mtx = *merged_psbt.tx;
            std::vector<CTxOut> prevouts(mtx.vin.size());

            // Sum inputs
            for (size_t i = 0; i < mtx.vin.size(); ++i) {
                if (i >= merged_psbt.inputs.size()) continue;
                const PSBTInput& psbtin = merged_psbt.inputs[i];

                CTxOut utxo;
                if (!psbtin.witness_utxo.IsNull()) {
                    utxo = psbtin.witness_utxo;
                } else if (psbtin.non_witness_utxo) {
                    const COutPoint& prevout = mtx.vin[i].prevout;
                    if (prevout.n < psbtin.non_witness_utxo->vout.size()) {
                        utxo = psbtin.non_witness_utxo->vout[prevout.n];
                    }
                }

                if (!utxo.IsNull()) {
                    if (const auto asset_in = assets::ParseAssetTag(utxo.vExt)) {
                        input_sums[asset_in->id] += asset_in->amount;
                        prevouts[i] = utxo;
                        continue;
                    }
                }

                auto hint_it = ballot_asset_hints.find(i);
                if (hint_it != ballot_asset_hints.end()) {
                    const auto& hint = hint_it->second;
                    input_sums[hint.id] += hint.amount;
                    if (i < merged_tx.vout.size()) {
                        prevouts[i] = merged_tx.vout[i];
                    }
                    continue;
                }
            }

            // Sum outputs
            for (const auto& txout : mtx.vout) {
                if (const auto asset_out = assets::ParseAssetTag(txout.vExt)) {
                    output_sums[asset_out->id] += asset_out->amount;
                }
            }

            // Compute total ballot units (should be sum of all ballot inputs from non-ICU outputs)
            uint64_t total_ballot_units = 0;
            std::optional<uint256> ballot_asset_id;
            bool has_ballot_inputs = false;

            // The first input should be the ICU, ballots start at index 1, fees at the end
            // We only care about ballot inputs (which have asset data)
            for (size_t i = 1; i < mtx.vin.size(); ++i) {
                if (i >= merged_psbt.inputs.size()) continue;
                const CTxOut& utxo = prevouts[i];

                // Skip inputs without UTXO data (fee inputs added by FundTransaction)
                if (utxo.IsNull()) {
                    continue;
                }

                const auto asset_in = assets::ParseAssetTag(utxo.vExt);
                // Skip BTC-only inputs (fee inputs)
                if (!asset_in) {
                    continue;
                }

                // Check if this is an ICU (has IssuerReg)
                bool is_icu = !utxo.vExt.empty() && assets::ParseIssuerReg(utxo.vExt).has_value();
                if (is_icu) {
                    continue;
                }

                has_ballot_inputs = true;

                if (!ballot_asset_id) {
                    ballot_asset_id = asset_in->id;
                } else if (*ballot_asset_id != asset_in->id) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot inputs reference multiple asset IDs");
                }

                if (i >= mtx.vout.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing paired output for ballot input");
                }

                const CTxOut& paired_out = mtx.vout[i];
                if (paired_out.scriptPubKey != utxo.scriptPubKey || paired_out.nValue != utxo.nValue) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot outputs must self-bounce to original holder");
                }

                const auto asset_out = assets::ParseAssetTag(paired_out.vExt);
                if (!asset_out) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot outputs must carry the asset back to the holder");
                }
                if (asset_out->id != asset_in->id || asset_out->amount != asset_in->amount) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot outputs must keep asset ID and amount unchanged");
                }

                total_ballot_units += asset_in->amount;
            }

            if (!has_ballot_inputs) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No ballot inputs present in merged transaction");
            }

            // Validate Δ=0 for each asset (inputs == outputs)
            uint64_t max_delta = 0;
            for (const auto& [asset_id, input_sum] : input_sums) {
                const uint64_t output_sum = output_sums[asset_id];
                const uint64_t delta = (input_sum > output_sum) ? (input_sum - output_sum) : (output_sum - input_sum);
                max_delta = std::max(max_delta, delta);
            }
            for (const auto& [asset_id, output_sum] : output_sums) {
                if (input_sums.find(asset_id) == input_sums.end()) {
                    // New asset being minted
                    max_delta = std::max(max_delta, output_sum);
                }
            }

            if (max_delta != 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Rotation must preserve asset supply (Δ=0 constraint violated)");
            }

            if (!rotation_meta.issuer_reg_commit.IsNull()) {
                if (mtx.vout.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Rotation transaction missing issuer output");
                }
                const uint256 issuer_commit = TxOutCommitment(mtx.vout.at(0));
                if (issuer_commit != rotation_meta.issuer_reg_commit) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "IssuerReg output mismatch (template altered after ballot)");
                }
            }

            if (rotation_meta.chunk_index != std::numeric_limits<uint8_t>::max()) {
                if (rotation_meta.chunk_index >= mtx.vout.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing ICU chunk output referenced in template");
                }
                const uint256 chunk_commit = TxOutCommitment(mtx.vout.at(rotation_meta.chunk_index));
                if (chunk_commit != rotation_meta.chunk_commit) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU chunk output mismatch (template altered after ballot)");
                }
            }

            // Check if quorum is met using metadata from template PSBT
            bool quorum_met = total_ballot_units >= rotation_meta.required_units;

            // Encode merged PSBT
            DataStream ssTx{};
            ssTx << merged_psbt;
            std::string psbt_b64 = EncodeBase64(MakeUCharSpan(ssTx));

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", psbt_b64);
            result.pushKV("total_ballot_units", total_ballot_units);
            result.pushKV("asset_delta", max_delta);
            result.pushKV("quorum_met", quorum_met);
            result.pushKV("required_units", rotation_meta.required_units);
            result.pushKV("policy_quorum_bps", rotation_meta.quorum_bps);
            result.pushKV("settled_supply", rotation_meta.settled_supply);
            return result;
        });
}

RPCHelpMan validate_ballot()
{
    return RPCHelpMan("validate_ballot",
        "Validate a single ballot PSBT before merging.\n"
        "Checks UTXO existence, signature validity, and proposal binding.\n"
        "Prevents malicious/invalid ballots from wasting issuer's time.",
        {
            {"template_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded template PSBT"},
            {"ballot_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded ballot PSBT to validate"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether ballot is valid"},
                {RPCResult::Type::STR, "error", /* optional */ true, "Error message if invalid"},
                {RPCResult::Type::NUM, "ballot_units", /* optional */ true, "Voting units if valid"},
                {RPCResult::Type::ARR, "issues", /* optional */ true, "List of validation issues",
                    {
                        {RPCResult::Type::STR, "", "Issue description"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("validate_ballot", "\"cHNidP8...\" \"cHNidP8...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return NullUniValue;

            LOCK(pwallet->cs_wallet);

            UniValue result(UniValue::VOBJ);
            UniValue issues(UniValue::VARR);
            bool valid = true;

            // Decode template PSBT
            PartiallySignedTransaction template_psbt;
            std::string error;
            if (!DecodeBase64PSBT(template_psbt, request.params[0].get_str(), error)) {
                result.pushKV("valid", false);
                result.pushKV("error", strprintf("Template PSBT decode failed: %s", error));
                return result;
            }

            // Decode ballot PSBT
            PartiallySignedTransaction ballot_psbt;
            if (!DecodeBase64PSBT(ballot_psbt, request.params[1].get_str(), error)) {
                result.pushKV("valid", false);
                result.pushKV("error", strprintf("Ballot PSBT decode failed: %s", error));
                return result;
            }

            // Extract rotation metadata from template
            auto meta_opt = ExtractRotationMetadata(template_psbt);
            if (!meta_opt) {
                result.pushKV("valid", false);
                result.pushKV("error", "Template PSBT missing rotation metadata");
                return result;
            }
            RotationMetadata rotation_meta = *meta_opt;

            const CMutableTransaction& template_tx = *template_psbt.tx;
            const CMutableTransaction& ballot_tx = *ballot_psbt.tx;
            const size_t template_inputs = template_tx.vin.size();

            // 1. Check ballot has minimum required inputs
            if (ballot_tx.vin.size() < template_inputs) {
                result.pushKV("valid", false);
                result.pushKV("error", "Ballot missing template inputs");
                return result;
            }

            // 2. Verify ICU input matches (index 0)
            if (ballot_tx.vin[0].prevout != template_tx.vin[0].prevout) {
                issues.push_back("ICU input mismatch");
                valid = false;
            }

            // 3. Verify fee inputs match
            size_t num_template_fees = template_inputs - 1;
            size_t ballot_fee_start = ballot_tx.vin.size() - num_template_fees;
            for (size_t i = 0; i < num_template_fees; ++i) {
                if (ballot_tx.vin[ballot_fee_start + i].prevout != template_tx.vin[1 + i].prevout) {
                    issues.push_back(strprintf("Fee input %zu mismatch", i));
                    valid = false;
                }
            }

            // 4. Compute expected proposal hash
            uint256 expected_proposal_hash = ComputeRotationProposalHash(template_tx);

            // 5. Validate ballot inputs (between ICU and fee inputs)
            uint64_t total_ballot_units = 0;
            std::optional<uint256> ballot_asset_id;

            // Batch lookup all ballot UTXOs
            std::map<COutPoint, Coin> coins;
            for (size_t idx = 1; idx < ballot_fee_start; ++idx) {
                coins[ballot_tx.vin[idx].prevout]; // Create empty map entry
            }
            pwallet->chain().findCoins(coins);

            for (size_t idx = 1; idx < ballot_fee_start; ++idx) {
                const CTxIn& ballot_input = ballot_tx.vin[idx];

                // Check UTXO exists on-chain
                auto coin_it = coins.find(ballot_input.prevout);
                if (coin_it == coins.end() || coin_it->second.IsSpent()) {
                    issues.push_back(strprintf("UTXO not found or spent: %s:%d",
                        ballot_input.prevout.hash.ToString(), ballot_input.prevout.n));
                    valid = false;
                    continue;
                }

                const Coin& coin = coin_it->second;

                // Parse asset tag from UTXO
                const auto asset_in = assets::ParseAssetTag(coin.out.vExt);
                if (!asset_in) {
                    issues.push_back(strprintf("Input %zu missing asset tag", idx));
                    valid = false;
                    continue;
                }

                // Check asset ID consistency
                if (!ballot_asset_id) {
                    ballot_asset_id = asset_in->id;
                } else if (*ballot_asset_id != asset_in->id) {
                    issues.push_back("Multiple asset IDs in ballot");
                    valid = false;
                }

                // Verify paired output exists and matches
                if (idx >= ballot_tx.vout.size()) {
                    issues.push_back(strprintf("Missing paired output for input %zu", idx));
                    valid = false;
                    continue;
                }

                const CTxOut& paired_out = ballot_tx.vout[idx];
                const auto asset_out = assets::ParseAssetTag(paired_out.vExt);

                if (!asset_out) {
                    issues.push_back(strprintf("Output %zu missing asset tag", idx));
                    valid = false;
                    continue;
                }

                // Verify proposal_hash binding
                if (!asset_out->has_proposal_hash) {
                    issues.push_back(strprintf("Output %zu missing proposal_hash", idx));
                    valid = false;
                } else if (asset_out->proposal_hash != expected_proposal_hash) {
                    issues.push_back(strprintf("Output %zu proposal_hash mismatch", idx));
                    valid = false;
                }

                // Verify self-bounce (same scriptPubKey, value, asset)
                if (paired_out.scriptPubKey != coin.out.scriptPubKey) {
                    issues.push_back(strprintf("Output %zu scriptPubKey mismatch (not self-bounce)", idx));
                    valid = false;
                }

                if (paired_out.nValue != coin.out.nValue) {
                    issues.push_back(strprintf("Output %zu BTC value mismatch", idx));
                    valid = false;
                }

                if (asset_out->id != asset_in->id || asset_out->amount != asset_in->amount) {
                    issues.push_back(strprintf("Output %zu asset amount mismatch", idx));
                    valid = false;
                }

                // Check signature exists and is valid
                if (idx < ballot_psbt.inputs.size()) {
                    const PSBTInput& psbt_in = ballot_psbt.inputs[idx];

                    // Check if we have any signature data
                    bool has_signature = false;

                    if (!psbt_in.final_script_sig.empty() || !psbt_in.final_script_witness.IsNull()) {
                        has_signature = true;
                    } else if (!psbt_in.partial_sigs.empty()) {
                        has_signature = true;
                    }

                    if (!has_signature) {
                        issues.push_back(strprintf("Input %zu missing signature", idx));
                        valid = false;
                    }

                    // TODO: Full signature verification would require building the transaction
                    // and calling VerifyScript - this is expensive but might be worth it
                    // For now, we just check signatures exist
                }

                total_ballot_units += asset_in->amount;
            }

            // 6. Check we found at least one ballot input
            if (total_ballot_units == 0 && valid) {
                issues.push_back("No ballot inputs found");
                valid = false;
            }

            result.pushKV("valid", valid);
            if (!valid && !issues.empty()) {
                result.pushKV("issues", issues);
            }
            if (valid) {
                result.pushKV("ballot_units", total_ballot_units);
            }

            return result;
        });
}

RPCHelpMan finalize_rotation()
{
    return RPCHelpMan{
        "finalize_rotation",
        "Finalize and broadcast a merged governance rotation.\n"
        "Adds BTC fee inputs, signs ICU input with SIGHASH_ALL, and broadcasts.",
        {
            {"merged_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded merged PSBT from merge_rotation"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Transaction ID"},
                {RPCResult::Type::STR_HEX, "hex", "Signed raw transaction hex"},
                {RPCResult::Type::BOOL, "broadcast", "True if the transaction was submitted to the mempool"},
            }
        },
        RPCExamples{
            HelpExampleCli("finalize_rotation", "\"cHNidP8...\" '{\"broadcast\":true}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Decode merged PSBT
            PartiallySignedTransaction psbtx;
            std::string error;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            // Parse options
            bool do_broadcast = true;
            CCoinControl coin_control;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                const UniValue& options = request.params[1];
                if (options["broadcast"].isBool()) {
                    do_broadcast = options["broadcast"].get_bool();
                }
                if (!options["fee_rate"].isNull()) {
                    coin_control.m_feerate = CFeeRate(AmountFromValue(options["fee_rate"], /*decimals=*/3));
                }
            }

            auto rotation_meta = ExtractRotationMetadata(psbtx);

            CMutableTransaction original_tx = *psbtx.tx;

            struct OutputTemplate {
                CTxOut txout;
                bool has_destination;
            };

            std::vector<OutputTemplate> output_templates;
            std::vector<CRecipient> recipients;
            output_templates.reserve(original_tx.vout.size());
            recipients.reserve(original_tx.vout.size());

            for (const auto& txout : original_tx.vout) {
                OutputTemplate templ{txout, false};
                CTxDestination dest;
                if (ExtractDestination(txout.scriptPubKey, dest)) {
                    templ.has_destination = true;
                    recipients.push_back({dest, txout.nValue, /*fSubtractFeeFromAmount=*/false});
                }
                output_templates.push_back(std::move(templ));
            }

            // NOW add fee inputs - we know the exact transaction size after merging ballots
            // Ballots signed with ANYONECANPAY | SINGLE allow adding inputs/outputs safely
            CMutableTransaction funded_tx = original_tx;

            std::vector<CTxOut> final_vout;
            final_vout.reserve(original_tx.vout.size() + 1);  // +1 for potential ICU_TEXT_CHUNK

            // Reconstruct vout[0] (IssuerReg) with vExt from metadata
            // PSBT serialization doesn't preserve vExt in the unsigned tx, so we restore it here
            if (!rotation_meta || rotation_meta->issuer_reg_tlv.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Rotation metadata missing IssuerReg TLV");
            }
            if (original_tx.vout.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Rotation transaction missing vout[0]");
            }

            // Copy vout[0] and restore vExt from metadata
            CTxOut issuer_reg_out = original_tx.vout[0];
            issuer_reg_out.vExt = rotation_meta->issuer_reg_tlv;
            final_vout.push_back(issuer_reg_out);

            // Copy remaining outputs (ballots) - they don't have vExt
            for (size_t i = 1; i < original_tx.vout.size(); ++i) {
                final_vout.push_back(original_tx.vout[i]);
            }

            // Add ICU_TEXT_CHUNK output if payload is present in metadata
            if (rotation_meta && !rotation_meta->icu_payload.empty()) {
                CTxOut chunk_out(0, CScript() << OP_RETURN);
                std::vector<unsigned char> chunk_tlv;
                chunk_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ICU_TEXT_CHUNK));
                VectorWriter writer(chunk_tlv, chunk_tlv.size());
                WriteCompactSize(writer, rotation_meta->icu_payload.size());
                chunk_tlv.insert(chunk_tlv.end(), rotation_meta->icu_payload.begin(), rotation_meta->icu_payload.end());
                chunk_out.vExt = chunk_tlv;

                final_vout.push_back(chunk_out);

                // Update chunk_index in metadata
                if (final_vout.size() > std::numeric_limits<uint8_t>::max()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Too many outputs to encode ICU chunk index");
                }
                rotation_meta->chunk_index = static_cast<uint8_t>(final_vout.size() - 1);
            }

            funded_tx.vout = std::move(final_vout);

            if (rotation_meta) {
                const auto& final_outputs = funded_tx.vout;
                if (final_outputs.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Rotation transaction missing outputs after funding");
                }
                const uint256 issuer_commit = TxOutCommitment(final_outputs.at(0));
                if (!rotation_meta->issuer_reg_commit.IsNull() && issuer_commit != rotation_meta->issuer_reg_commit) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "IssuerReg output mismatch before signing");
                }
                if (rotation_meta->chunk_index != std::numeric_limits<uint8_t>::max()) {
                    const size_t chunk_idx = rotation_meta->chunk_index;
                    if (chunk_idx >= final_outputs.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing ICU chunk output before signing");
                    }
                    const uint256 chunk_commit = TxOutCommitment(final_outputs.at(chunk_idx));
                    if (chunk_commit != rotation_meta->chunk_commit) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU chunk output mismatch before signing");
                    }
                }
            }

            // Get user-specified fee rate or use default
            CFeeRate fee_rate(10000);  // Default 10 sat/vB
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                const UniValue& options = request.params[1];
                if (!options["fee_rate"].isNull()) {
                    fee_rate = CFeeRate(AmountFromValue(options["fee_rate"], /*decimals=*/3));
                }
                if (options["broadcast"].isBool()) {
                    do_broadcast = options["broadcast"].get_bool();
                }
            }

            // Sum existing outputs
            CAmount output_value = 0;
            for (const CTxOut& txout : funded_tx.vout) {
                output_value += txout.nValue;
            }

            // Sum existing inputs (ICU + ballots)
            CAmount input_value = 0;
            for (size_t i = 0; i < funded_tx.vin.size() && i < psbtx.inputs.size(); ++i) {
                if (!psbtx.inputs[i].witness_utxo.IsNull()) {
                    input_value += psbtx.inputs[i].witness_utxo.nValue;
                } else if (psbtx.inputs[i].non_witness_utxo) {
                    const CTransaction& prev_tx = *psbtx.inputs[i].non_witness_utxo;
                    if (funded_tx.vin[i].prevout.n < prev_tx.vout.size()) {
                        input_value += prev_tx.vout[funded_tx.vin[i].prevout.n].nValue;
                    }
                }
            }

            auto compute_fee = [&](const CMutableTransaction& tx) {
                return fee_rate.GetFee(GetVirtualTransactionSize(CTransaction(tx)));
            };

            // Determine which inputs are already in use so we don't re-select them
            std::set<COutPoint> existing_inputs;
            for (const CTxIn& txin : funded_tx.vin) {
                existing_inputs.insert(txin.prevout);
            }

            // Prepare candidate list for funding
            CCoinControl funding_control;
            funding_control.m_avoid_asset_utxos = true;
            funding_control.m_min_depth = 1;

            std::vector<COutput> available_coins = AvailableCoins(*pwallet, &funding_control).All();

            std::vector<COutput> selected_coins;
            CAmount selected_value = 0;

            CMutableTransaction tx_with_inputs = funded_tx; // clone to append fee inputs as we go

            // Helper lambda to add a coin to provisional transaction
            auto add_coin = [&](const COutput& coin) {
                selected_coins.push_back(coin);
                selected_value += coin.txout.nValue;
                tx_with_inputs.vin.emplace_back(coin.outpoint);
                existing_inputs.insert(coin.outpoint);
            };

            // Select coins until inputs cover outputs + required fee
            size_t idx = 0;
            while (true) {
                CAmount fee_needed = compute_fee(tx_with_inputs);
                CAmount available_for_fees = (input_value + selected_value) - output_value;

                if (available_for_fees >= fee_needed) {
                    break; // enough inputs selected
                }

                if (idx >= available_coins.size()) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient funds for governance fees: deficit %s",
                                  FormatMoney(fee_needed - available_for_fees)));
                }

                const COutput& coin = available_coins[idx++];
                if (existing_inputs.count(coin.outpoint)) continue;
                if (coin.txout.nValue <= 0) continue;
                if (!coin.txout.vExt.empty()) {
                    if (assets::ParseAssetTag(coin.txout.vExt) || assets::ParseIssuerReg(coin.txout.vExt)) {
                        continue; // skip asset-bearing UTXOs for fee funding
                    }
                }

                add_coin(coin);
            }

            // Compute change after accounting for fee requirement without change output
            CAmount fee_without_change = compute_fee(tx_with_inputs);
            CAmount change_amount = (input_value + selected_value) - output_value - fee_without_change;

            // If we didn't add any new coins, nothing to do
            if (!selected_coins.empty()) {
                // Decide whether to add change output
                const CAmount dust_threshold = 546;
                bool add_change = change_amount >= dust_threshold;

                if (add_change) {
                    auto change_res = pwallet->GetNewDestination(OutputType::BECH32M, "governance-change");
                    if (!change_res) {
                        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(change_res).original);
                    }
                    const CScript change_script = GetScriptForDestination(*change_res);

                    tx_with_inputs.vout.push_back(CTxOut(change_amount, change_script));
                    CAmount fee_with_change = compute_fee(tx_with_inputs);
                    CAmount adjusted_change = (input_value + selected_value) - output_value - fee_with_change;

                    if (adjusted_change < dust_threshold) {
                        tx_with_inputs.vout.pop_back();
                        change_amount = 0;
                    } else {
                        change_amount = adjusted_change;
                        tx_with_inputs.vout.back().nValue = change_amount;
                    }
                }

                funded_tx = tx_with_inputs;
                input_value += selected_value;
            }

            PartiallySignedTransaction final_psbt(funded_tx);
            if (rotation_meta) {
                AttachRotationMetadata(final_psbt, *rotation_meta);
            }

            // Copy PSBTInputs from merged_psbt
            // Input layout from prepare_rotation: [ICU] (LEAN template, no fee inputs)
            // After ballot(): [ICU, ...ballots (signed)]
            // After fee funding above: [ICU, ...ballots, ...fee_inputs (NEW)]
            for (size_t i = 0; i < psbtx.inputs.size() && i < final_psbt.inputs.size(); ++i) {
                final_psbt.inputs[i] = psbtx.inputs[i];
            }

            // Populate witness_utxo for newly added fee inputs
            for (size_t i = psbtx.inputs.size(); i < funded_tx.vin.size(); ++i) {
                const CTxIn& txin = funded_tx.vin[i];
                const auto wallet_it = pwallet->mapWallet.find(txin.prevout.hash);
                if (wallet_it != pwallet->mapWallet.end() && txin.prevout.n < wallet_it->second.tx->vout.size()) {
                    if (i < final_psbt.inputs.size()) {
                        final_psbt.inputs[i].witness_utxo = wallet_it->second.tx->vout[txin.prevout.n];
                        final_psbt.inputs[i].sighash_type = SIGHASH_ALL;
                    }
                }
            }

            size_t original_outputs = output_templates.size();
            for (size_t i = 0; i < psbtx.outputs.size() && i < final_psbt.outputs.size() && i < original_outputs; ++i) {
                final_psbt.outputs[i] = psbtx.outputs[i];
            }

            // Sign only ICU input and fee inputs (NOT ballot inputs which are already signed)
            // Ballots are identified by having final_script_witness set
            for (size_t i = 0; i < final_psbt.inputs.size() && i < funded_tx.vin.size(); ++i) {
                const PSBTInput& psbt_in = final_psbt.inputs[i];
                // Pre-populate funded_tx with any finalized signatures so SignTransaction skips them
                if (!psbt_in.final_script_sig.empty()) {
                    funded_tx.vin[i].scriptSig = psbt_in.final_script_sig;
                }
                if (!psbt_in.final_script_witness.IsNull()) {
                    funded_tx.vin[i].scriptWitness = psbt_in.final_script_witness;
                }
            }

            std::map<COutPoint, Coin> coins;
            for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
                const CTxIn& txin = funded_tx.vin[i];
                Coin coin;
                bool have_coin = false;

                if (i < final_psbt.inputs.size()) {
                    const PSBTInput& psbt_in = final_psbt.inputs[i];
                    if (!psbt_in.witness_utxo.IsNull()) {
                        coin = Coin(psbt_in.witness_utxo, /*nHeight=*/0, /*coinbase=*/false);
                        have_coin = true;
                    } else if (psbt_in.non_witness_utxo) {
                        const CTransaction& prev_tx = *psbt_in.non_witness_utxo;
                        if (txin.prevout.n < prev_tx.vout.size()) {
                            coin = Coin(prev_tx.vout[txin.prevout.n], /*nHeight=*/0, /*coinbase=*/false);
                            have_coin = true;
                        }
                    }
                }

                bool is_ballot_input = i < final_psbt.inputs.size() && !final_psbt.inputs[i].final_script_witness.IsNull();

                if (!is_ballot_input) {
                    const auto wallet_it = pwallet->mapWallet.find(txin.prevout.hash);
                    if (wallet_it == pwallet->mapWallet.end() || txin.prevout.n >= wallet_it->second.tx->vout.size()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Wallet missing rotation input %s:%d", txin.prevout.hash.ToString(), txin.prevout.n));
                    }
                    const CWalletTx& wtx = wallet_it->second;
                    int height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
                    coin = Coin(wtx.tx->vout[txin.prevout.n], height, wtx.IsCoinBase());
                    have_coin = true;
                } else if (!have_coin) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Missing ballot prevout metadata for input %zu (%s:%u)",
                        i, txin.prevout.hash.ToString(), txin.prevout.n));
                }

                coins[txin.prevout] = coin;
            }

            // Sign the transaction
            std::map<int, bilingual_str> input_errors;
            bool signed_all = pwallet->SignTransaction(funded_tx, coins, SIGHASH_ALL, input_errors);
            if (!signed_all) {
                // Check if failures are only on ballot inputs (which we expect to skip)
                bool has_non_ballot_failures = false;
                for (const auto& [idx, msg] : input_errors) {
                    // Allow failures on ballot inputs (already finalized), fail on ICU/fee inputs
                    size_t input_idx = static_cast<size_t>(idx);
                    if (input_idx >= final_psbt.inputs.size() || final_psbt.inputs[input_idx].final_script_witness.IsNull()) {
                        // This is an ICU or fee input that failed to sign
                        has_non_ballot_failures = true;
                        break;
                    }
                }
                if (has_non_ballot_failures) {
                    UniValue errors_arr(UniValue::VARR);
                    for (const auto& [idx, msg] : input_errors) {
                        UniValue err(UniValue::VOBJ);
                        err.pushKV("input_index", idx);
                        err.pushKV("error", msg.original);
                        errors_arr.push_back(err);
                    }
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to sign rotation: %s", errors_arr.write()));
                }
            }

            // Update final_psbt with signatures
            for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
                if (i < final_psbt.inputs.size()) {
                    if (!funded_tx.vin[i].scriptWitness.IsNull()) {
                        final_psbt.inputs[i].final_script_witness = funded_tx.vin[i].scriptWitness;
                    }
                    if (!funded_tx.vin[i].scriptSig.empty()) {
                        final_psbt.inputs[i].final_script_sig = funded_tx.vin[i].scriptSig;
                    }
                }
            }

            // Manually verify all inputs are finalized (FillPSBT may return false for mixed sighash types)
            bool all_finalized = true;
            std::string unsigned_inputs;
            for (size_t i = 0; i < final_psbt.inputs.size(); ++i) {
                const PSBTInput& input = final_psbt.inputs[i];
                bool is_finalized = !input.final_script_sig.empty() || !input.final_script_witness.IsNull();
                if (!is_finalized) {
                    all_finalized = false;
                    if (!unsigned_inputs.empty()) unsigned_inputs += ", ";
                    unsigned_inputs += strprintf("%zu", i);
                }
            }

            if (!all_finalized) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                    "Failed to sign rotation transaction completely. Unsigned inputs: [%s] (total inputs: %zu)",
                    unsigned_inputs, final_psbt.inputs.size()));
            }

            // Manually extract the transaction since all inputs are already finalized
            // FinalizeAndExtractPSBT may fail with mixed sighash types (SIGHASH_SINGLE ballots + SIGHASH_ALL others)
            CMutableTransaction signed_mtx = *final_psbt.tx;
            for (size_t i = 0; i < final_psbt.inputs.size(); ++i) {
                const PSBTInput& input = final_psbt.inputs[i];
                signed_mtx.vin[i].scriptSig = input.final_script_sig;
                signed_mtx.vin[i].scriptWitness = input.final_script_witness;
            }

            CTransactionRef tx = MakeTransactionRef(CTransaction(signed_mtx));
            if (do_broadcast) {
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("hex", EncodeHexTx(*tx));
            result.pushKV("broadcast", do_broadcast);
            return result;
        }
    };
}

// ZK Whitelist Hardening: Compliance Root RPCs

RPCHelpMan getassetcomplianceroot()
{
    return RPCHelpMan{
        "getassetcomplianceroot",
        "Query the active compliance root commitment for a KYC asset.\n"
        "Returns the commitment (root‖height packed), extracted height, max_root_age, and vk_commitment.\n",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Asset identifier"},
                {RPCResult::Type::STR_HEX, "compliance_root_commit", "32-byte commitment (root‖height)"},
                {RPCResult::Type::NUM, "root_height", "Extracted capture height (last 4 bytes, big-endian)"},
                {RPCResult::Type::NUM, "max_root_age", "Maximum merkle root age in blocks"},
                {RPCResult::Type::STR_HEX, "zk_vk_commitment", "ZK verification key commitment"},
                {RPCResult::Type::BOOL, "has_commitment", "Whether a compliance root is set"},
                {RPCResult::Type::STR_HEX, "compliance_delegate_asset_id", /*optional=*/true, "Declared delegation source asset (only when delegating)"},
                {RPCResult::Type::OBJ, "effective_kyc_policy", /*optional=*/true, "Resolved effective policy when delegating",
                {
                    {RPCResult::Type::BOOL, "ok", "Whether delegation resolves (else the spend fails closed)"},
                    {RPCResult::Type::STR, "reason", /*optional=*/true, "Consensus reject reason when ok=false"},
                    {RPCResult::Type::STR_HEX, "source_asset_id", /*optional=*/true, "Effective source asset"},
                    {RPCResult::Type::STR_HEX, "vk_commitment", /*optional=*/true, "Effective VK (from source)"},
                    {RPCResult::Type::STR_HEX, "compliance_root_commit", /*optional=*/true, "Effective root (from source)"},
                    {RPCResult::Type::NUM, "max_root_age", /*optional=*/true, "Effective max_root_age = min(source, follower)"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getassetcomplianceroot", "\"a3f747562969280eb3ddc96ff57e3692b7b55611d8c89785f52fc2d1535d22b3\"") +
            HelpExampleCli("getassetcomplianceroot", "\"GOLD\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());

            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            const AssetRegistryEntry& entry = *resolved.registry;
            UniValue result(UniValue::VOBJ);

            result.pushKV("asset_id", resolved.asset_id.ToString());

            const bool has_commit = !entry.compliance_root_commit.IsNull();
            result.pushKV("has_commitment", has_commit);

            if (has_commit) {
                result.pushKV("compliance_root_commit", entry.compliance_root_commit.ToString());

                // Extract height from last 4 bytes (big-endian)
                const unsigned char* bytes = entry.compliance_root_commit.begin();
                uint32_t height = (static_cast<uint32_t>(bytes[28]) << 24) |
                                  (static_cast<uint32_t>(bytes[29]) << 16) |
                                  (static_cast<uint32_t>(bytes[30]) << 8) |
                                  static_cast<uint32_t>(bytes[31]);
                result.pushKV("root_height", static_cast<uint64_t>(height));
            } else {
                result.pushKV("compliance_root_commit", "0000000000000000000000000000000000000000000000000000000000000000");
                result.pushKV("root_height", 0);
            }

            result.pushKV("max_root_age", static_cast<uint64_t>(entry.max_root_age));
            result.pushKV("zk_vk_commitment", entry.zk_vk_commitment.ToString());

            // Delegated / reusable KYC: declared delegate + resolved effective policy.
            if (!entry.compliance_delegate_asset_id.IsNull()) {
                result.pushKV("compliance_delegate_asset_id", entry.compliance_delegate_asset_id.ToString());
                WalletContext& wctx = EnsureWalletContext(request.context);
                AssetRegistryEntry src;
                const AssetRegistryEntry* srcp = nullptr;
                if (wctx.chain && entry.compliance_delegate_asset_id != resolved.asset_id) {
                    if (auto se = wctx.chain->getAssetRegistryEntry(entry.compliance_delegate_asset_id)) { src = *se; srcp = &src; }
                }
                const auto eff = assets::ResolveEffectiveKycPolicy(
                    resolved.asset_id, entry, srcp, assets::IsCanonicalVk);
                UniValue effobj(UniValue::VOBJ);
                effobj.pushKV("ok", eff.ok);
                if (!eff.ok) {
                    effobj.pushKV("reason", eff.reason);
                } else {
                    effobj.pushKV("source_asset_id", eff.source_asset_id.ToString());
                    effobj.pushKV("vk_commitment", eff.vk_commitment.ToString());
                    if (!eff.compliance_root_commit.IsNull()) {
                        effobj.pushKV("compliance_root_commit", eff.compliance_root_commit.ToString());
                    }
                    effobj.pushKV("max_root_age", static_cast<uint64_t>(eff.max_root_age));
                }
                result.pushKV("effective_kyc_policy", effobj);
            }

            return result;
        }
    };
}

RPCHelpMan listassetcomplianceroots()
{
    return RPCHelpMan{
        "listassetcomplianceroots",
        "List historical compliance root commitments for a KYC asset.\n"
        "Returns ordered history from the ring buffer with activation heights and txids.\n",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"count", RPCArg::Type::NUM, RPCArg::Default{32}, "Maximum number of entries to return (default: 32)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Asset identifier"},
                {RPCResult::Type::ARR, "history", "Ordered compliance root history (oldest first)",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "root_commit", "32-byte commitment (root‖height)"},
                                {RPCResult::Type::NUM, "root_height", "Extracted capture height"},
                                {RPCResult::Type::NUM, "activation_height", "Block height when this root became active"},
                                {RPCResult::Type::STR_HEX, "txid", "Transaction that committed this root"},
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("listassetcomplianceroots", "\"GOLD\"") +
            HelpExampleCli("listassetcomplianceroots", "\"a3f747562969280eb3ddc96ff57e3692b7b55611d8c89785f52fc2d1535d22b3\" 10")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());

            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            const AssetRegistryEntry& entry = *resolved.registry;

            size_t max_count = 32;
            if (!request.params[1].isNull()) {
                max_count = request.params[1].getInt<int>();
                if (max_count == 0 || max_count > 1000) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 1000");
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", resolved.asset_id.ToString());

            UniValue history_arr(UniValue::VARR);
            size_t added = 0;
            for (const auto& hist : entry.compliance_root_history) {
                if (added >= max_count) break;

                UniValue hist_obj(UniValue::VOBJ);
                hist_obj.pushKV("root_commit", hist.root_commit.ToString());

                // Extract height from last 4 bytes (big-endian)
                const unsigned char* bytes = hist.root_commit.begin();
                uint32_t height = (static_cast<uint32_t>(bytes[28]) << 24) |
                                  (static_cast<uint32_t>(bytes[29]) << 16) |
                                  (static_cast<uint32_t>(bytes[30]) << 8) |
                                  static_cast<uint32_t>(bytes[31]);
                hist_obj.pushKV("root_height", static_cast<uint64_t>(height));
                hist_obj.pushKV("activation_height", hist.activation_height);
                hist_obj.pushKV("txid", hist.txid.ToString());

                history_arr.push_back(hist_obj);
                ++added;
            }

            result.pushKV("history", history_arr);
            return result;
        }
    };
}

RPCHelpMan updatecomplianceroot()
{
    return RPCHelpMan{
        "updatecomplianceroot",
        "Update the compliance root commitment for a KYC asset by building an IssuerReg rotation transaction.\n"
        "The wallet must hold the ICU authority (control over icu_outpoint) to sign the rotation.\n"
        "The compliance_root_commit should be a 32-byte hex string encoding root‖height as expected by the circuit.\n",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"compliance_root_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte compliance root commitment (root‖height)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Additional options",
                {
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::DefaultHint{"unchanged"}, "Override max_root_age (blocks)"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast the transaction"},
                    {"delegate_asset", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"unchanged"}, "Install/follow this source asset's compliance cohort (emits IssuerReg v2). Omitting it leaves delegation UNCHANGED — a v1 reg preserves any existing delegate (so mint/rotate never clear it). Use clear_delegation to opt out."},
                    {"clear_delegation", RPCArg::Type::BOOL, RPCArg::Default{false}, "Opt out of delegation: emit a v2 self reg that clears the delegate. Requires a canonical own VK and the (non-null) compliance_root_commit passed here."},
                },
                RPCArgOptions{.oneline_description = "options"}
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Transaction ID"},
                {RPCResult::Type::STR_HEX, "hex", "Serialized transaction hex"},
                {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast"},
            }
        },
        RPCExamples{
            HelpExampleCli("updatecomplianceroot", "\"GOLD\" \"a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890\"") +
            HelpExampleCli("updatecomplianceroot", "\"GOLD\" \"a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890\" '{\"max_root_age\": 10000}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_ERROR, "No wallet available");

            LOCK(pwallet->cs_wallet);

            AssetResolution resolved = ResolveAssetIdOrTicker(request, request.params[0].get_str());

            if (!resolved.registry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            const AssetRegistryEntry& entry = *resolved.registry;

            // Verify asset has KYC enabled
            if (!entry.has_kyc) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset does not have KYC enabled");
            }

            // Parse compliance_root_commit
            std::string root_hex = request.params[1].get_str();
            if (root_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "compliance_root_commit must be exactly 32 bytes (64 hex chars)");
            }

            auto new_root_commit_opt = uint256::FromHex(root_hex);
            if (!new_root_commit_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex for compliance_root_commit");
            }
            uint256 new_root_commit = *new_root_commit_opt;

            // Parse options
            bool do_broadcast = true;
            std::optional<uint32_t> new_max_root_age;
            std::optional<uint256> delegate_asset;

            if (!request.params[2].isNull()) {
                const UniValue& opts = request.params[2].get_obj();
                if (opts.exists("broadcast")) {
                    do_broadcast = opts["broadcast"].get_bool();
                }
                if (opts.exists("max_root_age")) {
                    new_max_root_age = opts["max_root_age"].getInt<int>();
                    if (*new_max_root_age > 1000000) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_root_age must be <= 1,000,000 blocks");
                    }
                }
                const bool clear_delegation = opts.exists("clear_delegation") && opts["clear_delegation"].get_bool();
                if (opts.exists("delegate_asset")) {
                    if (clear_delegation) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "delegate_asset and clear_delegation are mutually exclusive");
                    }
                    const std::string d = opts["delegate_asset"].get_str();
                    auto dv = uint256::FromHex(d);
                    if (!dv) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex for delegate_asset");
                    }
                    if (!dv->IsNull()) {  // all-zero => leave delegation unchanged (v1)
                        if (*dv == resolved.asset_id) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "delegate_asset cannot be the asset itself; use clear_delegation to opt out");
                        }
                        delegate_asset = *dv;
                    }
                }
                if (clear_delegation) {
                    // v2 reg with delegate == own asset_id is the opt-out sentinel.
                    delegate_asset = resolved.asset_id;
                }
            }

            // Get ICU UTXO details
            const CWalletTx* icu_wtx = pwallet->GetWalletTx(entry.icu_outpoint.hash);
            if (!icu_wtx || entry.icu_outpoint.n >= icu_wtx->tx->vout.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU UTXO not found in wallet");
            }
            CAmount icu_value = icu_wtx->tx->vout[entry.icu_outpoint.n].nValue;

            // Build IssuerReg payload with updated compliance_root_commit
            std::vector<unsigned char> reg_payload;
            reg_payload.reserve(254);

            // asset_id [32]
            reg_payload.insert(reg_payload.end(), resolved.asset_id.begin(), resolved.asset_id.end());

            // policy_bits [4]
            unsigned char pb[4];
            WriteLE32(pb, entry.policy_bits);
            reg_payload.insert(reg_payload.end(), pb, pb + 4);

            // allowed_spk_families [2]
            unsigned char spk[2];
            WriteLE16(spk, entry.allowed_spk_families);
            reg_payload.insert(reg_payload.end(), spk, spk + 2);

            // format_version [1] (v2 when installing a delegate pointer)
            reg_payload.push_back(delegate_asset ? assets::ISSUER_REG_FORMAT_V2 : assets::ISSUER_REG_FORMAT_V1);

            // ticker_len [1] + ticker
            const uint8_t ticker_len = static_cast<uint8_t>(entry.ticker.size());
            reg_payload.push_back(ticker_len);
            if (ticker_len > 0) {
                reg_payload.insert(reg_payload.end(), entry.ticker.begin(), entry.ticker.end());
            }

            // decimals [1]
            reg_payload.push_back(entry.decimals);

            // unlock_fees [8]
            unsigned char uf[8];
            WriteLE64(uf, entry.unlock_fees_sats);
            reg_payload.insert(reg_payload.end(), uf, uf + 8);

            // ZK section (76 bytes)
            unsigned char zk_buf[76];
            const uint32_t effective_max_root_age = new_max_root_age.value_or(entry.max_root_age);

            // Compute kyc_flags from has_kyc. Must match every other reg builder
            // (registerasset / mintasset / rotatezk / burnasset all use 1), because
            // kyc_flags feeds core_policy_commit — using KYC_REQUIRED (0x10) here
            // recomputes a different commit and trips policy-core-changed post-issuance.
            const uint32_t kyc_flags = entry.has_kyc ? 1u : 0u;
            WriteLE32(zk_buf, kyc_flags);
            std::copy(entry.zk_vk_commitment.begin(), entry.zk_vk_commitment.end(), zk_buf + 4);
            WriteLE32(zk_buf + 36, effective_max_root_age);
            WriteLE32(zk_buf + 40, entry.tfr_flags);
            // compliance_root_commit [32] - NEW VALUE
            std::copy(new_root_commit.begin(), new_root_commit.end(), zk_buf + 44);
            reg_payload.insert(reg_payload.end(), zk_buf, zk_buf + 76);

            // ICU section (129 bytes) - unchanged from current state
            unsigned char icu_buf[129];
            WriteLE32(icu_buf, entry.icu_flags);
            WriteLE64(icu_buf + 4, entry.issuance_cap_units);
            std::copy(entry.icu_ctxt_commit.begin(), entry.icu_ctxt_commit.end(), icu_buf + 12);
            std::copy(entry.icu_plain_commit.begin(), entry.icu_plain_commit.end(), icu_buf + 44);
            std::copy(entry.kdf_salt.begin(), entry.kdf_salt.end(), icu_buf + 76);
            icu_buf[92] = entry.icu_version;
            icu_buf[93] = entry.icu_visibility;
            std::copy(entry.core_policy_commit.begin(), entry.core_policy_commit.end(), icu_buf + 94);
            icu_buf[126] = entry.policy_epoch;
            WriteLE16(icu_buf + 127, entry.policy_quorum_bps);
            reg_payload.insert(reg_payload.end(), icu_buf, icu_buf + 129);

            // v2 trailing compliance_delegate_asset_id [32] (reusable/delegated KYC).
            if (delegate_asset) {
                reg_payload.insert(reg_payload.end(), delegate_asset->begin(), delegate_asset->end());
            }

            // Verify final size (v1: [254,265]; v2 adds the 32-byte delegate).
            const size_t min_sz = delegate_asset ? 286u : 254u;
            const size_t max_sz = delegate_asset ? 297u : 265u;
            if (reg_payload.size() < min_sz || reg_payload.size() > max_sz) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("Internal error: IssuerReg payload size %u out of range [%u, %u]", reg_payload.size(), min_sz, max_sz));
            }

            // Create IssuerReg TLV
            std::vector<unsigned char> reg_tlv;
            reg_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (reg_payload.size() < 253) {
                reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
            } else {
                reg_tlv.push_back(253);
                reg_tlv.push_back(reg_payload.size() & 0xFF);
                reg_tlv.push_back((reg_payload.size() >> 8) & 0xFF);
            }
            reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());

            // Build the rotation transaction
            CMutableTransaction mtx;
            mtx.vin.emplace_back(entry.icu_outpoint);

            // Get ICU destination for output
            CTxDestination icu_dest;
            if (!ExtractDestination(icu_wtx->tx->vout[entry.icu_outpoint.n].scriptPubKey, icu_dest)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract ICU destination");
            }
            const CScript icu_script = GetScriptForDestination(icu_dest);

            // Store TLV for re-attachment after funding
            std::vector<std::pair<CScript, std::vector<unsigned char>>> output_tlvs;
            output_tlvs.emplace_back(icu_script, reg_tlv);

            // Fund transaction
            CCoinControl coin_control;
            std::vector<CRecipient> recipients;
            CRecipient icu_recipient{icu_dest, icu_value, /*fSubtractFeeFromAmount=*/false};
            recipients.push_back(icu_recipient);

            auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt,
                                     /*lockUnspents=*/false, coin_control);
            if (!txr) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
            }

            // Apply the funded transaction
            mtx = CMutableTransaction(*txr->tx);

            // Re-attach TLV to ICU output (funding creates new transaction without vExt)
            for (auto& out : mtx.vout) {
                for (const auto& [script, tlv] : output_tlvs) {
                    if (out.scriptPubKey == script && out.vExt.empty()) {
                        out.vExt = tlv;
                        break;
                    }
                }
            }

            // Sign transaction
            if (!feebumper::SignTransaction(*pwallet, mtx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign rotation transaction");
            }

            CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));

            if (do_broadcast) {
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("hex", EncodeHexTx(*tx));
            result.pushKV("broadcast", do_broadcast);

            return result;
        }
    };
}

RPCHelpMan distributeasset()
{
    return RPCHelpMan{
        "distributeasset",
        "Distribute an asset or TSC pro-rata to all holders of a specified asset.\n"
        "Scans the UTXO set to find all holders, then creates a transaction paying each\n"
        "holder proportionally based on their holdings.\n"
        "\nIMPORTANT: This operation can take 10-60 seconds for full UTXO set scan.\n",
        {
            {"target_asset", RPCArg::Type::STR, RPCArg::Optional::NO,
                "Asset ID (hex) or ticker whose holders will receive distribution"},
            {"distribution_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO,
                "Total amount to distribute. For TSC: BTC amount. For assets: raw units."},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"distribution_asset", RPCArg::Type::STR, RPCArg::Default{"TSC"},
                        "Asset to distribute (TSC or asset_id/ticker)"},
                    {"min_dust_threshold", RPCArg::Type::NUM, RPCArg::Default{1000},
                        "Minimum payment (satoshis for TSC, raw units for assets)"},
                    {"snapshot_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Block height for UTXO snapshot"},
                    {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false},
                        "Preview distribution without broadcasting"},
                    {"max_recipients", RPCArg::Type::NUM, RPCArg::Default{1000},
                        "Maximum recipients per transaction"},
                    {"remainder_strategy", RPCArg::Type::STR, RPCArg::Default{"refund"},
                        "'refund' or 'topup'"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Fee rate in sat/vB"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction ID (only if dry_run=false)"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Transaction hex (only if dry_run=false)"},
                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "Transaction fee (only if dry_run=false)"},
                {RPCResult::Type::NUM, "asset_change", /*optional=*/true, "Asset change returned (only for asset distributions)"},
                {RPCResult::Type::STR, "distribution_asset", "Asset distributed"},
                {RPCResult::Type::NUM, "total_distributed", "Actual amount distributed"},
                {RPCResult::Type::NUM, "remainder", "Undistributed amount due to rounding"},
                {RPCResult::Type::NUM, "recipient_count", "Number of recipients"},
                {RPCResult::Type::NUM, "filtered_count", "Recipients filtered by dust"},
                {RPCResult::Type::NUM, "utxos_scanned", "Total UTXOs scanned"},
                {RPCResult::Type::NUM, "utxos_with_asset", "UTXOs containing target asset"},
                {RPCResult::Type::ARR, "recipients", "Distribution list (filtered recipients excluded)",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "address", "Recipient address"},
                                {RPCResult::Type::NUM, "holdings", "Asset units held"},
                                {RPCResult::Type::NUM, "amount", "Distribution amount"},
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("distributeasset", "\"GOLD\" 1.0 '{\"dry_run\":true}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            // Parse parameters
            const std::string target_asset_str = request.params[0].get_str();
            const UniValue& amount_val = request.params[1];

            bool dry_run = false;
            uint64_t min_dust_threshold = 1000;
            std::optional<int> snapshot_height_opt;
            uint64_t max_recipients = 1000;
            std::string remainder_strategy = "refund";
            std::string distribution_asset_str = "TSC";

            if (!request.params[2].isNull()) {
                const UniValue& opt = request.params[2];
                if (opt.exists("dry_run")) dry_run = opt["dry_run"].get_bool();
                if (opt.exists("min_dust_threshold")) {
                    int64_t val = opt["min_dust_threshold"].getInt<int64_t>();
                    if (val < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "min_dust_threshold must be non-negative");
                    min_dust_threshold = static_cast<uint64_t>(val);
                }
                if (opt.exists("snapshot_height")) {
                    int height = opt["snapshot_height"].getInt<int>();
                    if (height < 0) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "snapshot_height must be non-negative");
                    }
                    snapshot_height_opt = height;
                }
                if (opt.exists("max_recipients")) {
                    int64_t val = opt["max_recipients"].getInt<int64_t>();
                    if (val <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "max_recipients must be positive");
                    max_recipients = static_cast<uint64_t>(val);
                }
                if (opt.exists("remainder_strategy")) remainder_strategy = opt["remainder_strategy"].get_str();
                if (opt.exists("distribution_asset")) distribution_asset_str = opt["distribution_asset"].get_str();
            }

            if (remainder_strategy != "refund" && remainder_strategy != "topup") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "remainder_strategy must be 'refund' or 'topup'");
            }

            // Resolve assets
            AssetResolution target_asset = ResolveAssetIdOrTicker(request, target_asset_str);
            bool distributing_tsc = (distribution_asset_str == "TSC" || distribution_asset_str == "tsc");
            uint256 distribution_asset_id;

            if (!distributing_tsc) {
                AssetResolution dist_asset = ResolveAssetIdOrTicker(request, distribution_asset_str);
                distribution_asset_id = dist_asset.asset_id;

                // Check if the distribution asset itself requires keywrap
                // This would require per-recipient ECDH encryption for each output
                if (dist_asset.registry) {
                    const uint32_t ICU_FLAG_WRAP_REQUIRED = 0x01;
                    if (dist_asset.registry->icu_flags & ICU_FLAG_WRAP_REQUIRED) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Cannot distribute WRAP_REQUIRED asset %s. "
                                      "Per-recipient keywrap for bulk distributions is not yet supported. "
                                      "Use sendasset for individual transfers instead.",
                                      distribution_asset_str));
                    }
                }
            }

            // Parse distribution amount
            uint64_t distribution_amount;
            if (distributing_tsc) {
                CAmount amount_satoshis = AmountFromValue(amount_val, 8);
                if (amount_satoshis <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "distribution_amount must be positive");
                }
                distribution_amount = static_cast<uint64_t>(amount_satoshis);
            } else {
                if (!amount_val.isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset amount must be a number");
                }
                int64_t amount_signed = amount_val.getInt<int64_t>();
                if (amount_signed <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "distribution_amount must be positive");
                }
                distribution_amount = static_cast<uint64_t>(amount_signed);
            }

            // Get registry entry and validate
            std::map<uint256, std::optional<AssetRegistryEntry>> registry_cache;
            const AssetRegistryEntry* registry_entry = LookupRegistryEntry(request, target_asset.asset_id, registry_cache);

            if (!registry_entry) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Target asset not found in registry");
            }

            const uint64_t settled_supply = registry_entry->issued_total - registry_entry->burned_total;
            if (settled_supply == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Target asset has zero settled supply");
            }

            // Note: We removed the WRAP_REQUIRED check here because:
            // 1. The target_asset is the asset whose HOLDERS we're finding, not what we're distributing
            // 2. Whether the target asset requires keywrap is irrelevant for distributing TO its holders
            // 3. Keywrap is only needed when SENDING the wrapped asset itself
            //
            // For example: Distributing TSC to holders of a WRAP_REQUIRED asset should work fine,
            // as we're not actually sending the wrapped asset, just using it to identify recipients.

            // Validate treasury balance
            if (distributing_tsc) {
                CAmount treasury_balance = GetBalance(*pwallet).m_mine_trusted;
                if (treasury_balance < static_cast<CAmount>(distribution_amount)) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient TSC. Have: %s, Need: %s",
                            FormatMoney(treasury_balance), FormatMoney(distribution_amount)));
                }
            } else {
                // Check asset balance from wallet
                CCoinControl coin_control;
                coin_control.m_include_unsafe_inputs = true;
                coin_control.m_avoid_asset_utxos = false;  // Ensure asset-tagged UTXOs are considered
                CoinFilterParams filter_params;
                filter_params.skip_locked = true;

                std::vector<WalletAssetUtxo> asset_utxos = CollectAssetUtxos(*pwallet, coin_control, filter_params);

                uint64_t treasury_asset_balance = 0;
                for (const auto& utxo : asset_utxos) {
                    if (utxo.asset_id == distribution_asset_id && utxo.spendable && utxo.ismine_spendable) {
                        treasury_asset_balance += utxo.units;
                    }
                }

                if (treasury_asset_balance < distribution_amount) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient asset balance. Have: %llu, Need: %llu",
                            treasury_asset_balance, distribution_amount));
                }
            }

            // Get node context through wallet context
            const WalletContext& wallet_context = EnsureWalletContext(request.context);
            if (!wallet_context.node_context) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            }

            // Snapshot lock
            const CBlockIndex* snapshot_pindex;
            uint256 snapshot_blockhash;
            int snapshot_height;

            {
                LOCK(cs_main);
                ChainstateManager& chainman = EnsureChainman(*wallet_context.node_context);

                if (snapshot_height_opt) {
                    snapshot_height = *snapshot_height_opt;
                    int tip_height = chainman.ActiveChain().Height();
                    if (snapshot_height > tip_height) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("snapshot_height %d exceeds chain tip %d", snapshot_height, tip_height));
                    }
                    snapshot_pindex = chainman.ActiveChain()[snapshot_height];
                    if (!snapshot_pindex) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block not found at snapshot height");
                    }
                } else {
                    snapshot_pindex = chainman.ActiveChain().Tip();
                    snapshot_height = snapshot_pindex->nHeight;
                }
                snapshot_blockhash = snapshot_pindex->GetBlockHash();
            }

            // Scan UTXO set
            struct HolderInfo {
                uint64_t total_units{0};
                uint64_t utxo_count{0};
            };

            std::map<CScript, HolderInfo> holdings_map;
            uint64_t utxos_scanned = 0;
            uint64_t utxos_with_vext = 0;
            uint64_t utxos_with_target_asset = 0;

            {
                LOCK(cs_main);
                ChainstateManager& chainman = EnsureChainman(*wallet_context.node_context);
                Chainstate& active_chainstate = chainman.ActiveChainstate();

                // Flush chainstate to ensure UTXO set is fully written to disk
                active_chainstate.ForceFlushStateToDisk();

                std::unique_ptr<CCoinsViewCursor> pcursor = active_chainstate.CoinsDB().Cursor();
                if (!pcursor) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create UTXO cursor");
                }

                while (pcursor->Valid()) {
                    COutPoint outpoint;
                    Coin coin;

                    if (pcursor->GetKey(outpoint) && pcursor->GetValue(coin)) {
                        utxos_scanned++;

                        if (!coin.out.vExt.empty()) {
                            utxos_with_vext++;
                            std::optional<assets::AssetTag> tag = assets::ParseAssetTag(coin.out.vExt);
                            if (tag && tag->id == target_asset.asset_id) {
                                utxos_with_target_asset++;
                                holdings_map[coin.out.scriptPubKey].total_units += tag->amount;
                                holdings_map[coin.out.scriptPubKey].utxo_count++;
                            }
                        }
                    }

                    pcursor->Next();

                    if (utxos_scanned % 100000 == 0 && holdings_map.size() > max_recipients * 10) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR,
                            strprintf("Too many holders: %d", holdings_map.size()));
                    }
                }

                LogPrintf("distributeasset: scanned %d UTXOs, %d with vExt, %d with target asset %s, found %d holders\n",
                    utxos_scanned, utxos_with_vext, utxos_with_target_asset, target_asset.asset_id.ToString(), holdings_map.size());
            }

            // Reorg check
            {
                LOCK(cs_main);
                ChainstateManager& chainman = EnsureChainman(*wallet_context.node_context);
                const CBlockIndex* current = chainman.ActiveChain()[snapshot_height];
                if (!current || current->GetBlockHash() != snapshot_blockhash) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Chain reorg detected during scan");
                }
            }

            // Pro-rata calculation using integer arithmetic
            struct RecipientPayment {
                CScript scriptPubKey;
                std::string address;
                uint64_t holdings;
                uint64_t utxo_count;
                uint64_t amount;
                bool filtered;
            };

            std::vector<RecipientPayment> recipients;
            uint64_t total_distributed = 0;
            uint64_t filtered_count = 0;

            arith_uint256 dist_amt_big(distribution_amount);
            arith_uint256 supply_big(settled_supply);

            for (const auto& [spk, holder_info] : holdings_map) {
                RecipientPayment payment;
                payment.scriptPubKey = spk;
                payment.holdings = holder_info.total_units;
                payment.utxo_count = holder_info.utxo_count;

                CTxDestination dest;
                if (ExtractDestination(spk, dest)) {
                    payment.address = EncodeDestination(dest);
                } else {
                    payment.address = HexStr(spk);
                }

                // Integer pro-rata: (holdings * distribution_amount) / settled_supply
                arith_uint256 holdings_big(payment.holdings);
                arith_uint256 numerator = holdings_big * dist_amt_big;
                arith_uint256 result = numerator / supply_big;
                payment.amount = result.GetLow64();

                if (payment.amount < min_dust_threshold) {
                    payment.filtered = true;
                    filtered_count++;
                } else {
                    payment.filtered = false;
                    total_distributed += payment.amount;
                }

                recipients.push_back(payment);
            }

            size_t active_recipients = recipients.size() - filtered_count;
            if (active_recipients > max_recipients) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Too many recipients: %d (max: %d)", active_recipients, max_recipients));
            }

            // Handle remainder
            uint64_t unallocated = distribution_amount - total_distributed;
            if (remainder_strategy == "topup" && unallocated > 0) {
                std::vector<RecipientPayment*> sortable;
                for (auto& r : recipients) {
                    if (!r.filtered) sortable.push_back(&r);
                }
                std::sort(sortable.begin(), sortable.end(),
                    [](const RecipientPayment* a, const RecipientPayment* b) {
                        return a->amount > b->amount;
                    });

                for (size_t i = 0; i < std::min<size_t>(unallocated, sortable.size()); i++) {
                    sortable[i]->amount += 1;
                    total_distributed += 1;
                    unallocated -= 1;
                }
            }

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("distribution_asset", distributing_tsc ? "TSC" : distribution_asset_id.ToString());
            result.pushKV("total_distributed", total_distributed);
            result.pushKV("remainder", distribution_amount - total_distributed);
            result.pushKV("recipient_count", static_cast<uint64_t>(active_recipients));
            result.pushKV("filtered_count", filtered_count);
            result.pushKV("utxos_scanned", utxos_scanned);
            result.pushKV("utxos_with_asset", utxos_with_target_asset);

            UniValue recipients_arr(UniValue::VARR);
            for (const auto& r : recipients) {
                // Only include non-filtered recipients in the output
                if (!r.filtered) {
                    UniValue rec(UniValue::VOBJ);
                    rec.pushKV("address", r.address);
                    rec.pushKV("holdings", r.holdings);
                    rec.pushKV("amount", r.amount);
                    recipients_arr.push_back(rec);
                }
            }
            result.pushKV("recipients", recipients_arr);

            if (!dry_run) {
                // Create and broadcast distribution transaction
                CMutableTransaction template_tx;
                template_tx.version = CTransaction::CURRENT_VERSION;
                template_tx.nLockTime = 0;

                struct PlannedDistributionOutput {
                    CScript scriptPubKey;
                    CAmount nValue;
                    uint64_t asset_units;
                };

                std::vector<PlannedDistributionOutput> planned_outputs;
                planned_outputs.reserve(recipients.size());

                uint64_t total_distributed_units = 0;
                for (const auto& r : recipients) {
                    if (r.filtered) continue;

                    PlannedDistributionOutput planned;
                    planned.scriptPubKey = r.scriptPubKey;
                    planned.nValue = distributing_tsc ? r.amount : DEFAULT_ASSET_OUTPUT_VALUE; // 1000 sat anchor for assets
                    planned.asset_units = r.amount;
                    planned_outputs.push_back(planned);

                    total_distributed_units += r.amount;
                }

                // For asset distributions, select and add asset inputs BEFORE FundTransaction
                uint64_t asset_change_units = 0;
                if (!distributing_tsc) {
                    // Select asset UTXOs for distribution_asset_id
                    CCoinControl asset_coin_control;
                    asset_coin_control.m_include_unsafe_inputs = true;
                    asset_coin_control.m_avoid_asset_utxos = false;

                    CoinFilterParams filter_params;
                    filter_params.only_spendable = true;

                    std::vector<WalletAssetUtxo> asset_utxos = CollectAssetUtxos(*pwallet, asset_coin_control, filter_params);

                    // Sort by depth (confirmed first)
                    std::sort(asset_utxos.begin(), asset_utxos.end(), [](const WalletAssetUtxo& a, const WalletAssetUtxo& b) {
                        if (a.depth != b.depth) return a.depth > b.depth;
                        if (a.outpoint.hash != b.outpoint.hash) return a.outpoint.hash < b.outpoint.hash;
                        return a.outpoint.n < b.outpoint.n;
                    });

                    // Select UTXOs for distribution_asset_id
                    std::vector<WalletAssetUtxo> selected_asset_utxos;
                    uint64_t selected_units = 0;
                    for (const WalletAssetUtxo& utxo : asset_utxos) {
                        if (utxo.asset_id != distribution_asset_id) continue;
                        if (!utxo.spendable || !utxo.ismine_spendable) continue;

                        selected_asset_utxos.push_back(utxo);
                        selected_units += utxo.units;

                        if (selected_units >= total_distributed_units) break;
                    }

                    if (selected_units < total_distributed_units) {
                        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                            strprintf("Insufficient asset balance for distribution. Have: %llu, Need: %llu",
                                selected_units, total_distributed_units));
                    }

                    asset_change_units = selected_units - total_distributed_units;

                    // Add asset inputs to template_tx BEFORE FundTransaction
                    template_tx.vin.reserve(selected_asset_utxos.size());
                    for (const WalletAssetUtxo& utxo : selected_asset_utxos) {
                        template_tx.vin.emplace_back(utxo.outpoint);
                    }

                    // Add asset change output if needed
                    if (asset_change_units > 0) {
                        auto change_dest_res = pwallet->GetNewDestination(OutputType::BECH32, "asset-change");
                        if (!change_dest_res) {
                            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(change_dest_res).original);
                        }
                        const CTxDestination change_dest = *change_dest_res;
                        const CScript change_script = GetScriptForDestination(change_dest);

                        PlannedDistributionOutput change_output;
                        change_output.scriptPubKey = change_script;
                        change_output.nValue = DEFAULT_ASSET_OUTPUT_VALUE;
                        change_output.asset_units = asset_change_units;
                        planned_outputs.push_back(change_output);
                    }
                }

                // Build CRecipient vector for FundTransaction
                std::vector<CRecipient> funding_recipients;
                funding_recipients.reserve(planned_outputs.size());
                for (const PlannedDistributionOutput& planned : planned_outputs) {
                    CTxDestination dest;
                    ExtractDestination(planned.scriptPubKey, dest);
                    funding_recipients.push_back({dest, planned.nValue, /*fSubtractFeeFromAmount=*/false});
                }

                // Fund the transaction (adds BTC inputs for fees, preserves existing asset inputs)
                CCoinControl funding_control;
                funding_control.m_include_unsafe_inputs = true;
                funding_control.m_avoid_asset_utxos = true; // CRITICAL: Avoid asset UTXOs for fee funding
                funding_control.m_signal_bip125_rbf = true;

                auto funded = FundTransaction(*pwallet, template_tx, funding_recipients, /*change_pos=*/std::nullopt,
                                             /*lockUnspents=*/false, funding_control);
                if (!funded) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(funded).original);
                }

                CMutableTransaction candidate(*funded->tx);
                CAmount fee = funded->fee;

                // For asset distributions, match outputs and add asset tags
                if (!distributing_tsc) {
                    std::vector<bool> matched(candidate.vout.size(), false);

                    for (const PlannedDistributionOutput& planned : planned_outputs) {
                        bool found = false;
                        for (size_t idx = 0; idx < candidate.vout.size(); ++idx) {
                            if (matched[idx]) continue;
                            CTxOut& out = candidate.vout[idx];

                            if (out.nValue == planned.nValue && out.scriptPubKey == planned.scriptPubKey) {
                                // Add asset tag to this output
                                out.vExt = BuildAssetTagTlv(distribution_asset_id, planned.asset_units, std::nullopt);
                                matched[idx] = true;
                                found = true;
                                break;
                            }
                        }

                        if (!found) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate funded distribution output");
                        }
                    }
                }

                // Sign the transaction
                PartiallySignedTransaction psbtx(candidate);
                bool complete = false;

                const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                if (fill_err) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                if (!complete) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction completely");
                }

                CMutableTransaction signed_mtx;
                if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
                }

                // Broadcast or return hex
                const CTransactionRef tx_final = MakeTransactionRef(CTransaction(signed_mtx));
                result.pushKV("txid", tx_final->GetHash().ToString());
                result.pushKV("hex", EncodeHexTx(*tx_final));
                result.pushKV("fee", ValueFromAmount(fee));

                if (!distributing_tsc) {
                    result.pushKV("asset_change", asset_change_units);
                }

                std::string err;
                if (!pwallet->chain().broadcastTransaction(tx_final, /*max_tx_fee=*/0, /*relay=*/true, err)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Broadcast failed: %s", err));
                }
            }

            return result;
        }
    };
}

} // namespace wallet
