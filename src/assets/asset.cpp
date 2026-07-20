#include <assets/asset.h>
#include <assets/icu_payload.h>
#include <arith_uint256.h>        // DecodeScalarValue out-param
#include <consensus/scalar_cfd.h> // DecodeScalarValue (publication canonicality)
#include <serialize.h>
#include <logging.h>
#include <hash.h>
#include <crypto/common.h> // WriteLE64
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>

namespace assets {

// --- Ticker grammar helpers (ICU_CHILD.md §3.1, §5.1) ---

bool IsRootTicker(std::string_view t)
{
    if (t.size() < 3 || t.size() > 11) return false;
    auto is_letter = [](char c) { return c >= 'A' && c <= 'Z'; };
    auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    if (!is_letter(t[0])) return false;
    for (char c : t) {
        if (!(is_letter(c) || is_digit(c))) return false;
    }
    return true;
}

std::optional<ChildTicker> ParseChildTicker(std::string_view t)
{
    const size_t dot = t.find('.');
    if (dot == std::string_view::npos) return std::nullopt;
    // No second dot: only one child level is permitted.
    if (t.find('.', dot + 1) != std::string_view::npos) return std::nullopt;
    const std::string_view root = t.substr(0, dot);
    const std::string_view suffix = t.substr(dot + 1);
    if (!IsRootTicker(root) || !IsRootTicker(suffix)) return std::nullopt;
    return ChildTicker{std::string(root), std::string(suffix)};
}

bool IsTickerValidForIssuerReg(std::string_view t)
{
    if (t.empty()) return false;
    if (t.find('.') == std::string_view::npos) return IsRootTicker(t);
    return ParseChildTicker(t).has_value();
}

static bool ReadCompactSizeFrom(const unsigned char*& p, const unsigned char* end, uint64_t& out_len)
{
    if (p >= end) return false;
    unsigned char ch = *p++;
    if (ch < 253) { out_len = ch; return true; }
    if (ch == 253) {
        if (end - p < 2) return false;
        out_len = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8);
        p += 2;
        if (out_len < 253) return false; // non-canonical
        return true;
    }
    if (ch == 254) {
        if (end - p < 4) return false;
        out_len = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24);
        p += 4;
        if (out_len < 0x10000ULL) return false; // non-canonical
        return true;
    }
    if (end - p < 8) return false;
    out_len =  ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
             | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
    p += 8;
    if (out_len < 0x100000000ULL) return false; // non-canonical
    return true;
}

static bool IsValidUtf8(const std::vector<unsigned char>& data)
{
    size_t i = 0;
    while (i < data.size()) {
        unsigned char c = data[i];
        if ((c & 0x80) == 0) {
            ++i;
            continue;
        }
        if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= data.size()) return false;
            unsigned char c1 = data[i + 1];
            if ((c1 & 0xC0) != 0x80) return false;
            if (c < 0xC2) return false; // overlong
            i += 2;
            continue;
        }
        if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= data.size()) return false;
            unsigned char c1 = data[i + 1];
            unsigned char c2 = data[i + 2];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return false;
            if (c == 0xE0 && c1 < 0xA0) return false;        // overlong
            if (c == 0xED && c1 >= 0xA0) return false;        // surrogate halves
            i += 3;
            continue;
        }
        if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= data.size()) return false;
            unsigned char c1 = data[i + 1];
            unsigned char c2 = data[i + 2];
            unsigned char c3 = data[i + 3];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return false;
            if (c == 0xF0 && c1 < 0x90) return false;        // overlong
            if (c == 0xF4 && c1 >= 0x90) return false;        // > U+10FFFF
            if (c > 0xF4) return false;
            i += 4;
            continue;
        }
        return false;
    }
    return true;
}

static bool ParseSingleTLV(const std::vector<unsigned char>& vext, uint8_t& type, const unsigned char*& val, size_t& vlen)
{
    if (vext.size() < 2) return false;
    const unsigned char* p = vext.data();
    const unsigned char* end = vext.data() + vext.size();
    type = *p++;
    uint64_t len = 0;
    if (!ReadCompactSizeFrom(p, end, len)) return false;
    if ((size_t)(end - p) != len) return false;
    if (len > 4096) {
        // Large-but-valid TLV (e.g. vault/contract extensions routinely exceed 4 KiB).
        // The length is already validated above, so this is informational only — gate
        // to debug so it doesn't flood the log on every parse during wallet rescans.
        LogDebug(BCLog::VALIDATION, "VEXT: large TLV type=%u len=%u vext_size=%u\n", static_cast<unsigned>(type), static_cast<unsigned>(len), static_cast<unsigned>(vext.size()));
    }
    val = p;
    vlen = (size_t)len;
    return true;
}

std::optional<AssetTag> ParseAssetTag(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::ASSET_TAG)) return std::nullopt;
    if (vlen < 32 + 8) return std::nullopt;
    AssetTag tag{};
    // Copy 32 raw bytes into uint256 (little-endian in memory representation)
    uint256 id;
    std::memcpy(id.begin(), val, 32);
    if (id.IsNull()) {
        return std::nullopt;
    }
    tag.id = id;
    tag.amount = ReadLE64(val + 32);
    size_t cursor = 32 + 8;
    const bool has_flags = (vlen - cursor >= 4) && val[cursor] != 0x02 && val[cursor] != 0x03;
    if (has_flags) {
        tag.flags = ReadLE32(val + cursor);
        cursor += 4;
    }

    while (cursor < vlen) {
        if (vlen - cursor < 2) return std::nullopt;
        uint8_t sub_type = val[cursor++];

        // Sub-TLV type 0x02 (epoch): uses 1-byte length
        if (sub_type == 0x02) {
            uint8_t sub_len = val[cursor++];
            if (vlen - cursor < sub_len) return std::nullopt;
            if (sub_len != 1) return std::nullopt;
            tag.has_epoch = true;
            tag.epoch = val[cursor];
            cursor += sub_len;
        }
        // Sub-TLV type 0x03 (ICU_KEYWRAP): uses CompactSize length
        else if (sub_type == 0x03) {
            const unsigned char* p = val + cursor;
            const unsigned char* end = val + vlen;
            uint64_t sub_len = 0;
            if (!ReadCompactSizeFrom(p, end, sub_len)) return std::nullopt;
            cursor = p - val;
            if (vlen - cursor < sub_len) return std::nullopt;

            // Parse keywrap payload (same format as top-level ICU_KEYWRAP)
            const unsigned char* kw_start = val + cursor;
            const unsigned char* kw_end = kw_start + sub_len;
            const unsigned char* kw_p = kw_start;

            if (sub_len < 32 + 32 + 32 + 1 + 1) return std::nullopt;

            std::memcpy(tag.keywrap_asset_id.begin(), kw_p, 32);
            kw_p += 32;
            std::memcpy(tag.keywrap_ctxt_hash.begin(), kw_p, 32);
            kw_p += 32;
            std::memcpy(tag.keywrap_spk_hash32.begin(), kw_p, 32);
            kw_p += 32;

            uint64_t wrap_len = 0;
            if (!ReadCompactSizeFrom(kw_p, kw_end, wrap_len)) return std::nullopt;
            if (wrap_len > MAX_ICU_KEYWRAP_WRAPPED_KEY_BYTES) return std::nullopt;
            if (kw_end - kw_p < static_cast<std::ptrdiff_t>(wrap_len + 2)) return std::nullopt;

            tag.keywrap_wrapped_key.assign(reinterpret_cast<const char*>(kw_p), reinterpret_cast<const char*>(kw_p + wrap_len));
            std::vector<unsigned char> wrapped_bytes(tag.keywrap_wrapped_key.begin(), tag.keywrap_wrapped_key.end());
            if (!IsValidUtf8(wrapped_bytes)) return std::nullopt;
            kw_p += wrap_len;

            tag.keywrap_suite_id = *kw_p++;
            tag.keywrap_extras_mask = *kw_p++;

            const uint8_t allowed_mask = ICU_KEYWRAP_EXTRA_WRAP_COMMIT | ICU_KEYWRAP_EXTRA_KC_TAG;
            if ((tag.keywrap_extras_mask & ~allowed_mask) != 0) return std::nullopt;

            if (tag.keywrap_extras_mask & ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
                if (kw_end - kw_p < 32) return std::nullopt;
                tag.keywrap_has_wrap_commit = true;
                std::memcpy(tag.keywrap_wrap_commit.begin(), kw_p, 32);
                kw_p += 32;
            }

            if (tag.keywrap_extras_mask & ICU_KEYWRAP_EXTRA_KC_TAG) {
                if (kw_end - kw_p < static_cast<std::ptrdiff_t>(ICU_KEYWRAP_KC_TAG_SIZE)) return std::nullopt;
                tag.keywrap_has_kc_tag = true;
                std::memcpy(tag.keywrap_kc_tag.data(), kw_p, ICU_KEYWRAP_KC_TAG_SIZE);
                kw_p += ICU_KEYWRAP_KC_TAG_SIZE;
            }

            if (kw_p != kw_end) return std::nullopt;

            tag.has_keywrap = true;
            cursor += sub_len;
        }
        // Sub-TLV type 0x04 (proposal_hash for rotation ballots): uses 1-byte length
        else if (sub_type == 0x04) {
            uint8_t sub_len = val[cursor++];
            if (vlen - cursor < sub_len) return std::nullopt;
            if (sub_len != 32) return std::nullopt;
            tag.has_proposal_hash = true;
            std::memcpy(tag.proposal_hash.begin(), val + cursor, 32);
            cursor += sub_len;
        }
        else {
            return std::nullopt;
        }
    }
    return tag;
}

// V1 Parser (forward declaration from asset_parser_v1.cpp)
std::optional<IssuerReg> ParseIssuerRegV1(const unsigned char* val, size_t vlen);

std::optional<IssuerReg> ParseIssuerReg(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::ISSUER_REG)) return std::nullopt;

    // ParseIssuerRegV1 handles both v1 and v2 (v2 == v1 + trailing delegate).
    return ParseIssuerRegV1(val, vlen);

}

std::optional<ZkParamsChunk> ParseZkParamsChunk(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::ZK_PARAMS_CHUNK)) return std::nullopt;
    if (vlen < 32 + 32 + 2 + 2) return std::nullopt;

    ZkParamsChunk chunk{};
    std::memcpy(chunk.asset_id.begin(), val, 32);
    std::memcpy(chunk.vk_hash.begin(), val + 32, 32);
    chunk.chunk_index = ReadLE16(val + 64);
    chunk.chunk_count = ReadLE16(val + 66);

    // Reject obviously malformed metadata before allocating the payload buffer.
    if (chunk.chunk_count == 0 || chunk.chunk_count > MAX_ZK_CHUNKS) {
        return std::nullopt;
    }
    if (chunk.chunk_index >= chunk.chunk_count) {
        return std::nullopt;
    }

    constexpr size_t HEADER_BYTES = 32 + 32 + 2 + 2;
    const size_t data_len = vlen - HEADER_BYTES;
    if (data_len > MAX_ZK_CHUNK_SIZE) {
        return std::nullopt;
    }

    chunk.data.assign(val + HEADER_BYTES, val + HEADER_BYTES + data_len);
    if (!ValidateChunkParams(chunk)) {
        return std::nullopt;
    }
    return chunk;
}

std::optional<TfrAnchor> ParseTfrAnchor(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::TFR_ANCHOR)) return std::nullopt;
    if (vlen < 32 + 32) return std::nullopt;

    TfrAnchor anchor{};
    std::memcpy(anchor.asset_id.begin(), val, 32);
    std::memcpy(anchor.tfr_commit.begin(), val + 32, 32);
    if (vlen == 32 + 32) {
        return anchor;
    }
    if (vlen < 32 + 32 + 4) return std::nullopt;

    anchor.keyset_id = ReadLE32(val + 64);
    const size_t locator_len = vlen - (32 + 32 + 4);
    anchor.locator.assign(val + 68, val + 68 + locator_len);
    return anchor;
}

std::optional<ZkProofPayload> ParseZkProofPayload(const std::vector<unsigned char>& vext)
{
    LogPrintf("ParseZkProofPayload: vext.size=%u\n", vext.size());

    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) {
        LogPrintf("ParseZkProofPayload: ParseSingleTLV failed\n");
        return std::nullopt;
    }
    LogPrintf("ParseZkProofPayload: type=0x%02x, vlen=%u\n", type, vlen);

    if (type != static_cast<uint8_t>(OutExtType::ZK_PROOF_PAYLOAD)) {
        LogPrintf("ParseZkProofPayload: wrong type, expected 0x22\n");
        return std::nullopt;
    }

    // Minimum: asset_id (32) + proof_len (1) + proof (≥1) + inputs_len (1) + inputs (≥1) = 36 bytes
    if (vlen < 36) {
        LogPrintf("ParseZkProofPayload: vlen %u < 36 (minimum)\n", vlen);
        return std::nullopt;
    }

    const unsigned char* p = val;
    const unsigned char* end = val + vlen;
    LogPrintf("ParseZkProofPayload: payload has %u bytes\n", vlen);

    ZkProofPayload payload{};

    // Read asset_id (32 bytes)
    if (end - p < 32) {
        LogPrintf("ParseZkProofPayload: insufficient bytes for asset_id\n");
        return std::nullopt;
    }
    std::memcpy(payload.asset_id.begin(), p, 32);
    p += 32;
    LogPrintf("ParseZkProofPayload: asset_id=%s\n", payload.asset_id.ToString().c_str());

    // Read proof (CompactSize length + data)
    uint64_t proof_len = 0;
    if (!ReadCompactSizeFrom(p, end, proof_len)) {
        LogPrintf("ParseZkProofPayload: failed to read proof CompactSize\n");
        return std::nullopt;
    }
    LogPrintf("ParseZkProofPayload: proof_len=%u\n", proof_len);

    if (proof_len > GROTH16_PROOF_SIZE * 2) {
        LogPrintf("ParseZkProofPayload: proof_len %u > max %u\n", proof_len, GROTH16_PROOF_SIZE * 2);
        return std::nullopt;
    }

    if ((size_t)(end - p) < proof_len) {
        LogPrintf("ParseZkProofPayload: insufficient bytes for proof, have %u need %u\n", (size_t)(end - p), proof_len);
        return std::nullopt;
    }
    payload.proof.assign(p, p + proof_len);
    p += proof_len;
    LogPrintf("ParseZkProofPayload: proof read, %u bytes remaining\n", (size_t)(end - p));

    // Read public_inputs (CompactSize length + data)
    uint64_t inputs_len = 0;
    if (!ReadCompactSizeFrom(p, end, inputs_len)) {
        LogPrintf("ParseZkProofPayload: failed to read inputs CompactSize\n");
        return std::nullopt;
    }
    LogPrintf("ParseZkProofPayload: inputs_len=%u\n", inputs_len);

    if (inputs_len > GROTH16_MAX_PUBLIC_INPUTS_SIZE) {
        LogPrintf("ParseZkProofPayload: inputs_len %u > max %u\n", inputs_len, GROTH16_MAX_PUBLIC_INPUTS_SIZE);
        return std::nullopt;
    }

    if ((size_t)(end - p) != inputs_len) {
        LogPrintf("ParseZkProofPayload: remaining bytes %u != inputs_len %u\n", (size_t)(end - p), inputs_len);
        return std::nullopt;
    }
    payload.public_inputs.assign(p, p + inputs_len);

    LogPrintf("ParseZkProofPayload: SUCCESS - asset=%s proof=%u inputs=%u\n",
              payload.asset_id.ToString().c_str(), payload.proof.size(), payload.public_inputs.size());
    return payload;
}

std::optional<IcuTextChunk> ParseIcuTextChunk(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::ICU_TEXT_CHUNK)) return std::nullopt;

    LogPrintf("VEXT_DEBUG: ParseIcuTextChunk vlen=%u max=%u\n", vlen, MAX_ICU_PAYLOAD_BYTES);

    if (vlen > MAX_ICU_PAYLOAD_BYTES) return std::nullopt;

    LogPrintf("VEXT_DEBUG: ParseIcuTextChunk about to assign %u bytes\n", vlen);
    IcuTextChunk chunk;
    chunk.payload.assign(val, val + vlen);
    LogPrintf("VEXT_DEBUG: ParseIcuTextChunk assignment succeeded, payload size: %u\n", chunk.payload.size());
    IcuChunkMetadata metadata;
    if (StripIcuChunkMetadata(chunk.payload, metadata)) {
        LogPrintf("VEXT_DEBUG: Metadata trailer found - version=%u compression=%u encryption_mode=%u has_witness=%d\n",
                  metadata.version, metadata.compression, metadata.encryption_mode, metadata.has_witness_hash);
        LogPrintf("VEXT_DEBUG: After stripping trailer, payload size: %u\n", chunk.payload.size());
        chunk.metadata = metadata;
    } else {
        LogPrintf("VEXT_DEBUG: No metadata trailer found (payload size: %u)\n", chunk.payload.size());
    }
    return chunk;
}

std::optional<IcuKeywrap> ParseIcuKeywrap(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::ICU_KEYWRAP)) return std::nullopt;
    if (vlen < 32 + 32 + 32 + 1 + 1) return std::nullopt;

    const unsigned char* p = val;
    const unsigned char* end = val + vlen;

    IcuKeywrap wrap;
    std::memcpy(wrap.asset_id.begin(), p, 32);
    p += 32;
    std::memcpy(wrap.ctxt_hash.begin(), p, 32);
    p += 32;
    std::memcpy(wrap.spk_hash32.begin(), p, 32);
    p += 32;

    uint64_t wrap_len = 0;
    if (!ReadCompactSizeFrom(p, end, wrap_len)) return std::nullopt;

    LogPrintf("VEXT_DEBUG: ParseIcuKeywrap wrap_len=%llu max=%u remaining=%td\n",
              wrap_len, MAX_ICU_KEYWRAP_WRAPPED_KEY_BYTES, end - p);

    if (wrap_len > MAX_ICU_KEYWRAP_WRAPPED_KEY_BYTES) return std::nullopt;
    if (end - p < static_cast<std::ptrdiff_t>(wrap_len + 2)) return std::nullopt;

    LogPrintf("VEXT_DEBUG: ParseIcuKeywrap about to assign %llu bytes\n", wrap_len);
    wrap.wrapped_key.assign(reinterpret_cast<const char*>(p), reinterpret_cast<const char*>(p + wrap_len));
    LogPrintf("VEXT_DEBUG: ParseIcuKeywrap assignment succeeded\n");
    std::vector<unsigned char> wrapped_bytes(wrap.wrapped_key.begin(), wrap.wrapped_key.end());
    if (!IsValidUtf8(wrapped_bytes)) {
        return std::nullopt;
    }
    p += wrap_len;

    wrap.suite_id = *p++;
    wrap.extras_mask = *p++;

    const uint8_t allowed_mask = ICU_KEYWRAP_EXTRA_WRAP_COMMIT | ICU_KEYWRAP_EXTRA_KC_TAG;
    if ((wrap.extras_mask & ~allowed_mask) != 0) {
        return std::nullopt;
    }

    if (wrap.extras_mask & ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
        if (end - p < 32) return std::nullopt;
        wrap.has_wrap_commit = true;
        std::memcpy(wrap.wrap_commit.begin(), p, 32);
        p += 32;
    }

    if (wrap.extras_mask & ICU_KEYWRAP_EXTRA_KC_TAG) {
        if (end - p < static_cast<std::ptrdiff_t>(ICU_KEYWRAP_KC_TAG_SIZE)) return std::nullopt;
        wrap.has_kc_tag = true;
        std::memcpy(wrap.kc_tag.data(), p, ICU_KEYWRAP_KC_TAG_SIZE);
        p += ICU_KEYWRAP_KC_TAG_SIZE;
    }

    if (p != end) {
        return std::nullopt;
    }

    return wrap;
}

uint256 ComputeCorePolicyCommit(
    uint16_t allowed_spk_families,
    uint32_t policy_bits,
    uint32_t kyc_flags,
    uint32_t tfr_flags)
{
    // Canonical encoding: 14 bytes
    uint8_t buf[16]; // 14 bytes used, 2 reserved
    WriteLE16(buf + 0,  allowed_spk_families);
    WriteLE32(buf + 2,  policy_bits & POLICY_BITS_IMMUTABLE_MASK);
    WriteLE32(buf + 6,  kyc_flags);
    WriteLE32(buf + 10, tfr_flags);
    buf[14] = 0x00; // reserved
    buf[15] = 0x00; // reserved

    // Compute tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
    HashWriter hasher = TaggedHash("ASSET/V2_CORE");
    hasher.write(std::as_bytes(std::span<const uint8_t>(buf, 16)));
    return hasher.GetSHA256();
}

bool IsCollateralSafeRotationRejected(uint32_t prev_policy_bits, uint32_t new_policy_bits,
                                      uint32_t prev_icu_flags, uint32_t new_icu_flags,
                                      int height, int scalar_cfd_height)
{
    if (height < scalar_cfd_height) return false; // inert before activation (no consensus change)
    const bool was_safe = (prev_policy_bits & COLLATERAL_SAFE) != 0;
    const bool now_safe = (new_policy_bits & COLLATERAL_SAFE) != 0;
    if (was_safe != now_safe) return true;        // the bit itself is frozen post-activation
    if (was_safe && new_icu_flags != prev_icu_flags) return true; // icu_flags frozen for a safe asset
    return false;
}

std::vector<unsigned char> BuildAssetTagTlv(const uint256& asset_id, uint64_t units)
{
    std::vector<unsigned char> payload;
    payload.reserve(32 + sizeof(uint64_t));
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_bytes[sizeof(uint64_t)];
    WriteLE64(amount_bytes, units);
    payload.insert(payload.end(), amount_bytes, amount_bytes + sizeof(uint64_t));

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(OutExtType::ASSET_TAG));
    tlv.push_back(static_cast<uint8_t>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::optional<IssuerScalar> ParseIssuerScalar(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(OutExtType::ISSUER_SCALAR)) return std::nullopt;
    // Strict fixed width: no trailing bytes, no short body (canonical form).
    if (vlen != ISSUER_SCALAR_BODY_SIZE) return std::nullopt;

    IssuerScalar s{};
    std::memcpy(s.underlying_asset_id.begin(), val, 32);
    s.feed_id          = ReadLE32(val + 32);
    s.scalar_epoch     = ReadLE64(val + 36);
    s.scalar_format_id = ReadLE16(val + 44);
    std::memcpy(s.scalar.begin(), val + 46, 32);
    return s;
}

std::vector<unsigned char> BuildIssuerScalarTlv(const IssuerScalar& s)
{
    std::vector<unsigned char> payload;
    payload.reserve(ISSUER_SCALAR_BODY_SIZE);
    payload.insert(payload.end(), s.underlying_asset_id.begin(), s.underlying_asset_id.end());
    unsigned char b4[4]; WriteLE32(b4, s.feed_id);          payload.insert(payload.end(), b4, b4 + 4);
    unsigned char b8[8]; WriteLE64(b8, s.scalar_epoch);     payload.insert(payload.end(), b8, b8 + 8);
    unsigned char b2[2]; WriteLE16(b2, s.scalar_format_id); payload.insert(payload.end(), b2, b2 + 2);
    payload.insert(payload.end(), s.scalar.begin(), s.scalar.end());

    std::vector<unsigned char> tlv;
    tlv.reserve(2 + payload.size());
    tlv.push_back(static_cast<uint8_t>(OutExtType::ISSUER_SCALAR));
    tlv.push_back(static_cast<uint8_t>(payload.size())); // 78 < 253 -> 1-byte CompactSize
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

ScalarPubStatus CheckScalarPublication(
    uint16_t scalar_format_id,
    const uint256& scalar,
    uint64_t scalar_epoch,
    bool carrier_unspendable,
    bool underlying_registered,
    bool icu_authenticated,
    bool head_exists,
    uint64_t head_last_epoch,
    bool epoch_exists)
{
    if (!IsKnownScalarFormat(scalar_format_id)) return ScalarPubStatus::BadFormat;
    // Reject a value the settlement opcode could not read (e.g. a fixed-width format with non-zero
    // padding bytes): DecodeScalarValue is the single source of truth for "canonical under this format".
    // Without this, a non-canonical "real" fixing is staged, then the opcode fails closed at settlement
    // and — because an in-time real fixing pre-empts the fallback — the contract is bricked.
    { arith_uint256 tmp; if (!DecodeScalarValue(scalar_format_id, scalar, tmp)) return ScalarPubStatus::NonCanonical; }
    if (!carrier_unspendable)                    return ScalarPubStatus::CarrierSpendable;
    if (!underlying_registered)                  return ScalarPubStatus::UnknownAsset;
    if (!icu_authenticated)                      return ScalarPubStatus::NoIcuAuth;
    if (scalar_epoch == 0)                       return ScalarPubStatus::ZeroEpoch;
    if (head_exists && head_last_epoch == std::numeric_limits<uint64_t>::max())
        return ScalarPubStatus::EpochOverflow;
    const uint64_t expected = head_exists ? head_last_epoch + 1 : 1;
    if (scalar_epoch != expected)                return ScalarPubStatus::NonMonotonic;
    if (epoch_exists)                            return ScalarPubStatus::DuplicateEpoch;
    return ScalarPubStatus::Ok;
}

const char* ScalarPubStatusString(ScalarPubStatus status)
{
    switch (status) {
        case ScalarPubStatus::Ok:               return "scalar-ok";
        case ScalarPubStatus::BadFormat:        return "scalar-bad-format";
        case ScalarPubStatus::NonCanonical:     return "scalar-noncanonical";
        case ScalarPubStatus::CarrierSpendable: return "scalar-carrier-spendable";
        case ScalarPubStatus::UnknownAsset:     return "scalar-unknown-asset";
        case ScalarPubStatus::NoIcuAuth:        return "scalar-no-icu-auth";
        case ScalarPubStatus::ZeroEpoch:        return "scalar-zero-epoch";
        case ScalarPubStatus::EpochOverflow:    return "scalar-epoch-overflow";
        case ScalarPubStatus::NonMonotonic:     return "scalar-nonmonotonic";
        case ScalarPubStatus::DuplicateEpoch:   return "scalar-duplicate-epoch";
    }
    return "scalar-unknown-status";
}

std::vector<unsigned char> BuildAssetTagWithProposal(
    const uint256& asset_id,
    uint64_t amount,
    const uint256& proposal_hash,
    uint32_t flags,
    bool has_epoch,
    uint8_t epoch)
{
    std::vector<unsigned char> vext;

    // TLV type: ASSET_TAG
    vext.push_back(static_cast<uint8_t>(OutExtType::ASSET_TAG));

    // Calculate payload size
    size_t payload_size = 32 + 8 + 4;  // asset_id + amount + flags (always present)
    if (has_epoch) payload_size += 1 + 1 + 1;  // sub-TLV: type + len + value
    payload_size += 1 + 1 + 32;  // proposal_hash sub-TLV: type + len + value

    // Write CompactSize length
    if (payload_size < 253) {
        vext.push_back(static_cast<uint8_t>(payload_size));
    } else if (payload_size <= 0xFFFF) {
        vext.push_back(253);
        vext.push_back(static_cast<uint8_t>(payload_size & 0xFF));
        vext.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));
    } else {
        vext.push_back(254);
        for (int i = 0; i < 4; ++i) {
            vext.push_back(static_cast<uint8_t>((payload_size >> (i * 8)) & 0xFF));
        }
    }

    // Write asset_id (32 bytes little-endian)
    vext.insert(vext.end(), asset_id.begin(), asset_id.end());

    // Write amount (8 bytes little-endian)
    for (int i = 0; i < 8; ++i) {
        vext.push_back(static_cast<uint8_t>((amount >> (i * 8)) & 0xFF));
    }

    // Write flags (4 bytes little-endian, always present even if zero)
    for (int i = 0; i < 4; ++i) {
        vext.push_back(static_cast<uint8_t>((flags >> (i * 8)) & 0xFF));
    }

    // Write epoch sub-TLV if present
    if (has_epoch) {
        vext.push_back(0x02);  // sub-type: epoch
        vext.push_back(0x01);  // length: 1 byte
        vext.push_back(epoch);
    }

    // Write proposal_hash sub-TLV (type 0x04)
    vext.push_back(0x04);  // sub-type: proposal_hash
    vext.push_back(32);    // length: 32 bytes
    vext.insert(vext.end(), proposal_hash.begin(), proposal_hash.end());

    return vext;
}

} // namespace assets
