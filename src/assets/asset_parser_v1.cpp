// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/asset.h>
#include <serialize.h>
#include <util/strencodings.h>

namespace assets {

// V1 IssuerReg Parser (Clean, Deterministic Format)
//
// Wire Format:
//   asset_id                [32]
//   policy_bits             [4]
//   allowed_spk             [2]
//   format_version          [1]   // 0x01
//   ticker_len              [1]   // 0-11, 0 = no ticker
//   [ticker]                [ticker_len]
//   decimals                [1]   // 0xFF = not set
//   unlock_fees             [8]   // 0xFFFFFFFFFFFFFFFF = not set
//
//   // ZK section (always present, zero if unused)
//   kyc_flags               [4]
//   vk_commitment           [32]
//   max_root_age            [4]
//   tfr_flags               [4]
//   compliance_root_commit  [32]  // Added 2025-10-20: root‖height (28+4 bytes)
//
//   // ICU section (always present)
//   icu_flags               [4]
//   issuance_cap            [8]
//   icu_ctxt_commit         [32]
//   icu_plain_commit        [32]
//   kdf_salt                [16]
//   icu_version             [1]
//   icu_visibility          [1]
//   core_policy_commit      [32]
//   policy_epoch            [1]
//   policy_quorum_bps       [2]

std::optional<IssuerReg> ParseIssuerRegV1(const unsigned char* val, size_t vlen)
{
    // Minimum size: 32 + 4 + 2 + 1 + 1 + 0 + 1 + 8 + 76 + 129 = 254 bytes (no ticker, with compliance_root_commit)
    // Maximum size: 254 + 23 = 277 bytes (max one-hop child ticker ROOT.SUFFIX, 11+1+11)
    // v2 appends a trailing 32-byte compliance_delegate_asset_id, so its bounds
    // are the v1 bounds + 32.
    static constexpr size_t MIN_V1_SIZE = 254;
    static constexpr size_t MAX_V1_SIZE = 277;
    static constexpr size_t DELEGATE_SIZE = 32;

    // Loose bounds check up front (covers both v1 and v2). The exact, version-
    // specific length is enforced below once format_version is known.
    if (vlen < MIN_V1_SIZE || vlen > MAX_V1_SIZE + DELEGATE_SIZE) {
        return std::nullopt;
    }

    IssuerReg reg;
    size_t pos = 0;

    // Parse asset_id [32]
    std::memcpy(reg.asset_id.begin(), val + pos, 32);
    pos += 32;

    // Parse policy_bits [4]
    reg.policy_bits = ReadLE32(val + pos);
    pos += 4;

    // Parse allowed_spk_families [2]
    reg.allowed_spk_families = ReadLE16(val + pos);
    pos += 2;

    // Parse format_version [1]
    reg.format_version = val[pos++];
    if (reg.format_version != ISSUER_REG_FORMAT_V1 &&
        reg.format_version != ISSUER_REG_FORMAT_V2) {
        return std::nullopt; // Unknown version
    }
    const bool has_delegate = (reg.format_version == ISSUER_REG_FORMAT_V2);

    // Parse ticker_len [1]
    // A one-hop child ticker ROOT.SUFFIX is up to 11 + 1 + 11 = 23 bytes.
    uint8_t ticker_len = val[pos++];
    if (ticker_len > 23) {
        return std::nullopt; // Invalid ticker length
    }

    // Parse ticker [ticker_len]
    if (ticker_len > 0) {
        if (vlen < pos + ticker_len) return std::nullopt;

        std::string ticker(reinterpret_cast<const char*>(val + pos), ticker_len);

        // Accept a bare root or a one-hop child (ROOT.SUFFIX). This single shared gate
        // rejects lowercase, a non-letter first char, an empty/short suffix, a second
        // dot, and any dotless ticker longer than 11 bytes (e.g. a 12-byte dotless
        // name). The parser carries no block-height context — activation-aware rules
        // live in validation.cpp (ICU_CHILD.md §5.1).
        if (!IsTickerValidForIssuerReg(ticker)) return std::nullopt;

        reg.ticker = std::move(ticker);
        pos += ticker_len;
    }

    // Parse decimals [1]
    reg.decimals = val[pos++];
    // Validate: 0xFF (not set) or 0-18
    if (reg.decimals != 0xFF && reg.decimals > 18) {
        return std::nullopt; // Invalid decimals
    }

    // Parse unlock_fees [8]
    reg.unlock_fees_sats = ReadLE64(val + pos);
    pos += 8;

    // Verify we have exactly ZK + ICU sections remaining
    size_t remaining = vlen - pos;
    static constexpr size_t ZK_SECTION_SIZE = 4 + 32 + 4 + 4 + 32; // 76 (added compliance_root_commit)
    static constexpr size_t ICU_SECTION_SIZE = 4 + 8 + 32 + 32 + 16 + 1 + 1 + 32 + 1 + 2; // 129 (added icu_visibility)
    static constexpr size_t TAIL_SIZE = ZK_SECTION_SIZE + ICU_SECTION_SIZE; // 205

    if (remaining != TAIL_SIZE + (has_delegate ? DELEGATE_SIZE : 0)) {
        return std::nullopt; // Malformed
    }

    // Parse ZK section (always present in v1)
    reg.kyc_flags = ReadLE32(val + pos);
    pos += 4;

    std::memcpy(reg.zk_vk_commitment.begin(), val + pos, 32);
    pos += 32;

    reg.max_root_age = ReadLE32(val + pos);
    pos += 4;

    reg.tfr_flags = ReadLE32(val + pos);
    pos += 4;

    // Parse compliance_root_commit [32] (added 2025-10-20)
    std::memcpy(reg.compliance_root_commit.begin(), val + pos, 32);
    pos += 32;

    // Parse ICU section (always present in v1)
    reg.icu_flags = ReadLE32(val + pos);
    pos += 4;

    reg.issuance_cap_units = ReadLE64(val + pos);
    pos += 8;

    std::memcpy(reg.icu_ctxt_commit.begin(), val + pos, 32);
    pos += 32;

    std::memcpy(reg.icu_plain_commit.begin(), val + pos, 32);
    pos += 32;

    std::memcpy(reg.kdf_salt.data(), val + pos, 16);
    pos += 16;

    reg.icu_version = val[pos++];
    // Validate: 0 (unused) or ICU_VERSION_V1
    if (reg.icu_version != 0 && reg.icu_version != ICU_VERSION_V1) {
        return std::nullopt; // Unknown ICU version
    }

    reg.icu_visibility = val[pos++];
    // Validate: 0 or 1
    if (reg.icu_visibility > 1) {
        return std::nullopt; // Invalid visibility
    }

    std::memcpy(reg.core_policy_commit.begin(), val + pos, 32);
    pos += 32;

    reg.policy_epoch = val[pos++];

    reg.policy_quorum_bps = ReadLE16(val + pos);
    pos += 2;

    // Validate: 0..10,000 basis points (0%..100%)
    if (reg.policy_quorum_bps > 10000) {
        return std::nullopt; // Invalid quorum bps
    }

    // Parse v2 trailing compliance_delegate_asset_id [32].
    if (has_delegate) {
        std::memcpy(reg.compliance_delegate_asset_id.begin(), val + pos, 32);
        pos += 32;
        // A v2 reg MUST carry a non-null delegate. delegate == own asset_id is the
        // opt-out sentinel (handled in validation); a v1 reg preserves the delegate.
        if (reg.compliance_delegate_asset_id.IsNull()) {
            return std::nullopt;
        }
    }

    // Verify exact consumption
    if (pos != vlen) {
        return std::nullopt;
    }

    return reg;
}

} // namespace assets
