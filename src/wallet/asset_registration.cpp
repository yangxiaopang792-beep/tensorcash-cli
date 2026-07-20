// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/asset_registration.h>

#include <assets/asset.h>
#include <assets/icu_payload.h>
#include <crypto/common.h>   // WriteLE16 / WriteLE32 / WriteLE64
#include <crypto/sha256.h>
#include <rpc/protocol.h>    // RPC_* codes
#include <rpc/request.h>     // JSONRPCError
#include <sync.h>            // LOCK
#include <univalue.h>
#include <util/check.h>      // Assume
#include <util/strencodings.h> // DecodeBase64
#include <wallet/wallet.h>

#include <algorithm>
#include <optional>

namespace wallet {

std::vector<unsigned char> BuildIssuerRegV1(
    const uint256& asset_id,
    uint32_t policy_bits,
    uint16_t allowed_spk,
    const std::string& ticker,
    uint8_t decimals,
    uint64_t unlock_fees,
    uint32_t kyc_flags,
    const uint256& vk_commitment,
    uint32_t max_root_age,
    uint32_t tfr_flags,
    const uint256& compliance_root_commit,
    uint32_t icu_flags,
    uint64_t issuance_cap_units,
    const uint256& icu_ctxt_commit,
    const uint256& icu_plain_commit,
    const std::array<unsigned char, 16>& kdf_salt,
    uint8_t icu_version,
    uint8_t icu_visibility,
    const uint256& core_policy_commit,
    uint8_t policy_epoch,
    uint16_t policy_quorum_bps,
    const uint256& delegate)
{
    // Precondition: ticker_len is a single byte and the parser rejects issuer tickers > 23 bytes
    // (asset_parser_v1.cpp). Callers MUST pass a parser-valid ticker (BuildAssetRegistrationTLVs gates
    // this); a longer ticker here would silently truncate the length byte.
    Assume(ticker.size() <= 23);

    std::vector<unsigned char> payload;
    payload.reserve(256);

    payload.insert(payload.end(), asset_id.begin(), asset_id.end());

    unsigned char buf32[4];
    WriteLE32(buf32, policy_bits);
    payload.insert(payload.end(), buf32, buf32 + sizeof(buf32));

    unsigned char buf16[2];
    WriteLE16(buf16, allowed_spk);
    payload.insert(payload.end(), buf16, buf16 + sizeof(buf16));

    payload.push_back(delegate.IsNull() ? assets::ISSUER_REG_FORMAT_V1 : assets::ISSUER_REG_FORMAT_V2);

    payload.push_back(static_cast<uint8_t>(ticker.size()));
    payload.insert(payload.end(), ticker.begin(), ticker.end());

    payload.push_back(decimals);

    unsigned char buf64[8];
    WriteLE64(buf64, unlock_fees);
    payload.insert(payload.end(), buf64, buf64 + sizeof(buf64));

    WriteLE32(buf32, kyc_flags);
    payload.insert(payload.end(), buf32, buf32 + sizeof(buf32));
    payload.insert(payload.end(), vk_commitment.begin(), vk_commitment.end());
    WriteLE32(buf32, max_root_age);
    payload.insert(payload.end(), buf32, buf32 + sizeof(buf32));
    WriteLE32(buf32, tfr_flags);
    payload.insert(payload.end(), buf32, buf32 + sizeof(buf32));
    payload.insert(payload.end(), compliance_root_commit.begin(), compliance_root_commit.end());

    WriteLE32(buf32, icu_flags);
    payload.insert(payload.end(), buf32, buf32 + sizeof(buf32));
    WriteLE64(buf64, issuance_cap_units);
    payload.insert(payload.end(), buf64, buf64 + sizeof(buf64));
    payload.insert(payload.end(), icu_ctxt_commit.begin(), icu_ctxt_commit.end());
    payload.insert(payload.end(), icu_plain_commit.begin(), icu_plain_commit.end());
    payload.insert(payload.end(), kdf_salt.begin(), kdf_salt.end());
    payload.push_back(icu_version);
    payload.push_back(icu_visibility);
    payload.insert(payload.end(), core_policy_commit.begin(), core_policy_commit.end());
    payload.push_back(policy_epoch);
    WriteLE16(buf16, policy_quorum_bps);
    payload.insert(payload.end(), buf16, buf16 + sizeof(buf16));

    // v2 trailing compliance_delegate_asset_id (reusable/delegated KYC).
    if (!delegate.IsNull()) {
        payload.insert(payload.end(), delegate.begin(), delegate.end());
    }

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ISSUER_REG));
    if (payload.size() < 253) {
        tlv.push_back(static_cast<unsigned char>(payload.size()));
    } else {
        tlv.push_back(253);
        tlv.push_back(payload.size() & 0xFF);
        tlv.push_back((payload.size() >> 8) & 0xFF);
    }
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

AssetRegistrationTLVs BuildAssetRegistrationTLVs(CWallet& wallet, AssetRegistrationInputs in)
{
    // Enforce the registry preconditions HERE rather than trusting every caller (review finding):
    // icu_visibility must be 0 (public) or 1 (encrypted) — the parser rejects > 1 — and a non-empty
    // ticker must satisfy the shared issuer-ticker grammar (root, or one-hop ROOT.SUFFIX, <= 23 bytes).
    if (in.icu_visibility > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_visibility must be 0 (public) or 1 (encrypted)");
    }
    if (!in.ticker.empty() && !assets::IsTickerValidForIssuerReg(in.ticker)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ticker: expected a root or one-hop child ROOT.SUFFIX (<= 23 bytes)");
    }

    AssetRegistrationTLVs out;
    uint256 vk_commitment;
    std::vector<std::vector<unsigned char>> vk_chunks;

    // VK chunking (KYC): vk_commitment = double-SHA256(vk_data); 512-byte chunks.
    if (!in.vk_data.empty()) {
        CSHA256 h1; h1.Write(in.vk_data.data(), in.vk_data.size());
        uint256 single; h1.Finalize(single.begin());
        CSHA256 h2; h2.Write(single.begin(), 32); h2.Finalize(vk_commitment.begin());
        const size_t CHUNK_SIZE = 512;
        for (size_t i = 0; i < in.vk_data.size(); i += CHUNK_SIZE) {
            const size_t n = std::min(CHUNK_SIZE, in.vk_data.size() - i);
            vk_chunks.emplace_back(in.vk_data.begin() + i, in.vk_data.begin() + i + n);
        }
    }

    // ICU payload: normalize/encrypt the canonical plaintext into the cipher + commits.
    std::optional<assets::IcuStorageEntry> built_storage_entry;
    if (in.icu_plaintext_provided) {
        auto parsed = assets::ParseCanonicalIcuPayload(in.icu_plaintext);
        if (!parsed) throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse icu_payload_plain as CanonicalIcuPayload");
        const std::string canonical_text_str(parsed->canonical_text.begin(), parsed->canonical_text.end());
        const std::string witness_str(parsed->witness_bundle.begin(), parsed->witness_bundle.end());
        UniValue witness_obj;
        if (!witness_obj.read(witness_str)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse witness_bundle JSON");
        in.icu_plain_commit = parsed->GetCanonicalHash();

        std::array<unsigned char, 32> dek{};
        if (in.icu_visibility == 1) {
            std::string dek_b64;
            { LOCK(wallet.cs_wallet); dek_b64 = wallet.GetOrCreateAssetDek(in.asset_id); }
            auto dek_bytes = DecodeBase64(dek_b64);
            if (!dek_bytes || dek_bytes->size() != 32) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive ICU data encryption key (must be 32 bytes)");
            std::copy_n(dek_bytes->begin(), 32, dek.begin());
        }
        assets::IcuStorageEntry se;
        if (!assets::BuildCanonicalIcuPayload(canonical_text_str, witness_obj, in.icu_visibility, dek,
                                              in.use_compression, in.icu_plain_commit, in.icu_ctxt_commit,
                                              in.kdf_salt, se, parsed->metadata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build ICU payload");
        }
        in.icu_payload = se.icu_cipher;
        in.icu_plain_commit = se.canonical_hash;
        built_storage_entry = se;
        if (in.icu_visibility == 1 && (in.icu_flags & assets::WRAP_REQUIRED) == 0) in.icu_flags |= assets::WRAP_REQUIRED;
        if (in.use_compression) in.icu_flags |= assets::ICU_COMPRESSED;
    }

    // IssuerReg TLV (compliance_root_commit zero for initial registration).
    out.issuer_reg_tlv = BuildIssuerRegV1(
        in.asset_id, in.policy_bits, in.allowed_spk, in.ticker, in.decimals, in.unlock_fees,
        in.kyc_flags, vk_commitment, in.max_root_age, in.tfr_flags, /*compliance_root_commit=*/uint256(),
        in.icu_flags, in.issuance_cap_units, in.icu_ctxt_commit, in.icu_plain_commit, in.kdf_salt,
        /*icu_version=*/1, in.icu_visibility,
        assets::ComputeCorePolicyCommit(in.allowed_spk, in.policy_bits, in.kyc_flags, in.tfr_flags),
        /*policy_epoch=*/0, in.policy_quorum_bps);

    // ICU_TEXT_CHUNK TLV (type 0x30) with chunk metadata appended.
    if (!in.icu_payload.empty()) {
        std::vector<unsigned char> chunk = in.icu_payload;
        if (built_storage_entry) {
            assets::IcuChunkMetadata md;
            md.compression = built_storage_entry->compression;
            md.encryption_mode = built_storage_entry->encryption_mode;
            md.has_witness_hash = !built_storage_entry->witness_hash.IsNull();
            md.witness_hash = built_storage_entry->witness_hash;
            chunk = assets::AppendIcuChunkMetadata(chunk, md);
        }
        auto& t = out.icu_chunk_tlv;
        t.push_back(static_cast<uint8_t>(assets::OutExtType::ICU_TEXT_CHUNK));
        if (chunk.size() < 253) { t.push_back(static_cast<uint8_t>(chunk.size())); }
        else { t.push_back(253); t.push_back(chunk.size() & 0xFF); t.push_back((chunk.size() >> 8) & 0xFF); }
        t.insert(t.end(), chunk.begin(), chunk.end());
    }

    // ZK_PARAMS_CHUNK TLVs (type 0x20): asset_id + vk_commitment + chunk_index + chunk_count + data.
    for (size_t ci = 0; ci < vk_chunks.size(); ++ci) {
        std::vector<unsigned char> p;
        p.insert(p.end(), in.asset_id.begin(), in.asset_id.end());
        p.insert(p.end(), vk_commitment.begin(), vk_commitment.end());
        p.push_back(ci & 0xFF); p.push_back((ci >> 8) & 0xFF);
        p.push_back(vk_chunks.size() & 0xFF); p.push_back((vk_chunks.size() >> 8) & 0xFF);
        p.insert(p.end(), vk_chunks[ci].begin(), vk_chunks[ci].end());
        std::vector<unsigned char> t;
        t.push_back(static_cast<unsigned char>(assets::OutExtType::ZK_PARAMS_CHUNK));
        if (p.size() < 253) { t.push_back(static_cast<unsigned char>(p.size())); }
        else { t.push_back(253); t.push_back(p.size() & 0xFF); t.push_back((p.size() >> 8) & 0xFF); }
        t.insert(t.end(), p.begin(), p.end());
        out.zk_chunk_tlvs.push_back(std::move(t));
    }

    return out;
}

} // namespace wallet
