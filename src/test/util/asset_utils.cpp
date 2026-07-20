// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/asset_utils.h>

#include <serialize.h>
#include <span.h>
#include <streams.h>

namespace test_util {

std::vector<unsigned char> BuildV1IssuerReg(
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
    uint32_t icu_flags,
    uint64_t issuance_cap_units,
    const uint256& icu_ctxt_commit,
    const uint256& icu_plain_commit,
    const std::array<unsigned char, 16>& kdf_salt,
    uint8_t icu_version,
    uint8_t icu_visibility,
    const uint256& core_policy_commit,
    uint8_t policy_epoch,
    uint16_t policy_quorum_bps)
{
    std::vector<unsigned char> payload;

    // Header
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char buf32[4]; WriteLE32(buf32, policy_bits); payload.insert(payload.end(), buf32, buf32+4);
    unsigned char buf16[2]; WriteLE16(buf16, allowed_spk); payload.insert(payload.end(), buf16, buf16+2);
    payload.push_back(assets::ISSUER_REG_FORMAT_V1); // format_version

    // Ticker
    payload.push_back(static_cast<uint8_t>(ticker.size()));
    payload.insert(payload.end(), ticker.begin(), ticker.end());

    // Decimals
    payload.push_back(decimals);

    // Unlock fees
    unsigned char buf64[8]; WriteLE64(buf64, unlock_fees); payload.insert(payload.end(), buf64, buf64+8);

    // ZK section (76 bytes) - ZK Whitelist Hardening update
    WriteLE32(buf32, kyc_flags); payload.insert(payload.end(), buf32, buf32+4);
    payload.insert(payload.end(), vk_commitment.begin(), vk_commitment.end());
    WriteLE32(buf32, max_root_age); payload.insert(payload.end(), buf32, buf32+4);
    WriteLE32(buf32, tfr_flags); payload.insert(payload.end(), buf32, buf32+4);
    // compliance_root_commit [32] - zero for tests (issuer would set via updatecomplianceroot)
    payload.insert(payload.end(), 32, 0);

    // ICU section (129 bytes with icu_visibility)
    WriteLE32(buf32, icu_flags); payload.insert(payload.end(), buf32, buf32+4);
    WriteLE64(buf64, issuance_cap_units); payload.insert(payload.end(), buf64, buf64+8);
    payload.insert(payload.end(), icu_ctxt_commit.begin(), icu_ctxt_commit.end());
    payload.insert(payload.end(), icu_plain_commit.begin(), icu_plain_commit.end());
    payload.insert(payload.end(), kdf_salt.begin(), kdf_salt.end());
    payload.push_back(icu_version);
    payload.push_back(icu_visibility);
    payload.insert(payload.end(), core_policy_commit.begin(), core_policy_commit.end());
    payload.push_back(policy_epoch);
    WriteLE16(buf16, policy_quorum_bps); payload.insert(payload.end(), buf16, buf16+2);

    // Wrap in TLV
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

std::vector<unsigned char> BuildAssetTag(
    const uint256& asset_id,
    uint64_t amount,
    uint32_t flags,
    bool has_epoch,
    uint8_t epoch,
    const IcuKeywrapData* keywrap)
{
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());

    unsigned char abuf[8];
    WriteLE64(abuf, amount);
    payload.insert(payload.end(), abuf, abuf+8);

    if (flags != 0) {
        unsigned char fbuf[4];
        WriteLE32(fbuf, flags);
        payload.insert(payload.end(), fbuf, fbuf+4);
    }

    if (has_epoch) {
        payload.push_back(0x02); // epoch sub-TLV type
        payload.push_back(0x01); // length
        payload.push_back(epoch);
    }

    if (keywrap) {
        // Build ICU_KEYWRAP sub-TLV (type 0x03)
        std::vector<unsigned char> kw_payload;

        // asset_id (32 bytes)
        kw_payload.insert(kw_payload.end(), keywrap->asset_id.begin(), keywrap->asset_id.end());
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

        // Write sub-TLV to main payload: type (1 byte) + CompactSize length + data
        payload.push_back(0x03); // ICU_KEYWRAP sub-TLV type
        VectorWriter payload_writer(payload, payload.size());
        WriteCompactSize(payload_writer, kw_payload.size());
        payload.insert(payload.end(), kw_payload.begin(), kw_payload.end());
    }

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    if (payload.size() < 253) {
        tlv.push_back(static_cast<unsigned char>(payload.size()));
    } else {
        VectorWriter tlv_writer(tlv, tlv.size());
        WriteCompactSize(tlv_writer, payload.size());
    }
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::vector<unsigned char> BuildZkProofPayload(
    const uint256& asset_id,
    const std::vector<unsigned char>& proof,
    const std::vector<unsigned char>& public_inputs)
{
    // Build payload: asset_id || CompactSize(proof_len) || proof || CompactSize(inputs_len) || inputs
    std::vector<unsigned char> payload;

    // asset_id (32 bytes)
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());

    // proof (CompactSize length + data)
    VectorWriter proof_writer(payload, payload.size());
    WriteCompactSize(proof_writer, proof.size());
    payload.insert(payload.end(), proof.begin(), proof.end());

    // public_inputs (CompactSize length + data)
    VectorWriter inputs_writer(payload, payload.size());
    WriteCompactSize(inputs_writer, public_inputs.size());
    payload.insert(payload.end(), public_inputs.begin(), public_inputs.end());

    // Wrap in TLV
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ZK_PROOF_PAYLOAD));
    if (payload.size() < 253) {
        tlv.push_back(static_cast<unsigned char>(payload.size()));
    } else {
        VectorWriter tlv_writer(tlv, tlv.size());
        WriteCompactSize(tlv_writer, payload.size());
    }
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

} // namespace test_util
