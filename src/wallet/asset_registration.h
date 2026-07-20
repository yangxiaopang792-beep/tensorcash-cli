// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ASSET_REGISTRATION_H
#define BITCOIN_WALLET_ASSET_REGISTRATION_H

// Shared asset-registration TLV builders, lifted out of wallet/rpc/assets.cpp (OPTION_TOKENIZATION.md
// §6.6 helper extraction). Used by sponsorchildasset and the option-series registration path. NOTE:
// the root `registerasset` RPC still has its own byte-equivalent inline build (assets.cpp) pending
// migration onto this builder — verified equivalent by asset_tests' issuerreg_roundtrip, but not yet
// the single source of truth. The builders enforce the registry preconditions (icu_visibility,
// ticker grammar) so callers cannot construct an unparseable IssuerReg.

#include <assets/asset.h> // assets::SPK_DEFAULT_ALLOWED
#include <uint256.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace wallet {
class CWallet;

//! Build the v1 (or v2, when `delegate` is set) IssuerReg TLV — the ICU output's vExt — from the
//! asset's policy/registry fields. Pure byte assembly; no wallet or chain state.
std::vector<unsigned char> BuildIssuerRegV1(
    const uint256& asset_id, uint32_t policy_bits, uint16_t allowed_spk, const std::string& ticker,
    uint8_t decimals, uint64_t unlock_fees, uint32_t kyc_flags, const uint256& vk_commitment,
    uint32_t max_root_age, uint32_t tfr_flags, const uint256& compliance_root_commit, uint32_t icu_flags,
    uint64_t issuance_cap_units, const uint256& icu_ctxt_commit, const uint256& icu_plain_commit,
    const std::array<unsigned char, 16>& kdf_salt, uint8_t icu_version, uint8_t icu_visibility,
    const uint256& core_policy_commit, uint8_t policy_epoch, uint16_t policy_quorum_bps,
    const uint256& delegate = uint256());

//! The TLVs an asset registration emits: the IssuerReg (ICU output vExt), the ICU_TEXT_CHUNK payload
//! (empty when no ICU), and one ZK_PARAMS_CHUNK per VK chunk.
struct AssetRegistrationTLVs {
    std::vector<unsigned char> issuer_reg_tlv;
    std::vector<unsigned char> icu_chunk_tlv;
    std::vector<std::vector<unsigned char>> zk_chunk_tlvs;
};

//! Inputs to BuildAssetRegistrationTLVs (asset params + ICU/ZK inputs already parsed from the RPC).
struct AssetRegistrationInputs {
    uint256 asset_id;
    uint32_t policy_bits{0};
    uint16_t allowed_spk{assets::SPK_DEFAULT_ALLOWED};
    std::string ticker;            // "" => none; may be ROOT.SUFFIX for a child
    uint8_t decimals{0xFF};        // 0xFF => unset
    uint64_t unlock_fees{std::numeric_limits<uint64_t>::max()};
    // ZK / compliance
    uint32_t kyc_flags{0};
    std::vector<unsigned char> vk_data;
    uint32_t max_root_age{0};
    uint32_t tfr_flags{0};
    // ICU
    std::vector<unsigned char> icu_plaintext;   // canonical payload from buildcanonicalicupayload
    bool icu_plaintext_provided{false};
    uint32_t icu_flags{0};
    uint8_t icu_visibility{0};
    bool use_compression{false};
    uint16_t policy_quorum_bps{0};
    uint64_t issuance_cap_units{0};
    // precomputed ICU fields (used only when !icu_plaintext_provided)
    uint256 icu_plain_commit;
    uint256 icu_ctxt_commit;
    std::array<unsigned char, 16> kdf_salt{};
    std::vector<unsigned char> icu_payload;     // pre-built cipher
};

//! Shared asset-registration builder (registerasset + sponsorchildasset + option series; ICU_CHILD.md
//! §6.1): runs the ICU normalization/encryption (BuildCanonicalIcuPayload) and VK chunking, returning
//! the IssuerReg TLV plus the ICU_TEXT_CHUNK / ZK_PARAMS_CHUNK dust-output TLVs. `wallet` is used only
//! to derive the ICU DEK when icu_visibility == 1 (encrypted). Throws JSONRPCError on malformed input.
AssetRegistrationTLVs BuildAssetRegistrationTLVs(CWallet& wallet, AssetRegistrationInputs in);

} // namespace wallet

#endif // BITCOIN_WALLET_ASSET_REGISTRATION_H
