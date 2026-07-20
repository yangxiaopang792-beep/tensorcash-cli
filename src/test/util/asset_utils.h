// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_ASSET_UTILS_H
#define BITCOIN_TEST_UTIL_ASSET_UTILS_H

#include <assets/asset.h>
#include <uint256.h>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace test_util {

/**
 * Build a v1 IssuerReg TLV for testing.
 *
 * V1 format is deterministic:
 * - Always includes format_version byte (0x01)
 * - Always includes 44-byte ZK section
 * - Always includes 128-byte ICU section
 * - Total size: 221-232 bytes (depending on ticker length)
 *
 * Uses sentinel values for optional fields:
 * - Empty ticker → not set
 * - decimals == 0xFF → not set
 * - unlock_fees == UINT64_MAX → not set
 */
std::vector<unsigned char> BuildV1IssuerReg(
    const uint256& asset_id,
    uint32_t policy_bits,
    uint16_t allowed_spk = assets::SPK_DEFAULT_ALLOWED,
    const std::string& ticker = "",
    uint8_t decimals = 0xFF,
    uint64_t unlock_fees = std::numeric_limits<uint64_t>::max(),
    uint32_t kyc_flags = 0,
    const uint256& vk_commitment = uint256(),
    uint32_t max_root_age = 0,
    uint32_t tfr_flags = 0,
    uint32_t icu_flags = 0,
    uint64_t issuance_cap_units = 0,
    const uint256& icu_ctxt_commit = uint256(),
    const uint256& icu_plain_commit = uint256(),
    const std::array<unsigned char, 16>& kdf_salt = {},
    uint8_t icu_version = 0,
    uint8_t icu_visibility = 0,
    const uint256& core_policy_commit = uint256(),
    uint8_t policy_epoch = 0,
    uint16_t policy_quorum_bps = 0);

/**
 * Optional ICU_KEYWRAP data for BuildAssetTag.
 */
struct IcuKeywrapData {
    uint256 asset_id;
    uint256 ctxt_hash;
    uint256 spk_hash32;
    std::string wrapped_key;
    uint8_t suite_id{0};
    uint8_t extras_mask{0};
    uint256 wrap_commit;
    std::array<unsigned char, 16> kc_tag{};
};

/**
 * Build an AssetTag TLV for testing.
 */
std::vector<unsigned char> BuildAssetTag(
    const uint256& asset_id,
    uint64_t amount,
    uint32_t flags = 0,
    bool has_epoch = false,
    uint8_t epoch = 0,
    const IcuKeywrapData* keywrap = nullptr);

/**
 * Build a ZK_PROOF_PAYLOAD TLV for testing.
 *
 * TLV-based proof transport: proof lives in output TLV, not witness stack.
 */
std::vector<unsigned char> BuildZkProofPayload(
    const uint256& asset_id,
    const std::vector<unsigned char>& proof,           // 192 bytes Groth16
    const std::vector<unsigned char>& public_inputs);  // N × 32 bytes (128 legacy, 192 HDv1)

} // namespace test_util

#endif // BITCOIN_TEST_UTIL_ASSET_UTILS_H
