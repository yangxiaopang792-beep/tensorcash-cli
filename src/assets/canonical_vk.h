// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSETS_CANONICAL_VK_H
#define BITCOIN_ASSETS_CANONICAL_VK_H

#include <cstdint>
#include <map>
#include <string>

#include <uint256.h>

namespace assets {

// Metadata for a consensus-blessed ("canonical") KYC verifying key / circuit.
//
// The allowlist is a MAP, not just a set (see REUSABLE_KYC.md §3): the delegation
// resolver and future code need the circuit's shape — output binding, which
// public inputs are free, tree depth, input count — not merely membership.
struct CanonicalVkInfo {
    std::string circuit_id;        // e.g. "hd_v1_depth8"
    uint32_t depth{0};             // Merkle tree depth (8 today; 24/32 for the deep circuit)
    uint8_t public_input_count{0}; // 4 (legacy) or 6 (HDv1)
    uint32_t flags{0};             // CANON_* bit flags below
};

// CanonicalVkInfo.flags
static constexpr uint32_t CANON_HD_OUTPUT_BOUND = 0x0001; // binds the spend output key (HDv1)
static constexpr uint32_t CANON_ASSET_ID_FREE   = 0x0002; // public_inputs[1] unconstrained in-circuit
static constexpr uint32_t CANON_TFR_FREE        = 0x0004; // public_inputs[3] unconstrained in-circuit

// The consensus allowlist of blessed VK commitments.
//
// NOTE: intentionally EMPTY until the genesis-blessed depth-8 HDv1 VK hash (and
// later the canonical deep-circuit hash) are added in the allowlist-population
// slice. An empty allowlist makes all delegation fail closed
// ("kyc-delegate-source-noncanonical"), which is the correct default before the
// feature is activated. Changing this set is a consensus change.
// See REUSABLE_KYC.md §3, §7.
const std::map<uint256, CanonicalVkInfo>& CanonicalVkAllowlist();

// True iff vk_hash is a consensus-blessed canonical circuit. Null is never canonical.
bool IsCanonicalVk(const uint256& vk_hash);

} // namespace assets

#endif // BITCOIN_ASSETS_CANONICAL_VK_H
