// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSETS_KYC_DELEGATION_H
#define BITCOIN_ASSETS_KYC_DELEGATION_H

#include <cstdint>
#include <deque>
#include <functional>
#include <string>

#include <assets/asset.h>
#include <assets/registry.h>
#include <uint256.h>

namespace assets {

// Result of the registration-time delegation check.
struct DelegateRegCheck {
    bool ok{false};
    std::string reason;  // consensus reject reason when !ok
};

// Validate a delegate install / opt-out at REGISTRATION time (ConnectBlock).
// Pure — the caller looks up `source` (the delegate target's entry, or nullptr
// if absent / self) and passes it in. Belt-and-suspenders to the spend-time
// resolver, plus the opt-out coherence rule. See REUSABLE_KYC.md §2.3.
//   - delegate set on a non-KYC reg            -> kyc-delegate-requires-kyc
//   - prev VK history longer than root history -> asset-registry-malformed
//   - install: self / source-missing / source-no-kyc / multi-hop /
//              source-no-root / source-noncanonical / own-vk-noncanonical
//   - opt-out (was delegated, now self): requires canonical own VK + non-null
//     own root -> kyc-optout-own-vk-noncanonical / kyc-optout-no-root
DelegateRegCheck ValidateDelegateRegistration(
    const uint256& asset_id,
    const IssuerReg& reg,
    const AssetRegistryEntry& prev,
    bool had_prev,
    const AssetRegistryEntry* source,
    const std::function<bool(const uint256&)>& is_canonical_vk);

// The delegate pointer an IssuerReg produces, given the prior on-chain delegate.
// Single source of truth shared by the registry-update path (validation.cpp) and
// the in-flight-reg spend path (CheckTxInputs), so they cannot drift:
//   v1 reg                  -> inherit prev_delegate (mint/rotate/governance preserve)
//   v2, delegate == self    -> null  (explicit opt-out clear)
//   v2, delegate != self    -> reg.compliance_delegate_asset_id (install / change)
uint256 ResolveRegDelegate(const IssuerReg& reg, const uint256& asset_id,
                           const uint256& prev_delegate);

// Effective KYC policy for a spend of a (possibly delegating) asset B.
// See REUSABLE_KYC.md §2.2 for the field-wise resolution rules.
//
// CRITICAL: identity proof material (vk / root / history / max_age) may be
// sourced from a delegated source asset A, but asset-scoped semantics
// (expected_asset_id and tfr_flags) ALWAYS stay with the spending asset B.
// Do NOT replace B's policy snapshot wholesale with A's — that is the bug this
// resolver exists to make impossible.
struct EffectiveKycPolicy {
    bool ok{false};            // when false: fail the spend closed with `reason`
    std::string reason;        // consensus reject reason when !ok
    bool required{false};      // mirrors B.has_kyc
    bool delegated{false};     // B follows a source asset
    uint256 source_asset_id;   // declared source (set whenever B delegates, even on failure)

    // --- asset-scoped: ALWAYS from B ---
    uint256 expected_asset_id;                 // public_inputs[1] binds here
    uint32_t tfr_flags{0};                     // frozen asset semantics

    // --- identity material: B, or A when delegated ---
    uint256 vk_commitment;
    uint256 compliance_root_commit;
    std::deque<ComplianceRootHistory> compliance_root_history;
    std::deque<uint256> compliance_root_history_vk; // parallel to compliance_root_history
    uint32_t max_root_age{0};                  // B, or min(A,B) when delegated
    int32_t active_root_activation_height{0};  // B or A (delegated-asset heartbeat)
};

// Combine a source's and a follower's max_root_age windows.
//
// Treats 0 as "no staleness bound from that side" (unset). Returns the min of
// the positive values, or 0 (unbounded) when both are 0. This implements "the
// follower can only TIGHTEN the staleness window, never loosen it," while
// keeping an unset value on the follower from bricking delegation. The
// delegated-asset heartbeat fires only when the result is > 0.
// See REUSABLE_KYC.md §2.4.
uint32_t EffectiveMaxRootAge(uint32_t source_age, uint32_t follower_age);

// Pure resolver — performs NO I/O.
//
//   spending_asset_id : the asset being spent (B). expected_asset_id is always this.
//   B                 : B's registry entry.
//   source            : when B delegates (B.compliance_delegate_asset_id != null),
//                       A's already-looked-up registry entry, or nullptr if A is
//                       absent. Ignored when B does not delegate.
//   is_canonical_vk   : predicate testing the consensus canonical-VK allowlist.
//
// Spend-time guardrails are enforced here and surface as ok=false + reason:
//   kyc-delegate-self / -source-missing / -source-no-kyc / -multi-hop /
//   -source-no-root / -source-noncanonical.
// A non-delegating asset always resolves ok=true from its own fields (a null own
// root is left for the downstream "zk-root-not-set" check, not failed here).
EffectiveKycPolicy ResolveEffectiveKycPolicy(
    const uint256& spending_asset_id,
    const AssetRegistryEntry& B,
    const AssetRegistryEntry* source,
    const std::function<bool(const uint256&)>& is_canonical_vk);

// Best-effort activation height of an entry's ACTIVE compliance root.
// Returns the explicit active_root_activation_height when set; otherwise (legacy
// entry) derives it by scanning compliance_root_history for the entry matching
// the active root; returns 0 if neither is available. See REUSABLE_KYC.md §2.4.
int DeriveActiveRootActivationHeight(const AssetRegistryEntry& e);

// Apply a compliance-root update to `now`, the entry being written this block.
//
// Maintains compliance_root_commit, compliance_root_history,
// compliance_root_history_vk (the per-root VK), and active_root_activation_height.
// The two history deques are kept in EXACT lockstep — appended together, trimmed
// together (to MAX_ROOT_HISTORY), cleared together. A legacy `prev` that has root
// history but no VK history is migrated by left-padding the VK deque with prev's
// ACTIVE VK (prev.zk_vk_commitment) — the VK every historical root was verified
// under before this upgrade; padding with null would re-create a hard cutover.
//
//   prev/had_prev : the prior on-chain entry (had_prev=false on first registration)
//   new_root      : reg.compliance_root_commit (null => root removed)
//   active_vk     : the VK the new root is committed under (reg.zk_vk_commitment)
//   height,txid   : the connecting block height and registering txid
void ApplyComplianceRootUpdate(
    AssetRegistryEntry& now,
    const AssetRegistryEntry& prev,
    bool had_prev,
    const uint256& new_root,
    const uint256& active_vk,
    int height,
    const uint256& txid);

} // namespace assets

#endif // BITCOIN_ASSETS_KYC_DELEGATION_H
