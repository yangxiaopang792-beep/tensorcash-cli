// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/kyc_delegation.h>

#include <algorithm>

namespace assets {

DelegateRegCheck ValidateDelegateRegistration(
    const uint256& asset_id,
    const IssuerReg& reg,
    const AssetRegistryEntry& prev,
    bool had_prev,
    const AssetRegistryEntry* source,
    const std::function<bool(const uint256&)>& is_canonical_vk)
{
    // Malformed prior state: VK history longer than root history (independent of delegation).
    if (had_prev && prev.compliance_root_history_vk.size() > prev.compliance_root_history.size()) {
        return {false, "asset-registry-malformed"};
    }

    // Only a v2 IssuerReg changes delegation. A v1 reg (mint / rotatezk / governance,
    // which don't know about the delegate field) PRESERVES the existing delegate pointer
    // and needs no delegation-specific checks. This is what stops mint from silently
    // clearing a follower's delegation.
    if (reg.format_version < ISSUER_REG_FORMAT_V2) return {true, ""};

    if (reg.kyc_flags == 0) return {false, "kyc-delegate-requires-kyc"};

    // v2 with delegate == self is the explicit opt-out sentinel (clear delegation).
    // Require a coherent self-config so opt-out can never land on a stale/arbitrary VK.
    if (reg.compliance_delegate_asset_id == asset_id) {
        if (!is_canonical_vk(reg.zk_vk_commitment)) return {false, "kyc-optout-own-vk-noncanonical"};
        if (reg.compliance_root_commit.IsNull()) return {false, "kyc-optout-no-root"};
        return {true, ""};
    }

    // v2 install / change of delegation to a source asset.
    if (source == nullptr) return {false, "kyc-delegate-source-missing"};
    if (!source->has_kyc) return {false, "kyc-delegate-source-no-kyc"};
    if (!source->compliance_delegate_asset_id.IsNull()) return {false, "kyc-delegate-multi-hop"};
    if (source->compliance_root_commit.IsNull()) return {false, "kyc-delegate-source-no-root"};
    if (!is_canonical_vk(source->zk_vk_commitment)) return {false, "kyc-delegate-source-noncanonical"};
    // Belt-and-suspenders: own VK must be canonical so opt-out can never fall back to
    // arbitrary VK material.
    if (!is_canonical_vk(reg.zk_vk_commitment)) return {false, "kyc-delegate-own-vk-noncanonical"};
    return {true, ""};
}

uint256 ResolveRegDelegate(const IssuerReg& reg, const uint256& asset_id,
                           const uint256& prev_delegate)
{
    if (reg.format_version < ISSUER_REG_FORMAT_V2) return prev_delegate;       // v1 inherits
    if (reg.compliance_delegate_asset_id == asset_id) return uint256{};        // v2 self => clear
    return reg.compliance_delegate_asset_id;                                   // v2 install
}

int DeriveActiveRootActivationHeight(const AssetRegistryEntry& e)
{
    if (e.active_root_activation_height != 0) return e.active_root_activation_height;
    if (e.compliance_root_commit.IsNull()) return 0;
    // Legacy entry: find the most-recent history entry matching the active root.
    for (auto it = e.compliance_root_history.rbegin(); it != e.compliance_root_history.rend(); ++it) {
        if (it->root_commit == e.compliance_root_commit) return it->activation_height;
    }
    return 0;
}

void ApplyComplianceRootUpdate(
    AssetRegistryEntry& now,
    const AssetRegistryEntry& prev,
    bool had_prev,
    const uint256& new_root,
    const uint256& active_vk,
    int height,
    const uint256& txid)
{
    if (new_root.IsNull()) {
        // Root removed (issuer dropped the compliance root).
        now.compliance_root_commit.SetNull();
        now.active_root_activation_height = 0;
        if (had_prev && !prev.compliance_root_commit.IsNull()) {
            now.compliance_root_history.clear();
            now.compliance_root_history_vk.clear();
        }
        return;
    }

    const bool root_new = !had_prev;
    const bool root_changed = had_prev && (prev.compliance_root_commit != new_root);

    // Inherit prior history (both deques).
    if (had_prev) {
        now.compliance_root_history = prev.compliance_root_history;
        now.compliance_root_history_vk = prev.compliance_root_history_vk;
    }
    // Migrate a legacy entry (root history but no per-root VKs) to lockstep.
    // The correct historical VK is prev's ACTIVE VK: before this upgrade every
    // historical root was verified under the then-current active VK. Padding with
    // null here would re-create the hard cutover the VK history exists to avoid.
    // (null must only ever mean "truly no VK available".)
    while (now.compliance_root_history_vk.size() < now.compliance_root_history.size()) {
        now.compliance_root_history_vk.push_front(prev.zk_vk_commitment);
    }
    // Defensive: never silently carry an over-long VK deque (malformed input).
    // Align from the back — the most-recent (root,vk) pairs are authoritative.
    // Validation additionally fails closed on this malformed state before calling us.
    while (now.compliance_root_history_vk.size() > now.compliance_root_history.size()) {
        now.compliance_root_history_vk.pop_front();
    }

    if (root_new || root_changed) {
        ComplianceRootHistory h;
        h.root_commit = new_root;
        h.activation_height = height;
        h.txid = txid;
        now.compliance_root_history.push_back(h);
        now.compliance_root_history_vk.push_back(active_vk);

        // Trim both deques identically (FIFO).
        while (now.compliance_root_history.size() > MAX_ROOT_HISTORY) {
            now.compliance_root_history.pop_front();
            now.compliance_root_history_vk.pop_front();
        }
        now.active_root_activation_height = height;
    } else {
        // Root unchanged (re-registration with same root): preserve the prior
        // activation height, deriving it for a legacy prev that never stored it.
        now.active_root_activation_height = DeriveActiveRootActivationHeight(prev);
    }

    now.compliance_root_commit = new_root;
}

uint32_t EffectiveMaxRootAge(uint32_t source_age, uint32_t follower_age)
{
    if (source_age == 0) return follower_age;   // source unbounded -> follower's window applies
    if (follower_age == 0) return source_age;   // follower unset   -> source's window applies
    return std::min(source_age, follower_age);  // both set         -> the stricter (smaller)
}

EffectiveKycPolicy ResolveEffectiveKycPolicy(
    const uint256& spending_asset_id,
    const AssetRegistryEntry& B,
    const AssetRegistryEntry* source,
    const std::function<bool(const uint256&)>& is_canonical_vk)
{
    EffectiveKycPolicy eff;
    eff.required = B.has_kyc;

    // Asset-scoped fields are ALWAYS B's, on every path (including failures).
    eff.expected_asset_id = spending_asset_id;
    eff.tfr_flags = B.tfr_flags;

    // --- Non-delegating: identity material from B itself ---
    if (B.compliance_delegate_asset_id.IsNull()) {
        eff.delegated = false;
        eff.vk_commitment = B.zk_vk_commitment;
        eff.compliance_root_commit = B.compliance_root_commit;
        eff.compliance_root_history = B.compliance_root_history;
        eff.compliance_root_history_vk = B.compliance_root_history_vk;
        eff.max_root_age = B.max_root_age;
        eff.active_root_activation_height = DeriveActiveRootActivationHeight(B);
        // A null own root is handled downstream by the existing "zk-root-not-set"
        // check, not here — preserve current non-delegated behavior.
        eff.ok = true;
        return eff;
    }

    // --- Delegating: B follows source A ---
    eff.delegated = true;
    eff.source_asset_id = B.compliance_delegate_asset_id;

    // Spend-time guardrails (cheap structural checks first). One-hop is checked
    // HERE, at spend time, because A can begin delegating after B opted in.
    if (B.compliance_delegate_asset_id == spending_asset_id) {
        eff.reason = "kyc-delegate-self";
        return eff;
    }
    if (source == nullptr) {
        eff.reason = "kyc-delegate-source-missing";
        return eff;
    }
    if (!source->has_kyc) {
        eff.reason = "kyc-delegate-source-no-kyc";
        return eff;
    }
    if (!source->compliance_delegate_asset_id.IsNull()) {
        eff.reason = "kyc-delegate-multi-hop";
        return eff;
    }
    if (source->compliance_root_commit.IsNull()) {
        eff.reason = "kyc-delegate-source-no-root";
        return eff;
    }
    if (!is_canonical_vk(source->zk_vk_commitment)) {
        eff.reason = "kyc-delegate-source-noncanonical";
        return eff;
    }

    // Identity material from A; asset semantics (above) stay B's.
    eff.vk_commitment = source->zk_vk_commitment;
    eff.compliance_root_commit = source->compliance_root_commit;
    eff.compliance_root_history = source->compliance_root_history;
    eff.compliance_root_history_vk = source->compliance_root_history_vk;
    eff.max_root_age = EffectiveMaxRootAge(source->max_root_age, B.max_root_age);
    eff.active_root_activation_height = DeriveActiveRootActivationHeight(*source);
    eff.ok = true;
    return eff;
}

} // namespace assets
