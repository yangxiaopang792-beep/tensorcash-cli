// Unit tests for effective KYC policy resolution under delegation (Upgrade 1).
// These are PURE tests of the field-wise resolver — no proofs, no DB. This is
// the spot where a wrong snapshot swap would create a silent KYC-bypass or
// wrong-asset-binding bug, so it is pinned exhaustively. See REUSABLE_KYC.md §2.2.

#include <boost/test/unit_test.hpp>

#include <assets/asset.h>
#include <assets/canonical_vk.h>
#include <assets/kyc_delegation.h>
#include <assets/registry.h>
#include <hash.h>
#include <test/util/golden_vector_loader.h>
#include <uint256.h>

#include <cstring>
#include <span>

using namespace assets;

namespace {

uint256 Fill(unsigned char b)
{
    uint256 v;
    std::memset(v.data(), b, v.size());
    return v;
}

// A self-sovereign KYC asset entry with distinct, recognizable field values.
AssetRegistryEntry MakeKycEntry(unsigned char vk, unsigned char root, uint32_t max_age = 1000)
{
    AssetRegistryEntry e;
    e.has_kyc = true;
    e.zk_vk_commitment = Fill(vk);
    e.compliance_root_commit = Fill(root);
    e.max_root_age = max_age;
    e.tfr_flags = 0;
    e.active_root_activation_height = 100;
    ComplianceRootHistory h;
    h.root_commit = Fill(root);
    h.activation_height = 100;
    e.compliance_root_history.push_back(h);
    e.compliance_root_history_vk.push_back(Fill(vk));
    return e;
}

// VK 0xAA is the only "canonical" circuit in these tests.
const std::function<bool(const uint256&)> kCanonical =
    [](const uint256& vk) { return vk == Fill(0xAA); };

} // namespace

BOOST_AUTO_TEST_SUITE(asset_kyc_delegation_tests)

// --- Non-delegating (self) ---

BOOST_AUTO_TEST_CASE(self_resolves_from_B)
{
    AssetRegistryEntry B = MakeKycEntry(/*vk=*/0xBB, /*root=*/0xCC);
    const uint256 bid = Fill(0x01);

    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(bid, B, nullptr, kCanonical);

    BOOST_CHECK(eff.ok);
    BOOST_CHECK(!eff.delegated);
    BOOST_CHECK(eff.expected_asset_id == bid);
    BOOST_CHECK(eff.vk_commitment == Fill(0xBB));
    BOOST_CHECK(eff.compliance_root_commit == Fill(0xCC));
    BOOST_CHECK_EQUAL(eff.max_root_age, 1000u);
    BOOST_CHECK_EQUAL(eff.compliance_root_history.size(), 1u);
    BOOST_CHECK_EQUAL(eff.compliance_root_history_vk.size(), 1u);
}

BOOST_AUTO_TEST_CASE(self_with_null_root_is_ok_here)
{
    // A non-delegated null root is the downstream "zk-root-not-set" path, not a
    // resolver failure — preserve existing behavior.
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_root_commit.SetNull();
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, nullptr, kCanonical);
    BOOST_CHECK(eff.ok);
    BOOST_CHECK(eff.compliance_root_commit.IsNull());
}

// --- Delegating: happy path ---

BOOST_AUTO_TEST_CASE(delegated_pulls_identity_from_A_keeps_asset_semantics_from_B)
{
    const uint256 bid = Fill(0x01);
    const uint256 aid = Fill(0x02);

    AssetRegistryEntry A = MakeKycEntry(/*vk=*/0xAA, /*root=*/0xDD, /*max_age=*/500);
    A.tfr_flags = 0x9999;               // A's tfr must NOT leak into the result
    A.active_root_activation_height = 250;

    AssetRegistryEntry B = MakeKycEntry(/*vk=*/0xBB, /*root=*/0xCC, /*max_age=*/1000);
    B.tfr_flags = 0x0004;               // B's own tfr — this is what must survive
    B.compliance_delegate_asset_id = aid;

    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(bid, B, &A, kCanonical);

    BOOST_CHECK(eff.ok);
    BOOST_CHECK(eff.delegated);
    BOOST_CHECK(eff.source_asset_id == aid);
    // identity material from A
    BOOST_CHECK(eff.vk_commitment == Fill(0xAA));
    BOOST_CHECK(eff.compliance_root_commit == Fill(0xDD));
    BOOST_CHECK_EQUAL(eff.active_root_activation_height, 250);
    // asset semantics from B
    BOOST_CHECK(eff.expected_asset_id == bid);          // NEVER A
    BOOST_CHECK_EQUAL(eff.tfr_flags, 0x0004u);          // B's, NEVER A's 0x9999
    // window = min(A=500, B=1000)
    BOOST_CHECK_EQUAL(eff.max_root_age, 500u);
}

BOOST_AUTO_TEST_CASE(delegated_ignores_Bs_own_root)
{
    AssetRegistryEntry A = MakeKycEntry(0xAA, 0xDD);
    AssetRegistryEntry B = MakeKycEntry(0xBB, /*root=*/0xCC);  // B's own root is junk
    B.compliance_delegate_asset_id = Fill(0x02);

    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, &A, kCanonical);
    BOOST_CHECK(eff.ok);
    BOOST_CHECK(eff.compliance_root_commit == Fill(0xDD));     // A's, not B's 0xCC
    BOOST_CHECK(eff.compliance_root_history.front().root_commit == Fill(0xDD));
    BOOST_CHECK(eff.compliance_root_history_vk.front() == Fill(0xAA));
}

// --- Delegating: guardrails (each must fail closed) ---

BOOST_AUTO_TEST_CASE(self_delegation_rejected)
{
    const uint256 bid = Fill(0x01);
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_delegate_asset_id = bid;                      // points at itself
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(bid, B, &B, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK_EQUAL(eff.reason, "kyc-delegate-self");
}

BOOST_AUTO_TEST_CASE(source_missing_rejected)
{
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_delegate_asset_id = Fill(0x02);
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, nullptr, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK_EQUAL(eff.reason, "kyc-delegate-source-missing");
}

BOOST_AUTO_TEST_CASE(source_non_kyc_rejected)
{
    AssetRegistryEntry A = MakeKycEntry(0xAA, 0xDD);
    A.has_kyc = false;
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_delegate_asset_id = Fill(0x02);
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, &A, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK_EQUAL(eff.reason, "kyc-delegate-source-no-kyc");
}

BOOST_AUTO_TEST_CASE(multi_hop_rejected_at_spend_time)
{
    AssetRegistryEntry A = MakeKycEntry(0xAA, 0xDD);
    A.compliance_delegate_asset_id = Fill(0x03);               // A itself delegates -> 2 hops
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_delegate_asset_id = Fill(0x02);
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, &A, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK_EQUAL(eff.reason, "kyc-delegate-multi-hop");
}

BOOST_AUTO_TEST_CASE(source_null_root_rejected)
{
    AssetRegistryEntry A = MakeKycEntry(0xAA, 0xDD);
    A.compliance_root_commit.SetNull();
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_delegate_asset_id = Fill(0x02);
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, &A, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK_EQUAL(eff.reason, "kyc-delegate-source-no-root");
}

BOOST_AUTO_TEST_CASE(source_noncanonical_vk_rejected)
{
    AssetRegistryEntry A = MakeKycEntry(/*vk=*/0xBE, /*root=*/0xDD);  // 0xBE not canonical
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.compliance_delegate_asset_id = Fill(0x02);
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(Fill(0x01), B, &A, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK_EQUAL(eff.reason, "kyc-delegate-source-noncanonical");
}

BOOST_AUTO_TEST_CASE(failed_delegation_still_pins_asset_scoped_fields_to_B)
{
    // Even on a guardrail failure the asset-scoped fields must read as B's, never
    // leak from a partially-populated source.
    const uint256 bid = Fill(0x01);
    AssetRegistryEntry B = MakeKycEntry(0xBB, 0xCC);
    B.tfr_flags = 0x0004;
    B.compliance_delegate_asset_id = Fill(0x02);
    EffectiveKycPolicy eff = ResolveEffectiveKycPolicy(bid, B, nullptr, kCanonical);
    BOOST_CHECK(!eff.ok);
    BOOST_CHECK(eff.expected_asset_id == bid);
    BOOST_CHECK_EQUAL(eff.tfr_flags, 0x0004u);
    BOOST_CHECK(eff.source_asset_id == Fill(0x02));
}

// --- EffectiveMaxRootAge: "0 = unset; follower can only tighten" ---

BOOST_AUTO_TEST_CASE(effective_max_root_age_rules)
{
    BOOST_CHECK_EQUAL(EffectiveMaxRootAge(1000, 300), 300u);  // both set -> stricter
    BOOST_CHECK_EQUAL(EffectiveMaxRootAge(300, 1000), 300u);  // order-independent
    BOOST_CHECK_EQUAL(EffectiveMaxRootAge(0, 500), 500u);     // source unbounded -> follower's
    BOOST_CHECK_EQUAL(EffectiveMaxRootAge(500, 0), 500u);     // follower unset  -> source's
    BOOST_CHECK_EQUAL(EffectiveMaxRootAge(0, 0), 0u);         // both unset -> unbounded (no heartbeat)
    BOOST_CHECK_EQUAL(EffectiveMaxRootAge(500, 500), 500u);   // equal
}

// --- ApplyComplianceRootUpdate: root/VK history lockstep ---

namespace {
AssetRegistryEntry EntryWithRoot(unsigned char root, unsigned char vk, int h)
{
    AssetRegistryEntry e;
    e.has_kyc = true;
    e.compliance_root_commit = Fill(root);
    e.active_root_activation_height = h;
    ComplianceRootHistory hist; hist.root_commit = Fill(root); hist.activation_height = h;
    e.compliance_root_history.push_back(hist);
    e.compliance_root_history_vk.push_back(Fill(vk));
    return e;
}
}

BOOST_AUTO_TEST_CASE(apply_root_new)
{
    AssetRegistryEntry now, prev;
    ApplyComplianceRootUpdate(now, prev, /*had_prev=*/false, Fill(0xA1), Fill(0xB1), 100, Fill(0xC1));
    BOOST_CHECK(now.compliance_root_commit == Fill(0xA1));
    BOOST_REQUIRE_EQUAL(now.compliance_root_history.size(), 1u);
    BOOST_CHECK(now.compliance_root_history[0].root_commit == Fill(0xA1));
    BOOST_CHECK_EQUAL(now.compliance_root_history[0].activation_height, 100);
    BOOST_REQUIRE_EQUAL(now.compliance_root_history_vk.size(), 1u);
    BOOST_CHECK(now.compliance_root_history_vk[0] == Fill(0xB1));
    BOOST_CHECK_EQUAL(now.active_root_activation_height, 100);
}

BOOST_AUTO_TEST_CASE(apply_root_changed_keeps_lockstep)
{
    AssetRegistryEntry prev = EntryWithRoot(0xA1, 0xB1, 100);
    AssetRegistryEntry now;
    ApplyComplianceRootUpdate(now, prev, true, Fill(0xA2), Fill(0xB2), 200, Fill(0xC2));
    BOOST_CHECK(now.compliance_root_commit == Fill(0xA2));
    BOOST_REQUIRE_EQUAL(now.compliance_root_history.size(), 2u);
    BOOST_REQUIRE_EQUAL(now.compliance_root_history_vk.size(), 2u);
    BOOST_CHECK(now.compliance_root_history[0].root_commit == Fill(0xA1));
    BOOST_CHECK(now.compliance_root_history[1].root_commit == Fill(0xA2));
    BOOST_CHECK(now.compliance_root_history_vk[0] == Fill(0xB1));
    BOOST_CHECK(now.compliance_root_history_vk[1] == Fill(0xB2));
    BOOST_CHECK_EQUAL(now.active_root_activation_height, 200);
}

BOOST_AUTO_TEST_CASE(apply_root_unchanged_preserves_active_height)
{
    AssetRegistryEntry prev = EntryWithRoot(0xA1, 0xB1, 100);
    AssetRegistryEntry now;
    ApplyComplianceRootUpdate(now, prev, true, Fill(0xA1), Fill(0xB1), 200, Fill(0xC2));
    BOOST_CHECK(now.compliance_root_commit == Fill(0xA1));
    BOOST_CHECK_EQUAL(now.compliance_root_history.size(), 1u);     // not re-pushed
    BOOST_CHECK_EQUAL(now.compliance_root_history_vk.size(), 1u);
    BOOST_CHECK_EQUAL(now.active_root_activation_height, 100);     // preserved, not 200
}

BOOST_AUTO_TEST_CASE(apply_root_removed_clears_both)
{
    AssetRegistryEntry prev = EntryWithRoot(0xA1, 0xB1, 100);
    AssetRegistryEntry now;
    ApplyComplianceRootUpdate(now, prev, true, uint256{} /*null*/, Fill(0xB2), 200, Fill(0xC2));
    BOOST_CHECK(now.compliance_root_commit.IsNull());
    BOOST_CHECK(now.compliance_root_history.empty());
    BOOST_CHECK(now.compliance_root_history_vk.empty());
    BOOST_CHECK_EQUAL(now.active_root_activation_height, 0);
}

BOOST_AUTO_TEST_CASE(apply_legacy_vk_backfill_keeps_lockstep)
{
    // Legacy prev: two historical roots, but NO per-root VKs (pre-v5).
    AssetRegistryEntry prev;
    prev.has_kyc = true;
    prev.zk_vk_commitment = Fill(0xBE);             // prev's active VK
    prev.compliance_root_commit = Fill(0xA2);
    for (auto r : {0xA1, 0xA2}) {
        ComplianceRootHistory h; h.root_commit = Fill((unsigned char)r); h.activation_height = 100;
        prev.compliance_root_history.push_back(h);
    }
    // prev.compliance_root_history_vk intentionally left empty.
    AssetRegistryEntry now;
    ApplyComplianceRootUpdate(now, prev, true, Fill(0xA3), Fill(0xB3), 300, Fill(0xC3));
    BOOST_REQUIRE_EQUAL(now.compliance_root_history.size(), 3u);
    BOOST_REQUIRE_EQUAL(now.compliance_root_history_vk.size(), 3u);   // lockstep restored
    // Legacy roots backfill to prev's ACTIVE VK (not null) — preserves the
    // pre-upgrade behavior that historical roots verified under the active VK.
    BOOST_CHECK(now.compliance_root_history_vk[0] == Fill(0xBE));
    BOOST_CHECK(now.compliance_root_history_vk[1] == Fill(0xBE));
    BOOST_CHECK(now.compliance_root_history_vk[2] == Fill(0xB3));     // new root -> its own VK
}

BOOST_AUTO_TEST_CASE(apply_overlong_vk_deque_normalized)
{
    // Malformed prev: more VKs than roots. The helper must not silently carry it.
    AssetRegistryEntry prev;
    prev.has_kyc = true;
    prev.zk_vk_commitment = Fill(0xBE);
    prev.compliance_root_commit = Fill(0xA1);
    ComplianceRootHistory h; h.root_commit = Fill(0xA1); h.activation_height = 100;
    prev.compliance_root_history.push_back(h);                 // 1 root
    prev.compliance_root_history_vk.push_back(Fill(0xB1));
    prev.compliance_root_history_vk.push_back(Fill(0xB2));     // 2 VKs (overlong)
    AssetRegistryEntry now;
    ApplyComplianceRootUpdate(now, prev, true, Fill(0xA1) /*unchanged*/, Fill(0xB1), 200, Fill(0xC1));
    BOOST_CHECK_EQUAL(now.compliance_root_history.size(), 1u);
    BOOST_CHECK_EQUAL(now.compliance_root_history_vk.size(), 1u);  // normalized to lockstep
    BOOST_CHECK(now.compliance_root_history_vk[0] == Fill(0xB2));  // back-aligned survivor
}

BOOST_AUTO_TEST_CASE(apply_trim_keeps_both_deques_equal)
{
    AssetRegistryEntry prev;
    prev.has_kyc = true;
    for (size_t i = 0; i < MAX_ROOT_HISTORY; ++i) {
        ComplianceRootHistory h; h.root_commit = Fill((unsigned char)i); h.activation_height = (int)i;
        prev.compliance_root_history.push_back(h);
        prev.compliance_root_history_vk.push_back(Fill((unsigned char)(0x80 + i)));
    }
    prev.compliance_root_commit = Fill((unsigned char)(MAX_ROOT_HISTORY - 1));
    AssetRegistryEntry now;
    ApplyComplianceRootUpdate(now, prev, true, Fill(0xEE), Fill(0xEF), 999, Fill(0xFE));
    BOOST_CHECK_EQUAL(now.compliance_root_history.size(), MAX_ROOT_HISTORY);
    BOOST_CHECK_EQUAL(now.compliance_root_history_vk.size(), MAX_ROOT_HISTORY);
    BOOST_CHECK(now.compliance_root_history.back().root_commit == Fill(0xEE));
    BOOST_CHECK(now.compliance_root_history_vk.back() == Fill(0xEF));
    BOOST_CHECK(now.compliance_root_history.front().root_commit == Fill(0x01)); // index 0 dropped
}

// --- ValidateDelegateRegistration: install / opt-out / malformed ---

namespace {
IssuerReg MakeReg(uint32_t kyc_flags, unsigned char vk, unsigned char root, const uint256& delegate,
                  uint8_t format_version = ISSUER_REG_FORMAT_V2)
{
    IssuerReg r;
    r.format_version = format_version;
    r.kyc_flags = kyc_flags;
    r.zk_vk_commitment = Fill(vk);
    r.compliance_root_commit = (root == 0) ? uint256{} : Fill(root);
    r.compliance_delegate_asset_id = delegate;
    return r;
}
const uint256 BID = Fill(0x01);   // the registering asset
const uint256 AID = Fill(0x02);   // the delegation source
}

BOOST_AUTO_TEST_CASE(reg_install_ok)
{
    AssetRegistryEntry src = MakeKycEntry(0xAA, 0xDD);          // canonical VK, root set, not delegated
    IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID);                // own VK canonical, delegate -> A
    AssetRegistryEntry prev;
    auto chk = ValidateDelegateRegistration(BID, reg, prev, /*had_prev=*/false, &src, kCanonical);
    BOOST_CHECK(chk.ok);
}

BOOST_AUTO_TEST_CASE(reg_install_guardrails)
{
    AssetRegistryEntry prev;
    auto canon_src = MakeKycEntry(0xAA, 0xDD);

    // source missing
    {
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, nullptr, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-source-missing");
    }
    // source not KYC
    {
        AssetRegistryEntry src = canon_src; src.has_kyc = false;
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, &src, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-source-no-kyc");
    }
    // source itself delegated (multi-hop)
    {
        AssetRegistryEntry src = canon_src; src.compliance_delegate_asset_id = Fill(0x03);
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, &src, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-multi-hop");
    }
    // source no root
    {
        AssetRegistryEntry src = canon_src; src.compliance_root_commit.SetNull();
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, &src, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-source-no-root");
    }
    // source VK non-canonical
    {
        AssetRegistryEntry src = MakeKycEntry(0xBE, 0xDD);
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, &src, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-source-noncanonical");
    }
    // own VK non-canonical
    {
        IssuerReg reg = MakeReg(1, 0xBE, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, &canon_src, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-own-vk-noncanonical");
    }
    // delegate on a non-KYC reg
    {
        IssuerReg reg = MakeReg(0, 0xAA, 0xCC, AID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev, false, &canon_src, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-delegate-requires-kyc");
    }
}

BOOST_AUTO_TEST_CASE(reg_optout_rules)
{
    AssetRegistryEntry prev_deleg;
    prev_deleg.has_kyc = true;
    prev_deleg.compliance_delegate_asset_id = AID;   // was delegated

    // Opt-out = a v2 reg whose delegate == the asset's own id (self sentinel).
    // opt-out OK: canonical own VK + non-null own root
    {
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, BID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev_deleg, true, nullptr, kCanonical);
        BOOST_CHECK(chk.ok);
    }
    // opt-out with non-canonical own VK
    {
        IssuerReg reg = MakeReg(1, 0xBE, 0xCC, BID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev_deleg, true, nullptr, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-optout-own-vk-noncanonical");
    }
    // opt-out with null own root
    {
        IssuerReg reg = MakeReg(1, 0xAA, 0x00, BID);
        auto chk = ValidateDelegateRegistration(BID, reg, prev_deleg, true, nullptr, kCanonical);
        BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "kyc-optout-no-root");
    }
    // A v1 reg (mint / rotatezk) PRESERVES delegation — never an opt-out, no checks,
    // even on a delegated asset with a non-canonical VK / null root in the reg.
    {
        IssuerReg reg = MakeReg(1, 0xBE, 0x00, uint256{}, ISSUER_REG_FORMAT_V1);
        auto chk = ValidateDelegateRegistration(BID, reg, prev_deleg, true, nullptr, kCanonical);
        BOOST_CHECK(chk.ok);
    }
}

BOOST_AUTO_TEST_CASE(reg_malformed_prev_rejected)
{
    AssetRegistryEntry prev;
    prev.has_kyc = true;
    ComplianceRootHistory h; h.root_commit = Fill(0xA1); prev.compliance_root_history.push_back(h); // 1 root
    prev.compliance_root_history_vk.push_back(Fill(0xB1));
    prev.compliance_root_history_vk.push_back(Fill(0xB2));   // 2 VKs -> malformed
    IssuerReg reg = MakeReg(1, 0xAA, 0xCC, uint256{});
    auto chk = ValidateDelegateRegistration(BID, reg, prev, true, nullptr, kCanonical);
    BOOST_CHECK(!chk.ok); BOOST_CHECK_EQUAL(chk.reason, "asset-registry-malformed");
}

BOOST_AUTO_TEST_CASE(resolve_reg_delegate_rules)
{
    const uint256 PREV = Fill(0x07);
    // v1 reg inherits the prior delegate (mint/rotate preserve), ignoring its delegate field.
    {
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, uint256{}, ISSUER_REG_FORMAT_V1);
        BOOST_CHECK(ResolveRegDelegate(reg, BID, PREV) == PREV);
        BOOST_CHECK(ResolveRegDelegate(reg, BID, uint256{}).IsNull());
    }
    // v2 install: delegate != self -> the delegate.
    {
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, AID, ISSUER_REG_FORMAT_V2);
        BOOST_CHECK(ResolveRegDelegate(reg, BID, PREV) == AID);
    }
    // v2 self -> clear, even if previously delegated.
    {
        IssuerReg reg = MakeReg(1, 0xAA, 0xCC, BID, ISSUER_REG_FORMAT_V2);
        BOOST_CHECK(ResolveRegDelegate(reg, BID, PREV).IsNull());
    }
}

BOOST_AUTO_TEST_CASE(derive_active_height_rules)
{
    // explicit field wins
    AssetRegistryEntry a; a.active_root_activation_height = 500; a.compliance_root_commit = Fill(0x01);
    BOOST_CHECK_EQUAL(DeriveActiveRootActivationHeight(a), 500);

    // legacy: derive from matching history entry
    AssetRegistryEntry b = EntryWithRoot(0xA1, 0xB1, 300);
    b.active_root_activation_height = 0; // legacy: field never stored
    BOOST_CHECK_EQUAL(DeriveActiveRootActivationHeight(b), 300);

    // unknown: no field, no matching history -> 0
    AssetRegistryEntry c; c.compliance_root_commit = Fill(0x09);
    BOOST_CHECK_EQUAL(DeriveActiveRootActivationHeight(c), 0);

    // null root -> 0
    AssetRegistryEntry d;
    BOOST_CHECK_EQUAL(DeriveActiveRootActivationHeight(d), 0);
}

// --- Canonical VK allowlist: verify the hardcoded genesis hash is correct ---
// Recomputes the on-chain commitment from the golden HDv1 VK bytes and asserts it
// is the canonical entry. Catches any derivation/endianness/transcription error in
// the consensus-critical literal in canonical_vk.cpp (which cannot be hand-verified).
BOOST_AUTO_TEST_CASE(canonical_vk_matches_genesis_hdv1_golden)
{
    if (!golden_vectors::HDV1GoldenVectorsAvailable()) {
        BOOST_TEST_MESSAGE("HDv1 golden vectors unavailable; skipping canonical VK check");
        return;
    }
    auto gv = golden_vectors::LoadHDV1GoldenVector("valid");
    BOOST_REQUIRE(gv.has_value());
    BOOST_REQUIRE(!gv->vk_bytes.empty());

    // vk_commitment = double-SHA256(vk_data), matching registerasset (assets.cpp).
    HashWriter h;
    h.write(std::as_bytes(std::span<const unsigned char>(gv->vk_bytes.data(), gv->vk_bytes.size())));
    const uint256 commitment = h.GetHash();

    BOOST_CHECK_MESSAGE(IsCanonicalVk(commitment),
        "genesis HDv1 VK commitment " + commitment.ToString() + " is not in the canonical allowlist");
    const auto& allow = CanonicalVkAllowlist();
    auto it = allow.find(commitment);
    BOOST_REQUIRE(it != allow.end());
    BOOST_CHECK_EQUAL(it->second.circuit_id, "hd_v1_depth8");
    BOOST_CHECK_EQUAL(it->second.depth, 8u);
    BOOST_CHECK_EQUAL(it->second.public_input_count, 6);
    BOOST_CHECK_EQUAL(allow.size(), 1u); // exactly the genesis circuit, nothing else
}

// KYC/PQ registration guard keys on kyc_flags (canonical KYC signal), not the
// KYC_REQUIRED policy bit. These pin the wrong-field bypass shut: a KYC asset is
// identified by kyc_flags != 0, and such an asset may not enable PQ (witness-v2).
BOOST_AUTO_TEST_CASE(kyc_pq_family_conflict_keys_on_kyc_flags)
{
    using namespace assets;
    IssuerReg kyc;    kyc.kyc_flags = 1;       // KYC asset (kyc_flags != 0)
    IssuerReg nonkyc; nonkyc.kyc_flags = 0;    // non-KYC asset
    // Also confirm policy_bits is irrelevant to the decision: a KYC_REQUIRED bit set on a
    // non-KYC reg must NOT trigger the conflict (kyc_flags is what counts).
    IssuerReg bitset_only; bitset_only.kyc_flags = 0; bitset_only.policy_bits = KYC_REQUIRED;

    // KYC (kyc_flags != 0) + PQ family => conflict (must be rejected).
    BOOST_CHECK(KycPqFamilyConflict(kyc, SPK_P2TR_V2));
    BOOST_CHECK(KycPqFamilyConflict(kyc, static_cast<uint16_t>(SPK_P2TR | SPK_P2TR_V2)));
    // Non-KYC (kyc_flags == 0) + PQ family => allowed (PQ is opt-in for non-KYC assets).
    BOOST_CHECK(!KycPqFamilyConflict(nonkyc, SPK_P2TR_V2));
    // The KYC_REQUIRED policy bit alone (without kyc_flags) is NOT a KYC asset here.
    BOOST_CHECK(!KycPqFamilyConflict(bitset_only, SPK_P2TR_V2));
    // KYC without PQ => allowed.
    BOOST_CHECK(!KycPqFamilyConflict(kyc, static_cast<uint16_t>(SPK_P2WPKH | SPK_P2TR)));
    BOOST_CHECK(!KycPqFamilyConflict(kyc, SPK_DEFAULT_ALLOWED));
    // The helper takes the whole IssuerReg, so a caller cannot pass policy_bits where
    // kyc_flags is meant (both are uint32_t) — the original bypass is unreachable.
}

BOOST_AUTO_TEST_SUITE_END()
