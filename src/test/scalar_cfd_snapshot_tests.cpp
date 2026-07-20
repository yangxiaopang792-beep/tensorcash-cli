// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/scalar_cfd_snapshot.h>

#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_snapshot_tests, BasicTestingSetup)

namespace {
uint256 U256(uint8_t b) { return uint256{std::vector<unsigned char>(32, b)}; }

// Shared committed coordinates / terms.
const uint256 U        = U256(0x11);
constexpr uint32_t FEED = 7;
constexpr uint64_t REF  = 1000;
const uint256 FALLBACK  = U256(0xBB);
const uint256 REAL      = U256(0xAA);
constexpr uint16_t FMT  = 1;          // SCALAR_FORMAT_RAW_U256_LE
constexpr int CTX = 200, MAT = 100, GRACE = 100;

constexpr uint8_t ISSUER = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
constexpr uint8_t CHAIN  = static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC);

ScalarCfdLeaf MakeLeaf(uint8_t source_type, uint32_t deadline)
{
    ScalarCfdLeaf leaf;
    leaf.source_type = source_type;
    leaf.underlying_asset_id = U;
    leaf.feed_id = FEED;
    leaf.fixing_ref = REF;
    leaf.publication_deadline_height = deadline;
    leaf.fallback_scalar = FALLBACK;
    leaf.scalar_format_id = FMT;
    return leaf;
}

ScalarFixingKey KeyOf(const ScalarCfdLeaf& leaf)
{
    return ScalarFixingKey{leaf.source_type, leaf.underlying_asset_id, leaf.feed_id, leaf.fixing_ref};
}

// Reader returning a real record (pub height + format configurable) only for the shared key.
ScalarReader RealReader(int pub_height, uint16_t fmt)
{
    return [pub_height, fmt](const uint256& a, uint32_t f, uint64_t e) -> std::optional<ScalarRecord> {
        if (a == U && f == FEED && e == REF) {
            ScalarRecord r;
            r.scalar = REAL;
            r.publication_height = pub_height;
            r.scalar_format_id = fmt;
            return r;
        }
        return std::nullopt;
    };
}

ScalarReader EmptyReader()
{
    return [](const uint256&, uint32_t, uint64_t) -> std::optional<ScalarRecord> { return std::nullopt; };
}
} // namespace

// ---- ScalarFixingSnapshot map behaviour -----------------------------------------------------

BOOST_AUTO_TEST_CASE(snapshot_add_get_and_miss)
{
    ScalarFixingSnapshot snap;
    BOOST_CHECK(snap.empty());

    const ScalarFixingKey k{ISSUER, U, FEED, REF};
    snap.Add(k, ResolvedScalar{REAL, FMT, /*is_fallback=*/false});
    BOOST_CHECK_EQUAL(snap.size(), 1u);

    const auto hit = snap.Get(k);
    BOOST_REQUIRE(hit);
    BOOST_CHECK(hit->scalar == REAL);
    BOOST_CHECK(!hit->is_fallback);

    // Any differing coordinate misses.
    BOOST_CHECK(!snap.Get(ScalarFixingKey{ISSUER, U, FEED + 1, REF}));
    BOOST_CHECK(!snap.Get(ScalarFixingKey{ISSUER, U, FEED, REF + 1}));
    BOOST_CHECK(!snap.Get(ScalarFixingKey{CHAIN, U, FEED, REF}));
    BOOST_CHECK(!snap.Get(ScalarFixingKey{ISSUER, U256(0x22), FEED, REF}));
}

// ---- AddResolvedScalarLeaf resolution glue --------------------------------------------------

BOOST_AUTO_TEST_CASE(issuer_real_fixing_is_added)
{
    const ScalarCfdLeaf leaf = MakeLeaf(ISSUER, /*deadline=*/150);
    ScalarFixingSnapshot snap;
    // Real fixing at height 50: buried (50 <= 200-100) and in-time (50 <= 150).
    BOOST_CHECK(AddResolvedScalarLeaf(leaf, CTX, MAT, GRACE, RealReader(/*pub=*/50, FMT), snap));

    const auto r = snap.Get(KeyOf(leaf));
    BOOST_REQUIRE(r);
    BOOST_CHECK(r->scalar == REAL);
    BOOST_CHECK_EQUAL(r->scalar_format_id, FMT);
    BOOST_CHECK(!r->is_fallback);
}

BOOST_AUTO_TEST_CASE(issuer_fallback_when_no_record_past_deadline)
{
    const ScalarCfdLeaf leaf = MakeLeaf(ISSUER, /*deadline=*/50); // 200 >= 50 + 100 grace
    ScalarFixingSnapshot snap;
    BOOST_CHECK(AddResolvedScalarLeaf(leaf, CTX, MAT, GRACE, EmptyReader(), snap));

    const auto r = snap.Get(KeyOf(leaf));
    BOOST_REQUIRE(r);
    BOOST_CHECK(r->scalar == FALLBACK);
    BOOST_CHECK(r->is_fallback);
}

BOOST_AUTO_TEST_CASE(issuer_pending_adds_no_entry)
{
    const ScalarCfdLeaf leaf = MakeLeaf(ISSUER, /*deadline=*/150); // 200 < 150 + 100 grace
    ScalarFixingSnapshot snap;
    BOOST_CHECK(!AddResolvedScalarLeaf(leaf, CTX, MAT, GRACE, EmptyReader(), snap));
    BOOST_CHECK(snap.empty());
    BOOST_CHECK(!snap.Get(KeyOf(leaf)));
}

BOOST_AUTO_TEST_CASE(real_fixing_wrong_format_falls_through_to_fallback)
{
    // A published record in a DIFFERENT encoding is unusable -> contract uses the committed
    // fallback (in the leaf's format), never reads bytes under the wrong encoding.
    const ScalarCfdLeaf leaf = MakeLeaf(ISSUER, /*deadline=*/50);
    ScalarFixingSnapshot snap;
    BOOST_CHECK(AddResolvedScalarLeaf(leaf, CTX, MAT, GRACE, RealReader(/*pub=*/40, /*fmt=*/999), snap));

    const auto r = snap.Get(KeyOf(leaf));
    BOOST_REQUIRE(r);
    BOOST_CHECK(r->scalar == FALLBACK);
    BOOST_CHECK(r->is_fallback);
}

BOOST_AUTO_TEST_CASE(chain_intrinsic_is_not_resolved_here)
{
    // CHAIN_INTRINSIC resolution is deferred to a later chain-reader slice: no entry -> the opcode
    // fails closed. Even with a (mis)matching reader present, nothing is added.
    const ScalarCfdLeaf leaf = MakeLeaf(CHAIN, /*deadline=*/150);
    ScalarFixingSnapshot snap;
    BOOST_CHECK(!AddResolvedScalarLeaf(leaf, CTX, MAT, GRACE, RealReader(/*pub=*/50, FMT), snap));
    BOOST_CHECK(snap.empty());
}

BOOST_AUTO_TEST_CASE(distinct_leaves_coexist)
{
    // The map supports multiple keys (robust if the one-settle-input rule ever relaxes): two leaves
    // differing only in fixing_ref each resolve independently.
    ScalarCfdLeaf a = MakeLeaf(ISSUER, /*deadline=*/50);
    ScalarCfdLeaf b = MakeLeaf(ISSUER, /*deadline=*/50);
    b.fixing_ref = REF + 1;

    ScalarFixingSnapshot snap;
    BOOST_CHECK(AddResolvedScalarLeaf(a, CTX, MAT, GRACE, EmptyReader(), snap)); // fallback
    BOOST_CHECK(AddResolvedScalarLeaf(b, CTX, MAT, GRACE, EmptyReader(), snap)); // fallback
    BOOST_CHECK_EQUAL(snap.size(), 2u);
    BOOST_CHECK(snap.Get(KeyOf(a)));
    BOOST_CHECK(snap.Get(KeyOf(b)));
}

// ---- Collateral policy surface (Slice 4a) ---------------------------------------------------
// The snapshot also carries each non-native collateral asset's resolved policy (§5.1). Slice 4a
// only stores/retrieves the raw fields faithfully; the GATE over them (the §2.3-step-4 verdict)
// is the interpreter's job in Slice 4c, so these tests assert STORAGE FIDELITY, not the gate.

BOOST_AUTO_TEST_CASE(collateral_policy_add_get_roundtrip)
{
    ScalarFixingSnapshot snap;
    const uint256 C = U256(0xC1);
    // A clean, gate-passing-shaped policy: the bit set, no kyc/tfr, no WRAP_REQUIRED.
    const ScalarCollateralPolicy pol{/*collateral_safe=*/true, /*kyc=*/0, /*tfr=*/0, /*icu=*/0};
    snap.AddCollateralPolicy(C, pol);

    const auto got = snap.GetCollateralPolicy(C);
    BOOST_REQUIRE(got);
    BOOST_CHECK(got->collateral_safe);
    BOOST_CHECK_EQUAL(got->kyc_flags, 0u);
    BOOST_CHECK_EQUAL(got->tfr_flags, 0u);
    BOOST_CHECK_EQUAL(got->icu_flags, 0u);

    // The scalar-fixing map is independent: adding a collateral policy does not make the snapshot
    // "non-empty" for the validation-layer attach decision.
    BOOST_CHECK(snap.empty());
    BOOST_CHECK_EQUAL(snap.size(), 0u);
}

BOOST_AUTO_TEST_CASE(collateral_policy_miss_is_fail_closed)
{
    ScalarFixingSnapshot snap;
    // An unstaged collateral asset resolves to nullopt -> the opcode's gate fails closed (§5.1).
    BOOST_CHECK(!snap.GetCollateralPolicy(U256(0xC2)));

    snap.AddCollateralPolicy(U256(0xC1), ScalarCollateralPolicy{true, 0, 0, 0});
    BOOST_CHECK(!snap.GetCollateralPolicy(U256(0xC2))); // still a miss for a different asset id
}

BOOST_AUTO_TEST_CASE(collateral_policy_preserves_constraint_fields)
{
    // Fields that the gate will REJECT on must round-trip verbatim (the snapshot stores raw flags,
    // not a verdict): a non-safe asset, and a safe asset carrying kyc/tfr/WRAP_REQUIRED.
    ScalarFixingSnapshot snap;
    const uint256 C_unsafe = U256(0xD0);
    const uint256 C_dirty  = U256(0xD1);
    snap.AddCollateralPolicy(C_unsafe, ScalarCollateralPolicy{/*safe=*/false, 0, 0, 0});
    snap.AddCollateralPolicy(C_dirty,  ScalarCollateralPolicy{/*safe=*/true, /*kyc=*/0x10, /*tfr=*/0x20, /*icu=*/0x0001});

    const auto u = snap.GetCollateralPolicy(C_unsafe);
    BOOST_REQUIRE(u);
    BOOST_CHECK(!u->collateral_safe);

    const auto d = snap.GetCollateralPolicy(C_dirty);
    BOOST_REQUIRE(d);
    BOOST_CHECK(d->collateral_safe);
    BOOST_CHECK_EQUAL(d->kyc_flags, 0x10u);
    BOOST_CHECK_EQUAL(d->tfr_flags, 0x20u);
    BOOST_CHECK_EQUAL(d->icu_flags, 0x0001u); // WRAP_REQUIRED preserved for the gate to reject
}

BOOST_AUTO_TEST_CASE(collateral_policy_gate_verdict)
{
    // CollateralPolicyGatePasses (§2.3 step 4): usable iff collateral_safe AND no kyc/tfr AND no
    // WRAP_REQUIRED. WRAP_REQUIRED is icu_flags bit 0x0001.
    constexpr uint32_t WRAP = 0x0001u;     // assets::WRAP_REQUIRED
    constexpr uint32_t OTHER_ICU = 0x0002u; // a non-WRAP icu flag (e.g. ICU_COMPRESSED) is harmless

    BOOST_CHECK(CollateralPolicyGatePasses(ScalarCollateralPolicy{/*safe=*/true, 0, 0, 0}));
    BOOST_CHECK(CollateralPolicyGatePasses(ScalarCollateralPolicy{true, 0, 0, OTHER_ICU})); // non-WRAP ok

    BOOST_CHECK(!CollateralPolicyGatePasses(ScalarCollateralPolicy{/*safe=*/false, 0, 0, 0}));      // no bit
    BOOST_CHECK(!CollateralPolicyGatePasses(ScalarCollateralPolicy{true, /*kyc=*/1, 0, 0}));         // kyc
    BOOST_CHECK(!CollateralPolicyGatePasses(ScalarCollateralPolicy{true, 0, /*tfr=*/1, 0}));         // tfr
    BOOST_CHECK(!CollateralPolicyGatePasses(ScalarCollateralPolicy{true, 0, 0, /*icu=*/WRAP}));      // WRAP_REQUIRED
    BOOST_CHECK(!CollateralPolicyGatePasses(ScalarCollateralPolicy{true, 0, 0, WRAP | OTHER_ICU}));  // WRAP among others
}

BOOST_AUTO_TEST_CASE(collateral_policy_last_write_wins)
{
    // Map semantics for a repeated key are last-write-wins. (In production the builder resolves each
    // collateral asset once, so a re-stage is identical by construction — but the container contract
    // is deterministic overwrite, so assert it with DIFFERENT values to actually prove the second
    // write wins rather than merely re-confirming an identical one.)
    ScalarFixingSnapshot snap;
    const uint256 C = U256(0xC3);
    snap.AddCollateralPolicy(C, ScalarCollateralPolicy{/*safe=*/false, /*kyc=*/0x10, /*tfr=*/0x20, /*icu=*/0x0001});
    snap.AddCollateralPolicy(C, ScalarCollateralPolicy{/*safe=*/true, /*kyc=*/0, /*tfr=*/0, /*icu=*/0});
    const auto got = snap.GetCollateralPolicy(C);
    BOOST_REQUIRE(got);
    BOOST_CHECK(got->collateral_safe);          // second (clean) policy won
    BOOST_CHECK_EQUAL(got->kyc_flags, 0u);
    BOOST_CHECK_EQUAL(got->tfr_flags, 0u);
    BOOST_CHECK_EQUAL(got->icu_flags, 0u);
}

BOOST_AUTO_TEST_SUITE_END()
