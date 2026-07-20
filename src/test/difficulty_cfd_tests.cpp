// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <consensus/difficulty_cfd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(difficulty_cfd_tests, BasicTestingSetup)

namespace {
constexpr bool LONG_LEG = false;   // DOWN: loses as difficulty falls  (realized_target > strike_target)
constexpr bool SHORT_LEG = true;   // UP:   loses as difficulty rises  (realized_target < strike_target)
constexpr uint32_t LAMBDA_X10 = 10 * static_cast<uint32_t>(DIFFCFD_LAMBDA_SCALE); // lambda = 10, Q16
constexpr uint32_t LAMBDA_X1 = 1 * static_cast<uint32_t>(DIFFCFD_LAMBDA_SCALE);    // lambda = 1, Q16

// Build targets directly as small integers so each golden vector has an EXACT rational move and the
// expected payout is hand-computable (the production code never linearizes — it is a 512-bit floor).
void CheckPayout(const char* label,
                 uint64_t strike_target, uint64_t realized_target,
                 uint32_t lambda_q, uint64_t vault_im, bool short_leg,
                 uint64_t expect_owner, uint64_t expect_cp)
{
    DiffCfdPayout out;
    const bool ok = ComputeDiffCfdPayout(arith_uint256{strike_target}, arith_uint256{realized_target},
                                         lambda_q, vault_im, short_leg, out);
    BOOST_CHECK_MESSAGE(ok, label << ": ComputeDiffCfdPayout returned false unexpectedly");
    BOOST_CHECK_MESSAGE(out.payout_owner == expect_owner,
                        label << ": owner " << out.payout_owner << " != " << expect_owner);
    BOOST_CHECK_MESSAGE(out.payout_cp == expect_cp,
                        label << ": cp " << out.payout_cp << " != " << expect_cp);
    // Conservation: the two legs always sum back to the posted margin.
    BOOST_CHECK_MESSAGE(out.payout_owner + out.payout_cp == vault_im,
                        label << ": legs do not sum to vault_im");
}
} // namespace

// §1.3 golden-vector table — both legs, both clamp directions, flat, full liquidation, a >+100%
// move (num > denom), and both dust-snap directions.
BOOST_AUTO_TEST_CASE(golden_vectors)
{
    const uint64_t IM = 1'000'000'000; // 10 TSC at 1e8 sat/TSC

    // short leg, difficulty +5%: K = 1.05*S (strike target 5% above realized) -> lambda*move = 0.5
    CheckPayout("short +5%", /*K=*/21, /*S=*/20, LAMBDA_X10, IM, SHORT_LEG, /*owner=*/500'000'000, /*cp=*/500'000'000);

    // short leg, difficulty +10%: lambda*move == 1.0 exactly -> boundary resolves to full liquidation
    CheckPayout("short +10% (boundary)", /*K=*/22, /*S=*/20, LAMBDA_X10, IM, SHORT_LEG, /*owner=*/0, /*cp=*/IM);

    // short leg, difficulty +12%: lambda*move = 1.2 -> clamp to full liquidation
    CheckPayout("short +12% (clamp)", /*K=*/28, /*S=*/25, LAMBDA_X10, IM, SHORT_LEG, /*owner=*/0, /*cp=*/IM);

    // short leg, difficulty flat (realized == strike): owner keeps full margin, no cp output
    CheckPayout("short flat", /*K=*/20, /*S=*/20, LAMBDA_X10, IM, SHORT_LEG, /*owner=*/IM, /*cp=*/0);

    // short leg, difficulty DOWN (in-the-money for short): realized target rises above strike -> owner full
    CheckPayout("short in-the-money", /*K=*/20, /*S=*/21, LAMBDA_X10, IM, SHORT_LEG, /*owner=*/IM, /*cp=*/0);

    // long leg, difficulty -5%: realized target 5% above strike -> lambda*move = 0.5
    CheckPayout("long -5%", /*K=*/19, /*S=*/20, LAMBDA_X10, IM, LONG_LEG, /*owner=*/500'000'000, /*cp=*/500'000'000);

    // long leg, difficulty UP (in-the-money for long): realized target below strike -> owner full
    CheckPayout("long in-the-money", /*K=*/21, /*S=*/20, LAMBDA_X10, IM, LONG_LEG, /*owner=*/IM, /*cp=*/0);

    // lambda = 1, move = 0.5 (no clamp): cp = floor(0.5 * IM)
    CheckPayout("lambda1 +50%", /*K=*/30, /*S=*/20, LAMBDA_X1, IM, SHORT_LEG, /*owner=*/500'000'000, /*cp=*/500'000'000);

    // lambda = 1, move = +200% (num > denom): exercises the >256-bit intermediate + clamp
    CheckPayout("lambda1 +200% (num>denom)", /*K=*/60, /*S=*/20, LAMBDA_X1, IM, SHORT_LEG, /*owner=*/0, /*cp=*/IM);
}

// Dust-snap: a non-zero leg below MIN_SETTLE_OUTPUT is snapped to 0, its value going to the
// surviving leg, so no non-zero covenant output is ever sub-dust.
BOOST_AUTO_TEST_CASE(dust_snap)
{
    // cp computes to 273 (= 0.5 * 546) which is < MIN_SETTLE_OUTPUT -> snapped to owner.
    CheckPayout("cp dust -> owner", /*K=*/21, /*S=*/20, LAMBDA_X10, /*vault_im=*/546, SHORT_LEG,
                /*owner=*/546, /*cp=*/0);

    // owner computes to 6 (vault_im 600, fraction 0.99 -> cp 594) which is < MIN_SETTLE_OUTPUT ->
    // snapped to cp.
    CheckPayout("owner dust -> cp", /*K=*/1099, /*S=*/1000, LAMBDA_X10, /*vault_im=*/600, SHORT_LEG,
                /*owner=*/0, /*cp=*/600);
}

// Invalid committed terms are rejected (the opcode maps these to SCRIPT_ERR_DIFFCFD_TERMS).
BOOST_AUTO_TEST_CASE(invalid_terms)
{
    DiffCfdPayout out;
    BOOST_CHECK(!ComputeDiffCfdPayout(arith_uint256{21}, arith_uint256{20}, /*lambda_q=*/0, 1'000'000'000, SHORT_LEG, out));
    BOOST_CHECK(!ComputeDiffCfdPayout(arith_uint256{21}, arith_uint256{20}, LAMBDA_X10, /*vault_im=*/MIN_SETTLE_OUTPUT - 1, SHORT_LEG, out));
    BOOST_CHECK(!ComputeDiffCfdPayout(arith_uint256{21}, arith_uint256{0}, LAMBDA_X10, 1'000'000'000, SHORT_LEG, out)); // zero realized target
}

// Full-width sanity: a 256-bit realized target with a one-ulp move must not overflow or truncate in
// the 512-bit intermediate. With lambda = 1 and a tiny move the payout floors to 0.
BOOST_AUTO_TEST_CASE(wide_target_no_overflow)
{
    arith_uint256 big = arith_uint256{1} << 224;   // wide target, ~regtest-scale powLimit magnitude
    arith_uint256 strike = big + arith_uint256{1};  // realized = big, strike one ulp higher (short ITM-ish)
    DiffCfdPayout out;
    // short leg: realized(big) < strike(big+1) -> num = 1, denom = big -> floor(~0) = 0 -> owner full.
    BOOST_CHECK(ComputeDiffCfdPayout(strike, big, LAMBDA_X1, 1'000'000'000, SHORT_LEG, out));
    BOOST_CHECK_EQUAL(out.payout_cp, 0u);
    BOOST_CHECK_EQUAL(out.payout_owner, 1'000'000'000u);
}

// Maturity / burial boundary (DiffCfdFixingResolvable): a fixing is resolvable iff
// 0 <= H < context_height AND H <= context_height - maturity_depth. This is the consensus burial
// rule applied identically in block validation and mempool.
BOOST_AUTO_TEST_CASE(fixing_resolvable_boundary)
{
    const int ctx = 1000;
    const int depth = DIFFCFD_MATURITY_DEPTH; // 100

    // Exact maturity boundary: H == ctx - depth accepted; H == ctx - depth + 1 rejected.
    BOOST_CHECK(DiffCfdFixingResolvable(ctx - depth, ctx, depth));       // 900 ok
    BOOST_CHECK(!DiffCfdFixingResolvable(ctx - depth + 1, ctx, depth));  // 901 too recent
    BOOST_CHECK(!DiffCfdFixingResolvable(ctx - 1, ctx, depth));          // 999 too recent

    // Strict upper bound: never the anchor itself or the future.
    BOOST_CHECK(!DiffCfdFixingResolvable(ctx, ctx, /*depth=*/0));
    BOOST_CHECK(!DiffCfdFixingResolvable(ctx + 5, ctx, depth));
    BOOST_CHECK(DiffCfdFixingResolvable(ctx - 1, ctx, /*depth=*/0));     // depth 0 -> only strict <

    // Negative / zero heights.
    BOOST_CHECK(!DiffCfdFixingResolvable(-1, ctx, depth));
    BOOST_CHECK(DiffCfdFixingResolvable(0, ctx, depth));
}

BOOST_AUTO_TEST_SUITE_END()
