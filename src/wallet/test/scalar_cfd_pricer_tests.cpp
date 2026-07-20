// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Slice 5f-6b — the bilateral scalar-CFD mark-to-market pricer. The headline invariant: the pricer's loss
// fraction shares the CONSENSUS direction/denominator convention (ComputeScalarCfdPayout) — long loses
// X<K, short loses X>K, mode 0 denom K / mode 1 denom X. Plus intrinsic vs expected, the σ→0 collapse to
// the deterministic mark, MTM antisymmetry, delta sign, and the known-fixing deterministic path.

#include <wallet/pricing/scalar_cfd_pricer.h>

#include <arith_uint256.h>
#include <assets/asset.h>             // SCALAR_FORMAT_RAW_U256_LE
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT
#include <consensus/scalar_cfd.h>     // ComputeScalarCfdPayout, ScalarLossDenominator
#include <consensus/scalar_cfd_leaf.h>
#include <key.h>
#include <pubkey.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cmath>
#include <limits>

using namespace wallet;
using namespace wallet::pricing;

namespace {

uint256 Filled(unsigned char b) { uint256 u; std::fill(u.begin(), u.end(), b); return u; }
uint256 Raw(uint64_t v) { return ArithToUint256(arith_uint256(v)); }
CKey KeyFromSeed(uint8_t s)
{
    uint256 k; std::fill(k.begin(), k.end(), s); k.data()[0] = s; k.data()[31] = 0x01;
    CKey ck; ck.Set(k.begin(), k.end(), true); BOOST_REQUIRE(ck.IsValid()); return ck;
}
XOnlyPubKey XOnly(const CKey& k) { return XOnlyPubKey(k.GetPubKey()); }

ScalarCfdContractTerms ExampleTerms(uint8_t mode = static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE),
                                    uint64_t im = 10000)
{
    ScalarCfdContractTerms t;
    t.source_type = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
    t.payoff_mode = mode;
    t.underlying_asset_id = Filled(0xA1);
    t.feed_id = 7;
    t.fixing_ref = 1;
    t.publication_deadline_height = 1'000'000;
    t.settle_lock_height = 500;
    t.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    t.strike = Raw(100);
    t.fallback_scalar = Raw(95);
    t.collateral_asset_id = uint256{}; // native
    t.long_leg.im = im;  t.long_leg.lambda_q = 1u << 16;
    t.long_leg.owner_key = XOnly(KeyFromSeed(0x11));  t.long_leg.cp_key = XOnly(KeyFromSeed(0x22));
    t.short_leg.im = im; t.short_leg.lambda_q = 1u << 16;
    t.short_leg.owner_key = XOnly(KeyFromSeed(0x22)); t.short_leg.cp_key = XOnly(KeyFromSeed(0x11));
    return t;
}

ScalarCfdMarketInputs Mkt(uint64_t x_now, double forward, double sigma, double tau)
{
    ScalarCfdMarketInputs m;
    m.current_scalar = Raw(x_now);
    m.forward_cross_rate = forward;
    m.sigma = sigma;
    m.tau_years = tau;
    m.discount_factor = 1.0;
    return m;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_pricer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(loss_fraction_matches_consensus)
{
    // ScalarLossFraction must equal ComputeScalarCfdPayout's cp/vault_im in the SAME convention, away from
    // the dust boundary. Grid over X (X<K loss for long, X>K loss for short, flat, deep), both modes/dirs.
    const uint64_t im = 1'000'000; // big enough that no leg snaps to dust
    const arith_uint256 K = arith_uint256(100);
    for (uint8_t mode : {static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE),
                         static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)}) {
        const ScalarLossDenominator denom = mode == static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)
                                                ? ScalarLossDenominator::REALIZED : ScalarLossDenominator::STRIKE;
        for (uint64_t x : {60u, 80u, 95u, 100u, 105u, 120u, 140u}) {
            for (bool is_short : {false, true}) {
                ScalarCfdPayout p;
                BOOST_REQUIRE(ComputeScalarCfdPayout(K, arith_uint256(x), denom, 1u << 16, im, is_short,
                                                     static_cast<uint64_t>(MIN_SETTLE_OUTPUT), p));
                const double frac = ScalarLossFraction(static_cast<double>(x) / 100.0, 1u << 16, mode, is_short);
                const double model_cp = frac * static_cast<double>(im);
                // floor() in consensus vs continuous fraction -> within 1 unit.
                BOOST_CHECK_MESSAGE(std::abs(model_cp - static_cast<double>(p.payout_cp)) <= 1.0,
                    strprintf("mode=%d x=%d short=%d model_cp=%f consensus_cp=%llu", mode, (int)x, (int)is_short,
                              model_cp, (unsigned long long)p.payout_cp));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(intrinsic_direction_long_loses_below_strike)
{
    // X=80 < K=100: the LONG loses 20% of its IM; short is flat. Long net MTM = -2000.
    const ScalarCfdValuation v = ScalarCfdPricer::Price(ExampleTerms(), Mkt(80, /*forward=*/0.0, 0.0, 0.0));
    BOOST_REQUIRE(!v.model_unreliable);
    BOOST_CHECK_CLOSE(v.long_leg_intrinsic_cp_payout, 2000.0, 1e-6);   // 0.2 * 10000 to the short
    BOOST_CHECK_CLOSE(v.long_leg_intrinsic_owner_payout, 8000.0, 1e-6);
    BOOST_CHECK_CLOSE(v.short_leg_intrinsic_cp_payout, 0.0, 1e-9);     // short does not lose below strike
    BOOST_CHECK_CLOSE(v.intrinsic_long_mtm, -2000.0, 1e-6);
    BOOST_CHECK_CLOSE(v.intrinsic_short_mtm, 2000.0, 1e-6);
    BOOST_CHECK_CLOSE(v.current_ratio, 0.8, 1e-9);
}

BOOST_AUTO_TEST_CASE(intrinsic_direction_short_loses_above_strike)
{
    // X=120 > K=100: the SHORT loses 20%; long is flat. Long net MTM = +2000.
    const ScalarCfdValuation v = ScalarCfdPricer::Price(ExampleTerms(), Mkt(120, 0.0, 0.0, 0.0));
    BOOST_CHECK_CLOSE(v.short_leg_intrinsic_cp_payout, 2000.0, 1e-6); // 0.2 * 10000 to the long
    BOOST_CHECK_CLOSE(v.long_leg_intrinsic_cp_payout, 0.0, 1e-9);
    BOOST_CHECK_CLOSE(v.intrinsic_long_mtm, 2000.0, 1e-6);
}

BOOST_AUTO_TEST_CASE(expected_collapses_to_intrinsic_at_zero_vol)
{
    // Flat forward (0) + σ=0 -> exact consensus expected == intrinsic.
    const ScalarCfdValuation v = ScalarCfdPricer::Price(ExampleTerms(), Mkt(80, 0.0, 0.0, 0.0));
    BOOST_CHECK_CLOSE(v.expected_long_mtm, v.intrinsic_long_mtm, 1e-6);

    // Model path (curve forward = current) with σ→0 also collapses to the deterministic fraction.
    const ScalarCfdValuation vm = ScalarCfdPricer::Price(ExampleTerms(), Mkt(80, /*forward=*/80.0, /*sigma=*/0.0, 0.5));
    BOOST_CHECK_CLOSE(vm.long_leg_expected_cp_payout, 2000.0, 1e-6);
}

BOOST_AUTO_TEST_CASE(stochastic_mark_and_greeks)
{
    // Forward below strike (long in the loss zone), positive vol -> finite model MTM + greeks.
    const ScalarCfdValuation v = ScalarCfdPricer::Price(ExampleTerms(), Mkt(90, /*forward=*/90.0, /*sigma=*/0.4, /*tau=*/0.5));
    BOOST_REQUIRE(!v.model_unreliable);
    BOOST_CHECK(std::isfinite(v.expected_long_mtm));
    BOOST_CHECK_CLOSE(v.expected_short_mtm, -v.expected_long_mtm, 1e-9); // antisymmetry
    // Long loses as X falls -> long MTM rises with X -> positive delta to the cross rate.
    BOOST_CHECK_GT(v.long_delta_to_cross_rate, 0.0);
    BOOST_CHECK_CLOSE(v.short_delta_to_cross_rate, -v.long_delta_to_cross_rate, 1e-9);
    BOOST_CHECK(std::isfinite(v.long_vega));
    BOOST_CHECK(std::isfinite(v.long_theta));
    BOOST_CHECK_CLOSE(v.forecast_ratio, 0.9, 1e-9);
}

BOOST_AUTO_TEST_CASE(known_fixing_is_deterministic)
{
    // realized scalar set -> sigma ignored, expected == intrinsic-at-realized, no greeks.
    ScalarCfdMarketInputs m = Mkt(100, /*forward=*/200.0, /*sigma=*/0.9, /*tau=*/1.0);
    m.realized_scalar = Raw(120); // short loses 20%
    const ScalarCfdValuation v = ScalarCfdPricer::Price(ExampleTerms(), m);
    BOOST_REQUIRE(v.fixing_reached);
    BOOST_CHECK_CLOSE(v.expected_long_mtm, 2000.0, 1e-6); // long gains the short's 20% loss
    BOOST_CHECK_SMALL(v.long_delta_to_cross_rate, 1e-12); // greeks skipped at a known fixing
}

BOOST_AUTO_TEST_CASE(realized_mode_uses_X_denominator)
{
    // Mode 1 (REALIZED): at X=80, long fraction = lambda*|X-K|/X = 20/80 = 0.25 -> cp 2500 (vs 2000 mode 0).
    const ScalarCfdValuation v = ScalarCfdPricer::Price(
        ExampleTerms(static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)), Mkt(80, 0.0, 0.0, 0.0));
    BOOST_CHECK_CLOSE(v.long_leg_intrinsic_cp_payout, 2500.0, 1e-6);
}

BOOST_AUTO_TEST_CASE(fails_closed_on_malformed_market_data)
{
    const ScalarCfdContractTerms t = ExampleTerms();
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    auto bad = [&](ScalarCfdMarketInputs m) { return ScalarCfdPricer::Price(t, m).model_unreliable; };
    { auto m = Mkt(80, 0.0, 0.0, 0.0); m.discount_factor = nan; BOOST_CHECK(bad(m)); }
    { auto m = Mkt(80, 0.0, 0.0, 0.0); m.discount_factor = -1.0; BOOST_CHECK(bad(m)); }
    { auto m = Mkt(80, 0.0, 0.0, 0.0); m.discount_factor = inf; BOOST_CHECK(bad(m)); }
    BOOST_CHECK(bad(Mkt(80, nan, 0.0, 0.0)));   // non-finite forward
    BOOST_CHECK(bad(Mkt(80, -5.0, 0.0, 0.0)));  // negative forward
    BOOST_CHECK(bad(Mkt(80, 0.0, nan, 0.5)));   // non-finite sigma
    BOOST_CHECK(bad(Mkt(80, 0.0, -0.1, 0.5)));  // negative sigma
    BOOST_CHECK(bad(Mkt(80, 0.0, 0.3, inf)));   // non-finite tau
    BOOST_CHECK(!bad(Mkt(80, 0.0, 0.0, 0.0)));  // clean inputs price fine
}

BOOST_AUTO_TEST_CASE(loss_fraction_fails_closed_on_unknown_mode)
{
    BOOST_CHECK(std::isnan(ScalarLossFraction(0.8, 1u << 16, /*mode=*/2, false)));
    BOOST_CHECK(std::isnan(ScalarLossFraction(1.2, 1u << 16, /*mode=*/99, true)));
    BOOST_CHECK(!std::isnan(ScalarLossFraction(0.8, 1u << 16, 0, false))); // STRIKE
    BOOST_CHECK(!std::isnan(ScalarLossFraction(0.8, 1u << 16, 1, false))); // REALIZED
}

BOOST_AUTO_TEST_SUITE_END()
