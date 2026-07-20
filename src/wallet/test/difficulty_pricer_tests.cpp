// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/difficulty_cfd.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <wallet/difficulty_contract.h>
#include <wallet/pricing/difficulty_curve.h>
#include <wallet/pricing/difficulty_pricer.h>
#include <wallet/pricing/difficulty_vol_surface.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <memory>
#include <vector>

namespace wallet {
namespace pricing {

struct DifficultyPricerTestFixture : public WalletTestingSetup {
    std::unique_ptr<PricingContext> ctx;
    uint256 pow_limit;
    uint32_t base_nbits{0};   //!< a valid compact target for this chain (== powLimit-ish genesis)

    DifficultyPricerTestFixture() : WalletTestingSetup(ChainType::REGTEST)
    {
        ctx = std::make_unique<PricingContext>(m_wallet);
        pow_limit = Params().GetConsensus().powLimit;
        base_nbits = Params().GenesisBlock().nBits;
    }

    DifficultyMarketInputs MakeMkt(uint32_t current_nbits, int current_height)
    {
        DifficultyMarketInputs mkt;
        mkt.current_nbits = current_nbits;
        mkt.current_height = current_height;
        mkt.pow_limit = pow_limit;
        mkt.pow_target_spacing = Params().GetConsensus().nPowTargetSpacing;
        mkt.current_time = GetTime();
        mkt.source = PriceSource::MARKET;
        return mkt;
    }

    //! A compact target with 2x the base difficulty (half the target), guaranteed <= powLimit.
    uint32_t harder_nbits() const
    {
        const auto t = DeriveTarget(base_nbits, pow_limit);
        BOOST_REQUIRE(t.has_value());
        arith_uint256 half = *t;
        half >>= 1;  // half the target == 2x difficulty; stays arith_uint256 for GetCompact()
        return half.GetCompact();
    }

    DifficultyContractTerms MakeCfd(uint32_t strike_nbits, uint32_t fixing_height) const
    {
        DifficultyContractTerms t;
        t.kind = DIFFICULTY_KIND_CFD;
        t.strike_nbits = strike_nbits;
        t.fixing_height = fixing_height;
        t.settle_lock_height = fixing_height + DIFFCFD_MATURITY_DEPTH;
        t.long_leg.im = 100000000;  t.long_leg.lambda_q = 10u * 65536u;
        t.short_leg.im = 100000000; t.short_leg.lambda_q = 10u * 65536u;
        return t;
    }

    void AddVol(double sigma)
    {
        DifficultyVolSurface surf;
        surf.horizons_blocks = {1, 1000000};
        surf.sigmas = {sigma, sigma};
        surf.timestamp = GetTime();
        surf.source = PriceSource::MARKET;
        BOOST_REQUIRE(ctx->AddDifficultyVolSurface(surf));
    }

    //! Compact target == base target (powLimit) scaled by num/den (always <= powLimit for num<=den).
    uint32_t nbits_scaled(uint32_t num, uint32_t den) const
    {
        const auto t = DeriveTarget(base_nbits, pow_limit);
        BOOST_REQUIRE(t.has_value());
        arith_uint256 scaled = *t;
        scaled /= arith_uint256(den);
        scaled *= num;
        if (scaled == 0) scaled = arith_uint256(1);
        return scaled.GetCompact();
    }

    //! A two-leg CFD with a far-future fixing (always forecasting, never 'fixed').
    DifficultyContractTerms cfd(uint32_t strike_nbits, CAmount im, uint32_t lambda_q) const
    {
        DifficultyContractTerms t;
        t.kind = DIFFICULTY_KIND_CFD;
        t.strike_nbits = strike_nbits;
        t.fixing_height = 100000;
        t.settle_lock_height = t.fixing_height + DIFFCFD_MATURITY_DEPTH;
        t.long_leg.im = im;  t.long_leg.lambda_q = lambda_q;
        t.short_leg.im = im; t.short_leg.lambda_q = lambda_q;
        return t;
    }

    //! The pricer's intrinsic payouts (ExactQuote at the current target) must equal the consensus
    //! ComputeDiffCfdPayout leg-for-leg, and no nonzero payout may sit below the dust floor.
    void check_intrinsic_matches_consensus(const DifficultyContractTerms& terms, uint32_t current_nbits)
    {
        auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current_nbits, /*height=*/10), /*greeks=*/false);
        BOOST_REQUIRE(!v.model_unreliable);
        const auto st = DeriveTarget(terms.strike_nbits, pow_limit);
        const auto cur = DeriveTarget(current_nbits, pow_limit);
        BOOST_REQUIRE(st && cur);
        DiffCfdPayout lp, sp;
        BOOST_REQUIRE(ComputeDiffCfdPayout(*st, *cur, terms.long_leg.lambda_q,
                                           (uint64_t)terms.long_leg.im, /*short=*/false, lp));
        BOOST_REQUIRE(ComputeDiffCfdPayout(*st, *cur, terms.short_leg.lambda_q,
                                           (uint64_t)terms.short_leg.im, /*short=*/true, sp));
        BOOST_CHECK_EQUAL(v.long_leg_intrinsic_owner_payout, (double)lp.payout_owner);
        BOOST_CHECK_EQUAL(v.long_leg_intrinsic_cp_payout, (double)lp.payout_cp);
        BOOST_CHECK_EQUAL(v.short_leg_intrinsic_owner_payout, (double)sp.payout_owner);
        BOOST_CHECK_EQUAL(v.short_leg_intrinsic_cp_payout, (double)sp.payout_cp);
        for (double p : {v.long_leg_intrinsic_owner_payout, v.long_leg_intrinsic_cp_payout,
                         v.short_leg_intrinsic_owner_payout, v.short_leg_intrinsic_cp_payout}) {
            BOOST_CHECK(p == 0.0 || p >= (double)MIN_SETTLE_OUTPUT);  // dust invariant
        }
    }
};

BOOST_FIXTURE_TEST_SUITE(difficulty_pricer_tests, DifficultyPricerTestFixture)

// Finding 1: with no curve and no vol, the expected MTM is settled through the EXACT consensus
// ComputeDiffCfdPayout — so it equals the intrinsic MTM bit-for-bit (no continuous-approx drift).
BOOST_AUTO_TEST_CASE(no_surface_expected_equals_exact_intrinsic)
{
    const uint32_t strike = base_nbits;       // powLimit-side (lowest difficulty)
    const uint32_t current = harder_nbits();  // 2x difficulty => realized target < strike => short loses
    auto terms = MakeCfd(strike, /*fixing_height=*/1000);
    auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current, /*current_height=*/10), /*greeks=*/true);

    BOOST_REQUIRE(!v.model_unreliable);
    BOOST_CHECK_EQUAL(v.forward_provenance, "flat");
    BOOST_CHECK(!v.fixing_reached);
    BOOST_CHECK_EQUAL(v.sigma, 0.0);
    // Exact-fallback invariant (df == 1, no native curve in this context).
    BOOST_CHECK_EQUAL(v.expected_long_mtm, v.intrinsic_long_mtm);
    BOOST_CHECK_EQUAL(v.expected_short_mtm, v.intrinsic_short_mtm);
    BOOST_CHECK_EQUAL(v.expected_long_mtm, -v.expected_short_mtm);
    BOOST_CHECK(v.expected_long_mtm > 0.0);  // non-trivial: long wins as difficulty rose above strike
}

// E[payout(R)] != payout(E[R]): an ATM option has positive time value once a vol surface exists,
// where the deterministic point forecast returns ~0. Buyer MTM strictly increases; vega > 0.
BOOST_AUTO_TEST_CASE(option_time_value_positive_with_vol)
{
    DifficultyContractTerms t;
    t.kind = DIFFICULTY_KIND_OPTION;
    t.strike_nbits = base_nbits;              // strike == current => ATM (R = 1)
    t.fixing_height = 2000;
    t.settle_lock_height = 2000 + DIFFCFD_MATURITY_DEPTH;
    t.short_leg.im = 100000000; t.short_leg.lambda_q = 2u * 65536u;  // writer = short
    t.premium = 1000000;
    auto mkt = MakeMkt(base_nbits, /*current_height=*/0);

    // No vol -> deterministic ATM -> writer cp = 0 -> buyer MTM = -premium (exact fallback).
    auto v0 = DifficultyPricer::Price(t, *ctx, mkt, /*greeks=*/true);
    BOOST_REQUIRE(!v0.model_unreliable);
    BOOST_CHECK_EQUAL(v0.expected_buyer_mtm, v0.intrinsic_buyer_mtm);
    BOOST_CHECK_CLOSE(v0.intrinsic_buyer_mtm, -1000000.0, 1e-6);

    // With vol -> positive time value.
    AddVol(0.6);
    auto v1 = DifficultyPricer::Price(t, *ctx, mkt, /*greeks=*/true);
    BOOST_CHECK(v1.sigma > 0.0);
    BOOST_CHECK(v1.tau_years > 0.0);
    BOOST_CHECK_GT(v1.expected_buyer_mtm, v0.expected_buyer_mtm);
    BOOST_CHECK_GT(v1.buyer_vega, 0.0);
    BOOST_CHECK_EQUAL(v1.expected_writer_mtm, -v1.expected_buyer_mtm);
}

// Finding/§10.5: once the fixing height is buried, the underlying is known -> deterministic, vol ignored.
BOOST_AUTO_TEST_CASE(fixing_reached_is_deterministic)
{
    auto terms = MakeCfd(base_nbits, /*fixing_height=*/5);
    auto mkt = MakeMkt(base_nbits, /*current_height=*/200);  // current >= fixing
    mkt.realized_nbits = harder_nbits();                     // realized difficulty != strike
    AddVol(0.6);                                             // present, but must be ignored

    auto v = DifficultyPricer::Price(terms, *ctx, mkt, /*greeks=*/true);
    BOOST_CHECK(v.fixing_reached);
    BOOST_CHECK_EQUAL(v.forward_provenance, "fixed");
    BOOST_CHECK_EQUAL(v.sigma, 0.0);
    BOOST_CHECK_EQUAL(v.long_delta_to_difficulty, 0.0);  // greeks skipped when the fixing is known
    BOOST_CHECK(v.expected_long_mtm > 0.0);              // realized > strike difficulty => long wins

    // Deterministic == the exact consensus payout at the realized target.
    const auto strike_t = DeriveTarget(base_nbits, pow_limit);
    const auto realized_t = DeriveTarget(*mkt.realized_nbits, pow_limit);
    BOOST_REQUIRE(strike_t && realized_t);
    DiffCfdPayout sp; DiffCfdPayout lp;
    BOOST_REQUIRE(ComputeDiffCfdPayout(*strike_t, *realized_t, terms.short_leg.lambda_q,
                                       (uint64_t)terms.short_leg.im, /*short=*/true, sp));
    BOOST_REQUIRE(ComputeDiffCfdPayout(*strike_t, *realized_t, terms.long_leg.lambda_q,
                                       (uint64_t)terms.long_leg.im, /*short=*/false, lp));
    // long net = long owner + short cp - long im  (df == 1 here).
    const double exact_long = (double)lp.payout_owner + (double)sp.payout_cp - (double)terms.long_leg.im;
    BOOST_CHECK_EQUAL(v.expected_long_mtm, exact_long);
}

// --- Consensus-adjacent payout edge cases (guard the pricer's ExactQuote -> ComputeDiffCfdPayout path).

// Full liquidation: difficulty up past the band (lambda*(R-1) >= 1) -> losing leg pays its whole IM.
BOOST_AUTO_TEST_CASE(intrinsic_full_liquidation)
{
    const CAmount im = 100000000;
    auto terms = cfd(base_nbits, im, 2u * 65536u);   // lambda = 2
    const uint32_t current = nbits_scaled(1, 2);     // R = 2 -> short f = clamp(2*1) = 1
    check_intrinsic_matches_consensus(terms, current);
    auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current, 10), false);
    BOOST_CHECK_EQUAL(v.short_leg_intrinsic_cp_payout, (double)im);    // short fully liquidated
    BOOST_CHECK_EQUAL(v.short_leg_intrinsic_owner_payout, 0.0);
    BOOST_CHECK_EQUAL(v.long_leg_intrinsic_cp_payout, 0.0);            // long out-of-the-money
    BOOST_CHECK_EQUAL(v.long_leg_intrinsic_owner_payout, (double)im);
}

// >+100% move (num > denom): still clamped to the full IM, no overflow in the 512-bit path.
BOOST_AUTO_TEST_CASE(intrinsic_over_100pct_move_clamps)
{
    const CAmount im = 100000000;
    auto terms = cfd(base_nbits, im, 65536);         // lambda = 1
    const uint32_t current = nbits_scaled(1, 3);     // R = 3 -> short f = clamp(2) = 1
    check_intrinsic_matches_consensus(terms, current);
    auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current, 10), false);
    BOOST_CHECK_EQUAL(v.short_leg_intrinsic_cp_payout, (double)im);
}

// Partial loss inside the band -> a strictly partial transfer.
BOOST_AUTO_TEST_CASE(intrinsic_partial_in_band)
{
    const CAmount im = 100000000;
    auto terms = cfd(base_nbits, im, 2u * 65536u);   // lambda = 2
    const uint32_t current = nbits_scaled(4, 5);     // R ~ 1.25 -> short f ~ 0.5
    check_intrinsic_matches_consensus(terms, current);
    auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current, 10), false);
    BOOST_CHECK_GT(v.short_leg_intrinsic_cp_payout, 0.0);
    BOOST_CHECK_LT(v.short_leg_intrinsic_cp_payout, (double)im);
}

// Dust snap: a sub-MIN_SETTLE_OUTPUT loss collapses to the surviving leg (no dust output is emitted).
BOOST_AUTO_TEST_CASE(intrinsic_dust_snaps_to_surviving_leg)
{
    const CAmount im = MIN_SETTLE_OUTPUT;            // 546: any partial loss is sub-dust on both sides
    auto terms = cfd(base_nbits, im, 65536);         // lambda = 1
    const uint32_t current = nbits_scaled(4, 5);     // R ~ 1.25 -> short cp ~ 136 in (0, 546)
    check_intrinsic_matches_consensus(terms, current);
    auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current, 10), false);
    BOOST_CHECK_EQUAL(v.short_leg_intrinsic_cp_payout, 0.0);           // snapped away
    BOOST_CHECK_EQUAL(v.short_leg_intrinsic_owner_payout, (double)im); // value to the owner
}

// lambda < 1: the losing leg can never fully liquidate (max loss = lambda * IM < IM).
BOOST_AUTO_TEST_CASE(lambda_below_one_never_fully_liquidates)
{
    const CAmount im = 100000000;
    auto terms = cfd(nbits_scaled(1, 1u << 20), im, 32768);  // lambda = 0.5, strike very hard
    const uint32_t current = base_nbits;             // R ~ 2^-20 -> deep long loss
    check_intrinsic_matches_consensus(terms, current);
    auto v = DifficultyPricer::Price(terms, *ctx, MakeMkt(current, 10), false);
    BOOST_CHECK_GT(v.long_leg_intrinsic_cp_payout, 0.0);
    BOOST_CHECK_LT(v.long_leg_intrinsic_cp_payout, (double)im);        // capped below full IM
}

// Stochastic cap: a deep-ITM forward saturates the call spread -> expected cp -> the full IM.
BOOST_AUTO_TEST_CASE(stochastic_deep_itm_cp_caps_at_im)
{
    const CAmount im = 100000000;
    DifficultyContractTerms terms;
    terms.kind = DIFFICULTY_KIND_CFD;
    terms.strike_nbits = base_nbits;
    terms.fixing_height = 20;                         // small horizon -> small sigma*sqrt(tau)
    terms.settle_lock_height = 20 + DIFFCFD_MATURITY_DEPTH;
    terms.long_leg.im = im;  terms.long_leg.lambda_q = 2u * 65536u;
    terms.short_leg.im = im; terms.short_leg.lambda_q = 2u * 65536u;
    AddVol(0.5);

    DifficultyMarketInputs mkt = MakeMkt(base_nbits, /*height=*/0);
    mkt.forecast_nbits_override = nbits_scaled(1, 5); // forward target T0/5 -> F_R = 5 (deep ITM short)
    auto v = DifficultyPricer::Price(terms, *ctx, mkt, true);

    BOOST_CHECK(v.sigma > 0.0);
    BOOST_CHECK(v.tau_years > 0.0);
    BOOST_CHECK(!v.fixing_reached);
    BOOST_CHECK_GT(v.short_leg_expected_cp_payout, 0.95 * (double)im);
    BOOST_CHECK_LE(v.short_leg_expected_cp_payout, (double)im + 1.0);
}

// Wide (regtest powLimit-scale) targets must not blow up the chainwork/ratio math.
BOOST_AUTO_TEST_CASE(wide_powlimit_target_stochastic_is_finite)
{
    const CAmount im = 100000000;
    auto terms = cfd(base_nbits, im, 2u * 65536u);   // strike at powLimit scale
    AddVol(0.6);
    DifficultyMarketInputs mkt = MakeMkt(base_nbits, /*height=*/0);  // fixing far -> tau > 0
    auto v = DifficultyPricer::Price(terms, *ctx, mkt, true);
    BOOST_CHECK(!v.model_unreliable);
    BOOST_CHECK(std::isfinite(v.expected_long_mtm));
    BOOST_CHECK(std::isfinite(v.expected_short_mtm));
    BOOST_CHECK(std::isfinite(v.long_delta_to_difficulty));
    BOOST_CHECK(std::isfinite(v.long_vega));
    BOOST_CHECK(std::isfinite(v.forecast_difficulty_ratio));
}

BOOST_AUTO_TEST_SUITE_END()

// Pure model/calibration helpers (no chain needed).
BOOST_AUTO_TEST_SUITE(difficulty_model_tests)

BOOST_AUTO_TEST_CASE(model_curve_projects_expected_drift)
{
    const double d_now = 1.0e12;
    const double drift = 1e-5;  // per block
    const std::vector<uint32_t> horizons = {100, 200, 400};
    auto c = BuildModelDifficultyCurve(d_now, drift, horizons, /*ts=*/123);

    BOOST_CHECK(c.provenance == DiffCurveProvenance::MODEL);
    BOOST_REQUIRE_EQUAL(c.forward_difficulties.size(), 3u);
    for (size_t i = 0; i < horizons.size(); ++i) {
        BOOST_CHECK_CLOSE(c.forward_difficulties[i], d_now * std::exp(drift * horizons[i]), 1e-9);
    }
    BOOST_CHECK(!c.Validate());
    BOOST_CHECK_GT(c.forward_difficulties[2], c.forward_difficulties[0]);  // positive drift
}

BOOST_AUTO_TEST_CASE(estimate_stats_pure_exponential_zero_vol)
{
    // D_i = D0 * r^i (constant ratio) -> zero vol, drift = ln(r)/stride.
    const double r = 1.10;
    const uint32_t stride = 2016;
    const int64_t spacing = 600;
    std::vector<double> works;
    double d = 1e6;
    for (int i = 0; i < 10; ++i) { works.push_back(d); d *= r; }

    auto s = EstimateDifficultyHistoryStats(works, stride, spacing);
    BOOST_CHECK_EQUAL(s.samples, 9u);
    BOOST_CHECK_CLOSE(s.mean_drift_per_block, std::log(r) / stride, 1e-6);
    BOOST_CHECK_SMALL(s.sigma_annual, 1e-9);
}

BOOST_AUTO_TEST_CASE(estimate_stats_nonzero_vol)
{
    const uint32_t stride = 2016;
    const int64_t spacing = 600;
    std::vector<double> works = {1e6};
    double d = 1e6;
    for (double u : {1.2, 0.9, 1.15, 0.95, 1.1, 0.92}) { d *= u; works.push_back(d); }

    auto s = EstimateDifficultyHistoryStats(works, stride, spacing);
    BOOST_CHECK_EQUAL(s.samples, 6u);
    BOOST_CHECK_GT(s.sigma_annual, 0.0);
}

BOOST_AUTO_TEST_CASE(estimate_stats_insufficient_history)
{
    std::vector<double> works = {1e6};  // single point -> no returns
    auto s = EstimateDifficultyHistoryStats(works, 2016, 600);
    BOOST_CHECK_EQUAL(s.samples, 0u);
    BOOST_CHECK_EQUAL(s.mean_drift_per_block, 0.0);
    BOOST_CHECK_EQUAL(s.sigma_annual, 0.0);
}

BOOST_AUTO_TEST_CASE(flat_vol_surface_builder)
{
    const std::vector<uint32_t> horizons = {144, 1008};
    auto surf = BuildFlatDifficultyVolSurface(0.7, horizons, /*ts=*/99);
    BOOST_REQUIRE_EQUAL(surf.sigmas.size(), 2u);
    BOOST_CHECK_EQUAL(surf.sigmas[0], 0.7);
    BOOST_CHECK(!surf.Validate());
    std::vector<Warning> w;
    auto sig = surf.Sigma(500, w);
    BOOST_REQUIRE(sig.has_value());
    BOOST_CHECK_EQUAL(*sig, 0.7);
}

BOOST_AUTO_TEST_CASE(retarget_aware_curve_is_flat_within_epoch_then_steps)
{
    const double d0 = 1.0e12;
    const double drift = 1e-5;   // per block
    const uint32_t interval = 100;
    // blocks_into_epoch = 0 -> first future boundary at h = interval (100).
    auto c = BuildRetargetAwareDifficultyCurve(d0, drift, interval, /*blocks_into_epoch=*/0,
                                               /*max_horizon=*/250, /*ts=*/1);
    BOOST_CHECK(c.provenance == DiffCurveProvenance::MODEL);
    BOOST_CHECK(!c.Validate());

    std::vector<Warning> w;
    // Flat within the current epoch (h < 100) at the current difficulty.
    BOOST_CHECK_CLOSE(*c.ForwardDifficulty(1, w), d0, 1e-6);
    BOOST_CHECK_CLOSE(*c.ForwardDifficulty(50, w), d0, 1e-6);
    BOOST_CHECK_CLOSE(*c.ForwardDifficulty(99, w), d0, 1e-6);

    // One step after the first boundary; flat across the second epoch [100, 200).
    const double after1 = d0 * std::exp(drift * interval);
    BOOST_CHECK_CLOSE(*c.ForwardDifficulty(100, w), after1, 1e-6);
    BOOST_CHECK_CLOSE(*c.ForwardDifficulty(150, w), after1, 1e-6);

    // Two steps after the second boundary.
    const double after2 = d0 * std::exp(drift * interval * 2.0);
    BOOST_CHECK_CLOSE(*c.ForwardDifficulty(240, w), after2, 1e-6);

    // The step is sharp: difficulty just before the boundary is still the prior epoch's level.
    BOOST_CHECK_LT(*c.ForwardDifficulty(99, w), *c.ForwardDifficulty(100, w));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace pricing
} // namespace wallet
