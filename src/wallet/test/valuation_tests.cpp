// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <test/util/zk_test_helpers.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/pricing/black_scholes.h>
#include <wallet/pricing/spread_option.h>
#include <wallet/pricing/leg_valuator.h>
#include <wallet/pricing/repo_pricer.h>
#include <wallet/pricing/forward_pricer.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/wallet.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>
#include <cmath>
#include <string>

using zk_test::uint256S;

namespace wallet {
namespace pricing {

// Test fixture with mock pricing context
struct ValuationTestFixture : public WalletTestingSetup {
    std::unique_ptr<PricingContext> pricing_ctx;

    ValuationTestFixture() : WalletTestingSetup(ChainType::REGTEST)
    {
        pricing_ctx = std::make_unique<PricingContext>(m_wallet);

        // Setup basic market data
        SetupMarketData();
    }

    void SetupMarketData()
    {
        int64_t now = GetTime();
        uint256 tsc_id;  // All-zero for TSC

        // Add a simple discount curve for native asset (TSC)
        DiscountCurve curve;
        curve.asset_id = tsc_id;
        curve.is_native = false;
        curve.timestamp = now;
        curve.tenors_days = {30, 90, 180, 365};
        curve.zero_rates = {0.02, 0.025, 0.03, 0.035};  // 2-3.5% rates
        pricing_ctx->AddCurve(curve);

        // Add vol surface for TSC
        VolSurface vol;
        vol.asset_id = tsc_id;
        vol.timestamp = now;
        vol.strikes_pct = {90.0, 100.0, 110.0};
        vol.maturities_days = {30, 90, 180, 365};
        vol.implied_vols = {
            {0.25, 0.28, 0.30, 0.32},  // 90% strike
            {0.20, 0.23, 0.25, 0.27},  // 100% strike
            {0.22, 0.25, 0.27, 0.29}   // 110% strike
        };
        pricing_ctx->AddVolSurface(vol);
    }
};

BOOST_FIXTURE_TEST_SUITE(valuation_tests, ValuationTestFixture)

// ============================================================================
// Black-Scholes Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(black_scholes_call_basic)
{
    // Classic example: S=100, K=100, T=1, r=5%, σ=20%
    // Known result: Call ≈ 10.45
    auto price_opt = BlackScholes::Price(
        100.0,  // S
        100.0,  // K
        1.0,    // T (years)
        0.05,   // r
        0.20,   // sigma
        0.0,    // q
        BlackScholes::OptionType::CALL
    );

    BOOST_REQUIRE(price_opt.has_value());
    BOOST_CHECK_CLOSE(*price_opt, 10.45, 1.0);  // Within 1% tolerance
}

BOOST_AUTO_TEST_CASE(black_scholes_put_basic)
{
    // Same params, put option
    // Known result: Put ≈ 5.57
    auto price_opt = BlackScholes::Price(
        100.0,
        100.0,
        1.0,
        0.05,
        0.20,
        0.0,
        BlackScholes::OptionType::PUT
    );

    BOOST_REQUIRE(price_opt.has_value());
    BOOST_CHECK_CLOSE(*price_opt, 5.57, 1.0);
}

BOOST_AUTO_TEST_CASE(black_scholes_put_call_parity)
{
    // Put-Call Parity: C - P = S*e^(-qT) - K*e^(-rT)
    const double S = 100.0, K = 100.0, T = 0.5, r = 0.03, sigma = 0.25, q = 0.0;

    auto call_opt = BlackScholes::Price(S, K, T, r, sigma, q, BlackScholes::OptionType::CALL);
    auto put_opt = BlackScholes::Price(S, K, T, r, sigma, q, BlackScholes::OptionType::PUT);

    BOOST_REQUIRE(call_opt && put_opt);

    const double lhs = *call_opt - *put_opt;
    const double rhs = S * std::exp(-q * T) - K * std::exp(-r * T);

    BOOST_CHECK_CLOSE(lhs, rhs, 0.01);  // Very tight tolerance for parity
}

BOOST_AUTO_TEST_CASE(black_scholes_greeks_delta)
{
    // ATM call delta should be ~0.5-0.6 (depends on r and T)
    const double S = 100.0, K = 100.0, T = 1.0, r = 0.05, sigma = 0.20, q = 0.0;

    Greeks greeks = BlackScholes::ComputeGreeks(
        S, K, T, r, sigma, q, BlackScholes::OptionType::CALL
    );

    BOOST_CHECK_GT(greeks.delta, 0.5);
    BOOST_CHECK_LT(greeks.delta, 0.7);
    BOOST_CHECK_GT(greeks.gamma, 0.0);  // Gamma always positive
    BOOST_CHECK_GT(greeks.vega, 0.0);   // Vega always positive
    BOOST_CHECK_GT(greeks.theta, 0.0);  // Theta positive (decay)
}

BOOST_AUTO_TEST_CASE(black_scholes_itm_otm)
{
    // Deep ITM call should be worth approximately S - K*e^(-rT)
    const double S = 150.0, K = 100.0, T = 1.0, r = 0.05, sigma = 0.20, q = 0.0;

    auto call_opt = BlackScholes::Price(S, K, T, r, sigma, q, BlackScholes::OptionType::CALL);
    BOOST_REQUIRE(call_opt);

    const double intrinsic = S - K * std::exp(-r * T);
    BOOST_CHECK_CLOSE(*call_opt, intrinsic, 5.0);  // Within 5% (time value small)

    // Deep OTM call should be nearly worthless
    auto otm_call_opt = BlackScholes::Price(50.0, 100.0, T, r, sigma, q, BlackScholes::OptionType::CALL);
    BOOST_REQUIRE(otm_call_opt);
    BOOST_CHECK_LT(*otm_call_opt, 1.0);
}

BOOST_AUTO_TEST_CASE(black_scholes_expiry)
{
    // At expiry, option worth intrinsic value
    const double S = 110.0, K = 100.0;

    auto call_opt = BlackScholes::Price(S, K, 1e-10, 0.05, 0.20, 0.0, BlackScholes::OptionType::CALL);
    BOOST_REQUIRE(call_opt);
    BOOST_CHECK_CLOSE(*call_opt, 10.0, 0.1);  // Intrinsic = S - K
}

BOOST_AUTO_TEST_CASE(black_scholes_dividend_yield_vectors)
{
    // Golden test vectors from QuantLib test suite (Haug reference)
    // These validate the q (dividend yield) parameter handling

    // Test 1: Deep OTM Put with dividend yield
    // Ref: QuantLib europeanoption.cpp
    auto put1 = BlackScholes::Price(100.0, 95.0, 0.5, 0.10, 0.20, 0.05, BlackScholes::OptionType::PUT);
    BOOST_REQUIRE(put1);
    BOOST_CHECK_CLOSE(*put1, 2.4648, 0.1);

    // Test 2: ATM Put with high dividend yield
    auto put2 = BlackScholes::Price(19.0, 19.0, 0.75, 0.10, 0.28, 0.10, BlackScholes::OptionType::PUT);
    BOOST_REQUIRE(put2);
    BOOST_CHECK_CLOSE(*put2, 1.7011, 0.1);

    // Test 3: ITM Put with dividend yield
    auto put3 = BlackScholes::Price(75.0, 70.0, 0.5, 0.10, 0.35, 0.05, BlackScholes::OptionType::PUT);
    BOOST_REQUIRE(put3);
    BOOST_CHECK_CLOSE(*put3, 4.0870, 0.1);

    // Test 4: Deep ITM Call with high dividend yield
    auto call1 = BlackScholes::Price(42.0, 40.0, 0.75, 0.04, 0.35, 0.08, BlackScholes::OptionType::CALL);
    BOOST_REQUIRE(call1);
    BOOST_CHECK_CLOSE(*call1, 5.0975, 0.1);
}

// ============================================================================
// Spread Option Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(spread_option_kirk_basic)
{
    // Simple spread: max(S_A - S_B, 0)
    const double S_A = 100.0, S_B = 95.0;
    const double alpha = 1.0, beta = 1.0, K = 0.0;
    const double T = 1.0, r = 0.05;
    const double sigma_A = 0.20, sigma_B = 0.25, rho = 0.5;

    auto price_opt = SpreadOption::Price(
        S_A, S_B, alpha, beta, K, T, r,
        sigma_A, sigma_B, rho, true  // Force Kirk
    );

    BOOST_REQUIRE(price_opt.has_value());
    BOOST_CHECK_GT(*price_opt, 0.0);
    BOOST_CHECK_LT(*price_opt, S_A);  // Can't be worth more than S_A
}

BOOST_AUTO_TEST_CASE(spread_option_intrinsic)
{
    // At expiry, spread option worth max(spread, 0)
    const double S_A = 100.0, S_B = 90.0;
    const double alpha = 1.0, beta = 1.0, K = 0.0;
    const double T = 1e-10;  // Near expiry
    const double r = 0.05, sigma_A = 0.20, sigma_B = 0.25, rho = 0.5;

    auto price_opt = SpreadOption::Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho);
    BOOST_REQUIRE(price_opt);

    const double intrinsic = std::max(alpha * S_A - beta * S_B - K, 0.0);
    BOOST_CHECK_CLOSE(*price_opt, intrinsic, 1.0);
}

BOOST_AUTO_TEST_CASE(spread_option_correlation_effect)
{
    // Higher correlation should reduce option value
    const double S_A = 100.0, S_B = 100.0;
    const double alpha = 1.0, beta = 1.0, K = 0.0;
    const double T = 1.0, r = 0.05;
    const double sigma_A = 0.30, sigma_B = 0.30;

    auto price_low_corr = SpreadOption::Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, 0.1);
    auto price_high_corr = SpreadOption::Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, 0.9);

    BOOST_REQUIRE(price_low_corr && price_high_corr);
    BOOST_CHECK_GT(*price_low_corr, *price_high_corr);  // Lower correlation = higher option value
}

BOOST_AUTO_TEST_CASE(spread_option_greeks)
{
    const double S_A = 100.0, S_B = 95.0;
    const double alpha = 1.0, beta = 1.0, K = 0.0;
    const double T = 1.0, r = 0.05;
    const double sigma_A = 0.20, sigma_B = 0.25, rho = 0.3;

    auto greeks = SpreadOption::ComputeGreeks(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho);

    // Delta_A should be positive (option increases with S_A)
    BOOST_CHECK_GT(greeks.delta_A, 0.0);
    // Delta_B should be negative (option decreases with S_B)
    BOOST_CHECK_LT(greeks.delta_B, 0.0);
    // Vegas should be positive
    BOOST_CHECK_GT(greeks.vega_A, 0.0);
    BOOST_CHECK_GT(greeks.vega_B, 0.0);
}

BOOST_AUTO_TEST_CASE(spread_option_kirk_vs_gauss_legendre)
{
    // Verify both Kirk and Gauss-Legendre methods return valid prices
    // Note: Gauss-Legendre is a simplified 1D approximation (marginalizes S_B via
    // conditional mean) and is NOT expected to match Kirk accurately. It's a fallback
    // for extreme cases where Kirk breaks down. Full 2D integration would be needed
    // for production-quality accuracy.
    const double S_A = 100.0, S_B = 100.0;
    const double alpha = 1.0, beta = 1.0, K = 5.0;
    const double T = 0.5, r = 0.03;
    const double sigma_A = 0.25, sigma_B = 0.30, rho = 0.4;

    auto kirk_price = SpreadOption::Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, true);
    auto gauss_price = SpreadOption::Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, false);

    // Both methods should return valid prices
    BOOST_REQUIRE(kirk_price);
    BOOST_REQUIRE(gauss_price);

    // Both should be positive (call option with positive spot and strike)
    BOOST_CHECK_GT(*kirk_price, 0.0);
    BOOST_CHECK_GT(*gauss_price, 0.0);

    // Kirk is canonical - use it as reference
    // Gauss-Legendre may deviate significantly due to approximation limitations
}

BOOST_AUTO_TEST_CASE(spread_option_kirk_matlab_golden)
{
    // Golden test vector from MATLAB spreadsensbykirk example
    // Heating Oil vs WTI Crude Oil spread option
    // Ref: https://www.mathworks.com/help/fininst/pricing-european-and-american-spread-options.html

    const double S_A = 110.0;  // Heating Oil: $110/barrel
    const double S_B = 100.0;  // WTI Crude: $100/barrel
    const double alpha = 1.0, beta = 1.0;
    const double K = 5.0;      // Strike: $5
    const double T = 1.0;      // 1 year
    const double r = 0.05;     // 5% risk-free rate
    const double sigma_A = 0.10;  // 10% vol (Heating Oil)
    const double sigma_B = 0.15;  // 15% vol (WTI Crude)
    const double rho = 0.3;    // 30% correlation
    const double q_A = 0.03;   // 3% carry yield (Heating Oil)
    const double q_B = 0.02;   // 2% carry yield (WTI Crude)

    // MATLAB Kirk result with carry yields: $8.36
    // Force Kirk since MATLAB uses Kirk approximation
    auto price_opt = SpreadOption::Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, true, q_A, q_B);

    BOOST_REQUIRE(price_opt);
    // With carry yields, should match MATLAB within tolerance
    BOOST_CHECK_CLOSE(*price_opt, 8.36, 1.0);  // Within 1% of MATLAB

    // Greeks validation from MATLAB - force Kirk for consistent finite differences
    auto greeks = SpreadOption::ComputeGreeks(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, q_A, q_B, true);

    // MATLAB: Delta_A = 0.6108, Delta_B = -0.5590
    BOOST_CHECK_CLOSE(greeks.delta_A, 0.6108, 5.0);  // Within 5%
    BOOST_CHECK_CLOSE(greeks.delta_B, -0.5590, 5.0);

    // MATLAB: Gamma_A = 0.0225, Gamma_B = 0.0249
    BOOST_CHECK_CLOSE(greeks.gamma_A, 0.0225, 10.0);  // Within 10%
    BOOST_CHECK_CLOSE(greeks.gamma_B, 0.0249, 10.0);
}

// ============================================================================
// LegValuator Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(leg_valuator_simple_pv)
{
    uint256 tsc_id;
    wallet::AssetLeg leg{tsc_id, false, 1000, std::nullopt};  // 1000 TSC (uint64_t)

    LegPV pv = LegValuator::PresentValue(
        leg, *pricing_ctx, 365, tsc_id, false, GetTime()
    );

    // PV should be discounted: 1000 * exp(-0.035 * 1) ≈ 965.6
    BOOST_CHECK_CLOSE(pv.pv_tsc, 965.6, 1.0);
    BOOST_CHECK_CLOSE(pv.discount_factor, std::exp(-0.035), 0.1);
    BOOST_CHECK_EQUAL(pv.spot_fx_used, 1.0);  // No FX conversion
}

BOOST_AUTO_TEST_CASE(leg_valuator_zero_maturity)
{
    uint256 tsc_id;
    wallet::AssetLeg leg{tsc_id, false, 1000, std::nullopt};

    LegPV pv = LegValuator::PresentValue(
        leg, *pricing_ctx, 0, tsc_id, false, GetTime()
    );

    // At maturity, DF = 1.0
    BOOST_CHECK_CLOSE(pv.pv_tsc, 1000.0, 0.01);
    BOOST_CHECK_CLOSE(pv.discount_factor, 1.0, 0.01);
}

BOOST_AUTO_TEST_CASE(leg_valuator_missing_curve_warning)
{
    uint256 unknown_asset = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    wallet::AssetLeg leg{unknown_asset, false, 1000, std::nullopt};

    LegPV pv = LegValuator::PresentValue(
        leg, *pricing_ctx, 365, unknown_asset, false, GetTime()
    );

    // Should emit warning about missing curve
    BOOST_CHECK_GT(pv.warnings.size(), 0);
    bool found_coverage_warning = false;
    for (const auto& w : pv.warnings) {
        if (w.category == WarningCategory::COVERAGE) {
            found_coverage_warning = true;
            break;
        }
    }
    BOOST_CHECK(found_coverage_warning);
}

BOOST_AUTO_TEST_CASE(leg_valuator_height_to_days)
{
    // 144 blocks/day (10 min target)
    BOOST_CHECK_EQUAL(LegValuator::HeightToDays(144), 1);
    BOOST_CHECK_EQUAL(LegValuator::HeightToDays(1440), 10);
    BOOST_CHECK_EQUAL(LegValuator::HeightToDays(100), 1);  // Rounds up
}

BOOST_AUTO_TEST_CASE(leg_valuator_days_to_years)
{
    // ACT/365
    BOOST_CHECK_CLOSE(LegValuator::DaysToYears(365), 1.0, 0.01);
    BOOST_CHECK_CLOSE(LegValuator::DaysToYears(182), 0.4986, 0.1);
}

// ============================================================================
// Repo Pricer Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(repo_pricer_basic)
{
    uint256 tsc_id;
    wallet::AssetLeg principal{tsc_id, false, 1000, std::nullopt};  // 1000 TSC principal
    wallet::AssetLeg interest{tsc_id, false, 50, std::nullopt};     // 50 TSC interest
    wallet::AssetLeg collateral{tsc_id, false, 1200, std::nullopt}; // 1200 TSC collateral

    RepoValuation valuation = RepoPricer::Price(
        principal, interest, collateral,
        365,  // 1 year maturity
        7,    // safety_k
        *pricing_ctx,
        tsc_id, false,  // Reporting currency
        GetTime(),
        true,  // compute greeks
        PriceSource::MARK,
        false
    );

    // Basic checks
    BOOST_CHECK_GT(valuation.principal_pv, 0.0);
    BOOST_CHECK_GT(valuation.interest_pv, 0.0);
    BOOST_CHECK_GT(valuation.collateral_pv, 0.0);

    // Coverage should be collateral / (principal + interest)
    const double expected_coverage = 1200.0 / 1050.0;  // Approximately, before discounting
    BOOST_CHECK_CLOSE(valuation.coverage_ratio, expected_coverage, 5.0);

    // LTV should be 100 / coverage
    BOOST_CHECK_CLOSE(valuation.ltv_pct, 100.0 / expected_coverage, 5.0);

    // Collateral option should be non-negative
    BOOST_CHECK_GE(valuation.collateral_option, 0.0);

    // Lender MTM = principal + interest - option
    BOOST_CHECK_CLOSE(
        valuation.lender_mtm,
        valuation.principal_pv + valuation.interest_pv - valuation.collateral_option,
        0.01
    );

    // Borrower MTM = -Lender MTM
    BOOST_CHECK_CLOSE(valuation.borrower_mtm, -valuation.lender_mtm, 0.01);
}

BOOST_AUTO_TEST_CASE(repo_pricer_undercollateralized_warning)
{
    uint256 tsc_id;
    wallet::AssetLeg principal{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg interest{tsc_id, false, 50, std::nullopt};
    wallet::AssetLeg collateral{tsc_id, false, 900, std::nullopt};  // Under-collateralized!

    RepoValuation valuation = RepoPricer::Price(
        principal, interest, collateral, 365, 7, *pricing_ctx, tsc_id, false, GetTime(), true, PriceSource::MARK, false
    );

    // Should have CRITICAL warning about coverage < 100%
    bool found_critical = false;
    for (const auto& w : valuation.warnings) {
        if (w.severity == WarningSeverity::CRITICAL &&
            w.category == WarningCategory::COVERAGE) {
            found_critical = true;
            break;
        }
    }
    BOOST_CHECK(found_critical);
    BOOST_CHECK_LT(valuation.coverage_ratio, 1.0);
}

BOOST_AUTO_TEST_CASE(repo_pricer_coverage_thresholds)
{
    uint256 tsc_id;
    wallet::AssetLeg principal{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg interest{tsc_id, false, 50, std::nullopt};

    // Test 104% coverage (should be CRITICAL: < 105%)
    {
        wallet::AssetLeg collateral{tsc_id, false, 1092, std::nullopt};  // 104% coverage
        RepoValuation val = RepoPricer::Price(principal, interest, collateral, 365, 7, *pricing_ctx, tsc_id, false, GetTime(), true, PriceSource::MARK, false);

        bool found_critical = false;
        for (const auto& w : val.warnings) {
            if (w.severity == WarningSeverity::CRITICAL && w.category == WarningCategory::COVERAGE) {
                found_critical = true;
            }
        }
        BOOST_CHECK(found_critical);
    }

    // Test 115% coverage (should be WARNING: < 120%)
    {
        wallet::AssetLeg collateral{tsc_id, false, 1207, std::nullopt};  // 115% coverage (rounded to uint64_t)
        RepoValuation val = RepoPricer::Price(principal, interest, collateral, 365, 7, *pricing_ctx, tsc_id, false, GetTime(), true, PriceSource::MARK, false);

        bool found_warning = false;
        for (const auto& w : val.warnings) {
            if (w.severity == WarningSeverity::WARNING && w.category == WarningCategory::COVERAGE) {
                found_warning = true;
            }
        }
        BOOST_CHECK(found_warning);
    }
}

BOOST_AUTO_TEST_CASE(repo_pricer_greeks)
{
    uint256 tsc_id;
    wallet::AssetLeg principal{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg interest{tsc_id, false, 50, std::nullopt};
    wallet::AssetLeg collateral{tsc_id, false, 1200, std::nullopt};

    RepoValuation valuation = RepoPricer::Price(
        principal, interest, collateral, 365, 7, *pricing_ctx, tsc_id, false, GetTime(), true, PriceSource::MARK, false
    );

    // Greeks should be finite (may be zero in degenerate same-asset case)
    BOOST_CHECK(std::isfinite(valuation.collateral_greeks.delta));
    BOOST_CHECK(std::isfinite(valuation.collateral_greeks.vega));
}

// ============================================================================
// Forward Pricer Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(forward_pricer_basic)
{
    uint256 tsc_id;
    wallet::AssetLeg receive{tsc_id, false, 1000, std::nullopt};  // Alice receives 1000 TSC
    wallet::AssetLeg pay{tsc_id, false, 950, std::nullopt};       // Alice pays 950 TSC
    wallet::AssetLeg im_alice{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg im_bob{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg premium{tsc_id, false, 0, std::nullopt};     // No premium

    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium,
        180,    // 6 months
        7,      // safety_k
        *pricing_ctx,
        tsc_id, false,  // Reporting currency
        GetTime(),
        true    // compute greeks
    );

    // Basic checks
    BOOST_CHECK_GT(valuation.pv_receive, 0.0);
    BOOST_CHECK_GT(valuation.pv_pay, 0.0);

    // Net spread should be positive (Alice receives more than pays)
    BOOST_CHECK_GT(valuation.net_spread_value, 0.0);

    // Bob has exposure (spread positive for Alice)
    BOOST_CHECK_GT(valuation.bob_exposure_uncapped, 0.0);
    BOOST_CHECK_EQUAL(valuation.alice_exposure_uncapped, 0.0);

    // IM coverage for Bob
    BOOST_CHECK_GT(valuation.im_coverage_bob, 0.0);

    // MTM calculations
    BOOST_CHECK_CLOSE(
        valuation.alice_mtm,
        valuation.net_spread_value + valuation.alice_short_call_value +
        valuation.alice_long_put_value + valuation.premium_pv,
        0.01
    );
    BOOST_CHECK_CLOSE(valuation.bob_mtm, -valuation.alice_mtm, 0.01);
}

BOOST_AUTO_TEST_CASE(forward_pricer_im_coverage_warning)
{
    uint256 tsc_id;
    wallet::AssetLeg receive{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg pay{tsc_id, false, 800, std::nullopt};  // Large spread favoring Alice
    wallet::AssetLeg im_alice{tsc_id, false, 200, std::nullopt};  // IM_Alice (adequate)
    wallet::AssetLeg im_bob{tsc_id, false, 50, std::nullopt};     // IM_Bob (inadequate for ~200 TSC exposure)
    wallet::AssetLeg premium{tsc_id, false, 0, std::nullopt};

    // Insufficient IM for Bob
    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium,
        180, 7, *pricing_ctx, tsc_id, false, GetTime()
    );

    // Should have warning about Bob's IM coverage
    bool found_im_warning = false;
    for (const auto& w : valuation.warnings) {
        if (w.category == WarningCategory::IM) {
            found_im_warning = true;
        }
    }
    BOOST_CHECK(found_im_warning);
    BOOST_CHECK_LT(valuation.im_coverage_bob, 1.0);
}

BOOST_AUTO_TEST_CASE(forward_pricer_spread_options)
{
    uint256 tsc_id;
    wallet::AssetLeg receive{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg pay{tsc_id, false, 950, std::nullopt};
    wallet::AssetLeg im_alice{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg im_bob{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg premium{tsc_id, false, 0, std::nullopt};

    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium, 180, 7, *pricing_ctx, tsc_id, false, GetTime(), true
    );

    // Both options should have been priced
    // Short call value should be negative (liability for Alice)
    BOOST_CHECK_LE(valuation.alice_short_call_value, 0.0);

    // Long put value should be non-negative (asset for Alice)
    BOOST_CHECK_GE(valuation.alice_long_put_value, 0.0);

    // Greeks objects should be finite (may be zero in degenerate same-asset case)
    BOOST_CHECK(std::isfinite(valuation.spread_greeks_call.delta_A));
    BOOST_CHECK(std::isfinite(valuation.spread_greeks_put.delta_A));
}

BOOST_AUTO_TEST_CASE(forward_pricer_symmetric_case)
{
    // Equal legs, equal IM - should be near zero MTM
    uint256 tsc_id;
    wallet::AssetLeg receive{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg pay{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg im_alice{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg im_bob{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg premium{tsc_id, false, 0, std::nullopt};

    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium, 180, 7, *pricing_ctx, tsc_id, false, GetTime()
    );

    // Net spread should be near zero
    BOOST_CHECK_SMALL(valuation.net_spread_value, 10.0);  // Within 10 TSC

    // Both exposures should be minimal
    BOOST_CHECK_SMALL(valuation.alice_exposure_uncapped, 10.0);
    BOOST_CHECK_SMALL(valuation.bob_exposure_uncapped, 10.0);

    // MTM should be near zero (symmetric contract)
    BOOST_CHECK_SMALL(std::abs(valuation.alice_mtm), 20.0);
}

BOOST_AUTO_TEST_CASE(forward_pricer_im_numeraire_symmetry)
{
    // Symmetric 1:1 forward with IM in leg currencies - MTM should be ~0
    const int64_t now = GetTime();
    const uint256 asset_id; // use default synthetic asset

    wallet::AssetLeg receive{asset_id, false, 1, std::nullopt};   // Alice receives 1 unit
    wallet::AssetLeg pay{asset_id, false, 1, std::nullopt};       // Alice pays 1 unit
    wallet::AssetLeg im_alice{asset_id, false, 1, std::nullopt};  // IM in A
    wallet::AssetLeg im_bob{asset_id, false, 1, std::nullopt};    // IM in B
    wallet::AssetLeg premium{asset_id, false, 0, std::nullopt};

    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium,
        180, 7, *pricing_ctx, asset_id, false, now, true
    );

    // Linear legs symmetric
    BOOST_CHECK_SMALL(valuation.net_spread_value, 1e-6);

    // Walkaways should offset
    BOOST_CHECK_LE(valuation.alice_short_call_value, 0.0);
    BOOST_CHECK_GE(valuation.alice_long_put_value, 0.0);
    BOOST_CHECK_SMALL(valuation.alice_mtm, 1e-4);
}

BOOST_AUTO_TEST_CASE(forward_pricer_zero_basket_warning)
{
    uint256 tsc_id;
    wallet::AssetLeg receive{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg pay{tsc_id, false, 0, std::nullopt};        // No pay leg -> basket zero
    wallet::AssetLeg im_alice{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg im_bob{tsc_id, false, 0, std::nullopt};     // No IM_Bob -> basket zero
    wallet::AssetLeg premium{tsc_id, false, 0, std::nullopt};

    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium, 180, 7, *pricing_ctx, tsc_id, false, GetTime(), true
    );

    bool found_zero_basket = false;
    for (const auto& w : valuation.warnings) {
        if (w.message.find("basket value non-positive") != std::string::npos) {
            found_zero_basket = true;
        }
    }
    BOOST_CHECK(found_zero_basket);
    BOOST_CHECK_EQUAL(valuation.alice_short_call_value, 0.0);
}

BOOST_AUTO_TEST_CASE(forward_pricer_kirk_extreme_warning)
{
    // Add high-vol asset and strong correlation to trigger Kirk warning
    const int64_t now = GetTime();
    const uint256 tsc_id;              // existing asset
    const uint256 vol_id = uint256S("01");

    DiscountCurve curve_high;
    curve_high.asset_id = vol_id;
    curve_high.is_native = false;
    curve_high.timestamp = now;
    curve_high.tenors_days = {30, 90, 180};
    curve_high.zero_rates = {0.02, 0.025, 0.03};
    pricing_ctx->AddCurve(curve_high);

    VolSurface vol_high;
    vol_high.asset_id = vol_id;
    vol_high.timestamp = now;
    vol_high.strikes_pct = {100.0};
    vol_high.maturities_days = {180};
    vol_high.implied_vols = {{1.20}};  // 120% vol to force warning
    pricing_ctx->AddVolSurface(vol_high);

    CorrelationMatrix corr;
    corr.asset_ids = {tsc_id, vol_id};
    corr.corr = {
        {1.0, 0.95},
        {0.95, 1.0}
    };
    corr.timestamp = now;
    pricing_ctx->AddCorrelationMatrix(corr);

    wallet::AssetLeg receive{tsc_id, false, 1000, std::nullopt};
    wallet::AssetLeg pay{vol_id, false, 900, std::nullopt};
    wallet::AssetLeg im_alice{tsc_id, false, 100, std::nullopt};
    wallet::AssetLeg im_bob{vol_id, false, 100, std::nullopt};
    wallet::AssetLeg premium{tsc_id, false, 0, std::nullopt};

    ForwardValuation valuation = ForwardPricer::Price(
        receive, pay, im_alice, im_bob, premium, 180, 7, *pricing_ctx, tsc_id, false, GetTime(), true
    );

    bool found_kirk_warning = false;
    for (const auto& w : valuation.warnings) {
        if (w.message.find("Kirk approximation may be inaccurate") != std::string::npos ||
            w.message.find("Forcing Kirk for short walkaway") != std::string::npos ||
            w.message.find("Forcing Kirk for long walkaway") != std::string::npos) {
            found_kirk_warning = true;
        }
    }
    BOOST_CHECK(found_kirk_warning);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace pricing
} // namespace wallet
