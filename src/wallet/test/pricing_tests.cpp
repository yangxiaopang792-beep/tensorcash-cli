// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <test/util/zk_test_helpers.h>
#include <wallet/pricing/discount_curve.h>
#include <wallet/pricing/fx_matrix.h>
#include <wallet/pricing/vol_surface.h>
#include <wallet/pricing/correlation_matrix.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <cmath>

using zk_test::uint256S;

namespace wallet {
namespace pricing {

BOOST_FIXTURE_TEST_SUITE(pricing_tests, BasicTestingSetup)

// ============================================================================
// Discount Curve Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(discount_curve_basic_interpolation)
{
    DiscountCurve curve;
    curve.asset_id = uint256S("0x1234");
    curve.is_native = false;
    curve.timestamp = GetTime();

    // Setup simple curve: 1% at 30 days, 2% at 365 days
    curve.tenors_days = {30, 365};
    curve.zero_rates = {0.01, 0.02};

    std::vector<Warning> warnings;

    // Test exact match at tenor points
    double df_30 = curve.GetDiscountFactor(30, warnings);
    BOOST_CHECK_CLOSE(df_30, std::exp(-0.01 * 30.0 / 365.0), 0.001);
    BOOST_CHECK(warnings.empty());

    double df_365 = curve.GetDiscountFactor(365, warnings);
    BOOST_CHECK_CLOSE(df_365, std::exp(-0.02), 0.001);
    BOOST_CHECK(warnings.empty());

    // Test interpolation between points (midpoint: ~182.5 days)
    warnings.clear();
    double rate_mid = curve.GetZeroRate(182, warnings);
    BOOST_CHECK_GT(rate_mid, 0.01);  // Should be > 1%
    BOOST_CHECK_LT(rate_mid, 0.02);  // Should be < 2%
    BOOST_CHECK(warnings.empty());
}

BOOST_AUTO_TEST_CASE(discount_curve_extrapolation)
{
    DiscountCurve curve;
    curve.asset_id = uint256S("0x1234");
    curve.is_native = true;
    curve.timestamp = GetTime();
    curve.tenors_days = {30, 365};
    curve.zero_rates = {0.01, 0.02};

    std::vector<Warning> warnings;

    // Test extrapolation before first tenor
    double rate_short = curve.GetZeroRate(1, warnings);
    BOOST_CHECK_EQUAL(rate_short, 0.01);  // Flat extrapolation
    BOOST_CHECK_EQUAL(warnings.size(), 1);
    BOOST_CHECK(warnings[0].category == WarningCategory::INTERPOLATION);
    BOOST_CHECK(warnings[0].severity == WarningSeverity::INFO);

    // Test extrapolation beyond last tenor
    warnings.clear();
    double rate_long = curve.GetZeroRate(730, warnings);
    BOOST_CHECK_EQUAL(rate_long, 0.02);  // Flat extrapolation
    BOOST_CHECK_EQUAL(warnings.size(), 1);
}

BOOST_AUTO_TEST_CASE(discount_curve_validation)
{
    DiscountCurve curve;
    curve.asset_id = uint256S("0x1234");
    curve.is_native = false;
    curve.timestamp = GetTime();

    // Empty curve
    auto err = curve.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("has no tenors") != std::string::npos);

    // Mismatched sizes
    curve.tenors_days = {30, 365};
    curve.zero_rates = {0.01};  // Only one rate
    err = curve.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("Tenor count") != std::string::npos);

    // Unsorted tenors
    curve.zero_rates = {0.01, 0.02};
    curve.tenors_days = {365, 30};  // Wrong order
    err = curve.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("strictly increasing") != std::string::npos);

    // Valid curve
    curve.tenors_days = {30, 365};
    err = curve.Validate();
    BOOST_CHECK(!err.has_value());
}

BOOST_AUTO_TEST_CASE(discount_curve_staleness)
{
    DiscountCurve curve;
    curve.asset_id = uint256S("0x1234");
    curve.is_native = false;
    curve.tenors_days = {30, 365};
    curve.zero_rates = {0.01, 0.02};

    int64_t now = GetTime();

    // Fresh data
    curve.timestamp = now;
    auto warn = curve.CheckStaleness(now);
    BOOST_CHECK(!warn.has_value());

    // 13 hours old - WARNING
    curve.timestamp = now - (13 * 3600);
    warn = curve.CheckStaleness(now);
    BOOST_CHECK(warn.has_value());
    BOOST_CHECK(warn->severity == WarningSeverity::WARNING);
    BOOST_CHECK(warn->category == WarningCategory::MARKET_DATA);

    // 25 hours old - CRITICAL
    curve.timestamp = now - (25 * 3600);
    warn = curve.CheckStaleness(now);
    BOOST_CHECK(warn.has_value());
    BOOST_CHECK(warn->severity == WarningSeverity::CRITICAL);
}

// ============================================================================
// FX Matrix Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(fx_direct_quote)
{
    FXMatrix matrix;
    uint256 hub = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 usd = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 eur = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    matrix.SetHub(hub);

    // Add USD/EUR quote: 1 USD = 0.92 EUR
    FXQuote quote;
    quote.base_asset = usd;
    quote.quote_asset = eur;
    quote.spot_rate = 0.92;
    quote.bid_ask_bps = 10;  // 1 bp spread
    quote.timestamp = GetTime();

    matrix.AddQuote(quote);

    // Test direct lookup
    FXResult result = matrix.GetRate(usd, eur, false, false, GetTime());
    BOOST_CHECK_CLOSE(result.rate, 0.92, 0.001);
    BOOST_CHECK_EQUAL(result.hops, 1);  // Direct quote has hops=1
    BOOST_CHECK(result.warnings.empty());
    BOOST_REQUIRE_EQUAL(result.path.size(), 2);
    BOOST_CHECK(result.path[0] == usd);
    BOOST_CHECK(result.path[1] == eur);

    // Test inverse lookup
    result = matrix.GetRate(eur, usd, false, false, GetTime());
    BOOST_CHECK_CLOSE(result.rate, 1.0 / 0.92, 0.001);
    BOOST_CHECK_EQUAL(result.hops, 1);  // Direct quote (inverse) has hops=1
}

BOOST_AUTO_TEST_CASE(fx_hub_triangulation)
{
    FXMatrix matrix;
    uint256 hub = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 usd = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 eur = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    matrix.SetHub(hub);

    // Add HUB/USD quote: 1 HUB = 1.00 USD
    FXQuote quote1;
    quote1.base_asset = hub;
    quote1.quote_asset = usd;
    quote1.spot_rate = 1.00;
    quote1.bid_ask_bps = 5;
    quote1.timestamp = GetTime();
    matrix.AddQuote(quote1);

    // Add HUB/EUR quote: 1 HUB = 0.92 EUR
    FXQuote quote2;
    quote2.base_asset = hub;
    quote2.quote_asset = eur;
    quote2.spot_rate = 0.92;
    quote2.bid_ask_bps = 5;
    quote2.timestamp = GetTime();
    matrix.AddQuote(quote2);

    // Get USD/EUR via hub: should be 0.92 / 1.00 = 0.92
    FXResult result = matrix.GetRate(usd, eur, false, false, GetTime());
    BOOST_CHECK_CLOSE(result.rate, 0.92, 0.001);
    BOOST_CHECK_EQUAL(result.hops, 2);  // Hub triangulation has hops=2
    BOOST_REQUIRE_EQUAL(result.path.size(), 3);
    BOOST_CHECK(result.path[0] == usd);
    BOOST_CHECK(result.path[1] == hub);
    BOOST_CHECK(result.path[2] == eur);
}

BOOST_AUTO_TEST_CASE(fx_multi_hop_pathfinding)
{
    FXMatrix matrix;
    uint256 hub = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 a = uint256S("0x4444444444444444444444444444444444444444444444444444444444444444");
    uint256 b = uint256S("0x5555555555555555555555555555555555555555555555555555555555555555");
    uint256 c = uint256S("0x6666666666666666666666666666666666666666666666666666666666666666");
    uint256 d = uint256S("0x7777777777777777777777777777777777777777777777777777777777777777");

    matrix.SetHub(hub);

    // Create chain: A -> B -> C -> D (3 hops)
    FXQuote quote1;
    quote1.base_asset = a;
    quote1.quote_asset = b;
    quote1.spot_rate = 2.0;
    quote1.bid_ask_bps = 5;
    quote1.timestamp = GetTime();
    matrix.AddQuote(quote1);

    FXQuote quote2;
    quote2.base_asset = b;
    quote2.quote_asset = c;
    quote2.spot_rate = 3.0;
    quote2.bid_ask_bps = 5;
    quote2.timestamp = GetTime();
    matrix.AddQuote(quote2);

    FXQuote quote3;
    quote3.base_asset = c;
    quote3.quote_asset = d;
    quote3.spot_rate = 1.5;
    quote3.bid_ask_bps = 5;
    quote3.timestamp = GetTime();
    matrix.AddQuote(quote3);

    // Get A/D: should be 2.0 * 3.0 * 1.5 = 9.0 via 3 hops
    FXResult result = matrix.GetRate(a, d, false, false, GetTime());
    BOOST_CHECK_CLOSE(result.rate, 9.0, 0.01);
    BOOST_CHECK_EQUAL(result.hops, 3);
    BOOST_REQUIRE_EQUAL(result.path.size(), 4);
    BOOST_CHECK(result.path[0] == a);
    BOOST_CHECK(result.path[1] == b);
    BOOST_CHECK(result.path[2] == c);
    BOOST_CHECK(result.path[3] == d);

    // Should warn about >2 hops
    BOOST_REQUIRE_EQUAL(result.warnings.size(), 1);
    BOOST_CHECK(result.warnings[0].category == WarningCategory::FX);
}

BOOST_AUTO_TEST_CASE(fx_arbitrage_detection)
{
    FXMatrix matrix;
    uint256 hub = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 a = uint256S("0x8888888888888888888888888888888888888888888888888888888888888888");
    uint256 b = uint256S("0x9999999999999999999999999999999999999999999999999999999999999999");
    uint256 c = uint256S("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    matrix.SetHub(hub);

    // Create a triangular arbitrage opportunity
    // A→B: rate = 2.0
    FXQuote quote1;
    quote1.base_asset = a;
    quote1.quote_asset = b;
    quote1.spot_rate = 2.0;
    quote1.bid_ask_bps = 5;
    quote1.timestamp = GetTime();
    matrix.AddQuote(quote1);

    // B→C: rate = 3.0
    FXQuote quote2;
    quote2.base_asset = b;
    quote2.quote_asset = c;
    quote2.spot_rate = 3.0;
    quote2.bid_ask_bps = 5;
    quote2.timestamp = GetTime();
    matrix.AddQuote(quote2);

    // C→A: should be 1/(2*3) = 1/6 ≈ 0.1667, but set to 0.1 to create arbitrage
    // Product: 2.0 * 3.0 * 0.1 = 0.6 (should be 1.0)
    FXQuote quote3;
    quote3.base_asset = c;
    quote3.quote_asset = a;
    quote3.spot_rate = 0.1;  // Creates arbitrage
    quote3.bid_ask_bps = 5;
    quote3.timestamp = GetTime();
    matrix.AddQuote(quote3);

    // Check for arbitrage
    auto arb_warn = matrix.CheckArbitrage();
    BOOST_CHECK(arb_warn.has_value());
    BOOST_CHECK(arb_warn->severity == WarningSeverity::WARNING);
    BOOST_CHECK(arb_warn->category == WarningCategory::FX);
}

BOOST_AUTO_TEST_CASE(fx_staleness_check)
{
    FXMatrix matrix;
    uint256 a = uint256S("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    uint256 b = uint256S("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");

    int64_t now = GetTime();

    FXQuote quote;
    quote.base_asset = a;
    quote.quote_asset = b;
    quote.spot_rate = 1.0;
    quote.bid_ask_bps = 5;
    quote.timestamp = now - (13 * 3600);  // 13 hours old
    matrix.AddQuote(quote);

    FXResult result = matrix.GetRate(a, b, false, false, now);
    BOOST_CHECK_EQUAL(result.warnings.size(), 1);
    BOOST_CHECK(result.warnings[0].category == WarningCategory::FX);
}

// ============================================================================
// Vol Surface Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(vol_surface_exact_lookup)
{
    VolSurface surface;
    surface.asset_id = uint256S("0x1234");
    surface.timestamp = GetTime();

    // 2x2 grid: strikes 90%, 110% x maturities 30, 365 days
    surface.strikes_pct = {90.0, 110.0};
    surface.maturities_days = {30, 365};
    surface.implied_vols = {
        {0.15, 0.20},  // 90% strike: 15% vol at 30d, 20% at 365d
        {0.12, 0.18}   // 110% strike: 12% vol at 30d, 18% at 365d
    };

    std::vector<Warning> warnings;

    // Exact lookup at grid points
    double vol_90_30 = surface.Lookup(90.0, 30, warnings);
    BOOST_CHECK_CLOSE(vol_90_30, 0.15, 0.001);
    BOOST_CHECK(warnings.empty());

    double vol_110_365 = surface.Lookup(110.0, 365, warnings);
    BOOST_CHECK_CLOSE(vol_110_365, 0.18, 0.001);
}

BOOST_AUTO_TEST_CASE(vol_surface_bilinear_interpolation)
{
    VolSurface surface;
    surface.asset_id = uint256S("0x1234");
    surface.timestamp = GetTime();

    // 2x2 grid with known values
    surface.strikes_pct = {90.0, 110.0};
    surface.maturities_days = {30, 365};
    surface.implied_vols = {
        {0.20, 0.30},  // 90% strike
        {0.10, 0.20}   // 110% strike
    };

    std::vector<Warning> warnings;

    // Interpolate at center: strike=100%, maturity~197.5 days
    // Should be roughly average of the 4 corners
    double vol_center = surface.Lookup(100.0, 197, warnings);
    BOOST_CHECK_GT(vol_center, 0.15);
    BOOST_CHECK_LT(vol_center, 0.25);
    BOOST_CHECK(warnings.empty());
}

BOOST_AUTO_TEST_CASE(vol_surface_extrapolation)
{
    VolSurface surface;
    surface.asset_id = uint256S("0x1234");
    surface.timestamp = GetTime();

    surface.strikes_pct = {95.0, 105.0};
    surface.maturities_days = {30, 365};
    surface.implied_vols = {
        {0.20, 0.25},
        {0.15, 0.20}
    };

    std::vector<Warning> warnings;

    // Extrapolate below strike range
    (void)surface.Lookup(80.0, 100, warnings);
    BOOST_CHECK_EQUAL(warnings.size(), 1);
    BOOST_CHECK(warnings[0].category == WarningCategory::INTERPOLATION);
    BOOST_CHECK(warnings[0].severity == WarningSeverity::INFO);

    // Extrapolate beyond maturity range
    warnings.clear();
    (void)surface.Lookup(100.0, 730, warnings);
    BOOST_CHECK_EQUAL(warnings.size(), 1);
}

BOOST_AUTO_TEST_CASE(vol_surface_validation)
{
    VolSurface surface;
    surface.asset_id = uint256S("0x1234");
    surface.timestamp = GetTime();

    // Empty surface
    auto err = surface.Validate();
    BOOST_CHECK(err.has_value());

    // Mismatched dimensions
    surface.strikes_pct = {90.0, 110.0};
    surface.maturities_days = {30, 365};
    surface.implied_vols = {{0.15}};  // Only 1x1 instead of 2x2
    err = surface.Validate();
    BOOST_CHECK(err.has_value());

    // Invalid volatility (outside reasonable range)
    surface.implied_vols = {
        {-0.15, 0.20},
        {0.12, 0.18}
    };
    err = surface.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("outside") != std::string::npos);

    // Valid surface
    surface.implied_vols = {
        {0.15, 0.20},
        {0.12, 0.18}
    };
    err = surface.Validate();
    BOOST_CHECK(!err.has_value());
}

// ============================================================================
// Correlation Matrix Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(correlation_matrix_lookup)
{
    CorrelationMatrix matrix;
    matrix.timestamp = GetTime();

    uint256 asset1 = uint256S("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    uint256 asset2 = uint256S("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    uint256 asset3 = uint256S("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

    matrix.asset_ids = {asset1, asset2, asset3};

    // 3x3 correlation matrix
    // Diagonal = 1.0, off-diagonal = 0.5
    matrix.corr = {
        {1.0, 0.5, 0.3},
        {0.5, 1.0, 0.6},
        {0.3, 0.6, 1.0}
    };

    std::vector<Warning> warnings;

    // Lookup existing correlations
    double corr_12 = matrix.Lookup(asset1, asset2, warnings);
    BOOST_CHECK_CLOSE(corr_12, 0.5, 0.001);
    BOOST_CHECK(warnings.empty());

    // Symmetric lookup
    double corr_21 = matrix.Lookup(asset2, asset1, warnings);
    BOOST_CHECK_CLOSE(corr_21, 0.5, 0.001);

    // Self-correlation
    double corr_11 = matrix.Lookup(asset1, asset1, warnings);
    BOOST_CHECK_CLOSE(corr_11, 1.0, 0.001);

    // Missing asset (returns 0.0 = independence assumption)
    uint256 missing = uint256S("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
    warnings.clear();
    double corr_missing = matrix.Lookup(asset1, missing, warnings);
    BOOST_CHECK_EQUAL(corr_missing, 0.0);
    BOOST_CHECK_EQUAL(warnings.size(), 1);
    BOOST_CHECK(warnings[0].category == WarningCategory::MODEL);
}

BOOST_AUTO_TEST_CASE(correlation_matrix_psd_validation)
{
    CorrelationMatrix matrix;
    matrix.timestamp = GetTime();

    uint256 a = uint256S("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF11");
    uint256 b = uint256S("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF22");

    matrix.asset_ids = {a, b};

    // Valid PSD matrix
    matrix.corr = {
        {1.0, 0.5},
        {0.5, 1.0}
    };
    auto err = matrix.Validate();
    BOOST_CHECK(!err.has_value());

    // Non-symmetric matrix
    matrix.corr = {
        {1.0, 0.5},
        {0.6, 1.0}  // Should be 0.5
    };
    err = matrix.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("symmetric") != std::string::npos);

    // Invalid diagonal
    matrix.corr = {
        {0.9, 0.5},  // Diagonal should be 1.0
        {0.5, 1.0}
    };
    err = matrix.Validate();
    BOOST_CHECK(err.has_value());

    // Correlation out of range
    matrix.corr = {
        {1.0, 1.5},  // Correlation > 1
        {1.5, 1.0}
    };
    err = matrix.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("range") != std::string::npos);

    // Non-PSD matrix (logically inconsistent correlations)
    // If A and B are highly correlated (0.9), and B and C are highly correlated (0.9),
    // but A and C are negatively correlated (-0.9), this violates triangle inequality
    uint256 c = uint256S("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF33");
    matrix.asset_ids = {a, b, c};
    matrix.corr = {
        {1.0,   0.9,  -0.9},
        {0.9,   1.0,   0.9},
        {-0.9,  0.9,   1.0}
    };
    err = matrix.Validate();
    BOOST_CHECK(err.has_value());
    BOOST_CHECK(err->find("positive semi-definite") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace pricing
} // namespace wallet
