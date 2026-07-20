// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Slice 5f-6a — the per-feed scalar forward curve (E[X] at a block horizon): validation, log-linear
// interpolation + flat extrapolation, staleness, history-stat estimation, and the drift-model builder.

#include <wallet/pricing/scalar_forward_curve.h>
#include <wallet/pricing/warnings.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <vector>

using namespace wallet::pricing;

BOOST_AUTO_TEST_SUITE(scalar_forward_curve_tests)

namespace {
ScalarForwardCurve Curve(std::vector<uint32_t> h, std::vector<double> f)
{
    ScalarForwardCurve c;
    c.horizons_blocks = std::move(h);
    c.forward_cross_rates = std::move(f);
    return c;
}
}

BOOST_AUTO_TEST_CASE(validate_accept_and_reject)
{
    BOOST_CHECK(!Curve({10, 20, 30}, {100, 200, 400}).Validate().has_value()); // ok
    BOOST_CHECK(Curve({}, {}).Validate().has_value());                          // empty
    BOOST_CHECK(Curve({10, 20}, {100}).Validate().has_value());                 // length mismatch
    BOOST_CHECK(Curve({10, 10}, {100, 200}).Validate().has_value());            // non-ascending
    BOOST_CHECK(Curve({10, 20}, {100, 0}).Validate().has_value());              // non-positive
    BOOST_CHECK(Curve({10, 20}, {100, -5}).Validate().has_value());             // negative
}

BOOST_AUTO_TEST_CASE(forward_scalar_interpolation_and_extrapolation)
{
    const ScalarForwardCurve c = Curve({10, 20}, {100.0, 400.0});
    std::vector<Warning> w;

    // Exact nodes.
    BOOST_CHECK_CLOSE(*c.ForwardCrossRate(10, w), 100.0, 1e-9);
    BOOST_CHECK_CLOSE(*c.ForwardCrossRate(20, w), 400.0, 1e-9);
    // Log-linear midpoint: exp(0.5*(ln100 + ln400)) = sqrt(40000) = 200.
    BOOST_CHECK_CLOSE(*c.ForwardCrossRate(15, w), 200.0, 1e-6);

    // Flat extrapolation both ends (+ warnings).
    const size_t before = w.size();
    BOOST_CHECK_CLOSE(*c.ForwardCrossRate(5, w), 100.0, 1e-9);
    BOOST_CHECK_GT(w.size(), before);
    const size_t mid = w.size();
    BOOST_CHECK_CLOSE(*c.ForwardCrossRate(30, w), 400.0, 1e-9);
    BOOST_CHECK_GT(w.size(), mid);

    // Empty curve -> nullopt + critical warning.
    std::vector<Warning> we;
    BOOST_CHECK(!Curve({}, {}).ForwardCrossRate(10, we).has_value());
    BOOST_CHECK(!we.empty());
}

BOOST_AUTO_TEST_CASE(staleness)
{
    ScalarForwardCurve c = Curve({10}, {100.0});
    c.timestamp = 1'000'000;
    BOOST_CHECK(!c.CheckStaleness(1'000'000 + 100, 43200, 86400).has_value()); // fresh
    BOOST_CHECK(c.CheckStaleness(1'000'000 + 50000, 43200, 86400).has_value()); // warn
    BOOST_CHECK(c.CheckStaleness(1'000'000 + 90000, 43200, 86400).has_value()); // critical
    ScalarForwardCurve c0 = Curve({10}, {100.0}); // timestamp 0 -> never stale
    BOOST_CHECK(!c0.CheckStaleness(9'999'999, 43200, 86400).has_value());
}

BOOST_AUTO_TEST_CASE(history_stats_doubling_series)
{
    // X doubles every stride: ratios all 2 -> drift = ln(2)/stride, zero variance -> sigma 0.
    const std::vector<double> samples{100, 200, 400, 800};
    const ScalarHistoryStats s = EstimateScalarHistoryStats(samples, /*stride_blocks=*/1, /*spacing_sec=*/600);
    BOOST_CHECK_CLOSE(s.mean_drift_per_block, std::log(2.0), 1e-6);
    BOOST_CHECK_SMALL(s.sigma_annual, 1e-9);
    BOOST_CHECK_EQUAL(s.samples, 3u);

    // Degenerate inputs -> zeroed stats.
    BOOST_CHECK_EQUAL(EstimateScalarHistoryStats({100}, 1, 600).samples, 0u);
    BOOST_CHECK_EQUAL(EstimateScalarHistoryStats(samples, 0, 600).samples, 0u);
}

BOOST_AUTO_TEST_CASE(model_curve_builder)
{
    // E[X](h) = 100 * exp(ln2 * h) -> 100, 200, 400 at horizons 0,1,2.
    const ScalarForwardCurve c = BuildModelScalarForwardCurve(100.0, std::log(2.0), {0, 1, 2}, /*ts=*/42);
    BOOST_REQUIRE_EQUAL(c.forward_cross_rates.size(), 3u);
    BOOST_CHECK_CLOSE(c.forward_cross_rates[0], 100.0, 1e-6);
    BOOST_CHECK_CLOSE(c.forward_cross_rates[1], 200.0, 1e-6);
    BOOST_CHECK_CLOSE(c.forward_cross_rates[2], 400.0, 1e-6);
    BOOST_CHECK(c.provenance == ScalarCurveProvenance::MODEL);
    BOOST_CHECK(!c.Validate().has_value());
}

BOOST_AUTO_TEST_SUITE_END()
