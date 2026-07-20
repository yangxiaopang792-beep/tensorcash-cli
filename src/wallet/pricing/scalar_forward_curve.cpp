// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricing/scalar_forward_curve.h>

#include <tinyformat.h>

#include <algorithm>
#include <cmath>

namespace wallet {
namespace pricing {

const char* ScalarCurveProvenanceToString(ScalarCurveProvenance p)
{
    switch (p) {
    case ScalarCurveProvenance::FLAT: return "flat";
    case ScalarCurveProvenance::MODEL: return "model";
    case ScalarCurveProvenance::MARK: return "mark";
    case ScalarCurveProvenance::MARKET: return "market";
    }
    return "unknown";
}

std::optional<std::string> ScalarForwardCurve::Validate() const
{
    if (horizons_blocks.size() != forward_cross_rates.size()) {
        return "scalar forward curve: horizons and forward_cross_rates length mismatch";
    }
    if (horizons_blocks.empty()) {
        return "scalar forward curve: empty";
    }
    for (size_t i = 0; i < forward_cross_rates.size(); ++i) {
        if (!(forward_cross_rates[i] > 0.0) || !std::isfinite(forward_cross_rates[i])) {
            return strprintf("scalar forward curve: forward_cross_rate[%u] must be finite and > 0", i);
        }
        if (i > 0 && horizons_blocks[i] <= horizons_blocks[i - 1]) {
            return "scalar forward curve: horizons must be strictly ascending";
        }
    }
    return std::nullopt;
}

std::optional<double> ScalarForwardCurve::ForwardCrossRate(uint32_t horizon_blocks,
                                                        std::vector<Warning>& warnings) const
{
    if (horizons_blocks.empty() || horizons_blocks.size() != forward_cross_rates.size()) {
        warnings.push_back(Warning::Critical(WarningCategory::COVERAGE, "Scalar forward curve is empty"));
        return std::nullopt;
    }

    // Flat extrapolation at both ends; log-linear interpolation in between (scalars > 0).
    if (horizon_blocks <= horizons_blocks.front()) {
        if (horizon_blocks < horizons_blocks.front()) {
            warnings.push_back(Warning::Info(WarningCategory::MODEL,
                "Scalar horizon before first curve node; flat-extrapolated"));
        }
        return forward_cross_rates.front();
    }
    if (horizon_blocks >= horizons_blocks.back()) {
        if (horizon_blocks > horizons_blocks.back()) {
            warnings.push_back(Warning::Warn(WarningCategory::MODEL,
                "Scalar horizon beyond last curve node; flat-extrapolated"));
        }
        return forward_cross_rates.back();
    }

    for (size_t i = 1; i < horizons_blocks.size(); ++i) {
        if (horizon_blocks <= horizons_blocks[i]) {
            const double h0 = static_cast<double>(horizons_blocks[i - 1]);
            const double h1 = static_cast<double>(horizons_blocks[i]);
            const double w = (h1 > h0) ? (static_cast<double>(horizon_blocks) - h0) / (h1 - h0) : 0.0;
            const double l0 = std::log(forward_cross_rates[i - 1]);
            const double l1 = std::log(forward_cross_rates[i]);
            return std::exp(l0 + w * (l1 - l0));
        }
    }
    return forward_cross_rates.back();
}

std::optional<Warning> ScalarForwardCurve::CheckStaleness(int64_t current_time,
                                                          int64_t warn_threshold_sec,
                                                          int64_t critical_threshold_sec) const
{
    const int64_t age = current_time - timestamp;
    if (timestamp == 0 || age < warn_threshold_sec) return std::nullopt;
    if (age >= critical_threshold_sec) {
        return Warning::Critical(WarningCategory::MARKET_DATA,
            strprintf("Scalar forward curve is %d s old", age), static_cast<double>(age));
    }
    return Warning::Warn(WarningCategory::MARKET_DATA,
        strprintf("Scalar forward curve is %d s old", age), static_cast<double>(age));
}

ScalarHistoryStats EstimateScalarHistoryStats(const std::vector<double>& samples,
                                              uint32_t stride_blocks,
                                              int64_t spacing_sec)
{
    ScalarHistoryStats out;
    if (samples.size() < 2 || stride_blocks == 0 || spacing_sec <= 0) return out;

    // Per-sample log-returns r_i = ln(X_i / X_{i-1}); ratios for the mean-consistent drift.
    std::vector<double> log_returns;
    double ratio_sum = 0.0;
    size_t ratio_n = 0;
    for (size_t i = 1; i < samples.size(); ++i) {
        if (!(samples[i] > 0.0) || !(samples[i - 1] > 0.0)) continue;
        const double ratio = samples[i] / samples[i - 1];
        ratio_sum += ratio;
        ++ratio_n;
        log_returns.push_back(std::log(ratio));
    }
    if (log_returns.empty() || ratio_n == 0) return out;

    const double S = static_cast<double>(stride_blocks);
    // Mean-consistent (martingale) log-growth of E[X]: ln(arithmetic mean of ratios) per block.
    out.mean_drift_per_block = std::log(ratio_sum / static_cast<double>(ratio_n)) / S;

    double mean_r = 0.0;
    for (double r : log_returns) mean_r += r;
    mean_r /= static_cast<double>(log_returns.size());
    double sse = 0.0;
    for (double r : log_returns) sse += (r - mean_r) * (r - mean_r);
    const size_t k = log_returns.size();
    const double var_per_sample = (k > 1) ? sse / static_cast<double>(k - 1) : 0.0;
    const double var_per_block = var_per_sample / S;
    const double blocks_per_year = (365.0 * 24.0 * 3600.0) / static_cast<double>(spacing_sec);
    out.sigma_annual = std::sqrt(std::max(0.0, var_per_block * blocks_per_year));
    out.samples = k;
    return out;
}

ScalarForwardCurve BuildModelScalarForwardCurve(double current_cross_rate,
                                                double drift_per_block,
                                                const std::vector<uint32_t>& horizons_blocks,
                                                int64_t timestamp)
{
    ScalarForwardCurve curve;
    curve.provenance = ScalarCurveProvenance::MODEL;
    curve.timestamp = timestamp;
    for (uint32_t h : horizons_blocks) {
        curve.horizons_blocks.push_back(h);
        curve.forward_cross_rates.push_back(current_cross_rate * std::exp(drift_per_block * static_cast<double>(h)));
    }
    return curve;
}

} // namespace pricing
} // namespace wallet
