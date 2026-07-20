// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricing/difficulty_curve.h>

#include <arith_uint256.h>
#include <tinyformat.h>

#include <algorithm>
#include <cmath>

namespace wallet {
namespace pricing {

double DifficultyWorkFromTarget(const arith_uint256& target)
{
    if (target == 0) return 0.0;
    // GetBlockProof: work == 2^256 / (target+1) == ~target / (target+1) + 1.
    return ((~target / (target + 1)) + 1).getdouble();
}

const char* DiffCurveProvenanceToString(DiffCurveProvenance p)
{
    switch (p) {
    case DiffCurveProvenance::FLAT: return "flat";
    case DiffCurveProvenance::MODEL: return "model";
    case DiffCurveProvenance::MARK: return "mark";
    case DiffCurveProvenance::MARKET: return "market";
    }
    return "unknown";
}

std::optional<std::string> DifficultyCurve::Validate() const
{
    if (horizons_blocks.size() != forward_difficulties.size()) {
        return "difficulty curve: horizons and forward_difficulties length mismatch";
    }
    if (horizons_blocks.empty()) {
        return "difficulty curve: empty";
    }
    for (size_t i = 0; i < forward_difficulties.size(); ++i) {
        if (!(forward_difficulties[i] > 0.0) || !std::isfinite(forward_difficulties[i])) {
            return strprintf("difficulty curve: forward_difficulty[%u] must be finite and > 0", i);
        }
        if (i > 0 && horizons_blocks[i] <= horizons_blocks[i - 1]) {
            return "difficulty curve: horizons must be strictly ascending";
        }
    }
    return std::nullopt;
}

std::optional<double> DifficultyCurve::ForwardDifficulty(uint32_t horizon_blocks,
                                                         std::vector<Warning>& warnings) const
{
    if (horizons_blocks.empty() || horizons_blocks.size() != forward_difficulties.size()) {
        warnings.push_back(Warning::Critical(WarningCategory::COVERAGE,
            "Difficulty forward curve is empty"));
        return std::nullopt;
    }

    // Flat extrapolation at both ends; log-linear interpolation in between (difficulties > 0).
    if (horizon_blocks <= horizons_blocks.front()) {
        if (horizon_blocks < horizons_blocks.front()) {
            warnings.push_back(Warning::Info(WarningCategory::MODEL,
                "Difficulty horizon before first curve node; flat-extrapolated"));
        }
        return forward_difficulties.front();
    }
    if (horizon_blocks >= horizons_blocks.back()) {
        if (horizon_blocks > horizons_blocks.back()) {
            warnings.push_back(Warning::Warn(WarningCategory::MODEL,
                "Difficulty horizon beyond last curve node; flat-extrapolated"));
        }
        return forward_difficulties.back();
    }

    for (size_t i = 1; i < horizons_blocks.size(); ++i) {
        if (horizon_blocks <= horizons_blocks[i]) {
            const double h0 = static_cast<double>(horizons_blocks[i - 1]);
            const double h1 = static_cast<double>(horizons_blocks[i]);
            const double w = (h1 > h0) ? (static_cast<double>(horizon_blocks) - h0) / (h1 - h0) : 0.0;
            const double l0 = std::log(forward_difficulties[i - 1]);
            const double l1 = std::log(forward_difficulties[i]);
            return std::exp(l0 + w * (l1 - l0));
        }
    }
    return forward_difficulties.back();
}

std::optional<Warning> DifficultyCurve::CheckStaleness(int64_t current_time,
                                                       int64_t warn_threshold_sec,
                                                       int64_t critical_threshold_sec) const
{
    const int64_t age = current_time - timestamp;
    if (timestamp == 0 || age < warn_threshold_sec) return std::nullopt;
    if (age >= critical_threshold_sec) {
        return Warning::Critical(WarningCategory::MARKET_DATA,
            strprintf("Difficulty forward curve is %d s old", age), static_cast<double>(age));
    }
    return Warning::Warn(WarningCategory::MARKET_DATA,
        strprintf("Difficulty forward curve is %d s old", age), static_cast<double>(age));
}

DifficultyHistoryStats EstimateDifficultyHistoryStats(const std::vector<double>& works,
                                                      uint32_t stride_blocks,
                                                      int64_t spacing_sec)
{
    DifficultyHistoryStats out;
    if (works.size() < 2 || stride_blocks == 0 || spacing_sec <= 0) return out;

    // Per-sample log-returns r_i = ln(D_i / D_{i-1}); ratios for the mean-consistent drift.
    std::vector<double> log_returns;
    double ratio_sum = 0.0;
    size_t ratio_n = 0;
    for (size_t i = 1; i < works.size(); ++i) {
        if (!(works[i] > 0.0) || !(works[i - 1] > 0.0)) continue;
        const double ratio = works[i] / works[i - 1];
        ratio_sum += ratio;
        ++ratio_n;
        log_returns.push_back(std::log(ratio));
    }
    if (log_returns.empty() || ratio_n == 0) return out;

    const double S = static_cast<double>(stride_blocks);
    // Drift of E[D]: ln(arithmetic mean of ratios) is the mean-consistent (martingale) log-growth.
    out.mean_drift_per_block = std::log(ratio_sum / static_cast<double>(ratio_n)) / S;

    // Sample variance of log-returns -> per-block variance -> annualized sigma.
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

DifficultyCurve BuildModelDifficultyCurve(double current_difficulty,
                                          double drift_per_block,
                                          const std::vector<uint32_t>& horizons_blocks,
                                          int64_t timestamp)
{
    DifficultyCurve curve;
    curve.provenance = DiffCurveProvenance::MODEL;
    curve.timestamp = timestamp;
    for (uint32_t h : horizons_blocks) {
        curve.horizons_blocks.push_back(h);
        curve.forward_difficulties.push_back(current_difficulty * std::exp(drift_per_block * static_cast<double>(h)));
    }
    return curve;
}

DifficultyCurve BuildRetargetAwareDifficultyCurve(double current_difficulty,
                                                  double drift_per_block,
                                                  uint32_t interval_blocks,
                                                  uint32_t blocks_into_epoch,
                                                  uint32_t max_horizon,
                                                  int64_t timestamp)
{
    DifficultyCurve curve;
    curve.provenance = DiffCurveProvenance::MODEL;
    curve.timestamp = timestamp;
    if (interval_blocks == 0) interval_blocks = 1;
    if (max_horizon == 0) max_horizon = 1;
    const double drift_per_retarget = drift_per_block * static_cast<double>(interval_blocks);

    // Skip non-ascending / duplicate nodes so the curve stays strictly ascending (Validate requirement).
    auto push = [&](uint32_t h, double d) {
        if (!curve.horizons_blocks.empty() && h <= curve.horizons_blocks.back()) return;
        curve.horizons_blocks.push_back(h);
        curve.forward_difficulties.push_back(d);
    };

    // Difficulty is flat within a retarget epoch and steps at each boundary. Flat segments are two
    // equal-value nodes (epoch start .. just-before-next-boundary); the step is a near-vertical
    // log-linear segment between (boundary-1) and (boundary).
    push(1, current_difficulty);  // current (partial) epoch — flat at current difficulty
    const uint32_t offset = blocks_into_epoch % interval_blocks;
    uint32_t boundary = (offset == 0) ? interval_blocks : (interval_blocks - offset);
    uint32_t step = 0;
    while (boundary <= max_horizon) {
        push(boundary - 1, current_difficulty * std::exp(drift_per_retarget * static_cast<double>(step)));
        ++step;
        push(boundary, current_difficulty * std::exp(drift_per_retarget * static_cast<double>(step)));
        boundary += interval_blocks;
    }
    push(max_horizon, current_difficulty * std::exp(drift_per_retarget * static_cast<double>(step)));
    return curve;
}

} // namespace pricing
} // namespace wallet
