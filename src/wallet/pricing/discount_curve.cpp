// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/discount_curve.h>
#include <tinyformat.h>
#include <cmath>
#include <algorithm>

namespace wallet {
namespace pricing {

std::optional<std::string> DiscountCurve::Validate() const
{
    if (tenors_days.empty()) {
        return "Discount curve has no tenors";
    }

    if (tenors_days.size() != zero_rates.size()) {
        return strprintf("Tenor count (%d) != rate count (%d)",
                        tenors_days.size(), zero_rates.size());
    }

    // Check tenors are strictly increasing
    for (size_t i = 1; i < tenors_days.size(); ++i) {
        if (tenors_days[i] <= tenors_days[i-1]) {
            return strprintf("Tenors not strictly increasing at index %d: %d -> %d",
                            i-1, tenors_days[i-1], tenors_days[i]);
        }
    }

    // Check rates are reasonable (-5% to +50% annualized)
    for (size_t i = 0; i < zero_rates.size(); ++i) {
        if (zero_rates[i] < -0.05 || zero_rates[i] > 0.50) {
            return strprintf("Zero rate at index %d (%.4f) outside reasonable range [-0.05, 0.50]",
                            i, zero_rates[i]);
        }
    }

    return std::nullopt;
}

std::optional<Warning> DiscountCurve::CheckStaleness(int64_t current_time,
                                                     int64_t warn_threshold_sec,
                                                     int64_t critical_threshold_sec) const
{
    const int64_t age_sec = current_time - timestamp;

    if (age_sec >= critical_threshold_sec) {
        return Warning::Critical(
            WarningCategory::MARKET_DATA,
            strprintf("Discount curve stale: %d hours old (>24h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    if (age_sec >= warn_threshold_sec) {
        return Warning::Warn(
            WarningCategory::MARKET_DATA,
            strprintf("Discount curve aging: %d hours old (>12h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    return std::nullopt;
}

double DiscountCurve::GetZeroRate(uint32_t maturity_days, std::vector<Warning>& warnings) const
{
    if (tenors_days.empty()) {
        warnings.push_back(Warning::Critical(
            WarningCategory::MARKET_DATA,
            "Discount curve is empty"
        ));
        return 0.0;
    }

    // Handle zero maturity
    if (maturity_days == 0) {
        return 0.0;
    }

    // Extrapolate below shortest tenor (flat)
    if (maturity_days < tenors_days.front()) {
        warnings.push_back(Warning::Info(
            WarningCategory::INTERPOLATION,
            strprintf("Maturity %d days < shortest tenor %d days, using flat extrapolation",
                     maturity_days, tenors_days.front())
        ));
        return zero_rates.front();
    }

    // Extrapolate beyond longest tenor (flat)
    if (maturity_days > tenors_days.back()) {
        warnings.push_back(Warning::Info(
            WarningCategory::INTERPOLATION,
            strprintf("Maturity %d days > longest tenor %d days, using flat extrapolation",
                     maturity_days, tenors_days.back())
        ));
        return zero_rates.back();
    }

    // Find bracketing tenors for interpolation
    auto upper_it = std::lower_bound(tenors_days.begin(), tenors_days.end(), maturity_days);

    // Exact match
    if (upper_it != tenors_days.end() && *upper_it == maturity_days) {
        size_t idx = upper_it - tenors_days.begin();
        return zero_rates[idx];
    }

    // Interpolate (log-linear on zero rates)
    size_t i_upper = upper_it - tenors_days.begin();
    size_t i_lower = i_upper - 1;

    const uint32_t T_lower = tenors_days[i_lower];
    const uint32_t T_upper = tenors_days[i_upper];
    const double r_lower = zero_rates[i_lower];
    const double r_upper = zero_rates[i_upper];

    // Log-linear interpolation: log(r) is linear in T
    // r(T) = exp(log(r_lower) + [log(r_upper) - log(r_lower)] * (T - T_lower) / (T_upper - T_lower))
    //
    // For safety when rates can be zero or negative, use linear interpolation instead
    const double weight = static_cast<double>(maturity_days - T_lower) / (T_upper - T_lower);
    const double r_interp = r_lower + weight * (r_upper - r_lower);

    return r_interp;
}

std::vector<DiscountCurve::RateBucketWeight>
DiscountCurve::GetZeroRateBucketWeights(uint32_t maturity_days) const
{
    std::vector<RateBucketWeight> out;

    if (tenors_days.empty() || maturity_days == 0) {
        return out;
    }

    // Below shortest tenor: all weight on front node
    if (maturity_days <= tenors_days.front()) {
        out.push_back({tenors_days.front(), 1.0});
        return out;
    }

    // Beyond longest tenor: all weight on last node
    if (maturity_days >= tenors_days.back()) {
        out.push_back({tenors_days.back(), 1.0});
        return out;
    }

    // Find bracketing tenors
    auto upper_it = std::lower_bound(tenors_days.begin(), tenors_days.end(), maturity_days);

    // Exact match
    if (upper_it != tenors_days.end() && *upper_it == maturity_days) {
        size_t idx = upper_it - tenors_days.begin();
        out.push_back({tenors_days[idx], 1.0});
        return out;
    }

    // Interpolate between adjacent nodes
    size_t i_upper = upper_it - tenors_days.begin();
    size_t i_lower = i_upper - 1;

    const uint32_t T_lower = tenors_days[i_lower];
    const uint32_t T_upper = tenors_days[i_upper];

    const double w = static_cast<double>(maturity_days - T_lower) /
                     static_cast<double>(T_upper - T_lower);

    out.push_back({T_lower, 1.0 - w});
    out.push_back({T_upper, w});
    return out;
}

double DiscountCurve::GetDiscountFactor(uint32_t maturity_days, std::vector<Warning>& warnings) const
{
    const double zero_rate = GetZeroRate(maturity_days, warnings);

    // DF = exp(-r * T)   where T is in years (ACT/365)
    const double T_years = maturity_days / 365.0;
    const double df = std::exp(-zero_rate * T_years);

    return df;
}

} // namespace pricing
} // namespace wallet
