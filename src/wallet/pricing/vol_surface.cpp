// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/vol_surface.h>
#include <tinyformat.h>
#include <algorithm>

namespace wallet {
namespace pricing {

std::optional<std::string> VolSurface::Validate() const
{
    if (strikes_pct.empty()) {
        return "Vol surface has no strikes";
    }

    if (maturities_days.empty()) {
        return "Vol surface has no maturities";
    }

    if (implied_vols.size() != strikes_pct.size()) {
        return strprintf("Vol surface strike count (%d) != vol rows (%d)",
                        strikes_pct.size(), implied_vols.size());
    }

    for (size_t i = 0; i < implied_vols.size(); ++i) {
        if (implied_vols[i].size() != maturities_days.size()) {
            return strprintf("Vol surface row %d has %d columns, expected %d",
                            i, implied_vols[i].size(), maturities_days.size());
        }
    }

    // Check strikes are strictly increasing
    for (size_t i = 1; i < strikes_pct.size(); ++i) {
        if (strikes_pct[i] <= strikes_pct[i-1]) {
            return strprintf("Strikes not strictly increasing at index %d: %.4f -> %.4f",
                            i-1, strikes_pct[i-1], strikes_pct[i]);
        }
    }

    // Check maturities are strictly increasing
    for (size_t i = 1; i < maturities_days.size(); ++i) {
        if (maturities_days[i] <= maturities_days[i-1]) {
            return strprintf("Maturities not strictly increasing at index %d: %d -> %d",
                            i-1, maturities_days[i-1], maturities_days[i]);
        }
    }

    // Check vols are reasonable (1% to 500%)
    for (size_t i = 0; i < implied_vols.size(); ++i) {
        for (size_t j = 0; j < implied_vols[i].size(); ++j) {
            const double vol = implied_vols[i][j];
            if (vol < 0.01 || vol > 5.0) {
                return strprintf("Vol at [%d][%d] (%.4f) outside reasonable range [0.01, 5.0]",
                                i, j, vol);
            }
        }
    }

    return std::nullopt;
}

std::optional<Warning> VolSurface::CheckStaleness(int64_t current_time,
                                                  int64_t warn_threshold_sec,
                                                  int64_t critical_threshold_sec) const
{
    const int64_t age_sec = current_time - timestamp;

    if (age_sec >= critical_threshold_sec) {
        return Warning::Critical(
            WarningCategory::MARKET_DATA,
            strprintf("Vol surface stale: %d hours old (>24h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    if (age_sec >= warn_threshold_sec) {
        return Warning::Warn(
            WarningCategory::MARKET_DATA,
            strprintf("Vol surface aging: %d hours old (>12h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    return std::nullopt;
}

double VolSurface::BilinearInterpolate(double strike_pct, uint32_t maturity_days,
                                      size_t strike_lower_idx, size_t strike_upper_idx,
                                      size_t maturity_lower_idx, size_t maturity_upper_idx) const
{
    const double K_lower = strikes_pct[strike_lower_idx];
    const double K_upper = strikes_pct[strike_upper_idx];
    const uint32_t T_lower = maturities_days[maturity_lower_idx];
    const uint32_t T_upper = maturities_days[maturity_upper_idx];

    const double vol_K0_T0 = implied_vols[strike_lower_idx][maturity_lower_idx];
    const double vol_K0_T1 = implied_vols[strike_lower_idx][maturity_upper_idx];
    const double vol_K1_T0 = implied_vols[strike_upper_idx][maturity_lower_idx];
    const double vol_K1_T1 = implied_vols[strike_upper_idx][maturity_upper_idx];

    // Weights
    const double w_K = (strike_pct - K_lower) / (K_upper - K_lower);
    const double w_T = static_cast<double>(maturity_days - T_lower) / (T_upper - T_lower);

    // Bilinear interpolation
    const double vol_interp = (1.0 - w_K) * (1.0 - w_T) * vol_K0_T0
                            + (1.0 - w_K) * w_T * vol_K0_T1
                            + w_K * (1.0 - w_T) * vol_K1_T0
                            + w_K * w_T * vol_K1_T1;

    return vol_interp;
}

double VolSurface::Lookup(double strike_pct, uint32_t maturity_days,
                          std::vector<Warning>& warnings) const
{
    if (strikes_pct.empty() || maturities_days.empty()) {
        warnings.push_back(Warning::Critical(
            WarningCategory::MARKET_DATA,
            "Vol surface is empty"
        ));
        return 0.0;
    }

    // Clamp strike to grid bounds (flat extrapolation)
    double strike_clamped = strike_pct;

    if (strike_pct < strikes_pct.front()) {
        strike_clamped = strikes_pct.front();
        warnings.push_back(Warning::Info(
            WarningCategory::INTERPOLATION,
            strprintf("Vol strike extrapolated: requested %.2f%%, using %.2f%% (lowest)",
                     strike_pct * 100, strike_clamped * 100)
        ));
    } else if (strike_pct > strikes_pct.back()) {
        strike_clamped = strikes_pct.back();
        warnings.push_back(Warning::Info(
            WarningCategory::INTERPOLATION,
            strprintf("Vol strike extrapolated: requested %.2f%%, using %.2f%% (highest)",
                     strike_pct * 100, strike_clamped * 100)
        ));
    }

    // Clamp maturity to grid bounds (flat extrapolation)
    uint32_t maturity_clamped = maturity_days;

    if (maturity_days < maturities_days.front()) {
        maturity_clamped = maturities_days.front();
        warnings.push_back(Warning::Info(
            WarningCategory::INTERPOLATION,
            strprintf("Vol maturity extrapolated: requested %d days, using %d days (shortest)",
                     maturity_days, maturity_clamped)
        ));
    } else if (maturity_days > maturities_days.back()) {
        maturity_clamped = maturities_days.back();
        warnings.push_back(Warning::Info(
            WarningCategory::INTERPOLATION,
            strprintf("Vol maturity extrapolated: requested %d days, using %d days (longest)",
                     maturity_days, maturity_clamped)
        ));
    }

    // Find bracketing strikes
    auto strike_upper_it = std::lower_bound(strikes_pct.begin(), strikes_pct.end(), strike_clamped);
    size_t strike_upper_idx = strike_upper_it - strikes_pct.begin();

    // Exact strike match
    if (strike_upper_it != strikes_pct.end() && *strike_upper_it == strike_clamped) {
        // Find bracketing maturities
        auto mat_upper_it = std::lower_bound(maturities_days.begin(), maturities_days.end(), maturity_clamped);
        size_t mat_upper_idx = mat_upper_it - maturities_days.begin();

        // Exact maturity match
        if (mat_upper_it != maturities_days.end() && *mat_upper_it == maturity_clamped) {
            return implied_vols[strike_upper_idx][mat_upper_idx];
        }

        // Interpolate maturity only
        if (mat_upper_idx == 0) {
            return implied_vols[strike_upper_idx][0];
        }

        size_t mat_lower_idx = mat_upper_idx - 1;
        const uint32_t T_lower = maturities_days[mat_lower_idx];
        const uint32_t T_upper = maturities_days[mat_upper_idx];
        const double w_T = static_cast<double>(maturity_clamped - T_lower) / (T_upper - T_lower);

        return (1.0 - w_T) * implied_vols[strike_upper_idx][mat_lower_idx]
             + w_T * implied_vols[strike_upper_idx][mat_upper_idx];
    }

    // Need to interpolate strike
    if (strike_upper_idx == 0) {
        strike_upper_idx = 1; // Use first two strikes
    }
    size_t strike_lower_idx = strike_upper_idx - 1;

    // Find bracketing maturities
    auto mat_upper_it = std::lower_bound(maturities_days.begin(), maturities_days.end(), maturity_clamped);
    size_t mat_upper_idx = mat_upper_it - maturities_days.begin();

    // Exact maturity match - interpolate strike only
    if (mat_upper_it != maturities_days.end() && *mat_upper_it == maturity_clamped) {
        const double K_lower = strikes_pct[strike_lower_idx];
        const double K_upper = strikes_pct[strike_upper_idx];
        const double w_K = (strike_clamped - K_lower) / (K_upper - K_lower);

        return (1.0 - w_K) * implied_vols[strike_lower_idx][mat_upper_idx]
             + w_K * implied_vols[strike_upper_idx][mat_upper_idx];
    }

    // Need to interpolate maturity too
    if (mat_upper_idx == 0) {
        mat_upper_idx = 1; // Use first two maturities
    }
    size_t mat_lower_idx = mat_upper_idx - 1;

    // Full bilinear interpolation
    return BilinearInterpolate(strike_clamped, maturity_clamped,
                              strike_lower_idx, strike_upper_idx,
                              mat_lower_idx, mat_upper_idx);
}

} // namespace pricing
} // namespace wallet
