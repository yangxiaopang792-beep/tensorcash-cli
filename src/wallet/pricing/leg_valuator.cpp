// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/leg_valuator.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/discount_curve.h>
#include <wallet/pricing/fx_matrix.h>
#include <tinyformat.h>
#include <cmath>

namespace wallet {
namespace pricing {

LegPV LegValuator::PresentValue(const wallet::AssetLeg& leg,
                                 const PricingContext& ctx,
                                 uint32_t maturity_days,
                                 const uint256& report_asset,
                                 bool report_is_native,
                                 int64_t current_time,
                                 PriceSource source)
{
    std::vector<Warning> warnings;

    // Convert uint64_t units to double for calculations
    // This preserves full precision for amounts up to 2^53
    const double spot_value = static_cast<double>(leg.units);

    if (leg.units == 0) {
        warnings.push_back(Warning::Info(
            WarningCategory::MODEL,
            "Leg has zero units"
        ));
    }

    // Step 1: Get discount factor for leg's asset
    double discount_factor = 1.0;

    auto curve_opt = ctx.GetCurve(leg.asset_id, leg.is_native, source);
    if (!curve_opt) {
        warnings.push_back(Warning::Critical(
            WarningCategory::COVERAGE,
            strprintf("Missing discount curve for asset %s%s",
                     leg.is_native ? "native" : leg.asset_id.GetHex().substr(0, 8),
                     leg.is_native ? "" : "..."),
            0.0
        ));
        // Fallback: use DF = 1.0 (no discounting)
    } else {
        std::vector<Warning> curve_warnings;
        discount_factor = curve_opt->GetDiscountFactor(maturity_days, curve_warnings);
        warnings.insert(warnings.end(), curve_warnings.begin(), curve_warnings.end());
    }

    // Step 3: Apply discount
    double pv_leg_asset = spot_value * discount_factor;

    // Step 4: Convert to report asset via FX
    double spot_fx = 1.0;

    // Check if conversion is needed
    bool needs_fx = (leg.asset_id != report_asset) || (leg.is_native != report_is_native);

    if (needs_fx) {
        FXResult fx_result = ctx.GetFXRate(leg.asset_id, report_asset,
                                          leg.is_native, report_is_native,
                                          current_time, source);
        spot_fx = fx_result.rate;
        warnings.insert(warnings.end(), fx_result.warnings.begin(), fx_result.warnings.end());

        if (spot_fx == 0.0) {
            warnings.push_back(Warning::Critical(
                WarningCategory::MARKET_DATA,
                strprintf("FX rate unavailable for %s → %s",
                         leg.is_native ? "native" : leg.asset_id.GetHex().substr(0, 8),
                         report_is_native ? "native" : report_asset.GetHex().substr(0, 8)),
                0.0
            ));
            spot_fx = 1.0;  // Fallback
        }
    }

    double pv_tsc = pv_leg_asset * spot_fx;

    return LegPV(pv_tsc, discount_factor, spot_fx, warnings);
}

uint32_t LegValuator::HeightToDays(uint32_t height_delta)
{
    // Bitcoin block target: 10 minutes = 600 seconds
    // Expected blocks per day: 144
    const uint32_t blocks_per_day = 144;
    return (height_delta + blocks_per_day - 1) / blocks_per_day;  // Round up
}

double LegValuator::DaysToYears(uint32_t days)
{
    // ACT/365 convention
    return static_cast<double>(days) / 365.0;
}

} // namespace pricing
} // namespace wallet
