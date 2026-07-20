// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_LEG_VALUATOR_H
#define BITCOIN_WALLET_PRICING_LEG_VALUATOR_H

#include <wallet/pricing/warnings.h>
#include <wallet/pricing/fx_matrix.h>
#include <wallet/contract.h>
#include <uint256.h>
#include <vector>
#include <optional>

namespace wallet {
namespace pricing {

class PricingContext;

/**
 * Present value result for a contract leg
 */
struct LegPV {
    double pv_tsc{0.0};          // Present value in TSC
    double discount_factor{1.0}; // Discount factor applied
    double spot_fx_used{1.0};    // FX rate used (asset → TSC)
    std::vector<Warning> warnings;

    LegPV() = default;
    LegPV(double pv, double df, double fx, std::vector<Warning> w = {})
        : pv_tsc(pv), discount_factor(df), spot_fx_used(fx), warnings(std::move(w)) {}
};

/**
 * Leg valuation engine
 * Computes present value of a future asset delivery using:
 * - Discount curves (ACT/365 day-count)
 * - FX triangulation (with TSC as hub by default)
 * - Staleness warnings for market data
 */
class LegValuator {
public:
    /**
     * Compute present value of a leg
     * @param leg Asset leg specification (wallet::AssetLeg from contract.h)
     * @param ctx Pricing context containing curves and FX matrix
     * @param maturity_days Time to delivery in days
     * @param report_asset Target asset for reporting
     * @param report_is_native Whether report_asset is native coin
     * @param current_time Unix timestamp for staleness checks
     * @param source Price source (MARK or MARKET)
     * @return LegPV with converted value and warnings
     */
    static LegPV PresentValue(const wallet::AssetLeg& leg,
                              const PricingContext& ctx,
                              uint32_t maturity_days,
                              const uint256& report_asset,
                              bool report_is_native,
                              int64_t current_time,
                              PriceSource source = PriceSource::MARKET);

    /**
     * Convert block height difference to days
     * Uses 10-minute target (144 blocks/day)
     * @param height_delta Number of blocks
     * @return Approximate days
     */
    static uint32_t HeightToDays(uint32_t height_delta);

    /**
     * Convert days to years for ACT/365 convention
     * @param days Number of days
     * @return Years (days / 365.0)
     */
    static double DaysToYears(uint32_t days);
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_LEG_VALUATOR_H
