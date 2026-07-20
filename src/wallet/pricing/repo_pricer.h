// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_REPO_PRICER_H
#define BITCOIN_WALLET_PRICING_REPO_PRICER_H

#include <wallet/pricing/leg_valuator.h>
#include <wallet/pricing/black_scholes.h>
#include <wallet/pricing/greeks.h>
#include <wallet/pricing/warnings.h>
#include <wallet/pricing/fx_matrix.h>
#include <serialize.h>
#include <vector>
#include <array>

namespace wallet {
namespace pricing {

class PricingContext;

/**
 * Repo contract valuation result
 *
 * Structure:
 * - Borrower delivers principal + interest at maturity
 * - Lender holds collateral, has call option to claim if borrower defaults
 * - Lender MTM = PV(principal) + PV(interest) - option_value
 * - Borrower MTM = -Lender MTM
 */
struct RepoValuation {
    // Present values in TSC
    double principal_pv{0.0};      // PV of principal repayment
    double interest_pv{0.0};       // PV of interest payment
    double collateral_pv{0.0};     // PV of collateral (in TSC)

    // Option valuation
    double collateral_option{0.0}; // Borrower's walkaway (put) option value (Black-Scholes)

    // Mark-to-market
    double lender_mtm{0.0};        // Lender's position value
    double borrower_mtm{0.0};      // Borrower's position value = -lender_mtm

    // Risk metrics
    double coverage_ratio{0.0};    // collateral / (principal + interest)
    double ltv_pct{0.0};           // 100 / coverage_ratio
    double over_collat_pct{0.0};   // (coverage - 1) * 100

    // Greeks for collateral option
    Greeks collateral_greeks;

    struct AssetGreeks {
        // Ordering: 0=principal, 1=interest, 2=collateral
        std::array<double, 3> delta{0.0, 0.0, 0.0};
        std::array<double, 3> vega{0.0, 0.0, 0.0};
        std::array<double, 3> gamma{0.0, 0.0, 0.0};
        std::array<std::array<double, 3>, 3> cross_gamma{};
        // Rate deltas: r_principal, r_interest, r_collateral, r_report
        std::array<double, 4> rate_delta{0.0, 0.0, 0.0, 0.0};

        SERIALIZE_METHODS(AssetGreeks, obj) {
            READWRITE(obj.delta, obj.vega, obj.gamma, obj.cross_gamma, obj.rate_delta);
        }
    } asset_greeks;

    // Warnings and diagnostics
    std::vector<Warning> warnings;

    SERIALIZE_METHODS(RepoValuation, obj) {
        READWRITE(obj.principal_pv, obj.interest_pv, obj.collateral_pv,
                  obj.collateral_option,
                  obj.lender_mtm, obj.borrower_mtm,
                  obj.coverage_ratio, obj.ltv_pct, obj.over_collat_pct,
                  obj.collateral_greeks, obj.asset_greeks, obj.warnings);
    }
};

/**
 * Repo pricing engine
 * Implements collateral coverage analysis and Black-Scholes option pricing
 */
class RepoPricer {
public:
    /**
     * Price a repo contract
     *
     * @param principal_leg Principal amount to be repaid (wallet::AssetLeg)
     * @param interest_leg Interest payment (wallet::AssetLeg)
     * @param collateral_leg Collateral held by lender (wallet::AssetLeg)
     * @param maturity_days Time to maturity in days
     * @param safety_k Minimum maturity days for warnings (e.g., 7)
     * @param ctx Pricing context with curves/FX/vols
     * @param report_asset Asset ID for reporting (e.g., TSC)
     * @param report_is_native Whether report asset is native coin
     * @param current_time Unix timestamp
     * @param compute_greeks Whether to compute option greeks (expensive)
     * @return RepoValuation with MTM and warnings
     */
    static RepoValuation Price(const wallet::AssetLeg& principal_leg,
                               const wallet::AssetLeg& interest_leg,
                               const wallet::AssetLeg& collateral_leg,
                               uint32_t maturity_days,
                               uint32_t safety_k,
                               const PricingContext& ctx,
                               const uint256& report_asset,
                               bool report_is_native,
                               int64_t current_time,
                               bool compute_greeks = true,
                               PriceSource source = PriceSource::MARKET,
                               bool include_inception_cashflows = false);

private:
    /**
     * Compute collateral option value
     * Modeled as the borrower's walkaway (put) on collateral vs obligation.
     * When collateral understates the obligation, the option gains value.
     *
     * Model: European call on collateral forward value with strike = forward(principal + interest)
     *
     * IMPORTANT: collateral_forward and strike_forward must be forward values at maturity,
     * not present values. The option is priced in the forward framework and then
     * discounted back to present.
     */
    static double PriceCollateralOption(double collateral_forward,
                                        double strike_forward,
                                        uint32_t maturity_days,
                                        double r,
                                        double sigma,
                                        Greeks* greeks_out,
                                        BlackScholes::OptionType option_type = BlackScholes::OptionType::CALL);
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_REPO_PRICER_H
