// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_FORWARD_PRICER_H
#define BITCOIN_WALLET_PRICING_FORWARD_PRICER_H

#include <wallet/pricing/leg_valuator.h>
#include <wallet/pricing/spread_option.h>
#include <wallet/pricing/warnings.h>
#include <wallet/pricing/fx_matrix.h>
#include <serialize.h>
#include <vector>
#include <array>

namespace wallet {
namespace pricing {

class PricingContext;

/**
 * Forward contract valuation with IM-capped DvP structure
 *
 * Structure:
 * - Alice delivers receive_leg to Bob at maturity
 * - Bob delivers pay_leg to Alice at maturity
 * - Net spread = PV(receive) - PV(pay)
 * - Alice holds IM_Alice, Bob holds IM_Bob
 *
 * Options from IM caps:
 * - Alice short call: -max(net_spread - IM_Bob, 0) [Bob can walk away if spread too negative]
 * - Alice long put: +max(-IM_Alice - net_spread, 0) [Alice can walk away if spread too positive]
 *
 * MTM: net_spread - short_call + long_put + premium_pv
 */
struct ForwardValuation {
    // Present values in TSC
    double pv_receive{0.0};        // PV(Bob → Alice delivery)
    double pv_pay{0.0};            // PV(Alice → Bob delivery)
    double net_spread_value{0.0};  // pv_receive - pv_pay
    double premium_pv{0.0};        // Upfront premium (if any)

    // Option values (IM caps)
    double alice_short_call_value{0.0};  // -max(spread - IM_Bob, 0)
    double alice_long_put_value{0.0};    // +max(-IM_Alice - spread, 0)

    // Mark-to-market
    double alice_mtm{0.0};         // net_spread - short_call + long_put + premium
    double bob_mtm{0.0};           // -alice_mtm

    // Risk metrics
    double alice_exposure_uncapped{0.0};  // max(0, -net_spread)
    double bob_exposure_uncapped{0.0};    // max(0, net_spread)
    double im_coverage_alice{0.0};        // IM_Alice / alice_exposure
    double im_coverage_bob{0.0};          // IM_Bob / bob_exposure

    // Diagnostics: inferred per-unit spot levels in reporting currency
    double spot_A0{0.0};  // pay_leg asset spot
    double spot_B0{0.0};  // receive_leg asset spot
    double spot_C0{0.0};  // im_alice_leg asset spot
    double spot_D0{0.0};  // im_bob_leg asset spot
    bool model_unreliable{false}; // true if structural preconditions are violated

    // Greeks for spread options
    SpreadOption::SpreadGreeks spread_greeks_call;
    SpreadOption::SpreadGreeks spread_greeks_put;

    struct AssetGreeks {
        // Ordering: 0=receive, 1=pay, 2=im_alice, 3=im_bob
        std::array<double, 4> delta{0.0, 0.0, 0.0, 0.0};
        std::array<double, 4> vega{0.0, 0.0, 0.0, 0.0};
        std::array<double, 4> gamma{0.0, 0.0, 0.0, 0.0};
        // Cross-gamma symmetric matrix [i][j] = ∂²V/∂Si∂Sj for i<j (diagonal uses gamma)
        std::array<std::array<double, 4>, 4> cross_gamma{};
        // Rate deltas: sensitivities to {r_receive, r_pay, r_im_alice, r_im_bob, r_report}
        std::array<double, 5> rate_delta{0.0, 0.0, 0.0, 0.0, 0.0};

        SERIALIZE_METHODS(AssetGreeks, obj) {
            READWRITE(obj.delta, obj.vega, obj.gamma, obj.cross_gamma, obj.rate_delta);
        }
    } asset_greeks;

    // Warnings and diagnostics
    std::vector<Warning> warnings;

    SERIALIZE_METHODS(ForwardValuation, obj) {
        READWRITE(obj.pv_receive, obj.pv_pay, obj.net_spread_value, obj.premium_pv,
                  obj.alice_short_call_value, obj.alice_long_put_value,
                  obj.alice_mtm, obj.bob_mtm,
                  obj.alice_exposure_uncapped, obj.bob_exposure_uncapped,
                  obj.im_coverage_alice, obj.im_coverage_bob,
                  obj.spot_A0, obj.spot_B0, obj.spot_C0, obj.spot_D0,
                  obj.model_unreliable,
                  obj.asset_greeks,
                  obj.warnings);
    }
};

/**
 * Forward pricing engine
 * Implements IM-capped DvP valuation using spread options
 */
class ForwardPricer {
public:
    /**
     * Price a forward contract
     *
     * @param receive_leg What Bob delivers to Alice (wallet::AssetLeg)
     * @param pay_leg What Alice delivers to Bob (wallet::AssetLeg)
     * @param im_alice_leg Alice's initial margin (wallet::AssetLeg)
     * @param im_bob_leg Bob's initial margin (wallet::AssetLeg)
     * @param premium_leg Upfront premium (wallet::AssetLeg, may have units=0)
     * @param maturity_days Time to maturity in days
     * @param safety_k Minimum maturity days for warnings
     * @param ctx Pricing context
     * @param report_asset Asset ID for reporting (e.g., TSC)
     * @param report_is_native Whether report asset is native coin
     * @param current_time Unix timestamp
     * @param compute_greeks Whether to compute option greeks
     * @param source Price source (MARK or MARKET)
     * @return ForwardValuation with MTM and warnings
     */
    static ForwardValuation Price(const wallet::AssetLeg& receive_leg,
                                  const wallet::AssetLeg& pay_leg,
                                  const wallet::AssetLeg& im_alice_leg,
                                  const wallet::AssetLeg& im_bob_leg,
                                  const wallet::AssetLeg& premium_leg,
                                  uint32_t maturity_days,
                                  uint32_t safety_k,
                                  const PricingContext& ctx,
                                  const uint256& report_asset,
                                  bool report_is_native,
                                  int64_t current_time,
                                  bool compute_greeks = true,
                                  PriceSource source = PriceSource::MARKET);
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_FORWARD_PRICER_H
