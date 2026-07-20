// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICING_DIFFICULTY_PRICER_H
#define BITCOIN_WALLET_PRICING_DIFFICULTY_PRICER_H

#include <uint256.h>
#include <wallet/difficulty_contract.h>
#include <wallet/pricing/fx_matrix.h>   // PriceSource
#include <wallet/pricing/warnings.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
namespace pricing {

class PricingContext;

//! Chain/market inputs the difficulty pricer needs. Assembled by the caller (RPC / portfolio) from
//! the active chain + consensus params; the forward curve / vol surface / native discount curve are
//! pulled from the PricingContext. v1 valuation is native-TSC; report-asset FX conversion is the
//! caller's job (DIFFICULTY_DERIVATIVE.md §10.6).
struct DifficultyMarketInputs {
    uint32_t current_nbits{0};       //!< tip nBits (intrinsic + flat-fallback forecast)
    int current_height{0};           //!< tip height
    uint256 pow_limit;               //!< chain powLimit (DeriveTarget range rule)
    int64_t pow_target_spacing{600}; //!< consensus nPowTargetSpacing (sec/block) for horizon annualization
    int64_t current_time{0};         //!< unix time (staleness checks)
    PriceSource source{PriceSource::MARKET};

    //! Realized nBits @ fixing_height, read from chain when current_height >= fixing_height
    //! (the fixing is known → deterministic pricing, no forecast). §10.5.
    std::optional<uint32_t> realized_nbits;
    //! Optional explicit forward-nBits override (display / what-if); supersedes the curve forecast.
    std::optional<uint32_t> forecast_nbits_override;
};

struct DifficultyValuation {
    uint32_t current_nbits{0};
    uint32_t forecast_nbits{0};
    uint32_t strike_nbits{0};
    uint32_t fixing_height{0};
    uint32_t settle_lock_height{0};
    int current_height{0};
    int blocks_to_fixing{0};
    int blocks_to_resolvable{0};

    bool is_option{false};
    bool option_writer_is_short{false};
    bool model_unreliable{false};
    bool fixing_reached{false};            //!< underlying known (priced deterministically)

    double current_difficulty_ratio{0.0};  //!< R now = current_difficulty / strike_difficulty
    double forecast_difficulty_ratio{0.0}; //!< F_R = E[R] at the fixing height

    // Stochastic model state (DIFFICULTY_DERIVATIVE.md §10.3)
    double sigma{0.0};                     //!< annualized vol of log R used
    double tau_years{0.0};                 //!< horizon to fixing (ACT/365)
    double discount_factor{1.0};           //!< native-TSC DF to settle_lock_height
    std::string forward_provenance;        //!< flat | model | mark | market | fixed

    double long_leg_expected_owner_payout{0.0};
    double long_leg_expected_cp_payout{0.0};
    double short_leg_expected_owner_payout{0.0};
    double short_leg_expected_cp_payout{0.0};

    double long_leg_intrinsic_owner_payout{0.0};
    double long_leg_intrinsic_cp_payout{0.0};
    double short_leg_intrinsic_owner_payout{0.0};
    double short_leg_intrinsic_cp_payout{0.0};

    // MTM = PV (native atomic TSC). expected_* are discounted, model-based; intrinsic_* are at current.
    double expected_long_mtm{0.0};
    double expected_short_mtm{0.0};
    double intrinsic_long_mtm{0.0};
    double intrinsic_short_mtm{0.0};

    double expected_writer_mtm{0.0};
    double expected_buyer_mtm{0.0};
    double intrinsic_writer_mtm{0.0};
    double intrinsic_buyer_mtm{0.0};
    double premium_pv{0.0};

    // Greeks (finite-difference on the discounted model MTM)
    double long_delta_to_difficulty{0.0};   //!< dMTM / d(difficulty fractional move)
    double short_delta_to_difficulty{0.0};
    double writer_delta_to_difficulty{0.0};
    double buyer_delta_to_difficulty{0.0};

    double long_vega{0.0};                   //!< dMTM / +0.01 vol
    double short_vega{0.0};
    double writer_vega{0.0};
    double buyer_vega{0.0};

    double long_theta{0.0};                  //!< dMTM / −1 day to fixing
    double short_theta{0.0};
    double writer_theta{0.0};
    double buyer_theta{0.0};

    std::vector<Warning> warnings;
};

class DifficultyPricer {
public:
    //! Mark a difficulty CFD/option to market off the PricingContext difficulty forward curve + vol
    //! surface, discounted on the native TSC curve. Degrades gracefully: missing curve → flat tip
    //! forecast; missing vol → σ=0 deterministic point forecast (both warned). Strict superset of the
    //! prior deterministic pricer (σ→0 reproduces ComputeDiffCfdPayout exactly).
    static DifficultyValuation Price(const DifficultyContractTerms& terms,
                                     const PricingContext& ctx,
                                     const DifficultyMarketInputs& mkt,
                                     bool compute_greeks = true);
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_DIFFICULTY_PRICER_H
