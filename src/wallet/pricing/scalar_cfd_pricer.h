// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TENSORCASH_WALLET_PRICING_SCALAR_CFD_PRICER_H
#define TENSORCASH_WALLET_PRICING_SCALAR_CFD_PRICER_H

// Mark-to-market pricer for a bilateral scalar CFD (CFD_GENERALISATION.md §7, Slice 5f-6b). The underlying
// is an FX cross rate X = base/quote; the strike K is in the same quote convention. The pricer shares the
// CONSENSUS direction convention exactly: long owner loses when X < K, short owner loses when X > K, with
// the capped loss fraction clamp(lambda * |X-K| / denom, 0, 1), denom = K (mode 0 STRIKE) or X (mode 1
// REALIZED). Intrinsic is computed through consensus ComputeScalarCfdPayout; the stochastic mark is the
// numerical expectation of the SAME loss fraction over a lognormal R = X/K with forward F/K and vol sigma,
// so sigma -> 0 reproduces the deterministic mark. MTM is in the COLLATERAL numeraire (vault_im units);
// PV discounting uses the collateral asset's discount factor supplied in the market inputs.

#include <uint256.h>
#include <wallet/pricing/scalar_forward_curve.h> // ScalarCurveProvenance
#include <wallet/pricing/warnings.h>
#include <wallet/scalar_cfd_contract.h>

#include <optional>
#include <vector>

namespace wallet {
namespace pricing {

//! Market/chain inputs for one mark. The forward cross rate + sigma + discount factor are RESOLVED by the
//! caller (the 5f-6c PricingContext glue) from the per-feed forward curve, vol surface, and the COLLATERAL
//! asset's discount curve — so this pricer is pure and unit-testable in isolation. `forward_cross_rate`
//! and the strike K (decoded from terms) must be in the SAME units (only the ratio F/K is used).
struct ScalarCfdMarketInputs {
    uint256 current_scalar;                    //!< X now (on-chain encoding) — intrinsic mark
    std::optional<uint256> realized_scalar;    //!< X at the fixing if known -> deterministic (sigma ignored)
    bool realized_is_fallback{false};          //!< the realized fixing is the committed fallback, not a real publication
    double forward_cross_rate{0.0};            //!< F = E[X], from the forward curve (same units as the scalar)
    ScalarCurveProvenance forward_provenance{ScalarCurveProvenance::FLAT};
    double sigma{0.0};                         //!< annualized vol of log X (== vol of log R)
    double tau_years{0.0};                     //!< horizon to the fixing (ACT/365)
    double discount_factor{1.0};               //!< collateral-asset DF to the settlement horizon (the later of
                                               //!< settle_lock_height and the resolvable deadline; resolved by the caller, NOT native-only)
    int current_height{0};
    int blocks_to_fixing{0};
    int blocks_to_resolvable{0};
    bool collateral_is_native{true};           //!< numeraire label only (TSC vs the asset C)
};

struct ScalarCfdValuation {
    bool model_unreliable{false};
    bool fixing_reached{false};                //!< X known -> priced deterministically
    bool is_fallback{false};                   //!< the known fixing is the committed fallback (not a real publication)

    double current_ratio{0.0};                 //!< R now = X_now / K
    double forecast_ratio{0.0};                //!< F_R = F / K
    double sigma{0.0};
    double tau_years{0.0};
    double discount_factor{1.0};
    std::string forward_provenance;            //!< flat | model | mark | market | fixed | fallback
    bool collateral_is_native{true};

    // Per-leg payouts in collateral units, UNDISCOUNTED (intrinsic at X_now; expected = model E[payout]).
    // Only the net MTM fields below are discounted (× discount_factor).
    double long_leg_intrinsic_owner_payout{0.0};
    double long_leg_intrinsic_cp_payout{0.0};
    double short_leg_intrinsic_owner_payout{0.0};
    double short_leg_intrinsic_cp_payout{0.0};
    double long_leg_expected_owner_payout{0.0};
    double long_leg_expected_cp_payout{0.0};
    double short_leg_expected_owner_payout{0.0};
    double short_leg_expected_cp_payout{0.0};

    // Net MTM per party, collateral numeraire. expected_* are discounted (× discount_factor).
    double intrinsic_long_mtm{0.0};
    double intrinsic_short_mtm{0.0};
    double expected_long_mtm{0.0};
    double expected_short_mtm{0.0};

    // Greeks: finite-difference on the discounted model long MTM (skipped when the fixing is known).
    double long_delta_to_cross_rate{0.0};      //!< dMTM / +1.0 fractional move in X
    double short_delta_to_cross_rate{0.0};
    double long_vega{0.0};                      //!< dMTM / +0.01 vol
    double short_vega{0.0};
    double long_theta{0.0};                     //!< dMTM / −1 day to fixing
    double short_theta{0.0};

    std::vector<Warning> warnings;
};

//! The capped loss FRACTION for one leg, in the EXACT consensus convention (ComputeScalarCfdPayout):
//! adverse move = max(0, 1-R) for the long (loses X<K) / max(0, R-1) for the short (loses X>K); mode 0
//! divides the lambda-scaled move by 1 (denom K), mode 1 by R (denom X); clamped to [0,1]. Continuous (no
//! dust-snap) — the snap is a settlement-integer detail, not a valuation one. A unit test pins this equal
//! to ComputeScalarCfdPayout's cp/vault_im away from the dust boundary.
double ScalarLossFraction(double ratio, uint32_t lambda_q, uint8_t payoff_mode, bool is_short);

class ScalarCfdPricer {
public:
    //! Mark a bilateral scalar CFD to market. Degrades gracefully: a known fixing -> deterministic; sigma=0
    //! -> point forecast at F; the caller's warnings (curve/vol/discount coverage) are surfaced. Intrinsic
    //! always settles through consensus ComputeScalarCfdPayout.
    static ScalarCfdValuation Price(const ScalarCfdContractTerms& terms,
                                    const ScalarCfdMarketInputs& mkt,
                                    bool compute_greeks = true);
};

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_SCALAR_CFD_PRICER_H
