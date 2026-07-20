// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TENSORCASH_WALLET_PRICING_DIFFICULTY_CURVE_H
#define TENSORCASH_WALLET_PRICING_DIFFICULTY_CURVE_H

#include <wallet/pricing/fx_matrix.h>  // For PriceSource enum
#include <wallet/pricing/warnings.h>
#include <serialize.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class arith_uint256;

namespace wallet {
namespace pricing {

//! Difficulty in chainwork-per-block units (== GetBlockProof: 2^256/(target+1)), a pure monotone
//! function of the target. This is the MODELLED underlying (R = D / D_strike is the lognormal
//! martingale; §10.1), so the forward curve stores E[D] in these units — NOT E[target], whose
//! arithmetic mean differs from 1/E[D] by a reciprocal-convexity term we deliberately do not carry.
//! Returns 0 for a zero target.
double DifficultyWorkFromTarget(const arith_uint256& target);

//! Provenance of a difficulty forward point — orthogonal to PriceSource (which is the DB
//! mark/market storage tier). Surfaced in pricing output so a consumer can tell a hard market
//! quote from a retarget-model projection or a bare flat fallback.
enum class DiffCurveProvenance : uint8_t {
    FLAT = 0,    //!< no curve; tip nBits carried flat to the fixing height
    MODEL = 1,   //!< chain retarget rolled forward under a hashrate-drift assumption
    MARK = 2,    //!< hand-entered
    MARKET = 3,  //!< calibrated from difficulty-derivative offers
};

const char* DiffCurveProvenanceToString(DiffCurveProvenance p);

//! Chain-global difficulty FORWARD curve: the market/model expectation of the realized DIFFICULTY
//! (E[D], chainwork-per-block units; DifficultyWorkFromTarget) at a future block height, as a
//! function of the horizon (blocks from now). Stored single-global per PriceSource (difficulty is
//! one chain-wide underlying, not per-asset). The per-contract forward ratio is then
//! F_R = E[D] / D_strike (DIFFICULTY_DERIVATIVE.md §10.3) — using difficulty (not target) avoids
//! any reciprocal-convexity adjustment.
//!
//! It is a FORECAST, never a discount factor — PV discounting is done separately on the native
//! TSC discount curve. Values are held as double: only ratios are taken, so magnitude precision is moot.
struct DifficultyCurve {
    std::vector<uint32_t> horizons_blocks;     //!< ascending horizon grid (blocks from "now")
    std::vector<double> forward_difficulties;  //!< E[D] at each horizon (chainwork-per-block units)
    int64_t timestamp{0};                      //!< unix ts when built
    DiffCurveProvenance provenance{DiffCurveProvenance::MARKET};
    PriceSource source{PriceSource::MARKET};   //!< DB storage tier (mark vs market)

    DifficultyCurve() = default;

    SERIALIZE_METHODS(DifficultyCurve, obj) {
        // provenance stored; source set after deserialization (matches DiscountCurve convention).
        uint8_t prov = static_cast<uint8_t>(obj.provenance);
        READWRITE(obj.horizons_blocks, obj.forward_difficulties, obj.timestamp, prov);
        SER_READ(obj, obj.provenance = static_cast<DiffCurveProvenance>(prov));
    }

    //! Structural validity: matching non-empty ascending horizons, strictly-positive difficulties.
    std::optional<std::string> Validate() const;

    //! Forecast difficulty E[D] at a horizon, log-linear interpolated, flat extrapolated.
    //! Pushes an extrapolation/empty warning when relevant. Returns nullopt only if empty.
    std::optional<double> ForwardDifficulty(uint32_t horizon_blocks, std::vector<Warning>& warnings) const;

    std::optional<Warning> CheckStaleness(int64_t current_time,
                                          int64_t warn_threshold_sec = 43200,
                                          int64_t critical_threshold_sec = 86400) const;
};

//! Statistics estimated from a sampled difficulty (work) history. The drift is the MEAN-consistent
//! log-growth of E[D] (== ln(mean(Dᵢ/Dᵢ₋₁)) per block), so it can be used directly to project E[D];
//! sigma is the annualized vol of log-difficulty == vol of log R (DIFFICULTY_DERIVATIVE.md §10).
struct DifficultyHistoryStats {
    double mean_drift_per_block{0.0};  //!< ln(mean(ratio)) / stride — drift of E[D]
    double sigma_annual{0.0};          //!< annualized stdev of log-difficulty increments
    size_t samples{0};                 //!< number of return observations used
};

//! Estimate drift + vol from a difficulty (chainwork) series sampled oldest→newest at a fixed stride
//! (typically the retarget interval, where difficulty actually moves — intra-epoch nBits is flat).
//! Returns zeros if fewer than two positive samples are supplied.
DifficultyHistoryStats EstimateDifficultyHistoryStats(const std::vector<double>& works_oldest_to_newest,
                                                      uint32_t stride_blocks,
                                                      int64_t spacing_sec);

//! Project a MODEL-provenance forward curve E[D(H)] = current_difficulty · exp(drift_per_block · H)
//! over the given horizons. drift_per_block is the mean-difficulty log-growth (0 ⇒ flat forward).
DifficultyCurve BuildModelDifficultyCurve(double current_difficulty,
                                          double drift_per_block,
                                          const std::vector<uint32_t>& horizons_blocks,
                                          int64_t timestamp);

//! Retarget-aware variant: difficulty is FLAT within a retarget epoch and STEPS at each boundary
//! (the actual chain behaviour), instead of the smooth exponential of BuildModelDifficultyCurve.
//! `blocks_into_epoch` = current_height % interval; nodes are auto-generated at boundaries up to
//! max_horizon (flat segments + ~1-block steps). Same E[D] as the smooth model at boundary horizons,
//! but flat in between — more faithful for a fixing that lands mid-epoch.
DifficultyCurve BuildRetargetAwareDifficultyCurve(double current_difficulty,
                                                  double drift_per_block,
                                                  uint32_t interval_blocks,
                                                  uint32_t blocks_into_epoch,
                                                  uint32_t max_horizon,
                                                  int64_t timestamp);

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_DIFFICULTY_CURVE_H
