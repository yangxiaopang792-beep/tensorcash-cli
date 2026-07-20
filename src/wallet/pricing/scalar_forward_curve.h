// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TENSORCASH_WALLET_PRICING_SCALAR_FORWARD_CURVE_H
#define TENSORCASH_WALLET_PRICING_SCALAR_FORWARD_CURVE_H

// Forward curve for an issuer-published scalar feed (CFD_GENERALISATION.md §7, Slice 5f-6). A scalar feed
// is an FX-style CROSS RATE: X = base_asset / quote_asset, quoted in the quote convention (e.g. SR3/TSC =
// 95.5 means 95.5 units of quote per unit of base). This curve holds the market/model FORWARD cross rate
// F = E[X] at a future block horizon, used by ScalarCfdPricer to mark a bilateral scalar CFD: the pricing
// ratio is simply F / K (strike in the same quote convention) — NO difficulty-style inversion and NO
// abstract scalar normalization. Unlike the chain-wide difficulty curve, a cross-rate feed is per
// (base, quote, feed_id), so the PricingContext stores one curve PER FEED — this struct is just the curve
// abstraction (interpolation/validation), keyed by the caller.

#include <wallet/pricing/fx_matrix.h>  // PriceSource
#include <wallet/pricing/warnings.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace wallet {
namespace pricing {

//! Identity of a scalar cross-rate feed for curve storage: the underlying oracle asset (base), the feed,
//! and the collateral/quote asset. A cross-rate forward is per (base, quote, feed), unlike the chain-wide
//! difficulty curve — so the PricingContext keys its scalar forward curves by this tuple.
struct ScalarFeedKey {
    uint256 underlying_asset_id;   //!< U (base)
    uint32_t feed_id{0};
    uint256 collateral_asset_id;   //!< C (quote / settlement numeraire; zero = native)

    friend bool operator<(const ScalarFeedKey& a, const ScalarFeedKey& b) {
        return std::tie(a.underlying_asset_id, a.feed_id, a.collateral_asset_id) <
               std::tie(b.underlying_asset_id, b.feed_id, b.collateral_asset_id);
    }
    friend bool operator==(const ScalarFeedKey& a, const ScalarFeedKey& b) {
        return a.underlying_asset_id == b.underlying_asset_id && a.feed_id == b.feed_id &&
               a.collateral_asset_id == b.collateral_asset_id;
    }
};

//! Provenance of a scalar forward point — orthogonal to PriceSource (the DB mark/market storage tier).
enum class ScalarCurveProvenance : uint8_t {
    FLAT = 0,    //!< no curve; the last published scalar carried flat to the fixing horizon
    MODEL = 1,   //!< drift model rolled forward from published history
    MARK = 2,    //!< hand-entered
    MARKET = 3,  //!< calibrated from scalar-CFD offers
};

const char* ScalarCurveProvenanceToString(ScalarCurveProvenance p);

//! Per-feed FORWARD cross-rate curve: F = E[X] (the modelled base/quote cross rate) at a future block
//! horizon (blocks from "now", typically to the contract's publication_deadline_height). The per-contract
//! forward ratio is F / K (strike in the same quote convention). A FORECAST, never a discount factor — PV
//! discounting is done separately on the QUOTE/COLLATERAL asset's discount curve (native TSC is only one
//! possible quote/collateral). Values are double: only ratios (X/K) are taken, so magnitude precision is moot.
struct ScalarForwardCurve {
    std::vector<uint32_t> horizons_blocks;   //!< ascending horizon grid (blocks from "now")
    std::vector<double> forward_cross_rates; //!< F = E[X] at each horizon (base/quote, in quote units)
    int64_t timestamp{0};                    //!< unix ts when built
    ScalarCurveProvenance provenance{ScalarCurveProvenance::MARKET};
    PriceSource source{PriceSource::MARKET}; //!< DB storage tier (mark vs market)

    ScalarForwardCurve() = default;

    SERIALIZE_METHODS(ScalarForwardCurve, obj) {
        uint8_t prov = static_cast<uint8_t>(obj.provenance);
        READWRITE(obj.horizons_blocks, obj.forward_cross_rates, obj.timestamp, prov);
        SER_READ(obj, obj.provenance = static_cast<ScalarCurveProvenance>(prov));
    }

    //! Structural validity: matching non-empty ascending horizons, strictly-positive finite cross rates.
    std::optional<std::string> Validate() const;

    //! Forecast forward cross rate F = E[X] at a horizon, log-linear interpolated, flat extrapolated at both
    //! ends. Pushes an extrapolation/empty warning when relevant. Returns nullopt only if the curve is empty.
    std::optional<double> ForwardCrossRate(uint32_t horizon_blocks, std::vector<Warning>& warnings) const;

    std::optional<Warning> CheckStaleness(int64_t current_time,
                                          int64_t warn_threshold_sec = 43200,
                                          int64_t critical_threshold_sec = 86400) const;
};

//! Statistics estimated from a sampled cross-rate history. drift is the MEAN-consistent log-growth of E[X]
//! (== ln(mean(Xᵢ/Xᵢ₋₁)) per block), usable directly to project the forward cross rate; sigma is the
//! annualized vol of log X (== vol of log(X/K) since the strike K is constant).
struct ScalarHistoryStats {
    double mean_drift_per_block{0.0};
    double sigma_annual{0.0};
    size_t samples{0};
};

//! Estimate drift + annualized vol from a cross-rate sample series taken every `stride_blocks` (block
//! spacing `spacing_sec`): arithmetic-mean-ratio drift + sample-variance vol.
ScalarHistoryStats EstimateScalarHistoryStats(const std::vector<double>& samples,
                                              uint32_t stride_blocks,
                                              int64_t spacing_sec);

//! A simple drift-model curve: F(h) = current_cross_rate * exp(drift_per_block * h) over the given horizons.
ScalarForwardCurve BuildModelScalarForwardCurve(double current_cross_rate,
                                                double drift_per_block,
                                                const std::vector<uint32_t>& horizons_blocks,
                                                int64_t timestamp);

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_SCALAR_FORWARD_CURVE_H
