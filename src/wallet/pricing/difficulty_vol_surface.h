// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TENSORCASH_WALLET_PRICING_DIFFICULTY_VOL_SURFACE_H
#define TENSORCASH_WALLET_PRICING_DIFFICULTY_VOL_SURFACE_H

#include <wallet/pricing/fx_matrix.h>  // For PriceSource enum
#include <wallet/pricing/warnings.h>
#include <serialize.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
namespace pricing {

//! Chain-global difficulty volatility term structure: the annualized lognormal volatility of the
//! difficulty ratio R (DIFFICULTY_DERIVATIVE.md §10) as a function of horizon (blocks to fixing).
//! v1 is flat across moneyness (one sigma per horizon); a moneyness dimension can be added later
//! exactly as VolSurface does for assets. Stored single-global per PriceSource.
struct DifficultyVolSurface {
    std::vector<uint32_t> horizons_blocks;   //!< ascending horizon grid (blocks to fixing)
    std::vector<double> sigmas;              //!< annualized vol of log R at each horizon
    int64_t timestamp{0};
    PriceSource source{PriceSource::MARKET};

    DifficultyVolSurface() = default;

    SERIALIZE_METHODS(DifficultyVolSurface, obj) {
        READWRITE(obj.horizons_blocks, obj.sigmas, obj.timestamp);
        // source set after deserialization (matches DiscountCurve / VolSurface convention).
    }

    std::optional<std::string> Validate() const;

    //! Annualized sigma at a horizon, linearly interpolated, flat extrapolated.
    //! Returns nullopt only if the surface is empty.
    std::optional<double> Sigma(uint32_t horizon_blocks, std::vector<Warning>& warnings) const;

    std::optional<Warning> CheckStaleness(int64_t current_time,
                                          int64_t warn_threshold_sec = 43200,
                                          int64_t critical_threshold_sec = 86400) const;
};

//! Build a flat (horizon-constant) difficulty vol surface at the given annualized sigma. Used by the
//! realized-vol calibrator, which estimates one sigma from historical log-difficulty increments.
DifficultyVolSurface BuildFlatDifficultyVolSurface(double sigma_annual,
                                                   const std::vector<uint32_t>& horizons_blocks,
                                                   int64_t timestamp);

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_DIFFICULTY_VOL_SURFACE_H
