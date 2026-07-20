// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_PRICING_VOL_SURFACE_H
#define TENSORCASH_WALLET_PRICING_VOL_SURFACE_H

#include <uint256.h>
#include <wallet/pricing/warnings.h>
#include <wallet/pricing/fx_matrix.h>  // For PriceSource enum
#include <serialize.h>

#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace wallet {
namespace pricing {

/**
 * Volatility surface for a specific asset
 * Grid structure: strikes (moneyness %) × maturities (days)
 * Interpolation: bilinear, extrapolation: flat with warnings
 */
struct VolSurface {
    uint256 asset_id;                                      // Asset identifier
    std::vector<double> strikes_pct;                       // Strike grid in moneyness % (e.g., [0.8, 0.9, 1.0, 1.1, 1.2])
    std::vector<uint32_t> maturities_days;                 // Maturity grid in days (e.g., [7, 30, 90, 180, 365])
    std::vector<std::vector<double>> implied_vols;         // implied_vols[strike_idx][maturity_idx]
    int64_t timestamp{0};                                   // Unix timestamp
    PriceSource source{PriceSource::MARKET};               // Price source (mark vs market)

    VolSurface() : asset_id() {}

    VolSurface(const uint256& id,
               std::vector<double> strikes,
               std::vector<uint32_t> maturities,
               std::vector<std::vector<double>> vols,
               int64_t ts,
               PriceSource src = PriceSource::MARKET)
        : asset_id(id),
          strikes_pct(std::move(strikes)),
          maturities_days(std::move(maturities)),
          implied_vols(std::move(vols)),
          timestamp(ts),
          source(src) {}

    SERIALIZE_METHODS(VolSurface, obj) {
        READWRITE(obj.asset_id, obj.strikes_pct, obj.maturities_days,
                  obj.implied_vols, obj.timestamp);
        // Note: source not serialized for backward compatibility; set after deserialization
    }

    /**
     * Validate surface structure
     */
    std::optional<std::string> Validate() const;

    /**
     * Lookup implied volatility using bilinear interpolation
     * Extrapolation: flat (use nearest grid point) with INFO warnings
     *
     * @param strike_pct Strike in moneyness % (S/K, e.g., 1.0 = ATM)
     * @param maturity_days Maturity in days
     * @param warnings Output warnings
     * @return Implied volatility (annualized)
     */
    double Lookup(double strike_pct, uint32_t maturity_days,
                  std::vector<Warning>& warnings) const;

    /**
     * Check if surface data is stale
     */
    std::optional<Warning> CheckStaleness(int64_t current_time,
                                         int64_t warn_threshold_sec = 43200,
                                         int64_t critical_threshold_sec = 86400) const;

private:
    /**
     * Bilinear interpolation helper
     */
    double BilinearInterpolate(double strike_pct, uint32_t maturity_days,
                              size_t strike_lower_idx, size_t strike_upper_idx,
                              size_t maturity_lower_idx, size_t maturity_upper_idx) const;
};

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_VOL_SURFACE_H
