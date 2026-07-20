// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_PRICING_DISCOUNT_CURVE_H
#define TENSORCASH_WALLET_PRICING_DISCOUNT_CURVE_H

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
 * Discount curve with zero rates for a specific asset
 * Convention: ACT/365, continuous compounding
 */
struct DiscountCurve {
    uint256 asset_id;                       // Asset identifier (all-zero for native BTC)
    bool is_native{false};                  // True if native BTC
    std::vector<uint32_t> tenors_days;      // Tenor grid in days (e.g., [7, 30, 90, 180, 365, 730])
    std::vector<double> zero_rates;         // Annualized zero rates (continuous compounding)
    int64_t timestamp{0};                   // Unix timestamp when curve was created
    PriceSource source{PriceSource::MARKET}; // Price source (mark vs market)

    DiscountCurve() : asset_id() {}

    DiscountCurve(const uint256& id, bool native,
                  std::vector<uint32_t> tenors,
                  std::vector<double> rates,
                  int64_t ts,
                  PriceSource src = PriceSource::MARKET)
        : asset_id(id), is_native(native),
          tenors_days(std::move(tenors)),
          zero_rates(std::move(rates)),
          timestamp(ts),
          source(src) {}

    SERIALIZE_METHODS(DiscountCurve, obj) {
        READWRITE(obj.asset_id, obj.is_native, obj.tenors_days, obj.zero_rates, obj.timestamp);
        // Note: source not serialized for backward compatibility; set after deserialization
    }

    /**
     * Validate curve structure
     * @return error string if invalid, nullopt if valid
     */
    std::optional<std::string> Validate() const;

    /**
     * Get discount factor for a specific maturity using log-linear interpolation
     * Formula: DF(T) = exp(-r(T) * T / 365)
     *
     * @param maturity_days Maturity in days (ACT/365 convention)
     * @param warnings Output warnings (extrapolation, staleness, etc.)
     * @return Discount factor (1.0 at T=0, decreases for longer maturities)
     */
    double GetDiscountFactor(uint32_t maturity_days, std::vector<Warning>& warnings) const;

    /**
     * Get bucket weights for the zero rate at a given maturity.
     *
     * Because zero_rates are interpolated linearly between curve tenors, the
     * zero rate r(T) at maturity_days is a convex combination of at most two
     * adjacent tenor node rates. This helper returns the contributing tenors
     * and their weights w_j such that:
     *
     *     r(T) = Σ_j w_j * r(t_j),   Σ_j w_j = 1.
     *
     * These weights can be used with the chain rule to decompose a scalar
     * rate sensitivity ∂V/∂r(T) into per-tenor bucket sensitivities:
     *
     *     ∂V/∂r(t_j) = (∂V/∂r(T)) * w_j.
     *
     * When maturity_days is before the first tenor, the first tenor gets
     * weight 1. When after the last tenor, the last tenor gets weight 1.
     * For maturity_days == 0, the bucket list is empty (no rate risk).
     */
    struct RateBucketWeight {
        uint32_t tenor_days;
        double weight;
    };

    std::vector<RateBucketWeight> GetZeroRateBucketWeights(uint32_t maturity_days) const;

    /**
     * Get zero rate for a specific maturity using log-linear interpolation on rates
     *
     * @param maturity_days Maturity in days
     * @param warnings Output warnings
     * @return Annualized zero rate (continuous compounding)
     */
    double GetZeroRate(uint32_t maturity_days, std::vector<Warning>& warnings) const;

    /**
     * Check if curve data is stale
     * @param current_time Current Unix timestamp
     * @param warn_threshold_sec Warn threshold in seconds (default 12h)
     * @param critical_threshold_sec Critical threshold in seconds (default 24h)
     * @return Staleness warning or nullopt
     */
    std::optional<Warning> CheckStaleness(int64_t current_time,
                                         int64_t warn_threshold_sec = 43200,    // 12h
                                         int64_t critical_threshold_sec = 86400  // 24h
                                         ) const;
};

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_DISCOUNT_CURVE_H
