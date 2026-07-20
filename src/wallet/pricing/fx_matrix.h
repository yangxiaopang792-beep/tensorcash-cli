// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_PRICING_FX_MATRIX_H
#define TENSORCASH_WALLET_PRICING_FX_MATRIX_H

#include <uint256.h>
#include <wallet/pricing/warnings.h>
#include <serialize.h>

#include <map>
#include <vector>
#include <cstdint>
#include <optional>
#include <utility>

namespace wallet {
namespace pricing {

/**
 * Price source type (mark vs market)
 */
enum class PriceSource {
    MARK,   // Manually marked prices (GUI entries)
    MARKET  // Market-derived prices (bulletin board calibration)
};

inline std::string PriceSourceToString(PriceSource source) {
    return source == PriceSource::MARK ? "mark" : "market";
}

inline PriceSource StringToPriceSource(const std::string& str) {
    return (str == "mark") ? PriceSource::MARK : PriceSource::MARKET;
}

/**
 * FX quote between two assets
 * Convention: spot_rate = base_asset / quote_asset
 */
struct FXQuote {
    uint256 base_asset;      // Numerator (ignored if base_is_native=true)
    uint256 quote_asset;     // Denominator (ignored if quote_is_native=true)
    bool base_is_native{false};   // True if base is native BTC/TSC
    bool quote_is_native{false};  // True if quote is native BTC/TSC
    double spot_rate{0.0};   // Mid price: base/quote
    double bid_ask_bps{0.0}; // Optional bid-ask spread in basis points (for diagnostics)
    int64_t timestamp{0};    // Unix timestamp
    PriceSource source{PriceSource::MARKET};  // Price source (mark vs market)

    FXQuote() : base_asset(), quote_asset() {}

    FXQuote(const uint256& base, const uint256& quote, double rate,
            double spread_bps = 0.0, int64_t ts = 0, PriceSource src = PriceSource::MARKET,
            bool base_native = false, bool quote_native = false)
        : base_asset(base), quote_asset(quote), base_is_native(base_native), quote_is_native(quote_native),
          spot_rate(rate), bid_ask_bps(spread_bps), timestamp(ts), source(src) {}

    SERIALIZE_METHODS(FXQuote, obj) {
        READWRITE(obj.base_asset, obj.quote_asset, obj.spot_rate,
                  obj.bid_ask_bps, obj.timestamp);
        // Note: source and is_native flags not serialized for backward compatibility
    }

    /**
     * Validate FX quote structure
     */
    std::optional<std::string> Validate() const;

    /**
     * Check if quote is stale
     */
    std::optional<Warning> CheckStaleness(int64_t current_time,
                                         int64_t warn_threshold_sec = 43200,
                                         int64_t critical_threshold_sec = 86400) const;

    /**
     * Get inverse quote (swap base and quote)
     */
    FXQuote Inverse() const {
        return FXQuote(quote_asset, base_asset, 1.0 / spot_rate,
                      bid_ask_bps, timestamp, source, quote_is_native, base_is_native);
    }
};

/**
 * FX lookup result with path information
 */
struct FXResult {
    double rate{0.0};                // Computed FX rate
    std::vector<uint256> path;       // Asset path taken (e.g., [USDT, USD, TSC])
    int hops{0};                     // Number of FX conversions
    std::vector<Warning> warnings;   // Staleness, long path, arbitrage, etc.

    FXResult() = default;

    FXResult(double r, std::vector<uint256> p, int h, std::vector<Warning> w = {})
        : rate(r), path(std::move(p)), hops(h), warnings(std::move(w)) {}
};

/**
 * FX quote lookup key (handles native assets)
 */
struct FXKey {
    uint256 base_asset;
    uint256 quote_asset;
    bool base_is_native{false};
    bool quote_is_native{false};

    bool operator<(const FXKey& other) const {
        if (base_is_native != other.base_is_native) return base_is_native < other.base_is_native;
        if (quote_is_native != other.quote_is_native) return quote_is_native < other.quote_is_native;
        if (base_asset != other.base_asset) return base_asset < other.base_asset;
        return quote_asset < other.quote_asset;
    }

    bool operator==(const FXKey& other) const {
        return base_is_native == other.base_is_native &&
               quote_is_native == other.quote_is_native &&
               base_asset == other.base_asset &&
               quote_asset == other.quote_asset;
    }
};

/**
 * FX matrix with triangulation and arbitrage detection
 * Default hub currency: TSC (native)
 */
class FXMatrix {
public:
    FXMatrix() = default;

    /**
     * Add or update an FX quote
     * Automatically adds the inverse quote
     */
    void AddQuote(const FXQuote& quote);

    /**
     * Get FX rate from base to quote asset
     * Tries direct quote first, then triangulation via hub (TSC), then general Dijkstra
     *
     * @param base_asset Source asset
     * @param quote_asset Target asset
     * @param base_is_native True if base is native BTC/TSC
     * @param quote_is_native True if quote is native BTC/TSC
     * @param current_time Current timestamp for staleness checks
     * @return FXResult with rate, path, and warnings
     */
    FXResult GetRate(const uint256& base_asset,
                     const uint256& quote_asset,
                     bool base_is_native,
                     bool quote_is_native,
                     int64_t current_time) const;

    /**
     * Set the hub currency for triangulation (default: TSC)
     */
    void SetHub(const uint256& hub_asset) { m_hub = hub_asset; }

    /**
     * Get all stored quotes (for diagnostics)
     */
    const std::map<FXKey, FXQuote>& GetAllQuotes() const {
        return m_quotes;
    }

    /**
     * Clear all quotes
     */
    void Clear() { m_quotes.clear(); }

    /**
     * Check for arbitrage cycles in the FX graph
     * Returns warning if detected arbitrage > threshold_bps
     */
    std::optional<Warning> CheckArbitrage(double threshold_bps = 10.0) const;

private:
    std::map<FXKey, FXQuote> m_quotes;
    uint256 m_hub; // Hub currency for triangulation (TSC)
    bool m_hub_is_native{true}; // Hub is typically native TSC

    /**
     * Try direct quote lookup
     */
    std::optional<FXResult> TryDirectQuote(const uint256& base,
                                          const uint256& quote,
                                          bool base_is_native,
                                          bool quote_is_native,
                                          int64_t current_time) const;

    /**
     * Try triangulation via hub currency
     */
    std::optional<FXResult> TryHubTriangulation(const uint256& base,
                                               const uint256& quote,
                                               bool base_is_native,
                                               bool quote_is_native,
                                               int64_t current_time) const;

    /**
     * General multi-hop pathfinding using Dijkstra on log prices
     */
    std::optional<FXResult> FindPathDijkstra(const uint256& base,
                                            const uint256& quote,
                                            bool base_is_native,
                                            bool quote_is_native,
                                            int64_t current_time) const;
};

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_FX_MATRIX_H
