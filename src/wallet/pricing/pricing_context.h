// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_PRICING_PRICING_CONTEXT_H
#define TENSORCASH_WALLET_PRICING_PRICING_CONTEXT_H

#include <wallet/pricing/discount_curve.h>
#include <wallet/pricing/fx_matrix.h>
#include <wallet/pricing/vol_surface.h>
#include <wallet/pricing/correlation_matrix.h>
#include <wallet/pricing/difficulty_curve.h>
#include <wallet/pricing/scalar_forward_curve.h>
#include <wallet/pricing/difficulty_vol_surface.h>
#include <wallet/pricing/warnings.h>
#include <uint256.h>

#include <map>
#include <memory>
#include <optional>
#include <mutex>

namespace wallet {

class CWallet;
class WalletBatch;

namespace pricing {

/**
 * DB key prefixes for pricing data persistence
 * Mark and market prices are stored separately
 */
static constexpr char DB_PRICING_CURVE_MARK_PREFIX[] = "pr/mark/curve/";
static constexpr char DB_PRICING_CURVE_MARKET_PREFIX[] = "pr/market/curve/";
static constexpr char DB_PRICING_FX_MARK_PREFIX[] = "pr/mark/fx/";
static constexpr char DB_PRICING_FX_MARKET_PREFIX[] = "pr/market/fx/";
static constexpr char DB_PRICING_VOL_MARK_PREFIX[] = "pr/mark/vol/";
static constexpr char DB_PRICING_VOL_MARKET_PREFIX[] = "pr/market/vol/";
static constexpr char DB_PRICING_CORR_PREFIX[] = "pr/corr/";
static constexpr char DB_PRICING_DIFFCURVE_MARK_PREFIX[] = "pr/mark/diffcurve/";
static constexpr char DB_PRICING_DIFFCURVE_MARKET_PREFIX[] = "pr/market/diffcurve/";
static constexpr char DB_PRICING_DIFFVOL_MARK_PREFIX[] = "pr/mark/diffvol/";
static constexpr char DB_PRICING_DIFFVOL_MARKET_PREFIX[] = "pr/market/diffvol/";

/**
 * Market data coverage summary for diagnostics
 */
struct MarketDataCoverage {
    size_t num_curves{0};
    size_t num_fx_quotes{0};
    size_t num_vol_surfaces{0};
    size_t num_correlation_matrices{0};

    int64_t oldest_curve_age_sec{0};
    int64_t oldest_fx_age_sec{0};
    int64_t oldest_vol_age_sec{0};
    int64_t oldest_corr_age_sec{0};

    std::vector<Warning> warnings;  // Aggregated staleness warnings
};

/**
 * Pricing context managing market data cache and persistence
 * Thread-safe access to discount curves, FX quotes, vol surfaces, and correlations
 */
class PricingContext {
public:
    explicit PricingContext(CWallet& wallet);

    /**
     * Discount curve operations
     */
    bool AddCurve(const DiscountCurve& curve);
    std::optional<DiscountCurve> GetCurve(const uint256& asset_id, bool is_native, PriceSource source) const;
    bool HasCurve(const uint256& asset_id, bool is_native, PriceSource source) const;

    /**
     * FX quote operations
     */
    bool AddFXQuote(const FXQuote& quote);
    FXResult GetFXRate(const uint256& base_asset, const uint256& quote_asset,
                       bool base_is_native, bool quote_is_native,
                       int64_t current_time, PriceSource source) const;
    void SetFXHub(const uint256& hub_asset);

    /**
     * Vol surface operations
     */
    bool AddVolSurface(const VolSurface& surface);
    std::optional<VolSurface> GetVolSurface(const uint256& asset_id, PriceSource source) const;
    bool HasVolSurface(const uint256& asset_id, PriceSource source) const;

    /**
     * Correlation matrix operations
     */
    bool AddCorrelationMatrix(const CorrelationMatrix& matrix);
    std::optional<CorrelationMatrix> GetCorrelationMatrix() const;  // Single global matrix for now
    bool HasCorrelationMatrix() const;

    /**
     * Difficulty forward curve / vol surface operations (chain-global, single per source).
     * The forward curve is a FORECAST of the realized difficulty target; PV discounting is done
     * on the native discount curve, not here (DIFFICULTY_DERIVATIVE.md §10).
     */
    bool AddDifficultyCurve(const DifficultyCurve& curve);
    std::optional<DifficultyCurve> GetDifficultyCurve(PriceSource source) const;
    bool HasDifficultyCurve(PriceSource source) const;

    bool AddDifficultyVolSurface(const DifficultyVolSurface& surface);
    std::optional<DifficultyVolSurface> GetDifficultyVolSurface(PriceSource source) const;
    bool HasDifficultyVolSurface(PriceSource source) const;

    /**
     * Scalar (FX cross-rate) forward curve operations, PER FEED — keyed by (underlying, feed_id,
     * collateral). A scalar feed is a base/quote cross rate, so each (base, quote, feed) has its own
     * forward curve; PV discounting uses the COLLATERAL asset's discount curve (GetCurve), not here.
     * In-memory in v1 (DB persistence is a follow-up); the per-feed map is set by the caller / RPC.
     */
    bool AddScalarForwardCurve(const ScalarFeedKey& key, const ScalarForwardCurve& curve);
    std::optional<ScalarForwardCurve> GetScalarForwardCurve(const ScalarFeedKey& key, PriceSource source) const;
    bool HasScalarForwardCurve(const ScalarFeedKey& key, PriceSource source) const;

    /**
     * Get market data coverage summary for diagnostics
     */
    MarketDataCoverage GetCoverageSummary(int64_t current_time) const;

    /**
     * Clear all cached data (does not affect persistence)
     */
    void ClearCache();

    /**
     * Load all pricing data from wallet DB
     */
    bool LoadFromDB();

    /**
     * Get decimals for an asset, using cache then registry.
     * Returns -1 if unknown.
     */
    int GetAssetDecimals(const uint256& asset_id, bool is_native) const;

private:
    CWallet& m_wallet;
    mutable std::mutex m_mutex;  // Protect concurrent access
    mutable std::map<std::pair<uint256, bool>, int> m_asset_decimals_cache; // Cache registry decimals

    // In-memory caches (separate storage for mark vs market prices)
    std::map<std::pair<uint256, bool>, DiscountCurve> m_curves_mark;    // key: (asset_id, is_native)
    std::map<std::pair<uint256, bool>, DiscountCurve> m_curves_market;
    FXMatrix m_fx_matrix_mark;
    FXMatrix m_fx_matrix_market;
    std::map<uint256, VolSurface> m_vol_surfaces_mark;
    std::map<uint256, VolSurface> m_vol_surfaces_market;
    std::optional<CorrelationMatrix> m_correlation_matrix;  // Single global matrix
    std::optional<DifficultyCurve> m_difficulty_curve_mark;     // chain-global difficulty forward curve
    std::optional<DifficultyCurve> m_difficulty_curve_market;
    std::optional<DifficultyVolSurface> m_difficulty_vol_mark;  // chain-global difficulty vol surface
    std::optional<DifficultyVolSurface> m_difficulty_vol_market;
    std::map<ScalarFeedKey, ScalarForwardCurve> m_scalar_curves_mark;   // per-feed scalar forward curves
    std::map<ScalarFeedKey, ScalarForwardCurve> m_scalar_curves_market;

    /**
     * Persistence helpers
     */
    bool WriteCurveToDB(WalletBatch& batch, const DiscountCurve& curve);
    bool ReadCurveFromDB(WalletBatch& batch, const uint256& asset_id, bool is_native,
                        DiscountCurve& curve);

    bool WriteFXQuoteToDB(WalletBatch& batch, const FXQuote& quote);
    bool ReadAllFXQuotesFromDB(WalletBatch& batch);

    bool WriteVolSurfaceToDB(WalletBatch& batch, const VolSurface& surface);
    bool ReadVolSurfaceFromDB(WalletBatch& batch, const uint256& asset_id, VolSurface& surface);

    bool WriteCorrMatrixToDB(WalletBatch& batch, const CorrelationMatrix& matrix);
    bool ReadCorrMatrixFromDB(WalletBatch& batch, CorrelationMatrix& matrix);

    bool WriteDiffCurveToDB(WalletBatch& batch, const DifficultyCurve& curve);
    bool WriteDiffVolToDB(WalletBatch& batch, const DifficultyVolSurface& surface);
    std::string MakeDiffCurveKey(PriceSource source) const;
    std::string MakeDiffVolKey(PriceSource source) const;

    /**
     * Generate DB keys (with source prefix)
     */
    std::string MakeCurveKey(const uint256& asset_id, bool is_native, PriceSource source) const;
    std::string MakeFXKey(const uint256& base_asset, const uint256& quote_asset, PriceSource source) const;
    std::string MakeVolKey(const uint256& asset_id, PriceSource source) const;
    std::string MakeCorrKey() const;  // Single global key for now
};

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_PRICING_CONTEXT_H
