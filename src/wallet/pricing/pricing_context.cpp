// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/pricing_context.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/time.h>
#include <cmath>
#include <utility>

#include <algorithm>

namespace wallet {
namespace pricing {

PricingContext::PricingContext(CWallet& wallet)
    : m_wallet(wallet)
{
    // TSC asset ID (placeholder - should be defined globally)
    // For now, set a default hub (can be updated via SetFXHub)
    uint256 tsc_id;  // All-zero for native, or actual TSC asset ID
    m_fx_matrix_mark.SetHub(tsc_id);
    m_fx_matrix_market.SetHub(tsc_id);
}

std::string PricingContext::MakeCurveKey(const uint256& asset_id, bool is_native, PriceSource source) const
{
    const char* prefix = (source == PriceSource::MARK) ? DB_PRICING_CURVE_MARK_PREFIX : DB_PRICING_CURVE_MARKET_PREFIX;
    return strprintf("%s%s",
                    prefix,
                    is_native ? "native" : asset_id.GetHex());
}

std::string PricingContext::MakeFXKey(const uint256& base_asset, const uint256& quote_asset, PriceSource source) const
{
    const char* prefix = (source == PriceSource::MARK) ? DB_PRICING_FX_MARK_PREFIX : DB_PRICING_FX_MARKET_PREFIX;
    return strprintf("%s%s_%s", prefix,
                    base_asset.GetHex(), quote_asset.GetHex());
}

std::string PricingContext::MakeVolKey(const uint256& asset_id, PriceSource source) const
{
    const char* prefix = (source == PriceSource::MARK) ? DB_PRICING_VOL_MARK_PREFIX : DB_PRICING_VOL_MARKET_PREFIX;
    return strprintf("%s%s", prefix, asset_id.GetHex());
}

std::string PricingContext::MakeCorrKey() const
{
    // Single global correlation matrix for now
    return std::string(DB_PRICING_CORR_PREFIX) + "global";
}

bool PricingContext::WriteCurveToDB(WalletBatch& batch, const DiscountCurve& curve)
{
    const std::string key = MakeCurveKey(curve.asset_id, curve.is_native, curve.source);
    return batch.WriteToBatch(key, curve);
}

bool PricingContext::ReadCurveFromDB(WalletBatch& batch, const uint256& asset_id,
                                     bool is_native, DiscountCurve& curve)
{
    // Try market first, then mark
    std::string key = MakeCurveKey(asset_id, is_native, PriceSource::MARKET);
    if (batch.ReadFromBatch(key, curve)) {
        curve.source = PriceSource::MARKET;
        return true;
    }
    key = MakeCurveKey(asset_id, is_native, PriceSource::MARK);
    if (batch.ReadFromBatch(key, curve)) {
        curve.source = PriceSource::MARK;
        return true;
    }
    return false;
}

bool PricingContext::WriteFXQuoteToDB(WalletBatch& batch, const FXQuote& quote)
{
    const std::string key = MakeFXKey(quote.base_asset, quote.quote_asset, quote.source);
    return batch.WriteToBatch(key, quote);
}

bool PricingContext::WriteVolSurfaceToDB(WalletBatch& batch, const VolSurface& surface)
{
    const std::string key = MakeVolKey(surface.asset_id, surface.source);
    return batch.WriteToBatch(key, surface);
}

bool PricingContext::ReadVolSurfaceFromDB(WalletBatch& batch, const uint256& asset_id,
                                         VolSurface& surface)
{
    // Try market first, then mark
    std::string key = MakeVolKey(asset_id, PriceSource::MARKET);
    if (batch.ReadFromBatch(key, surface)) {
        surface.source = PriceSource::MARKET;
        return true;
    }
    key = MakeVolKey(asset_id, PriceSource::MARK);
    if (batch.ReadFromBatch(key, surface)) {
        surface.source = PriceSource::MARK;
        return true;
    }
    return false;
}

bool PricingContext::WriteCorrMatrixToDB(WalletBatch& batch, const CorrelationMatrix& matrix)
{
    const std::string key = MakeCorrKey();
    return batch.WriteToBatch(key, matrix);
}

bool PricingContext::ReadCorrMatrixFromDB(WalletBatch& batch, CorrelationMatrix& matrix)
{
    const std::string key = MakeCorrKey();
    return batch.ReadFromBatch(key, matrix);
}

bool PricingContext::AddCurve(const DiscountCurve& curve)
{
    // Validate curve
    if (auto err = curve.Validate()) {
        LogPrintf("PricingContext::AddCurve: Validation failed: %s\n", *err);
        return false;
    }

    LOCK(m_wallet.cs_wallet);
    std::lock_guard<std::mutex> lock(m_mutex);

    // Add to appropriate cache based on source
    if (curve.source == PriceSource::MARK) {
        m_curves_mark[{curve.asset_id, curve.is_native}] = curve;
    } else {
        m_curves_market[{curve.asset_id, curve.is_native}] = curve;
    }

    // Persist to DB
    WalletBatch batch(m_wallet.GetDatabase());
    return WriteCurveToDB(batch, curve);
}

std::optional<DiscountCurve> PricingContext::GetCurve(const uint256& asset_id, bool is_native, PriceSource source) const
{
    LOCK(m_wallet.cs_wallet);
    std::lock_guard<std::mutex> lock(m_mutex);

    const auto& curves = (source == PriceSource::MARK) ? m_curves_mark : m_curves_market;
    auto it = curves.find({asset_id, is_native});
    if (it != curves.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool PricingContext::HasCurve(const uint256& asset_id, bool is_native, PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto& curves = (source == PriceSource::MARK) ? m_curves_mark : m_curves_market;
    return curves.count({asset_id, is_native}) > 0;
}

bool PricingContext::AddFXQuote(const FXQuote& quote)
{
    // Validate quote
    if (auto err = quote.Validate()) {
        LogPrintf("PricingContext::AddFXQuote: Validation failed: %s\n", *err);
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Add to appropriate FX matrix based on source
    if (quote.source == PriceSource::MARK) {
        m_fx_matrix_mark.AddQuote(quote);
    } else {
        m_fx_matrix_market.AddQuote(quote);
    }

    // Persist to DB (write both forward and inverse)
    WalletBatch batch(m_wallet.GetDatabase());
    bool success = WriteFXQuoteToDB(batch, quote);
    success &= WriteFXQuoteToDB(batch, quote.Inverse());

    return success;
}

FXResult PricingContext::GetFXRate(const uint256& base_asset, const uint256& quote_asset,
                                   bool base_is_native, bool quote_is_native,
                                   int64_t current_time, PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const FXMatrix& matrix = (source == PriceSource::MARK) ? m_fx_matrix_mark : m_fx_matrix_market;
    return matrix.GetRate(base_asset, quote_asset, base_is_native, quote_is_native, current_time);
}

int PricingContext::GetAssetDecimals(const uint256& asset_id, bool is_native) const
{
    if (is_native) return 8; // satoshis

    auto key = std::make_pair(asset_id, is_native);

    // Read cache
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_asset_decimals_cache.find(key);
        if (it != m_asset_decimals_cache.end()) {
            return it->second;
        }
    }

    LOCK(m_wallet.cs_wallet);
    auto entry = m_wallet.chain().getAssetRegistryEntry(asset_id);
    int decimals = -1;
    if (entry && entry->decimals != 255) {
        decimals = entry->decimals;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_asset_decimals_cache[key] = decimals;
    }
    return decimals;
}

void PricingContext::SetFXHub(const uint256& hub_asset)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_fx_matrix_mark.SetHub(hub_asset);
    m_fx_matrix_market.SetHub(hub_asset);
}

bool PricingContext::AddVolSurface(const VolSurface& surface)
{
    // Validate surface
    if (auto err = surface.Validate()) {
        LogPrintf("PricingContext::AddVolSurface: Validation failed: %s\n", *err);
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Add to appropriate cache based on source
    if (surface.source == PriceSource::MARK) {
        m_vol_surfaces_mark[surface.asset_id] = surface;
    } else {
        m_vol_surfaces_market[surface.asset_id] = surface;
    }

    // Persist to DB
    WalletBatch batch(m_wallet.GetDatabase());
    return WriteVolSurfaceToDB(batch, surface);
}

std::optional<VolSurface> PricingContext::GetVolSurface(const uint256& asset_id, PriceSource source) const
{
    LOCK(m_wallet.cs_wallet);
    std::lock_guard<std::mutex> lock(m_mutex);

    const auto& surfaces = (source == PriceSource::MARK) ? m_vol_surfaces_mark : m_vol_surfaces_market;
    auto it = surfaces.find(asset_id);
    if (it != surfaces.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool PricingContext::HasVolSurface(const uint256& asset_id, PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto& surfaces = (source == PriceSource::MARK) ? m_vol_surfaces_mark : m_vol_surfaces_market;
    return surfaces.count(asset_id) > 0;
}

bool PricingContext::AddCorrelationMatrix(const CorrelationMatrix& matrix)
{
    // Validate matrix
    if (auto err = matrix.Validate()) {
        LogPrintf("PricingContext::AddCorrelationMatrix: Validation failed: %s\n", *err);
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Store as global matrix
    m_correlation_matrix = matrix;

    // Persist to DB
    WalletBatch batch(m_wallet.GetDatabase());
    return WriteCorrMatrixToDB(batch, matrix);
}

std::optional<CorrelationMatrix> PricingContext::GetCorrelationMatrix() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_correlation_matrix;
}

bool PricingContext::HasCorrelationMatrix() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_correlation_matrix.has_value();
}

std::string PricingContext::MakeDiffCurveKey(PriceSource source) const
{
    const std::string prefix = (source == PriceSource::MARK)
        ? DB_PRICING_DIFFCURVE_MARK_PREFIX : DB_PRICING_DIFFCURVE_MARKET_PREFIX;
    return prefix + "global";
}

std::string PricingContext::MakeDiffVolKey(PriceSource source) const
{
    const std::string prefix = (source == PriceSource::MARK)
        ? DB_PRICING_DIFFVOL_MARK_PREFIX : DB_PRICING_DIFFVOL_MARKET_PREFIX;
    return prefix + "global";
}

bool PricingContext::WriteDiffCurveToDB(WalletBatch& batch, const DifficultyCurve& curve)
{
    return batch.WriteToBatch(MakeDiffCurveKey(curve.source), curve);
}

bool PricingContext::WriteDiffVolToDB(WalletBatch& batch, const DifficultyVolSurface& surface)
{
    return batch.WriteToBatch(MakeDiffVolKey(surface.source), surface);
}

bool PricingContext::AddDifficultyCurve(const DifficultyCurve& curve)
{
    if (auto err = curve.Validate()) {
        LogPrintf("PricingContext::AddDifficultyCurve: Validation failed: %s\n", *err);
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    if (curve.source == PriceSource::MARK) m_difficulty_curve_mark = curve;
    else m_difficulty_curve_market = curve;

    WalletBatch batch(m_wallet.GetDatabase());
    return WriteDiffCurveToDB(batch, curve);
}

std::optional<DifficultyCurve> PricingContext::GetDifficultyCurve(PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (source == PriceSource::MARK) ? m_difficulty_curve_mark : m_difficulty_curve_market;
}

bool PricingContext::HasDifficultyCurve(PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (source == PriceSource::MARK) ? m_difficulty_curve_mark.has_value()
                                         : m_difficulty_curve_market.has_value();
}

bool PricingContext::AddScalarForwardCurve(const ScalarFeedKey& key, const ScalarForwardCurve& curve)
{
    if (auto err = curve.Validate()) {
        LogPrintf("PricingContext::AddScalarForwardCurve: Validation failed: %s\n", *err);
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    // In-memory per-feed store (DB persistence is a follow-up; the pricing path is identical either way).
    if (curve.source == PriceSource::MARK) m_scalar_curves_mark[key] = curve;
    else m_scalar_curves_market[key] = curve;
    return true;
}

std::optional<ScalarForwardCurve> PricingContext::GetScalarForwardCurve(const ScalarFeedKey& key, PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto& m = (source == PriceSource::MARK) ? m_scalar_curves_mark : m_scalar_curves_market;
    const auto it = m.find(key);
    if (it == m.end()) return std::nullopt;
    return it->second;
}

bool PricingContext::HasScalarForwardCurve(const ScalarFeedKey& key, PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto& m = (source == PriceSource::MARK) ? m_scalar_curves_mark : m_scalar_curves_market;
    return m.find(key) != m.end();
}

bool PricingContext::AddDifficultyVolSurface(const DifficultyVolSurface& surface)
{
    if (auto err = surface.Validate()) {
        LogPrintf("PricingContext::AddDifficultyVolSurface: Validation failed: %s\n", *err);
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    if (surface.source == PriceSource::MARK) m_difficulty_vol_mark = surface;
    else m_difficulty_vol_market = surface;

    WalletBatch batch(m_wallet.GetDatabase());
    return WriteDiffVolToDB(batch, surface);
}

std::optional<DifficultyVolSurface> PricingContext::GetDifficultyVolSurface(PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (source == PriceSource::MARK) ? m_difficulty_vol_mark : m_difficulty_vol_market;
}

bool PricingContext::HasDifficultyVolSurface(PriceSource source) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (source == PriceSource::MARK) ? m_difficulty_vol_mark.has_value()
                                         : m_difficulty_vol_market.has_value();
}

MarketDataCoverage PricingContext::GetCoverageSummary(int64_t current_time) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    MarketDataCoverage coverage;
    coverage.num_curves = m_curves_mark.size() + m_curves_market.size();
    coverage.num_fx_quotes = m_fx_matrix_mark.GetAllQuotes().size() + m_fx_matrix_market.GetAllQuotes().size();
    coverage.num_vol_surfaces = m_vol_surfaces_mark.size() + m_vol_surfaces_market.size();
    coverage.num_correlation_matrices = m_correlation_matrix.has_value() ? 1 : 0;

    // Find oldest data ages
    int64_t oldest_curve = 0;
    for (const auto& [key, curve] : m_curves_mark) {
        const int64_t age = current_time - curve.timestamp;
        if (age > oldest_curve) oldest_curve = age;

        if (auto warn = curve.CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    for (const auto& [key, curve] : m_curves_market) {
        const int64_t age = current_time - curve.timestamp;
        if (age > oldest_curve) oldest_curve = age;

        if (auto warn = curve.CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    coverage.oldest_curve_age_sec = oldest_curve;

    int64_t oldest_fx = 0;
    for (const auto& [pair, quote] : m_fx_matrix_mark.GetAllQuotes()) {
        const int64_t age = current_time - quote.timestamp;
        if (age > oldest_fx) oldest_fx = age;

        if (auto warn = quote.CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    for (const auto& [pair, quote] : m_fx_matrix_market.GetAllQuotes()) {
        const int64_t age = current_time - quote.timestamp;
        if (age > oldest_fx) oldest_fx = age;

        if (auto warn = quote.CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    coverage.oldest_fx_age_sec = oldest_fx;

    int64_t oldest_vol = 0;
    for (const auto& [asset_id, surface] : m_vol_surfaces_mark) {
        const int64_t age = current_time - surface.timestamp;
        if (age > oldest_vol) oldest_vol = age;

        if (auto warn = surface.CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    for (const auto& [asset_id, surface] : m_vol_surfaces_market) {
        const int64_t age = current_time - surface.timestamp;
        if (age > oldest_vol) oldest_vol = age;

        if (auto warn = surface.CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    coverage.oldest_vol_age_sec = oldest_vol;

    int64_t oldest_corr = 0;
    if (m_correlation_matrix) {
        oldest_corr = current_time - m_correlation_matrix->timestamp;

        if (auto warn = m_correlation_matrix->CheckStaleness(current_time)) {
            coverage.warnings.push_back(*warn);
        }
    }
    coverage.oldest_corr_age_sec = oldest_corr;

    // Check for FX arbitrage (check both mark and market)
    if (auto warn = m_fx_matrix_mark.CheckArbitrage()) {
        coverage.warnings.push_back(*warn);
    }
    if (auto warn = m_fx_matrix_market.CheckArbitrage()) {
        coverage.warnings.push_back(*warn);
    }

    // Sort warnings by severity
    std::sort(coverage.warnings.begin(), coverage.warnings.end(),
             [](const Warning& a, const Warning& b) { return a.severity > b.severity; });

    return coverage;
}

void PricingContext::ClearCache()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_curves_mark.clear();
    m_curves_market.clear();
    m_fx_matrix_mark.Clear();
    m_fx_matrix_market.Clear();
    m_vol_surfaces_mark.clear();
    m_vol_surfaces_market.clear();
    m_correlation_matrix.reset();
    m_scalar_curves_mark.clear();
    m_scalar_curves_market.clear();
}

bool PricingContext::LoadFromDB()
{
    LOCK(m_wallet.cs_wallet);
    std::lock_guard<std::mutex> lock(m_mutex);
    WalletBatch batch(m_wallet.GetDatabase());

    LogPrintf("PricingContext::LoadFromDB: Loading market data from database...\n");

    int curves_loaded = 0;
    int fx_loaded = 0;
    int vols_loaded = 0;
    int corr_loaded = 0;

    // Load discount curves (mark and market)
    for (int src = 0; src < 2; ++src) {
        PriceSource source = (src == 0) ? PriceSource::MARK : PriceSource::MARKET;
        const std::string prefix_str = (source == PriceSource::MARK) ?
            DB_PRICING_CURVE_MARK_PREFIX : DB_PRICING_CURVE_MARKET_PREFIX;
        DataStream prefix{};
        prefix << prefix_str;
        auto cursor = batch.GetNewPrefixCursor(prefix);

        if (cursor) {
            DataStream ss_key{};
            DataStream ss_value{};

            while (cursor->Next(ss_key, ss_value) == DatabaseCursor::Status::MORE) {
                try {
                    std::string key_str;
                    ss_key >> key_str;

                    DiscountCurve curve;
                    ss_value >> curve;
                    curve.source = source;

                    if (source == PriceSource::MARK) {
                        m_curves_mark[{curve.asset_id, curve.is_native}] = curve;
                    } else {
                        m_curves_market[{curve.asset_id, curve.is_native}] = curve;
                    }
                    ++curves_loaded;
                } catch (const std::exception& e) {
                    LogPrintf("PricingContext::LoadFromDB: Failed to deserialize curve: %s\n", e.what());
                }
            }
        }
    }

    // Load FX quotes (mark and market)
    for (int src = 0; src < 2; ++src) {
        PriceSource source = (src == 0) ? PriceSource::MARK : PriceSource::MARKET;
        const std::string prefix_str = (source == PriceSource::MARK) ?
            DB_PRICING_FX_MARK_PREFIX : DB_PRICING_FX_MARKET_PREFIX;
        DataStream prefix{};
        prefix << prefix_str;
        auto cursor = batch.GetNewPrefixCursor(prefix);

        if (cursor) {
            DataStream ss_key{};
            DataStream ss_value{};

            while (cursor->Next(ss_key, ss_value) == DatabaseCursor::Status::MORE) {
                try {
                    std::string key_str;
                    ss_key >> key_str;

                    FXQuote quote;
                    ss_value >> quote;
                    quote.source = source;

                    // Add to appropriate FX matrix
                    if (source == PriceSource::MARK) {
                        m_fx_matrix_mark.AddQuote(quote);
                    } else {
                        m_fx_matrix_market.AddQuote(quote);
                    }
                    ++fx_loaded;
                } catch (const std::exception& e) {
                    LogPrintf("PricingContext::LoadFromDB: Failed to deserialize FX quote: %s\n", e.what());
                }
            }
        }
    }

    // Load vol surfaces (mark and market)
    for (int src = 0; src < 2; ++src) {
        PriceSource source = (src == 0) ? PriceSource::MARK : PriceSource::MARKET;
        const std::string prefix_str = (source == PriceSource::MARK) ?
            DB_PRICING_VOL_MARK_PREFIX : DB_PRICING_VOL_MARKET_PREFIX;
        DataStream prefix{};
        prefix << prefix_str;
        auto cursor = batch.GetNewPrefixCursor(prefix);

        if (cursor) {
            DataStream ss_key{};
            DataStream ss_value{};

            while (cursor->Next(ss_key, ss_value) == DatabaseCursor::Status::MORE) {
                try {
                    std::string key_str;
                    ss_key >> key_str;

                    VolSurface surface;
                    ss_value >> surface;
                    surface.source = source;

                    if (source == PriceSource::MARK) {
                        m_vol_surfaces_mark[surface.asset_id] = surface;
                    } else {
                        m_vol_surfaces_market[surface.asset_id] = surface;
                    }
                    ++vols_loaded;
                } catch (const std::exception& e) {
                    LogPrintf("PricingContext::LoadFromDB: Failed to deserialize vol surface: %s\n", e.what());
                }
            }
        }
    }

    // Load correlation matrix
    {
        CorrelationMatrix matrix;
        if (ReadCorrMatrixFromDB(batch, matrix)) {
            m_correlation_matrix = matrix;
            ++corr_loaded;
        }
    }

    // Load difficulty forward curve + vol surface (mark and market, single-global per source)
    int diff_loaded = 0;
    for (int src = 0; src < 2; ++src) {
        const PriceSource source = (src == 0) ? PriceSource::MARK : PriceSource::MARKET;
        {
            DifficultyCurve curve;
            if (batch.ReadFromBatch(MakeDiffCurveKey(source), curve)) {
                curve.source = source;
                if (source == PriceSource::MARK) m_difficulty_curve_mark = curve;
                else m_difficulty_curve_market = curve;
                ++diff_loaded;
            }
        }
        {
            DifficultyVolSurface surface;
            if (batch.ReadFromBatch(MakeDiffVolKey(source), surface)) {
                surface.source = source;
                if (source == PriceSource::MARK) m_difficulty_vol_mark = surface;
                else m_difficulty_vol_market = surface;
                ++diff_loaded;
            }
        }
    }

    LogPrintf("PricingContext::LoadFromDB: Loaded %d curves, %d FX quotes, %d vol surfaces, %d correlation matrices, %d difficulty objects\n",
             curves_loaded, fx_loaded, vols_loaded, corr_loaded, diff_loaded);

    return true;
}

} // namespace pricing
} // namespace wallet
