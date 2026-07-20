// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricing/difficulty_vol_surface.h>

#include <tinyformat.h>

#include <algorithm>
#include <cmath>

namespace wallet {
namespace pricing {

std::optional<std::string> DifficultyVolSurface::Validate() const
{
    if (horizons_blocks.size() != sigmas.size()) {
        return "difficulty vol surface: horizons and sigmas length mismatch";
    }
    if (horizons_blocks.empty()) {
        return "difficulty vol surface: empty";
    }
    for (size_t i = 0; i < sigmas.size(); ++i) {
        if (!(sigmas[i] >= 0.0) || !std::isfinite(sigmas[i])) {
            return strprintf("difficulty vol surface: sigma[%u] must be finite and >= 0", i);
        }
        if (i > 0 && horizons_blocks[i] <= horizons_blocks[i - 1]) {
            return "difficulty vol surface: horizons must be strictly ascending";
        }
    }
    return std::nullopt;
}

std::optional<double> DifficultyVolSurface::Sigma(uint32_t horizon_blocks,
                                                  std::vector<Warning>& warnings) const
{
    if (horizons_blocks.empty() || horizons_blocks.size() != sigmas.size()) {
        warnings.push_back(Warning::Critical(WarningCategory::COVERAGE,
            "Difficulty vol surface is empty"));
        return std::nullopt;
    }

    if (horizon_blocks <= horizons_blocks.front()) {
        return sigmas.front();
    }
    if (horizon_blocks >= horizons_blocks.back()) {
        if (horizon_blocks > horizons_blocks.back()) {
            warnings.push_back(Warning::Warn(WarningCategory::MODEL,
                "Difficulty horizon beyond last vol node; flat-extrapolated"));
        }
        return sigmas.back();
    }

    for (size_t i = 1; i < horizons_blocks.size(); ++i) {
        if (horizon_blocks <= horizons_blocks[i]) {
            const double h0 = static_cast<double>(horizons_blocks[i - 1]);
            const double h1 = static_cast<double>(horizons_blocks[i]);
            const double w = (h1 > h0) ? (static_cast<double>(horizon_blocks) - h0) / (h1 - h0) : 0.0;
            return sigmas[i - 1] + w * (sigmas[i] - sigmas[i - 1]);
        }
    }
    return sigmas.back();
}

std::optional<Warning> DifficultyVolSurface::CheckStaleness(int64_t current_time,
                                                            int64_t warn_threshold_sec,
                                                            int64_t critical_threshold_sec) const
{
    const int64_t age = current_time - timestamp;
    if (timestamp == 0 || age < warn_threshold_sec) return std::nullopt;
    if (age >= critical_threshold_sec) {
        return Warning::Critical(WarningCategory::MARKET_DATA,
            strprintf("Difficulty vol surface is %d s old", age), static_cast<double>(age));
    }
    return Warning::Warn(WarningCategory::MARKET_DATA,
        strprintf("Difficulty vol surface is %d s old", age), static_cast<double>(age));
}

DifficultyVolSurface BuildFlatDifficultyVolSurface(double sigma_annual,
                                                   const std::vector<uint32_t>& horizons_blocks,
                                                   int64_t timestamp)
{
    DifficultyVolSurface surface;
    surface.timestamp = timestamp;
    for (uint32_t h : horizons_blocks) {
        surface.horizons_blocks.push_back(h);
        surface.sigmas.push_back(std::max(0.0, sigma_annual));
    }
    return surface;
}

} // namespace pricing
} // namespace wallet
