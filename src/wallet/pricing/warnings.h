// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_PRICING_WARNINGS_H
#define TENSORCASH_WALLET_PRICING_WARNINGS_H

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

namespace wallet {
namespace pricing {

/**
 * Warning severity levels for pricing diagnostics
 */
enum class WarningSeverity : std::uint8_t {
    INFO = 0,      // Informational (e.g., correlation assumed zero, extrapolation used)
    WARNING = 1,   // Potential issue (e.g., coverage <1.2, stale data >12h)
    CRITICAL = 2   // Serious issue (e.g., under-collateralized, stale data >24h)
};

/**
 * Warning categories for filtering and aggregation
 */
enum class WarningCategory : std::uint8_t {
    COVERAGE = 0,      // Collateral/IM coverage issues
    DEADLINE = 1,      // Maturity/deadline approaching
    MARKET_DATA = 2,   // Stale or missing market data
    MODEL = 3,         // Model assumptions or limitations
    IM = 4,            // Initial margin sufficiency
    FX = 5,            // FX-related warnings
    INTERPOLATION = 6  // Interpolation/extrapolation warnings
};

/**
 * Warning struct emitted by pricing engines and market data lookups
 */
struct Warning {
    WarningSeverity severity;
    WarningCategory category;
    std::string message;
    std::optional<double> threshold_value;  // Optional numeric value for filtering

    Warning(WarningSeverity sev, WarningCategory cat, std::string msg,
            std::optional<double> threshold = std::nullopt)
        : severity(sev), category(cat), message(std::move(msg)), threshold_value(threshold) {}

    // Factory helpers for common warnings
    static Warning Info(WarningCategory cat, const std::string& msg,
                       std::optional<double> threshold = std::nullopt) {
        return Warning(WarningSeverity::INFO, cat, msg, threshold);
    }

    static Warning Warn(WarningCategory cat, const std::string& msg,
                       std::optional<double> threshold = std::nullopt) {
        return Warning(WarningSeverity::WARNING, cat, msg, threshold);
    }

    static Warning Critical(WarningCategory cat, const std::string& msg,
                           std::optional<double> threshold = std::nullopt) {
        return Warning(WarningSeverity::CRITICAL, cat, msg, threshold);
    }

    // Severity comparison for sorting
    bool operator<(const Warning& other) const {
        return static_cast<std::uint8_t>(severity) < static_cast<std::uint8_t>(other.severity);
    }
};

/**
 * Convert severity to string for JSON serialization
 */
inline std::string SeverityToString(WarningSeverity sev) {
    switch (sev) {
        case WarningSeverity::INFO: return "info";
        case WarningSeverity::WARNING: return "warning";
        case WarningSeverity::CRITICAL: return "critical";
    }
    return "unknown";
}

/**
 * Convert category to string for JSON serialization
 */
inline std::string CategoryToString(WarningCategory cat) {
    switch (cat) {
        case WarningCategory::COVERAGE: return "coverage";
        case WarningCategory::DEADLINE: return "deadline";
        case WarningCategory::MARKET_DATA: return "market_data";
        case WarningCategory::MODEL: return "model";
        case WarningCategory::IM: return "im";
        case WarningCategory::FX: return "fx";
        case WarningCategory::INTERPOLATION: return "interpolation";
    }
    return "unknown";
}

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_WARNINGS_H
