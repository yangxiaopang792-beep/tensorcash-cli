// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_PRICING_CORRELATION_MATRIX_H
#define TENSORCASH_WALLET_PRICING_CORRELATION_MATRIX_H

#include <uint256.h>
#include <wallet/pricing/warnings.h>
#include <serialize.h>

#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace wallet {
namespace pricing {

/**
 * Correlation matrix for multiple assets
 * Must be symmetric, diagonal = 1.0, positive semi-definite (PSD)
 */
struct CorrelationMatrix {
    std::vector<uint256> asset_ids;          // Assets in order
    std::vector<std::vector<double>> corr;   // corr[i][j] = correlation between asset_ids[i] and asset_ids[j]
    int64_t timestamp{0};                     // Unix timestamp

    CorrelationMatrix() = default;

    CorrelationMatrix(std::vector<uint256> ids,
                      std::vector<std::vector<double>> matrix,
                      int64_t ts)
        : asset_ids(std::move(ids)), corr(std::move(matrix)), timestamp(ts) {}

    SERIALIZE_METHODS(CorrelationMatrix, obj) {
        READWRITE(obj.asset_ids, obj.corr, obj.timestamp);
    }

    /**
     * Validate matrix structure and properties
     * Checks:
     * - Square matrix matching asset count
     * - Symmetric
     * - Diagonal all 1.0
     * - Off-diagonal ∈ [-1, 1]
     * - Positive semi-definite (eigenvalue test)
     */
    std::optional<std::string> Validate() const;

    /**
     * Lookup correlation between two assets
     * Returns 0.0 if either asset not in matrix (independent assumption)
     *
     * @param asset_a First asset
     * @param asset_b Second asset
     * @param warnings Output warnings if assumption made
     * @return Correlation coefficient ∈ [-1, 1]
     */
    double Lookup(const uint256& asset_a, const uint256& asset_b,
                  std::vector<Warning>& warnings) const;

    /**
     * Check if matrix data is stale
     */
    std::optional<Warning> CheckStaleness(int64_t current_time,
                                         int64_t warn_threshold_sec = 43200,
                                         int64_t critical_threshold_sec = 86400) const;

    /**
     * Get matrix size
     */
    size_t Size() const { return asset_ids.size(); }

private:
    /**
     * Find asset index in asset_ids vector
     */
    std::optional<size_t> FindAssetIndex(const uint256& asset_id) const;

    /**
     * Check if matrix is positive semi-definite via eigenvalue decomposition
     * Returns error string if eigenvalues negative beyond tolerance
     */
    std::optional<std::string> CheckPSD(double tolerance = 1e-10) const;
};

} // namespace pricing
} // namespace wallet

#endif // TENSORCASH_WALLET_PRICING_CORRELATION_MATRIX_H
