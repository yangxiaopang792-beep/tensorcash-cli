// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/correlation_matrix.h>
#include <tinyformat.h>
#include <cmath>
#include <algorithm>

namespace wallet {
namespace pricing {

namespace {

/**
 * Simple eigenvalue computation for symmetric matrices using Jacobi method
 * Suitable for small matrices (correlation matrices typically <10x10)
 * Returns minimum eigenvalue for PSD checking
 */
double ComputeMinEigenvalue(const std::vector<std::vector<double>>& matrix)
{
    const size_t n = matrix.size();
    if (n == 0) return 0.0;

    // Copy matrix (Jacobi method modifies in-place)
    std::vector<std::vector<double>> A = matrix;
    std::vector<double> eigenvalues(n, 0.0);

    // Jacobi iteration parameters
    const int max_iterations = 100;
    const double tolerance = 1e-12;

    for (int iter = 0; iter < max_iterations; ++iter) {
        // Find largest off-diagonal element
        double max_off_diag = 0.0;
        size_t p = 0, q = 0;

        for (size_t i = 0; i < n; ++i) {
            for (size_t j = i + 1; j < n; ++j) {
                const double abs_aij = std::abs(A[i][j]);
                if (abs_aij > max_off_diag) {
                    max_off_diag = abs_aij;
                    p = i;
                    q = j;
                }
            }
        }

        // Converged if all off-diagonal elements are small
        if (max_off_diag < tolerance) {
            break;
        }

        // Compute rotation angle
        const double theta = 0.5 * std::atan2(2.0 * A[p][q], A[q][q] - A[p][p]);
        const double c = std::cos(theta);
        const double s = std::sin(theta);

        // Apply Givens rotation
        std::vector<std::vector<double>> A_new = A;

        // Update diagonal elements
        A_new[p][p] = c * c * A[p][p] + s * s * A[q][q] - 2.0 * s * c * A[p][q];
        A_new[q][q] = s * s * A[p][p] + c * c * A[q][q] + 2.0 * s * c * A[p][q];
        A_new[p][q] = 0.0;
        A_new[q][p] = 0.0;

        // Update off-diagonal elements
        for (size_t i = 0; i < n; ++i) {
            if (i != p && i != q) {
                const double aip = A[i][p];
                const double aiq = A[i][q];
                A_new[i][p] = c * aip - s * aiq;
                A_new[p][i] = A_new[i][p];
                A_new[i][q] = s * aip + c * aiq;
                A_new[q][i] = A_new[i][q];
            }
        }

        A = A_new;
    }

    // Extract eigenvalues from diagonal
    for (size_t i = 0; i < n; ++i) {
        eigenvalues[i] = A[i][i];
    }

    // Return minimum eigenvalue
    return *std::min_element(eigenvalues.begin(), eigenvalues.end());
}

} // anonymous namespace

std::optional<std::string> CorrelationMatrix::Validate() const
{
    const size_t n = asset_ids.size();

    if (n == 0) {
        return "Correlation matrix has no assets";
    }

    if (corr.size() != n) {
        return strprintf("Correlation matrix size (%d) != asset count (%d)",
                        corr.size(), n);
    }

    // Check square matrix
    for (size_t i = 0; i < n; ++i) {
        if (corr[i].size() != n) {
            return strprintf("Correlation matrix row %d has %d columns, expected %d",
                            i, corr[i].size(), n);
        }
    }

    // Check diagonal elements are 1.0
    for (size_t i = 0; i < n; ++i) {
        if (std::abs(corr[i][i] - 1.0) > 1e-6) {
            return strprintf("Correlation matrix diagonal[%d] = %.6f, expected 1.0",
                            i, corr[i][i]);
        }
    }

    // Check symmetry
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (std::abs(corr[i][j] - corr[j][i]) > 1e-6) {
                return strprintf("Correlation matrix not symmetric at [%d][%d]: %.6f != %.6f",
                                i, j, corr[i][j], corr[j][i]);
            }
        }
    }

    // Check off-diagonal elements in [-1, 1]
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            if (i == j) continue;

            if (corr[i][j] < -1.0 || corr[i][j] > 1.0) {
                return strprintf("Correlation[%d][%d] = %.6f outside valid range [-1, 1]",
                                i, j, corr[i][j]);
            }
        }
    }

    // Check PSD
    if (auto err = CheckPSD()) {
        return *err;
    }

    return std::nullopt;
}

std::optional<std::string> CorrelationMatrix::CheckPSD(double tolerance) const
{
    if (corr.empty()) {
        return "Cannot check PSD of empty matrix";
    }

    const double min_eigenvalue = ComputeMinEigenvalue(corr);

    if (min_eigenvalue < -tolerance) {
        return strprintf("Correlation matrix not positive semi-definite: "
                        "min eigenvalue = %.8f (< %.8f tolerance)",
                        min_eigenvalue, -tolerance);
    }

    return std::nullopt;
}

std::optional<Warning> CorrelationMatrix::CheckStaleness(int64_t current_time,
                                                         int64_t warn_threshold_sec,
                                                         int64_t critical_threshold_sec) const
{
    const int64_t age_sec = current_time - timestamp;

    if (age_sec >= critical_threshold_sec) {
        return Warning::Critical(
            WarningCategory::MARKET_DATA,
            strprintf("Correlation matrix stale: %d hours old (>24h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    if (age_sec >= warn_threshold_sec) {
        return Warning::Warn(
            WarningCategory::MARKET_DATA,
            strprintf("Correlation matrix aging: %d hours old (>12h)", age_sec / 3600),
            static_cast<double>(age_sec)
        );
    }

    return std::nullopt;
}

std::optional<size_t> CorrelationMatrix::FindAssetIndex(const uint256& asset_id) const
{
    for (size_t i = 0; i < asset_ids.size(); ++i) {
        if (asset_ids[i] == asset_id) {
            return i;
        }
    }
    return std::nullopt;
}

double CorrelationMatrix::Lookup(const uint256& asset_a, const uint256& asset_b,
                                 std::vector<Warning>& warnings) const
{
    // Same asset -> correlation = 1.0
    if (asset_a == asset_b) {
        return 1.0;
    }

    auto idx_a = FindAssetIndex(asset_a);
    auto idx_b = FindAssetIndex(asset_b);

    // Both assets in matrix
    if (idx_a && idx_b) {
        return corr[*idx_a][*idx_b];
    }

    // One or both assets missing -> assume zero correlation (independent)
    warnings.push_back(Warning::Info(
        WarningCategory::MODEL,
        strprintf("Correlation not available for asset pair, assuming independent (ρ=0)")
    ));

    return 0.0;
}

} // namespace pricing
} // namespace wallet
