// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_SPREAD_OPTION_H
#define BITCOIN_WALLET_PRICING_SPREAD_OPTION_H

#include <wallet/pricing/greeks.h>
#include <optional>

namespace wallet {
namespace pricing {

/**
 * Spread option pricing for forward contracts
 *
 * Payoff: max(α*S_A - β*S_B - K, 0)
 * where α, β are weights, S_A, S_B are underlyings, K is strike
 *
 * Methods:
 * 1. Kirk approximation (fast, accurate when 0.5 < S/K < 2 and |ρ| < 0.95)
 * 2. Gauss-Legendre integration (fallback for extreme cases)
 */
class SpreadOption {
public:
    /**
     * Price a spread call option
     *
     * @param S_A Spot price of asset A
     * @param S_B Spot price of asset B
     * @param alpha Weight on asset A (e.g., units delivered)
     * @param beta Weight on asset B (e.g., units paid)
     * @param K Strike (e.g., zero for ATM forward)
     * @param T Time to maturity (years)
     * @param r Risk-free rate (continuous)
     * @param sigma_A Volatility of asset A
     * @param sigma_B Volatility of asset B
     * @param rho Correlation between A and B
     * @param q_A Carry yield of asset A (dividend yield, storage cost, etc.)
     * @param q_B Carry yield of asset B
     * @param use_kirk Force Kirk approximation (default: auto-select)
     * @return Option price
     */
    static std::optional<double> Price(double S_A,
                                       double S_B,
                                       double alpha,
                                       double beta,
                                       double K,
                                       double T,
                                       double r,
                                       double sigma_A,
                                       double sigma_B,
                                       double rho,
                                       bool use_kirk = false,
                                       double q_A = 0.0,
                                       double q_B = 0.0);

    /**
     * Compute Greeks via finite differences
     * Returns separate sensitivities for each underlying
     */
    struct SpreadGreeks {
        double delta_A{0.0};   // ∂V/∂S_A
        double delta_B{0.0};   // ∂V/∂S_B
        double gamma_A{0.0};   // ∂²V/∂S_A²
        double gamma_B{0.0};   // ∂²V/∂S_B²
        double vega_A{0.0};    // ∂V/∂σ_A
        double vega_B{0.0};    // ∂V/∂σ_B
        double theta{0.0};     // -∂V/∂t
        double rho_rate{0.0};  // ∂V/∂r
    };

    static SpreadGreeks ComputeGreeks(double S_A,
                                      double S_B,
                                      double alpha,
                                      double beta,
                                      double K,
                                      double T,
                                      double r,
                                      double sigma_A,
                                      double sigma_B,
                                      double rho,
                                      double q_A = 0.0,
                                      double q_B = 0.0,
                                      bool use_kirk = false);

private:
    /**
     * Kirk approximation
     * Approximates spread option as BS call with adjusted volatility
     */
    static std::optional<double> PriceKirk(double S_A,
                                           double S_B,
                                           double alpha,
                                           double beta,
                                           double K,
                                           double T,
                                           double r,
                                           double sigma_A,
                                           double sigma_B,
                                           double rho,
                                           double q_A,
                                           double q_B);

    /**
     * Gauss-Legendre integration
     * Numerically integrates the option payoff
     * @param n_points Number of quadrature points (default 32)
     */
    static std::optional<double> PriceGaussLegendre(double S_A,
                                                     double S_B,
                                                     double alpha,
                                                     double beta,
                                                     double K,
                                                     double T,
                                                     double r,
                                                     double sigma_A,
                                                     double sigma_B,
                                                     double rho,
                                                     double q_A,
                                                     double q_B,
                                                     int n_points = 32);

    /**
     * Check if Kirk approximation is suitable
     */
    static bool ShouldUseKirk(double S_A,
                             double S_B,
                             double alpha,
                             double beta,
                             double K,
                             double rho);
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_SPREAD_OPTION_H
