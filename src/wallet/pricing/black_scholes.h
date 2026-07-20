// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_BLACK_SCHOLES_H
#define BITCOIN_WALLET_PRICING_BLACK_SCHOLES_H

#include <wallet/pricing/greeks.h>
#include <optional>
#include <string>

namespace wallet {
namespace pricing {

/**
 * Black-Scholes option pricing for repo collateral options
 *
 * Standard European option formula:
 * Call: S*e^(-qT)*N(d1) - K*e^(-rT)*N(d2)
 * Put:  K*e^(-rT)*N(-d2) - S*e^(-qT)*N(-d1)
 *
 * where:
 * d1 = [ln(S/K) + (r-q+σ²/2)T] / (σ√T)
 * d2 = d1 - σ√T
 */
class BlackScholes {
public:
    enum class OptionType { CALL, PUT };

    /**
     * Price European option
     * @param S Spot price of underlying
     * @param K Strike price
     * @param T Time to maturity (years, ACT/365)
     * @param r Risk-free rate (continuous)
     * @param sigma Implied volatility (annualized)
     * @param q Carry yield / dividend yield (default 0)
     * @param type Call or Put
     * @return Option price, or error message
     */
    static std::optional<double> Price(double S,
                                       double K,
                                       double T,
                                       double r,
                                       double sigma,
                                       double q,
                                       OptionType type);

    /**
     * Compute Greeks via finite differences
     * Uses bump sizes per spec:
     * - Delta/Gamma: ±0.5% spot
     * - Vega: ±1% vol (absolute)
     * - Theta: 1 day time decay
     * - Rho: ±1 bp rate
     *
     * @return Greeks structure
     */
    static Greeks ComputeGreeks(double S,
                                 double K,
                                 double T,
                                 double r,
                                 double sigma,
                                 double q,
                                 OptionType type);

    /**
     * Implied volatility solver (for future use)
     * Uses Newton-Raphson on vega
     * @param market_price Observed option price
     * @param S,K,T,r,q Standard BS parameters
     * @param type Call or Put
     * @param initial_guess Starting vol estimate (default 0.3)
     * @param tolerance Convergence tolerance (default 1e-6)
     * @param max_iterations Maximum iterations (default 100)
     * @return Implied vol, or nullopt if failed
     */
    static std::optional<double> ImpliedVol(double market_price,
                                            double S,
                                            double K,
                                            double T,
                                            double r,
                                            double q,
                                            OptionType type,
                                            double initial_guess = 0.3,
                                            double tolerance = 1e-6,
                                            int max_iterations = 100);

private:
    // Standard normal CDF N(x)
    static double NormalCDF(double x);

    // Standard normal PDF φ(x)
    static double NormalPDF(double x);

    // Compute d1 and d2
    static void ComputeD1D2(double S, double K, double T, double r,
                           double sigma, double q,
                           double& d1, double& d2);
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_BLACK_SCHOLES_H
