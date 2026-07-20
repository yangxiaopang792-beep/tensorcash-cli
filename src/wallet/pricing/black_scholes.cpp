// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/black_scholes.h>
#include <cmath>
#include <algorithm>

namespace wallet {
namespace pricing {

// Constants
static constexpr double SQRT_2PI = 2.506628274631000502;
static constexpr double INV_SQRT_2 = 0.707106781186547524;

double BlackScholes::NormalPDF(double x)
{
    return std::exp(-0.5 * x * x) / SQRT_2PI;
}

double BlackScholes::NormalCDF(double x)
{
    // Approximation using error function
    // N(x) = 0.5 * (1 + erf(x/√2))
    return 0.5 * (1.0 + std::erf(x * INV_SQRT_2));
}

void BlackScholes::ComputeD1D2(double S, double K, double T, double r,
                               double sigma, double q,
                               double& d1, double& d2)
{
    const double sigma_sqrt_t = sigma * std::sqrt(T);
    d1 = (std::log(S / K) + (r - q + 0.5 * sigma * sigma) * T) / sigma_sqrt_t;
    d2 = d1 - sigma_sqrt_t;
}

std::optional<double> BlackScholes::Price(double S,
                                          double K,
                                          double T,
                                          double r,
                                          double sigma,
                                          double q,
                                          OptionType type)
{
    // Validation
    if (S <= 0.0) return std::nullopt;  // "Spot price must be positive"
    if (K < 0.0) return std::nullopt;  // "Strike cannot be negative"
    if (T <= 0.0) return 0.0;           // Expired option worth intrinsic only
    if (sigma <= 0.0) return std::nullopt;  // "Volatility must be positive"

    // Handle K=0 edge case (deep ITM call or worthless put)
    if (K < 1e-10) {
        const double df_q = std::exp(-q * T);
        if (type == OptionType::CALL) {
            // Deep ITM call worth spot discounted at dividend yield
            return S * df_q;
        } else {
            // Put with zero strike is worthless
            return 0.0;
        }
    }

    // Handle edge cases
    if (T < 1e-6) {
        // Near expiry, return intrinsic value
        if (type == OptionType::CALL) {
            return std::max(S - K, 0.0);
        } else {
            return std::max(K - S, 0.0);
        }
    }

    // Compute d1, d2
    double d1, d2;
    ComputeD1D2(S, K, T, r, sigma, q, d1, d2);

    // Black-Scholes formula
    const double df_r = std::exp(-r * T);
    const double df_q = std::exp(-q * T);

    if (type == OptionType::CALL) {
        const double nd1 = NormalCDF(d1);
        const double nd2 = NormalCDF(d2);
        return S * df_q * nd1 - K * df_r * nd2;
    } else {
        const double nd1_neg = NormalCDF(-d1);
        const double nd2_neg = NormalCDF(-d2);
        return K * df_r * nd2_neg - S * df_q * nd1_neg;
    }
}

Greeks BlackScholes::ComputeGreeks(double S,
                                   double K,
                                   double T,
                                   double r,
                                   double sigma,
                                   double q,
                                   OptionType type)
{
    Greeks greeks;

    // Base price
    auto V0_opt = Price(S, K, T, r, sigma, q, type);
    if (!V0_opt) return greeks;  // Return zeros on error
    const double V0 = *V0_opt;

    // Delta: ∂V/∂S via central difference (±0.5% spot bump)
    const double bump_S = 0.005 * S;
    auto V_up_opt = Price(S + bump_S, K, T, r, sigma, q, type);
    auto V_down_opt = Price(S - bump_S, K, T, r, sigma, q, type);
    if (V_up_opt && V_down_opt) {
        greeks.delta = (*V_up_opt - *V_down_opt) / (2.0 * bump_S);

        // Gamma: ∂²V/∂S²
        greeks.gamma = (*V_up_opt - 2.0 * V0 + *V_down_opt) / (bump_S * bump_S);
    }

    // Vega: ∂V/∂σ (bump ±1% absolute vol)
    const double bump_sigma = 0.01;
    auto V_sigma_up_opt = Price(S, K, T, r, sigma + bump_sigma, q, type);
    auto V_sigma_down_opt = Price(S, K, T, r, sigma - bump_sigma, q, type);
    if (V_sigma_up_opt && V_sigma_down_opt) {
        greeks.vega = (*V_sigma_up_opt - *V_sigma_down_opt) / (2.0 * bump_sigma);
    }

    // Theta: -∂V/∂t (1-day decay, ACT/365)
    const double bump_T = 1.0 / 365.0;
    if (T > bump_T) {
        auto V_tomorrow_opt = Price(S, K, T - bump_T, r, sigma, q, type);
        if (V_tomorrow_opt) {
            greeks.theta = V0 - *V_tomorrow_opt;  // Positive theta means decay
        }
    }

    // Rho: ∂V/∂r (bump ±1 bp = 0.0001)
    const double bump_r = 0.0001;
    auto V_r_up_opt = Price(S, K, T, r + bump_r, sigma, q, type);
    auto V_r_down_opt = Price(S, K, T, r - bump_r, sigma, q, type);
    if (V_r_up_opt && V_r_down_opt) {
        greeks.rho = (*V_r_up_opt - *V_r_down_opt) / (2.0 * bump_r);
    }

    return greeks;
}

std::optional<double> BlackScholes::ImpliedVol(double market_price,
                                               double S,
                                               double K,
                                               double T,
                                               double r,
                                               double q,
                                               OptionType type,
                                               double initial_guess,
                                               double tolerance,
                                               int max_iterations)
{
    // Newton-Raphson solver
    double sigma = initial_guess;

    for (int iter = 0; iter < max_iterations; ++iter) {
        auto price_opt = Price(S, K, T, r, sigma, q, type);
        if (!price_opt) return std::nullopt;

        const double price = *price_opt;
        const double diff = price - market_price;

        if (std::abs(diff) < tolerance) {
            return sigma;  // Converged
        }

        // Compute vega (∂V/∂σ)
        const double bump_sigma = 0.001;
        auto price_bumped_opt = Price(S, K, T, r, sigma + bump_sigma, q, type);
        if (!price_bumped_opt) return std::nullopt;

        const double vega = (*price_bumped_opt - price) / bump_sigma;

        if (std::abs(vega) < 1e-10) {
            return std::nullopt;  // Vega too small, cannot iterate
        }

        // Newton step
        sigma -= diff / vega;

        // Clamp to reasonable range
        sigma = std::max(0.001, std::min(sigma, 5.0));
    }

    return std::nullopt;  // Did not converge
}

} // namespace pricing
} // namespace wallet
