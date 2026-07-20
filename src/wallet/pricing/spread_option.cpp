// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/spread_option.h>
#include <wallet/pricing/black_scholes.h>
#include <cmath>
#include <algorithm>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace wallet {
namespace pricing {

bool SpreadOption::ShouldUseKirk(double S_A,
                                 double S_B,
                                 double alpha,
                                 double beta,
                                 double K,
                                 double rho)
{
    // Kirk works well when:
    // 1. Moneyness ratio is reasonable (0.5 < S/K < 2)
    // 2. Correlation not extreme (|ρ| < 0.95)

    const double spread_value = alpha * S_A - beta * S_B;
    const double effective_strike = K;

    // Avoid division by zero
    if (std::abs(effective_strike) < 1e-10) {
        // ATM case - Kirk is fine
        return std::abs(rho) < 0.95;
    }

    const double moneyness = spread_value / effective_strike;

    return (moneyness > 0.5 && moneyness < 2.0) && (std::abs(rho) < 0.95);
}

std::optional<double> SpreadOption::PriceKirk(double S_A,
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
                                              double q_B)
{
    // Kirk (1995) approximation for spread options
    // Payoff: max(α*F_A - β*F_B - K, 0)
    //
    // Kirk's formula:
    // Treat as call on α*F_A with strike (β*F_B + K)
    // Effective volatility: σ²_eff = σ²_A + (β*F_B/(β*F_B+K))² σ²_B - 2ρ (β*F_B/(β*F_B+K)) σ_A σ_B

    // Forward prices
    const double F_A = S_A * std::exp((r - q_A) * T);
    const double F_B = S_B * std::exp((r - q_B) * T);

    // Apply weights
    const double weighted_F_A = alpha * F_A;
    const double weighted_F_B = beta * F_B;
    const double effective_strike = weighted_F_B + K;

    // Kirk's volatility adjustment
    // Key insight: weight sigma_B by F_B/(F_B+K) to account for strike
    const double beta_adj = weighted_F_B / effective_strike;

    const double sigma_eff_sq = sigma_A * sigma_A
                              + beta_adj * beta_adj * sigma_B * sigma_B
                              - 2.0 * beta_adj * rho * sigma_A * sigma_B;

    if (sigma_eff_sq < 0.0) {
        return std::nullopt;
    }

    const double sigma_composite = std::sqrt(sigma_eff_sq);

    // Price as Black-Scholes call on weighted_F_A with strike effective_strike
    // Using forward pricing (r=0), then discount back
    auto call_price_opt = BlackScholes::Price(
        weighted_F_A,      // Underlying = α*F_A
        effective_strike,  // Strike = K + β*F_B
        T,
        0.0,               // r = 0 (forward framework)
        sigma_composite,   // Kirk's composite volatility
        0.0,               // q = 0
        BlackScholes::OptionType::CALL
    );

    if (!call_price_opt) return std::nullopt;

    // Discount from forward to present value
    return *call_price_opt * std::exp(-r * T);
}

std::optional<double> SpreadOption::PriceGaussLegendre(double S_A,
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
                                                       int n_points)
{
    // Gauss-Legendre quadrature nodes and weights (32-point)
    // For simplicity, using 1D integration over S_A (marginalizing S_B given S_A)
    // This is a simplified implementation - production code would use full 2D integration

    // Standard Gauss-Legendre weights and nodes for [-1, 1]
    // For n=32, we'd need the full table. Here's a simplified 8-point version:
    static const std::vector<double> nodes_8 = {
        -0.9602898565, -0.7966664774, -0.5255324099, -0.1834346425,
         0.1834346425,  0.5255324099,  0.7966664774,  0.9602898565
    };
    static const std::vector<double> weights_8 = {
        0.1012285363, 0.2223810345, 0.3137066459, 0.3626837834,
        0.3626837834, 0.3137066459, 0.2223810345, 0.1012285363
    };

    // Use 8-point for now (can be extended to 32-point)
    const auto& nodes = nodes_8;
    const auto& weights = weights_8;

    // Integration bounds: [0, +∞) for S_A
    // Transform: x ∈ [-1, 1] → S_A ∈ [0, S_max]
    // Use S_max = S_A * exp(5*sigma_A*sqrt(T)) as upper bound (~5 std devs)
    const double S_A_max = S_A * std::exp(5.0 * sigma_A * std::sqrt(T));

    double integral = 0.0;

    for (size_t i = 0; i < nodes.size(); ++i) {
        // Transform node to [0, S_max]
        const double x = nodes[i];
        const double S_A_i = 0.5 * S_A_max * (1.0 + x);

        // Lognormal density for S_A (with carry yield)
        const double drift_A = (r - q_A - 0.5 * sigma_A * sigma_A) * T;
        const double diffusion = sigma_A * std::sqrt(T);
        const double z_A = (std::log(S_A_i / S_A) - drift_A) / diffusion;
        const double pdf_A = std::exp(-0.5 * z_A * z_A) / (S_A_i * diffusion * std::sqrt(2.0 * M_PI));

        // Conditional mean and variance of S_B given S_A (with carry yield)
        const double mu_B = (r - q_B - 0.5 * sigma_B * sigma_B) * T;
        const double sigma_B_T = sigma_B * std::sqrt(T);
        const double mu_B_cond = std::log(S_B) + mu_B + rho * sigma_B_T * (z_A * sigma_A * std::sqrt(T)) / (sigma_A * std::sqrt(T));
        const double sigma_B_cond = sigma_B_T * std::sqrt(1.0 - rho * rho);

        // Expected payoff conditioned on S_A_i
        // E[max(α*S_A_i - β*S_B - K, 0) | S_A = S_A_i]
        // This requires another integration over S_B - simplified here

        // Approximate: use conditional mean of S_B
        const double S_B_mean = std::exp(mu_B_cond + 0.5 * sigma_B_cond * sigma_B_cond);
        const double payoff = std::max(alpha * S_A_i - beta * S_B_mean - K, 0.0);

        // Weighted contribution
        integral += weights[i] * payoff * pdf_A;
    }

    // Jacobian of transformation: d(S_A) = 0.5 * S_A_max * dx
    integral *= 0.5 * S_A_max;

    // Discount to present
    return integral * std::exp(-r * T);
}

std::optional<double> SpreadOption::Price(double S_A,
                                          double S_B,
                                          double alpha,
                                          double beta,
                                          double K,
                                          double T,
                                          double r,
                                          double sigma_A,
                                          double sigma_B,
                                          double rho,
                                          bool use_kirk,
                                          double q_A,
                                          double q_B)
{
    // Validation
    if (S_A <= 0.0 || S_B <= 0.0) return std::nullopt;
    if (T <= 0.0) {
        // Expired - return intrinsic
        return std::max(alpha * S_A - beta * S_B - K, 0.0);
    }

    // Degenerate cases: one leg deterministic -> fall back to single-asset Black-Scholes
    if (sigma_B <= 0.0 && sigma_A > 0.0) {
        // Payoff = alpha*S_A - const where const = beta*S_B_T + K
        const double strike = (beta * S_B * std::exp((r - q_B) * T) + K) / alpha;
        auto call = BlackScholes::Price(S_A, strike, T, r, sigma_A, q_A, BlackScholes::OptionType::CALL);
        if (!call) return std::nullopt;
        return alpha * (*call);
    }

    if (sigma_A <= 0.0 && sigma_B > 0.0) {
        // Payoff = const - beta*S_B where const = alpha*S_A_T - K
        const double forward_const = alpha * S_A * std::exp((r - q_A) * T) - K;
        if (forward_const <= 0.0) {
            return 0.0; // Always out of the money
        }
        const double strike = forward_const / beta;
        auto put = BlackScholes::Price(S_B, strike, T, r, sigma_B, q_B, BlackScholes::OptionType::PUT);
        if (!put) return std::nullopt;
        return beta * (*put);
    }

    // Both vols zero -> intrinsic
    if (sigma_A <= 0.0 && sigma_B <= 0.0) {
        return std::max(alpha * S_A - beta * S_B - K, 0.0);
    }

    if (std::abs(rho) > 1.0) return std::nullopt;

    // Auto-select method
    if (!use_kirk && !ShouldUseKirk(S_A, S_B, alpha, beta, K, rho)) {
        return PriceGaussLegendre(S_A, S_B, alpha, beta, K, T, r,
                                  sigma_A, sigma_B, rho, q_A, q_B);
    }

    // Try Kirk first
    auto kirk_result = PriceKirk(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, q_A, q_B);

    // If Kirk fails (e.g., unstable parameters), fallback to Gauss-Legendre
    if (!kirk_result) {
        return PriceGaussLegendre(S_A, S_B, alpha, beta, K, T, r,
                                  sigma_A, sigma_B, rho, q_A, q_B);
    }

    return kirk_result;
}

SpreadOption::SpreadGreeks SpreadOption::ComputeGreeks(double S_A,
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
                                                       bool use_kirk)
{
    SpreadGreeks greeks;

    // Base price - use same method for all perturbations
    auto V0_opt = Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    if (!V0_opt) return greeks;
    const double V0 = *V0_opt;

    // Delta A: ∂V/∂S_A
    const double bump_S_A = 0.005 * S_A;
    auto V_A_up_opt = Price(S_A + bump_S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    auto V_A_down_opt = Price(S_A - bump_S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    if (V_A_up_opt && V_A_down_opt) {
        greeks.delta_A = (*V_A_up_opt - *V_A_down_opt) / (2.0 * bump_S_A);
        greeks.gamma_A = (*V_A_up_opt - 2.0 * V0 + *V_A_down_opt) / (bump_S_A * bump_S_A);
    }

    // Delta B: ∂V/∂S_B
    const double bump_S_B = 0.005 * S_B;
    auto V_B_up_opt = Price(S_A, S_B + bump_S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    auto V_B_down_opt = Price(S_A, S_B - bump_S_B, alpha, beta, K, T, r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    if (V_B_up_opt && V_B_down_opt) {
        greeks.delta_B = (*V_B_up_opt - *V_B_down_opt) / (2.0 * bump_S_B);
        greeks.gamma_B = (*V_B_up_opt - 2.0 * V0 + *V_B_down_opt) / (bump_S_B * bump_S_B);
    }

    // Vega A: ∂V/∂σ_A
    const double bump_sigma = 0.01;
    auto V_sigma_A_up_opt = Price(S_A, S_B, alpha, beta, K, T, r, sigma_A + bump_sigma, sigma_B, rho, use_kirk, q_A, q_B);
    auto V_sigma_A_down_opt = Price(S_A, S_B, alpha, beta, K, T, r, sigma_A - bump_sigma, sigma_B, rho, use_kirk, q_A, q_B);
    if (V_sigma_A_up_opt && V_sigma_A_down_opt) {
        greeks.vega_A = (*V_sigma_A_up_opt - *V_sigma_A_down_opt) / (2.0 * bump_sigma);
    }

    // Vega B: ∂V/∂σ_B
    auto V_sigma_B_up_opt = Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B + bump_sigma, rho, use_kirk, q_A, q_B);
    auto V_sigma_B_down_opt = Price(S_A, S_B, alpha, beta, K, T, r, sigma_A, sigma_B - bump_sigma, rho, use_kirk, q_A, q_B);
    if (V_sigma_B_up_opt && V_sigma_B_down_opt) {
        greeks.vega_B = (*V_sigma_B_up_opt - *V_sigma_B_down_opt) / (2.0 * bump_sigma);
    }

    // Theta: -∂V/∂t (1-day decay)
    const double bump_T = 1.0 / 365.0;
    if (T > bump_T) {
        auto V_tomorrow_opt = Price(S_A, S_B, alpha, beta, K, T - bump_T, r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
        if (V_tomorrow_opt) {
            greeks.theta = V0 - *V_tomorrow_opt;
        }
    }

    // Rho: ∂V/∂r
    const double bump_r = 0.0001;
    auto V_r_up_opt = Price(S_A, S_B, alpha, beta, K, T, r + bump_r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    auto V_r_down_opt = Price(S_A, S_B, alpha, beta, K, T, r - bump_r, sigma_A, sigma_B, rho, use_kirk, q_A, q_B);
    if (V_r_up_opt && V_r_down_opt) {
        greeks.rho_rate = (*V_r_up_opt - *V_r_down_opt) / (2.0 * bump_r);
    }

    return greeks;
}

} // namespace pricing
} // namespace wallet
