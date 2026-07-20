// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PRICING_GREEKS_H
#define BITCOIN_WALLET_PRICING_GREEKS_H

#include <serialize.h>

namespace wallet {
namespace pricing {

/**
 * Greeks sensitivities for option pricing
 * Computed via finite-difference bumps:
 * - Delta/Gamma: ±0.5% spot bumps
 * - Vega: ±1 vol point (absolute)
 * - Theta: 1 calendar day time decay
 * - Rho: ±1 bp rate bumps
 */
struct Greeks {
    double delta{0.0};   // ∂V/∂S (per unit underlying)
    double gamma{0.0};   // ∂²V/∂S² (convexity)
    double vega{0.0};    // ∂V/∂σ (per 1% vol point)
    double theta{0.0};   // -∂V/∂t (1-day decay)
    double rho{0.0};     // ∂V/∂r (per 1 bp rate)

    Greeks() = default;
    Greeks(double d, double g, double v, double t, double r)
        : delta(d), gamma(g), vega(v), theta(t), rho(r) {}

    SERIALIZE_METHODS(Greeks, obj) {
        READWRITE(obj.delta, obj.gamma, obj.vega, obj.theta, obj.rho);
    }

    // Add two greeks (for portfolio aggregation)
    Greeks operator+(const Greeks& other) const {
        return Greeks(
            delta + other.delta,
            gamma + other.gamma,  // Note: gamma summation is approximate
            vega + other.vega,
            theta + other.theta,
            rho + other.rho
        );
    }

    // Scale greeks by a factor
    Greeks operator*(double factor) const {
        return Greeks(
            delta * factor,
            gamma * factor,
            vega * factor,
            theta * factor,
            rho * factor
        );
    }
};

} // namespace pricing
} // namespace wallet

#endif // BITCOIN_WALLET_PRICING_GREEKS_H
