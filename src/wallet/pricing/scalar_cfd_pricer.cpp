// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricing/scalar_cfd_pricer.h>

#include <arith_uint256.h>
#include <consensus/difficulty_cfd.h>   // MIN_SETTLE_OUTPUT
#include <consensus/scalar_cfd.h>       // ComputeScalarCfdPayout, DecodeScalarValue, ScalarLossDenominator, SCALARCFD_LAMBDA_SCALE
#include <consensus/scalar_cfd_leaf.h>  // ScalarCfdPayoffMode

#include <algorithm>
#include <cmath>
#include <limits>

namespace wallet {
namespace pricing {

double ScalarLossFraction(double ratio, uint32_t lambda_q, uint8_t payoff_mode, bool is_short)
{
    // Fail closed on an unknown payoff mode (mirror consensus — only STRIKE/REALIZED exist). A future
    // mode 2 must not silently price as STRIKE; a direct caller gets NaN and the valuation guard rejects it.
    if (payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE) &&
        payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)) {
        return std::numeric_limits<double>::quiet_NaN();
    }
    if (lambda_q == 0) return 0.0;
    const double lam = static_cast<double>(lambda_q) / static_cast<double>(SCALARCFD_LAMBDA_SCALE);
    // Cross rate is strictly positive in practice; defend the divide: X<=0 => long fully loses, short flat.
    if (!(ratio > 0.0)) return is_short ? 0.0 : 1.0;
    // Direction: long (is_short=false) loses as R falls below 1; short loses as R rises above 1.
    const double adverse = is_short ? std::max(0.0, ratio - 1.0) : std::max(0.0, 1.0 - ratio);
    if (adverse <= 0.0) return 0.0;
    // Denominator: mode 0 STRIKE (|X-K|/K = adverse), mode 1 REALIZED (|X-K|/X = adverse / R).
    const bool realized = (payoff_mode == static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED));
    const double frac = realized ? (lam * adverse / ratio) : (lam * adverse);
    return std::clamp(frac, 0.0, 1.0);
}

namespace {

struct LegQuote {
    double owner_payout{0.0};
    double cp_payout{0.0};
    bool ok{false};
};
struct ContractQuote {
    LegQuote long_leg;
    LegQuote short_leg;
};

//! Exact (consensus) leg payout at a known integer scalar — the deterministic / intrinsic path.
LegQuote ExactLeg(const ScalarCfdLegTerms& leg, const arith_uint256& K, const arith_uint256& X,
                  ScalarLossDenominator denom, bool is_short)
{
    LegQuote out;
    if (leg.im == 0 || leg.lambda_q == 0) { out.ok = true; return out; }
    ScalarCfdPayout payout;
    if (!ComputeScalarCfdPayout(K, X, denom, leg.lambda_q, leg.im, is_short,
                                static_cast<uint64_t>(MIN_SETTLE_OUTPUT), payout)) {
        return out; // ok=false -> model_unreliable
    }
    out.owner_payout = static_cast<double>(payout.payout_owner);
    out.cp_payout = static_cast<double>(payout.payout_cp);
    out.ok = true;
    return out;
}

ContractQuote ExactQuote(const ScalarCfdContractTerms& terms, const arith_uint256& K, const arith_uint256& X)
{
    const ScalarLossDenominator denom = terms.payoff_mode == static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)
                                            ? ScalarLossDenominator::REALIZED : ScalarLossDenominator::STRIKE;
    ContractQuote out;
    out.long_leg = ExactLeg(terms.long_leg, K, X, denom, /*is_short=*/false);
    out.short_leg = ExactLeg(terms.short_leg, K, X, denom, /*is_short=*/true);
    return out;
}

//! E[ScalarLossFraction(R)] over a lognormal R = F_R * exp(v*z - v^2/2), z~N(0,1), via a normalized
//! trapezoidal quadrature on z in [-6, 6]. sigma*sqrt(tau) ~ 0 -> the deterministic fraction at F_R, so
//! the stochastic path collapses to the same convention as the consensus intrinsic. Uniform across modes.
double ExpectedFraction(double F_R, double sigma, double tau, uint32_t lambda_q, uint8_t payoff_mode, bool is_short)
{
    if (!(F_R > 0.0)) return is_short ? 0.0 : 1.0;
    const double v = sigma * std::sqrt(std::max(0.0, tau));
    if (v <= 1e-9) return ScalarLossFraction(F_R, lambda_q, payoff_mode, is_short);
    const double drift = -0.5 * v * v;
    const int N = 240;
    const double zmax = 6.0;
    const double dz = 2.0 * zmax / static_cast<double>(N);
    double num = 0.0, den = 0.0;
    for (int i = 0; i <= N; ++i) {
        const double z = -zmax + static_cast<double>(i) * dz;
        double w = std::exp(-0.5 * z * z);           // φ up to a constant (cancels in num/den)
        if (i == 0 || i == N) w *= 0.5;              // trapezoidal endpoint half-weights
        const double R = F_R * std::exp(v * z + drift);
        num += w * ScalarLossFraction(R, lambda_q, payoff_mode, is_short);
        den += w;
    }
    return (den > 0.0) ? num / den : ScalarLossFraction(F_R, lambda_q, payoff_mode, is_short);
}

LegQuote ExpectedLeg(const ScalarCfdLegTerms& leg, double F_R, double sigma, double tau, uint8_t payoff_mode, bool is_short)
{
    LegQuote out;
    out.ok = true;
    if (leg.im == 0 || leg.lambda_q == 0) return out;
    const double frac = ExpectedFraction(F_R, sigma, tau, leg.lambda_q, payoff_mode, is_short);
    out.cp_payout = frac * static_cast<double>(leg.im);
    out.owner_payout = static_cast<double>(leg.im) - out.cp_payout;
    return out;
}

ContractQuote ExpectedQuote(const ScalarCfdContractTerms& terms, double F_R, double sigma, double tau)
{
    ContractQuote out;
    out.long_leg = ExpectedLeg(terms.long_leg, F_R, sigma, tau, terms.payoff_mode, /*is_short=*/false);
    out.short_leg = ExpectedLeg(terms.short_leg, F_R, sigma, tau, terms.payoff_mode, /*is_short=*/true);
    return out;
}

//! Long party's net PnL (collateral units): owns the long-leg owner payout + receives the short-leg cp
//! (loss transferred from the short) − the long-leg IM it posted. Short is the exact negative.
double LongNetPnl(const ScalarCfdContractTerms& terms, const ContractQuote& q)
{
    return q.long_leg.owner_payout + q.short_leg.cp_payout - static_cast<double>(terms.long_leg.im);
}

} // namespace

ScalarCfdValuation ScalarCfdPricer::Price(const ScalarCfdContractTerms& terms,
                                          const ScalarCfdMarketInputs& mkt,
                                          bool compute_greeks)
{
    ScalarCfdValuation result;
    result.discount_factor = mkt.discount_factor;
    result.sigma = mkt.sigma;
    result.tau_years = mkt.tau_years;
    result.collateral_is_native = mkt.collateral_is_native;
    result.forward_provenance = ScalarCurveProvenanceToString(mkt.forward_provenance);

    std::string verr;
    if (!terms.Validate(verr)) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MODEL, "Invalid scalar CFD terms: " + verr));
        return result;
    }

    // Fail closed on malformed market data (5f-6c feeds discount_factor / forward / sigma / tau from curves
    // + RPC inputs): a non-finite or negative value would otherwise yield a NaN/negative PV silently.
    // forward_cross_rate == 0 is the legitimate "no forward -> flat" sentinel.
    if (!std::isfinite(mkt.discount_factor) || mkt.discount_factor < 0.0 ||
        !std::isfinite(mkt.sigma) || mkt.sigma < 0.0 ||
        !std::isfinite(mkt.tau_years) || mkt.tau_years < 0.0 ||
        !std::isfinite(mkt.forward_cross_rate) || mkt.forward_cross_rate < 0.0) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MARKET_DATA,
            "non-finite or negative market input (discount_factor / forward_cross_rate / sigma / tau_years)"));
        return result;
    }

    arith_uint256 K, X_now;
    if (!DecodeScalarValue(terms.scalar_format_id, terms.strike, K) ||
        !DecodeScalarValue(terms.scalar_format_id, mkt.current_scalar, X_now)) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MARKET_DATA, "scalar decode failed (strike/current)"));
        return result;
    }
    const double K_d = K.getdouble();
    if (!(K_d > 0.0)) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MODEL, "strike decodes to a non-positive value"));
        return result;
    }
    result.current_ratio = X_now.getdouble() / K_d;

    // ---- Forward: a known fixing settles deterministically; else the curve-resolved forward cross rate.
    const bool fixing_reached = mkt.realized_scalar.has_value();
    result.fixing_reached = fixing_reached;
    arith_uint256 forward_X = X_now;      // flat fallback (display)
    bool have_arith_forward = true;       // true while we hold an integer forward -> EXACT consensus path
    double F_R;
    if (fixing_reached) {
        if (!DecodeScalarValue(terms.scalar_format_id, *mkt.realized_scalar, forward_X)) {
            result.model_unreliable = true;
            result.warnings.push_back(Warning::Critical(WarningCategory::MARKET_DATA, "realized scalar decode failed"));
            return result;
        }
        F_R = forward_X.getdouble() / K_d;
        // A deadline fallback is economically distinct from a real published fixing — surface it.
        result.is_fallback = mkt.realized_is_fallback;
        result.forward_provenance = mkt.realized_is_fallback ? "fallback" : "fixed";
    } else if (mkt.forward_cross_rate > 0.0) {
        F_R = mkt.forward_cross_rate / K_d; // curve forward -> double F_R only; settle via the model
        have_arith_forward = false;
    } else {
        F_R = X_now.getdouble() / K_d;      // no forward supplied -> flat at current
        result.warnings.push_back(Warning::Info(WarningCategory::COVERAGE,
            "No scalar forward; using the current cross rate as a flat forecast"));
    }
    result.forecast_ratio = F_R;

    const double sigma = fixing_reached ? 0.0 : std::max(0.0, mkt.sigma);
    const double tau = fixing_reached ? 0.0 : std::max(0.0, mkt.tau_years);
    result.sigma = sigma;
    result.tau_years = tau;
    const double df = mkt.discount_factor;

    // ---- Intrinsic (exact at current). Expected: exact consensus when the fixing is known, or σ=0 with an
    // integer forward (the flat default); otherwise the continuous model at F_R.
    const ContractQuote intrinsic = ExactQuote(terms, K, X_now);
    const bool use_exact_expected = fixing_reached || (sigma == 0.0 && have_arith_forward);
    const ContractQuote expected = use_exact_expected ? ExactQuote(terms, K, forward_X)
                                                      : ExpectedQuote(terms, F_R, sigma, tau);
    if (!intrinsic.long_leg.ok || !intrinsic.short_leg.ok || !expected.long_leg.ok || !expected.short_leg.ok) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MODEL, "Scalar payout computation rejected the terms"));
        return result;
    }

    result.long_leg_intrinsic_owner_payout = intrinsic.long_leg.owner_payout;
    result.long_leg_intrinsic_cp_payout = intrinsic.long_leg.cp_payout;
    result.short_leg_intrinsic_owner_payout = intrinsic.short_leg.owner_payout;
    result.short_leg_intrinsic_cp_payout = intrinsic.short_leg.cp_payout;
    result.long_leg_expected_owner_payout = expected.long_leg.owner_payout;
    result.long_leg_expected_cp_payout = expected.long_leg.cp_payout;
    result.short_leg_expected_owner_payout = expected.short_leg.owner_payout;
    result.short_leg_expected_cp_payout = expected.short_leg.cp_payout;

    result.intrinsic_long_mtm = LongNetPnl(terms, intrinsic);
    result.intrinsic_short_mtm = -result.intrinsic_long_mtm;
    result.expected_long_mtm = df * LongNetPnl(terms, expected);
    result.expected_short_mtm = -result.expected_long_mtm;

    // ---- Greeks: finite-difference the discounted model long MTM (skipped when the fixing is known).
    if (compute_greeks && !fixing_reached) {
        auto long_mtm = [&](double fr, double sig, double tauv) -> double {
            return df * LongNetPnl(terms, ExpectedQuote(terms, fr, sig, tauv));
        };
        const double base = long_mtm(F_R, sigma, tau);
        const double up = long_mtm(F_R * 1.01, sigma, tau);
        const double down = long_mtm(F_R * 0.99, sigma, tau);
        result.long_delta_to_cross_rate = (up - down) / 0.02; // per 1.0 fractional move in X
        result.short_delta_to_cross_rate = -result.long_delta_to_cross_rate;
        result.long_vega = long_mtm(F_R, sigma + 0.01, tau) - base; // per +0.01 vol
        result.short_vega = -result.long_vega;
        const double tau_day = std::max(0.0, tau - 1.0 / 365.0);
        result.long_theta = long_mtm(F_R, sigma, tau_day) - base;   // per −1 day to fixing
        result.short_theta = -result.long_theta;
    }

    return result;
}

} // namespace pricing
} // namespace wallet
