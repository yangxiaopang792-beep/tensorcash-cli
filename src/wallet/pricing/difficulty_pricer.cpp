// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricing/difficulty_pricer.h>

#include <arith_uint256.h>
#include <consensus/difficulty_cfd.h>
#include <pow.h>
#include <tinyformat.h>
#include <wallet/pricing/black_scholes.h>
#include <wallet/pricing/difficulty_curve.h>
#include <wallet/pricing/difficulty_vol_surface.h>
#include <wallet/pricing/discount_curve.h>
#include <wallet/pricing/pricing_context.h>

#include <algorithm>
#include <cmath>
#include <string>

namespace wallet {
namespace pricing {
namespace {

constexpr double SECONDS_PER_YEAR = 365.0 * 24.0 * 3600.0;

struct LegQuote {
    double owner_payout{0.0};
    double cp_payout{0.0};
    bool ok{false};
};

struct ContractQuote {
    LegQuote long_leg;
    LegQuote short_leg;
};

// ---- Exact (consensus) leg payout at a known realized target — used for intrinsic + reached fixing.
LegQuote ExactLeg(const DifficultyLegTerms& leg,
                  const arith_uint256& strike_target,
                  const arith_uint256& realized_target,
                  bool is_short)
{
    LegQuote out;
    if (leg.im <= 0 || leg.lambda_q == 0) { out.ok = true; return out; }
    DiffCfdPayout payout;
    if (!ComputeDiffCfdPayout(strike_target, realized_target, leg.lambda_q,
                              static_cast<uint64_t>(leg.im), is_short, payout)) {
        return out;
    }
    out.owner_payout = static_cast<double>(payout.payout_owner);
    out.cp_payout = static_cast<double>(payout.payout_cp);
    out.ok = true;
    return out;
}

ContractQuote ExactQuote(const DifficultyContractTerms& terms,
                         const arith_uint256& strike_target,
                         const arith_uint256& realized_target)
{
    ContractQuote out;
    if (terms.IsOption()) {
        if (terms.OptionWriterIsShort()) {
            out.long_leg.ok = true;
            out.short_leg = ExactLeg(terms.short_leg, strike_target, realized_target, /*is_short=*/true);
        } else {
            out.long_leg = ExactLeg(terms.long_leg, strike_target, realized_target, /*is_short=*/false);
            out.short_leg.ok = true;
        }
        return out;
    }
    out.long_leg = ExactLeg(terms.long_leg, strike_target, realized_target, /*is_short=*/false);
    out.short_leg = ExactLeg(terms.short_leg, strike_target, realized_target, /*is_short=*/true);
    return out;
}

// ---- Stochastic (model) expected payout: lognormal R, capped call/put spread, Black-76 (§10.2-10.3).
//      Forward (undiscounted) option value on R, E[(R-K)+] / E[(K-R)+].
double ForwardOption(double F, double K, double sigma, double tau, bool call)
{
    if (K <= 0.0) return call ? F : 0.0;            // put@<=0 worthless; call@<=0 always exercised
    const double v = sigma * std::sqrt(std::max(0.0, tau));
    if (v <= 1e-12 || F <= 0.0) {                   // degenerate -> intrinsic on the forward
        return call ? std::max(F - K, 0.0) : std::max(K - F, 0.0);
    }
    auto p = BlackScholes::Price(F, K, std::max(tau, 1e-12), /*r=*/0.0, sigma, /*q=*/0.0,
                                 call ? BlackScholes::OptionType::CALL : BlackScholes::OptionType::PUT);
    if (!p) return call ? std::max(F - K, 0.0) : std::max(K - F, 0.0);
    return std::max(0.0, *p);
}

double ExpectedLegCp(const DifficultyLegTerms& leg, double F_R, double sigma, double tau, bool is_short)
{
    if (leg.im <= 0 || leg.lambda_q == 0) return 0.0;
    const double lam = static_cast<double>(leg.lambda_q) / static_cast<double>(DIFFCFD_LAMBDA_SCALE);
    const double im = static_cast<double>(leg.im);
    double frac;
    if (is_short) {  // call spread struck at 1 and 1+1/lam
        const double c1 = ForwardOption(F_R, 1.0, sigma, tau, /*call=*/true);
        const double c2 = ForwardOption(F_R, 1.0 + 1.0 / lam, sigma, tau, /*call=*/true);
        frac = lam * (c1 - c2);
    } else {         // put spread struck at 1 and 1-1/lam (floored at 0)
        const double p1 = ForwardOption(F_R, 1.0, sigma, tau, /*call=*/false);
        const double p2 = ForwardOption(F_R, std::max(0.0, 1.0 - 1.0 / lam), sigma, tau, /*call=*/false);
        frac = lam * (p1 - p2);
    }
    frac = std::clamp(frac, 0.0, 1.0);
    return frac * im;
}

LegQuote ExpectedLeg(const DifficultyLegTerms& leg, double F_R, double sigma, double tau, bool is_short)
{
    LegQuote out;
    out.ok = true;
    if (leg.im <= 0 || leg.lambda_q == 0) return out;
    out.cp_payout = ExpectedLegCp(leg, F_R, sigma, tau, is_short);
    out.owner_payout = static_cast<double>(leg.im) - out.cp_payout;
    return out;
}

ContractQuote ExpectedQuote(const DifficultyContractTerms& terms, double F_R, double sigma, double tau)
{
    ContractQuote out;
    if (terms.IsOption()) {
        if (terms.OptionWriterIsShort()) {
            out.long_leg.ok = true;
            out.short_leg = ExpectedLeg(terms.short_leg, F_R, sigma, tau, /*is_short=*/true);
        } else {
            out.long_leg = ExpectedLeg(terms.long_leg, F_R, sigma, tau, /*is_short=*/false);
            out.short_leg.ok = true;
        }
        return out;
    }
    out.long_leg = ExpectedLeg(terms.long_leg, F_R, sigma, tau, /*is_short=*/false);
    out.short_leg = ExpectedLeg(terms.short_leg, F_R, sigma, tau, /*is_short=*/true);
    return out;
}

// Net contingent PnL building blocks (the IM cancels in the CFD net; see §10.3).
double LongNetPnl(const DifficultyContractTerms& terms, const ContractQuote& q)
{
    if (terms.IsOption()) return 0.0;
    return q.long_leg.owner_payout + q.short_leg.cp_payout - static_cast<double>(terms.long_leg.im);
}

double WriterLegCp(const DifficultyContractTerms& terms, const ContractQuote& q)
{
    return terms.OptionWriterIsShort() ? q.short_leg.cp_payout : q.long_leg.cp_payout;
}

double DifficultyRatio(const arith_uint256& strike_target, const arith_uint256& target)
{
    const double denom = target.getdouble();
    if (denom <= 0.0) return 0.0;
    return strike_target.getdouble() / denom;
}

bool TermsEconomicallyValid(const DifficultyContractTerms& terms, std::string& err)
{
    auto valid_leg = [&](const DifficultyLegTerms& leg, const char* name) {
        if (leg.im < MIN_SETTLE_OUTPUT) { err = strprintf("%s IM is below MIN_SETTLE_OUTPUT", name); return false; }
        if (leg.lambda_q == 0) { err = strprintf("%s lambda_q must be non-zero", name); return false; }
        return true;
    };
    if (terms.IsOption()) {
        if (terms.premium < MIN_SETTLE_OUTPUT) { err = "option premium is below MIN_SETTLE_OUTPUT"; return false; }
        const bool long_active = terms.long_leg.im > 0 || terms.long_leg.lambda_q > 0;
        const bool short_active = terms.short_leg.im > 0 || terms.short_leg.lambda_q > 0;
        if (long_active == short_active) { err = "option must have exactly one active writer leg"; return false; }
        return valid_leg(terms.OptionWriterLeg(), "writer");
    }
    if (terms.premium != 0) { err = "CFD premium must be zero"; return false; }
    return valid_leg(terms.long_leg, "long") && valid_leg(terms.short_leg, "short");
}

} // namespace

DifficultyValuation DifficultyPricer::Price(const DifficultyContractTerms& terms,
                                            const PricingContext& ctx,
                                            const DifficultyMarketInputs& mkt,
                                            bool compute_greeks)
{
    DifficultyValuation result;
    result.current_nbits = mkt.current_nbits;
    result.strike_nbits = terms.strike_nbits;
    result.fixing_height = terms.fixing_height;
    result.settle_lock_height = terms.settle_lock_height;
    result.current_height = mkt.current_height;
    result.blocks_to_fixing = std::max(0, static_cast<int>(terms.fixing_height) - mkt.current_height);
    result.blocks_to_resolvable = std::max(0, static_cast<int>(terms.fixing_height) + DIFFCFD_MATURITY_DEPTH - mkt.current_height);
    result.is_option = terms.IsOption();
    result.option_writer_is_short = terms.IsOption() && terms.OptionWriterIsShort();
    result.premium_pv = static_cast<double>(terms.premium);

    std::string econ_err;
    if (!TermsEconomicallyValid(terms, econ_err)) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MODEL, "Invalid difficulty terms: " + econ_err));
        return result;
    }

    const auto strike_target = DeriveTarget(terms.strike_nbits, mkt.pow_limit);
    const auto current_target = DeriveTarget(mkt.current_nbits, mkt.pow_limit);
    if (!strike_target || !current_target) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MARKET_DATA,
            "strike/current nBits out of range for the chain powLimit"));
        return result;
    }
    result.current_difficulty_ratio = DifficultyRatio(*strike_target, *current_target);

    // ---- Determine the forward target (forecast of realized target @ fixing) + provenance.
    const bool fixing_reached = mkt.realized_nbits.has_value();
    result.fixing_reached = fixing_reached;
    arith_uint256 forward_target = *current_target;  // flat fallback (today's behaviour)
    uint32_t forward_nbits = mkt.current_nbits;
    result.forward_provenance = "flat";
    // True while we hold an arith forward target (flat / override / fixed) — lets the σ=0 / no-vol
    // path settle through the EXACT consensus ComputeDiffCfdPayout. The curve path yields only a
    // double F_R, so it always takes the continuous model (acceptable: a curve is itself a model input).
    bool have_arith_forward = true;

    if (fixing_reached) {
        const auto realized = DeriveTarget(*mkt.realized_nbits, mkt.pow_limit);
        if (!realized) {
            result.model_unreliable = true;
            result.warnings.push_back(Warning::Critical(WarningCategory::MARKET_DATA,
                "realized nBits @ fixing height out of range for the chain powLimit"));
            return result;
        }
        forward_target = *realized;
        forward_nbits = *mkt.realized_nbits;
        result.forward_provenance = "fixed";
    } else if (mkt.forecast_nbits_override) {
        const auto fwd = DeriveTarget(*mkt.forecast_nbits_override, mkt.pow_limit);
        if (fwd) { forward_target = *fwd; forward_nbits = *mkt.forecast_nbits_override; result.forward_provenance = "mark"; }
    } else if (auto curve = ctx.GetDifficultyCurve(mkt.source)) {
        // F_R = E[D] / D_strike, both in difficulty (chainwork) space — no reciprocal-convexity term
        // (§10.1). forward_target/forward_nbits stay at the flat value for display only; provenance
        // tells the consumer the forecast came from the curve.
        std::vector<Warning> cw;
        if (auto fwd_d = curve->ForwardDifficulty(static_cast<uint32_t>(result.blocks_to_fixing), cw)) {
            const double strike_d = DifficultyWorkFromTarget(*strike_target);
            if (strike_d > 0.0) {
                result.forecast_difficulty_ratio = *fwd_d / strike_d;
                result.forward_provenance = DiffCurveProvenanceToString(curve->provenance);
                have_arith_forward = false;  // only a double F_R; settle via the continuous model
            }
        }
        result.warnings.insert(result.warnings.end(), cw.begin(), cw.end());
    } else {
        result.warnings.push_back(Warning::Info(WarningCategory::COVERAGE,
            "No difficulty forward curve; using tip nBits as a flat forecast"));
    }

    // F_R (= E[R]) in double space. For the curve path it is already set above; otherwise from targets.
    double F_R = (result.forecast_difficulty_ratio > 0.0)
        ? result.forecast_difficulty_ratio
        : DifficultyRatio(*strike_target, forward_target);
    result.forecast_difficulty_ratio = F_R;
    result.forecast_nbits = forward_nbits;

    // ---- Volatility + horizon.
    double sigma = 0.0;
    if (!fixing_reached) {
        if (auto vol = ctx.GetDifficultyVolSurface(mkt.source)) {
            std::vector<Warning> vw;
            if (auto s = vol->Sigma(static_cast<uint32_t>(result.blocks_to_fixing), vw)) sigma = std::max(0.0, *s);
            result.warnings.insert(result.warnings.end(), vw.begin(), vw.end());
        } else {
            result.warnings.push_back(Warning::Warn(WarningCategory::MODEL,
                "No difficulty vol surface; option time value is unpriced (deterministic point forecast)"));
        }
    }
    const double tau = fixing_reached ? 0.0
        : std::max(0, result.blocks_to_fixing) * static_cast<double>(mkt.pow_target_spacing) / SECONDS_PER_YEAR;
    result.sigma = sigma;
    result.tau_years = tau;

    // ---- Native-TSC discount factor to settle_lock_height.
    double df = 1.0;
    {
        const uint256 native_id;  // all-zero == native
        if (auto native_curve = ctx.GetCurve(native_id, /*is_native=*/true, mkt.source)) {
            const int settle_blocks = std::max(0, static_cast<int>(terms.settle_lock_height) - mkt.current_height);
            const double days = settle_blocks * static_cast<double>(mkt.pow_target_spacing) / 86400.0;
            std::vector<Warning> dw;
            df = native_curve->GetDiscountFactor(static_cast<uint32_t>(std::lround(days)), dw);
            result.warnings.insert(result.warnings.end(), dw.begin(), dw.end());
        } else {
            result.warnings.push_back(Warning::Info(WarningCategory::COVERAGE,
                "No native discount curve; difficulty MTM is undiscounted (DF=1)"));
        }
    }
    result.discount_factor = df;

    // ---- Intrinsic (exact, at current) and expected quotes. When the fixing is known, or when there
    // is no vol (σ=0) and we still hold an arith forward (the no-surface default), settle through the
    // EXACT consensus ComputeDiffCfdPayout so the default path reproduces today's behaviour bit-for-bit.
    const ContractQuote intrinsic = ExactQuote(terms, *strike_target, *current_target);
    const bool use_exact_expected = fixing_reached || (sigma == 0.0 && have_arith_forward);
    ContractQuote expected;
    if (use_exact_expected) {
        expected = ExactQuote(terms, *strike_target, forward_target);
    } else {
        expected = ExpectedQuote(terms, F_R, sigma, tau);
    }
    if (!intrinsic.long_leg.ok || !intrinsic.short_leg.ok || !expected.long_leg.ok || !expected.short_leg.ok) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(WarningCategory::MODEL,
            "Difficulty payout computation rejected the contract terms"));
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

    if (terms.IsOption()) {
        result.intrinsic_buyer_mtm = WriterLegCp(terms, intrinsic) - static_cast<double>(terms.premium);
        result.intrinsic_writer_mtm = -result.intrinsic_buyer_mtm;
        result.expected_buyer_mtm = df * WriterLegCp(terms, expected) - static_cast<double>(terms.premium);
        result.expected_writer_mtm = -result.expected_buyer_mtm;
    } else {
        result.intrinsic_long_mtm = LongNetPnl(terms, intrinsic);
        result.intrinsic_short_mtm = -result.intrinsic_long_mtm;
        result.expected_long_mtm = df * LongNetPnl(terms, expected);
        result.expected_short_mtm = -result.expected_long_mtm;
    }

    // ---- Greeks: finite-difference the discounted model MTM. Skipped when the fixing is known.
    if (compute_greeks && !fixing_reached) {
        auto role_mtm = [&](double fr, double sig, double tauv) -> double {
            const ContractQuote q = ExpectedQuote(terms, fr, sig, tauv);
            if (terms.IsOption()) return df * WriterLegCp(terms, q) - static_cast<double>(terms.premium);
            return df * LongNetPnl(terms, q);
        };
        const double base = role_mtm(F_R, sigma, tau);
        const double up = role_mtm(F_R * 1.01, sigma, tau);
        const double down = role_mtm(F_R * 0.99, sigma, tau);
        const double delta = (up - down) / 0.02;                     // per 1.0 difficulty fractional move
        const double vega = role_mtm(F_R, sigma + 0.01, tau) - base; // per +0.01 vol
        const double tau_day = std::max(0.0, tau - 1.0 / 365.0);
        const double theta = role_mtm(F_R, sigma, tau_day) - base;   // per −1 day to fixing

        if (terms.IsOption()) {
            result.buyer_delta_to_difficulty = delta; result.writer_delta_to_difficulty = -delta;
            result.buyer_vega = vega; result.writer_vega = -vega;
            result.buyer_theta = theta; result.writer_theta = -theta;
        } else {
            result.long_delta_to_difficulty = delta; result.short_delta_to_difficulty = -delta;
            result.long_vega = vega; result.short_vega = -vega;
            result.long_theta = theta; result.short_theta = -theta;
        }
    }

    return result;
}

} // namespace pricing
} // namespace wallet
