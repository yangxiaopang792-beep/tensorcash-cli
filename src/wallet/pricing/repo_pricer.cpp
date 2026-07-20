// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/repo_pricer.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/black_scholes.h>
#include <wallet/pricing/vol_surface.h>
#include <tinyformat.h>
#include <cmath>

namespace wallet {
namespace pricing {

RepoValuation RepoPricer::Price(const wallet::AssetLeg& principal_leg,
                                const wallet::AssetLeg& interest_leg,
                                const wallet::AssetLeg& collateral_leg,
                                uint32_t maturity_days,
                                uint32_t safety_k,
                               const PricingContext& ctx,
                               const uint256& report_asset,
                               bool report_is_native,
                               int64_t current_time,
                               bool compute_greeks,
                               PriceSource source,
                               bool include_inception_cashflows)
{
    RepoValuation result;
    const double T = LegValuator::DaysToYears(maturity_days);

    // Step 1: Compute PV of principal
    LegPV principal_pv = LegValuator::PresentValue(
        principal_leg, ctx, maturity_days, report_asset, report_is_native, current_time, source);
    result.principal_pv = principal_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          principal_pv.warnings.begin(),
                          principal_pv.warnings.end());

    // Step 2: Compute PV of interest
    LegPV interest_pv = LegValuator::PresentValue(
        interest_leg, ctx, maturity_days, report_asset, report_is_native, current_time, source);
    result.interest_pv = interest_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          interest_pv.warnings.begin(),
                          interest_pv.warnings.end());

    // Step 3: Compute PV of collateral
    LegPV collateral_pv = LegValuator::PresentValue(
        collateral_leg, ctx, maturity_days, report_asset, report_is_native, current_time, source);
    result.collateral_pv = collateral_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          collateral_pv.warnings.begin(),
                          collateral_pv.warnings.end());

    // Step 4: Compute coverage metrics
    const double total_obligation = result.principal_pv + result.interest_pv;

    if (total_obligation > 0.0) {
        result.coverage_ratio = result.collateral_pv / total_obligation;
        result.ltv_pct = 100.0 / result.coverage_ratio;
        result.over_collat_pct = (result.coverage_ratio - 1.0) * 100.0;
    } else {
        result.warnings.push_back(Warning::Critical(
            WarningCategory::COVERAGE,
            "Total obligation (principal + interest) is zero or negative",
            total_obligation
        ));
    }

    // Coverage warnings
    if (result.coverage_ratio < 1.0) {
        result.warnings.push_back(Warning::Critical(
            WarningCategory::COVERAGE,
            strprintf("Collateral undercollateralized: coverage %.2f%% (< 100%%)",
                     result.coverage_ratio * 100.0),
            result.coverage_ratio
        ));
    } else if (result.coverage_ratio < 1.05) {
        result.warnings.push_back(Warning::Critical(
            WarningCategory::COVERAGE,
            strprintf("Collateral critically low: coverage %.2f%% (< 105%%)",
                     result.coverage_ratio * 100.0),
            result.coverage_ratio
        ));
    } else if (result.coverage_ratio < 1.20) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::COVERAGE,
            strprintf("Collateral below recommended: coverage %.2f%% (< 120%%)",
                     result.coverage_ratio * 100.0),
            result.coverage_ratio
        ));
    }

    // Maturity warnings
    if (maturity_days < safety_k) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::DEADLINE,
            strprintf("Maturity approaching: %d days (< %d day safety threshold)",
                     maturity_days, safety_k),
            static_cast<double>(maturity_days)
        ));
    }

    // Step 5: Price collateral option
    // Get risk-free rate from principal curve
    double r = 0.0;
    auto curve_opt = ctx.GetCurve(principal_leg.asset_id, principal_leg.is_native, source);
    if (curve_opt) {
        std::vector<Warning> curve_warnings;
        r = curve_opt->GetZeroRate(maturity_days, curve_warnings);
    } else {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::COVERAGE,
            "Missing discount curve for option pricing, using r=0",
            0.0
        ));
    }

    // Helper: load volatility for a leg
    auto load_sigma = [&](const wallet::AssetLeg& leg) -> std::pair<double, std::vector<Warning>> {
        double sigma_local = 0.0;
        std::vector<Warning> warns;
        if (leg.is_native) {
            return {sigma_local, warns}; // Native TSC -> deterministic (σ=0)
        }
        sigma_local = 0.3;  // Default 30% when missing
        auto vol_surface_opt = ctx.GetVolSurface(leg.asset_id, source);
        if (vol_surface_opt) {
            std::vector<Warning> vol_warnings;
            // ATM moneyness: 1.0 = 100%
            sigma_local = vol_surface_opt->Lookup(1.0, maturity_days, vol_warnings);
            warns.insert(warns.end(), vol_warnings.begin(), vol_warnings.end());
        } else {
            warns.push_back(Warning::Warn(
                WarningCategory::MARKET_DATA,
                strprintf("Missing vol surface for %s, using default σ=30%%",
                         leg.is_native ? "TSC" : leg.asset_id.GetHex().substr(0, 8)),
                sigma_local
            ));
        }
        if (sigma_local > 0.8) {
            warns.push_back(Warning::Warn(
                WarningCategory::MODEL,
                strprintf("Volatility very high: σ=%.1f%%", sigma_local * 100.0),
                sigma_local
            ));
        }
        return {sigma_local, warns};
    };

    // Helper: get correlation between two assets
    auto load_correlation = [&](const wallet::AssetLeg& leg1, const wallet::AssetLeg& leg2) -> std::pair<double, std::vector<Warning>> {
        std::vector<Warning> warns;
        // Same asset -> perfect correlation
        if (leg1.asset_id == leg2.asset_id && leg1.is_native == leg2.is_native) {
            return {1.0, warns};
        }
        // Native vs anything -> 0 correlation (native is deterministic)
        if (leg1.is_native || leg2.is_native) {
            return {0.0, warns};
        }
        // Cross-asset: lookup from correlation matrix
        if (auto corr = ctx.GetCorrelationMatrix()) {
            std::vector<Warning> corr_warns;
            double rho = corr->Lookup(leg1.asset_id, leg2.asset_id, corr_warns);
            warns.insert(warns.end(), corr_warns.begin(), corr_warns.end());
            return {rho, warns};
        } else {
            warns.push_back(Warning::Info(
                WarningCategory::MODEL,
                "Missing correlation matrix, assuming ρ=0"
            ));
            return {0.0, warns};
        }
    };

    // Convert PVs to forward values at maturity for option pricing
    // CRITICAL: Each leg uses its OWN discount factor (fixes multi-asset bug)
    // Guard against division by zero or very small discount factors
    const double collateral_forward = (collateral_pv.discount_factor > 1e-10)
        ? (result.collateral_pv / collateral_pv.discount_factor)
        : result.collateral_pv;
    const double principal_forward = (principal_pv.discount_factor > 1e-10)
        ? (result.principal_pv / principal_pv.discount_factor)
        : result.principal_pv;
    const double interest_forward = (interest_pv.discount_factor > 1e-10)
        ? (result.interest_pv / interest_pv.discount_factor)
        : result.interest_pv;
    const double obligation_forward = principal_forward + interest_forward;

    // Load volatilities for all three legs
    std::vector<Warning> sigma_warns;
    auto [sigma_coll, coll_warns] = load_sigma(collateral_leg);
    sigma_warns.insert(sigma_warns.end(), coll_warns.begin(), coll_warns.end());

    auto [sigma_prin, prin_warns] = load_sigma(principal_leg);
    sigma_warns.insert(sigma_warns.end(), prin_warns.begin(), prin_warns.end());

    auto [sigma_int, int_warns] = load_sigma(interest_leg);
    sigma_warns.insert(sigma_warns.end(), int_warns.begin(), int_warns.end());

    // Compute obligation basket volatility
    // When principal and interest are different assets, treat obligation as a basket
    double sigma_obligation;
    const bool prin_int_same = (principal_leg.asset_id == interest_leg.asset_id &&
                                 principal_leg.is_native == interest_leg.is_native);

    if (prin_int_same) {
        // Same asset for principal and interest -> just use that asset's vol
        sigma_obligation = sigma_prin;
    } else if (obligation_forward < 1e-10) {
        // Degenerate case: total obligation near zero
        sigma_obligation = 0.0;
        sigma_warns.push_back(Warning::Warn(
            WarningCategory::MODEL,
            "Obligation forward near zero, setting σ_obligation=0"
        ));
    } else {
        // Basket: principal and interest are different assets
        // Forward-weighted basket vol: σ² = w_p² σ_p² + w_i² σ_i² + 2 w_p w_i ρ_{pi} σ_p σ_i
        const double w_prin = principal_forward / obligation_forward;
        const double w_int = interest_forward / obligation_forward;

        auto [rho_pi, pi_warns] = load_correlation(principal_leg, interest_leg);
        sigma_warns.insert(sigma_warns.end(), pi_warns.begin(), pi_warns.end());

        const double var_basket = w_prin * w_prin * sigma_prin * sigma_prin +
                                   w_int * w_int * sigma_int * sigma_int +
                                   2.0 * w_prin * w_int * rho_pi * sigma_prin * sigma_int;
        sigma_obligation = std::sqrt(std::max(0.0, var_basket));

        // Guard against NaN/Inf
        if (!std::isfinite(sigma_obligation)) {
            sigma_obligation = 0.3;  // Fall back to default
            sigma_warns.push_back(Warning::Warn(
                WarningCategory::MODEL,
                "Basket volatility calculation produced non-finite value, using default σ=30%"
            ));
        }

        sigma_warns.push_back(Warning::Info(
            WarningCategory::MODEL,
            strprintf("Multi-asset obligation basket: w_p=%.2f%% (σ=%.1f%%), w_i=%.2f%% (σ=%.1f%%), ρ=%.2f → σ_obl=%.1f%%",
                     w_prin * 100.0, sigma_prin * 100.0,
                     w_int * 100.0, sigma_int * 100.0,
                     rho_pi, sigma_obligation * 100.0)
        ));
    }

    // Compute cross-volatility: collateral vs obligation
    // σ_cross² = σ_coll² + σ_obl² - 2 ρ_{coll,obl} σ_coll σ_obl
    double sigma;
    if (collateral_leg.asset_id == principal_leg.asset_id &&
        collateral_leg.is_native == principal_leg.is_native &&
        prin_int_same) {
        // Collateral = principal = interest -> use underlying vol (still option value)
        sigma = sigma_coll;
    } else {
        // Need correlation between collateral and obligation basket
        // ρ_{coll,basket} = (w_p ρ_{coll,prin} σ_p + w_i ρ_{coll,int} σ_i) / σ_basket
        double rho_coll_obl = 0.0;
        if (sigma_obligation > 1e-10) {
            const double w_prin = principal_forward / obligation_forward;
            const double w_int = interest_forward / obligation_forward;

            auto [rho_cp, cp_warns] = load_correlation(collateral_leg, principal_leg);
            sigma_warns.insert(sigma_warns.end(), cp_warns.begin(), cp_warns.end());

            auto [rho_ci, ci_warns] = load_correlation(collateral_leg, interest_leg);
            sigma_warns.insert(sigma_warns.end(), ci_warns.begin(), ci_warns.end());

            const double cov_sum = w_prin * rho_cp * sigma_prin + w_int * rho_ci * sigma_int;
            rho_coll_obl = cov_sum / sigma_obligation;
            // Clamp to [-1, 1] to handle numerical issues
            rho_coll_obl = std::max(-1.0, std::min(1.0, rho_coll_obl));
        }

        const double var_cross = sigma_coll * sigma_coll +
                                  sigma_obligation * sigma_obligation -
                                  2.0 * rho_coll_obl * sigma_coll * sigma_obligation;
        sigma = std::sqrt(std::max(0.0, var_cross));
    }

    // Final guard against NaN/Inf in cross-volatility
    if (!std::isfinite(sigma)) {
        sigma = 0.3;  // Fall back to default
        sigma_warns.push_back(Warning::Warn(
            WarningCategory::MODEL,
            "Cross-volatility calculation produced non-finite value, using default σ=30%"
        ));
    }

    result.warnings.insert(result.warnings.end(), sigma_warns.begin(), sigma_warns.end());

    const double strike_forward = obligation_forward;

    // Price borrower's walkaway option (put) on forward values
    Greeks* greeks_ptr = compute_greeks ? &result.collateral_greeks : nullptr;
    result.collateral_option = PriceCollateralOption(
        collateral_forward,
        strike_forward,
        maturity_days,
        r,
        sigma,
        greeks_ptr,
        BlackScholes::OptionType::PUT
    );

    // Step 6: Compute MTM
    result.lender_mtm = result.principal_pv + result.interest_pv - result.collateral_option;
    result.borrower_mtm = -result.lender_mtm;

    // Step 7: Optional initial principal exchange at inception (t=0)
    if (include_inception_cashflows) {
        LegPV principal_spot = LegValuator::PresentValue(
            principal_leg, ctx, /*maturity_days=*/0, report_asset, report_is_native, current_time, source);
        result.warnings.insert(result.warnings.end(),
                               principal_spot.warnings.begin(),
                               principal_spot.warnings.end());
        result.lender_mtm -= principal_spot.pv_tsc;
        result.borrower_mtm += principal_spot.pv_tsc;
    }

    // Step 8: Per-asset Greeks via finite differences in reporting currency
    if (compute_greeks) {
        const double eps = 0.005;     // 50 bps spot bump
        const double vol_bump = 0.01; // 1 vol point
        const double dr = 0.0001;     // 1 bp rate bump

        const double spot_principal = (principal_pv.discount_factor > 1e-10)
            ? (result.principal_pv / principal_pv.discount_factor)
            : result.principal_pv;
        const double spot_interest = (interest_pv.discount_factor > 1e-10)
            ? (result.interest_pv / interest_pv.discount_factor)
            : result.interest_pv;
        const double spot_collateral = (collateral_pv.discount_factor > 1e-10)
            ? (result.collateral_pv / collateral_pv.discount_factor)
            : result.collateral_pv;

        auto reprice = [&](double mult_prin, double mult_int, double mult_coll,
                           double sigma_override,
                           double r_prin_override, double r_int_override,
                           double r_coll_override, double r_rep_override) -> double {
            const double s_prin = spot_principal * mult_prin;
            const double s_int = spot_interest * mult_int;
            const double s_coll = spot_collateral * mult_coll;

            const double f_prin = s_prin * std::exp((r_rep_override - r_prin_override) * T);
            const double f_int = s_int * std::exp((r_rep_override - r_int_override) * T);
            const double f_coll = s_coll * std::exp((r_rep_override - r_coll_override) * T);
            const double obl_forward = f_prin + f_int;

            double sigma_local = sigma_override;
            if (obl_forward < 1e-12) {
                sigma_local = 0.0;
            }

            const double option = PriceCollateralOption(
                f_coll,
                obl_forward,
                maturity_days,
                r_prin_override,
                sigma_local,
                nullptr,
                BlackScholes::OptionType::PUT
            );

            const double pv_prin = s_prin * std::exp(-r_prin_override * T);
            const double pv_int = s_int * std::exp(-r_int_override * T);

            return pv_prin + pv_int - option;
        };

        const double base = result.lender_mtm;
        double mtm_up[3] = {base, base, base};

        // Deltas and gammas (principal, interest, collateral)
        for (int i = 0; i < 3; ++i) {
            const double spot_i = (i == 0) ? spot_principal : (i == 1 ? spot_interest : spot_collateral);
            if (spot_i <= 0.0) continue;
            double mult_up[3] = {1.0, 1.0, 1.0};
            double mult_dn[3] = {1.0, 1.0, 1.0};
            mult_up[i] += eps;
            mult_dn[i] -= eps;

            mtm_up[i] = reprice(mult_up[0], mult_up[1], mult_up[2],
                                sigma, r, r, r, 0.0);
            const double mtm_dn = reprice(mult_dn[0], mult_dn[1], mult_dn[2],
                                          sigma, r, r, r, 0.0);

            result.asset_greeks.delta[i] = (mtm_up[i] - mtm_dn) / (2.0 * spot_i * eps);
            result.asset_greeks.gamma[i] = (mtm_up[i] - 2.0 * base + mtm_dn)
                                           / (spot_i * spot_i * eps * eps);
        }

        // Cross gammas
        for (int i = 0; i < 3; ++i) {
            const double spot_i = (i == 0) ? spot_principal : (i == 1 ? spot_interest : spot_collateral);
            if (spot_i <= 0.0) continue;
            for (int j = i + 1; j < 3; ++j) {
                const double spot_j = (j == 0) ? spot_principal : (j == 1 ? spot_interest : spot_collateral);
                if (spot_j <= 0.0) continue;
                double mult_both[3] = {1.0, 1.0, 1.0};
                mult_both[i] += eps;
                mult_both[j] += eps;
                const double mtm_ij = reprice(mult_both[0], mult_both[1], mult_both[2],
                                              sigma, r, r, r, 0.0);
                const double cross_val = (mtm_ij - mtm_up[i] - mtm_up[j] + base)
                                         / (spot_i * spot_j * eps * eps);
                result.asset_greeks.cross_gamma[i][j] = cross_val;
                result.asset_greeks.cross_gamma[j][i] = cross_val;
            }
        }

        // Vegas: bump collateral sigma (primary driver) and obligation sigma by 1 vol point
        double sigma_up = sigma + vol_bump;
        double sigma_dn = std::max(0.0, sigma - vol_bump);
        const double mtm_up_sigma = reprice(1.0, 1.0, 1.0, sigma_up, r, r, r, 0.0);
        const double mtm_dn_sigma = reprice(1.0, 1.0, 1.0, sigma_dn, r, r, r, 0.0);
        const double vega_all = (mtm_up_sigma - mtm_dn_sigma) / (2.0 * vol_bump);
        // Attribute vega to collateral only to avoid double counting
        result.asset_greeks.vega[0] = 0.0;
        result.asset_greeks.vega[1] = 0.0;
        result.asset_greeks.vega[2] = vega_all;

        // Rate deltas: bump each independently; r_report modeled as reporting discount mover
        for (int i = 0; i < 4; ++i) {
            double r_up[4] = {r, r, r, 0.0};
            double r_dn[4] = {r, r, r, 0.0};
            r_up[i] += dr;
            r_dn[i] -= dr;
            const double mtm_up_rate = reprice(1.0, 1.0, 1.0, sigma, r_up[0], r_up[1], r_up[2], r_up[3]);
            const double mtm_dn_rate = reprice(1.0, 1.0, 1.0, sigma, r_dn[0], r_dn[1], r_dn[2], r_dn[3]);
            result.asset_greeks.rate_delta[i] = (mtm_up_rate - mtm_dn_rate) / (2.0 * dr);
        }
    }

    return result;
}

double RepoPricer::PriceCollateralOption(double collateral_forward,
                                         double strike_forward,
                                         uint32_t maturity_days,
                                         double r,
                                         double sigma,
                                         Greeks* greeks_out,
                                         BlackScholes::OptionType option_type)
{
    const double T = LegValuator::DaysToYears(maturity_days);
    const double q = 0.0;  // No carry yield

    // Price option on forward/spot values
    // Black-Scholes will handle the discounting internally
    auto price_opt = BlackScholes::Price(
        collateral_forward,
        strike_forward,
        T,
        r,
        sigma,
        q,
        option_type
    );

    if (greeks_out) {
        *greeks_out = BlackScholes::ComputeGreeks(
            collateral_forward, strike_forward, T, r, sigma, q,
            option_type
        );
    }

    return price_opt.value_or(0.0);
}

} // namespace pricing
} // namespace wallet
