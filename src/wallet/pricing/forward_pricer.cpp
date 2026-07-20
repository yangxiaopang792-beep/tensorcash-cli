// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/forward_pricer.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/vol_surface.h>
#include <wallet/pricing/correlation_matrix.h>
#include <wallet/pricing/black_scholes.h>
#include <tinyformat.h>
#include <cmath>

namespace wallet {
namespace pricing {

ForwardValuation ForwardPricer::Price(const wallet::AssetLeg& receive_leg,
                                      const wallet::AssetLeg& pay_leg,
                                      const wallet::AssetLeg& im_alice_leg,
                                      const wallet::AssetLeg& im_bob_leg,
                                      const wallet::AssetLeg& premium_leg,
                                      uint32_t maturity_days,
                                      uint32_t safety_k,
                                      const PricingContext& ctx,
                                      const uint256& report_asset,
                                      bool report_is_native,
                                      int64_t current_time,
                                      bool compute_greeks,
                                      PriceSource source)
{
    ForwardValuation result;

    // Step 1: Compute PV of receive leg (Bob → Alice)
    LegPV receive_pv = LegValuator::PresentValue(
        receive_leg, ctx, maturity_days, report_asset, report_is_native, current_time, source);
    result.pv_receive = receive_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          receive_pv.warnings.begin(),
                          receive_pv.warnings.end());

    // Step 2: Compute PV of pay leg (Alice → Bob)
    LegPV pay_pv = LegValuator::PresentValue(
        pay_leg, ctx, maturity_days, report_asset, report_is_native, current_time, source);
    result.pv_pay = pay_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          pay_pv.warnings.begin(),
                          pay_pv.warnings.end());

    // Step 3: Net spread
    result.net_spread_value = result.pv_receive - result.pv_pay;

    // Step 3a: Convert IM legs to reporting currency (IM posted at t=0, no discounting)
    LegPV im_alice_pv = LegValuator::PresentValue(
        im_alice_leg, ctx, 0, report_asset, report_is_native, current_time, source);
    const double im_alice = im_alice_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          im_alice_pv.warnings.begin(),
                          im_alice_pv.warnings.end());

    LegPV im_bob_pv = LegValuator::PresentValue(
        im_bob_leg, ctx, 0, report_asset, report_is_native, current_time, source);
    const double im_bob = im_bob_pv.pv_tsc;
    result.warnings.insert(result.warnings.end(),
                          im_bob_pv.warnings.begin(),
                          im_bob_pv.warnings.end());

    // Step 3b: Premium (paid at t=0, no discounting)
    if (premium_leg.units > 0) {
        LegPV premium_pv = LegValuator::PresentValue(
            premium_leg, ctx, 0, report_asset, report_is_native, current_time, source);
        result.premium_pv = premium_pv.pv_tsc;
        result.warnings.insert(result.warnings.end(),
                              premium_pv.warnings.begin(),
                              premium_pv.warnings.end());
    }

    // Step 4: Uncapped exposures
    result.alice_exposure_uncapped = std::max(0.0, -result.net_spread_value);
    result.bob_exposure_uncapped = std::max(0.0, result.net_spread_value);

    // Step 5: IM coverage ratios
    if (result.alice_exposure_uncapped > 0.0) {
        result.im_coverage_alice = im_alice / result.alice_exposure_uncapped;
    } else {
        result.im_coverage_alice = 1e9;  // No exposure = infinite coverage
    }

    if (result.bob_exposure_uncapped > 0.0) {
        result.im_coverage_bob = im_bob / result.bob_exposure_uncapped;
    } else {
        result.im_coverage_bob = 1e9;
    }

    // Coverage warnings
    if (result.im_coverage_alice < 1.0) {
        result.warnings.push_back(Warning::Critical(
            WarningCategory::IM,
            strprintf("Alice IM undercollateralized: %.2f%% coverage",
                     result.im_coverage_alice * 100.0),
            result.im_coverage_alice
        ));
    } else if (result.im_coverage_alice < 1.2) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::IM,
            strprintf("Alice IM coverage low: %.2f%%",
                     result.im_coverage_alice * 100.0),
            result.im_coverage_alice
        ));
    }

    if (result.im_coverage_bob < 1.0) {
        result.warnings.push_back(Warning::Critical(
            WarningCategory::IM,
            strprintf("Bob IM undercollateralized: %.2f%% coverage",
                     result.im_coverage_bob * 100.0),
            result.im_coverage_bob
        ));
    } else if (result.im_coverage_bob < 1.2) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::IM,
            strprintf("Bob IM coverage low: %.2f%%",
                     result.im_coverage_bob * 100.0),
            result.im_coverage_bob
        ));
    }

    // Maturity warnings
    if (maturity_days < safety_k) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::DEADLINE,
            strprintf("Maturity approaching: %d days (< %d safety threshold)",
                     maturity_days, safety_k),
            static_cast<double>(maturity_days)
        ));
    }

    // Step 6: Get market data for option pricing
    const double T = LegValuator::DaysToYears(maturity_days);

    // Helpers for rates, vols, and correlation
    auto load_rate = [&](const wallet::AssetLeg& leg, const char* label) -> double {
        double rate = 0.0;
        auto curve_opt = ctx.GetCurve(leg.asset_id, leg.is_native, source);
        if (curve_opt) {
            std::vector<Warning> curve_warnings;
            rate = curve_opt->GetZeroRate(maturity_days, curve_warnings);
            result.warnings.insert(result.warnings.end(),
                                   curve_warnings.begin(),
                                   curve_warnings.end());
        } else {
            result.warnings.push_back(Warning::Warn(
                WarningCategory::COVERAGE,
                strprintf("Missing discount curve for %s, using r=0", label),
                0.0
            ));
        }
        return rate;
    };

    auto load_sigma = [&](const wallet::AssetLeg& leg, const char* label) -> double {
        if (leg.is_native) {
            return 0.0; // Native coin deterministic
        }
        double sigma_local = 0.3;  // Default 30%
        auto vol_surface_opt = ctx.GetVolSurface(leg.asset_id, source);
        if (vol_surface_opt) {
            std::vector<Warning> vol_warnings;
            sigma_local = vol_surface_opt->Lookup(1.0, maturity_days, vol_warnings);
            result.warnings.insert(result.warnings.end(),
                                   vol_warnings.begin(),
                                   vol_warnings.end());
        } else {
            result.warnings.push_back(Warning::Warn(
                WarningCategory::MARKET_DATA,
                strprintf("Missing vol surface for %s, using σ=30%%", label),
                sigma_local
            ));
        }
        return sigma_local;
    };

    auto load_correlation = [&](const wallet::AssetLeg& leg1, const wallet::AssetLeg& leg2) -> double {
        // Perfect when same asset (and nativeness)
        if (leg1.asset_id == leg2.asset_id && leg1.is_native == leg2.is_native) {
            return 1.0;
        }
        // Native vs anything else: deterministic leg
        if (leg1.is_native || leg2.is_native) {
            return 0.0;
        }
        if (auto corr = ctx.GetCorrelationMatrix()) {
            std::vector<Warning> corr_warnings;
            double rho = corr->Lookup(leg1.asset_id, leg2.asset_id, corr_warnings);
            result.warnings.insert(result.warnings.end(),
                                   corr_warnings.begin(),
                                   corr_warnings.end());
            return rho;
        }
        result.warnings.push_back(Warning::Info(
            WarningCategory::MODEL,
            "Missing correlation matrix, assuming ρ=0"
        ));
        return 0.0;
    };

    // Rates in their own numéraires
    double r_receive = load_rate(receive_leg, "receive_leg");     // r_B
    double r_pay = load_rate(pay_leg, "pay_leg");                 // r_A
    double r_im_alice = load_rate(im_alice_leg, "im_alice");
    double r_im_bob = load_rate(im_bob_leg, "im_bob");

    // Reporting (domestic) rate (used only for discounting linear legs)
    double r_report = 0.0;
    {
        wallet::AssetLeg report_leg{report_asset, report_is_native, 0, {}};
        r_report = load_rate(report_leg, "report_asset");
    }

    // Volatilities vs report/TSC
    double sigma_receive = load_sigma(receive_leg, "receive_leg");    // σ_B
    double sigma_pay = load_sigma(pay_leg, "pay_leg");                // σ_A
    double sigma_im_alice = load_sigma(im_alice_leg, "im_alice");     // σ_C
    double sigma_im_bob = load_sigma(im_bob_leg, "im_bob");           // σ_D

    // Asset-level correlations ρ_ij
    const double rho_AB = load_correlation(receive_leg, pay_leg);             // B vs A
    const double rho_DB = load_correlation(im_bob_leg, receive_leg);          // D vs B
    const double rho_AD = load_correlation(pay_leg, im_bob_leg);              // A vs D
    const double rho_AC = load_correlation(pay_leg, im_alice_leg);            // A vs C
    const double rho_BC = load_correlation(receive_leg, im_alice_leg);        // B vs C

    // Helper: clamp correlation into [-1, 1]
    auto clamp_rho = [&](double rho) -> double {
        if (rho > 1.0) return 1.0;
        if (rho < -1.0) return -1.0;
        return rho;
    };

    // Cross-variance/covariance helpers for log cross-rates vs numéraire
    auto cross_var = [&](double sigma_i, double sigma_n, double rho_in) {
        return sigma_i * sigma_i
             + sigma_n * sigma_n
             - 2.0 * rho_in * sigma_i * sigma_n;
    };

    auto cross_cov = [&](double sigma_i, double sigma_j, double sigma_n,
                         double rho_ij, double rho_in, double rho_jn) {
        // cov(ln(S_i/S_n), ln(S_j/S_n))
        return sigma_i * sigma_j * rho_ij
             - sigma_i * sigma_n * rho_in
             - sigma_j * sigma_n * rho_jn
             + sigma_n * sigma_n;
    };

    const bool im_bob_matches_A = (im_bob_leg.asset_id == pay_leg.asset_id &&
                                   im_bob_leg.is_native == pay_leg.is_native);
    const bool im_bob_matches_B = (im_bob_leg.asset_id == receive_leg.asset_id &&
                                   im_bob_leg.is_native == receive_leg.is_native);
    const bool im_alice_matches_A = (im_alice_leg.asset_id == pay_leg.asset_id &&
                                     im_alice_leg.is_native == pay_leg.is_native);
    const bool im_alice_matches_B = (im_alice_leg.asset_id == receive_leg.asset_id &&
                                     im_alice_leg.is_native == receive_leg.is_native);

    // Spot notional values in reporting currency (remove leg discounting, keep FX)
    // These are "q_i * S_i(0)" for deliver legs and "m_i * S_i(0)" for IM legs.
    const double spot_receive_notional = (receive_pv.discount_factor > 1e-10)
        ? (result.pv_receive / receive_pv.discount_factor)
        : result.pv_receive;
    const double spot_pay_notional = (pay_pv.discount_factor > 1e-10)
        ? (result.pv_pay / pay_pv.discount_factor)
        : result.pv_pay;

    const double spot_im_a_notional = im_alice; // IM already at t=0 in report currency
    const double spot_im_b_notional = im_bob;

    // Extract per-unit spot prices S_i(0) in report currency
    const double q_B = static_cast<double>(receive_leg.units);
    const double q_A = static_cast<double>(pay_leg.units);
    const double m_C = static_cast<double>(im_alice_leg.units);
    const double m_D = static_cast<double>(im_bob_leg.units);

    double S_B0 = 0.0;
    double S_A0 = 0.0;
    double S_C0 = 0.0;
    double S_D0 = 0.0;

    if (q_B > 0.0 && spot_receive_notional > 0.0) {
        S_B0 = spot_receive_notional / q_B;
    }
    if (q_A > 0.0 && spot_pay_notional > 0.0) {
        S_A0 = spot_pay_notional / q_A;
    }
    if (m_C > 0.0 && spot_im_a_notional > 0.0) {
        S_C0 = spot_im_a_notional / m_C;
    }
    if (m_D > 0.0 && spot_im_b_notional > 0.0) {
        S_D0 = spot_im_b_notional / m_D;
    }

    // Export inferred spot levels for diagnostics
    result.spot_A0 = S_A0;
    result.spot_B0 = S_B0;
    result.spot_C0 = S_C0;
    result.spot_D0 = S_D0;

    // Guard against missing spot data for deliver legs
    if (S_A0 <= 0.0 || S_B0 <= 0.0) {
        result.model_unreliable = true;
        result.warnings.push_back(Warning::Critical(
            WarningCategory::MODEL,
            "basket value non-positive; failed to infer spot prices for deliver legs; cannot price walkaway options"
        ));
        // MTM will just be linear forward + premium in this case
    } else {
        // === Short's walkaway: Bob may default; Alice is short a call in D units ===
        // Numéraire N = D (Bob's IM asset). X_B = S_B / S_D, X_A = S_A / S_D.

        std::optional<double> short_call_value_report;

        if (q_A > 0.0 && q_B > 0.0 && m_D >= 0.0) {
            // Cross vol for A/B used in degeneracies
            const double var_X_AB = cross_var(sigma_pay, sigma_receive, rho_AB);

            if (im_bob_matches_B && S_B0 > 0.0 && var_X_AB > 0.0) {
                // Degeneracy D = B: X_B ≡ 1, X_A = A/B
                const double X0 = S_A0 / S_B0; // A/B
                const double sigma_X = std::sqrt(var_X_AB);

                if (sigma_X > 0.0 && q_B > m_D) {
                    const double K_X = (q_B - m_D) / q_A; // from q_B - q_A X - m_D > 0
                    auto bs_put = BlackScholes::Price(
                        X0,
                        K_X,
                        T,
                        r_receive,          // numéraire B
                        sigma_X,
                        r_pay,              // A carry
                        BlackScholes::OptionType::PUT
                    );
                    if (bs_put) {
                        const double value_B = q_A * (*bs_put);
                        short_call_value_report = value_B * S_B0;

                        if (compute_greeks) {
                            auto greeks_bs = BlackScholes::ComputeGreeks(
                                X0,
                                K_X,
                                T,
                                r_receive,
                                sigma_X,
                                r_pay,
                                BlackScholes::OptionType::PUT
                            );
                            result.spread_greeks_call.delta_A = q_A * greeks_bs.delta;
                            result.spread_greeks_call.gamma_A = q_A * greeks_bs.gamma;
                            result.spread_greeks_call.vega_A = q_A * greeks_bs.vega;
                            result.spread_greeks_call.theta = greeks_bs.theta;
                            result.spread_greeks_call.rho_rate = greeks_bs.rho;
                        }
                    }
                } else if (q_B <= m_D) {
                    // IM fully covers liability in B
                    short_call_value_report = 0.0;
                }
            } else if (im_bob_matches_A && S_A0 > 0.0) {
                // Degeneracy D = A: X_A ≡ 1, X_B = B/A
                const double X0 = S_B0 / S_A0; // B/A

                const double var_X = cross_var(sigma_receive, sigma_pay, rho_AB);
                const double sigma_X = (var_X > 0.0) ? std::sqrt(var_X) : 0.0;

                if (sigma_X > 0.0) {
                    if (std::max(sigma_pay, sigma_receive) > 0.8 || std::abs(rho_AB) > 0.8) {
                        result.warnings.push_back(Warning::Warn(
                            WarningCategory::MODEL,
                            strprintf("Kirk approximation may be inaccurate for short walkaway (degenerate D=A, σ=%.2f/%.2f, ρ=%.2f)",
                                      sigma_pay, sigma_receive, rho_AB)
                        ));
                    }
                    const double K_X = (q_A + m_D) / q_B; // from q_B X - q_A - m_D > 0
                    auto bs_call = BlackScholes::Price(
                        X0,
                        K_X,
                        T,
                        r_pay,               // numéraire A
                        sigma_X,
                        r_receive,           // B carry
                        BlackScholes::OptionType::CALL
                    );
                    if (bs_call) {
                        const double value_A = q_B * (*bs_call);
                        short_call_value_report = value_A * S_A0;

                        if (compute_greeks) {
                            auto greeks_bs = BlackScholes::ComputeGreeks(
                                X0,
                                K_X,
                                T,
                                r_pay,
                                sigma_X,
                                r_receive,
                                BlackScholes::OptionType::CALL
                            );
                            result.spread_greeks_call.delta_A = q_B * greeks_bs.delta;
                            result.spread_greeks_call.gamma_A = q_B * greeks_bs.gamma;
                            result.spread_greeks_call.vega_A = q_B * greeks_bs.vega;
                            result.spread_greeks_call.theta = greeks_bs.theta;
                            result.spread_greeks_call.rho_rate = greeks_bs.rho;
                        }
                    }
                }
            } else {
                // Generic 3-asset: D is third asset. X_B = B/D, X_A = A/D.
                if (S_D0 <= 0.0) {
                    result.model_unreliable = true;
                    result.warnings.push_back(Warning::Critical(
                        WarningCategory::COVERAGE,
                        "Short walkaway requires S_D(0); missing FX/spot for Bob IM asset"
                    ));
                } else {
                    const double X_B0 = S_B0 / S_D0;
                    const double X_A0 = S_A0 / S_D0;

                    const double var_BD = cross_var(sigma_receive, sigma_im_bob, rho_DB);
                    const double var_AD = cross_var(sigma_pay, sigma_im_bob, rho_AD);
                    const double cov_BA = cross_cov(
                        sigma_receive, sigma_pay, sigma_im_bob,
                        rho_AB, rho_DB, rho_AD
                    );

                    double sigma_BD = 0.0;
                    double sigma_AD = 0.0;
                    double rho_BD_AD = 0.0;
                    if (var_BD > 0.0) sigma_BD = std::sqrt(var_BD);
                    if (var_AD > 0.0) sigma_AD = std::sqrt(var_AD);
                    if (var_BD > 0.0 && var_AD > 0.0) {
                        rho_BD_AD = clamp_rho(cov_BA / (std::sqrt(var_BD * var_AD) + 1e-16));
                    }

                    if (X_B0 > 0.0 && X_A0 > 0.0 && sigma_BD > 0.0 && sigma_AD > 0.0) {
                        if (std::abs(rho_BD_AD) >= 0.95) {
                            result.warnings.push_back(Warning::Info(
                                WarningCategory::MODEL,
                                strprintf("Forcing Kirk for short walkaway (|ρ|=%.3f)", rho_BD_AD)
                            ));
                        } else if (std::max(sigma_BD, sigma_AD) > 0.8 || std::abs(rho_BD_AD) > 0.8) {
                            result.warnings.push_back(Warning::Warn(
                                WarningCategory::MODEL,
                                strprintf("Kirk approximation may be inaccurate for short walkaway (σ=%.2f/%.2f, ρ=%.2f)",
                                          sigma_BD, sigma_AD, rho_BD_AD)
                            ));
                        }

                        auto call_D = SpreadOption::Price(
                            X_B0, X_A0,
                            q_B, q_A, m_D,    // α, β, K
                            T,
                            r_im_bob,         // D numéraire
                            sigma_BD, sigma_AD,
                            rho_BD_AD,
                            true,             // ALWAYS Kirk, never Gauss stub
                            r_receive,        // B carry
                            r_pay             // A carry
                        );

                        if (call_D) {
                            short_call_value_report = (*call_D) * S_D0;
                        }

                        if (compute_greeks) {
                            auto greeks_D = SpreadOption::ComputeGreeks(
                                X_B0, X_A0,
                                q_B, q_A, m_D,
                                T,
                                r_im_bob,
                                sigma_BD, sigma_AD,
                                rho_BD_AD,
                                r_receive,        // B carry
                                r_pay,            // A carry
                                true              // use Kirk
                            );
                            result.spread_greeks_call = greeks_D;
                        }
                    }
                }
            }
        }

        if (short_call_value_report) {
            // Alice is short Bob's walkaway protection
            result.alice_short_call_value = -(*short_call_value_report);
        } else {
            result.warnings.push_back(Warning::Warn(
                WarningCategory::MODEL,
                "Failed to price Alice short call walkaway option",
                0.0
            ));
        }

        // === Long's walkaway: Alice may default; option in C units ===
        // Numéraire N = C (Alice's IM asset). X_A = A/C, X_B = B/C.

        std::optional<double> long_put_value_report;

        if (q_A > 0.0 && q_B > 0.0 && m_C >= 0.0) {
            // Cross vol for A/B used in degeneracies
            const double var_X_AB = cross_var(sigma_pay, sigma_receive, rho_AB);

            if (im_alice_matches_A && S_A0 > 0.0 && var_X_AB > 0.0) {
                // Degeneracy C = A: X_A ≡ 1, X_B = B/A
                const double X0 = S_B0 / S_A0; // B/A
                const double sigma_X = std::sqrt(var_X_AB);

                if (sigma_X > 0.0 && q_A > m_C) {
                    if (std::max(sigma_pay, sigma_receive) > 0.8 || std::abs(rho_AB) > 0.8) {
                        result.warnings.push_back(Warning::Warn(
                            WarningCategory::MODEL,
                            strprintf("Kirk approximation may be inaccurate for long walkaway (degenerate C=A, σ=%.2f/%.2f, ρ=%.2f)",
                                      sigma_pay, sigma_receive, rho_AB)
                        ));
                    }
                    const double K_X = (q_A - m_C) / q_B; // from q_A - q_B X - m_C > 0
                    auto bs_put = BlackScholes::Price(
                        X0,
                        K_X,
                        T,
                        r_pay,               // numéraire A
                        sigma_X,
                        r_receive,           // B carry
                        BlackScholes::OptionType::PUT
                    );
                    if (bs_put) {
                        const double value_A = q_B * (*bs_put);
                        long_put_value_report = value_A * S_A0;

                        if (compute_greeks) {
                            auto greeks_bs = BlackScholes::ComputeGreeks(
                                X0,
                                K_X,
                                T,
                                r_pay,
                                sigma_X,
                                r_receive,
                                BlackScholes::OptionType::PUT
                            );
                            result.spread_greeks_put.delta_A = q_B * greeks_bs.delta;
                            result.spread_greeks_put.gamma_A = q_B * greeks_bs.gamma;
                            result.spread_greeks_put.vega_A = q_B * greeks_bs.vega;
                            result.spread_greeks_put.theta = greeks_bs.theta;
                            result.spread_greeks_put.rho_rate = greeks_bs.rho;
                        }
                    }
                } else if (q_A <= m_C) {
                    long_put_value_report = 0.0; // IM fully covers liability in A
                }
            } else if (im_alice_matches_B && S_B0 > 0.0) {
                // Degeneracy C = B: X_B ≡ 1, X_A = A/B
                const double X0 = S_A0 / S_B0; // A/B

                const double var_X = cross_var(sigma_pay, sigma_receive, rho_AB);
                const double sigma_X = (var_X > 0.0) ? std::sqrt(var_X) : 0.0;

                if (sigma_X > 0.0) {
                    if (std::max(sigma_pay, sigma_receive) > 0.8 || std::abs(rho_AB) > 0.8) {
                        result.warnings.push_back(Warning::Warn(
                            WarningCategory::MODEL,
                            strprintf("Kirk approximation may be inaccurate for long walkaway (degenerate C=B, σ=%.2f/%.2f, ρ=%.2f)",
                                      sigma_pay, sigma_receive, rho_AB)
                        ));
                    }
                    const double K_X = (q_B + m_C) / q_A; // from q_A X - q_B - m_C > 0
                    auto bs_call = BlackScholes::Price(
                        X0,
                        K_X,
                        T,
                        r_receive,           // numéraire B
                        sigma_X,
                        r_pay,               // A carry
                        BlackScholes::OptionType::CALL
                    );
                    if (bs_call) {
                        const double value_B = q_A * (*bs_call);
                        long_put_value_report = value_B * S_B0;

                        if (compute_greeks) {
                            auto greeks_bs = BlackScholes::ComputeGreeks(
                                X0,
                                K_X,
                                T,
                                r_receive,
                                sigma_X,
                                r_pay,
                                BlackScholes::OptionType::CALL
                            );
                            result.spread_greeks_put.delta_A = q_A * greeks_bs.delta;
                            result.spread_greeks_put.gamma_A = q_A * greeks_bs.gamma;
                            result.spread_greeks_put.vega_A = q_A * greeks_bs.vega;
                            result.spread_greeks_put.theta = greeks_bs.theta;
                            result.spread_greeks_put.rho_rate = greeks_bs.rho;
                        }
                    }
                }
            } else {
                // Generic 3-asset: C is third asset; X_A = A/C, X_B = B/C.
                if (S_C0 <= 0.0) {
                    result.model_unreliable = true;
                    result.warnings.push_back(Warning::Critical(
                        WarningCategory::COVERAGE,
                        "Long walkaway requires S_C(0); missing FX/spot for Alice IM asset"
                    ));
                } else {
                    const double X_A0 = S_A0 / S_C0;
                    const double X_B0 = S_B0 / S_C0;

                    const double var_AC = cross_var(sigma_pay, sigma_im_alice, rho_AC);
                    const double var_BC = cross_var(sigma_receive, sigma_im_alice, rho_BC);
                    const double cov_AB = cross_cov(
                        sigma_pay, sigma_receive, sigma_im_alice,
                        rho_AB, rho_AC, rho_BC
                    );

                    double sigma_AC = 0.0;
                    double sigma_BC = 0.0;
                    double rho_AC_BC = 0.0;
                    if (var_AC > 0.0) sigma_AC = std::sqrt(var_AC);
                    if (var_BC > 0.0) sigma_BC = std::sqrt(var_BC);
                    if (var_AC > 0.0 && var_BC > 0.0) {
                        rho_AC_BC = clamp_rho(cov_AB / (std::sqrt(var_AC * var_BC) + 1e-16));
                    }

                    if (X_A0 > 0.0 && X_B0 > 0.0 && sigma_AC > 0.0 && sigma_BC > 0.0) {
                        if (std::abs(rho_AC_BC) >= 0.95) {
                            result.warnings.push_back(Warning::Info(
                                WarningCategory::MODEL,
                                strprintf("Forcing Kirk for long walkaway (|ρ|=%.3f)", rho_AC_BC)
                            ));
                        } else if (std::max(sigma_AC, sigma_BC) > 0.8 || std::abs(rho_AC_BC) > 0.8) {
                            result.warnings.push_back(Warning::Warn(
                                WarningCategory::MODEL,
                                strprintf("Kirk approximation may be inaccurate for long walkaway (σ=%.2f/%.2f, ρ=%.2f)",
                                          sigma_AC, sigma_BC, rho_AC_BC)
                            ));
                        }

                        auto call_C = SpreadOption::Price(
                            X_A0, X_B0,
                            q_A, q_B, m_C,     // α, β, K
                            T,
                            r_im_alice,        // C numéraire
                            sigma_AC, sigma_BC,
                            rho_AC_BC,
                            true,              // ALWAYS Kirk
                            r_pay,             // A carry
                            r_receive          // B carry
                        );

                        if (call_C) {
                            // This is the call in C units; convert to report currency
                            long_put_value_report = (*call_C) * S_C0;
                        }

                        if (compute_greeks) {
                            auto greeks_C = SpreadOption::ComputeGreeks(
                                X_A0, X_B0,
                                q_A, q_B, m_C,
                                T,
                                r_im_alice,
                                sigma_AC, sigma_BC,
                                rho_AC_BC,
                                r_pay,             // A carry
                                r_receive,         // B carry
                                true               // use Kirk
                            );
                            result.spread_greeks_put = greeks_C;
                        }
                    }
                }
            }
        }

        if (long_put_value_report) {
            result.alice_long_put_value = *long_put_value_report;
        } else {
            result.warnings.push_back(Warning::Warn(
                WarningCategory::MODEL,
                "Failed to price Alice long put walkaway option",
                0.0
            ));
        }
    }

    // Warn if option values are large relative to IM
    if (std::abs(result.alice_short_call_value) > 0.5 * im_bob) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::IM,
            strprintf("Short call value (%.2f) > 50%% of Bob's IM (%.2f)",
                     std::abs(result.alice_short_call_value), im_bob),
            std::abs(result.alice_short_call_value) / im_bob
        ));
    }

    if (result.alice_long_put_value > 0.5 * im_alice) {
        result.warnings.push_back(Warning::Warn(
            WarningCategory::IM,
            strprintf("Long put value (%.2f) > 50%% of Alice's IM (%.2f)",
                     result.alice_long_put_value, im_alice),
            result.alice_long_put_value / im_alice
        ));
    }

    // Step 8: Compute MTM
    result.alice_mtm = result.net_spread_value
                     + result.alice_short_call_value
                     + result.alice_long_put_value
                     + result.premium_pv;
    result.bob_mtm = -result.alice_mtm;

    // Optional per-asset Greeks via finite differences (report currency)
    if (compute_greeks) {
        const double eps = 0.005;     // 50 bps bump on spots
        const double vol_bump = 0.01; // +1 vol point
        const double dr = 0.0001;     // 1 bp rate bump

        // Cache base per-unit spots inferred above (may be zero if missing)
        const double base_S_A0 = S_A0;
        const double base_S_B0 = S_B0;
        const double base_S_C0 = S_C0;
        const double base_S_D0 = S_D0;

        auto recompute_mtm = [&](double mult_rec, double mult_pay, double mult_im_a, double mult_im_b,
                                 double sigma_rec_override, double sigma_pay_override,
                                 double r_rec_override, double r_pay_override,
                                 double /*r_rep_override*/) -> double {
            // Bumped spot levels in report currency
            const double S_B0_b = base_S_B0 * mult_rec;
            const double S_A0_b = base_S_A0 * mult_pay;
            const double S_C0_b = base_S_C0 * mult_im_a;
            const double S_D0_b = base_S_D0 * mult_im_b;

            // Recompute clean forward PV with bumped rates and spots via DF ratios
            const double df_rec_factor = std::exp(-(r_rec_override - r_receive) * T);
            const double df_pay_factor = std::exp(-(r_pay_override - r_pay) * T);
            const double pv_rec_bumped = result.pv_receive * mult_rec * df_rec_factor;
            const double pv_pay_bumped = result.pv_pay * mult_pay * df_pay_factor;
            double net_spread = pv_rec_bumped - pv_pay_bumped;

            double short_call = 0.0;
            double long_put = 0.0;

            // Only attempt option revaluation if we have meaningful spot data
            if (S_A0_b > 0.0 && S_B0_b > 0.0) {
                // === Short walkaway: Bob may default; Alice is short a call in D units ===
                if (q_A > 0.0 && q_B > 0.0 && m_D >= 0.0) {
                    // Cross vol for A/B used in degeneracies
                    const double var_X_AB_b = cross_var(sigma_pay_override, sigma_rec_override, rho_AB);

                    if (im_bob_matches_B && S_B0_b > 0.0 && var_X_AB_b > 0.0) {
                        // Degeneracy D = B: X_B ≡ 1, X_A = A/B
                        const double X0_b = S_A0_b / S_B0_b; // A/B
                        const double sigma_X_b = std::sqrt(var_X_AB_b);

                        if (sigma_X_b > 0.0 && q_B > m_D) {
                            const double K_X_b = (q_B - m_D) / q_A;
                            auto bs_put_b = BlackScholes::Price(
                                X0_b,
                                K_X_b,
                                T,
                                r_rec_override,      // numéraire B
                                sigma_X_b,
                                r_pay_override,      // A carry
                                BlackScholes::OptionType::PUT
                            );
                            if (bs_put_b) {
                                const double value_B_b = q_A * (*bs_put_b);
                                short_call = -value_B_b * S_B0_b;
                            }
                        }
                    } else if (im_bob_matches_A && S_A0_b > 0.0) {
                        // Degeneracy D = A: X_A ≡ 1, X_B = B/A
                        const double X0_b = S_B0_b / S_A0_b; // B/A

                        const double var_X_b = cross_var(sigma_rec_override, sigma_pay_override, rho_AB);
                        const double sigma_X_b = (var_X_b > 0.0) ? std::sqrt(var_X_b) : 0.0;

                        if (sigma_X_b > 0.0) {
                            const double K_X_b = (q_A + m_D) / q_B;
                            auto bs_call_b = BlackScholes::Price(
                                X0_b,
                                K_X_b,
                                T,
                                r_pay_override,       // numéraire A
                                sigma_X_b,
                                r_rec_override,       // B carry
                                BlackScholes::OptionType::CALL
                            );
                            if (bs_call_b) {
                                const double value_A_b = q_B * (*bs_call_b);
                                short_call = -value_A_b * S_A0_b;
                            }
                        }
                    } else if (S_D0_b > 0.0) {
                        // Generic 3-asset: D is third asset. X_B = B/D, X_A = A/D.
                        const double X_B0_b = S_B0_b / S_D0_b;
                        const double X_A0_b = S_A0_b / S_D0_b;

                        const double var_BD_b = cross_var(sigma_rec_override, sigma_im_bob, rho_DB);
                        const double var_AD_b = cross_var(sigma_pay_override, sigma_im_bob, rho_AD);
                        const double cov_BA_b = cross_cov(
                            sigma_rec_override, sigma_pay_override, sigma_im_bob,
                            rho_AB, rho_DB, rho_AD
                        );

                        double sigma_BD_b = 0.0;
                        double sigma_AD_b = 0.0;
                        double rho_BD_AD_b = 0.0;
                        if (var_BD_b > 0.0) sigma_BD_b = std::sqrt(var_BD_b);
                        if (var_AD_b > 0.0) sigma_AD_b = std::sqrt(var_AD_b);
                        if (var_BD_b > 0.0 && var_AD_b > 0.0) {
                            rho_BD_AD_b = cov_BA_b / (std::sqrt(var_BD_b * var_AD_b) + 1e-16);
                            if (rho_BD_AD_b > 1.0) rho_BD_AD_b = 1.0;
                            if (rho_BD_AD_b < -1.0) rho_BD_AD_b = -1.0;
                        }

                        if (X_B0_b > 0.0 && X_A0_b > 0.0 && sigma_BD_b > 0.0 && sigma_AD_b > 0.0) {
                            auto call_D_b = SpreadOption::Price(
                                X_B0_b, X_A0_b,
                                q_B, q_A, m_D,
                                T,
                                r_im_bob,         // discount at r_D (unchanged)
                                sigma_BD_b,
                                sigma_AD_b,
                                rho_BD_AD_b,
                                true,             // use Kirk approximation
                                r_rec_override,   // B carry (bumped)
                                r_pay_override    // A carry (bumped)
                            );
                            if (call_D_b) {
                                const double value_D_b = *call_D_b;
                                short_call = -value_D_b * S_D0_b;
                            }
                        }
                    }
                }

                // === Long walkaway: Alice may default; option in C units ===
                if (q_A > 0.0 && q_B > 0.0 && m_C >= 0.0) {
                    // Cross vol for A/B used in degeneracies
                    const double var_X_AB_b = cross_var(sigma_pay_override, sigma_rec_override, rho_AB);

                    if (im_alice_matches_A && S_A0_b > 0.0 && var_X_AB_b > 0.0) {
                        // Degeneracy C = A: X_A ≡ 1, X_B = B/A
                        const double X0_b = S_B0_b / S_A0_b; // B/A
                        const double sigma_X_b = std::sqrt(var_X_AB_b);

                        if (sigma_X_b > 0.0 && q_A > m_C) {
                            const double K_X_b = (q_A - m_C) / q_B;
                            auto bs_put_b = BlackScholes::Price(
                                X0_b,
                                K_X_b,
                                T,
                                r_pay_override,       // numéraire A
                                sigma_X_b,
                                r_rec_override,       // B carry
                                BlackScholes::OptionType::PUT
                            );
                            if (bs_put_b) {
                                const double value_A_b = q_B * (*bs_put_b);
                                long_put = value_A_b * S_A0_b;
                            }
                        }
                    } else if (im_alice_matches_B && S_B0_b > 0.0) {
                        // Degeneracy C = B: X_B ≡ 1, X_A = A/B
                        const double X0_b = S_A0_b / S_B0_b; // A/B

                        const double var_X_b = cross_var(sigma_pay_override, sigma_rec_override, rho_AB);
                        const double sigma_X_b = (var_X_b > 0.0) ? std::sqrt(var_X_b) : 0.0;

                        if (sigma_X_b > 0.0) {
                            const double K_X_b = (q_B + m_C) / q_A;
                            auto bs_call_b = BlackScholes::Price(
                                X0_b,
                                K_X_b,
                                T,
                                r_rec_override,       // numéraire B
                                sigma_X_b,
                                r_pay_override,       // A carry
                                BlackScholes::OptionType::CALL
                            );
                            if (bs_call_b) {
                                const double value_B_b = q_A * (*bs_call_b);
                                long_put = value_B_b * S_B0_b;
                            }
                        }
                    } else if (S_C0_b > 0.0) {
                        // Generic 3-asset: C is third asset; X_A = A/C, X_B = B/C.
                        const double X_A0_b = S_A0_b / S_C0_b;
                        const double X_B0_b = S_B0_b / S_C0_b;

                        const double var_AC_b = cross_var(sigma_pay_override, sigma_im_alice, rho_AC);
                        const double var_BC_b = cross_var(sigma_rec_override, sigma_im_alice, rho_BC);
                        const double cov_AB_b = cross_cov(
                            sigma_pay_override, sigma_rec_override, sigma_im_alice,
                            rho_AB, rho_AC, rho_BC
                        );

                        double sigma_AC_b = 0.0;
                        double sigma_BC_b = 0.0;
                        double rho_AC_BC_b = 0.0;
                        if (var_AC_b > 0.0) sigma_AC_b = std::sqrt(var_AC_b);
                        if (var_BC_b > 0.0) sigma_BC_b = std::sqrt(var_BC_b);
                        if (var_AC_b > 0.0 && var_BC_b > 0.0) {
                            rho_AC_BC_b = cov_AB_b / (std::sqrt(var_AC_b * var_BC_b) + 1e-16);
                            if (rho_AC_BC_b > 1.0) rho_AC_BC_b = 1.0;
                            if (rho_AC_BC_b < -1.0) rho_AC_BC_b = -1.0;
                        }

                        if (X_A0_b > 0.0 && X_B0_b > 0.0 && sigma_AC_b > 0.0 && sigma_BC_b > 0.0) {
                            auto call_C_b = SpreadOption::Price(
                                X_A0_b, X_B0_b,
                                q_A, q_B, m_C,
                                T,
                                r_im_alice,       // discount at r_C (unchanged)
                                sigma_AC_b,
                                sigma_BC_b,
                                rho_AC_BC_b,
                                true,             // use Kirk approximation
                                r_pay_override,   // A carry (bumped)
                                r_rec_override    // B carry (bumped)
                            );
                            if (call_C_b) {
                                const double value_C_b = *call_C_b;
                                long_put = value_C_b * S_C0_b;
                            }
                        }
                    }
                }
            }

            return net_spread + short_call + long_put + result.premium_pv;
        };

        // Cache base MTM
        const double base_mtm = result.alice_mtm;

        // Spot deltas/gammas
        double mtm_up[4] = {base_mtm, base_mtm, base_mtm, base_mtm};
        for (int i = 0; i < 4; ++i) {
            const double spot_i = (i == 0) ? spot_receive_notional
                                           : (i == 1 ? spot_pay_notional
                                                     : (i == 2 ? spot_im_a_notional : spot_im_b_notional));
            if (spot_i <= 0.0) continue;
            double mult_up[4] = {1.0, 1.0, 1.0, 1.0};
            double mult_dn[4] = {1.0, 1.0, 1.0, 1.0};
            mult_up[i] += eps;
            mult_dn[i] -= eps;

            mtm_up[i] = recompute_mtm(mult_up[0], mult_up[1], mult_up[2], mult_up[3],
                                      sigma_receive, sigma_pay,
                                      r_receive, r_pay, r_report);
            const double mtm_dn = recompute_mtm(mult_dn[0], mult_dn[1], mult_dn[2], mult_dn[3],
                                                sigma_receive, sigma_pay,
                                                r_receive, r_pay, r_report);

            result.asset_greeks.delta[i] = (mtm_up[i] - mtm_dn) / (2.0 * spot_i * eps);
            result.asset_greeks.gamma[i] = (mtm_up[i] - 2.0 * base_mtm + mtm_dn)
                                          / (spot_i * spot_i * eps * eps);
        }

        // Cross gammas
        for (int i = 0; i < 4; ++i) {
            const double spot_i = (i == 0) ? spot_receive_notional
                                           : (i == 1 ? spot_pay_notional
                                                     : (i == 2 ? spot_im_a_notional : spot_im_b_notional));
            if (spot_i <= 0.0) continue;
            for (int j = i + 1; j < 4; ++j) {
                const double spot_j = (j == 0) ? spot_receive_notional
                                               : (j == 1 ? spot_pay_notional
                                                         : (j == 2 ? spot_im_a_notional : spot_im_b_notional));
                if (spot_j <= 0.0) continue;
                double mult_both[4] = {1.0, 1.0, 1.0, 1.0};
                mult_both[i] += eps;
                mult_both[j] += eps;
                const double mtm_ij = recompute_mtm(mult_both[0], mult_both[1], mult_both[2], mult_both[3],
                                                    sigma_receive, sigma_pay,
                                                    r_receive, r_pay, r_report);
                const double cross_val = (mtm_ij - mtm_up[i] - mtm_up[j] + base_mtm)
                                         / (spot_i * spot_j * eps * eps);
                result.asset_greeks.cross_gamma[i][j] = cross_val;
                result.asset_greeks.cross_gamma[j][i] = cross_val;
            }
        }

        // Vegas: bump vols for receive, pay, im_alice, im_bob
        for (int i = 0; i < 4; ++i) {
            double sigma_up_rec = sigma_receive;
            double sigma_up_pay = sigma_pay;
            double sigma_dn_rec = sigma_receive;
            double sigma_dn_pay = sigma_pay;
            double sigma_up_im_a = sigma_im_alice;
            double sigma_dn_im_a = sigma_im_alice;
            double sigma_up_im_b = sigma_im_bob;
            double sigma_dn_im_b = sigma_im_bob;

            if (i == 0) {
                sigma_up_rec += vol_bump;
                sigma_dn_rec = std::max(0.0, sigma_dn_rec - vol_bump);
            } else if (i == 1) {
                sigma_up_pay += vol_bump;
                sigma_dn_pay = std::max(0.0, sigma_dn_pay - vol_bump);
            } else if (i == 2) {
                sigma_up_im_a += vol_bump;
                sigma_dn_im_a = std::max(0.0, sigma_dn_im_a - vol_bump);
            } else {
                sigma_up_im_b += vol_bump;
                sigma_dn_im_b = std::max(0.0, sigma_dn_im_b - vol_bump);
            }

            // recompute_mtm only takes receive/pay sigma overrides; IM sigmas enter via captured sigma_im_*.
            // So adjust the captured sigmas locally when calling recompute_mtm.
            const double orig_sigma_im_a = sigma_im_alice;
            const double orig_sigma_im_b = sigma_im_bob;

            // Up bump
            const_cast<double&>(sigma_im_alice) = sigma_up_im_a;
            const_cast<double&>(sigma_im_bob) = sigma_up_im_b;
            const double mtm_up_sigma = recompute_mtm(1.0, 1.0, 1.0, 1.0,
                                                      sigma_up_rec, sigma_up_pay,
                                                      r_receive, r_pay, r_report);

            // Down bump
            const_cast<double&>(sigma_im_alice) = sigma_dn_im_a;
            const_cast<double&>(sigma_im_bob) = sigma_dn_im_b;
            const double mtm_dn_sigma = recompute_mtm(1.0, 1.0, 1.0, 1.0,
                                                      sigma_dn_rec, sigma_dn_pay,
                                                      r_receive, r_pay, r_report);

            // Restore originals
            const_cast<double&>(sigma_im_alice) = orig_sigma_im_a;
            const_cast<double&>(sigma_im_bob) = orig_sigma_im_b;

            result.asset_greeks.vega[i] = (mtm_up_sigma - mtm_dn_sigma) / (2.0 * vol_bump);
        }

        // Rate deltas: r_receive, r_pay, r_report (IM strikes treated deterministic in report currency)
        for (int i = 0; i < 5; ++i) {
            double r_up[5] = {r_receive, r_pay, r_im_alice, r_im_bob, r_report};
            double r_dn[5] = {r_receive, r_pay, r_im_alice, r_im_bob, r_report};
            r_up[i] += dr;
            r_dn[i] -= dr;
            if (i == 2 || i == 3) {
                result.asset_greeks.rate_delta[i] = 0.0;
                continue;
            }
            const double mtm_up_rate = recompute_mtm(1.0, 1.0, 1.0, 1.0,
                                                     sigma_receive, sigma_pay,
                                                     r_up[0], r_up[1], r_up[4]);
            const double mtm_dn_rate = recompute_mtm(1.0, 1.0, 1.0, 1.0,
                                                     sigma_receive, sigma_pay,
                                                     r_dn[0], r_dn[1], r_dn[4]);
            result.asset_greeks.rate_delta[i] = (mtm_up_rate - mtm_dn_rate) / (2.0 * dr);
        }
    }

    return result;
}

} // namespace pricing
} // namespace wallet
