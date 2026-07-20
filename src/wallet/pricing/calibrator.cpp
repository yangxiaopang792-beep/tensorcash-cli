// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/pricing/calibrator.h>
#include <wallet/pricing/black_scholes.h>
#include <wallet/pricing/leg_valuator.h>
#include <wallet/wallet.h>
#include <rpc/util.h>
#include <util/time.h>
#include <logging.h>
#include <cmath>
#include <algorithm>
#include <map>
#include <set>

namespace wallet {
namespace pricing {

// Helper: Create asset key for native vs custom assets
static std::string AssetKey(const uint256& asset_id, bool is_native)
{
    if (is_native) {
        return "NATIVE_BTC";
    }
    return asset_id.ToString();
}

CalibrationResult Calibrator::Calibrate(
    CWallet& wallet,
    const std::string& source,
    double max_age_hours,
    double decay_tau,
    uint64_t min_volume)
{
    int64_t current_time = GetTime();
    auto offers = FetchOffers(wallet, current_time, max_age_hours);
    return CalibrateFromOffers(wallet, offers, current_time, decay_tau, min_volume);
}

CalibrationResult Calibrator::CalibrateFromOffers(
    CWallet& wallet,
    const std::vector<ParsedOffer>& offers,
    int64_t current_time,
    double decay_tau,
    uint64_t min_volume)
{
    CalibrationResult result;
    result.offers_fetched = offers.size();

    LogPrintf("Calibrator: Starting calibration from %d offers\n", offers.size());

    if (offers.empty()) {
        result.warnings.push_back({
            WarningSeverity::WARNING,
            WarningCategory::MARKET_DATA,
            "No offers found on bulletin board"
        });
        return result;
    }

    // Filter by minimum volume (but allow offers without proof with default weight)
    std::vector<ParsedOffer> filtered_offers;
    for (const auto& offer : offers) {
        if (!offer.has_proof && min_volume > 0) {
            continue;  // Skip unproven offers only if min_volume is set
        }
        if (offer.has_proof && offer.proven_volume < min_volume) {
            continue;  // Skip proven but insufficient volume
        }

        filtered_offers.push_back(offer);

        if (offer.contract_type == "repo") result.repo_offers++;
        else if (offer.contract_type == "forward") result.forward_offers++;
        else if (offer.contract_type == "spot" || offer.offer_type == "buy" || offer.offer_type == "sell" || offer.offer_type == "swap") {
            result.spot_offers++;
        }
    }
    result.offers_parsed = filtered_offers.size();

    LogPrintf("Calibrator: Parsed %d offers (%d spot, %d repo, %d forward)\n",
        result.offers_parsed, result.spot_offers, result.repo_offers, result.forward_offers);

    auto& pricing_ctx = wallet.GetPricingContext();

    // Step 2: Calibrate spot FX rates
    result.fx_quotes_pushed = CalibrateSpotFX(
        filtered_offers, pricing_ctx, current_time, decay_tau, result.warnings
    );

    // Step 3: Bootstrap repo zero curves
    result.curves_pushed = CalibrateRepoCurves(
        filtered_offers, pricing_ctx, current_time, decay_tau, result.warnings
    );

    // Step 4: Fit volatility surfaces from forwards
    result.vol_surfaces_pushed = CalibrateVolSurfaces(
        filtered_offers, pricing_ctx, current_time, decay_tau, result.warnings
    );

    result.success = true;
    LogPrintf("Calibrator: Calibration complete. Pushed %d FX quotes, %d curves, %d vol surfaces\n",
        result.fx_quotes_pushed, result.curves_pushed, result.vol_surfaces_pushed);

    return result;
}

std::vector<ParsedOffer> Calibrator::FetchOffers(
    CWallet& wallet,
    int64_t current_time,
    double max_age_hours)
{
    std::vector<ParsedOffer> parsed_offers;

    // NOTE: This function cannot directly call cosign.list_offers RPC from wallet context
    // The RPC layer must fetch offers and pass them to Calibrator
    // For now, return empty - the RPC will populate this properly

    LogPrintf("Calibrator::FetchOffers: Stub implementation - RPC must provide offers\n");

    return parsed_offers;
}

bool Calibrator::ParseContractPayload(
    const UniValue& payload_json,
    ParsedOffer& offer)
{
    try {
        if (offer.contract_type == "repo") {
            RepoTerms terms;

            // Parse principal leg
            const UniValue& principal = payload_json["principal"];
            terms.principal_leg.is_native = principal["is_native"].get_bool();
            if (!terms.principal_leg.is_native) {
                auto asset_opt = uint256::FromHex(principal["asset"].get_str());
                if (!asset_opt) return false;
                terms.principal_leg.asset_id = *asset_opt;
            }
            terms.principal_leg.units = principal["units"].getInt<uint64_t>();

            // Parse interest leg
            const UniValue& interest = payload_json["interest"];
            terms.interest_leg.is_native = interest["is_native"].get_bool();
            if (!terms.interest_leg.is_native) {
                auto asset_opt = uint256::FromHex(interest["asset"].get_str());
                if (!asset_opt) return false;
                terms.interest_leg.asset_id = *asset_opt;
            }
            terms.interest_leg.units = interest["units"].getInt<uint64_t>();

            // Parse collateral leg
            const UniValue& collateral = payload_json["collateral"];
            terms.collateral_leg.is_native = collateral["is_native"].get_bool();
            if (!terms.collateral_leg.is_native) {
                auto asset_opt = uint256::FromHex(collateral["asset"].get_str());
                if (!asset_opt) return false;
                terms.collateral_leg.asset_id = *asset_opt;
            }
            terms.collateral_leg.units = collateral["units"].getInt<uint64_t>();

            terms.maturity_height = payload_json["maturity_height"].getInt<uint32_t>();
            terms.safety_k = payload_json["safety_k"].getInt<uint32_t>();

            offer.repo_terms = terms;
            return true;
        }

        if (offer.contract_type == "forward") {
            ForwardTerms terms;

            // Parse short party (Alice)
            const UniValue& short_party = payload_json["short_party"];
            const UniValue& alice_deliver = short_party["deliver"];
            terms.short_party.deliver_leg.is_native = alice_deliver["is_native"].get_bool();
            if (!terms.short_party.deliver_leg.is_native) {
                auto asset_opt = uint256::FromHex(alice_deliver["asset"].get_str());
                if (!asset_opt) return false;
                terms.short_party.deliver_leg.asset_id = *asset_opt;
            }
            terms.short_party.deliver_leg.units = alice_deliver["units"].getInt<uint64_t>();

            const UniValue& alice_margin = short_party["margin"];
            terms.short_party.margin_leg.is_native = alice_margin["is_native"].get_bool();
            if (!terms.short_party.margin_leg.is_native) {
                auto asset_opt = uint256::FromHex(alice_margin["asset"].get_str());
                if (!asset_opt) return false;
                terms.short_party.margin_leg.asset_id = *asset_opt;
            }
            terms.short_party.margin_leg.units = alice_margin["units"].getInt<uint64_t>();

            // Parse long party (Bob)
            const UniValue& long_party = payload_json["long_party"];
            const UniValue& bob_deliver = long_party["deliver"];
            terms.long_party.deliver_leg.is_native = bob_deliver["is_native"].get_bool();
            if (!terms.long_party.deliver_leg.is_native) {
                auto asset_opt = uint256::FromHex(bob_deliver["asset"].get_str());
                if (!asset_opt) return false;
                terms.long_party.deliver_leg.asset_id = *asset_opt;
            }
            terms.long_party.deliver_leg.units = bob_deliver["units"].getInt<uint64_t>();

            const UniValue& bob_margin = long_party["margin"];
            terms.long_party.margin_leg.is_native = bob_margin["is_native"].get_bool();
            if (!terms.long_party.margin_leg.is_native) {
                auto asset_opt = uint256::FromHex(bob_margin["asset"].get_str());
                if (!asset_opt) return false;
                terms.long_party.margin_leg.asset_id = *asset_opt;
            }
            terms.long_party.margin_leg.units = bob_margin["units"].getInt<uint64_t>();

            terms.deadline_short = payload_json["deadline_short"].getInt<uint32_t>();
            terms.safety_k = payload_json["safety_k"].getInt<uint32_t>();

            offer.forward_terms = terms;
            return true;
        }

    } catch (const std::exception& e) {
        LogPrintf("Calibrator: Failed to parse contract payload: %s\n", e.what());
    }

    return false;
}

double Calibrator::CalculateWeight(
    const ParsedOffer& offer,
    int64_t current_time,
    double decay_tau)
{
    // Time decay: w_i = volume_i * exp(-Δt_i/τ)
    double age_hours = (current_time - offer.created_at) / 3600.0;
    double time_decay = std::exp(-age_hours / decay_tau);
    double volume = offer.has_proof ? static_cast<double>(offer.proven_volume) : 1.0;  // Default weight 1.0 for unproven

    return volume * time_decay;
}

size_t Calibrator::CalibrateSpotFX(
    const std::vector<ParsedOffer>& offers,
    PricingContext& ctx,
    int64_t current_time,
    double decay_tau,
    std::vector<Warning>& warnings)
{
    // Map of asset_pair_key -> {sum_weighted_price, sum_weights, count}
    struct FXAccumulator {
        double sum_weighted_price{0.0};
        double sum_weights{0.0};
        size_t count{0};
        uint256 base_asset;
        bool base_is_native{false};
        uint256 quote_asset;
        bool quote_is_native{false};
    };

    std::map<std::string, FXAccumulator> fx_data;

    // Accumulate weighted prices
    for (const auto& offer : offers) {
        if (offer.offer_type != "buy" && offer.offer_type != "sell" && offer.offer_type != "swap") {
            continue;
        }

        if (offer.price <= 0.0 || offer.amount <= 0.0) {
            continue;
        }

        double weight = CalculateWeight(offer, current_time, decay_tau);
        if (weight < 1e-10) continue;

        // Determine base/quote and normalize price
        // Convention: price = quote_units / base_units
        // "buy" offer: maker buys asset_recv, pays asset_send -> price is asset_send/asset_recv
        // "sell" offer: maker sells asset_send, receives asset_recv -> price is asset_recv/asset_send

        uint256 base_asset, quote_asset;
        bool base_is_native, quote_is_native;
        double normalized_price;

        if (offer.offer_type == "buy") {
            // Maker buys asset_recv with asset_send
            base_asset = offer.asset_recv;
            base_is_native = offer.asset_recv_is_native;
            quote_asset = offer.asset_send;
            quote_is_native = offer.asset_send_is_native;
            normalized_price = offer.price;  // price already in quote/base
        } else {
            // Maker sells asset_send for asset_recv
            base_asset = offer.asset_send;
            base_is_native = offer.asset_send_is_native;
            quote_asset = offer.asset_recv;
            quote_is_native = offer.asset_recv_is_native;
            normalized_price = offer.price;
        }

        // Create unique key for asset pair
        std::string key = AssetKey(base_asset, base_is_native) + "/" + AssetKey(quote_asset, quote_is_native);

        auto& accum = fx_data[key];
        if (accum.count == 0) {
            accum.base_asset = base_asset;
            accum.base_is_native = base_is_native;
            accum.quote_asset = quote_asset;
            accum.quote_is_native = quote_is_native;
        }

        accum.sum_weighted_price += normalized_price * weight;
        accum.sum_weights += weight;
        accum.count++;
    }

    // Push FX quotes
    size_t pushed = 0;
    for (const auto& [pair_key, accum] : fx_data) {
        if (accum.sum_weights > 0.0 && accum.count >= 1) {
            double weighted_mid = accum.sum_weighted_price / accum.sum_weights;

            FXQuote quote(accum.base_asset, accum.quote_asset, weighted_mid, 0.0, current_time);

            if (ctx.AddFXQuote(quote)) {
                pushed++;
                LogPrintf("Calibrator: Pushed FX quote %s, rate=%.6f from %d offers\n",
                    pair_key.c_str(), weighted_mid, accum.count);
            }
        }
    }

    if (pushed == 0) {
        warnings.push_back({
            WarningSeverity::WARNING,
            WarningCategory::MARKET_DATA,
            "No spot FX quotes could be calibrated from offers"
        });
    }

    return pushed;
}

size_t Calibrator::CalibrateRepoCurves(
    const std::vector<ParsedOffer>& offers,
    PricingContext& ctx,
    int64_t current_time,
    double decay_tau,
    std::vector<Warning>& warnings)
{
    // Map of asset_key -> vector of (tenor_days, implied_rate, weight)
    struct RatePoint {
        uint32_t tenor_days;
        double implied_rate;
        double weight;
    };
    std::map<std::string, std::vector<RatePoint>> curve_data;

    // Extract implied zero rates from repo offers
    for (const auto& offer : offers) {
        if (offer.contract_type != "repo" || !offer.repo_terms) {
            continue;
        }

        const auto& terms = *offer.repo_terms;

        if (offer.tenor_days == 0) continue;

        // Calculate simple implied rate from repo structure
        // Per spec §12: account for collateral option value using flat 100% vol assumption
        double principal_amt = static_cast<double>(terms.principal_leg.units);
        double interest_amt = static_cast<double>(terms.interest_leg.units);
        double collateral_amt = static_cast<double>(terms.collateral_leg.units);

        if (principal_amt <= 0.0) continue;

        // Estimate collateral option value (borrower walkaway put)
        // Simplified: option_value ≈ intrinsic + time_value
        // Using flat 100% volatility as per spec to minimize optionality bias
        double time_to_maturity_years = offer.tenor_days / 365.0;
        double strike = principal_amt + interest_amt;  // Total amount due
        double spot = collateral_amt;  // Collateral market value (assuming 1:1 FX for now)
        double risk_free_rate = 0.05;  // Default 5% for bootstrapping
        double vol = 1.0;  // 100% vol assumption per spec

        // Black-Scholes put option value (borrower's option to walk away)
        double option_value = 0.0;
        if (time_to_maturity_years > 0.0001 && vol > 0.0) {
            auto bs_opt = BlackScholes::Price(spot, strike, time_to_maturity_years, risk_free_rate, vol, 0.0, BlackScholes::OptionType::PUT);
            if (bs_opt) {
                option_value = *bs_opt;
            }
        }

        // Adjust funding leg: effective_interest = stated_interest - option_value
        double effective_interest = std::max(0.0, interest_amt - option_value);

        // Implied zero rate: rate = (effective_interest / principal) / time_fraction
        double simple_rate = (effective_interest / principal_amt) / time_to_maturity_years;

        // Weight by volume and time decay
        double weight = CalculateWeight(offer, current_time, decay_tau);

        // Key by principal asset
        std::string asset_key = AssetKey(terms.principal_leg.asset_id, terms.principal_leg.is_native);

        curve_data[asset_key].push_back({
            offer.tenor_days,
            simple_rate,
            weight
        });
    }

    // Build curves using hierarchical bootstrap
    size_t pushed = 0;
    for (const auto& [asset_key, points] : curve_data) {
        if (points.empty()) continue;

        // Determine number of anchor tenors: ceil(log2(1 + N))
        size_t n_anchors = static_cast<size_t>(std::ceil(std::log2(1.0 + points.size())));
        n_anchors = std::max<size_t>(2, std::min<size_t>(n_anchors, 10));  // Clamp to [2,10]

        // Extract unique tenors from data
        std::set<uint32_t> data_tenors;
        for (const auto& pt : points) {
            data_tenors.insert(pt.tenor_days);
        }

        // Select anchor tenors from actual data
        std::vector<uint32_t> tenors;
        std::vector<uint32_t> sorted_tenors(data_tenors.begin(), data_tenors.end());

        if (sorted_tenors.size() <= n_anchors) {
            tenors = sorted_tenors;  // Use all available tenors
        } else {
            // Sample uniformly across tenor range
            for (size_t i = 0; i < n_anchors; ++i) {
                size_t idx = (i * sorted_tenors.size()) / n_anchors;
                tenors.push_back(sorted_tenors[idx]);
            }
        }

        // Bootstrap rates at each tenor
        std::vector<double> rates;
        for (uint32_t tenor : tenors) {
            double sum_weighted_rate = 0.0;
            double sum_weights = 0.0;

            for (const auto& pt : points) {
                // Weight by both time decay and proximity to target tenor
                double tenor_distance = std::abs(static_cast<int>(pt.tenor_days) - static_cast<int>(tenor));
                double proximity_weight = std::exp(-tenor_distance / 30.0);  // 30-day half-life
                double combined_weight = pt.weight * proximity_weight;

                sum_weighted_rate += pt.implied_rate * combined_weight;
                sum_weights += combined_weight;
            }

            if (sum_weights > 1e-10) {
                rates.push_back(sum_weighted_rate / sum_weights);
            } else {
                rates.push_back(0.05);  // Default 5% if no data
            }
        }

        // Parse asset_id from key
        bool is_native = (asset_key == "NATIVE_BTC");
        uint256 asset_id;
        if (!is_native) {
            auto asset_opt = uint256::FromHex(asset_key);
            if (!asset_opt) continue;
            asset_id = *asset_opt;
        }

        // Push curve
        DiscountCurve curve(asset_id, is_native, tenors, rates, current_time);
        if (ctx.AddCurve(curve)) {
            pushed++;
            LogPrintf("Calibrator: Pushed discount curve for %s from %d repo offers, %d tenors\n",
                asset_key.c_str(), points.size(), tenors.size());
        }
    }

    if (pushed == 0 && !curve_data.empty()) {
        warnings.push_back({
            WarningSeverity::WARNING,
            WarningCategory::MARKET_DATA,
            "No discount curves could be calibrated from repo offers"
        });
    }

    return pushed;
}

size_t Calibrator::CalibrateVolSurfaces(
    const std::vector<ParsedOffer>& offers,
    PricingContext& ctx,
    int64_t current_time,
    double decay_tau,
    std::vector<Warning>& warnings)
{
    // Basic volatility surface calibration from forward spread options
    // Map of asset_key -> vector of implied vol points

    struct VolPoint {
        double moneyness;  // Strike as % of spot
        uint32_t maturity_days;
        double implied_vol;
        double weight;
    };
    std::map<std::string, std::vector<VolPoint>> vol_data;

    for (const auto& offer : offers) {
        if (offer.contract_type != "forward" || !offer.forward_terms) {
            continue;
        }

        // TODO: Implement implied vol extraction from forward spread options
        // This requires solving for vol given spread option prices
        // For now, use a flat 50% vol assumption with proper data structure

        const auto& terms = *offer.forward_terms;

        // Use Bob's deliverable as the underlying asset
        std::string asset_key = AssetKey(terms.long_party.deliver_leg.asset_id, terms.long_party.deliver_leg.is_native);

        double weight = CalculateWeight(offer, current_time, decay_tau);

        // Simple placeholder: assume ATM, 50% vol
        vol_data[asset_key].push_back({
            1.0,  // ATM
            offer.tenor_days,
            0.50,  // 50% placeholder vol
            weight
        });
    }

    // Build vol surfaces
    size_t pushed = 0;
    for (const auto& [asset_key, points] : vol_data) {
        if (points.empty()) continue;

        // Create simple vol surface with standard grid
        std::vector<double> strikes = {0.8, 0.9, 1.0, 1.1, 1.2};  // Moneyness grid
        std::vector<uint32_t> maturities = {30, 90, 180, 365};  // Standard maturities

        // Fit vols at each grid point using weighted average
        std::vector<std::vector<double>> implied_vols;
        for (double strike : strikes) {
            std::vector<double> maturity_vols;
            for (uint32_t maturity : maturities) {
                double sum_weighted_vol = 0.0;
                double sum_weights = 0.0;

                for (const auto& pt : points) {
                    // Weight by proximity to grid point
                    double strike_dist = std::abs(pt.moneyness - strike);
                    double tenor_dist = std::abs(static_cast<int>(pt.maturity_days) - static_cast<int>(maturity));

                    double proximity = std::exp(-strike_dist / 0.2) * std::exp(-tenor_dist / 60.0);
                    double weight = pt.weight * proximity;

                    sum_weighted_vol += pt.implied_vol * weight;
                    sum_weights += weight;
                }

                if (sum_weights > 1e-10) {
                    maturity_vols.push_back(sum_weighted_vol / sum_weights);
                } else {
                    maturity_vols.push_back(0.50);  // Default 50%
                }
            }
            implied_vols.push_back(maturity_vols);
        }

        // Parse asset_id
        bool is_native = (asset_key == "NATIVE_BTC");
        uint256 asset_id;
        if (!is_native) {
            auto asset_opt = uint256::FromHex(asset_key);
            if (!asset_opt) continue;
            asset_id = *asset_opt;
        }

        // Push vol surface
        VolSurface surface(asset_id, strikes, maturities, implied_vols, current_time);
        if (ctx.AddVolSurface(surface)) {
            pushed++;
            LogPrintf("Calibrator: Pushed vol surface for %s from %d forward offers\n",
                asset_key.c_str(), points.size());
        }
    }

    if (pushed == 0 && !vol_data.empty()) {
        warnings.push_back({
            WarningSeverity::INFO,
            WarningCategory::MODEL,
            "Volatility surface calibration uses placeholder 50% vol - forward pricing not yet fully implemented"
        });
    }

    return pushed;
}

} // namespace pricing
} // namespace wallet
