// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/calibrator.h>
#include <wallet/pricing/warnings.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <kernel/cs_main.h>
#include <node/context.h>
#include <pow.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/context.h>

#include <algorithm>
#include <limits>

namespace wallet {

using namespace pricing;

// Helper: Convert Warning to JSON
static UniValue WarningToJSON(const Warning& warn)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("severity", SeverityToString(warn.severity));
    obj.pushKV("category", CategoryToString(warn.category));
    obj.pushKV("message", warn.message);
    if (warn.threshold_value) {
        obj.pushKV("threshold", *warn.threshold_value);
    }
    return obj;
}

RPCHelpMan pricing_market_push_curve()
{
    return RPCHelpMan{
        "pricing.market.push_curve",
        "Add or update a discount curve in the pricing cache\n",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID (use '0' or empty for native BTC)"},
            {"is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "True if native BTC"},
            {"tenors_days", RPCArg::Type::ARR, RPCArg::Optional::NO, "Tenor grid in days",
                {
                    {"tenor", RPCArg::Type::NUM, RPCArg::Optional::NO, "Tenor in days"},
                }
            },
            {"zero_rates", RPCArg::Type::ARR, RPCArg::Optional::NO, "Zero rates (annualized, continuous)",
                {
                    {"rate", RPCArg::Type::NUM, RPCArg::Optional::NO, "Zero rate"},
                }
            },
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Price source: 'mark' (manual) or 'market' (calibrated)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "True if curve was added successfully"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if validation failed"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.market.push_curve", "\"USDT_ID\" false \"[7,30,90,180,365]\" \"[0.05,0.055,0.06,0.065,0.07]\"")
            + HelpExampleRpc("pricing.market.push_curve", "\"USDT_ID\", false, [7,30,90,180,365], [0.05,0.055,0.06,0.065,0.07]")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const std::string asset_hex = request.params[0].get_str();
            const bool is_native = request.params.size() > 1 && request.params[1].get_bool();

            uint256 asset_id;
            if (!is_native && !asset_hex.empty() && asset_hex != "0") {
                asset_id = ParseHashV(request.params[0], "asset_id");
            }

            const UniValue& tenors_arr = request.params[2].get_array();
            const UniValue& rates_arr = request.params[3].get_array();

            if (tenors_arr.size() != rates_arr.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Tenors and rates arrays must have same length");
            }

            std::vector<uint32_t> tenors;
            std::vector<double> rates;

            for (size_t i = 0; i < tenors_arr.size(); ++i) {
                tenors.push_back(tenors_arr[i].getInt<uint32_t>());
                rates.push_back(rates_arr[i].get_real());
            }

            const std::string source_str = request.params.size() > 4 ? request.params[4].get_str() : "market";
            PriceSource source = StringToPriceSource(source_str);

            DiscountCurve curve(asset_id, is_native, tenors, rates, GetTime(), source);

            // Get pricing context (create if needed)
            auto& pricing_ctx = wallet->GetPricingContext();

            bool success = pricing_ctx.AddCurve(curve);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);

            if (!success) {
                if (auto err = curve.Validate()) {
                    result.pushKV("error", *err);
                } else {
                    result.pushKV("error", "Failed to persist curve to database");
                }
            }

            return result;
        }
    };
}

RPCHelpMan pricing_market_push_fx()
{
    return RPCHelpMan{
        "pricing.market.push_fx",
        "Add or update an FX quote in the pricing cache\n",
        {
            {"base_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Base asset ID (ignored if base_is_native=true)"},
            {"quote_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Quote asset ID (ignored if quote_is_native=true)"},
            {"spot_rate", RPCArg::Type::NUM, RPCArg::Optional::NO, "Spot rate (base/quote)"},
            {"bid_ask_bps", RPCArg::Type::NUM, RPCArg::Default{0.0}, "Bid-ask spread in basis points"},
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Price source: 'mark' (manual) or 'market' (calibrated)"},
            {"base_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "True if base is native BTC/TSC"},
            {"quote_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "True if quote is native BTC/TSC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "True if FX quote was added successfully"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if validation failed"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.market.push_fx", "\"USDT_ID\" \"TSC_ID\" 0.95 5.0")
            + HelpExampleRpc("pricing.market.push_fx", "\"USDT_ID\", \"TSC_ID\", 0.95, 5.0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const bool base_is_native = request.params.size() > 5 && request.params[5].get_bool();
            const bool quote_is_native = request.params.size() > 6 && request.params[6].get_bool();

            uint256 base_asset;
            uint256 quote_asset;

            if (!base_is_native) {
                base_asset = ParseHashV(request.params[0], "base_asset");
            }
            if (!quote_is_native) {
                quote_asset = ParseHashV(request.params[1], "quote_asset");
            }

            const double spot_rate = request.params[2].get_real();
            const double bid_ask_bps = request.params.size() > 3 ? request.params[3].get_real() : 0.0;
            const std::string source_str = request.params.size() > 4 ? request.params[4].get_str() : "market";
            PriceSource source = StringToPriceSource(source_str);

            FXQuote quote(base_asset, quote_asset, spot_rate, bid_ask_bps, GetTime(), source, base_is_native, quote_is_native);

            auto& pricing_ctx = wallet->GetPricingContext();
            bool success = pricing_ctx.AddFXQuote(quote);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);

            if (!success) {
                if (auto err = quote.Validate()) {
                    result.pushKV("error", *err);
                } else {
                    result.pushKV("error", "Failed to persist FX quote to database");
                }
            }

            return result;
        }
    };
}

RPCHelpMan pricing_market_push_vol_surface()
{
    return RPCHelpMan{
        "pricing.market.push_vol_surface",
        "Add or update a volatility surface in the pricing cache\n",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
            {"strikes_pct", RPCArg::Type::ARR, RPCArg::Optional::NO, "Strike grid in moneyness %",
                {
                    {"strike", RPCArg::Type::NUM, RPCArg::Optional::NO, "Strike moneyness (e.g., 1.0 = ATM)"},
                }
            },
            {"maturities_days", RPCArg::Type::ARR, RPCArg::Optional::NO, "Maturity grid in days",
                {
                    {"maturity", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maturity in days"},
                }
            },
            {"implied_vols", RPCArg::Type::ARR, RPCArg::Optional::NO, "Implied vol matrix [strike][maturity]",
                {
                    {"vol_row", RPCArg::Type::ARR, RPCArg::Optional::NO, "Vol row for one strike",
                        {
                            {"vol", RPCArg::Type::NUM, RPCArg::Optional::NO, "Implied vol (annualized)"},
                        }
                    },
                }
            },
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Price source: 'mark' (manual) or 'market' (calibrated)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "True if vol surface was added successfully"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if validation failed"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.market.push_vol_surface", "\"BTC_ID\" \"[0.9,1.0,1.1]\" \"[30,90,180]\" \"[[0.5,0.6,0.7],[0.4,0.5,0.6],[0.3,0.4,0.5]]\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const uint256 asset_id = ParseHashV(request.params[0], "asset_id");

            const UniValue& strikes_arr = request.params[1].get_array();
            const UniValue& maturities_arr = request.params[2].get_array();
            const UniValue& vols_arr = request.params[3].get_array();

            std::vector<double> strikes;
            std::vector<uint32_t> maturities;
            std::vector<std::vector<double>> vols;

            for (size_t i = 0; i < strikes_arr.size(); ++i) {
                strikes.push_back(strikes_arr[i].get_real());
            }

            for (size_t i = 0; i < maturities_arr.size(); ++i) {
                maturities.push_back(maturities_arr[i].getInt<uint32_t>());
            }

            for (size_t i = 0; i < vols_arr.size(); ++i) {
                const UniValue& row = vols_arr[i].get_array();
                std::vector<double> vol_row;
                for (size_t j = 0; j < row.size(); ++j) {
                    vol_row.push_back(row[j].get_real());
                }
                vols.push_back(vol_row);
            }

            const std::string source_str = request.params.size() > 4 ? request.params[4].get_str() : "market";
            PriceSource source = StringToPriceSource(source_str);

            VolSurface surface(asset_id, strikes, maturities, vols, GetTime(), source);

            auto& pricing_ctx = wallet->GetPricingContext();
            bool success = pricing_ctx.AddVolSurface(surface);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);

            if (!success) {
                if (auto err = surface.Validate()) {
                    result.pushKV("error", *err);
                } else {
                    result.pushKV("error", "Failed to persist vol surface to database");
                }
            }

            return result;
        }
    };
}

RPCHelpMan pricing_market_push_correlation()
{
    return RPCHelpMan{
        "pricing.market.push_correlation",
        "Add or update the correlation matrix in the pricing cache\n",
        {
            {"asset_ids", RPCArg::Type::ARR, RPCArg::Optional::NO, "Asset IDs in matrix order",
                {
                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
                }
            },
            {"correlation_matrix", RPCArg::Type::ARR, RPCArg::Optional::NO, "Correlation matrix (must be symmetric, PSD)",
                {
                    {"row", RPCArg::Type::ARR, RPCArg::Optional::NO, "Correlation row",
                        {
                            {"corr", RPCArg::Type::NUM, RPCArg::Optional::NO, "Correlation coefficient"},
                        }
                    },
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "True if correlation matrix was added successfully"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if validation failed"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.market.push_correlation", "\"[\\\"BTC_ID\\\",\\\"USDT_ID\\\"]\" \"[[1.0,0.3],[0.3,1.0]]\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const UniValue& ids_arr = request.params[0].get_array();
            const UniValue& corr_arr = request.params[1].get_array();

            std::vector<uint256> asset_ids;
            for (size_t i = 0; i < ids_arr.size(); ++i) {
                asset_ids.push_back(ParseHashV(ids_arr[i], "asset_id"));
            }

            std::vector<std::vector<double>> corr_matrix;
            for (size_t i = 0; i < corr_arr.size(); ++i) {
                const UniValue& row = corr_arr[i].get_array();
                std::vector<double> corr_row;
                for (size_t j = 0; j < row.size(); ++j) {
                    corr_row.push_back(row[j].get_real());
                }
                corr_matrix.push_back(corr_row);
            }

            CorrelationMatrix matrix(asset_ids, corr_matrix, GetTime());

            auto& pricing_ctx = wallet->GetPricingContext();
            bool success = pricing_ctx.AddCorrelationMatrix(matrix);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);

            if (!success) {
                if (auto err = matrix.Validate()) {
                    result.pushKV("error", *err);
                } else {
                    result.pushKV("error", "Failed to persist correlation matrix to database");
                }
            }

            return result;
        }
    };
}

RPCHelpMan pricing_market_push_difficulty_curve()
{
    return RPCHelpMan{
        "pricing.market.push_difficulty_curve",
        "Add or update the chain-global difficulty FORWARD curve (forecast difficulty at future block\n"
        "heights). Forwards are supplied as compact difficulty targets (forward nBits) per horizon and\n"
        "stored internally as E[D] in chainwork units (DIFFICULTY_DERIVATIVE.md §10.4).\n",
        {
            {"horizons_blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ascending horizon grid (blocks from now)",
                {{"horizon", RPCArg::Type::NUM, RPCArg::Optional::NO, "Horizon in blocks"}}},
            {"forward_nbits", RPCArg::Type::ARR, RPCArg::Optional::NO, "Forecast compact difficulty target at each horizon",
                {{"nbits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Compact target (uint32)"}}},
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Price source: 'mark' (manual) or 'market' (calibrated)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "success", "True if the curve was added"},
             {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if validation failed"}}},
        RPCExamples{HelpExampleCli("pricing.market.push_difficulty_curve", "\"[144,1008,4320]\" \"[486604799,486000000,485000000]\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const UniValue& horizons_arr = request.params[0].get_array();
            const UniValue& nbits_arr = request.params[1].get_array();
            if (horizons_arr.size() != nbits_arr.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "horizons_blocks and forward_nbits must have the same length");
            }
            if (horizons_arr.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "curve is empty");

            const uint256 pow_limit = Params().GetConsensus().powLimit;
            std::vector<uint32_t> horizons;
            std::vector<double> diffs;
            for (size_t i = 0; i < horizons_arr.size(); ++i) {
                horizons.push_back(horizons_arr[i].getInt<uint32_t>());
                const int64_t nb = nbits_arr[i].getInt<int64_t>();
                if (nb < 0 || nb > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "forward_nbits out of uint32 range");
                }
                const auto tgt = DeriveTarget(static_cast<uint32_t>(nb), pow_limit);
                if (!tgt) throw JSONRPCError(RPC_INVALID_PARAMETER, "forward_nbits out of range for the chain powLimit");
                const double d = DifficultyWorkFromTarget(*tgt);
                if (!(d > 0.0)) throw JSONRPCError(RPC_INVALID_PARAMETER, "forward_nbits yields non-positive difficulty");
                diffs.push_back(d);
            }

            const std::string source_str = request.params.size() > 2 ? request.params[2].get_str() : "market";
            const PriceSource source = StringToPriceSource(source_str);

            DifficultyCurve curve;
            curve.horizons_blocks = std::move(horizons);
            curve.forward_difficulties = std::move(diffs);
            curve.timestamp = GetTime();
            curve.source = source;
            curve.provenance = (source == PriceSource::MARK) ? DiffCurveProvenance::MARK : DiffCurveProvenance::MARKET;

            auto& pricing_ctx = wallet->GetPricingContext();
            const bool success = pricing_ctx.AddDifficultyCurve(curve);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            if (!success) {
                if (auto err = curve.Validate()) result.pushKV("error", *err);
                else result.pushKV("error", "Failed to persist difficulty curve to database");
            }
            return result;
        }
    };
}

RPCHelpMan pricing_market_push_difficulty_surface()
{
    return RPCHelpMan{
        "pricing.market.push_difficulty_surface",
        "Add or update the chain-global difficulty volatility term structure: the annualized lognormal\n"
        "volatility of the difficulty ratio R per horizon (blocks to fixing). DIFFICULTY_DERIVATIVE.md §10.4.\n",
        {
            {"horizons_blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ascending horizon grid (blocks to fixing)",
                {{"horizon", RPCArg::Type::NUM, RPCArg::Optional::NO, "Horizon in blocks"}}},
            {"sigmas", RPCArg::Type::ARR, RPCArg::Optional::NO, "Annualized vol of log R at each horizon",
                {{"sigma", RPCArg::Type::NUM, RPCArg::Optional::NO, "Annualized sigma (>= 0)"}}},
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Price source: 'mark' (manual) or 'market' (calibrated)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "success", "True if the surface was added"},
             {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if validation failed"}}},
        RPCExamples{HelpExampleCli("pricing.market.push_difficulty_surface", "\"[144,1008,4320]\" \"[0.6,0.5,0.45]\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const UniValue& horizons_arr = request.params[0].get_array();
            const UniValue& sigmas_arr = request.params[1].get_array();
            if (horizons_arr.size() != sigmas_arr.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "horizons_blocks and sigmas must have the same length");
            }
            if (horizons_arr.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "surface is empty");

            std::vector<uint32_t> horizons;
            std::vector<double> sigmas;
            for (size_t i = 0; i < horizons_arr.size(); ++i) {
                horizons.push_back(horizons_arr[i].getInt<uint32_t>());
                const double s = sigmas_arr[i].get_real();
                if (!(s >= 0.0)) throw JSONRPCError(RPC_INVALID_PARAMETER, "sigma must be >= 0");
                sigmas.push_back(s);
            }

            const std::string source_str = request.params.size() > 2 ? request.params[2].get_str() : "market";
            const PriceSource source = StringToPriceSource(source_str);

            DifficultyVolSurface surface;
            surface.horizons_blocks = std::move(horizons);
            surface.sigmas = std::move(sigmas);
            surface.timestamp = GetTime();
            surface.source = source;

            auto& pricing_ctx = wallet->GetPricingContext();
            const bool success = pricing_ctx.AddDifficultyVolSurface(surface);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            if (!success) {
                if (auto err = surface.Validate()) result.pushKV("error", *err);
                else result.pushKV("error", "Failed to persist difficulty vol surface to database");
            }
            return result;
        }
    };
}

namespace {
constexpr double SECS_PER_YEAR = 365.0 * 24.0 * 3600.0;

//! Sample the difficulty (chainwork) series at a fixed block stride, oldest→newest. Caller holds cs_main.
std::vector<double> SampleDifficultyWorks(const CBlockIndex* tip, const uint256& pow_limit,
                                          uint32_t stride, int periods)
{
    std::vector<double> works;
    for (int j = periods; j >= 0; --j) {
        const int64_t h = static_cast<int64_t>(tip->nHeight) - static_cast<int64_t>(j) * stride;
        if (h < 0) continue;
        const CBlockIndex* bi = tip->GetAncestor(static_cast<int>(h));
        if (!bi) continue;
        const auto t = DeriveTarget(bi->nBits, pow_limit);
        if (!t) continue;
        works.push_back(DifficultyWorkFromTarget(*t));
    }
    return works;
}

std::vector<uint32_t> DefaultDifficultyHorizons(uint32_t interval)
{
    const uint32_t base = std::max<uint32_t>(1, interval);
    std::vector<uint32_t> h;
    for (uint32_t m : {1u, 2u, 4u, 8u, 16u}) h.push_back(base * m);
    return h;
}

std::vector<uint32_t> ParseHorizonsParam(const UniValue& v)
{
    std::vector<uint32_t> h;
    for (const auto& x : v.get_array().getValues()) h.push_back(x.getInt<uint32_t>());
    std::sort(h.begin(), h.end());
    h.erase(std::unique(h.begin(), h.end()), h.end());
    return h;
}
} // namespace

RPCHelpMan pricing_market_model_difficulty_curve()
{
    return RPCHelpMan{
        "pricing.market.model_difficulty_curve",
        "Auto-populate a MODEL-provenance difficulty forward curve from chain state, so difficulty\n"
        "pricing works without manual marks. Projects E[D(H)] = D_now * exp(drift * H) in chainwork units.\n"
        "If drift_per_year is omitted it is estimated from recent retarget history (mean-consistent log\n"
        "growth of E[D]); pass 0 for an explicitly flat forward. DIFFICULTY_DERIVATIVE.md §10.4.\n",
        {
            {"drift_per_year", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Annualized continuous growth of EXPECTED difficulty; omit to estimate from chain, 0 for flat"},
            {"horizons_blocks", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Horizon grid (blocks); default = 1,2,4,8,16 retarget intervals",
                {{"horizon", RPCArg::Type::NUM, RPCArg::Optional::NO, "Horizon in blocks"}}},
            {"lookback_periods", RPCArg::Type::NUM, RPCArg::Default{26}, "Retarget periods sampled when estimating drift"},
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Storage tier: 'mark' or 'market'"},
            {"model", RPCArg::Type::STR, RPCArg::Default{"smooth"}, "Projection: 'smooth' (exp drift) or 'retarget' (flat within epoch, steps at boundaries)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "True if the curve was stored"},
            {RPCResult::Type::STR, "provenance", "Always 'model'"},
            {RPCResult::Type::NUM, "drift_per_year", "Annualized drift of E[D] applied"},
            {RPCResult::Type::BOOL, "drift_estimated", "True if drift was estimated from chain history"},
            {RPCResult::Type::NUM, "samples", "Return observations used for the drift estimate"},
            {RPCResult::Type::NUM, "current_difficulty", "Tip difficulty (chainwork-per-block units)"},
            {RPCResult::Type::ARR, "nodes", "Per-horizon forward", {{RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "horizon_blocks", "Horizon"},
                {RPCResult::Type::NUM, "forward_difficulty", "E[D] at the horizon"},
                {RPCResult::Type::NUM, "growth_vs_now", "E[D]/D_now"}}}}},
            {RPCResult::Type::STR, "error", /*optional=*/true, "Error if validation failed"},
        }, /*skip_type_check=*/true},
        RPCExamples{HelpExampleCli("pricing.market.model_difficulty_curve", "0.5")
            + HelpExampleCli("pricing.market.model_difficulty_curve", "null null 52")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            const Consensus::Params& consensus = Params().GetConsensus();
            const uint256 pow_limit = consensus.powLimit;
            const int64_t spacing = consensus.nPowTargetSpacing;
            const uint32_t interval = static_cast<uint32_t>(std::max<int64_t>(1, consensus.DifficultyAdjustmentInterval()));

            const bool drift_supplied = request.params.size() > 0 && !request.params[0].isNull();
            const int lookback = (request.params.size() > 2 && !request.params[2].isNull())
                ? request.params[2].getInt<int>() : 26;
            const std::string source_str = (request.params.size() > 3 && !request.params[3].isNull())
                ? request.params[3].get_str() : "market";
            const PriceSource source = StringToPriceSource(source_str);

            std::vector<uint32_t> horizons = (request.params.size() > 1 && !request.params[1].isNull())
                ? ParseHorizonsParam(request.params[1]) : DefaultDifficultyHorizons(interval);
            if (horizons.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "horizons_blocks is empty");

            double current_difficulty = 0.0;
            double drift_per_block = 0.0;
            int current_height = 0;
            size_t samples = 0;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = chainman.ActiveChain().Tip();
                if (!tip) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                const auto tip_t = DeriveTarget(tip->nBits, pow_limit);
                if (!tip_t) throw JSONRPCError(RPC_INTERNAL_ERROR, "Tip nBits out of range for powLimit");
                current_difficulty = DifficultyWorkFromTarget(*tip_t);
                current_height = tip->nHeight;

                if (drift_supplied) {
                    drift_per_block = request.params[0].get_real() * static_cast<double>(spacing) / SECS_PER_YEAR;
                } else {
                    const auto works = SampleDifficultyWorks(tip, pow_limit, interval, std::max(2, lookback));
                    const auto stats = EstimateDifficultyHistoryStats(works, interval, spacing);
                    drift_per_block = stats.mean_drift_per_block;
                    samples = stats.samples;
                }
            }

            const std::string model_mode = (request.params.size() > 4 && !request.params[4].isNull())
                ? request.params[4].get_str() : "smooth";
            if (model_mode != "smooth" && model_mode != "retarget") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "model must be 'smooth' or 'retarget'");
            }

            DifficultyCurve curve;
            if (model_mode == "retarget") {
                const uint32_t max_h = *std::max_element(horizons.begin(), horizons.end());
                curve = BuildRetargetAwareDifficultyCurve(current_difficulty, drift_per_block, interval,
                    static_cast<uint32_t>(current_height) % interval, max_h, GetTime());
            } else {
                curve = BuildModelDifficultyCurve(current_difficulty, drift_per_block, horizons, GetTime());
            }
            curve.source = source;

            auto& pricing_ctx = wallet->GetPricingContext();
            const bool success = pricing_ctx.AddDifficultyCurve(curve);

            UniValue nodes(UniValue::VARR);
            for (size_t i = 0; i < curve.horizons_blocks.size(); ++i) {
                UniValue n(UniValue::VOBJ);
                n.pushKV("horizon_blocks", static_cast<uint64_t>(curve.horizons_blocks[i]));
                n.pushKV("forward_difficulty", curve.forward_difficulties[i]);
                n.pushKV("growth_vs_now", current_difficulty > 0.0 ? curve.forward_difficulties[i] / current_difficulty : 0.0);
                nodes.push_back(n);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            result.pushKV("provenance", "model");
            result.pushKV("model", model_mode);
            result.pushKV("drift_per_year", drift_per_block * SECS_PER_YEAR / static_cast<double>(spacing));
            result.pushKV("drift_estimated", !drift_supplied);
            result.pushKV("samples", static_cast<uint64_t>(samples));
            result.pushKV("current_difficulty", current_difficulty);
            result.pushKV("nodes", nodes);
            if (!success) {
                if (auto err = curve.Validate()) result.pushKV("error", *err);
                else result.pushKV("error", "Failed to persist difficulty curve to database");
            } else if (!drift_supplied && samples < 2) {
                result.pushKV("error", "Insufficient retarget history; drift defaulted to ~flat");
            }
            return result;
        }
    };
}

RPCHelpMan pricing_market_calibrate_difficulty_vol()
{
    return RPCHelpMan{
        "pricing.market.calibrate_difficulty_vol",
        "Estimate the difficulty volatility from realized log-difficulty changes sampled at retarget\n"
        "boundaries (where difficulty actually moves) and store a flat difficulty vol surface. The vol of\n"
        "log difficulty equals the vol of the ratio R. DIFFICULTY_DERIVATIVE.md §10.4.\n",
        {
            {"lookback_periods", RPCArg::Type::NUM, RPCArg::Default{52}, "Retarget periods to sample"},
            {"stride_blocks", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Sampling stride; default = retarget interval"},
            {"horizons_blocks", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Horizon grid (blocks); default = 1,2,4,8,16 intervals",
                {{"horizon", RPCArg::Type::NUM, RPCArg::Optional::NO, "Horizon in blocks"}}},
            {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Storage tier: 'mark' or 'market'"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "True if the surface was stored"},
            {RPCResult::Type::NUM, "sigma_annual", "Estimated annualized vol of log difficulty"},
            {RPCResult::Type::NUM, "samples", "Return observations used"},
            {RPCResult::Type::NUM, "stride_blocks", "Sampling stride used"},
            {RPCResult::Type::STR, "error", /*optional=*/true, "Error if validation failed or insufficient history"},
        }, /*skip_type_check=*/true},
        RPCExamples{HelpExampleCli("pricing.market.calibrate_difficulty_vol", "52")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            const Consensus::Params& consensus = Params().GetConsensus();
            const uint256 pow_limit = consensus.powLimit;
            const int64_t spacing = consensus.nPowTargetSpacing;
            const uint32_t interval = static_cast<uint32_t>(std::max<int64_t>(1, consensus.DifficultyAdjustmentInterval()));

            const int lookback = (request.params.size() > 0 && !request.params[0].isNull())
                ? request.params[0].getInt<int>() : 52;
            const uint32_t stride = (request.params.size() > 1 && !request.params[1].isNull())
                ? static_cast<uint32_t>(std::max<int64_t>(1, request.params[1].getInt<int64_t>())) : interval;
            const std::string source_str = (request.params.size() > 3 && !request.params[3].isNull())
                ? request.params[3].get_str() : "market";
            const PriceSource source = StringToPriceSource(source_str);
            std::vector<uint32_t> horizons = (request.params.size() > 2 && !request.params[2].isNull())
                ? ParseHorizonsParam(request.params[2]) : DefaultDifficultyHorizons(interval);
            if (horizons.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "horizons_blocks is empty");

            DifficultyHistoryStats stats;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = chainman.ActiveChain().Tip();
                if (!tip) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                const auto works = SampleDifficultyWorks(tip, pow_limit, stride, std::max(2, lookback));
                stats = EstimateDifficultyHistoryStats(works, stride, spacing);
            }

            DifficultyVolSurface surface = BuildFlatDifficultyVolSurface(stats.sigma_annual, horizons, GetTime());
            surface.source = source;

            auto& pricing_ctx = wallet->GetPricingContext();
            const bool success = pricing_ctx.AddDifficultyVolSurface(surface);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            result.pushKV("sigma_annual", stats.sigma_annual);
            result.pushKV("samples", static_cast<uint64_t>(stats.samples));
            result.pushKV("stride_blocks", static_cast<uint64_t>(stride));
            if (!success) {
                if (auto err = surface.Validate()) result.pushKV("error", *err);
                else result.pushKV("error", "Failed to persist difficulty vol surface to database");
            } else if (stats.samples < 2) {
                result.pushKV("error", "Insufficient retarget history; sigma defaulted to 0 (no time value)");
            }
            return result;
        }
    };
}

RPCHelpMan pricing_market_status()
{
    return RPCHelpMan{
        "pricing.market.status",
        "Get market data coverage and staleness summary\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "num_curves", "Number of discount curves"},
                {RPCResult::Type::NUM, "num_fx_quotes", "Number of FX quotes"},
                {RPCResult::Type::NUM, "num_vol_surfaces", "Number of vol surfaces"},
                {RPCResult::Type::NUM, "num_correlation_matrices", "Number of correlation matrices"},
                {RPCResult::Type::NUM, "oldest_curve_age_hours", "Age of oldest curve in hours"},
                {RPCResult::Type::NUM, "oldest_fx_age_hours", "Age of oldest FX quote in hours"},
                {RPCResult::Type::NUM, "oldest_vol_age_hours", "Age of oldest vol surface in hours"},
                {RPCResult::Type::NUM, "oldest_corr_age_hours", "Age of oldest correlation matrix in hours"},
                {RPCResult::Type::ARR, "warnings", "Aggregated warnings",
                    {
                        {RPCResult::Type::OBJ, "", "Warning",
                            {
                                {RPCResult::Type::STR, "severity", "info|warning|critical"},
                                {RPCResult::Type::STR, "category", "coverage|deadline|market_data|model|im|fx|interpolation"},
                                {RPCResult::Type::STR, "message", "Warning message"},
                                {RPCResult::Type::NUM, "threshold", /*optional=*/true, "Threshold value if applicable"},
                            }
                        },
                    }
                },
                {RPCResult::Type::OBJ, "difficulty", /*optional=*/false, "Difficulty forward-curve / vol-surface coverage, per source tier "
                    "(mark, market): present, provenance, node count, age, staleness, and the resulting pricing fallback state", {}},
            }, /*skip_type_check=*/true  // difficulty block has conditional (present-dependent) fields
        },
        RPCExamples{
            HelpExampleCli("pricing.market.status", "")
            + HelpExampleRpc("pricing.market.status", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            auto& pricing_ctx = wallet->GetPricingContext();
            const int64_t current_time = GetTime();

            MarketDataCoverage coverage = pricing_ctx.GetCoverageSummary(current_time);

            UniValue result(UniValue::VOBJ);
            result.pushKV("num_curves", static_cast<uint64_t>(coverage.num_curves));
            result.pushKV("num_fx_quotes", static_cast<uint64_t>(coverage.num_fx_quotes));
            result.pushKV("num_vol_surfaces", static_cast<uint64_t>(coverage.num_vol_surfaces));
            result.pushKV("num_correlation_matrices", static_cast<uint64_t>(coverage.num_correlation_matrices));

            result.pushKV("oldest_curve_age_hours", coverage.oldest_curve_age_sec / 3600.0);
            result.pushKV("oldest_fx_age_hours", coverage.oldest_fx_age_sec / 3600.0);
            result.pushKV("oldest_vol_age_hours", coverage.oldest_vol_age_sec / 3600.0);
            result.pushKV("oldest_corr_age_hours", coverage.oldest_corr_age_sec / 3600.0);

            UniValue warnings_arr(UniValue::VARR);
            for (const auto& warn : coverage.warnings) {
                warnings_arr.push_back(WarningToJSON(warn));
            }
            result.pushKV("warnings", warnings_arr);

            // Difficulty forward-curve / vol-surface coverage per source tier.
            auto describe_difficulty = [&](PriceSource src) {
                UniValue o(UniValue::VOBJ);
                const auto curve = pricing_ctx.GetDifficultyCurve(src);
                const auto vol = pricing_ctx.GetDifficultyVolSurface(src);
                o.pushKV("curve_present", static_cast<bool>(curve));
                if (curve) {
                    o.pushKV("curve_provenance", DiffCurveProvenanceToString(curve->provenance));
                    o.pushKV("curve_nodes", static_cast<uint64_t>(curve->horizons_blocks.size()));
                    o.pushKV("curve_age_hours", curve->timestamp > 0 ? (current_time - curve->timestamp) / 3600.0 : 0.0);
                    o.pushKV("curve_stale", curve->CheckStaleness(current_time).has_value());
                }
                o.pushKV("vol_present", static_cast<bool>(vol));
                if (vol) {
                    o.pushKV("vol_nodes", static_cast<uint64_t>(vol->horizons_blocks.size()));
                    o.pushKV("vol_age_hours", vol->timestamp > 0 ? (current_time - vol->timestamp) / 3600.0 : 0.0);
                    o.pushKV("vol_stale", vol->CheckStaleness(current_time).has_value());
                }
                // The fallback the difficulty pricer would take at this tier.
                o.pushKV("pricing_state", !curve ? "flat forecast (no curve)"
                                          : (!vol ? "deterministic, sigma=0 (no vol surface)"
                                                  : "stochastic"));
                return o;
            };
            UniValue diff_obj(UniValue::VOBJ);
            diff_obj.pushKV("mark", describe_difficulty(PriceSource::MARK));
            diff_obj.pushKV("market", describe_difficulty(PriceSource::MARKET));
            result.pushKV("difficulty", diff_obj);

            return result;
        }
    };
}

RPCHelpMan pricing_market_calibrate()
{
    return RPCHelpMan{
        "pricing.market.calibrate",
        "Calibrate market data (FX, curves, vol surfaces) from bulletin board offers\n"
        "Implements volume-weighted averaging with time decay as specified in PRICING&VALUATION.md §12\n",
        {
            {"source", RPCArg::Type::STR, RPCArg::Default{"nostr"}, "Data source: 'nostr' (bulletin board)"},
            {"max_age_hours", RPCArg::Type::NUM, RPCArg::Default{24.0}, "Maximum age of offers to include (hours)"},
            {"decay_tau", RPCArg::Type::NUM, RPCArg::Default{6.0}, "Time decay constant (hours)"},
            {"min_volume", RPCArg::Type::NUM, RPCArg::Default{0}, "Minimum volume threshold to include offer"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether calibration succeeded"},
                {RPCResult::Type::NUM, "offers_fetched", "Total offers fetched from source"},
                {RPCResult::Type::NUM, "offers_parsed", "Offers successfully parsed and included"},
                {RPCResult::Type::NUM, "spot_offers", "Number of spot offers processed"},
                {RPCResult::Type::NUM, "repo_offers", "Number of repo offers processed"},
                {RPCResult::Type::NUM, "forward_offers", "Number of forward offers processed"},
                {RPCResult::Type::NUM, "fx_quotes_pushed", "FX quotes added to pricing context"},
                {RPCResult::Type::NUM, "curves_pushed", "Discount curves added to pricing context"},
                {RPCResult::Type::NUM, "vol_surfaces_pushed", "Vol surfaces added to pricing context"},
                {RPCResult::Type::ARR, "warnings", "Calibration warnings",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "severity", "info|warning|critical"},
                                {RPCResult::Type::STR, "category", "coverage|deadline|market_data|model|im|fx|interpolation"},
                                {RPCResult::Type::STR, "message", "Warning message"},
                            }
                        }
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.market.calibrate", "\"nostr\"")
            + HelpExampleCli("pricing.market.calibrate", "\"nostr\" 12 3 10000")
            + HelpExampleRpc("pricing.market.calibrate", "\"nostr\", 24, 6, 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            // Parse parameters
            // std::string source = request.params.size() > 0 ? request.params[0].get_str() : "nostr";  // TODO: use for source selection
            // double max_age_hours = request.params.size() > 1 ? request.params[1].get_real() : 24.0;  // TODO: use for filtering
            double decay_tau = request.params.size() > 2 ? request.params[2].get_real() : 6.0;
            uint64_t min_volume = request.params.size() > 3 ? request.params[3].getInt<uint64_t>() : 0;

            int64_t current_time = GetTime();

            // TODO: Fetch offers from bulletin board based on source and max_age_hours
            // For now, this is a stub that returns no calibration
            // The RPC needs to call cosign.list_offers, parse responses into ParsedOffer,
            // and pass them to Calibrator::CalibrateFromOffers
            std::vector<ParsedOffer> offers;

            // Run calibration with fetched offers
            CalibrationResult result = Calibrator::CalibrateFromOffers(
                *wallet,
                offers,
                current_time,
                decay_tau,
                min_volume
            );

            // Build response
            UniValue response(UniValue::VOBJ);
            response.pushKV("success", result.success);
            response.pushKV("offers_fetched", static_cast<uint64_t>(result.offers_fetched));
            response.pushKV("offers_parsed", static_cast<uint64_t>(result.offers_parsed));
            response.pushKV("spot_offers", static_cast<uint64_t>(result.spot_offers));
            response.pushKV("repo_offers", static_cast<uint64_t>(result.repo_offers));
            response.pushKV("forward_offers", static_cast<uint64_t>(result.forward_offers));
            response.pushKV("fx_quotes_pushed", static_cast<uint64_t>(result.fx_quotes_pushed));
            response.pushKV("curves_pushed", static_cast<uint64_t>(result.curves_pushed));
            response.pushKV("vol_surfaces_pushed", static_cast<uint64_t>(result.vol_surfaces_pushed));

            UniValue warnings_arr(UniValue::VARR);
            for (const auto& warn : result.warnings) {
                warnings_arr.push_back(WarningToJSON(warn));
            }
            response.pushKV("warnings", warnings_arr);

            return response;
        }
    };
}

} // namespace wallet
