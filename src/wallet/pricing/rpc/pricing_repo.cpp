// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/contract.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/repo_pricer.h>
#include <wallet/pricing/warnings.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>

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

// Helper: Convert Greeks to JSON
static UniValue GreeksToJSON(const Greeks& greeks)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("delta", greeks.delta);
    obj.pushKV("gamma", greeks.gamma);
    obj.pushKV("vega", greeks.vega);
    obj.pushKV("theta", greeks.theta);
    obj.pushKV("rho", greeks.rho);
    return obj;
}

RPCHelpMan pricing_repo_quote()
{
    return RPCHelpMan{
        "pricing.repo.quote",
        "Compute mark-to-market valuation for a repo contract\n"
        "Supports both registry-backed contracts (via registry_id) and inline term specification.\n",
        {
            {"source_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Contract source: 'registry' or 'inline'"},
            {"registry_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Registry contract ID (required if source_type='registry')"},
            {"inline_terms", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline repo terms (required if source_type='inline')",
                {
                    {"principal_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Principal asset ID"},
                    {"principal_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Principal is native BTC"},
                    {"principal_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Principal amount"},
                    {"interest_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Interest asset ID"},
                    {"interest_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Interest is native BTC"},
                    {"interest_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Interest amount"},
                    {"collateral_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Collateral asset ID"},
                    {"collateral_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Collateral is native BTC"},
                    {"collateral_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Collateral amount"},
                    {"maturity_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maturity block height"},
                    {"safety_k", RPCArg::Type::NUM, RPCArg::Default{144}, "Safety window (blocks before maturity)"},
                }
            },
            {"report_asset", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Reporting currency (empty for TSC)"},
            {"report_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Reporting currency is native BTC"},
            {"compute_greeks", RPCArg::Type::BOOL, RPCArg::Default{true}, "Compute option Greeks"},
            {"source", RPCArg::Type::STR, RPCArg::Default{"mark"}, "Price source: 'mark' (manual) or 'market' (calibrated)"},
            {"include_inception_cashflows", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include principal cashflow at t=0 in MTM (for pre-execution views)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "principal_pv", "Present value of principal leg (in reporting currency)"},
                {RPCResult::Type::NUM, "interest_pv", "Present value of interest leg"},
                {RPCResult::Type::NUM, "collateral_pv", "Present value of collateral leg"},
                {RPCResult::Type::NUM, "collateral_option", "Value of borrower walkaway (put) option"},
                {RPCResult::Type::NUM, "lender_mtm", "Lender mark-to-market (principal + interest - option)"},
                {RPCResult::Type::NUM, "borrower_mtm", "Borrower mark-to-market (-lender_mtm)"},
                {RPCResult::Type::NUM, "coverage_ratio", "Collateral coverage ratio (collateral / (principal + interest))"},
                {RPCResult::Type::NUM, "ltv_pct", "Loan-to-value percentage (100 / coverage_ratio)"},
                {RPCResult::Type::NUM, "over_collat_pct", "Over-collateralization percentage ((coverage_ratio - 1) * 100)"},
                {RPCResult::Type::OBJ, "collateral_greeks", /*optional=*/true, "Option Greeks",
                    {
                        {RPCResult::Type::NUM, "delta", "Delta (∂V/∂S)"},
                        {RPCResult::Type::NUM, "gamma", "Gamma (∂²V/∂S²)"},
                        {RPCResult::Type::NUM, "vega", "Vega (∂V/∂σ)"},
                        {RPCResult::Type::NUM, "theta", "Theta (-∂V/∂t)"},
                        {RPCResult::Type::NUM, "rho", "Rho (∂V/∂r)"},
                    }
                },
                {RPCResult::Type::ARR, "warnings", "Diagnostic warnings",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "severity", "WARNING, CRITICAL, INFO"},
                                {RPCResult::Type::STR, "category", "coverage, deadline, market_data, model"},
                                {RPCResult::Type::STR, "message", "Human-readable message"},
                                {RPCResult::Type::NUM, "threshold", /*optional=*/true, "Threshold value if applicable"},
                            }
                        }
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.repo.quote", "\"registry\" \"CONTRACT_ID\"")
            + HelpExampleCli("pricing.repo.quote", "\"inline\" \"\" '{\"principal_asset\":\"BTC\", \"principal_is_native\":true, ...}'")
            + HelpExampleRpc("pricing.repo.quote", "\"registry\", \"CONTRACT_ID\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const std::string source_type = request.params[0].get_str();

            // Parse reporting currency
            uint256 report_asset;
            bool report_is_native = true; // Default: native TSC unless explicitly overridden
            if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty()) {
                report_asset = ParseHashV(request.params[3], "report_asset");
                report_is_native = request.params.size() > 4 && request.params[4].get_bool();
            }

            bool compute_greeks = request.params.size() <= 5 || request.params[5].get_bool();
            bool include_inception_cashflows = request.params.size() > 7 ? request.params[7].get_bool() : false;

            // Parse price source
            std::string source_str = request.params.size() > 6 ? request.params[6].get_str() : "mark";
            PriceSource price_source = StringToPriceSource(source_str);

            // Get pricing context
            auto& pricing_ctx = wallet->GetPricingContext();
            int64_t current_time = GetTime();

            RepoTerms terms;
            uint32_t maturity_days = 0;

            if (source_type == "registry") {
                // Load from registry
                if (request.params.size() < 2) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "registry_id required for source_type='registry'");
                }
                uint256 registry_id = ParseHashV(request.params[1], "registry_id");

                // Load repo offer from registry
                LOCK(wallet->cs_wallet);
                auto repo_offer = wallet->FindRepoOffer(registry_id);
                if (!repo_offer) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Repo contract not found in registry");
                }
                terms = repo_offer->terms;

                // Normalize units to 8 decimals (consistent with inline source which uses 8-decimal encoding)
                // Registry stores raw atomic units; pricer expects 8-decimal normalized units.
                // Formula: normalized = raw_units * 10^(8 - asset_decimals)
                auto normalize_leg = [&](wallet::AssetLeg& leg) {
                    int decimals = pricing_ctx.GetAssetDecimals(leg.asset_id, leg.is_native);
                    if (decimals < 0) decimals = 8; // Fallback to 8 if unknown
                    if (decimals != 8) {
                        double scale = std::pow(10.0, 8 - decimals);
                        leg.units = static_cast<uint64_t>(std::round(static_cast<double>(leg.units) * scale));
                    }
                };
                normalize_leg(terms.principal_leg);
                normalize_leg(terms.interest_leg);
                normalize_leg(terms.collateral_leg);

                // Compute maturity in days from current chain height
                int current_height = WITH_LOCK(wallet->cs_wallet, return wallet->GetLastBlockHeight());
                int blocks_to_maturity = std::max(0, static_cast<int>(terms.maturity_height) - current_height);
                maturity_days = (blocks_to_maturity * 10) / (60 * 24); // 10 min blocks -> days

            } else if (source_type == "inline") {
                // Parse inline terms
                if (request.params.size() < 3) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "inline_terms required for source_type='inline'");
                }
                const UniValue& terms_obj = request.params[2].get_obj();

                // Parse principal leg
                uint256 principal_asset;
                bool principal_is_native = terms_obj.find_value("principal_is_native").get_bool();
                if (!principal_is_native) {
                    principal_asset = ParseHashV(terms_obj.find_value("principal_asset"), "principal_asset");
                }
                uint64_t principal_units = static_cast<uint64_t>(terms_obj.find_value("principal_units").getInt<int64_t>());
                terms.principal_leg = {principal_asset, principal_is_native, principal_units, {}};

                // Parse interest leg
                uint256 interest_asset;
                bool interest_is_native = terms_obj.find_value("interest_is_native").get_bool();
                if (!interest_is_native) {
                    interest_asset = ParseHashV(terms_obj.find_value("interest_asset"), "interest_asset");
                }
                uint64_t interest_units = static_cast<uint64_t>(terms_obj.find_value("interest_units").getInt<int64_t>());
                terms.interest_leg = {interest_asset, interest_is_native, interest_units, {}};

                // Parse collateral leg
                uint256 collateral_asset;
                bool collateral_is_native = terms_obj.find_value("collateral_is_native").get_bool();
                if (!collateral_is_native) {
                    collateral_asset = ParseHashV(terms_obj.find_value("collateral_asset"), "collateral_asset");
                }
                uint64_t collateral_units = static_cast<uint64_t>(terms_obj.find_value("collateral_units").getInt<int64_t>());
                terms.collateral_leg = {collateral_asset, collateral_is_native, collateral_units, {}};

                terms.maturity_height = static_cast<uint32_t>(terms_obj.find_value("maturity_height").getInt<int64_t>());
                terms.safety_k = static_cast<uint32_t>(terms_obj.find_value("safety_k").getInt<int64_t>());

                // Compute maturity in days
                int current_height = WITH_LOCK(wallet->cs_wallet, return wallet->GetLastBlockHeight());
                int blocks_to_maturity = std::max(0, static_cast<int>(terms.maturity_height) - current_height);
                maturity_days = (blocks_to_maturity * 10) / (60 * 24);

            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "source_type must be 'registry' or 'inline'");
            }

            // Price the repo contract
            auto valuation = RepoPricer::Price(
                terms.principal_leg,
                terms.interest_leg,
                terms.collateral_leg,
                maturity_days,
                terms.safety_k,
                pricing_ctx,
                report_asset,
                report_is_native,
                current_time,
                compute_greeks,
                price_source,
                include_inception_cashflows
            );

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("principal_pv", valuation.principal_pv);
            result.pushKV("interest_pv", valuation.interest_pv);
            result.pushKV("collateral_pv", valuation.collateral_pv);
            result.pushKV("collateral_option", valuation.collateral_option);
            result.pushKV("lender_mtm", valuation.lender_mtm);
            result.pushKV("borrower_mtm", valuation.borrower_mtm);
            result.pushKV("coverage_ratio", valuation.coverage_ratio);
            result.pushKV("ltv_pct", valuation.ltv_pct);
            result.pushKV("over_collat_pct", valuation.over_collat_pct);

            if (compute_greeks) {
                result.pushKV("collateral_greeks", GreeksToJSON(valuation.collateral_greeks));

                // Add per-asset Greeks for portfolio risk aggregation
                UniValue assetGreeks(UniValue::VOBJ);

                // Delta array (principal, interest, collateral)
                UniValue deltas(UniValue::VARR);
                for (int i = 0; i < 3; ++i) {
                    deltas.push_back(valuation.asset_greeks.delta[i]);
                }
                assetGreeks.pushKV("delta", deltas);

                // Vega array
                UniValue vegas(UniValue::VARR);
                for (int i = 0; i < 3; ++i) {
                    vegas.push_back(valuation.asset_greeks.vega[i]);
                }
                assetGreeks.pushKV("vega", vegas);

                // Gamma array
                UniValue gammas(UniValue::VARR);
                for (int i = 0; i < 3; ++i) {
                    gammas.push_back(valuation.asset_greeks.gamma[i]);
                }
                assetGreeks.pushKV("gamma", gammas);

                // Cross-gamma matrix
                UniValue crossGamma(UniValue::VARR);
                for (int i = 0; i < 3; ++i) {
                    UniValue row(UniValue::VARR);
                    for (int j = 0; j < 3; ++j) {
                        row.push_back(valuation.asset_greeks.cross_gamma[i][j]);
                    }
                    crossGamma.push_back(row);
                }
                assetGreeks.pushKV("cross_gamma", crossGamma);

                // Rate deltas (principal, interest, collateral, report)
                UniValue rateDeltas(UniValue::VARR);
                for (int i = 0; i < 4; ++i) {
                    rateDeltas.push_back(valuation.asset_greeks.rate_delta[i]);
                }
                assetGreeks.pushKV("rate_delta", rateDeltas);

                result.pushKV("asset_greeks", assetGreeks);
            }

            UniValue warnings_arr(UniValue::VARR);
            for (const auto& warn : valuation.warnings) {
                warnings_arr.push_back(WarningToJSON(warn));
            }
            result.pushKV("warnings", warnings_arr);

            return result;
        },
    };
}

} // namespace wallet
