// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/contract.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/forward_pricer.h>
#include <wallet/pricing/spread_option.h>
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
// Currently unused but kept for potential future use
/*
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
*/

// Helper: Convert SpreadGreeks to JSON
static UniValue SpreadGreeksToJSON(const SpreadOption::SpreadGreeks& greeks)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("delta_A", greeks.delta_A);
    obj.pushKV("delta_B", greeks.delta_B);
    obj.pushKV("gamma_A", greeks.gamma_A);
    obj.pushKV("gamma_B", greeks.gamma_B);
    obj.pushKV("vega_A", greeks.vega_A);
    obj.pushKV("vega_B", greeks.vega_B);
    obj.pushKV("theta", greeks.theta);
    obj.pushKV("rho_rate", greeks.rho_rate);
    return obj;
}

RPCHelpMan pricing_forward_quote()
{
    return RPCHelpMan{
        "pricing.forward.quote",
        "Compute mark-to-market valuation for a forward (IM-capped DvP) contract\n"
        "Supports both registry-backed contracts and inline term specification.\n",
        {
            {"source_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Contract source: 'registry' or 'inline'"},
            {"registry_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Registry contract ID"},
            {"inline_terms", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline forward terms",
                {
                    {"alice_deliver_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Alice delivery asset (omit if is_native)"},
                    {"alice_deliver_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Alice delivers native BTC"},
                    {"alice_deliver_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Alice delivery units"},
                    {"alice_im_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Alice IM asset (omit if is_native)"},
                    {"alice_im_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Alice IM is native BTC"},
                    {"alice_im_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Alice IM units"},
                    {"bob_deliver_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Bob delivery asset (omit if is_native)"},
                    {"bob_deliver_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Bob delivers native BTC"},
                    {"bob_deliver_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Bob delivery units"},
                    {"bob_im_asset", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Bob IM asset (omit if is_native)"},
                    {"bob_im_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Bob IM is native BTC"},
                    {"bob_im_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Bob IM units"},
                    {"premium_asset", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Premium asset (omit if is_native)"},
                    {"premium_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Premium is native BTC"},
                    {"premium_units", RPCArg::Type::NUM, RPCArg::Default{0}, "Premium units"},
                    {"deadline_short", RPCArg::Type::NUM, RPCArg::Optional::NO, "Bob's deadline (block height)"},
                    {"safety_k", RPCArg::Type::NUM, RPCArg::Default{144}, "Safety window blocks"},
                }
            },
            {"report_asset", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Reporting currency"},
            {"report_is_native", RPCArg::Type::BOOL, RPCArg::Default{false}, "Reporting currency is native BTC"},
            {"compute_greeks", RPCArg::Type::BOOL, RPCArg::Default{true}, "Compute spread option Greeks"},
            {"price_source", RPCArg::Type::STR, RPCArg::Default{"mark"}, "Price source: 'mark' or 'market'"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "pv_receive", "PV of Alice's receipt (Bob delivers to Alice)"},
                {RPCResult::Type::NUM, "pv_pay", "PV of Alice's payment (Alice delivers to Bob)"},
                {RPCResult::Type::NUM, "net_spread_value", "pv_receive - pv_pay"},
                {RPCResult::Type::NUM, "premium_pv", "Premium PV (paid at t=0)"},
                {RPCResult::Type::NUM, "alice_short_call_value", "Alice's short call on Bob's IM"},
                {RPCResult::Type::NUM, "alice_long_put_value", "Alice's long put on her own IM"},
                {RPCResult::Type::NUM, "alice_mtm", "Alice's total mark-to-market"},
                {RPCResult::Type::NUM, "bob_mtm", "Bob's mark-to-market (-alice_mtm)"},
                {RPCResult::Type::NUM, "im_coverage_alice", "IM coverage ratio for Alice"},
                {RPCResult::Type::NUM, "im_coverage_bob", "IM coverage ratio for Bob"},
                {RPCResult::Type::NUM, "spot_A0", "Spot of pay_leg asset (A) in report currency"},
                {RPCResult::Type::NUM, "spot_B0", "Spot of receive_leg asset (B) in report currency"},
                {RPCResult::Type::NUM, "spot_C0", "Spot of Alice IM asset (C) in report currency"},
                {RPCResult::Type::NUM, "spot_D0", "Spot of Bob IM asset (D) in report currency"},
                {RPCResult::Type::BOOL, "model_unreliable", "True if walkaway options could not be priced reliably"},
                {RPCResult::Type::OBJ, "spread_greeks_call", /*optional=*/true, "Greeks for short call component",
                    {
                        {RPCResult::Type::NUM, "delta_A", "Delta w.r.t. asset A"},
                        {RPCResult::Type::NUM, "delta_B", "Delta w.r.t. asset B"},
                        {RPCResult::Type::NUM, "gamma_A", "Gamma w.r.t. asset A"},
                        {RPCResult::Type::NUM, "gamma_B", "Gamma w.r.t. asset B"},
                        {RPCResult::Type::NUM, "vega_A", "Vega w.r.t. vol of A"},
                        {RPCResult::Type::NUM, "vega_B", "Vega w.r.t. vol of B"},
                        {RPCResult::Type::NUM, "theta", "Time decay"},
                        {RPCResult::Type::NUM, "rho_rate", "Interest rate sensitivity"},
                    }
                },
                {RPCResult::Type::OBJ, "spread_greeks_put", /*optional=*/true, "Greeks for long put component",
                    {
                        {RPCResult::Type::NUM, "delta_A", "Delta w.r.t. asset A"},
                        {RPCResult::Type::NUM, "delta_B", "Delta w.r.t. asset B"},
                        {RPCResult::Type::NUM, "gamma_A", "Gamma w.r.t. asset A"},
                        {RPCResult::Type::NUM, "gamma_B", "Gamma w.r.t. asset B"},
                        {RPCResult::Type::NUM, "vega_A", "Vega w.r.t. vol of A"},
                        {RPCResult::Type::NUM, "vega_B", "Vega w.r.t. vol of B"},
                        {RPCResult::Type::NUM, "theta", "Time decay"},
                        {RPCResult::Type::NUM, "rho_rate", "Interest rate sensitivity"},
                    }
                },
                {RPCResult::Type::OBJ, "asset_greeks", /*optional=*/true, "Per-leg Greeks for portfolio aggregation",
                    {
                        {RPCResult::Type::ARR, "delta", "Spot delta for {receive, pay, im_alice, im_bob}",
                            {
                                {RPCResult::Type::NUM, "", "Delta element"}
                            }
                        },
                        {RPCResult::Type::ARR, "vega", "Vega for {receive, pay, im_alice, im_bob}",
                            {
                                {RPCResult::Type::NUM, "", "Vega element"}
                            }
                        },
                        {RPCResult::Type::ARR, "gamma", "Gamma for {receive, pay, im_alice, im_bob}",
                            {
                                {RPCResult::Type::NUM, "", "Gamma element"}
                            }
                        },
                        {RPCResult::Type::ARR, "cross_gamma", "4x4 cross-gamma matrix",
                            {
                                {RPCResult::Type::ARR, "", "",
                                    {
                                        {RPCResult::Type::NUM, "", "Cross-gamma element"}
                                    }
                                }
                            }
                        },
                        {RPCResult::Type::ARR, "rate_delta", "Rate delta for {r_receive, r_pay, r_im_alice, r_im_bob, r_report}",
                            {
                                {RPCResult::Type::NUM, "", "Rate delta element"}
                            }
                        },
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
            HelpExampleCli("pricing.forward.quote", "\"registry\" \"CONTRACT_ID\"")
            + HelpExampleRpc("pricing.forward.quote", "\"inline\", \"\", {\"alice_deliver_asset\":\"...\", ...}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const std::string source_type = request.params[0].get_str();

            // Parse reporting currency
            uint256 report_asset;
            bool report_is_native = true; // Default to native TSC unless explicitly overridden
            if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty()) {
                report_asset = ParseHashV(request.params[3], "report_asset");
                report_is_native = request.params.size() > 4 && request.params[4].get_bool();
            }

            bool compute_greeks = request.params.size() <= 5 || request.params[5].get_bool();

            // Parse price_source parameter (param 6)
            PriceSource price_source = PriceSource::MARK;  // Default to mark
            if (request.params.size() > 6 && !request.params[6].isNull()) {
                std::string source_str = request.params[6].get_str();
                if (source_str == "market") {
                    price_source = PriceSource::MARKET;
                } else if (source_str != "mark") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "price_source must be 'mark' or 'market'");
                }
            }

            auto& pricing_ctx = wallet->GetPricingContext();
            int64_t current_time = GetTime();

            ForwardTerms terms;
            uint32_t maturity_days = 0;

            if (source_type == "registry") {
                if (request.params.size() < 2) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "registry_id required");
                }
                uint256 registry_id = ParseHashV(request.params[1], "registry_id");

                LOCK(wallet->cs_wallet);
                auto fwd_contract = wallet->FindForwardContract(registry_id);
                if (!fwd_contract) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Forward contract not found");
                }
                terms = fwd_contract->terms;

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
                normalize_leg(terms.long_party.deliver_leg);
                normalize_leg(terms.long_party.margin_leg);
                normalize_leg(terms.short_party.deliver_leg);
                normalize_leg(terms.short_party.margin_leg);
                normalize_leg(terms.premium_leg);

                int current_height = wallet->GetLastBlockHeight();
                int blocks_to_deadline = std::max(0, static_cast<int>(terms.deadline_short) - current_height);
                maturity_days = (blocks_to_deadline * 10) / (60 * 24);

            } else if (source_type == "inline") {
                if (request.params.size() < 3) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "inline_terms required");
                }
                const UniValue& terms_obj = request.params[2].get_obj();

                // Parse Alice (long party) deliver leg
                uint256 alice_deliver_asset;
                bool alice_deliver_is_native = false;
                if (!terms_obj.find_value("alice_deliver_is_native").isNull()) {
                    alice_deliver_is_native = terms_obj.find_value("alice_deliver_is_native").get_bool();
                }
                if (!alice_deliver_is_native) {
                    alice_deliver_asset = ParseHashV(terms_obj.find_value("alice_deliver_asset"), "alice_deliver_asset");
                }
                uint64_t alice_deliver_units = static_cast<uint64_t>(terms_obj.find_value("alice_deliver_units").getInt<int64_t>());
                terms.long_party.deliver_leg = {alice_deliver_asset, alice_deliver_is_native, alice_deliver_units, {}};

                // Parse Alice IM leg
                uint256 alice_im_asset;
                bool alice_im_is_native = false;
                if (!terms_obj.find_value("alice_im_is_native").isNull()) {
                    alice_im_is_native = terms_obj.find_value("alice_im_is_native").get_bool();
                }
                if (!alice_im_is_native) {
                    alice_im_asset = ParseHashV(terms_obj.find_value("alice_im_asset"), "alice_im_asset");
                }
                uint64_t alice_im_units = static_cast<uint64_t>(terms_obj.find_value("alice_im_units").getInt<int64_t>());
                terms.long_party.margin_leg = {alice_im_asset, alice_im_is_native, alice_im_units, {}};

                // Parse Bob (short party) deliver leg
                uint256 bob_deliver_asset;
                bool bob_deliver_is_native = false;
                if (!terms_obj.find_value("bob_deliver_is_native").isNull()) {
                    bob_deliver_is_native = terms_obj.find_value("bob_deliver_is_native").get_bool();
                }
                if (!bob_deliver_is_native) {
                    bob_deliver_asset = ParseHashV(terms_obj.find_value("bob_deliver_asset"), "bob_deliver_asset");
                }
                uint64_t bob_deliver_units = static_cast<uint64_t>(terms_obj.find_value("bob_deliver_units").getInt<int64_t>());
                terms.short_party.deliver_leg = {bob_deliver_asset, bob_deliver_is_native, bob_deliver_units, {}};

                // Parse Bob IM leg
                uint256 bob_im_asset;
                bool bob_im_is_native = false;
                if (!terms_obj.find_value("bob_im_is_native").isNull()) {
                    bob_im_is_native = terms_obj.find_value("bob_im_is_native").get_bool();
                }
                if (!bob_im_is_native) {
                    bob_im_asset = ParseHashV(terms_obj.find_value("bob_im_asset"), "bob_im_asset");
                }
                uint64_t bob_im_units = static_cast<uint64_t>(terms_obj.find_value("bob_im_units").getInt<int64_t>());
                terms.short_party.margin_leg = {bob_im_asset, bob_im_is_native, bob_im_units, {}};

                // Parse premium
                if (!terms_obj.find_value("premium_asset").isNull() && !terms_obj.find_value("premium_units").isNull()) {
                    uint256 premium_asset;
                    bool premium_is_native = false;
                    if (!terms_obj.find_value("premium_is_native").isNull()) {
                        premium_is_native = terms_obj.find_value("premium_is_native").get_bool();
                    }
                    if (!premium_is_native) {
                        premium_asset = ParseHashV(terms_obj.find_value("premium_asset"), "premium_asset");
                    }
                    uint64_t premium_units = static_cast<uint64_t>(terms_obj.find_value("premium_units").getInt<int64_t>());
                    terms.premium_leg = {premium_asset, premium_is_native, premium_units, {}};
                }

                terms.deadline_short = static_cast<uint32_t>(terms_obj.find_value("deadline_short").getInt<int64_t>());
                terms.safety_k = static_cast<uint32_t>(terms_obj.find_value("safety_k").getInt<int64_t>());

                int current_height = WITH_LOCK(wallet->cs_wallet, return wallet->GetLastBlockHeight());
                int blocks_to_deadline = std::max(0, static_cast<int>(terms.deadline_short) - current_height);
                maturity_days = (blocks_to_deadline * 10) / (60 * 24);

            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "source_type must be 'registry' or 'inline'");
            }

            // Price the forward contract
            auto valuation = ForwardPricer::Price(
                terms.short_party.deliver_leg,   // What Alice receives (Bob delivers)
                terms.long_party.deliver_leg,    // What Alice pays (Alice delivers)
                terms.long_party.margin_leg,     // Alice's IM
                terms.short_party.margin_leg,    // Bob's IM
                terms.premium_leg,
                maturity_days,
                terms.safety_k,
                pricing_ctx,
                report_asset,
                report_is_native,
                current_time,
                compute_greeks,
                price_source
            );

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("pv_receive", valuation.pv_receive);
            result.pushKV("pv_pay", valuation.pv_pay);
            result.pushKV("net_spread_value", valuation.net_spread_value);
            result.pushKV("premium_pv", valuation.premium_pv);
            result.pushKV("alice_short_call_value", valuation.alice_short_call_value);
            result.pushKV("alice_long_put_value", valuation.alice_long_put_value);
            result.pushKV("alice_mtm", valuation.alice_mtm);
            result.pushKV("bob_mtm", valuation.bob_mtm);
            result.pushKV("im_coverage_alice", valuation.im_coverage_alice);
            result.pushKV("im_coverage_bob", valuation.im_coverage_bob);
            result.pushKV("spot_A0", valuation.spot_A0);
            result.pushKV("spot_B0", valuation.spot_B0);
            result.pushKV("spot_C0", valuation.spot_C0);
            result.pushKV("spot_D0", valuation.spot_D0);
            result.pushKV("model_unreliable", valuation.model_unreliable);

            if (compute_greeks) {
                result.pushKV("spread_greeks_call", SpreadGreeksToJSON(valuation.spread_greeks_call));
                result.pushKV("spread_greeks_put", SpreadGreeksToJSON(valuation.spread_greeks_put));

                // Add per-asset Greeks for portfolio risk aggregation
                UniValue assetGreeks(UniValue::VOBJ);

                // Delta array (receive, pay, im_alice, im_bob)
                UniValue deltas(UniValue::VARR);
                for (int i = 0; i < 4; ++i) {
                    deltas.push_back(valuation.asset_greeks.delta[i]);
                }
                assetGreeks.pushKV("delta", deltas);

                // Vega array
                UniValue vegas(UniValue::VARR);
                for (int i = 0; i < 4; ++i) {
                    vegas.push_back(valuation.asset_greeks.vega[i]);
                }
                assetGreeks.pushKV("vega", vegas);

                // Gamma array
                UniValue gammas(UniValue::VARR);
                for (int i = 0; i < 4; ++i) {
                    gammas.push_back(valuation.asset_greeks.gamma[i]);
                }
                assetGreeks.pushKV("gamma", gammas);

                // Cross-gamma matrix
                UniValue crossGamma(UniValue::VARR);
                for (int i = 0; i < 4; ++i) {
                    UniValue row(UniValue::VARR);
                    for (int j = 0; j < 4; ++j) {
                        row.push_back(valuation.asset_greeks.cross_gamma[i][j]);
                    }
                    crossGamma.push_back(row);
                }
                assetGreeks.pushKV("cross_gamma", crossGamma);

                // Rate deltas (receive, pay, im_alice, im_bob, report)
                UniValue rateDeltas(UniValue::VARR);
                for (int i = 0; i < 5; ++i) {
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
