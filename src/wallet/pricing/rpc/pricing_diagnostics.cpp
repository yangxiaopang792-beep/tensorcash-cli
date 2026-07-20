// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/context.h>
#include <wallet/contract.h>
#include <wallet/difficulty_contract.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/repo_pricer.h>
#include <wallet/pricing/forward_pricer.h>
#include <wallet/pricing/difficulty_pricer.h>
#include <wallet/pricing/warnings.h>
#include <chain.h>
#include <chainparams.h>
#include <kernel/cs_main.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>
#include <algorithm>

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

struct DiagnosticEntry {
    std::string contract_type;  // "repo", "forward", or "difficulty"
    uint256 contract_id;
    std::vector<Warning> warnings;
    double mtm_value;
};

//! Assemble difficulty market inputs from the active chain (reads the buried fixing if reached).
//! Takes cs_main internally — call with NO wallet lock held (two-phase: copy records, then price).
static DifficultyMarketInputs BuildDifficultyMarketInputs(ChainstateManager& chainman,
                                                          const DifficultyContractTerms& terms,
                                                          int64_t current_time)
{
    DifficultyMarketInputs mkt;
    const Consensus::Params& consensus = Params().GetConsensus();
    mkt.pow_limit = consensus.powLimit;
    mkt.pow_target_spacing = consensus.nPowTargetSpacing;
    mkt.current_time = current_time;
    mkt.source = PriceSource::MARKET;
    LOCK(cs_main);
    const CBlockIndex* tip = chainman.ActiveChain().Tip();
    if (tip) {
        mkt.current_nbits = tip->nBits;
        mkt.current_height = tip->nHeight;
        if (tip->nHeight >= static_cast<int>(terms.fixing_height)) {
            if (const CBlockIndex* fix = tip->GetAncestor(static_cast<int>(terms.fixing_height))) {
                mkt.realized_nbits = fix->nBits;
            }
        }
    }
    return mkt;
}

RPCHelpMan pricing_diagnostics_scan()
{
    return RPCHelpMan{
        "pricing.diagnostics.scan",
        "Scan all repo, forward, and difficulty contracts for pricing warnings\n"
        "Returns contracts sorted by severity (CRITICAL first)\n",
        {
            {"contract_type", RPCArg::Type::STR, RPCArg::Default{"all"}, "Filter: 'all', 'repo', 'forward', or 'difficulty'"},
            {"min_severity", RPCArg::Type::STR, RPCArg::Default{"INFO"}, "Minimum severity: 'INFO', 'WARNING', 'CRITICAL'"},
            {"limit", RPCArg::Type::NUM, RPCArg::Default{50}, "Maximum number of contracts to return"},
            {"report_asset", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Reporting currency (empty for TSC)"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "Array of contracts with warnings",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "contract_type", "'repo' or 'forward'"},
                        {RPCResult::Type::STR_HEX, "contract_id", "Registry contract ID"},
                        {RPCResult::Type::NUM, "mtm_value", "Mark-to-market value in reporting currency"},
                        {RPCResult::Type::ARR, "warnings", "Array of warnings",
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
                }
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.diagnostics.scan", "\"all\" \"CRITICAL\" 20")
            + HelpExampleRpc("pricing.diagnostics.scan", "\"repo\", \"WARNING\", 10")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const std::string contract_type = request.params.size() > 0 ? request.params[0].get_str() : "all";
            const std::string min_severity_str = request.params.size() > 1 ? request.params[1].get_str() : "INFO";
            const size_t limit = request.params.size() > 2 ? static_cast<size_t>(request.params[2].getInt<int>()) : 50;

            uint256 report_asset;
            bool report_is_native = false;
            if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty()) {
                report_asset = ParseHashV(request.params[3], "report_asset");
            }

            // Parse severity
            WarningSeverity min_severity = WarningSeverity::INFO;
            if (min_severity_str == "WARNING") min_severity = WarningSeverity::WARNING;
            else if (min_severity_str == "CRITICAL") min_severity = WarningSeverity::CRITICAL;

            auto& pricing_ctx = wallet->GetPricingContext();
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            int64_t current_time = GetTime();
            int current_height = WITH_LOCK(wallet->cs_wallet, return wallet->GetLastBlockHeight());

            std::vector<DiagnosticEntry> entries;

            // Scan repo contracts
            if (contract_type == "all" || contract_type == "repo") {
                LOCK(wallet->cs_wallet);
                auto repo_offers = wallet->ListRepoOffers();

                for (const auto& offer : repo_offers) {
                    int blocks_to_maturity = std::max(0, static_cast<int>(offer.terms.maturity_height) - current_height);
                    uint32_t maturity_days = (blocks_to_maturity * 10) / (60 * 24);

                    auto valuation = RepoPricer::Price(
                        offer.terms.principal_leg,
                        offer.terms.interest_leg,
                        offer.terms.collateral_leg,
                        maturity_days,
                        offer.terms.safety_k,
                        pricing_ctx,
                        report_asset,
                        report_is_native,
                        current_time,
                        false,  // Skip greeks for scan
                        PriceSource::MARK,
                        false
                    );

                    // Filter by severity
                    std::vector<Warning> filtered_warnings;
                    for (const auto& warn : valuation.warnings) {
                        if (warn.severity >= min_severity) {
                            filtered_warnings.push_back(warn);
                        }
                    }

                    if (!filtered_warnings.empty()) {
                        DiagnosticEntry entry;
                        entry.contract_type = "repo";
                        entry.contract_id = offer.offer_id;
                        entry.warnings = filtered_warnings;
                        entry.mtm_value = valuation.lender_mtm;
                        entries.push_back(entry);
                    }
                }
            }

            // Scan forward contracts
            if (contract_type == "all" || contract_type == "forward") {
                LOCK(wallet->cs_wallet);
                auto fwd_contracts = wallet->ListForwardContracts();

                for (const auto& contract : fwd_contracts) {
                    int blocks_to_deadline = std::max(0, static_cast<int>(contract.terms.deadline_short) - current_height);
                    uint32_t maturity_days = (blocks_to_deadline * 10) / (60 * 24);

                    auto valuation = ForwardPricer::Price(
                        contract.terms.short_party.deliver_leg,
                        contract.terms.long_party.deliver_leg,
                        contract.terms.long_party.margin_leg,
                        contract.terms.short_party.margin_leg,
                        contract.terms.premium_leg,
                        maturity_days,
                        contract.terms.safety_k,
                        pricing_ctx,
                        report_asset,
                        report_is_native,
                        current_time,
                        false  // Skip greeks
                    );

                    std::vector<Warning> filtered_warnings;
                    for (const auto& warn : valuation.warnings) {
                        if (warn.severity >= min_severity) {
                            filtered_warnings.push_back(warn);
                        }
                    }

                    if (!filtered_warnings.empty()) {
                        entries.push_back({
                            "forward",
                            contract.contract_id,
                            filtered_warnings,
                            valuation.alice_mtm
                        });
                    }
                }
            }

            // Scan difficulty contracts (two-phase: copy records under cs_wallet, then price under cs_main)
            if (contract_type == "all" || contract_type == "difficulty") {
                std::vector<DifficultyContractRecord> diffs;
                { LOCK(wallet->cs_wallet); diffs = wallet->ListDifficultyContracts(); }

                for (const auto& diff : diffs) {
                    auto mkt = BuildDifficultyMarketInputs(chainman, diff.terms, current_time);
                    auto valuation = DifficultyPricer::Price(diff.terms, pricing_ctx, mkt, /*greeks=*/false);

                    std::vector<Warning> filtered_warnings;
                    for (const auto& warn : valuation.warnings) {
                        if (warn.severity >= min_severity) filtered_warnings.push_back(warn);
                    }

                    if (!filtered_warnings.empty()) {
                        DiagnosticEntry entry;
                        entry.contract_type = "difficulty";
                        entry.contract_id = diff.contract_id;
                        entry.warnings = filtered_warnings;
                        entry.mtm_value = valuation.is_option ? valuation.expected_buyer_mtm : valuation.expected_long_mtm;
                        entries.push_back(entry);
                    }
                }
            }

            // Sort by severity (CRITICAL first)
            std::sort(entries.begin(), entries.end(), [](const DiagnosticEntry& a, const DiagnosticEntry& b) {
                auto max_severity_a = std::max_element(a.warnings.begin(), a.warnings.end(),
                    [](const Warning& w1, const Warning& w2) { return w1.severity < w2.severity; });
                auto max_severity_b = std::max_element(b.warnings.begin(), b.warnings.end(),
                    [](const Warning& w1, const Warning& w2) { return w1.severity < w2.severity; });
                if (max_severity_a == a.warnings.end()) return false;
                if (max_severity_b == b.warnings.end()) return true;
                return max_severity_a->severity > max_severity_b->severity;
            });

            // Limit results
            if (entries.size() > limit) {
                entries.resize(limit);
            }

            // Build result
            UniValue result(UniValue::VARR);
            for (const auto& entry : entries) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("contract_type", entry.contract_type);
                obj.pushKV("contract_id", entry.contract_id.ToString());
                obj.pushKV("mtm_value", entry.mtm_value);

                UniValue warnings_arr(UniValue::VARR);
                for (const auto& warn : entry.warnings) {
                    warnings_arr.push_back(WarningToJSON(warn));
                }
                obj.pushKV("warnings", warnings_arr);

                result.push_back(obj);
            }

            return result;
        },
    };
}

RPCHelpMan pricing_portfolio_summary()
{
    return RPCHelpMan{
        "pricing.portfolio.summary",
        "Compute aggregated portfolio statistics across all repo, forward, and difficulty contracts\n",
        {
            {"report_asset", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Reporting currency (empty for TSC)"},
            {"compute_greeks", RPCArg::Type::BOOL, RPCArg::Default{false}, "Aggregate portfolio Greeks (approximate)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "total_repo_count", "Number of repo contracts"},
                {RPCResult::Type::NUM, "total_forward_count", "Number of forward contracts"},
                {RPCResult::Type::NUM, "total_difficulty_count", "Number of difficulty contracts"},
                {RPCResult::Type::NUM, "total_repo_mtm", "Aggregate repo MTM (lender perspective)"},
                {RPCResult::Type::NUM, "total_forward_mtm", "Aggregate forward MTM (Alice/long perspective)"},
                {RPCResult::Type::NUM, "total_difficulty_mtm", "Aggregate difficulty MTM (long/buyer perspective)"},
                {RPCResult::Type::NUM, "net_portfolio_mtm", "Total portfolio MTM"},
                {RPCResult::Type::NUM, "critical_warnings_count", "Number of CRITICAL warnings"},
                {RPCResult::Type::NUM, "warning_count", "Number of WARNING-level warnings"},
                {RPCResult::Type::OBJ, "portfolio_greeks", /*optional=*/true, "Aggregated Greeks (approximate)",
                    {
                        {RPCResult::Type::NUM, "total_delta", "Sum of asset deltas (repo+forward)"},
                        {RPCResult::Type::NUM, "total_vega", "Sum of asset vegas (repo+forward)"},
                        {RPCResult::Type::NUM, "difficulty_delta", "Sum of difficulty deltas (separate risk factor)"},
                        {RPCResult::Type::NUM, "difficulty_vega", "Sum of difficulty vegas"},
                        {RPCResult::Type::STR, "gamma_note", "Gamma sums are approximate (non-additive)"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("pricing.portfolio.summary", "\"\" true")
            + HelpExampleRpc("pricing.portfolio.summary", "\"\", false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            uint256 report_asset;
            bool report_is_native = false;
            if (request.params.size() > 0 && !request.params[0].isNull() && !request.params[0].get_str().empty()) {
                report_asset = ParseHashV(request.params[0], "report_asset");
            }

            bool compute_greeks = request.params.size() > 1 && request.params[1].get_bool();

            auto& pricing_ctx = wallet->GetPricingContext();
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            int64_t current_time = GetTime();
            int current_height = WITH_LOCK(wallet->cs_wallet, return wallet->GetLastBlockHeight());

            size_t repo_count = 0;
            size_t forward_count = 0;
            size_t difficulty_count = 0;
            double total_repo_mtm = 0.0;
            double total_forward_mtm = 0.0;
            double total_difficulty_mtm = 0.0;
            size_t critical_count = 0;
            size_t warning_count = 0;

            double total_delta = 0.0;
            double total_vega = 0.0;
            double total_difficulty_delta = 0.0;
            double total_difficulty_vega = 0.0;

            // Process repos
            {
                LOCK(wallet->cs_wallet);
                auto repo_offers = wallet->ListRepoOffers();
                repo_count = repo_offers.size();

                for (const auto& offer : repo_offers) {
                    int blocks_to_maturity = std::max(0, static_cast<int>(offer.terms.maturity_height) - current_height);
                    uint32_t maturity_days = (blocks_to_maturity * 10) / (60 * 24);

                    auto valuation = RepoPricer::Price(
                        offer.terms.principal_leg,
                        offer.terms.interest_leg,
                        offer.terms.collateral_leg,
                        maturity_days,
                        offer.terms.safety_k,
                        pricing_ctx,
                        report_asset,
                        report_is_native,
                        current_time,
                        compute_greeks,
                        PriceSource::MARK,
                        false
                    );

                    total_repo_mtm += valuation.lender_mtm;

                    for (const auto& warn : valuation.warnings) {
                        if (warn.severity == WarningSeverity::CRITICAL) critical_count++;
                        else if (warn.severity == WarningSeverity::WARNING) warning_count++;
                    }

                    if (compute_greeks) {
                        total_delta += valuation.collateral_greeks.delta;
                        total_vega += valuation.collateral_greeks.vega;
                    }
                }
            }

            // Process forwards
            {
                LOCK(wallet->cs_wallet);
                auto fwd_contracts = wallet->ListForwardContracts();
                forward_count = fwd_contracts.size();

                for (const auto& contract : fwd_contracts) {
                    int blocks_to_deadline = std::max(0, static_cast<int>(contract.terms.deadline_short) - current_height);
                    uint32_t maturity_days = (blocks_to_deadline * 10) / (60 * 24);

                    auto valuation = ForwardPricer::Price(
                        contract.terms.short_party.deliver_leg,
                        contract.terms.long_party.deliver_leg,
                        contract.terms.long_party.margin_leg,
                        contract.terms.short_party.margin_leg,
                        contract.terms.premium_leg,
                        maturity_days,
                        contract.terms.safety_k,
                        pricing_ctx,
                        report_asset,
                        report_is_native,
                        current_time,
                        compute_greeks
                    );

                    total_forward_mtm += valuation.alice_mtm;

                    for (const auto& warn : valuation.warnings) {
                        if (warn.severity == WarningSeverity::CRITICAL) critical_count++;
                        else if (warn.severity == WarningSeverity::WARNING) warning_count++;
                    }

                    if (compute_greeks) {
                        total_delta += valuation.spread_greeks_call.delta_A + valuation.spread_greeks_call.delta_B
                                     + valuation.spread_greeks_put.delta_A + valuation.spread_greeks_put.delta_B;
                        total_vega += valuation.spread_greeks_call.vega_A + valuation.spread_greeks_call.vega_B
                                    + valuation.spread_greeks_put.vega_A + valuation.spread_greeks_put.vega_B;
                    }
                }
            }

            // Process difficulty contracts (two-phase: copy under cs_wallet, price under cs_main)
            {
                std::vector<DifficultyContractRecord> diffs;
                { LOCK(wallet->cs_wallet); diffs = wallet->ListDifficultyContracts(); }
                difficulty_count = diffs.size();

                // Difficulty MTM/greeks come out of the pricer in native TSC; FX-convert to the report
                // asset the same way the leg valuator does (value * fx_rate). Identity for native TSC
                // (the default, report_asset empty) — so the common case is unchanged.
                double diff_fx = 1.0;
                if (!report_asset.IsNull()) {
                    const uint256 native_asset;  // all-zero == native TSC
                    FXResult fx = pricing_ctx.GetFXRate(native_asset, report_asset, /*base_is_native=*/true,
                                                        report_is_native, current_time, PriceSource::MARKET);
                    if (fx.rate > 0.0) diff_fx = fx.rate;
                }

                for (const auto& diff : diffs) {
                    auto mkt = BuildDifficultyMarketInputs(chainman, diff.terms, current_time);
                    auto valuation = DifficultyPricer::Price(diff.terms, pricing_ctx, mkt, compute_greeks);

                    if (valuation.is_option) {
                        total_difficulty_mtm += valuation.expected_buyer_mtm * diff_fx;
                        if (compute_greeks) {
                            total_difficulty_delta += valuation.buyer_delta_to_difficulty * diff_fx;
                            total_difficulty_vega += valuation.buyer_vega * diff_fx;
                        }
                    } else {
                        total_difficulty_mtm += valuation.expected_long_mtm * diff_fx;
                        if (compute_greeks) {
                            total_difficulty_delta += valuation.long_delta_to_difficulty * diff_fx;
                            total_difficulty_vega += valuation.long_vega * diff_fx;
                        }
                    }

                    for (const auto& warn : valuation.warnings) {
                        if (warn.severity == WarningSeverity::CRITICAL) critical_count++;
                        else if (warn.severity == WarningSeverity::WARNING) warning_count++;
                    }
                }
            }

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("total_repo_count", (uint64_t)repo_count);
            result.pushKV("total_forward_count", (uint64_t)forward_count);
            result.pushKV("total_difficulty_count", (uint64_t)difficulty_count);
            result.pushKV("total_repo_mtm", total_repo_mtm);
            result.pushKV("total_forward_mtm", total_forward_mtm);
            result.pushKV("total_difficulty_mtm", total_difficulty_mtm);
            result.pushKV("net_portfolio_mtm", total_repo_mtm + total_forward_mtm + total_difficulty_mtm);
            result.pushKV("critical_warnings_count", (uint64_t)critical_count);
            result.pushKV("warning_count", (uint64_t)warning_count);

            if (compute_greeks) {
                UniValue greeks_obj(UniValue::VOBJ);
                greeks_obj.pushKV("total_delta", total_delta);
                greeks_obj.pushKV("total_vega", total_vega);
                greeks_obj.pushKV("difficulty_delta", total_difficulty_delta);
                greeks_obj.pushKV("difficulty_vega", total_difficulty_vega);
                greeks_obj.pushKV("gamma_note", "Gamma sums are approximate (non-additive across contracts)");
                result.pushKV("portfolio_greeks", greeks_obj);
            }

            return result;
        },
    };
}

} // namespace wallet
