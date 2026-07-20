// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <util/time.h>
#include <kernel/cs_main.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/context.h>
#include <wallet/difficulty_contract.h>
#include <wallet/pricing/difficulty_pricer.h>
#include <wallet/pricing/warnings.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <limits>
#include <optional>
#include <string>

namespace wallet {

using namespace pricing;

namespace {

uint32_t ParseUint32Param(const UniValue& v, const std::string& field)
{
    const int64_t n = v.getInt<int64_t>();
    if (n < 0 || n > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, field + " out of uint32 range");
    }
    return static_cast<uint32_t>(n);
}

uint32_t ParseUint32Field(const UniValue& obj, const std::string& key)
{
    return ParseUint32Param(obj.find_value(key), key);
}

void ParseCfdLegEconomics(const UniValue& obj, DifficultyLegTerms& leg, const std::string& name)
{
    if (!obj.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be an object");
    leg.im = AmountFromValue(obj.find_value("im"));
    leg.lambda_q = ParseUint32Field(obj, "lambda_q");
}

DifficultyContractTerms ParseInlineTerms(const UniValue& obj)
{
    if (!obj.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "inline_terms must be an object");

    DifficultyContractTerms terms;
    terms.strike_nbits = ParseUint32Field(obj, "strike_nbits");
    terms.fixing_height = ParseUint32Field(obj, "fixing_height");
    terms.settle_lock_height = ParseUint32Field(obj, "settle_lock_height");

    std::string kind = "cfd";
    if (const UniValue& k = obj.find_value("kind"); !k.isNull()) {
        kind = k.get_str();
    }

    if (kind == "cfd") {
        terms.kind = DIFFICULTY_KIND_CFD;
        ParseCfdLegEconomics(obj.find_value("long"), terms.long_leg, "long");
        ParseCfdLegEconomics(obj.find_value("short"), terms.short_leg, "short");
        terms.premium = 0;
        return terms;
    }

    if (kind == "option") {
        terms.kind = DIFFICULTY_KIND_OPTION;
        terms.premium = AmountFromValue(obj.find_value("premium"));
        const CAmount im = AmountFromValue(obj.find_value("im"));
        const uint32_t lambda_q = ParseUint32Field(obj, "lambda_q");
        const std::string writer_side = obj.find_value("writer_side").get_str();
        if (writer_side == "short") {
            terms.short_leg.im = im;
            terms.short_leg.lambda_q = lambda_q;
        } else if (writer_side == "long") {
            terms.long_leg.im = im;
            terms.long_leg.lambda_q = lambda_q;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "writer_side must be 'long' or 'short'");
        }
        return terms;
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "kind must be 'cfd' or 'option'");
}

UniValue WarningToJSON(const Warning& warn)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("severity", SeverityToString(warn.severity));
    obj.pushKV("category", CategoryToString(warn.category));
    obj.pushKV("message", warn.message);
    if (warn.threshold_value) obj.pushKV("threshold", *warn.threshold_value);
    return obj;
}

UniValue WarningsToJSON(const std::vector<Warning>& warnings)
{
    UniValue arr(UniValue::VARR);
    for (const Warning& warn : warnings) {
        arr.push_back(WarningToJSON(warn));
    }
    return arr;
}

void PushCommonResult(UniValue& result, const DifficultyValuation& v)
{
    result.pushKV("contract_type", "difficulty");
    result.pushKV("kind", v.is_option ? "option" : "cfd");
    result.pushKV("strike_nbits", static_cast<uint64_t>(v.strike_nbits));
    result.pushKV("current_nbits", static_cast<uint64_t>(v.current_nbits));
    result.pushKV("forecast_nbits", static_cast<uint64_t>(v.forecast_nbits));
    result.pushKV("fixing_height", static_cast<uint64_t>(v.fixing_height));
    result.pushKV("settle_lock_height", static_cast<uint64_t>(v.settle_lock_height));
    result.pushKV("current_height", v.current_height);
    result.pushKV("blocks_to_fixing", v.blocks_to_fixing);
    result.pushKV("blocks_to_resolvable", v.blocks_to_resolvable);
    result.pushKV("current_difficulty_ratio", v.current_difficulty_ratio);
    result.pushKV("forecast_difficulty_ratio", v.forecast_difficulty_ratio);
    result.pushKV("forward_provenance", v.forward_provenance);
    result.pushKV("fixing_reached", v.fixing_reached);
    result.pushKV("sigma", v.sigma);
    result.pushKV("tau_years", v.tau_years);
    result.pushKV("discount_factor", v.discount_factor);
    result.pushKV("model_unreliable", v.model_unreliable);
    result.pushKV("warnings", WarningsToJSON(v.warnings));
}

} // namespace

RPCHelpMan pricing_difficulty_quote()
{
    return RPCHelpMan{
        "pricing.difficulty.quote",
        "Compute deterministic MTM for a difficulty CFD/option using OP_DIFFCFD_SETTLE payout math.\n"
        "Registry quotes read contract terms from the wallet. Inline quotes accept economics-only terms.\n"
        "If forecast_nbits is omitted, the chain-tip nBits is used and a model warning is returned.\n",
        {
            {"source_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Contract source: 'registry' or 'inline'"},
            {"registry_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Registry contract ID"},
            {"inline_terms", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline difficulty terms",
                {
                    {"kind", RPCArg::Type::STR, RPCArg::Default{"cfd"}, "'cfd' or 'option'"},
                    {"strike_nbits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Committed compact difficulty target"},
                    {"fixing_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Fixing block height"},
                    {"settle_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Settlement CLTV height"},
                    {"long", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "CFD long leg", {
                        {"im", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Long IM"},
                        {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::NO, "Long leverage in Q16"},
                    }},
                    {"short", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "CFD short leg", {
                        {"im", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Short IM"},
                        {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::NO, "Short leverage in Q16"},
                    }},
                    {"writer_side", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Option writer side: 'long' or 'short'"},
                    {"im", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Option writer IM"},
                    {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Option writer leverage in Q16"},
                    {"premium", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Option premium"},
                }},
            {"forecast_nbits", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional forecast compact target for the fixing height"},
            {"compute_greeks", RPCArg::Type::BOOL, RPCArg::Default{true}, "Compute finite-difference delta to difficulty"},
            {"price_source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Market-data tier for the difficulty curve/vol/discount: 'mark' or 'market'"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "contract_type", "difficulty"},
                {RPCResult::Type::STR, "kind", "cfd or option"},
                {RPCResult::Type::NUM, "expected_long_mtm", /*optional=*/true, "CFD long MTM in native atomic units"},
                {RPCResult::Type::NUM, "expected_short_mtm", /*optional=*/true, "CFD short MTM in native atomic units"},
                {RPCResult::Type::NUM, "expected_writer_mtm", /*optional=*/true, "Option writer MTM in native atomic units"},
                {RPCResult::Type::NUM, "expected_buyer_mtm", /*optional=*/true, "Option buyer MTM in native atomic units"},
                {RPCResult::Type::NUM, "long_delta_to_difficulty", /*optional=*/true, "CFD long dMTM/d(1.0 difficulty move)"},
                {RPCResult::Type::NUM, "short_delta_to_difficulty", /*optional=*/true, "CFD short dMTM/d(1.0 difficulty move)"},
                {RPCResult::Type::NUM, "writer_delta_to_difficulty", /*optional=*/true, "Option writer dMTM/d(1.0 difficulty move)"},
                {RPCResult::Type::NUM, "buyer_delta_to_difficulty", /*optional=*/true, "Option buyer dMTM/d(1.0 difficulty move)"},
                {RPCResult::Type::BOOL, "model_unreliable", "True if terms or market data prevented a reliable quote"},
                {RPCResult::Type::ARR, "warnings", "Pricing warnings",
                    {{RPCResult::Type::STR, "", "A pricing warning message"}}},
            }, /*skip_type_check=*/true // payload is polymorphic (CFD vs option fields, optional greeks, writer_side)
        },
        RPCExamples{
            HelpExampleCli("pricing.difficulty.quote", "\"registry\" \"CONTRACT_ID\"")
            + HelpExampleCli("pricing.difficulty.quote", "\"registry\" \"CONTRACT_ID\" null 545259519")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

            const std::string source_type = request.params[0].get_str();
            DifficultyContractTerms terms;
            uint256 contract_id;

            if (source_type == "registry") {
                if (request.params.size() < 2 || request.params[1].isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "registry_id required");
                }
                contract_id = ParseHashV(request.params[1], "registry_id");
                const auto rec_opt = wallet->FindDifficultyContract(contract_id);
                if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Difficulty contract not found");
                terms = rec_opt->terms;
            } else if (source_type == "inline") {
                if (request.params.size() < 3 || request.params[2].isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "inline_terms required");
                }
                terms = ParseInlineTerms(request.params[2].get_obj());
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "source_type must be 'registry' or 'inline'");
            }

            std::optional<uint32_t> forecast_nbits;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                forecast_nbits = ParseUint32Param(request.params[3], "forecast_nbits");
            }
            const bool compute_greeks = request.params.size() <= 4 || request.params[4].isNull() || request.params[4].get_bool();
            PriceSource price_source = PriceSource::MARKET;
            if (request.params.size() > 5 && !request.params[5].isNull()) {
                price_source = StringToPriceSource(request.params[5].get_str());
            }

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            DifficultyMarketInputs mkt;
            mkt.pow_limit = Params().GetConsensus().powLimit;
            mkt.pow_target_spacing = Params().GetConsensus().nPowTargetSpacing;
            mkt.current_time = GetTime();
            mkt.source = price_source;
            mkt.forecast_nbits_override = forecast_nbits;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = chainman.ActiveChain().Tip();
                if (!tip) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                mkt.current_nbits = tip->nBits;
                mkt.current_height = tip->nHeight;
                // Fixing already buried into the chain -> the underlying is known; price it deterministically
                // off the committed ancestor's nBits (the same value OP_DIFFCFD_SETTLE resolves). §10.5.
                if (tip->nHeight >= static_cast<int>(terms.fixing_height)) {
                    if (const CBlockIndex* fix = tip->GetAncestor(static_cast<int>(terms.fixing_height))) {
                        mkt.realized_nbits = fix->nBits;
                    }
                }
            }

            const DifficultyValuation quote = DifficultyPricer::Price(
                terms, wallet->GetPricingContext(), mkt, compute_greeks);

            UniValue result(UniValue::VOBJ);
            if (!contract_id.IsNull()) result.pushKV("contract_id", contract_id.GetHex());
            PushCommonResult(result, quote);

            if (quote.is_option) {
                result.pushKV("writer_side", quote.option_writer_is_short ? "short" : "long");
                result.pushKV("premium_pv", quote.premium_pv);
                result.pushKV("intrinsic_writer_mtm", quote.intrinsic_writer_mtm);
                result.pushKV("intrinsic_buyer_mtm", quote.intrinsic_buyer_mtm);
                result.pushKV("expected_writer_mtm", quote.expected_writer_mtm);
                result.pushKV("expected_buyer_mtm", quote.expected_buyer_mtm);
                result.pushKV("writer_delta_to_difficulty", quote.writer_delta_to_difficulty);
                result.pushKV("buyer_delta_to_difficulty", quote.buyer_delta_to_difficulty);
                result.pushKV("writer_vega", quote.writer_vega);
                result.pushKV("buyer_vega", quote.buyer_vega);
                result.pushKV("writer_theta", quote.writer_theta);
                result.pushKV("buyer_theta", quote.buyer_theta);
            } else {
                result.pushKV("intrinsic_long_mtm", quote.intrinsic_long_mtm);
                result.pushKV("intrinsic_short_mtm", quote.intrinsic_short_mtm);
                result.pushKV("expected_long_mtm", quote.expected_long_mtm);
                result.pushKV("expected_short_mtm", quote.expected_short_mtm);
                result.pushKV("long_delta_to_difficulty", quote.long_delta_to_difficulty);
                result.pushKV("short_delta_to_difficulty", quote.short_delta_to_difficulty);
                result.pushKV("long_vega", quote.long_vega);
                result.pushKV("short_vega", quote.short_vega);
                result.pushKV("long_theta", quote.long_theta);
                result.pushKV("short_theta", quote.short_theta);
                result.pushKV("long_leg_expected_owner_payout", quote.long_leg_expected_owner_payout);
                result.pushKV("long_leg_expected_cp_payout", quote.long_leg_expected_cp_payout);
                result.pushKV("short_leg_expected_owner_payout", quote.short_leg_expected_owner_payout);
                result.pushKV("short_leg_expected_cp_payout", quote.short_leg_expected_cp_payout);
            }

            return result;
        },
    };
}

} // namespace wallet
