// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <kernel/cs_main.h>
#include <node/context.h>
#include <rpc/server_util.h>
#include <validation.h>
#include <wallet/context.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/contract.h>
#include <wallet/difficulty_contract.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/coincontrol.h>
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/repo_pricer.h>
#include <wallet/pricing/forward_pricer.h>
#include <wallet/pricing/difficulty_pricer.h>
#include <wallet/vaultregistry.h>
#include <assets/asset.h>
#include <assets/registry.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/time.h>
#include <cmath>
#include <set>

namespace wallet {

using namespace pricing;

namespace {

bool WalletOwnsDifficultyKey(const CWallet& wallet, const XOnlyPubKey& key)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    return key.IsFullyValid() &&
           (wallet.IsMine(GetScriptForDestination(WitnessV1Taproot{key})) & ISMINE_SPENDABLE);
}

std::string LocalDifficultyRole(const CWallet& wallet, const DifficultyContractRecord& rec)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const DifficultyContractTerms& terms = rec.terms;
    if (terms.IsOption()) {
        const DifficultyLegTerms& writer_leg = terms.OptionWriterLeg();
        if (WalletOwnsDifficultyKey(wallet, writer_leg.owner_key)) return "writer";
        if (WalletOwnsDifficultyKey(wallet, writer_leg.cp_key)) return "buyer";
        return "unknown";
    }

    if (WalletOwnsDifficultyKey(wallet, terms.long_leg.owner_key) ||
        WalletOwnsDifficultyKey(wallet, terms.short_leg.cp_key)) {
        return "long";
    }
    if (WalletOwnsDifficultyKey(wallet, terms.short_leg.owner_key) ||
        WalletOwnsDifficultyKey(wallet, terms.long_leg.cp_key)) {
        return "short";
    }
    return "unknown";
}

bool DifficultyLegLive(const CWallet& wallet, const DifficultyContractRecord& rec, bool is_short)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const COutPoint& op = rec.VaultOutpoint(is_short);
    return !op.IsNull() && !wallet.IsSpent(op);
}

} // namespace

RPCHelpMan pricing_portfolio_risk()
{
    return RPCHelpMan{
        "pricing.portfolio.risk",
        "Compute aggregated portfolio risk across all opened contracts and wallet balances\n"
        "Returns per-asset Greeks (delta, vega, gamma) and cross-gammas.\n",
        {
            {"include_balances", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include wallet balances as spot delta"},
            {"contract_ids", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional filter: when provided, aggregate only the specified contract IDs",
                {
                    {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Contract ID"},
                }
            },
            {"price_source", RPCArg::Type::STR, RPCArg::Default{"mark"}, "Price source: 'mark' or 'market'"},
            {"report_asset", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Reporting currency (empty for TSC)"},
            {"report_is_native", RPCArg::Type::BOOL, RPCArg::Default{true}, "Report currency is native"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "aggregate_risk", "Total portfolio risk",
                    {
                        {RPCResult::Type::OBJ, "deltas", "Total delta per asset"},
                        {RPCResult::Type::OBJ, "vegas", "Total vega per asset"},
                        {RPCResult::Type::OBJ, "gammas", "Total gamma per asset"},
                        {RPCResult::Type::OBJ, "cross_gammas", "Cross-gamma matrix"},
                        {RPCResult::Type::OBJ, "rate_deltas", "Rate sensitivity per asset (discount curve)"},
                    }
                },
                {RPCResult::Type::ARR, "positions", "Per-position Greeks",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "contract_id", "Contract ID"},
                                {RPCResult::Type::STR, "contract_type", "repo, forward, or difficulty"},
                                {RPCResult::Type::NUM, "mtm", "Mark-to-market value"},
                                {RPCResult::Type::OBJ, "asset_greeks", "Position Greeks"},
                            }
                        }
                    }
                },
                {RPCResult::Type::OBJ, "balance_deltas", /*optional=*/true, "Spot deltas from wallet balances"},
                {RPCResult::Type::NUM, "total_mtm", "Total portfolio MTM"},
                {RPCResult::Type::NUM, "positions_count", "Number of positions included"},
            }, /*skip_type_check=*/true  // positions are polymorphic across repo/forward/difficulty
        },
        RPCExamples{
            HelpExampleCli("pricing.portfolio.risk", "true")
            + HelpExampleCli("pricing.portfolio.risk", "true '[\"CONTRACT_ID_1\", \"CONTRACT_ID_2\"]'")
            + HelpExampleRpc("pricing.portfolio.risk", "false, null, \"market\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            auto pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            uint32_t current_chain_nbits = 0;
            int current_chain_height = 0;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = chainman.ActiveChain().Tip();
                if (!tip) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                current_chain_nbits = tip->nBits;
                current_chain_height = tip->nHeight;
            }

            LOCK(pwallet->cs_wallet);

            bool include_balances = request.params[0].isNull() ? true : request.params[0].get_bool();

            // Optional per-contract filter:
            // - If parameter is omitted or null  => include ALL opened contracts.
            // - If parameter is provided (even empty array) => include ONLY the
            //   listed contracts in aggregate metrics.
            bool has_contract_filter = !request.params[1].isNull();
            std::set<uint256> filter_contracts;
            if (has_contract_filter) {
                const UniValue& ids = request.params[1].get_array();
                for (const auto& id : ids.getValues()) {
                    filter_contracts.insert(ParseHashV(id, "contract_id"));
                }
            }

            PriceSource price_source = PriceSource::MARK;
            if (!request.params[2].isNull()) {
                std::string source_str = request.params[2].get_str();
                if (source_str == "market") {
                    price_source = PriceSource::MARKET;
                } else if (source_str != "mark") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "price_source must be 'mark' or 'market'");
                }
            }

            uint256 report_asset;
            if (!request.params[3].isNull() && !request.params[3].get_str().empty()) {
                report_asset = ParseHashV(request.params[3], "report_asset");
            }
            bool report_is_native = request.params[4].isNull() ? true : request.params[4].get_bool();

            auto& pricing_ctx = pwallet->GetPricingContext();
            int64_t current_time = GetTime();

            // Get TSC decimals for atomic->display conversion
            // NOTE: Risk RPC uses TSC (8 decimals) as reporting display scale.
            // All MTMs/Greeks from pricers are in atomic TSC; we convert them
            // to display units using this factor for the JSON response.
            int tsc_decimals = 8;
            const double atomic_to_display = 1.0 / std::pow(10.0, tsc_decimals);

            // Aggregate risk across assets (in display TSC units)
            std::map<std::string, double> total_deltas;
            std::map<std::string, double> total_vegas;
            std::map<std::string, double> total_gammas;
            std::map<std::pair<std::string, std::string>, double> total_cross_gammas;
            std::map<std::string, double> total_rate_deltas;
            // Bucketed rate sensitivities: asset → tenor_days → dv/dr(tenor)
            std::map<std::string, std::map<uint32_t, double>> total_rate_deltas_bucket;
            double total_mtm = 0.0;

            UniValue positions_arr(UniValue::VARR);
            int positions_count = 0;

            // Track local forward side by contract so we can later
            // classify which IM vaults belong to this wallet when
            // aggregating wallet balances (LONG excludes SHORT IM,
            // SHORT excludes LONG IM).
            std::map<uint256, ForwardSide> forward_side_by_contract;
            std::map<uint256, std::set<VaultRole>> difficulty_balance_roles_by_contract;

            // Build a cache of asset metadata for ticker lookup
            std::map<uint256, std::string> asset_ticker_cache;
            {
                CCoinControl control;
                control.m_min_depth = 0;
                control.m_max_depth = 9999999;
                control.m_include_unsafe_inputs = true;
                control.m_avoid_asset_utxos = false;

                CoinFilterParams filter_params;
                filter_params.only_spendable = false;

                const auto outputs = AvailableCoinsListUnspent(*pwallet, &control, filter_params).All();
                for (const COutput& out : outputs) {
                    const auto tag = assets::ParseAssetTag(out.txout.vExt);
                    if (tag && asset_ticker_cache.find(tag->id) == asset_ticker_cache.end()) {
                        if (auto meta = pwallet->GetAssetMetadata(out.outpoint)) {
                            if (meta->has_ticker && !meta->ticker.empty()) {
                                asset_ticker_cache[tag->id] = meta->ticker;
                            }
                        }
                    }
                }
            }

            // Helper to create asset key with cached ticker lookup
            auto make_asset_key = [&asset_ticker_cache](const uint256& asset_id, bool is_native) -> std::string {
                if (is_native) return "TSC";

                // Check cache for ticker
                auto it = asset_ticker_cache.find(asset_id);
                if (it != asset_ticker_cache.end()) {
                    return it->second;
                }

                // Fallback to short asset ID
                return asset_id.GetHex().substr(0, 8) + "...";
            };

            // Reporting curve key (native TSC or specific asset)
            const std::string report_curve_key = make_asset_key(report_asset, report_is_native);

            // Helper to normalize leg units to 8 decimals (consistent with inline pricing encoding)
            // Registry stores raw atomic units; pricer expects 8-decimal normalized units.
            auto normalize_leg = [&](const wallet::AssetLeg& leg) -> wallet::AssetLeg {
                wallet::AssetLeg normalized = leg;
                int decimals = pricing_ctx.GetAssetDecimals(leg.asset_id, leg.is_native);
                if (decimals < 0) decimals = 8; // Fallback to 8 if unknown
                if (decimals != 8) {
                    double scale = std::pow(10.0, 8 - decimals);
                    normalized.units = static_cast<uint64_t>(std::round(static_cast<double>(leg.units) * scale));
                }
                return normalized;
            };

            // Process repo contracts
            auto repo_offers = pwallet->ListRepoOffers();
            for (const auto& repo : repo_offers) {
                // Skip if not in opened state (pass wallet to check tx confirmation status)
                auto state = repo.DerivedState(pwallet.get());
                if (state != RepoContractState::OPENED) continue;

                // Check if this contract should be included in aggregate (but always show in positions).
                // When a filter is active, only contracts explicitly listed are aggregated.
                bool include_in_aggregate = !has_contract_filter || filter_contracts.count(repo.offer_id) > 0;

                // Compute maturity
                int current_height = pwallet->GetLastBlockHeight();
                int blocks_to_maturity = std::max(0, static_cast<int>(repo.terms.maturity_height) - current_height);
                uint32_t maturity_days = (blocks_to_maturity * 10) / (60 * 24);

                // Price the repo (normalize units to 8 decimals)
                auto valuation = RepoPricer::Price(
                    normalize_leg(repo.terms.principal_leg),
                    normalize_leg(repo.terms.interest_leg),
                    normalize_leg(repo.terms.collateral_leg),
                    maturity_days,
                    repo.terms.safety_k,
                    pricing_ctx,
                    report_asset,
                    report_is_native,
                    current_time,
                    true,  // compute_greeks
                    price_source,
                    false  // don't include inception
                );

                // Determine user's side (derive local role like contract.list does).
                // local_fs_tx_adaptor_secret is present if this wallet created the offer (is maker).
                // For legacy records where maker_role wasn't persisted, fall back to address
                // ownership — authoritative across restarts (derived from wallet descriptors).
                const bool i_am_maker = repo.local_fs_tx_adaptor_secret.has_value();
                bool is_lender;
                std::string local_role;
                if (repo.maker_role == "lender") {
                    is_lender = i_am_maker;
                    local_role = i_am_maker ? "lender" : "borrower";
                } else if (repo.maker_role == "borrower") {
                    is_lender = !i_am_maker;
                    local_role = i_am_maker ? "borrower" : "lender";
                } else {
                    const isminetype borrower_mine = pwallet->IsMine(GetScriptForDestination(repo.borrower_dest));
                    const isminetype lender_mine = pwallet->IsMine(GetScriptForDestination(repo.lender_dest));
                    if (lender_mine != ISMINE_NO && borrower_mine == ISMINE_NO) {
                        is_lender = true;
                        local_role = "lender";
                    } else if (borrower_mine != ISMINE_NO && lender_mine == ISMINE_NO) {
                        is_lender = false;
                        local_role = "borrower";
                    } else {
                        // Both/neither mine (watch-only or unusual case) — preserve old else-branch.
                        is_lender = !i_am_maker;
                        local_role = i_am_maker ? "borrower" : "lender";
                    }
                }

                // MTM in atomic units from pricer
                double position_mtm_atomic = is_lender ? valuation.lender_mtm : valuation.borrower_mtm;
                // Convert to display units
                double position_mtm = position_mtm_atomic * atomic_to_display;
                double sign = is_lender ? 1.0 : -1.0;  // Borrower has opposite risk

                // Only aggregate if this contract is checked/included
                if (include_in_aggregate) {
                    // Add to totals (now in display units)
                    total_mtm += position_mtm;

                // Aggregate Greeks (principal, interest, collateral)
                // Delta for repos:
                // - Native TSC legs: delta = PV (notional exposure), not price sensitivity
                // - Non-native legs: delta = ∂MTM/∂S (price sensitivity from option/FX)
                // Both sides get deltas specularly (opposite signs).
                std::vector<std::string> asset_keys = {
                    make_asset_key(repo.terms.principal_leg.asset_id, repo.terms.principal_leg.is_native),
                    make_asset_key(repo.terms.interest_leg.asset_id, repo.terms.interest_leg.is_native),
                    make_asset_key(repo.terms.collateral_leg.asset_id, repo.terms.collateral_leg.is_native)
                };
                std::vector<wallet::AssetLeg> curve_legs = {
                    repo.terms.principal_leg,
                    repo.terms.interest_leg,
                    repo.terms.collateral_leg
                };
                std::vector<bool> is_native_leg = {
                    repo.terms.principal_leg.is_native,
                    repo.terms.interest_leg.is_native,
                    repo.terms.collateral_leg.is_native
                };
                std::vector<double> leg_pvs = {
                    valuation.principal_pv,
                    valuation.interest_pv,
                    valuation.collateral_pv
                };

                for (int i = 0; i < 3; ++i) {
                    const bool is_collateral = (i == 2);
                    double delta_display = 0.0;

                    if (is_native_leg[i]) {
                        if (is_collateral) {
                            // Collateral stays with borrower until default: do not transfer spot delta
                            delta_display = 0.0;
                        } else {
                            // Native principal/interest: delta = PV exposure (atomic → display)
                            delta_display = leg_pvs[i] * atomic_to_display;
                        }
                    } else {
                        // Non-native leg: scale elasticity by notional PV to get TSC delta
                        double delta_atomic = valuation.asset_greeks.delta[i] * leg_pvs[i];
                        delta_display = delta_atomic * atomic_to_display;
                    }

                    // For lender: sign=+1, for borrower: sign=-1 (specular)
                    total_deltas[asset_keys[i]] += sign * delta_display;

                    // Vega: dMTM/dσ - convert MTM change to display
                    total_vegas[asset_keys[i]] += sign * valuation.asset_greeks.vega[i] * atomic_to_display;
                    // Gamma: d²MTM/dS² - convert to display
                    total_gammas[asset_keys[i]] += sign * valuation.asset_greeks.gamma[i] * atomic_to_display;

                    // Cross-gammas
                    for (int j = 0; j < 3; ++j) {
                        auto key = std::make_pair(asset_keys[i], asset_keys[j]);
                        total_cross_gammas[key] += sign * valuation.asset_greeks.cross_gamma[i][j] * atomic_to_display;
                    }
                }

                    // Rate deltas - aggregate per asset/curve in display units.
                    // Principal, interest, collateral legs use their respective asset keys.
                    for (int i = 0; i < 3; ++i) {
                        double rd_atomic = valuation.asset_greeks.rate_delta[i];
                        if (rd_atomic == 0.0) continue;

                        double rd_display = sign * rd_atomic * atomic_to_display;
                        const std::string& key = asset_keys[i];
                        total_rate_deltas[key] += rd_display;

                        // Decompose this scalar sensitivity into curve tenors via bucket weights.
                        // When no explicit discount curve exists, fall back to a single bucket
                        // at the contract maturity so that bucketed DV01s are still visible.
                        auto curve_opt = pricing_ctx.GetCurve(curve_legs[i].asset_id, curve_legs[i].is_native, price_source);
                        if (curve_opt) {
                            auto buckets = curve_opt->GetZeroRateBucketWeights(maturity_days);
                            if (!buckets.empty()) {
                                for (const auto& bw : buckets) {
                                    if (bw.weight == 0.0) continue;
                                    total_rate_deltas_bucket[key][bw.tenor_days] += rd_display * bw.weight;
                                }
                            } else {
                                total_rate_deltas_bucket[key][maturity_days] += rd_display;
                            }
                        } else {
                            total_rate_deltas_bucket[key][maturity_days] += rd_display;
                        }
                    }
                    // Reporting curve sensitivity is attributed to the reporting asset (or native TSC).
                    double rd_report_atomic = valuation.asset_greeks.rate_delta[3];
                    if (rd_report_atomic != 0.0) {
                        double rd_report_display = sign * rd_report_atomic * atomic_to_display;
                        total_rate_deltas[report_curve_key] += rd_report_display;

                        auto curve_opt = pricing_ctx.GetCurve(report_asset, report_is_native, price_source);
                        if (curve_opt) {
                            auto buckets = curve_opt->GetZeroRateBucketWeights(maturity_days);
                            if (!buckets.empty()) {
                                for (const auto& bw : buckets) {
                                    if (bw.weight == 0.0) continue;
                                    total_rate_deltas_bucket[report_curve_key][bw.tenor_days] += rd_report_display * bw.weight;
                                }
                            } else {
                                total_rate_deltas_bucket[report_curve_key][maturity_days] += rd_report_display;
                            }
                        } else {
                            total_rate_deltas_bucket[report_curve_key][maturity_days] += rd_report_display;
                        }
                    }
                }  // End include_in_aggregate

                // Add position details (ALWAYS, regardless of filter)
                UniValue pos(UniValue::VOBJ);
                pos.pushKV("contract_id", repo.offer_id.GetHex());
                pos.pushKV("contract_type", "repo");
                pos.pushKV("role", local_role);  // Use local role, not maker_role
                pos.pushKV("mtm", position_mtm);  // Already in display units

                // Add asset_greeks (already computed above)
                UniValue greeks(UniValue::VOBJ);
                UniValue deltas(UniValue::VARR);
                for (int i = 0; i < 3; ++i) {
                    deltas.push_back(sign * valuation.asset_greeks.delta[i]);
                }
                greeks.pushKV("delta", deltas);
                pos.pushKV("asset_greeks", greeks);

                positions_arr.push_back(pos);
                positions_count++;
            }

            // Process forward contracts
            auto forward_contracts = pwallet->ListForwardContracts();
            for (const auto& fwd : forward_contracts) {
                // Skip if not in opened state
                auto state = fwd.DerivedState();
                if (state != ForwardContractState::OPENED) continue;

                // Cache local side (LONG/SHORT) for this contract so that
                // wallet balance aggregation can later distinguish which IM
                // vaults (FORWARD_LONG/FORWARD_SHORT) belong to this wallet.
                forward_side_by_contract[fwd.contract_id] = fwd.local_side;

                // Check if this contract should be included in aggregate (but always show in positions).
                // When a filter is active, only contracts explicitly listed are aggregated.
                bool include_in_aggregate = !has_contract_filter || filter_contracts.count(fwd.contract_id) > 0;

                // Compute maturity
                int current_height = pwallet->GetLastBlockHeight();
                int blocks_to_deadline = std::max(0, static_cast<int>(fwd.terms.deadline_short) - current_height);
                uint32_t maturity_days = (blocks_to_deadline * 10) / (60 * 24);

                // Price the forward (normalize units to 8 decimals)
                // CRITICAL: long_party = Alice (LONG), short_party = Bob (SHORT)
                // - Alice RECEIVES what Bob delivers = short_party.deliver_leg
                // - Alice PAYS what she delivers = long_party.deliver_leg
                auto valuation = ForwardPricer::Price(
                    normalize_leg(fwd.terms.short_party.deliver_leg),  // receive: Bob → Alice
                    normalize_leg(fwd.terms.long_party.deliver_leg),   // pay: Alice → Bob
                    normalize_leg(fwd.terms.long_party.margin_leg),    // Alice's IM
                    normalize_leg(fwd.terms.short_party.margin_leg),   // Bob's IM
                    normalize_leg(fwd.terms.premium_leg),
                    maturity_days,
                    fwd.terms.safety_k,
                    pricing_ctx,
                    report_asset,
                    report_is_native,
                    current_time,
                    true,  // compute_greeks
                    price_source
                );

                // Determine user's side
                bool is_long = (fwd.local_side == ForwardSide::LONG);
                // MTM in atomic units from pricer
                double position_mtm_atomic = is_long ? valuation.alice_mtm : valuation.bob_mtm;
                // Convert to display units
                double position_mtm = position_mtm_atomic * atomic_to_display;
                double sign = is_long ? 1.0 : -1.0;

                // Only aggregate if this contract is checked/included
                if (include_in_aggregate) {
                    // Add to totals (now in display units)
                    total_mtm += position_mtm;

                // Asset keys now match pricer order: [0]=receive, [1]=pay, [2]=alice_im, [3]=bob_im
                std::vector<std::string> asset_keys = {
                    make_asset_key(fwd.terms.short_party.deliver_leg.asset_id, fwd.terms.short_party.deliver_leg.is_native),  // receive
                    make_asset_key(fwd.terms.long_party.deliver_leg.asset_id, fwd.terms.long_party.deliver_leg.is_native),    // pay
                    make_asset_key(fwd.terms.long_party.margin_leg.asset_id, fwd.terms.long_party.margin_leg.is_native),      // alice IM
                    make_asset_key(fwd.terms.short_party.margin_leg.asset_id, fwd.terms.short_party.margin_leg.is_native)     // bob IM
                };
                std::vector<wallet::AssetLeg> curve_legs = {
                    fwd.terms.short_party.deliver_leg,
                    fwd.terms.long_party.deliver_leg,
                    fwd.terms.long_party.margin_leg,
                    fwd.terms.short_party.margin_leg
                };

                // Get notional values for delta scaling (like repos)
                // valuation.pv_receive/pv_pay are PV in atomic TSC
                std::vector<double> leg_pvs_atomic = {
                    valuation.pv_receive,  // receive leg PV in atomic TSC
                    valuation.pv_pay,      // pay leg PV in atomic TSC
                    0.0,  // IM legs don't have PV from valuation
                    0.0
                };

                for (int i = 0; i < 4; ++i) {
                    // ONLY process deliver legs (i=0,1), NOT IM legs (i=2,3)
                    // IM is collateral expected to be returned, not portfolio exposure
                    if (i < 2) {
                        // Delta: Pricer returns dimensionless ∂MTM/∂S (elasticity)
                        // Must scale by notional to get delta in TSC units
                        double delta_atomic = valuation.asset_greeks.delta[i] * leg_pvs_atomic[i];
                        total_deltas[asset_keys[i]] += sign * delta_atomic * atomic_to_display;

                        // Vega: dMTM/dσ - convert MTM change to display
                        total_vegas[asset_keys[i]] += sign * valuation.asset_greeks.vega[i] * atomic_to_display;

                        // Gamma: d²MTM/dS² - convert to display
                        total_gammas[asset_keys[i]] += sign * valuation.asset_greeks.gamma[i] * atomic_to_display;

                        // Cross-gamma: only between deliver legs
                        for (int j = 0; j < 2; ++j) {
                            auto key = std::make_pair(asset_keys[i], asset_keys[j]);
                            total_cross_gammas[key] += sign * valuation.asset_greeks.cross_gamma[i][j] * atomic_to_display;
                        }
                    }
                }

                    // Rate deltas - aggregate per asset/curve in display units.
                    // Map receive/pay/IM legs to their asset keys; report curve to reporting asset.
                    for (int i = 0; i < 5; ++i) {
                        double rd_atomic = valuation.asset_greeks.rate_delta[i];
                        if (rd_atomic == 0.0) continue;

                        double rd_display = sign * rd_atomic * atomic_to_display;

                        if (i >= 0 && i <= 3) {
                            const int leg_index = i;
                            const std::string& key = asset_keys[leg_index];
                            total_rate_deltas[key] += rd_display;

                            auto curve_opt = pricing_ctx.GetCurve(curve_legs[leg_index].asset_id,
                                                                  curve_legs[leg_index].is_native,
                                                                  price_source);
                            if (curve_opt) {
                                auto buckets = curve_opt->GetZeroRateBucketWeights(maturity_days);
                                if (!buckets.empty()) {
                                    for (const auto& bw : buckets) {
                                        if (bw.weight == 0.0) continue;
                                        total_rate_deltas_bucket[key][bw.tenor_days] += rd_display * bw.weight;
                                    }
                                } else {
                                    total_rate_deltas_bucket[key][maturity_days] += rd_display;
                                }
                            } else {
                                total_rate_deltas_bucket[key][maturity_days] += rd_display;
                            }
                        } else if (i == 4) {
                            const std::string& key = report_curve_key;
                            total_rate_deltas[key] += rd_display;

                            auto curve_opt = pricing_ctx.GetCurve(report_asset, report_is_native, price_source);
                            if (curve_opt) {
                                auto buckets = curve_opt->GetZeroRateBucketWeights(maturity_days);
                                if (!buckets.empty()) {
                                    for (const auto& bw : buckets) {
                                        if (bw.weight == 0.0) continue;
                                        total_rate_deltas_bucket[key][bw.tenor_days] += rd_display * bw.weight;
                                    }
                                } else {
                                    total_rate_deltas_bucket[key][maturity_days] += rd_display;
                                }
                            } else {
                                total_rate_deltas_bucket[key][maturity_days] += rd_display;
                            }
                        }
                    }
                }  // End include_in_aggregate

                // Add position details (ALWAYS, regardless of filter)
                UniValue pos(UniValue::VOBJ);
                pos.pushKV("contract_id", fwd.contract_id.GetHex());
                pos.pushKV("contract_type", "forward");
                pos.pushKV("side", is_long ? "long" : "short");
                pos.pushKV("mtm", position_mtm);  // Already in display units

                positions_arr.push_back(pos);
                positions_count++;
            }

            // Process difficulty derivative contracts. These are native-TSC contracts whose
            // underlying exposure is the chain difficulty itself, reported under a synthetic
            // DIFFICULTY risk key. Partially-settled CFDs are deliberately skipped here instead
            // of being priced as full two-leg contracts, which would overstate remaining risk.
            const uint256 pow_limit = Params().GetConsensus().powLimit;
            // Difficulty MTM/greeks come out of the pricer in native-TSC display units; convert them to
            // the report asset with the same native->report FX the wallet-balance section uses below.
            double difficulty_report_fx = 1.0;
            if (!report_asset.IsNull() || !report_is_native) {
                const uint256 native_asset;  // all-zero == native TSC
                FXResult fx = pricing_ctx.GetFXRate(native_asset, report_asset, /*base_is_native=*/true,
                                                    report_is_native, current_time, price_source);
                if (fx.rate > 0.0) difficulty_report_fx = fx.rate;
            }
            auto difficulty_contracts = pwallet->ListDifficultyContracts();
            for (const auto& diff : difficulty_contracts) {
                const std::string local_role = LocalDifficultyRole(*pwallet, diff);
                std::set<VaultRole> local_difficulty_vault_roles;
                if (local_role == "long") {
                    local_difficulty_vault_roles.insert(VaultRole::DIFFICULTY_LONG);
                } else if (local_role == "short") {
                    local_difficulty_vault_roles.insert(VaultRole::DIFFICULTY_SHORT);
                } else if (local_role == "writer") {
                    local_difficulty_vault_roles.insert(diff.terms.OptionWriterIsShort() ?
                        VaultRole::DIFFICULTY_SHORT : VaultRole::DIFFICULTY_LONG);
                }
                difficulty_balance_roles_by_contract[diff.contract_id] = std::move(local_difficulty_vault_roles);

                if (diff.open_txid.IsNull()) continue;

                const bool is_option = diff.terms.IsOption();
                if (is_option) {
                    const bool writer_is_short = diff.terms.OptionWriterIsShort();
                    if (!DifficultyLegLive(*pwallet, diff, writer_is_short)) continue;
                } else {
                    if (!DifficultyLegLive(*pwallet, diff, /*is_short=*/false) ||
                        !DifficultyLegLive(*pwallet, diff, /*is_short=*/true)) {
                        continue;
                    }
                }

                const bool include_in_aggregate = !has_contract_filter || filter_contracts.count(diff.contract_id) > 0;

                // Mark off the difficulty forward curve + vol surface (PricingContext), discounted on the
                // native TSC curve. If the fixing height is already buried, read the committed ancestor's
                // nBits so the contract is priced deterministically rather than forecast (§10.5).
                DifficultyMarketInputs mkt;
                mkt.current_nbits = current_chain_nbits;
                mkt.current_height = current_chain_height;
                mkt.pow_limit = pow_limit;
                mkt.pow_target_spacing = Params().GetConsensus().nPowTargetSpacing;
                mkt.current_time = current_time;
                mkt.source = price_source;
                if (current_chain_height >= static_cast<int>(diff.terms.fixing_height)) {
                    LOCK(cs_main);
                    if (const CBlockIndex* tip = chainman.ActiveChain().Tip()) {
                        if (const CBlockIndex* fix = tip->GetAncestor(static_cast<int>(diff.terms.fixing_height))) {
                            mkt.realized_nbits = fix->nBits;
                        }
                    }
                }

                auto valuation = DifficultyPricer::Price(diff.terms, pricing_ctx, mkt, true);

                double position_mtm_atomic = 0.0;
                double delta_atomic = 0.0;
                double vega_atomic = 0.0;
                double theta_atomic = 0.0;
                if (is_option) {
                    if (local_role == "writer") {
                        position_mtm_atomic = valuation.expected_writer_mtm;
                        delta_atomic = valuation.writer_delta_to_difficulty;
                        vega_atomic = valuation.writer_vega;
                        theta_atomic = valuation.writer_theta;
                    } else {
                        position_mtm_atomic = valuation.expected_buyer_mtm;
                        delta_atomic = valuation.buyer_delta_to_difficulty;
                        vega_atomic = valuation.buyer_vega;
                        theta_atomic = valuation.buyer_theta;
                    }
                } else {
                    if (local_role == "short") {
                        position_mtm_atomic = valuation.expected_short_mtm;
                        delta_atomic = valuation.short_delta_to_difficulty;
                        vega_atomic = valuation.short_vega;
                        theta_atomic = valuation.short_theta;
                    } else {
                        position_mtm_atomic = valuation.expected_long_mtm;
                        delta_atomic = valuation.long_delta_to_difficulty;
                        vega_atomic = valuation.long_vega;
                        theta_atomic = valuation.long_theta;
                    }
                }

                const double position_mtm = position_mtm_atomic * atomic_to_display * difficulty_report_fx;
                const double delta_display = delta_atomic * atomic_to_display * difficulty_report_fx;
                const double vega_display = vega_atomic * atomic_to_display * difficulty_report_fx;
                const double theta_display = theta_atomic * atomic_to_display * difficulty_report_fx;

                if (include_in_aggregate) {
                    total_mtm += position_mtm;
                    if (delta_display != 0.0) {
                        total_deltas["DIFFICULTY"] += delta_display;
                    }
                    if (vega_display != 0.0) {
                        total_vegas["DIFFICULTY"] += vega_display;
                    }
                }

                UniValue pos(UniValue::VOBJ);
                pos.pushKV("contract_id", diff.contract_id.GetHex());
                pos.pushKV("contract_type", "difficulty");
                pos.pushKV("kind", is_option ? "option" : "cfd");
                pos.pushKV(is_option ? "role" : "side", local_role);
                pos.pushKV("mtm", position_mtm);
                pos.pushKV("current_nbits", static_cast<uint64_t>(valuation.current_nbits));
                pos.pushKV("forecast_nbits", static_cast<uint64_t>(valuation.forecast_nbits));
                pos.pushKV("forward_provenance", valuation.forward_provenance);
                pos.pushKV("fixing_reached", valuation.fixing_reached);
                pos.pushKV("sigma", valuation.sigma);
                pos.pushKV("discount_factor", valuation.discount_factor);
                pos.pushKV("report_fx", difficulty_report_fx);  // native-TSC -> report-asset rate applied

                UniValue greeks(UniValue::VOBJ);
                greeks.pushKV("delta_to_difficulty", delta_display);
                greeks.pushKV("vega", vega_display);
                greeks.pushKV("theta", theta_display);
                pos.pushKV("asset_greeks", greeks);
                pos.pushKV("model_unreliable", valuation.model_unreliable);

                positions_arr.push_back(pos);
                positions_count++;
            }

            // Add wallet balances as spot deltas with proper FX and decimal adjustment.
            // Build both native (TSC) and asset balances directly from UTXOs so that
            // covenant vault roles (borrower/lender/IM/escrow) are handled uniformly
            // for native and asset-backed contracts. For forwards, exclude the
            // counterparty IM vaults based on local contract side:
            // - If we are LONG, exclude FORWARD_SHORT vaults.
            // - If we are SHORT, exclude FORWARD_LONG vaults.
            UniValue balance_deltas(UniValue::VOBJ);
            double wallet_mtm = 0.0;

            if (include_balances) {
                // Collect all wallet-owned UTXOs (native + assets)
                CCoinControl control;
                control.m_min_depth = 0;  // Include unconfirmed for completeness
                control.m_max_depth = 9999999;
                control.m_include_unsafe_inputs = true;  // Include all UTXOs
                control.m_avoid_asset_utxos = false;     // Include asset outputs

                CoinFilterParams filter_params;
                filter_params.only_spendable = false;    // Include all outputs, not just spendable

                const auto outputs = AvailableCoinsListUnspent(*pwallet, &control, filter_params).All();

                // Structure to hold asset info with metadata
                struct AssetInfo {
                    uint64_t raw_units = 0;
                    std::string ticker;
                    uint8_t decimals = 0;
                    bool has_ticker = false;
                    bool has_decimals = false;
                };

                std::map<uint256, AssetInfo> asset_map;
                std::map<uint256, std::optional<AssetRegistryEntry>> registry_cache;

                // Native TSC balance in atomic units
                CAmount tsc_raw = 0;

                // Classify each UTXO as native or asset and apply vault-role filtering
                for (const COutput& out : outputs) {
                    // Determine if this is a covenant vault and, if so, which role it
                    // belongs to and which contract it is associated with.
                    wallet::VaultMetadata vault_meta;
                    bool is_vault = pwallet->GetCovenantVaultMetadata(out.txout.scriptPubKey, vault_meta);

                    if (is_vault) {
                        wallet::VaultRole vault_role = vault_meta.role;

                        // Lender/escrow-side vaults are contingent only on default/timeout.
                        // Do NOT treat these as wallet asset balances for delta/MTM.
                        if (vault_role == wallet::VaultRole::REPO_LENDER ||
                            vault_role == wallet::VaultRole::FORWARD_ESCROW_A ||
                            vault_role == wallet::VaultRole::FORWARD_ESCROW_B) {
                            continue;
                        }

                        // For forwards, apply contract-side based inclusion/exclusion:
                        // - If we are LONG on this contract, exclude short IM vaults.
                        // - If we are SHORT on this contract, exclude long IM vaults.
                        auto side_it = forward_side_by_contract.find(vault_meta.contract_id);
                        if (side_it != forward_side_by_contract.end()) {
                            ForwardSide local_side = side_it->second;
                            if ((local_side == ForwardSide::LONG && vault_role == wallet::VaultRole::FORWARD_SHORT) ||
                                (local_side == ForwardSide::SHORT && vault_role == wallet::VaultRole::FORWARD_LONG)) {
                                continue;
                            }
                        }

                        // Difficulty vaults are tracked by both counterparties so either side can
                        // settle. Only this wallet's own posted writer/CFD IM is a balance; the
                        // counterparty IM is represented through the difficulty MTM instead.
                        auto diff_roles_it = difficulty_balance_roles_by_contract.find(vault_meta.contract_id);
                        if (diff_roles_it != difficulty_balance_roles_by_contract.end() &&
                            (vault_role == wallet::VaultRole::DIFFICULTY_LONG ||
                             vault_role == wallet::VaultRole::DIFFICULTY_SHORT) &&
                            diff_roles_it->second.count(vault_role) == 0) {
                            continue;
                        }
                    }

                    // Parse asset tag (if any)
                    const auto tag = assets::ParseAssetTag(out.txout.vExt);
                    if (!tag) {
                        // Native TSC output
                        tsc_raw += out.txout.nValue;
                        continue;
                    }

                    // This is an asset we are entitled to under the no-default path
                    AssetInfo& info = asset_map[tag->id];
                    info.raw_units += tag->amount;

                    // Get metadata if we haven't already
                    if (!info.has_ticker || !info.has_decimals) {
                        // First check wallet metadata
                        if (auto meta = pwallet->GetAssetMetadata(out.outpoint)) {
                            if (meta->has_ticker && !info.has_ticker) {
                                info.ticker = meta->ticker;
                                info.has_ticker = true;
                            }
                            if (meta->has_decimals && !info.has_decimals) {
                                info.decimals = meta->decimals;
                                info.has_decimals = true;
                            }
                        }

                        // If still missing, check registry (cached)
                        if (!info.has_ticker || !info.has_decimals) {
                            std::optional<AssetRegistryEntry> registry_entry;
                            auto cache_it = registry_cache.find(tag->id);
                            if (cache_it != registry_cache.end()) {
                                registry_entry = cache_it->second;
                            } else {
                                // Get registry entry from chain interface
                                registry_entry = pwallet->chain().getAssetRegistryEntry(tag->id);
                                registry_cache.emplace(tag->id, registry_entry);
                            }

                            if (registry_entry) {
                                if (!info.has_ticker && !registry_entry->ticker.empty()) {
                                    info.ticker = registry_entry->ticker;
                                    info.has_ticker = true;
                                }
                                if (!info.has_decimals) {
                                    // Registry entries always have decimals (default 0 if not set)
                                    info.decimals = registry_entry->decimals;
                                    info.has_decimals = true;
                                }
                            }
                        }
                    }
                }

                // Process native TSC balance first
                if (tsc_raw != 0) {
                    double tsc_balance = static_cast<double>(tsc_raw) / COIN;

                    // Get FX rate for TSC to report currency if needed
                    double tsc_fx = 1.0;
                    if (!report_asset.IsNull() || !report_is_native) {
                        uint256 native_asset;
                        FXResult fx_result = pricing_ctx.GetFXRate(native_asset, report_asset,
                                                                  true, report_is_native,
                                                                  current_time, price_source);
                        tsc_fx = fx_result.rate;
                    }

                    double tsc_value = tsc_balance * tsc_fx;
                    wallet_mtm += tsc_value;
                    total_deltas["TSC"] += tsc_value;  // Store FX-adjusted value
                    balance_deltas.pushKV("TSC", tsc_value);
                }

                // Process each asset with FX and decimal conversion
                for (const auto& [asset_id, info] : asset_map) {
                    if (info.raw_units == 0) continue;

                    // Convert to display units using decimals
                    double divisor = info.has_decimals ? std::pow(10.0, info.decimals) : 1.0;
                    double display_units = static_cast<double>(info.raw_units) / divisor;

                    // Get FX rate to report currency
                    double fx_rate = 1.0;
                    if (asset_id != report_asset || !report_is_native) {
                        FXResult fx_result = pricing_ctx.GetFXRate(asset_id, report_asset,
                                                                   false, report_is_native,
                                                                   current_time, price_source);
                        fx_rate = fx_result.rate;
                        // If no FX path is found, fall back to 1.0 so balances
                        // are still visible in their native units instead of 0.
                        if (fx_rate <= 0.0) {
                            fx_rate = 1.0;
                        }
                    }

                    double fx_adjusted_value = display_units * fx_rate;
                    wallet_mtm += fx_adjusted_value;

                    // Use ticker if available, otherwise short asset ID
                    std::string key = info.has_ticker ? info.ticker :
                                     (asset_id.GetHex().substr(0, 8) + "...");

                    // For wallet balances, treat balance_deltas as MTM in report
                    // currency (used by the GUI Wallet Balances section). For the
                    // aggregate deltas used in risk metrics, keep the same value
                    // so that wallet exposures contribute to portfolio-level
                    // sensitivity. (If we ever want "pure" quantity deltas here,
                    // this is the place to switch to display_units instead.)
                    total_deltas[key] += fx_adjusted_value;
                    balance_deltas.pushKV(key, fx_adjusted_value);
                }
            }

            // Build result
            UniValue result(UniValue::VOBJ);

            // Aggregate risk
            UniValue aggregate(UniValue::VOBJ);

            // Calculate sums for display
            double delta_sum = 0.0;
            double vega_sum = 0.0;
            double gamma_sum = 0.0;

            UniValue deltas_obj(UniValue::VOBJ);
            for (const auto& [asset, delta] : total_deltas) {
                // Don't filter wallet balances - show all non-zero amounts
                if (delta != 0.0) {
                    deltas_obj.pushKV(asset, delta);
                    delta_sum += delta;
                }
            }
            deltas_obj.pushKV("_TOTAL", delta_sum);
            aggregate.pushKV("deltas", deltas_obj);

            UniValue vegas_obj(UniValue::VOBJ);
            for (const auto& [asset, vega] : total_vegas) {
                if (vega != 0.0) {
                    vegas_obj.pushKV(asset, vega);
                    vega_sum += std::abs(vega);  // Vegas typically summed in absolute terms
                }
            }
            vegas_obj.pushKV("_TOTAL", vega_sum);
            aggregate.pushKV("vegas", vegas_obj);

            UniValue gammas_obj(UniValue::VOBJ);
            for (const auto& [asset, gamma] : total_gammas) {
                if (gamma != 0.0) {
                    gammas_obj.pushKV(asset, gamma);
                    gamma_sum += std::abs(gamma);  // Gammas typically summed in absolute terms
                }
            }
            gammas_obj.pushKV("_TOTAL", gamma_sum);
            aggregate.pushKV("gammas", gammas_obj);

            UniValue cross_gammas_obj(UniValue::VOBJ);
            for (const auto& [pair, cross_gamma] : total_cross_gammas) {
                if (cross_gamma != 0.0) {
                    std::string key = pair.first + "/" + pair.second;
                    cross_gammas_obj.pushKV(key, cross_gamma);
                }
            }
            aggregate.pushKV("cross_gammas", cross_gammas_obj);

            UniValue rate_deltas_obj(UniValue::VOBJ);
            for (const auto& [curve, rate_delta] : total_rate_deltas) {
                if (rate_delta != 0.0) {
                    rate_deltas_obj.pushKV(curve, rate_delta);
                }
            }
            aggregate.pushKV("rate_deltas", rate_deltas_obj);

            // Bucketed rate deltas: per asset and tenor (days)
            UniValue rate_deltas_bucketed_obj(UniValue::VOBJ);
            for (const auto& [asset, buckets] : total_rate_deltas_bucket) {
                UniValue per_asset(UniValue::VOBJ);
                for (const auto& [tenor_days, dv] : buckets) {
                    if (dv == 0.0) continue;
                    per_asset.pushKV(std::to_string(tenor_days), dv);
                }
                if (!per_asset.getKeys().empty()) {
                    rate_deltas_bucketed_obj.pushKV(asset, per_asset);
                }
            }
            aggregate.pushKV("rate_deltas_bucketed", rate_deltas_bucketed_obj);

            result.pushKV("aggregate_risk", aggregate);
            result.pushKV("positions", positions_arr);
            if (include_balances) {
                result.pushKV("balance_deltas", balance_deltas);
                result.pushKV("wallet_mtm", wallet_mtm);  // Add wallet MTM
            }
            result.pushKV("total_mtm", total_mtm + wallet_mtm);  // Include wallet MTM in total
            result.pushKV("positions_count", positions_count);

            return result;
        },
    };
}

} // namespace wallet
