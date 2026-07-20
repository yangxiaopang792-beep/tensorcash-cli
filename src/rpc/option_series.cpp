// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Core (wallet-independent) option-series RPCs: optionseries.derive and optionseries.verify. Both are
// read-only and deterministic from the descriptor (the derivation core + RPC param layer live in
// bitcoin_common), so they are registered as CORE commands and work on ANY node with no wallet — the
// buyer/auditor/explorer side of OPTION_TOKENIZATION.md §3. The wallet-only optionseries.build_register
// (which funds + composes registerasset) stays in wallet/rpc/option_series.cpp.

#include <coins.h>             // CCoinsViewCursor, Coin
#include <node/context.h>      // NodeContext
#include <primitives/transaction.h> // COutPoint
#include <rpc/server.h>
#include <rpc/server_util.h>   // EnsureAnyChainman, EnsureAnyNodeContext
#include <rpc/util.h>
#include <script/script.h>     // CScript
#include <sync.h>              // LOCK, cs_main
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>        // ChainstateManager, Chainstate
#include <wallet/option_series.h>

#include <assets/asset.h>      // MINT_ALLOWED, BURN_ALLOWED, SPK_P2TR
#include <assets/registry.h>   // AssetRegistryEntry

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace wallet; // the derivation core + RPC param layer live in namespace wallet (bitcoin_common)

namespace {

RPCHelpMan optionseries_derive()
{
    return RPCHelpMan{
        "optionseries.derive",
        "Derive an option series' asset_id and per-lot covenant addresses from its terms alone "
        "(OPTION_TOKENIZATION.md §3 / OPTION_SERIES_FREEZE.md). Read-only and deterministic — no chain "
        "or wallet state, runs on any node. This is the verifier's tool: recompute asset_id == "
        "H(descriptor), then re-derive every lot vault / pot / sink to check a series on-chain.",
        {
            {"terms", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The frozen series terms (descriptor fields)",
                {
                    {"writer_key", RPCArg::Type::STR, RPCArg::Optional::NO, "Issuer/writer key: 32-byte x-only hex or a P2TR (bech32m) address"},
                    {"strike_nbits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Committed compact difficulty target (canonical)"},
                    {"fixing_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Buried ancestor height H"},
                    {"settle_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leaf CLTV; >= fixing_height + maturity"},
                    {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leverage in Q16 (lambda * 65536)"},
                    {"lot_im", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Per-lot initial margin (K/N)"},
                    {"lot_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "N (number of lots / fungible units)"},
                    {"series_salt", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte series randomizer"},
                    {"reference_premium", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Display/listing premium (default 0)"},
                    {"descriptor_version", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Descriptor version: 1 (call-only, default) or 2 (carries direction)"},
                    {"direction", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "0 call / writer-short (default), 1 put / writer-long; requires descriptor_version 2"},
                    {"issuance_mode", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "0 self-issuance (default), 1 bilateral"},
                    {"leaf_set", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "0 settle-only, 1 settle+buyback (default)"},
                }},
            {"lots", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Lot indices to derive in full (omit for asset_id + descriptor only)",
                {{"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "A lot index in [0, lot_count)"}}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "series_id = TaggedHash(\"TSC-OptionSeries/v1\", descriptor) (option-series canonical hex)"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "Same 32 bytes in the registry display hex (getassetinfo/getassetpolicy/geticupayload lookups)"},
                {RPCResult::Type::STR_HEX, "descriptor", "The canonical binary descriptor (the import-and-prove bundle)"},
                {RPCResult::Type::STR_HEX, "icu_metadata", "The canonical TSC-ICU-META-1 ICU metadata bytes (descriptor + termsheet bands) to embed at registration"},
                {RPCResult::Type::NUM, "lot_count", "N"},
                {RPCResult::Type::ARR, "lots", "Derived lots (one per requested index)",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "index", "Lot index"},
                            {RPCResult::Type::STR_HEX, "salt", "Per-lot salt"},
                            {RPCResult::Type::STR_HEX, "contract_id", "Vault contract id"},
                            {RPCResult::Type::STR_HEX, "sink_spk", "Retirement sink scriptPubKey"},
                            {RPCResult::Type::STR_HEX, "pot_key", "Pot taproot output key"},
                            {RPCResult::Type::STR_HEX, "pot_spk", "Pot scriptPubKey"},
                            {RPCResult::Type::STR_HEX, "vault_key", "Lot vault taproot output key"},
                            {RPCResult::Type::STR_HEX, "vault_spk", "Lot vault scriptPubKey (collateral sits here)"},
                            {RPCResult::Type::STR_HEX, "settle_leaf", "The OP_DIFFCFD_SETTLE leaf script"},
                            {RPCResult::Type::STR_HEX, "buyback_leaf", "The buy-back leaf script (omitted for settle-only)"},
                        }}}},
            }},
        RPCExamples{HelpExampleCli("optionseries.derive",
            "'{\"writer_key\":\"79be667e...\",\"strike_nbits\":486604799,\"fixing_height\":150000,"
            "\"settle_lock_height\":150100,\"lambda_q\":218453,\"lot_im\":\"30\",\"lot_count\":100,"
            "\"series_salt\":\"1d59c4b9...\"}' '[0,1,99]'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);

            std::string verr;
            if (!ValidateOptionSeriesTerms(terms, /*pow_limit=*/nullptr, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }

            const uint256 series_id = ComputeOptionSeriesId(terms);
            const std::vector<unsigned char> descriptor = SerializeOptionDescriptor(terms);

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", HexStr(series_id));
            result.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(series_id));
            result.pushKV("descriptor", HexStr(descriptor));
            result.pushKV("icu_metadata", HexStr(BuildOptionSeriesIcuMetadata(terms)));
            result.pushKV("lot_count", static_cast<uint64_t>(terms.lot_count));

            UniValue lots_out(UniValue::VARR);
            const UniValue& lots_in = request.params[1];
            if (!lots_in.isNull()) {
                if (!lots_in.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "lots must be an array of indices");
                for (size_t j = 0; j < lots_in.size(); ++j) {
                    if (!lots_in[j].isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, "lot indices must be numbers");
                    const int64_t idx = lots_in[j].getInt<int64_t>();
                    if (idx < 0 || static_cast<uint64_t>(idx) >= terms.lot_count) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("lot index %d out of range [0,%u)", idx, terms.lot_count));
                    }
                    const OptionLot lot = DeriveOptionLot(terms, series_id, static_cast<uint32_t>(idx));
                    UniValue lo(UniValue::VOBJ);
                    lo.pushKV("index", static_cast<uint64_t>(idx));
                    lo.pushKV("salt", HexStr(lot.salt));
                    lo.pushKV("contract_id", HexStr(lot.contract_id));
                    lo.pushKV("sink_spk", HexStr(lot.sink_spk));
                    lo.pushKV("pot_key", HexStr(lot.pot_key));
                    lo.pushKV("pot_spk", HexStr(lot.pot_spk));
                    lo.pushKV("vault_key", HexStr(lot.vault_key));
                    lo.pushKV("vault_spk", HexStr(lot.vault_spk));
                    lo.pushKV("settle_leaf", HexStr(lot.settle_leaf));
                    if (!lot.buyback_leaf.empty()) lo.pushKV("buyback_leaf", HexStr(lot.buyback_leaf));
                    lots_out.push_back(lo);
                }
            }
            result.pushKV("lots", lots_out);
            return result;
        },
    };
}

RPCHelpMan optionseries_verify()
{
    return RPCHelpMan{
        "optionseries.verify",
        "Pre-purchase fraud check for a tokenized option series (OPTION_TOKENIZATION.md §3). Given the "
        "asset_id a buyer intends to purchase and the series' published terms (as the raw descriptor, "
        "the on-chain ICU TSC-ICU-META-1 metadata, or the terms object), confirm the terms are "
        "AUTHENTIC: asset_id IS the tagged hash of the descriptor, so a swapped or forged term set "
        "cannot match the asset being bought. Returns the decoded terms and the backing the buyer must "
        "then confirm is funded on chain (N lot vaults, each at the per-lot IM). Read-only; any node.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte asset_id being purchased"},
            {"terms_source", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Exactly one published source of the terms",
                {
                    {"descriptor", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The §2 descriptor bytes (hex)"},
                    {"icu_metadata", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw TSC-ICU-META-1 container bytes (hex) from the ICU"},
                    {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "The series terms (same shape as optionseries.derive)",
                        {
                            {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"check_backing", RPCArg::Type::BOOL, RPCArg::Default{false},
                        "Also confirm the series is fully backed on chain: issued_total == N and each derived lot vault "
                        "is an unspent UTXO of lot_im_sats. Performs a full UTXO-set scan (heavy, like scantxoutset)."},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "authentic", "true iff the descriptor's tagged hash equals asset_id"},
                {RPCResult::Type::BOOL, "terms_valid", "true iff the decoded terms pass structural validation"},
                {RPCResult::Type::STR, "reason", "empty when authentic and terms_valid, else why it failed"},
                {RPCResult::Type::STR_HEX, "asset_id", "The asset_id supplied by the caller (lowercased)"},
                {RPCResult::Type::STR_HEX, "recomputed_asset_id", "Descriptor hash in the option-series canonical (forward) hex"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "Same bytes in the registry display (reverse) hex; either form is accepted as asset_id"},
                {RPCResult::Type::STR_HEX, "descriptor", "The §2 descriptor bytes that were checked"},
                {RPCResult::Type::ANY, "terms", "The decoded series terms"},
                {RPCResult::Type::ANY, "backing", "What must be funded on chain for the series to be real (plus an `on_chain` scan result when check_backing is set)"},
            }},
        RPCExamples{HelpExampleCli("optionseries.verify",
            "\"c4ed91972ef3...\" '{\"descriptor\":\"010001...\"}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            // Accept asset_id in EITHER hex convention for the same 32 bytes: the option-series
            // canonical HexStr(series_id) (forward, == descriptor hash) OR the registry/display form
            // (uint256::GetHex, reverse) that a buyer copies from getassetinfo / a market listing.
            if (!request.params[0].isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be a string");
            const std::string asset_id_hex = ToLower(request.params[0].get_str());
            if (!IsHex(asset_id_hex) || asset_id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be 32-byte hex");
            }
            const std::vector<unsigned char> descriptor = ExtractOptionSeriesDescriptorFromSource(request.params[1]);

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", asset_id_hex);
            result.pushKV("descriptor", HexStr(descriptor));

            auto parsed = ParseOptionSeriesDescriptor(descriptor);
            if (!parsed) {
                result.pushKV("authentic", false);
                result.pushKV("terms_valid", false);
                result.pushKV("recomputed_asset_id", "");
                result.pushKV("registry_asset_id", "");
                result.pushKV("reason", "source is not a valid option-series descriptor (v1 = 103 bytes, v2 = 104 bytes)");
                return result;
            }

            const uint256 recomputed = ComputeOptionSeriesId(*parsed);
            const std::string canonical_hex = HexStr(recomputed);
            const std::string registry_hex = OptionSeriesRegistryIdHex(recomputed);
            const bool authentic = (asset_id_hex == canonical_hex || asset_id_hex == registry_hex);
            result.pushKV("recomputed_asset_id", canonical_hex);
            result.pushKV("registry_asset_id", registry_hex);
            result.pushKV("authentic", authentic);

            std::string verr;
            const bool terms_valid = ValidateOptionSeriesTerms(*parsed, /*pow_limit=*/nullptr, verr);
            result.pushKV("terms_valid", terms_valid);
            result.pushKV("terms", OptionSeriesTermsToJson(*parsed));

            // The backing a buyer must then confirm is funded on chain: N vaults, each at the per-lot IM.
            UniValue backing(UniValue::VOBJ);
            backing.pushKV("lot_count", static_cast<int64_t>(parsed->lot_count));
            backing.pushKV("per_lot_im_sats", static_cast<int64_t>(parsed->lot_im_sats));
            backing.pushKV("payout_cap_per_lot_sats", static_cast<int64_t>(parsed->lot_im_sats));
            backing.pushKV("total_collateral_sats",
                terms_valid ? static_cast<int64_t>(parsed->lot_count) * static_cast<int64_t>(parsed->lot_im_sats) : 0);

            // Opt-in on-chain backing scan (any node, no wallet): issued_total == N and each derived
            // lot vault is an unspent UTXO of exactly lot_im_sats.
            bool check_backing = false;
            const UniValue& vopts = request.params[2];
            if (vopts.isObject() && !vopts.find_value("check_backing").isNull()) {
                check_backing = vopts.find_value("check_backing").get_bool();
            }
            if (check_backing && terms_valid) {
                const uint256 series_id = recomputed;
                // Re-derive the N lot-vault scriptPubKeys as scan needles.
                std::set<CScript> needles;
                for (uint32_t i = 0; i < parsed->lot_count; ++i) {
                    needles.insert(DeriveOptionLot(*parsed, series_id, i).vault_spk);
                }

                node::NodeContext& node_ctx = EnsureAnyNodeContext(request.context);
                ChainstateManager& chainman = EnsureChainman(node_ctx);

                // Get a consistent UTXO-DB cursor under cs_main (after flushing the cache), then scan
                // it WITHOUT the lock (the cursor is a snapshot) — the scantxoutset pattern.
                AssetRegistryEntry entry;
                bool registered = false;
                std::unique_ptr<CCoinsViewCursor> cursor;
                {
                    LOCK(cs_main);
                    Chainstate& active = chainman.ActiveChainstate();
                    registered = active.CoinsTip().ReadAssetPolicy(series_id, entry);
                    active.ForceFlushStateToDisk();
                    cursor = active.CoinsDB().Cursor();
                }
                int funded = 0; // vaults present as unspent NATIVE UTXOs of EXACTLY lot_im_sats
                int64_t scanned = 0;
                while (cursor->Valid()) {
                    COutPoint key;
                    Coin coin;
                    if (!cursor->GetKey(key) || !cursor->GetValue(coin)) break;
                    if (++scanned % 8192 == 0) node_ctx.rpc_interruption_point();
                    // A vault must be NATIVE (no asset tag) — settlement / record_issue both reject
                    // asset-tagged outputs at the vault SPK, so an asset-tagged UTXO is NOT backing.
                    if (!coin.IsSpent() && !coin.out.HasAssetTLV() &&
                        coin.out.nValue == parsed->lot_im_sats &&
                        needles.count(coin.out.scriptPubKey)) {
                        ++funded;
                    }
                    cursor->Next();
                }
                // Prove the full §2.5 registry invariants INDEPENDENTLY (a buyer cannot assume
                // build_register/build_issue were used): cap N, decimals 0, MINT set, no BURN, quorum 0,
                // public ICU, P2TR allowed.
                const bool invariants_ok = registered
                    && entry.issuance_cap_units == parsed->lot_count
                    && entry.decimals == 0
                    && (entry.policy_bits & assets::MINT_ALLOWED)
                    && !(entry.policy_bits & assets::BURN_ALLOWED)
                    && entry.policy_quorum_bps == 0
                    && entry.icu_visibility == 0
                    && (entry.allowed_spk_families & assets::SPK_P2TR);
                const bool issued_ok = registered && entry.issued_total == parsed->lot_count;
                const bool vaults_ok = (funded == static_cast<int>(parsed->lot_count));

                UniValue scan(UniValue::VOBJ);
                scan.pushKV("registered", registered);
                scan.pushKV("issued_total", registered ? static_cast<int64_t>(entry.issued_total) : 0);
                scan.pushKV("invariants_ok", invariants_ok);
                scan.pushKV("vaults_funded", funded);
                scan.pushKV("vaults_expected", static_cast<int64_t>(parsed->lot_count));
                // Gate on `authentic`: if the caller's asset_id doesn't match this descriptor, the scan
                // (of the descriptor's series) is irrelevant to what they asked about.
                scan.pushKV("verified", authentic && invariants_ok && issued_ok && vaults_ok);
                backing.pushKV("on_chain", scan);
            }
            result.pushKV("backing", backing);

            std::string reason;
            if (!authentic) reason = "descriptor does not hash to asset_id (terms do not match the asset being purchased)";
            else if (!terms_valid) reason = "terms malformed: " + verr;
            result.pushKV("reason", reason);
            return result;
        },
    };
}

} // namespace

void RegisterOptionSeriesRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &optionseries_derive},
        {"blockchain", &optionseries_verify},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
