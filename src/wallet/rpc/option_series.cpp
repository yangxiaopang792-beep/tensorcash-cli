// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wallet-only option-series RPCs. optionseries.build_register always creates a ROOT.SUFFIX sponsored
// child under an existing parent namespace; the read-only optionseries.derive / verify are core RPCs
// (rpc/option_series.cpp), and the shared derivation + param parsing live in bitcoin_common
// (wallet/option_series.{h,cpp}).

#include <addresstype.h>       // WitnessV1Taproot
#include <assets/asset.h>      // MINT_ALLOWED, BURN_ALLOWED
#include <assets/icu_payload.h> // CanonicalIcuPayload
#include <assets/registry.h>   // AssetRegistryEntry
#include <chainparams.h>       // Params (powLimit)
#include <consensus/amount.h>  // CAmount
#include <consensus/consensus.h> // WITNESS_SCALE_FACTOR
#include <consensus/difficulty_cfd.h> // DIFFCFD_MATURITY_DEPTH
#include <core_io.h>           // ValueFromAmount
#include <key_io.h>            // EncodeDestination
#include <node/context.h>      // NodeContext
#include <key.h>               // CKey
#include <policy/feerate.h>    // CFeeRate
#include <policy/policy.h>     // MAX_COVENANT_TX_OUTPUTS, GetVirtualTransactionSize
#include <psbt.h>              // PartiallySignedTransaction, PSBTInputSignedAndVerified
#include <random.h>            // GetRandHash
#include <script/interpreter.h> // SignatureHashSchnorr, ComputeTapleafHash, ScriptExecutionData
#include <script/signingprovider.h> // FlatSigningProvider, TaprootSpendData
#include <wallet/coinselection.h> // COutput
#include <wallet/scriptpubkeyman.h> // DescriptorScriptPubKeyMan
#include <rpc/server.h>
#include <rpc/server_util.h>   // EnsureChainman
#include <rpc/util.h>          // HelpExampleCli
#include <serialize.h>         // GetSizeOfCompactSize
#include <streams.h>           // DataStream
#include <primitives/transaction.h> // CTransactionRef, CTxOut
#include <sync.h>              // LOCK, cs_main
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/moneystr.h>     // FormatMoney
#include <util/strencodings.h> // HexStr, ToUpper
#include <util/transaction_identifier.h> // Txid
#include <validation.h>        // ChainstateManager, cs_main
#include <wallet/coincontrol.h> // CCoinControl, PreselectedInput
#include <wallet/context.h>    // WalletContext
#include <wallet/option_series.h>
#include <wallet/rpc/util.h>   // EnsureWalletContext, GetWalletForJSONRPCRequest
#include <wallet/spend.h>      // FundTransaction
#include <wallet/wallet.h>     // CWallet::GetWalletTx / GetTxDepthInMainChain / RegisterOptionSeries

#include <algorithm>          // std::sort
#include <cstdlib>             // std::stoul
#include <limits>             // std::numeric_limits
#include <set>
#include <string>
#include <vector>

namespace wallet {

namespace {
const std::string& RequireStr(const UniValue& v, const std::string& name)
{
    if (!v.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a string");
    return v.get_str();
}

// Weight of a keyless taproot script-path input (replicated from difficulty.cpp — not exported).
int64_t OptionScriptPathInputWeight(size_t script_size, size_t control_block_size, size_t signature_elements)
{
    constexpr int64_t BASE_NONWITNESS_WEIGHT = (32 + 4 + 1 + 4) * WITNESS_SCALE_FACTOR;
    int64_t weight = BASE_NONWITNESS_WEIGHT;
    const size_t stack_elems = signature_elements + 2; // sigs + script + control
    weight += GetSizeOfCompactSize(stack_elems);
    constexpr size_t TAPROOT_SIG_SIZE = 65;
    for (size_t i = 0; i < signature_elements; ++i) {
        weight += GetSizeOfCompactSize(TAPROOT_SIG_SIZE) + TAPROOT_SIG_SIZE;
    }
    weight += GetSizeOfCompactSize(script_size) + script_size;
    weight += GetSizeOfCompactSize(control_block_size) + control_block_size;
    return weight;
}

std::string OptionSeriesHumanText(const OptionSeriesTerms& terms, const uint256& series_id, const std::string& ticker_hint)
{
    return strprintf(
        "TSC option series %s\n"
        "\n"
        "This ICU describes a tokenized, fully collateralized option series. The binding machine terms "
        "are the TSC-ICU-OPTSERIES-1 descriptor in this payload metadata; this text is a readable summary "
        "of the same fields.\n"
        "\n"
        "Option kind: %s\n"
        "Canonical option asset id: %s\n"
        "Writer / issuer key: %s\n"
        "Strike nBits: %u\n"
        "Fixing height: %u\n"
        "Settlement lock height: %u\n"
        "Lambda Q16: %u\n"
        "Lots: %u\n"
        "Collateral per lot: %s TSC (%d sats)\n"
        "Total collateral required at issuance: %s TSC (%d sats)\n"
        "Reference premium: %s TSC (%d sats)\n"
        "Issuance model: self-issuance; all units are minted to the writer, then sold on market.\n"
        "Redemption: one option unit retires to the lot sink to sweep the matching settlement pot.",
        ticker_hint,
        terms.direction == OPTION_DIRECTION_PUT
            ? "PUT (long holder profits as difficulty falls below strike)"
            : "CALL (long holder profits as difficulty rises above strike)",
        HexStr(series_id),
        HexStr(terms.writer_key),
        terms.strike_nbits,
        terms.fixing_height,
        terms.settle_lock_height,
        terms.lambda_q,
        terms.lot_count,
        FormatMoney(terms.lot_im_sats), terms.lot_im_sats,
        FormatMoney(terms.lot_im_sats * static_cast<CAmount>(terms.lot_count)),
        terms.lot_im_sats * static_cast<CAmount>(terms.lot_count),
        FormatMoney(terms.reference_premium_sats), terms.reference_premium_sats);
}

// Emit the series terms in the EXACT shape ParseOptionSeriesTermsFromJson accepts (writer_key/salt as
// natural-order hex, amounts as decimal via ValueFromAmount), so a tool — e.g. the Qt lifecycle panel —
// can round-trip a recorded series straight back into build_settlement / build_redeem / build_buyback.
UniValue OptionSeriesTermsToParseJson(const OptionSeriesTerms& t)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("descriptor_version", static_cast<int64_t>(t.descriptor_version));
    o.pushKV("issuance_mode", static_cast<int64_t>(t.issuance_mode));
    o.pushKV("leaf_set", static_cast<int64_t>(t.leaf_set));
    o.pushKV("writer_key", HexStr(t.writer_key));
    o.pushKV("strike_nbits", static_cast<int64_t>(t.strike_nbits));
    o.pushKV("fixing_height", static_cast<int64_t>(t.fixing_height));
    o.pushKV("settle_lock_height", static_cast<int64_t>(t.settle_lock_height));
    o.pushKV("lambda_q", static_cast<int64_t>(t.lambda_q));
    o.pushKV("lot_im", ValueFromAmount(t.lot_im_sats));
    o.pushKV("lot_count", static_cast<int64_t>(t.lot_count));
    o.pushKV("reference_premium", ValueFromAmount(t.reference_premium_sats));
    o.pushKV("series_salt", HexStr(t.series_salt));
    o.pushKV("direction", static_cast<int64_t>(t.direction));
    return o;
}

} // namespace

// Defined in wallet/rpc/assets.cpp; composed (not duplicated) for the funded tx assembly.
RPCHelpMan sponsorchildasset();
RPCHelpMan mintasset();

RPCHelpMan optionseries_build_register()
{
    return RPCHelpMan{
        "optionseries.build_register",
        "Register the asset shell for a tokenized option series (self-issuance) as a sponsored child "
        "ROOT.SUFFIX under an existing parent namespace. This RPC never creates a standalone/root option "
        "asset. It composes sponsorchildasset with the OPTION_TOKENIZATION.md §2.5 invariants hard-set: "
        "asset bytes == series_id == TaggedHash(descriptor); decimals 0; issuance cap N (= lot_count); "
        "MINT_ALLOWED with no burn; governance quorum 0 (immutable). The child ICU carries both a "
        "human-readable terms summary and the canonical TSC-ICU-META-1 metadata band so buyers can "
        "verify the series on chain. Does NOT mint units (that is optionseries.build_issue).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The series terms (same shape as optionseries.derive)",
                {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"},
                }},
            {"root", RPCArg::Type::STR, RPCArg::Optional::NO, "Existing sponsoring root ticker"},
            {"suffix", RPCArg::Type::STR, RPCArg::Optional::NO, "Child suffix; the registered series ticker becomes ROOT.SUFFIX"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"child_bond_sats", RPCArg::Type::NUM, RPCArg::Default{10000}, "Child ICU bond in sats (>= SponsoredChildMinIcuBond)"},
                    {"parent_icu_outpoint", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional parent ICU outpoint override txid:vout"},
                    {"parent_successor_destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional address for the recreated parent ICU"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "series_id (option-series canonical hex; descriptor/verify convention)"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "Same asset in the registry's display hex (use for getassetinfo/getassetpolicy/geticupayload)"},
                {RPCResult::Type::STR_HEX, "descriptor", "The §2 descriptor bytes"},
                {RPCResult::Type::STR_HEX, "icu_metadata", "The canonical TSC-ICU-META-1 band committed in the ICU"},
                {RPCResult::Type::STR, "icu_text", "Human-readable ICU terms summary committed with the payload"},
                {RPCResult::Type::STR, "ticker", "The series ticker"},
                {RPCResult::Type::NUM, "lot_count", "N"},
                {RPCResult::Type::NUM, "issuance_cap_units", "Supply cap (= N, decimals 0)"},
                {RPCResult::Type::ANY, "registration", "The underlying sponsorchildasset result (txid/hex)"},
            }},
        RPCExamples{HelpExampleCli("optionseries.build_register",
            "'{\"writer_key\":\"79be667e...\",...}' \"ACME\" \"C150K\" '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);
            std::string verr;
            // Gate the strike against the chain powLimit at REGISTRATION — otherwise a difficulty strike
            // below the difficulty floor (target > powLimit) registers and tokenizes fine, then can never
            // settle (BuildOptionSettlementSkeleton re-checks DeriveTarget with the real powLimit and
            // rejects), stranding the collateral. Mirror difficulty.cpp, which passes &pow_limit at propose.
            const uint256 pow_limit = Params().GetConsensus().powLimit;
            if (!ValidateOptionSeriesTerms(terms, &pow_limit, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }
            const std::string root = ToUpper(RequireStr(request.params[1], "root"));
            const std::string suffix = ToUpper(RequireStr(request.params[2], "suffix"));
            if (!assets::IsRootTicker(root)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "root must be an existing root ticker, not an asset id or child ticker");
            }
            if (!assets::IsRootTicker(suffix)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "suffix must use root-ticker grammar [A-Z][A-Z0-9]{2,10}");
            }
            const std::string ticker_hint = root + "." + suffix;

            // §2.5 self-issuance: the ICU controller IS the descriptor writer. Derive the ICU
            // destination from terms.writer_key rather than accept an arbitrary address, so the ICU
            // controller can never diverge from the committed writer key.
            const std::string icu_address = EncodeDestination(WitnessV1Taproot{terms.writer_key});

            bool broadcast = false;
            UniValue fee_rate(UniValue::VNULL);
            UniValue child_bond_sats(UniValue::VNULL);
            UniValue parent_icu_outpoint(UniValue::VNULL);
            UniValue parent_successor_destination(UniValue::VNULL);
            const UniValue& opts = request.params[3];
            if (opts.isObject()) {
                child_bond_sats = opts.find_value("child_bond_sats");
                parent_icu_outpoint = opts.find_value("parent_icu_outpoint");
                parent_successor_destination = opts.find_value("parent_successor_destination");
                if (!opts.find_value("broadcast").isNull()) broadcast = opts.find_value("broadcast").get_bool();
                fee_rate = opts.find_value("fee_rate");
            }

            const uint256 series_id = ComputeOptionSeriesId(terms);
            const std::vector<unsigned char> descriptor = SerializeOptionDescriptor(terms);
            const std::vector<unsigned char> band = BuildOptionSeriesIcuMetadata(terms);

            // Canonical ICU payload: a public human note + the committed machine band in `metadata`.
            assets::CanonicalIcuPayload payload;
            payload.version = 1;
            payload.compression = 0;
            payload.encryption_mode = 0;
            payload.visibility = 0; // public — the descriptor band must be openly verifiable
            const std::string human = OptionSeriesHumanText(terms, series_id, ticker_hint);
            payload.canonical_text.assign(human.begin(), human.end());
            const std::string witness = "{}";
            payload.witness_bundle.assign(witness.begin(), witness.end());
            payload.metadata = band;
            const std::vector<unsigned char> icu_plain = payload.Serialize();

            // Compose sponsorchildasset. There is deliberately no registerasset fallback here:
            // every option series is a unique child under an existing parent root.
            UniValue child_opts(UniValue::VOBJ);
            child_opts.pushKV("autofund", true);
            child_opts.pushKV("broadcast", broadcast);
            if (!fee_rate.isNull()) child_opts.pushKV("fee_rate", fee_rate);
            if (!child_bond_sats.isNull()) child_opts.pushKV("child_bond_sats", child_bond_sats);
            if (!parent_icu_outpoint.isNull()) child_opts.pushKV("parent_icu_outpoint", parent_icu_outpoint);
            if (!parent_successor_destination.isNull()) child_opts.pushKV("parent_successor_destination", parent_successor_destination);
            child_opts.pushKV("icu_payload_plain", HexStr(icu_plain));
            child_opts.pushKV("icu_visibility", 0);
            child_opts.pushKV("issuance_cap_units", static_cast<int64_t>(terms.lot_count)); // N units, decimals 0
            child_opts.pushKV("policy_quorum_bps", 0); // immutable governance
            child_opts.pushKV("policy_bits", static_cast<int64_t>(assets::MINT_ALLOWED)); // mint, no burn
            child_opts.pushKV("allowed_spk_families", 28); // P2WPKH | P2WSH | P2TR
            child_opts.pushKV("decimals", 0);

            UniValue child_params(UniValue::VARR);
            child_params.push_back(root);                                      // [0] sponsoring root ticker
            child_params.push_back(suffix);                                    // [1] child suffix
            child_params.push_back(OptionSeriesRegistryIdHex(series_id));      // [2] child asset id, byte-exact
            child_params.push_back(icu_address);                               // [3] child ICU destination = writer
            child_params.push_back(child_opts);                                // [4] options

            JSONRPCRequest child_req;
            child_req.context = request.context;
            child_req.URI = request.URI;
            child_req.strMethod = "sponsorchildasset";
            child_req.params = child_params;
            const UniValue child_result = sponsorchildasset().HandleRequest(child_req);

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", HexStr(series_id));                  // option-series canonical (descriptor/verify convention)
            result.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(series_id)); // registry display convention (getassetinfo/policy/geticupayload lookups)
            result.pushKV("descriptor", HexStr(descriptor));
            result.pushKV("icu_metadata", HexStr(band));
            result.pushKV("icu_text", human);
            if (const UniValue& child_ticker = child_result.find_value("child_ticker"); child_ticker.isStr()) {
                result.pushKV("ticker", child_ticker.get_str());
            } else {
                result.pushKV("ticker", ticker_hint);
            }
            result.pushKV("lot_count", static_cast<int64_t>(terms.lot_count));
            result.pushKV("issuance_cap_units", static_cast<int64_t>(terms.lot_count));
            result.pushKV("registration", child_result);
            return result;
        },
    };
}

RPCHelpMan optionseries_build_issue()
{
    return RPCHelpMan{
        "optionseries.build_issue",
        "Issue a registered option series (self-issuance, tx2). Mints all N units to the writer AND "
        "funds the N derived lot vaults (lot_im_sats each) in one transaction, by composing mintasset "
        "with the lot vaults as native extra outputs. The series MUST already be registered and "
        "CONFIRMED (optionseries.build_register); build_issue reads the registry directly, uses the "
        "registry's current ICU outpoint, and preserves the TSC-ICU-META-1 band by commit-continuity "
        "(reuses the registry icu_ctxt_commit / icu_plain_commit; no new ICU payload). Does NOT persist "
        "the series record (that is optionseries.record_issue, next slice).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The series terms (same shape as optionseries.derive)",
                {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "series_id (option-series canonical hex)"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "Same asset in the registry's display hex (registry RPC lookups)"},
                {RPCResult::Type::NUM, "lot_count", "N units minted = N vaults funded"},
                {RPCResult::Type::NUM, "per_lot_im_sats", "Collateral per vault"},
                {RPCResult::Type::ARR, "vault_spks", "The N derived lot-vault scriptPubKeys (hex), in lot order",
                    {{RPCResult::Type::STR_HEX, "", "vault scriptPubKey"}}},
                {RPCResult::Type::ANY, "mint", "The underlying mintasset result (txid/hex)"},
            }},
        RPCExamples{HelpExampleCli("optionseries.build_issue",
            "'{\"writer_key\":\"79be667e...\",...}' '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);
            std::string verr;
            // Same powLimit gate as build_register — refuse to mint units against an out-of-range strike.
            const uint256 pow_limit = Params().GetConsensus().powLimit;
            if (!ValidateOptionSeriesTerms(terms, &pow_limit, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }
            // This builder only implements SELF-issuance (mint N to writer; no premium->writer output,
            // no buyer funding). A descriptor committed as BILATERAL must NOT be silently self-issued
            // here — that would drop the premium and the mint-to-buyer. Reject until bilateral lands.
            if (terms.issuance_mode != OPTION_ISSUANCE_SELF) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "optionseries.build_issue only supports self-issuance (issuance_mode=0); "
                    "bilateral cosign issuance is not yet implemented");
            }
            const uint256 series_id = ComputeOptionSeriesId(terms);
            const uint64_t N = terms.lot_count;

            // Output-count preflight BEFORE funding: N vaults + ICU + token + change must fit the cap.
            if (N + 3 > MAX_COVENANT_TX_OUTPUTS) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("lot_count %llu too large to issue in one tx (cap %u outputs; batched issuance is a later slice)",
                              (unsigned long long)N, MAX_COVENANT_TX_OUTPUTS));
            }

            // After the byte-order fix (OnChainAssetIdHex) the asset is registered under series_id
            // itself (natural bytes), so the registry key IS series_id — no hex round-trip.
            const uint256& registry_key = series_id;

            // Read the CONFIRMED registry entry directly from the chainstate (reject if absent: an
            // unconfirmed / unregistered series cannot be issued — no mempool chaining).
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            AssetRegistryEntry entry;
            CAmount icu_value = 0;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                if (!coins.ReadAssetPolicy(registry_key, entry)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Option series is not registered/confirmed on chain; run optionseries.build_register first and let it confirm");
                }
                // The registry's current ICU is the mint authority. Use it (never a user-supplied outpoint).
                const auto icu_coin = coins.GetCoin(entry.icu_outpoint);
                if (!icu_coin || icu_coin->IsSpent()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Registry ICU outpoint is missing or spent (already issued/rotated?)");
                }
                icu_value = icu_coin->out.nValue;
            }

            // Preflight the §2.5 invariants (reject anything that is not a pristine, issuable series).
            if (entry.issued_total != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Series already issued (issued_total != 0)");
            if (entry.issuance_cap_units != N) throw JSONRPCError(RPC_INVALID_PARAMETER, "Registry issuance cap does not equal lot_count");
            if (entry.decimals != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Series asset must have decimals 0");
            if (!(entry.policy_bits & assets::MINT_ALLOWED)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Series asset is not MINT_ALLOWED");
            if (entry.policy_bits & assets::BURN_ALLOWED) throw JSONRPCError(RPC_INVALID_PARAMETER, "Series asset must not be BURN_ALLOWED");
            if (entry.policy_quorum_bps != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Series governance quorum must be 0 (immutable)");
            if (entry.icu_visibility != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Series ICU must be public (visibility 0)");

            // Derive the N lot vaults internally from terms (never caller-supplied scripts).
            UniValue extra_native(UniValue::VARR);
            UniValue vault_spks(UniValue::VARR);
            for (uint32_t i = 0; i < N; ++i) {
                const OptionLot lot = DeriveOptionLot(terms, series_id, i);
                UniValue v(UniValue::VOBJ);
                v.pushKV("scriptPubKey", HexStr(lot.vault_spk));
                v.pushKV("amount", ValueFromAmount(terms.lot_im_sats));
                extra_native.push_back(v);
                vault_spks.push_back(HexStr(lot.vault_spk));
            }

            // The writer holds the ICU (rotate the successor back to it) and receives the N minted units.
            const std::string writer_addr = EncodeDestination(WitnessV1Taproot{terms.writer_key});

            bool broadcast = false;
            UniValue fee_rate(UniValue::VNULL);
            const UniValue& opts = request.params[1];
            if (opts.isObject()) {
                if (!opts.find_value("broadcast").isNull()) broadcast = opts.find_value("broadcast").get_bool();
                fee_rate = opts.find_value("fee_rate");
            }

            // Compose mintasset: mint N to writer + rotate ICU + fund the N vaults, preserving every
            // registry invariant (cap, quorum, ICU commits → band continuity) so the only state change
            // is the supply delta +N.
            UniValue mint_opts(UniValue::VOBJ);
            mint_opts.pushKV("autofund", true);
            mint_opts.pushKV("broadcast", broadcast);
            if (!fee_rate.isNull()) mint_opts.pushKV("fee_rate", fee_rate);
            mint_opts.pushKV("extra_native_outputs", extra_native);
            mint_opts.pushKV("issuance_cap_units", static_cast<int64_t>(N));
            mint_opts.pushKV("policy_quorum_bps", static_cast<int64_t>(entry.policy_quorum_bps));
            mint_opts.pushKV("icu_visibility", static_cast<int64_t>(entry.icu_visibility));
            mint_opts.pushKV("icu_flags", static_cast<int64_t>(entry.icu_flags));
            mint_opts.pushKV("icu_ctxt_commit", entry.icu_ctxt_commit.GetHex());   // band continuity
            mint_opts.pushKV("icu_plain_commit", entry.icu_plain_commit.GetHex());
            mint_opts.pushKV("kdf_salt", HexStr(entry.kdf_salt));

            UniValue mint_params(UniValue::VARR);
            mint_params.push_back(entry.icu_outpoint.hash.GetHex());                  // [0] icu_txid
            mint_params.push_back(static_cast<int64_t>(entry.icu_outpoint.n));        // [1] icu_vout
            mint_params.push_back(writer_addr);                                       // [2] icu_address (rotate to writer)
            mint_params.push_back(ValueFromAmount(icu_value));                        // [3] icu_amount (maintain bond)
            mint_params.push_back(writer_addr);                                       // [4] asset_address (mint to writer)
            mint_params.push_back(ValueFromAmount(546));                              // [5] asset_amount_btc (dust)
            mint_params.push_back(OptionSeriesRegistryIdHex(series_id));                      // [6] asset_id (byte-exact == vault covenants)
            mint_params.push_back(static_cast<int64_t>(N));                           // [7] asset_units = N
            mint_params.push_back(static_cast<int64_t>(entry.policy_bits));           // [8] policy_bits
            mint_params.push_back(static_cast<int64_t>(entry.allowed_spk_families));  // [9] allowed_spk_families
            mint_params.push_back(static_cast<int64_t>(entry.unlock_fees_sats));      // [10] unlock_fees_sats
            mint_params.push_back(mint_opts);                                         // [11] options

            JSONRPCRequest mint_req;
            mint_req.context = request.context;
            mint_req.URI = request.URI;
            mint_req.strMethod = "mintasset";
            mint_req.params = mint_params;
            const UniValue mint_result = mintasset().HandleRequest(mint_req);

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", HexStr(series_id));                  // option-series canonical
            result.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(series_id)); // registry lookup convention
            result.pushKV("lot_count", static_cast<int64_t>(N));
            result.pushKV("per_lot_im_sats", static_cast<int64_t>(terms.lot_im_sats));
            result.pushKV("vault_spks", vault_spks);
            result.pushKV("mint", mint_result);
            return result;
        },
    };
}

RPCHelpMan optionseries_record_issue()
{
    return RPCHelpMan{
        "optionseries.record_issue",
        "Persist a confirmed option-series issuance into the wallet (after optionseries.build_issue). "
        "Resolves the N lot-vault outpoints from the confirmed issuance tx by their derived "
        "scriptPubKeys (native, value == lot_im_sats), then stores the series record (terms, the N vault "
        "outpoints, the issue txid, the current ICU outpoint) so settlement / redemption can find it "
        "after a restart. Requires the series to be registered, fully issued (issued_total == N), and "
        "the issuance tx confirmed in this wallet.",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The series terms (same shape as optionseries.derive)",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"}}},
            {"issue_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The confirmed issuance transaction id (optionseries.build_issue → mint txid)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "series_id (option-series canonical hex)"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "registry lookup convention"},
                {RPCResult::Type::NUM, "lot_count", "N"},
                {RPCResult::Type::STR, "icu_outpoint", "Current ICU outpoint (txid:vout)"},
                {RPCResult::Type::ARR, "lot_vaults", "The N resolved vault outpoints (txid:vout)",
                    {{RPCResult::Type::STR, "", "outpoint"}}},
                {RPCResult::Type::BOOL, "persisted", "true when the series record was stored"},
            }},
        RPCExamples{HelpExampleCli("optionseries.record_issue", "'{\"writer_key\":\"79be667e...\",...}' \"<issue_txid>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);
            std::string verr;
            // Same powLimit gate — a recorded external issuance must also carry an in-range strike.
            const uint256 pow_limit = Params().GetConsensus().powLimit;
            if (!ValidateOptionSeriesTerms(terms, &pow_limit, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }
            const uint256 series_id = ComputeOptionSeriesId(terms);
            const uint64_t N = terms.lot_count;

            const uint256 issue_txid_u = ParseHashV(request.params[1], "issue_txid");
            const Txid issue_txid = Txid::FromUint256(issue_txid_u);

            // Confirmed registry read: issued_total must == N (proves the issuance confirmed), and the
            // current ICU successor must be an output of issue_txid (mintasset rotated it there).
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            AssetRegistryEntry entry;
            {
                LOCK(cs_main);
                if (!chainman.ActiveChainstate().CoinsTip().ReadAssetPolicy(series_id, entry)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Option series not registered/confirmed on chain");
                }
            }
            if (entry.issued_total != N) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Series not fully issued (issued_total %llu != lot_count %llu); run optionseries.build_issue and let it confirm",
                              (unsigned long long)entry.issued_total, (unsigned long long)N));
            }
            if (entry.icu_outpoint.hash != issue_txid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Registry ICU successor is not an output of issue_txid (wrong txid or rotated since issuance)");
            }

            // Resolve the issuance tx from the wallet (it created + broadcast it) and require confirmation.
            CTransactionRef tx;
            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(issue_txid);
                if (!wtx) throw JSONRPCError(RPC_INVALID_PARAMETER, "issue_txid is not a transaction in this wallet");
                if (pwallet->GetTxDepthInMainChain(*wtx) < 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "issue_txid is not confirmed yet");
                }
                tx = wtx->tx;
            }

            OptionSeriesRecord record;
            record.series_id = series_id;
            record.terms = terms;
            record.icu_outpoint = entry.icu_outpoint;
            record.issue_txid = issue_txid_u; // register_txid left null (provenance, not coherence-checked)

            UniValue lot_vaults(UniValue::VARR);
            for (uint32_t i = 0; i < N; ++i) {
                const OptionLot lot = DeriveOptionLot(terms, series_id, i);
                int found = -1;
                for (size_t v = 0; v < tx->vout.size(); ++v) {
                    const CTxOut& o = tx->vout[v];
                    if (!o.HasAssetTLV() && o.scriptPubKey == lot.vault_spk && o.nValue == terms.lot_im_sats) {
                        if (found >= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("lot %u vault scriptPubKey is ambiguous in the issue tx", i));
                        found = static_cast<int>(v);
                    }
                }
                if (found < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("lot %u vault not found in the issue tx (wrong terms or txid)", i));
                record.lot_vaults.emplace_back(issue_txid, static_cast<uint32_t>(found));
                lot_vaults.push_back(strprintf("%s:%u", issue_txid.GetHex(), static_cast<uint32_t>(found)));
            }

            // RegisterOptionSeries validates coherence (issue_txid, icu/vault txids, count, dups, no-null)
            // and persists; it throws on any inconsistency.
            pwallet->RegisterOptionSeries(record);

            UniValue result(UniValue::VOBJ);
            result.pushKV("asset_id", HexStr(series_id));
            result.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(series_id));
            result.pushKV("lot_count", static_cast<int64_t>(N));
            result.pushKV("icu_outpoint", strprintf("%s:%u", entry.icu_outpoint.hash.GetHex(), entry.icu_outpoint.n));
            result.pushKV("lot_vaults", lot_vaults);
            result.pushKV("persisted", true);
            return result;
        },
    };
}

RPCHelpMan optionseries_list()
{
    return RPCHelpMan{
        "optionseries.list",
        "List the option series persisted in this wallet (recorded via optionseries.record_issue). "
        "Reads the wallet's in-memory series map, which is repopulated from disk on load.",
        {},
        RPCResult{RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "asset_id", "series_id (option-series canonical hex)"},
                    {RPCResult::Type::STR_HEX, "registry_asset_id", "registry lookup convention"},
                    {RPCResult::Type::NUM, "lot_count", "N"},
                    {RPCResult::Type::STR_HEX, "issue_txid", "The issuance transaction id"},
                    {RPCResult::Type::STR, "icu_outpoint", "Current ICU outpoint (txid:vout)"},
                    {RPCResult::Type::ARR, "lot_vaults", "The N persisted vault outpoints (txid:vout)",
                        {{RPCResult::Type::STR, "", "outpoint"}}},
                    {RPCResult::Type::ANY, "terms", "The full series terms, ready to pass back into build_settlement / build_redeem / build_buyback"},
                }}}},
        RPCExamples{HelpExampleCli("optionseries.list", "")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            UniValue arr(UniValue::VARR);
            for (const OptionSeriesRecord& rec : pwallet->ListOptionSeries()) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("asset_id", HexStr(rec.series_id));
                o.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(rec.series_id));
                o.pushKV("lot_count", static_cast<int64_t>(rec.terms.lot_count));
                o.pushKV("issue_txid", rec.issue_txid.GetHex());
                o.pushKV("icu_outpoint", strprintf("%s:%u", rec.icu_outpoint.hash.GetHex(), rec.icu_outpoint.n));
                UniValue v(UniValue::VARR);
                for (const COutPoint& op : rec.lot_vaults) v.push_back(strprintf("%s:%u", op.hash.GetHex(), op.n));
                o.pushKV("lot_vaults", v);
                o.pushKV("terms", OptionSeriesTermsToParseJson(rec.terms));
                arr.push_back(o);
            }
            return arr;
        },
    };
}

RPCHelpMan optionseries_build_settlement()
{
    return RPCHelpMan{
        "optionseries.build_settlement",
        "Build the settlement transaction for ONE option-series lot vault (keeper-driven, signatureless "
        "covenant). The lot's fixing height must be buried by DIFFCFD_MATURITY_DEPTH and the settle CLTV "
        "open. The persisted series record is a DISCOVERY HINT only: this reads the LIVE vault UTXO and "
        "the builder re-derives the lot and re-checks the UTXO's script/value/native status, then "
        "recomputes the exact payout from the realized nBits at the fixing height. Returns a PSBT with "
        "the vault input already finalized; keeper flow: sign the fee input (walletprocesspsbt) -> "
        "difficulty.finalize_settlement -> sendrawtransaction (NOT finalizepsbt).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The series terms (same shape as optionseries.derive)",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"}}},
            {"lot_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The lot to settle, in [0, lot_count)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"vault_outpoint", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                        "The lot vault outpoint \"txid:vout\". Lets a third-party KEEPER (who never issued and "
                        "has no wallet record) settle; omit to use this wallet's recorded series."},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64 settlement PSBT (vault input finalized; fee input to be signed)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Fee the wallet added"},
                {RPCResult::Type::STR_AMOUNT, "payout_writer", "Amount returned to the writer (OTM remainder)"},
                {RPCResult::Type::STR_AMOUNT, "payout_pot", "Amount sent to the lot pot (ITM payout)"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the covenant vault input in the funded tx"},
                {RPCResult::Type::NUM, "lot_index", "The settled lot index"},
            }},
        RPCExamples{HelpExampleCli("optionseries.build_settlement", "'{\"writer_key\":\"79be667e...\",...}' 0")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);
            std::string verr;
            if (!ValidateOptionSeriesTerms(terms, /*pow_limit=*/nullptr, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }
            const uint256 series_id = ComputeOptionSeriesId(terms);
            const int64_t lot_index_i = request.params[1].getInt<int64_t>();
            if (lot_index_i < 0 || static_cast<uint64_t>(lot_index_i) >= terms.lot_count) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "lot_index out of range [0, lot_count)");
            }
            const uint32_t lot_index = static_cast<uint32_t>(lot_index_i);

            // DISCOVERY HINT only — settlement is signatureless/keeper-driven, so ANY wallet can build
            // it. The vault outpoint comes from `vault_outpoint` (txid:vout) when given (a third-party
            // keeper who never issued), else from this wallet's persisted record (the issuer convenience).
            // Either way the live UTXO + builder re-checks (spk == derived vault_spk, value, native) are
            // the authority, so a wrong outpoint is rejected.
            const UniValue settle_opts = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
            COutPoint vault_op;
            if (const UniValue& vo = settle_opts.find_value("vault_outpoint"); !vo.isNull()) {
                const std::string s = vo.get_str();
                const size_t colon = s.rfind(':');
                if (colon == std::string::npos) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault_outpoint must be \"txid:vout\"");
                const auto h = uint256::FromHex(s.substr(0, colon));
                if (!h) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault_outpoint txid is not valid hex");
                vault_op = COutPoint(Txid::FromUint256(*h), static_cast<uint32_t>(std::stoul(s.substr(colon + 1))));
            } else {
                const auto rec = pwallet->FindOptionSeries(series_id);
                if (!rec) throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Series not recorded in this wallet; run optionseries.record_issue, or pass options.vault_outpoint (keeper)");
                if (lot_index >= rec->lot_vaults.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Recorded series has no vault for that lot_index");
                vault_op = rec->lot_vaults[lot_index];
            }

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            // Resolve nBits @ fixing_height + enforce burial + read the LIVE vault UTXO (under cs_main,
            // released before FundTransaction which needs cs_wallet).
            uint32_t realized_nbits = 0;
            CTxOut vault_txout;
            {
                LOCK(cs_main);
                const CChain& chain = chainman.ActiveChain();
                const int tip_height = chain.Height();
                const int H = static_cast<int>(terms.fixing_height);
                if (tip_height < 0) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                if (H > tip_height - DIFFCFD_MATURITY_DEPTH) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Fixing height %d is not yet buried by %d (tip %d)", H, DIFFCFD_MATURITY_DEPTH, tip_height));
                }
                // The settlement tx carries nLockTime == settle_lock_height (the leaf's CLTV); it can only
                // enter the next block (height tip+1) once settle_lock_height < tip+1, i.e. <= tip
                // (CheckFinalTxAtTip semantics). Reject early instead of returning a non-final PSBT.
                const int settle_lock = static_cast<int>(terms.settle_lock_height);
                if (settle_lock > tip_height) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Settle-lock height %d not yet reached (tip %d); the settlement CLTV is not open", settle_lock, tip_height));
                }
                const CBlockIndex* pindexH = chain[H];
                if (!pindexH) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("No active-chain block at fixing height %d", H));
                realized_nbits = pindexH->nBits;
                const auto coin = chainman.ActiveChainstate().CoinsTip().GetCoin(vault_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint is missing or already spent");
                vault_txout = coin->out;
            }

            // Build the skeleton (re-derives the lot + re-checks vault_txout: spk == derived, value ==
            // per-lot IM, native-only). Exact payout outputs; vault witness = [settle_leaf, control].
            const uint256 pow_limit = Params().GetConsensus().powLimit;
            DifficultySettlementSkeleton skel;
            std::string serr;
            if (!BuildOptionSettlementSkeleton(terms, lot_index, FundedOutput{vault_op, vault_txout},
                                               realized_nbits, pow_limit, skel, serr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Settlement build failed: " + serr);
            }
            const std::vector<unsigned char>& leaf_bytes = skel.vault_input.scriptWitness.stack.at(0);
            const std::vector<unsigned char>& control = skel.vault_input.scriptWitness.stack.at(1);

            // Settlement payouts: OTM remainder -> writer key; ITM payout -> the derived lot pot key.
            const OptionLot lot = DeriveOptionLot(terms, series_id, lot_index);

            CCoinControl cc;
            cc.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            cc.m_change_type = OutputType::BECH32M;
            if (const UniValue& fr = settle_opts.find_value("fee_rate"); !fr.isNull()) {
                const CAmount fee_rate = AmountFromValue(fr, /*decimals=*/3);
                if (fee_rate <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be greater than 0");
                cc.m_feerate = CFeeRate{fee_rate};
                cc.fOverrideFeeRate = true;
            }
            PreselectedInput& preset = cc.Select(vault_op);
            preset.SetTxOut(vault_txout);
            preset.SetSequence(skel.vault_input.nSequence);
            preset.SetScriptWitness(skel.vault_input.scriptWitness);
            cc.SetInputWeight(vault_op, OptionScriptPathInputWeight(leaf_bytes.size(), control.size(), /*signature_elements=*/0));

            CMutableTransaction tx;
            tx.version = 2;
            tx.nLockTime = skel.nlocktime;
            tx.vin.push_back(skel.vault_input);

            std::vector<CRecipient> recipients;
            if (skel.payout.payout_owner > 0) {
                recipients.push_back({WitnessV1Taproot{terms.writer_key}, static_cast<CAmount>(skel.payout.payout_owner), false});
            }
            if (skel.payout.payout_cp > 0) {
                recipients.push_back({WitnessV1Taproot{lot.pot_key}, static_cast<CAmount>(skel.payout.payout_cp), false});
            }

            auto fund_res = FundTransaction(*pwallet, tx, recipients, /*change_pos=*/std::nullopt,
                                            /*lockUnspents=*/false, cc);
            if (!fund_res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original);
            CMutableTransaction funded{*fund_res->tx};
            const CAmount fee = fund_res->fee;

            int vault_in_idx = -1;
            for (size_t i = 0; i < funded.vin.size(); ++i) {
                if (funded.vin[i].prevout == vault_op) { vault_in_idx = static_cast<int>(i); break; }
            }
            if (vault_in_idx < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx lost the vault input");

            for (auto& vin : funded.vin) { vin.scriptSig.clear(); vin.scriptWitness.SetNull(); }

            PartiallySignedTransaction psbtx{funded};
            bool complete = false;
            if (const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                throw JSONRPCPSBTError(*fill_err);
            }
            PSBTInput& vin_psbt = psbtx.inputs[vault_in_idx];
            vin_psbt.witness_utxo = vault_txout;
            vin_psbt.final_script_witness.stack = {leaf_bytes, control}; // signatureless covenant spend

            DataStream ss;
            ss << psbtx;

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ss.str()));
            result.pushKV("fee", ValueFromAmount(fee));
            result.pushKV("payout_writer", ValueFromAmount(static_cast<CAmount>(skel.payout.payout_owner)));
            result.pushKV("payout_pot", ValueFromAmount(static_cast<CAmount>(skel.payout.payout_cp)));
            result.pushKV("vault_input_index", vault_in_idx);
            result.pushKV("lot_index", static_cast<int64_t>(lot_index));
            return result;
        },
    };
}

namespace {

//! Parse "txid:vout" into a COutPoint (vout decimal, txid reverse/display hex), throwing on malformed input.
COutPoint ParseOutPointStr(const std::string& s, const std::string& field)
{
    const size_t colon = s.rfind(':');
    if (colon == std::string::npos) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be \"txid:vout\"");
    const auto h = uint256::FromHex(s.substr(0, colon));
    if (!h) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " txid is not valid hex");
    int64_t vout = -1;
    try { vout = std::stoll(s.substr(colon + 1)); } catch (const std::exception&) { vout = -1; }
    if (vout < 0 || vout > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, field + " vout is invalid");
    }
    return COutPoint(Txid::FromUint256(*h), static_cast<uint32_t>(vout));
}

//! Sign the wallet (token + native) inputs of a redemption tx and assemble the final transaction.
//! The first `k` inputs are signatureless OP_OUTPUTMATCH_ASSET pot covenants whose witness
//! (`[pot_leaf, control]`) is already in `mtx`; they are extracted as-is — the node validates the
//! covenant against the tx outputs on submission, exactly as build_settlement defers OP_DIFFCFD_SETTLE.
//! EVERY other input must finalize AND verify normally. `spent[i]` is input i's prevout output, in
//! mtx.vin order (pots, then token, then native). Throws on any wallet-input signing/verify failure.
CTransactionRef SignExtractRedemption(CWallet& wallet, CMutableTransaction mtx,
                                      const std::vector<CTxOut>& spent, size_t k)
{
    // Snapshot the signatureless pot witnesses, then strip every witness for a clean PSBT round-trip.
    std::vector<CScriptWitness> pot_witness(k);
    for (size_t i = 0; i < k; ++i) pot_witness[i] = mtx.vin[i].scriptWitness;
    for (auto& vin : mtx.vin) { vin.scriptSig.clear(); vin.scriptWitness.SetNull(); }

    PartiallySignedTransaction psbtx{mtx};
    for (size_t i = 0; i < psbtx.inputs.size(); ++i) psbtx.inputs[i].witness_utxo = spent[i];

    // Sign + finalize the wallet inputs; the pots have no wallet keys so FillPSBT leaves them empty.
    bool complete = false;
    if (const auto fill_err = wallet.FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/true)) {
        throw JSONRPCPSBTError(*fill_err);
    }
    // Re-apply the covenant pot witnesses (signatureless; the node validates them on submission).
    for (size_t i = 0; i < k; ++i) psbtx.inputs[i].final_script_witness = pot_witness[i];

    // Extract: pots [0,k) skip local script verification; wallet inputs MUST be finalized + verified.
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    CMutableTransaction final_mtx{*psbtx.tx};
    for (size_t i = 0; i < final_mtx.vin.size(); ++i) {
        const PSBTInput& in = psbtx.inputs[i];
        if (i >= k && !PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                strprintf("token/native input %u failed to sign and verify", static_cast<unsigned>(i)));
        }
        final_mtx.vin[i].scriptSig = in.final_script_sig;
        final_mtx.vin[i].scriptWitness = in.final_script_witness;
    }
    return MakeTransactionRef(std::move(final_mtx));
}

//! Resolve the wallet's signing material for a Taproot OUTPUT key: the internal private key and the
//! taptweak merkle root, such that `internal_priv.SignSchnorr(hash, sig, &merkle_root)` yields a BIP340
//! signature valid under `output_key` (the bech32m address program). This is how the wallet signs the
//! buy-back leaf CHECKSIG under `writer_key` even though writer_key is the tweaked output key, not a bare
//! keystore key. Returns false if this wallet does not control output_key.
bool GetTaprootOutputKeySigner(CWallet& wallet, const XOnlyPubKey& output_key, CKey& internal_priv, uint256& merkle_root)
{
    const CScript spk = GetScriptForDestination(WitnessV1Taproot{output_key});
    LOCK(wallet.cs_wallet);
    for (ScriptPubKeyMan* spkm : wallet.GetScriptPubKeyMans(spk)) {
        auto* desc = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc) continue;
        std::unique_ptr<FlatSigningProvider> prov = desc->GetSolvingProviderForScript(spk, /*include_private=*/true);
        if (!prov) continue;
        TaprootSpendData spend;
        if (!prov->GetTaprootSpendData(output_key, spend)) continue;
        if (prov->GetKeyByXOnly(spend.internal_key, internal_priv) && internal_priv.IsValid()) {
            merkle_root = spend.merkle_root;
            return true;
        }
    }
    return false;
}

//! Sign the buy-back vault input (index 0). The builder left vin[0] = {<placeholder sig>, leaf, control};
//! this computes the BIP341 TAPSCRIPT sighash over the (output-binding) buy-back leaf and replaces the
//! placeholder with a writer signature. `spent` is the per-input prevout output in vin order. The outputs
//! (and thus the sighash) depend on the fee, so this is re-run on each fixed-point pass.
void SignBuybackVaultInput(CWallet& wallet, CMutableTransaction& mtx,
                           const std::vector<CTxOut>& spent, const XOnlyPubKey& writer_key)
{
    std::vector<std::vector<unsigned char>>& stack = mtx.vin[0].scriptWitness.stack;
    if (stack.size() != 3) throw JSONRPCError(RPC_WALLET_ERROR, "unexpected buy-back witness shape");
    const std::vector<unsigned char> leafvec = stack[1];

    CKey internal_priv;
    uint256 merkle_root;
    if (!GetTaprootOutputKeySigner(wallet, writer_key, internal_priv, merkle_root)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet does not control the writer key; cannot sign the buy-back");
    }

    const CTransaction tx{mtx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leafvec);

    uint256 sighash;
    if (!SignatureHashSchnorr(sighash, execdata, tx, /*in_pos=*/0, SIGHASH_DEFAULT,
                              SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute the buy-back tapscript sighash");
    }
    std::vector<unsigned char> sig(64);
    if (!internal_priv.SignSchnorr(sighash, sig, &merkle_root, GetRandHash())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create the buy-back signature");
    }
    stack[0] = std::move(sig);
}

} // namespace

RPCHelpMan optionseries_build_redeem()
{
    return RPCHelpMan{
        "optionseries.build_redeem",
        "Redeem one or more option-series settlement pots: spend each named pot (a funded ITM payout at "
        "the lot's covenant address) by retiring EXACTLY ONE option unit to that lot's unique sink, and "
        "sweep the pot value to the holder. The holder's token units and native fee inputs are selected "
        "automatically: token UTXOs whose AssetTag carries the raw series_id, and native-only coins for "
        "the fee (ICU / asset UTXOs are never spent). Pots are read LIVE from the UTXO set and the builder "
        "re-derives each lot, rejecting a wrong pot script, an asset-tagged pot, a duplicate lot, or a "
        "duplicate outpoint. The wallet signs its token + native inputs in-process and the finalized raw "
        "transaction is returned (the pots are signatureless covenants validated by the node on submission).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The series terms (same shape as optionseries.derive)",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"}}},
            {"pots", RPCArg::Type::ARR, RPCArg::Optional::NO, "The settlement pots to redeem (one unit retired per pot)",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"lot_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The lot this pot belongs to, in [0, lot_count)"},
                            {"pot", RPCArg::Type::STR, RPCArg::Optional::NO, "The pot outpoint \"txid:vout\""},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                        "Destination for the swept pot value and the token change; default a fresh wallet change address"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB (default 1)"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast the finalized transaction"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The finalized network-serialized transaction"},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id (also the wtxid prefix for lookups)"},
                {RPCResult::Type::STR_HEX, "asset_id", "series_id (option-series canonical hex)"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "registry lookup convention"},
                {RPCResult::Type::ARR, "redeemed_lots", "The lot indices redeemed (one unit each)",
                    {{RPCResult::Type::NUM, "", "lot index"}}},
                {RPCResult::Type::NUM, "units_retired", "Total option units retired to sinks (= number of pots)"},
                {RPCResult::Type::NUM, "token_change_units", "Option units returned to the holder as change"},
                {RPCResult::Type::STR_AMOUNT, "native_sweep", "Native value swept to the holder"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
                {RPCResult::Type::STR, "holder_address", "Where the sweep + token change were sent"},
                {RPCResult::Type::ARR, "sinks", "The per-lot sinks that received one unit",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "lot_index", "lot"},
                            {RPCResult::Type::STR, "address", "sink address"},
                            {RPCResult::Type::STR_HEX, "sink_spk", "sink scriptPubKey"},
                        }}}},
                {RPCResult::Type::OBJ, "inputs", "Input class counts",
                    {
                        {RPCResult::Type::NUM, "pots", "covenant pot inputs"},
                        {RPCResult::Type::NUM, "token", "holder token inputs"},
                        {RPCResult::Type::NUM, "native", "native fee inputs"},
                    }},
                {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast"},
            }},
        RPCExamples{HelpExampleCli("optionseries.build_redeem",
            "'{\"writer_key\":\"79be667e...\",...}' '[{\"lot_index\":0,\"pot\":\"<txid>:1\"}]' '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);
            std::string verr;
            if (!ValidateOptionSeriesTerms(terms, /*pow_limit=*/nullptr, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }
            const uint256 series_id = ComputeOptionSeriesId(terms);

            const UniValue& pots_arg = request.params[1].get_array();
            if (pots_arg.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "pots must list at least one pot");

            const UniValue opts = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();

            // Fee rate (sat/vB -> sat/kvB), default 1 sat/vB.
            CFeeRate feerate{1000};
            if (const UniValue& fr = opts.find_value("fee_rate"); !fr.isNull()) {
                const CAmount fee_rate = AmountFromValue(fr, /*decimals=*/3);
                if (fee_rate <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be greater than 0");
                feerate = CFeeRate{fee_rate};
            }
            bool broadcast = false;
            if (const UniValue& b = opts.find_value("broadcast"); !b.isNull()) broadcast = b.get_bool();

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            // 1) Parse the requested pots and read each one LIVE from the UTXO set. The builder still
            //    re-derives + re-checks every pot; this also fails early + clearly on a spent/missing pot.
            std::vector<OptionRedemptionPot> pots;
            std::set<COutPoint> pot_outpoints;
            std::set<uint32_t> pot_lots;
            CAmount pot_native = 0;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                for (size_t i = 0; i < pots_arg.size(); ++i) {
                    const UniValue& po = pots_arg[i];
                    if (!po.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "each pot must be an object {lot_index, pot}");
                    const int64_t li = po.find_value("lot_index").getInt<int64_t>();
                    if (li < 0 || static_cast<uint64_t>(li) >= terms.lot_count) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "pot lot_index out of range [0, lot_count)");
                    }
                    if (!pot_lots.insert(static_cast<uint32_t>(li)).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("duplicate lot_index %d in pots", static_cast<int>(li)));
                    }
                    const COutPoint op = ParseOutPointStr(RequireStr(po.find_value("pot"), "pot"), "pot");
                    if (!pot_outpoints.insert(op).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "duplicate pot outpoint");
                    }
                    const auto coin = coins.GetCoin(op);
                    if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "pot outpoint is missing or already spent");
                    pot_native += coin->out.nValue;
                    if (!MoneyRange(pot_native)) throw JSONRPCError(RPC_INVALID_PARAMETER, "pot value out of range");
                    pots.push_back(OptionRedemptionPot{static_cast<uint32_t>(li), FundedOutput{op, coin->out}});
                }
            }
            const size_t k = pots.size();

            // 2) Holder sink for the sweep + token change.
            CScript holder_spk;
            std::string holder_address;
            if (const UniValue& ha = opts.find_value("holder_address"); !ha.isNull()) {
                const CTxDestination dest = DecodeDestination(ha.get_str());
                if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid holder_address");
                holder_spk = GetScriptForDestination(dest);
                holder_address = ha.get_str();
            } else {
                auto dest = pwallet->GetNewChangeDestination(OutputType::BECH32M);
                if (!dest) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(dest).original);
                holder_spk = GetScriptForDestination(*dest);
                holder_address = EncodeDestination(*dest);
            }

            // 3) Auto-select holder token UTXOs (raw AssetID == series_id) + native fee candidates.
            //    m_required_asset_id lets this series' asset coins through AvailableCoins' asset filter;
            //    the ICU and any other-series coins are filtered out per-coin below (native = empty vExt).
            std::vector<FundedOutput> token_pool, native_pool;
            {
                CCoinControl cc;
                cc.m_required_asset_id = series_id;
                LOCK(pwallet->cs_wallet);
                for (const COutput& o : AvailableCoinsListUnspent(*pwallet, &cc).All()) {
                    if (!o.spendable) continue;
                    if (pot_outpoints.count(o.outpoint)) continue; // never the pots (not ours anyway)
                    if (o.txout.vExt.empty()) {
                        native_pool.push_back(FundedOutput{o.outpoint, o.txout});
                    } else if (const auto tag = assets::ParseAssetTag(o.txout.vExt); tag && tag->id == series_id && tag->amount > 0) {
                        token_pool.push_back(FundedOutput{o.outpoint, o.txout});
                    }
                    // else: ICU (IssuerReg) or some other asset -> not eligible.
                }
            }

            // Pick the fewest token inputs that cover k units.
            std::sort(token_pool.begin(), token_pool.end(), [](const FundedOutput& a, const FundedOutput& b) {
                return assets::ParseAssetTag(a.txout.vExt)->amount > assets::ParseAssetTag(b.txout.vExt)->amount;
            });
            std::vector<FundedOutput> token_inputs;
            uint64_t token_units = 0, token_native = 0;
            for (const FundedOutput& t : token_pool) {
                if (token_units >= k) break;
                token_inputs.push_back(t);
                token_units += assets::ParseAssetTag(t.txout.vExt)->amount;
                token_native += static_cast<uint64_t>(t.txout.nValue);
            }
            if (token_units < k) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Holder has %llu option units; %llu required for %llu pots",
                              (unsigned long long)token_units, (unsigned long long)k, (unsigned long long)k));
            }

            const CAmount dust = 546; // kMinAssetOutputDust; per asset output
            const size_t asset_outputs = k + (token_units > k ? 1u : 0u);
            const CAmount asset_out_dust = static_cast<CAmount>(asset_outputs) * dust;

            // 4) Build -> sign -> measure -> re-fee. Native is added only if the pots + token dust do not
            //    cover (fee + per-output dust + a non-dust sweep). When pots cover it (the ITM case), the
            //    input set is fixed and the fixed-point converges in two passes.
            std::vector<FundedOutput> native_inputs;
            std::set<COutPoint> native_selected;
            CAmount fee = 0;
            CTransactionRef tx_ref;
            bool converged = false;
            for (int pass = 0; pass < 8 && !converged; ++pass) {
                CAmount native_in = pot_native + static_cast<CAmount>(token_native);
                for (const FundedOutput& n : native_inputs) native_in += n.txout.nValue;
                const CAmount need = fee + asset_out_dust + dust; // reserve a non-dust sweep
                if (native_in < need) {
                    for (const FundedOutput& n : native_pool) {
                        if (native_in >= need) break;
                        if (!native_selected.insert(n.outpoint).second) continue;
                        native_inputs.push_back(n);
                        native_in += n.txout.nValue;
                    }
                    if (native_in < need) {
                        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                            "Pots + token + native inputs do not cover the fee and per-output dust");
                    }
                }
                CMutableTransaction mtx;
                std::string berr;
                if (!BuildOptionRedemption(terms, pots, token_inputs, native_inputs, holder_spk, fee, dust, mtx, berr)) {
                    // The builder re-derives + re-checks every input from its live UTXO; a rejection here is a
                    // bad caller request (wrong pot script, asset-tagged pot, output caps), not a wallet fault.
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Redemption build failed: " + berr);
                }
                std::vector<CTxOut> spent;
                spent.reserve(mtx.vin.size());
                for (const auto& p : pots) spent.push_back(p.pot.txout);
                for (const auto& t : token_inputs) spent.push_back(t.txout);
                for (const auto& n : native_inputs) spent.push_back(n.txout);
                tx_ref = SignExtractRedemption(*pwallet, mtx, spent, k);
                // tx_ref now carries exactly this `fee` (BuildOptionRedemption set native_sweep = in - fee
                // - dust). Converge only when the fee baked into THIS tx covers its own measured size.
                const CAmount want = feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                if (fee >= want) { converged = true; break; }
                fee = want;
            }
            // Never return a stale tx: if the fixed point did not settle, the tx in hand underpays.
            if (!tx_ref || !converged) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Redemption fee did not converge");
            }

            // Report fee + sweep from the SERIALIZED tx, not the loop variable: actual_fee = in - out, and
            // every asset output carries exactly `dust`, so the native sweep is whatever is left.
            CAmount total_in = pot_native + static_cast<CAmount>(token_native);
            for (const FundedOutput& n : native_inputs) total_in += n.txout.nValue;
            CAmount total_out = 0;
            for (const CTxOut& o : tx_ref->vout) total_out += o.nValue;
            const CAmount actual_fee = total_in - total_out;
            const CAmount native_sweep = total_out - asset_out_dust;

            std::string broadcast_err;
            if (broadcast) {
                if (!pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, broadcast_err)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Broadcast failed: " + broadcast_err);
                }
            }

            UniValue redeemed(UniValue::VARR);
            UniValue sinks(UniValue::VARR);
            for (const auto& p : pots) {
                redeemed.push_back(static_cast<int64_t>(p.lot_index));
                const OptionLot lot = DeriveOptionLot(terms, series_id, p.lot_index);
                UniValue s(UniValue::VOBJ);
                s.pushKV("lot_index", static_cast<int64_t>(p.lot_index));
                s.pushKV("address", EncodeDestination(WitnessV1Taproot{lot.sink_key}));
                s.pushKV("sink_spk", HexStr(lot.sink_spk));
                sinks.push_back(s);
            }

            UniValue input_counts(UniValue::VOBJ);
            input_counts.pushKV("pots", static_cast<int64_t>(k));
            input_counts.pushKV("token", static_cast<int64_t>(token_inputs.size()));
            input_counts.pushKV("native", static_cast<int64_t>(native_inputs.size()));

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(*tx_ref));
            result.pushKV("txid", tx_ref->GetHash().GetHex());
            result.pushKV("asset_id", HexStr(series_id));
            result.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(series_id));
            result.pushKV("redeemed_lots", redeemed);
            result.pushKV("units_retired", static_cast<int64_t>(k));
            result.pushKV("token_change_units", static_cast<int64_t>(token_units - k));
            result.pushKV("native_sweep", ValueFromAmount(native_sweep));
            result.pushKV("fee", ValueFromAmount(actual_fee));
            result.pushKV("holder_address", holder_address);
            result.pushKV("sinks", sinks);
            result.pushKV("inputs", input_counts);
            result.pushKV("broadcast", broadcast);
            return result;
        },
    };
}

RPCHelpMan optionseries_build_buyback()
{
    return RPCHelpMan{
        "optionseries.build_buyback",
        "The writer's early unwind for ONE lot vault (D1-b series only): spend the lot vault via its "
        "buy-back leaf — which binds an output-committing covenant AND requires a writer signature — by "
        "retiring exactly ONE repurchased option unit to the lot sink and reclaiming the collateral to the "
        "writer. The writer's repurchased token unit and native fee inputs are selected automatically (token "
        "UTXOs whose AssetTag carries the raw series_id; native-only coins for the fee). Unlike settlement "
        "there is NO maturity/burial or CLTV wait — the writer can unwind a lot at any time as long as they "
        "control writer_key and hold at least one unit. The wallet signs the vault (output-binding leaf) and "
        "its token + native inputs in-process and returns the finalized raw transaction.",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The series terms (same shape as optionseries.derive)",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A series terms field"}}},
            {"lot_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The lot to unwind, in [0, lot_count)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"vault_outpoint", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                        "The lot vault outpoint \"txid:vout\"; omit to use this wallet's recorded series"},
                    {"reclaim_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                        "Destination for the reclaimed collateral + token change; default the writer key's P2TR"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB (default 1)"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast the finalized transaction"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The finalized network-serialized transaction"},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "asset_id", "series_id (option-series canonical hex)"},
                {RPCResult::Type::STR_HEX, "registry_asset_id", "registry lookup convention"},
                {RPCResult::Type::NUM, "lot_index", "The unwound lot"},
                {RPCResult::Type::NUM, "unit_repurchased", "Option units retired to the sink (always 1)"},
                {RPCResult::Type::NUM, "token_change_units", "Option units returned to the writer as change"},
                {RPCResult::Type::STR_AMOUNT, "native_sweep", "Reclaimed collateral + change swept to the writer"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
                {RPCResult::Type::STR, "reclaim_address", "Where the collateral + token change were sent"},
                {RPCResult::Type::STR, "sink_address", "The lot sink that received the repurchased unit"},
                {RPCResult::Type::OBJ, "inputs", "Input class counts",
                    {
                        {RPCResult::Type::NUM, "vault", "the covenant vault input (always 1)"},
                        {RPCResult::Type::NUM, "token", "writer token inputs"},
                        {RPCResult::Type::NUM, "native", "native fee inputs"},
                    }},
                {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast"},
            }},
        RPCExamples{HelpExampleCli("optionseries.build_buyback", "'{\"writer_key\":\"79be667e...\",...}' 0 '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const OptionSeriesTerms terms = ParseOptionSeriesTermsFromJson(request.params[0]);
            std::string verr;
            if (!ValidateOptionSeriesTerms(terms, /*pow_limit=*/nullptr, verr)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid option series terms: " + verr);
            }
            if (terms.leaf_set != OPTION_LEAFSET_SETTLE_BUYBACK) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Series has no buy-back leaf (settle-only leaf_set)");
            }
            const uint256 series_id = ComputeOptionSeriesId(terms);
            const int64_t lot_index_i = request.params[1].getInt<int64_t>();
            if (lot_index_i < 0 || static_cast<uint64_t>(lot_index_i) >= terms.lot_count) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "lot_index out of range [0, lot_count)");
            }
            const uint32_t lot_index = static_cast<uint32_t>(lot_index_i);

            const UniValue opts = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
            CFeeRate feerate{1000};
            if (const UniValue& fr = opts.find_value("fee_rate"); !fr.isNull()) {
                const CAmount fee_rate = AmountFromValue(fr, /*decimals=*/3);
                if (fee_rate <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be greater than 0");
                feerate = CFeeRate{fee_rate};
            }
            bool broadcast = false;
            if (const UniValue& b = opts.find_value("broadcast"); !b.isNull()) broadcast = b.get_bool();

            // Vault discovery hint (explicit outpoint for any holder of the record, else the wallet's record);
            // the builder re-derives the lot and re-checks the live UTXO, so a wrong outpoint is rejected.
            COutPoint vault_op;
            if (const UniValue& vo = opts.find_value("vault_outpoint"); !vo.isNull()) {
                vault_op = ParseOutPointStr(vo.get_str(), "vault_outpoint");
            } else {
                const auto rec = pwallet->FindOptionSeries(series_id);
                if (!rec) throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Series not recorded in this wallet; run optionseries.record_issue, or pass options.vault_outpoint");
                if (lot_index >= rec->lot_vaults.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Recorded series has no vault for that lot_index");
                vault_op = rec->lot_vaults[lot_index];
            }

            // Reclaim destination: the writer's own key by default (it controls writer_key by construction).
            CScript writer_spk;
            std::string reclaim_address;
            if (const UniValue& ra = opts.find_value("reclaim_address"); !ra.isNull()) {
                const CTxDestination dest = DecodeDestination(ra.get_str());
                if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid reclaim_address");
                writer_spk = GetScriptForDestination(dest);
                reclaim_address = ra.get_str();
            } else {
                writer_spk = GetScriptForDestination(WitnessV1Taproot{terms.writer_key});
                reclaim_address = EncodeDestination(WitnessV1Taproot{terms.writer_key});
            }

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            // Read the LIVE vault UTXO.
            CTxOut vault_txout;
            {
                LOCK(cs_main);
                const auto coin = chainman.ActiveChainstate().CoinsTip().GetCoin(vault_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint is missing or already spent");
                vault_txout = coin->out;
            }
            const FundedOutput vault{vault_op, vault_txout};

            // Auto-select the writer's token UTXOs (>= 1 unit) + native fee candidates (exclude ICU/asset).
            std::vector<FundedOutput> token_pool, native_pool;
            {
                CCoinControl cc;
                cc.m_required_asset_id = series_id;
                LOCK(pwallet->cs_wallet);
                for (const COutput& o : AvailableCoinsListUnspent(*pwallet, &cc).All()) {
                    if (!o.spendable) continue;
                    if (o.outpoint == vault_op) continue; // the vault is native at a covenant spk; never a fee coin
                    if (o.txout.vExt.empty()) {
                        native_pool.push_back(FundedOutput{o.outpoint, o.txout});
                    } else if (const auto tag = assets::ParseAssetTag(o.txout.vExt); tag && tag->id == series_id && tag->amount > 0) {
                        token_pool.push_back(FundedOutput{o.outpoint, o.txout});
                    }
                }
            }
            std::sort(token_pool.begin(), token_pool.end(), [](const FundedOutput& a, const FundedOutput& b) {
                return assets::ParseAssetTag(a.txout.vExt)->amount > assets::ParseAssetTag(b.txout.vExt)->amount;
            });
            std::vector<FundedOutput> token_inputs;
            uint64_t token_units = 0, token_native = 0;
            for (const FundedOutput& t : token_pool) {
                if (token_units >= 1) break;
                token_inputs.push_back(t);
                token_units += assets::ParseAssetTag(t.txout.vExt)->amount;
                token_native += static_cast<uint64_t>(t.txout.nValue);
            }
            if (token_units < 1) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Writer holds no option units to repurchase");
            }

            const CAmount dust = 546;
            const size_t asset_outputs = 1 + (token_units > 1 ? 1u : 0u);
            const CAmount asset_out_dust = static_cast<CAmount>(asset_outputs) * dust;
            const CAmount vault_native = vault_txout.nValue; // reclaimed collateral

            // Build -> sign vault (output-binding) -> sign token/native -> measure -> re-fee. As redeem, but
            // the vault input must be re-signed each pass because the outputs (and thus its sighash) move.
            std::vector<FundedOutput> native_inputs;
            std::set<COutPoint> native_selected;
            CAmount fee = 0;
            CTransactionRef tx_ref;
            bool converged = false;
            for (int pass = 0; pass < 8 && !converged; ++pass) {
                CAmount native_in = vault_native + static_cast<CAmount>(token_native);
                for (const FundedOutput& n : native_inputs) native_in += n.txout.nValue;
                const CAmount need = fee + asset_out_dust + dust;
                if (native_in < need) {
                    for (const FundedOutput& n : native_pool) {
                        if (native_in >= need) break;
                        if (!native_selected.insert(n.outpoint).second) continue;
                        native_inputs.push_back(n);
                        native_in += n.txout.nValue;
                    }
                    if (native_in < need) {
                        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                            "Vault + token + native inputs do not cover the fee and per-output dust");
                    }
                }
                CMutableTransaction mtx;
                std::string berr;
                if (!BuildOptionBuyback(terms, lot_index, vault, token_inputs, native_inputs, writer_spk, fee, dust, mtx, berr)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Buy-back build failed: " + berr);
                }
                std::vector<CTxOut> spent;
                spent.reserve(mtx.vin.size());
                spent.push_back(vault_txout);
                for (const auto& t : token_inputs) spent.push_back(t.txout);
                for (const auto& n : native_inputs) spent.push_back(n.txout);
                SignBuybackVaultInput(*pwallet, mtx, spent, terms.writer_key); // vin[0] real writer signature
                tx_ref = SignExtractRedemption(*pwallet, mtx, spent, /*k=*/1); // vault skips local verify; node validates
                const CAmount want = feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                if (fee >= want) { converged = true; break; }
                fee = want;
            }
            if (!tx_ref || !converged) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Buy-back fee did not converge");
            }

            CAmount total_in = vault_native + static_cast<CAmount>(token_native);
            for (const FundedOutput& n : native_inputs) total_in += n.txout.nValue;
            CAmount total_out = 0;
            for (const CTxOut& o : tx_ref->vout) total_out += o.nValue;
            const CAmount actual_fee = total_in - total_out;
            const CAmount native_sweep = total_out - asset_out_dust;

            std::string broadcast_err;
            if (broadcast) {
                if (!pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, broadcast_err)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Broadcast failed: " + broadcast_err);
                }
            }

            const OptionLot lot = DeriveOptionLot(terms, series_id, lot_index);
            UniValue input_counts(UniValue::VOBJ);
            input_counts.pushKV("vault", 1);
            input_counts.pushKV("token", static_cast<int64_t>(token_inputs.size()));
            input_counts.pushKV("native", static_cast<int64_t>(native_inputs.size()));

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(*tx_ref));
            result.pushKV("txid", tx_ref->GetHash().GetHex());
            result.pushKV("asset_id", HexStr(series_id));
            result.pushKV("registry_asset_id", OptionSeriesRegistryIdHex(series_id));
            result.pushKV("lot_index", static_cast<int64_t>(lot_index));
            result.pushKV("unit_repurchased", 1);
            result.pushKV("token_change_units", static_cast<int64_t>(token_units - 1));
            result.pushKV("native_sweep", ValueFromAmount(native_sweep));
            result.pushKV("fee", ValueFromAmount(actual_fee));
            result.pushKV("reclaim_address", reclaim_address);
            result.pushKV("sink_address", EncodeDestination(WitnessV1Taproot{lot.sink_key}));
            result.pushKV("inputs", input_counts);
            result.pushKV("broadcast", broadcast);
            return result;
        },
    };
}

} // namespace wallet
