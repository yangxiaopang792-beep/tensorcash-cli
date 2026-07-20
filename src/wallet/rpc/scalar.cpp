// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wallet-only scalar note-pair securitisation RPCs (CFD_GENERALISATION.md §6/§7, Slice 5e). These wire
// the pure derivation/builders in wallet/scalar_note_pair.{h,cpp} into the wallet: registering the L/S
// child coupon assets, the issuer-gated atomic issuance, per-side redemption, and the permissionless
// complete-set unwind. The read-only scalar feed RPCs (scalarpublish_raw/scalargetfeed/scalarlistfeeds,
// Slice 1) live separately in src/rpc/scalar.cpp; these dotted scalar.* contract RPCs mirror the
// optionseries.* surface.

#include <addresstype.h>
#include <arith_uint256.h>
#include <assets/asset.h>
#include <assets/icu_payload.h>
#include <assets/registry.h>
#include <consensus/amount.h>
#include <consensus/scalar_cfd.h>
#include <consensus/scalar_cfd_leaf.h>
#include <core_io.h>
#include <key_io.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/asset_registration.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/rpc/util.h>
#include <wallet/coinselection.h>
#include <wallet/scalar_note_pair.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <array>
#include <map>
#include <string>
#include <vector>

namespace wallet {

// Forward decl of the sibling RPC we compose for confirmation-gated reads is unnecessary; we read the
// chainstate directly. EnsureChainman/EnsureWalletContext come from rpc/util.h + wallet/rpc/util.h.

namespace {

// --- small UniValue field accessors for the `terms` object ---------------------------------------
uint64_t ReqU64(const UniValue& o, const std::string& k)
{
    if (!o.exists(k)) throw JSONRPCError(RPC_INVALID_PARAMETER, "missing terms field: " + k);
    return o[k].getInt<uint64_t>();
}
uint32_t ReqU32(const UniValue& o, const std::string& k)
{
    const uint64_t v = ReqU64(o, k);
    if (v > std::numeric_limits<uint32_t>::max()) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " out of uint32 range");
    return static_cast<uint32_t>(v);
}
uint16_t ReqU16(const UniValue& o, const std::string& k)
{
    const uint64_t v = ReqU64(o, k);
    if (v > std::numeric_limits<uint16_t>::max()) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " out of uint16 range");
    return static_cast<uint16_t>(v);
}
uint8_t ReqU8(const UniValue& o, const std::string& k)
{
    const uint64_t v = ReqU64(o, k);
    if (v > 0xFF) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " out of uint8 range");
    return static_cast<uint8_t>(v);
}
uint8_t OptU8(const UniValue& o, const std::string& k, uint8_t dflt) { return o.exists(k) ? ReqU8(o, k) : dflt; }
//! A 32-byte id from display hex; empty/absent → zero (e.g. NATIVE_SENTINEL collateral, CHAIN U).
uint256 OptHash(const UniValue& o, const std::string& k)
{
    if (!o.exists(k) || o[k].get_str().empty()) return uint256{};
    auto h = uint256::FromHex(o[k].get_str());
    if (!h) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " is not 32-byte hex");
    return *h;
}

CTxDestination FreshBech32(CWallet& w, const std::string& label)
{
    auto d = w.GetNewDestination(OutputType::BECH32, label);
    if (!d) throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(d).original);
    return *d;
}

} // namespace

//! Parse the `terms` object into ScalarNotePairTerms (economics only) and DERIVE the canonical L/S token
//! ids (§6.2) — the caller never supplies them. Throws JSONRPCError on malformed input; runs
//! ValidateScalarNotePairTerms so a bad descriptor never reaches a builder.
ScalarNotePairTerms ParseScalarNotePairTermsFromJson(const UniValue& t)
{
    if (!t.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms must be an object");
    ScalarNotePairTerms s;
    s.descriptor_version = kScalarNotePairDescriptorVersion;
    s.source_type   = OptU8(t, "source_type", static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED));
    s.payoff_mode   = OptU8(t, "payoff_mode", static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE));
    s.loss_direction = OptU8(t, "loss_direction", 0);
    s.underlying_asset_id = OptHash(t, "underlying_asset_id");
    s.feed_id       = ReqU32(t, "feed_id");
    s.fixing_ref    = ReqU64(t, "fixing_ref");
    s.publication_deadline_height = ReqU32(t, "publication_deadline_height");
    s.settle_lock_height = ReqU32(t, "settle_lock_height");
    s.scalar_format_id = ReqU16(t, "scalar_format_id");
    s.strike        = OptHash(t, "strike");
    s.fallback_scalar = OptHash(t, "fallback_scalar");
    // strike/fallback are supplied as NUMERIC display hex; store the format's wire bytes (identity for LE,
    // byte-reversed for BE) BEFORE deriving token ids / validating, so the leaf + settlement read the
    // intended number. Every note-pair RPC re-parses the user's numeric terms, so this is deterministic;
    // ScalarNotePairTermsToJson decodes back to numeric so a round-tripped terms object re-encodes cleanly.
    {
        uint256 w;
        if (!EncodeScalarToWire(s.scalar_format_id, s.strike, w))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "strike exceeds the scalar_format_id width");
        s.strike = w;
        if (!EncodeScalarToWire(s.scalar_format_id, s.fallback_scalar, w))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "fallback_scalar exceeds the scalar_format_id width");
        s.fallback_scalar = w;
    }
    s.lambda_q      = ReqU32(t, "lambda_q");
    s.collateral_asset_id = OptHash(t, "collateral_asset_id");
    s.vault_im      = ReqU64(t, "vault_im");
    s.lot_count     = ReqU32(t, "lot_count");
    s.series_salt   = OptHash(t, "series_salt");
    // §6.2: the token ids are the canonical derivation of the economics (set last).
    std::tie(s.long_token_id, s.short_token_id) = DeriveScalarNotePairTokenIds(s);

    std::string err;
    if (!ValidateScalarNotePairTerms(s, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid scalar note-pair terms: " + err);
    return s;
}

//! Render terms (incl. the derived L/S + pair_id) back to JSON for decode/list responses.
UniValue ScalarNotePairTermsToJson(const ScalarNotePairTerms& s)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("descriptor_version", static_cast<int>(s.descriptor_version));
    o.pushKV("source_type", static_cast<int>(s.source_type));
    o.pushKV("payoff_mode", static_cast<int>(s.payoff_mode));
    o.pushKV("loss_direction", static_cast<int>(s.loss_direction));
    o.pushKV("underlying_asset_id", s.underlying_asset_id.GetHex());
    o.pushKV("feed_id", static_cast<int64_t>(s.feed_id));
    o.pushKV("fixing_ref", s.fixing_ref);
    o.pushKV("publication_deadline_height", static_cast<int64_t>(s.publication_deadline_height));
    o.pushKV("settle_lock_height", static_cast<int64_t>(s.settle_lock_height));
    o.pushKV("scalar_format_id", static_cast<int64_t>(s.scalar_format_id));
    // Decode wire -> NUMERIC for display so a round-tripped terms object re-encodes to the same wire.
    arith_uint256 kdec, fdec;
    o.pushKV("strike", DecodeScalarValue(s.scalar_format_id, s.strike, kdec) ? ArithToUint256(kdec).GetHex() : s.strike.GetHex());
    o.pushKV("fallback_scalar", DecodeScalarValue(s.scalar_format_id, s.fallback_scalar, fdec) ? ArithToUint256(fdec).GetHex() : s.fallback_scalar.GetHex());
    o.pushKV("lambda_q", static_cast<int64_t>(s.lambda_q));
    o.pushKV("collateral_asset_id", s.collateral_asset_id.GetHex());
    o.pushKV("vault_im", s.vault_im);
    o.pushKV("lot_count", static_cast<int64_t>(s.lot_count));
    o.pushKV("series_salt", s.series_salt.GetHex());
    o.pushKV("long_token_id", s.long_token_id.GetHex());
    o.pushKV("short_token_id", s.short_token_id.GetHex());
    o.pushKV("pair_id", ComputeScalarNotePairId(s).GetHex());
    return o;
}

RPCHelpMan scalar_build_register()
{
    return RPCHelpMan{
        "scalar.build_register",
        "Register the two coupon child assets (L and S) for a scalar note pair, as ONE sponsored-child "
        "batch transaction: it co-spends the parent root's current ICU once and creates both children "
        "(each a plain bearer coupon — MINT_ALLOWED only, cap = lot_count, decimals 0, immutable "
        "governance) plus a parent successor, autofunded. Both child ICUs carry the SAME §6.2 descriptor "
        "metadata, so either token self-describes the pair. The L/S asset ids are the canonical "
        "derivation of the terms (never supplied). Does NOT issue units (that is scalar.build_issue).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The note-pair economics (no token ids)",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"root", RPCArg::Type::STR, RPCArg::Optional::NO, "Sponsoring root ticker (must be an existing root)"},
            {"long_suffix", RPCArg::Type::STR, RPCArg::Optional::NO, "Child ticker suffix for token L (→ ROOT.SUFFIX)"},
            {"short_suffix", RPCArg::Type::STR, RPCArg::Optional::NO, "Child ticker suffix for token S"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"child_bond_sats", RPCArg::Type::NUM, RPCArg::Default{10000}, "Per-child ICU bond (>= SponsoredChildMinIcuBond)"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pair_id", "The note-pair id (descriptor hash)"},
                {RPCResult::Type::STR_HEX, "long_token_id", "L child asset id"},
                {RPCResult::Type::STR_HEX, "short_token_id", "S child asset id"},
                {RPCResult::Type::STR, "long_ticker", "ROOT.long_suffix"},
                {RPCResult::Type::STR, "short_ticker", "ROOT.short_suffix"},
                {RPCResult::Type::STR_HEX, "hex", "The raw registration transaction"},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::BOOL, "broadcast", "Whether it was broadcast"},
            }},
        RPCExamples{HelpExampleCli("scalar.build_register", "'{...terms...}' \"ACME\" \"U6L\" \"U6S\" '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const ScalarNotePairTerms terms = ParseScalarNotePairTermsFromJson(request.params[0]);
            const uint256 pair_id = ComputeScalarNotePairId(terms);
            const uint32_t N = terms.lot_count;

            const std::string root = request.params[1].get_str();
            if (!assets::IsRootTicker(root)) throw JSONRPCError(RPC_INVALID_PARAMETER, "root must be an existing root ticker");
            std::string long_suffix = request.params[2].get_str();
            std::string short_suffix = request.params[3].get_str();
            for (char& c : long_suffix) if (c >= 'a' && c <= 'z') c = char(c - 32);
            for (char& c : short_suffix) if (c >= 'a' && c <= 'z') c = char(c - 32);
            const std::string long_ticker = root + "." + long_suffix;
            const std::string short_ticker = root + "." + short_suffix;
            if (!assets::ParseChildTicker(long_ticker) || !assets::ParseChildTicker(short_ticker)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid child ticker (suffix grammar [A-Z][A-Z0-9]{2,10}, one hop)");
            }
            if (long_ticker == short_ticker) throw JSONRPCError(RPC_INVALID_PARAMETER, "long and short suffix must differ");

            bool broadcast = false;
            std::optional<double> fee_rate_vb;
            const Consensus::Params& consensus = Params().GetConsensus();
            CAmount child_bond = consensus.SponsoredChildMinIcuBond;
            if (request.params.size() > 4 && request.params[4].isObject()) {
                const UniValue& opt = request.params[4];
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("child_bond_sats")) child_bond = opt["child_bond_sats"].getInt<int64_t>();
            }
            if (!MoneyRange(child_bond)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "child_bond_sats out of MoneyRange");
            }
            if (child_bond < consensus.SponsoredChildMinIcuBond) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "child_bond_sats below SponsoredChildMinIcuBond");
            }

            // Resolve the parent root + its current confirmed ICU.
            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            uint256 parent_id;
            AssetRegistryEntry preg;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                if (!coins.ReadTickerBinding(root, parent_id) || !coins.ReadAssetPolicy(parent_id, preg)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "sponsoring root is not a registered/confirmed asset");
                }
            }
            const COutPoint parent_icu = preg.icu_outpoint;
            std::map<COutPoint, Coin> pcoins; pcoins[parent_icu];
            pwallet->chain().findCoins(pcoins);
            const Coin& pcoin = pcoins[parent_icu];
            if (pcoin.IsSpent()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Parent ICU is unknown or already spent");
            const CAmount parent_value = pcoin.out.nValue;
            const std::vector<unsigned char> parent_vext = pcoin.out.vExt;
            // The reused successor vExt MUST be the sponsoring root's own IssuerReg — guard against a
            // stale/inconsistent wallet coin before building a tx consensus would reject.
            const auto parent_reg = assets::ParseIssuerReg(parent_vext);
            if (!parent_reg) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Parent ICU does not carry an IssuerReg");
            if (parent_reg->asset_id != parent_id) throw JSONRPCError(RPC_INVALID_PARAMETER, "Parent ICU asset_id does not match the sponsoring root");
            if (parent_value < consensus.AssetMinIcuBond) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "parent ICU is below full root bond; it can no longer sponsor children");
            }

            // Build each child's IssuerReg + ICU/ZK chunk TLVs via the shared registration builder. The
            // band must be wrapped in a CanonicalIcuPayload (the builder calls ParseCanonicalIcuPayload on
            // icu_plaintext) — a public payload with a human note + the committed band in `metadata`.
            //
            // CRUCIAL: the two children get DISTINCT ICU payloads (a per-side human note), hence distinct
            // icu_ctxt_commits. Consensus CONSUMES (erases) each ICU payload as its asset claims it
            // (validation.cpp ~5545), so two NEW assets in one tx must NOT share an identical commit — an
            // identical payload would let the first child consume it and leave the second "icutext-missing".
            // The committed descriptor band (metadata) is IDENTICAL across both, so either token still
            // self-describes the same pair.
            const std::vector<unsigned char> band = BuildScalarNotePairIcuMetadata(terms);
            auto make_reg = [&](const uint256& aid, const std::string& ticker, const char* side) {
                assets::CanonicalIcuPayload payload;
                payload.version = 1;
                payload.compression = 0;
                payload.encryption_mode = 0;
                payload.visibility = 0; // public — the descriptor band must be openly verifiable
                const std::string human = strprintf("Scalar note pair %s %s leg (lots=%u)", pair_id.GetHex(), side, N);
                payload.canonical_text.assign(human.begin(), human.end());
                const std::string witness = "{}";
                payload.witness_bundle.assign(witness.begin(), witness.end());
                payload.metadata = band;
                const std::vector<unsigned char> icu_plain = payload.Serialize();

                AssetRegistrationInputs in;
                in.asset_id = aid;
                in.policy_bits = assets::MINT_ALLOWED;          // plain bearer coupon
                in.allowed_spk = assets::SPK_DEFAULT_ALLOWED;
                in.ticker = ticker;
                in.decimals = 0;
                in.unlock_fees = static_cast<uint64_t>(child_bond);
                in.icu_plaintext = icu_plain;
                in.icu_plaintext_provided = true;
                in.icu_visibility = 0;
                in.policy_quorum_bps = 0;                       // immutable governance
                in.issuance_cap_units = N;
                return BuildAssetRegistrationTLVs(*pwallet, in);
            };
            const AssetRegistrationTLVs lreg = make_reg(terms.long_token_id, long_ticker, "long");
            const AssetRegistrationTLVs sreg = make_reg(terms.short_token_id, short_ticker, "short");

            // Fresh, distinct destinations (reattach-by-script after funding needs unique scripts).
            const CTxDestination parent_succ_dest = FreshBech32(*pwallet, "scalar pair parent successor");
            const CTxDestination l_icu_dest = FreshBech32(*pwallet, "scalar L ICU");
            const CTxDestination s_icu_dest = FreshBech32(*pwallet, "scalar S ICU");
            const CScript parent_succ = GetScriptForDestination(parent_succ_dest);
            const CScript l_icu = GetScriptForDestination(l_icu_dest);
            const CScript s_icu = GetScriptForDestination(s_icu_dest);

            CMutableTransaction mtx;
            mtx.vin.emplace_back(parent_icu);

            CCoinControl cc;
            cc.m_allow_other_inputs = true;
            cc.m_avoid_asset_utxos = true; // native fees/change only (the pre-added parent ICU is kept)
            cc.m_change_type = OutputType::BECH32M;
            if (fee_rate_vb) { cc.fOverrideFeeRate = true; cc.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0)); }

            // recipients: parent successor + 2 child ICUs + each child's chunks (546 dust, reattached).
            std::vector<CRecipient> recipients;
            recipients.push_back(CRecipient{parent_succ_dest, parent_value, false});
            recipients.push_back(CRecipient{l_icu_dest, child_bond, false});
            recipients.push_back(CRecipient{s_icu_dest, child_bond, false});

            std::vector<std::pair<CScript, std::vector<unsigned char>>> chunks;
            auto add_chunks = [&](const AssetRegistrationTLVs& reg) {
                std::vector<std::vector<unsigned char>> tlvs;
                if (!reg.icu_chunk_tlv.empty()) tlvs.push_back(reg.icu_chunk_tlv);
                for (const auto& z : reg.zk_chunk_tlvs) tlvs.push_back(z);
                for (const auto& tlv : tlvs) {
                    const CTxDestination d = FreshBech32(*pwallet, "scalar ICU chunk");
                    chunks.emplace_back(GetScriptForDestination(d), tlv);
                    recipients.push_back(CRecipient{d, CAmount{546}, false});
                }
            };
            add_chunks(lreg);
            add_chunks(sreg);

            auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, cc);
            if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
            mtx = CMutableTransaction(*txr->tx);
            const unsigned int funded_size = GetVirtualTransactionSize(CTransaction(mtx));
            const CAmount funded_fee = txr->fee;

            // Reattach the IssuerReg / chunk TLVs by unique scriptPubKey (+ value for the ICUs).
            bool fp = false, fl = false, fs = false;
            std::vector<bool> chunk_done(chunks.size(), false);
            for (auto& o : mtx.vout) {
                if (!o.vExt.empty()) continue;
                if (!fp && o.scriptPubKey == parent_succ && o.nValue == parent_value) { o.vExt = parent_vext; fp = true; continue; }
                if (!fl && o.scriptPubKey == l_icu && o.nValue == child_bond) { o.vExt = lreg.issuer_reg_tlv; fl = true; continue; }
                if (!fs && o.scriptPubKey == s_icu && o.nValue == child_bond) { o.vExt = sreg.issuer_reg_tlv; fs = true; continue; }
                for (size_t k = 0; k < chunks.size(); ++k) {
                    if (!chunk_done[k] && o.nValue == 546 && o.scriptPubKey == chunks[k].first) { o.vExt = chunks[k].second; chunk_done[k] = true; break; }
                }
            }
            const bool all_chunks = std::all_of(chunk_done.begin(), chunk_done.end(), [](bool b){ return b; });
            if (!fp || !fl || !fs || !all_chunks) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to reattach IssuerReg/chunk TLVs after funding");

            // The vExt grew the tx after funding, so the funded fee now sits at a lower rate. Re-apply
            // the funded rate to the actual size by trimming a native change output (mirrors registerasset).
            const unsigned int actual_size = GetVirtualTransactionSize(CTransaction(mtx));
            const CFeeRate funded_rate = funded_size > 0 ? CFeeRate(funded_fee, funded_size) : CFeeRate(0);
            const CAmount required_fee = funded_rate.GetFee(actual_size);
            if (required_fee > funded_fee) {
                const CAmount deficit = required_fee - funded_fee;
                bool shaved = false;
                for (auto& o : mtx.vout) {
                    if (o.vExt.empty() && o.nValue != parent_value && o.nValue != child_bond && o.nValue != 546 && o.nValue > deficit + 546) {
                        o.nValue -= deficit;
                        shaved = true;
                        break;
                    }
                }
                if (!shaved) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "no change output available to cover the fee for the added IssuerReg/chunk data; raise fee_rate or add wallet funds");
                }
            }

            // Sign (PSBT) — the parent ICU must be wallet-spendable for a complete signature.
            PartiallySignedTransaction psbtx(mtx);
            bool complete = false;
            const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
            if (fill_err) throw JSONRPCPSBTError(*fill_err);
            if (!complete) throw JSONRPCError(RPC_WALLET_ERROR, "Transaction could not be fully signed (is the parent ICU wallet-spendable?)");
            CMutableTransaction signed_mtx;
            if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
            CTransactionRef tx = MakeTransactionRef(CTransaction(signed_mtx));

            if (broadcast) {
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});
                if (!pwallet->chain().isInMempool(tx->GetHash())) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR,
                        strprintf("scalar registration tx %s was created/recorded but the node rejected it from the mempool", tx->GetHash().ToString()));
                }
            }

            DataStream ds; ds << TX_WITH_WITNESS(*tx);
            UniValue result(UniValue::VOBJ);
            result.pushKV("pair_id", pair_id.GetHex());
            result.pushKV("long_token_id", terms.long_token_id.GetHex());
            result.pushKV("short_token_id", terms.short_token_id.GetHex());
            result.pushKV("long_ticker", long_ticker);
            result.pushKV("short_ticker", short_ticker);
            result.pushKV("hex", HexStr(ds));
            result.pushKV("txid", tx->GetHash().GetHex());
            result.pushKV("broadcast", broadcast);
            return result;
        },
    };
}

namespace {

//! Confirmed-registry coupon gate for one token (the §6.4 "confirmed before minting, no mempool
//! chaining" rule + the bearer-coupon profile). Reads the entry, checks it is pristine (issued_total==0)
//! and a plain coupon (policy_bits==MINT_ALLOWED, cap==N, decimals 0, quorum 0, no kyc/tfr/wrap, default
//! families), and returns its current ICU coin. Throws JSONRPCError otherwise.
ScalarFundedInput GateAndLoadIcu(ChainstateManager& chainman, CWallet& wallet,
                                 const uint256& token_id, uint32_t N, const char* side)
{
    AssetRegistryEntry e;
    {
        LOCK(cs_main);
        if (!chainman.ActiveChainstate().CoinsTip().ReadAssetPolicy(token_id, e)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token is not registered/confirmed on chain; run scalar.build_register and let it confirm", side));
        }
    }
    if (e.issued_total != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token already issued (issued_total != 0)", side));
    if (e.issuance_cap_units != N) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token cap != lot_count", side));
    if (e.policy_bits != assets::MINT_ALLOWED) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token policy_bits must be exactly MINT_ALLOWED", side));
    if (e.decimals != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token must have decimals 0", side));
    if (e.policy_quorum_bps != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token governance quorum must be 0", side));
    if (e.has_kyc) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token must not require KYC", side));
    if (e.tfr_flags != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token must have tfr_flags 0", side));
    if (e.icu_flags != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token must have icu_flags 0 (no WRAP_REQUIRED)", side));
    const uint16_t eff = e.allowed_spk_families ? e.allowed_spk_families : assets::SPK_DEFAULT_ALLOWED;
    if (eff != assets::SPK_DEFAULT_ALLOWED) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s token allowed_spk_families must be the default coupon set", side));

    std::map<COutPoint, Coin> coins; coins[e.icu_outpoint];
    wallet.chain().findCoins(coins);
    const Coin& c = coins[e.icu_outpoint];
    if (c.IsSpent()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s token ICU is unknown or already spent", side));
    // Guard the actual fetched coin (not just the registry entry) against stale/inconsistent state: its
    // own vExt must be an IssuerReg for this token before we co-spend it.
    const auto reg = assets::ParseIssuerReg(c.out.vExt);
    if (!reg || reg->asset_id != token_id) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s token ICU coin does not carry a matching IssuerReg", side));
    }
    ScalarFundedInput in;
    in.outpoint = e.icu_outpoint;
    in.txout = c.out;
    return in;
}

} // namespace

RPCHelpMan scalar_build_issue()
{
    return RPCHelpMan{
        "scalar.build_issue",
        "Issue a registered scalar note pair (§6.4): in ONE transaction, mint N units of L and N of S to "
        "the issuer AND fund the N derived collateral vaults, by co-spending BOTH child ICUs. The pair "
        "MUST already be registered and CONFIRMED (scalar.build_register) with issued_total == 0 for both "
        "tokens (no mempool chaining). Collateral C is pre-selected from the wallet (asset collateral) or "
        "funded natively (NATIVE_SENTINEL); native fees autofund. The assembled tx is checked against "
        "ValidateScalarNotePairIssuanceTx before broadcast. Does NOT persist the record (scalar.record_issue).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The note-pair economics",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"vault_native_sats", RPCArg::Type::NUM, RPCArg::Default{546}, "Native carrier per asset-collateral vault (>= dust; ignored for native collateral)"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pair_id", "The note-pair id"},
                {RPCResult::Type::NUM, "lot_count", "N units minted per side = N vaults funded"},
                {RPCResult::Type::ARR, "vault_spks", "The N derived lot-vault scriptPubKeys (hex), in lot order",
                    {{RPCResult::Type::STR_HEX, "", "vault scriptPubKey"}}},
                {RPCResult::Type::STR_HEX, "hex", "The raw issuance transaction"},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::BOOL, "broadcast", "Whether it was broadcast"},
            }},
        RPCExamples{HelpExampleCli("scalar.build_issue", "'{...terms...}' '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const ScalarNotePairTerms terms = ParseScalarNotePairTermsFromJson(request.params[0]);
            const uint256 pair_id = ComputeScalarNotePairId(terms);
            const uint32_t N = terms.lot_count;
            const bool native_collateral = terms.collateral_asset_id.IsNull();
            const uint64_t collateral_needed = static_cast<uint64_t>(N) * terms.vault_im;

            bool broadcast = false;
            std::optional<double> fee_rate_vb;
            CAmount vault_native_sats = 546;
            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& opt = request.params[1];
                if (opt.exists("broadcast")) broadcast = opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("vault_native_sats")) vault_native_sats = opt["vault_native_sats"].getInt<int64_t>();
            }
            if (!native_collateral && (vault_native_sats < 546 || !MoneyRange(vault_native_sats))) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vault_native_sats below dust or out of MoneyRange");
            }
            const CAmount vault_value = native_collateral ? static_cast<CAmount>(terms.vault_im) : vault_native_sats;
            const CAmount dust = 546;

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            // §6.4 confirmed-registry coupon gate + load both child ICUs.
            const ScalarFundedInput l_icu = GateAndLoadIcu(chainman, *pwallet, terms.long_token_id, N, "long");
            const ScalarFundedInput s_icu = GateAndLoadIcu(chainman, *pwallet, terms.short_token_id, N, "short");

            CMutableTransaction mtx;
            mtx.vin.emplace_back(l_icu.outpoint);
            mtx.vin.emplace_back(s_icu.outpoint);

            // Pre-select asset-C collateral inputs (FundTransaction is blind to the C need pre-reattach).
            uint64_t collateral_in = 0;
            if (!native_collateral) {
                // Collateral policy gate (§5.1 / §2.3 step 4): the OP_SCALAR_CFD_SETTLE opcode requires
                // the collateral asset to be COLLATERAL_SAFE with clean KYC/TFR/WRAP at settlement, else
                // it fails SCALARCFD_COLLATERAL. Reject up front so we never fund an un-settleable note.
                AssetRegistryEntry ce;
                {
                    LOCK(cs_main);
                    if (!chainman.ActiveChainstate().CoinsTip().ReadAssetPolicy(terms.collateral_asset_id, ce)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral asset C is not registered/confirmed on chain");
                    }
                }
                if (!(ce.policy_bits & assets::COLLATERAL_SAFE)) throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral asset is not COLLATERAL_SAFE");
                if (ce.has_kyc) throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral asset requires KYC (cannot back a keyless vault)");
                if (ce.tfr_flags != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral asset has tfr_flags set");
                if (ce.icu_flags & assets::WRAP_REQUIRED) throw JSONRPCError(RPC_INVALID_PARAMETER, "collateral asset has WRAP_REQUIRED");

                LOCK(pwallet->cs_wallet);
                CCoinControl sel;
                sel.m_avoid_asset_utxos = false; // we are specifically selecting asset-C UTXOs
                for (const COutput& o : AvailableCoins(*pwallet, &sel).All()) {
                    if (collateral_in >= collateral_needed) break;
                    const auto tag = assets::ParseAssetTag(o.txout.vExt);
                    if (!tag || tag->id != terms.collateral_asset_id || tag->amount == 0) continue;
                    if (tag->amount > std::numeric_limits<uint64_t>::max() - collateral_in) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "collateral unit sum overflow");
                    }
                    mtx.vin.emplace_back(o.outpoint);
                    collateral_in += tag->amount;
                }
                if (collateral_in < collateral_needed) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf("insufficient collateral C: need %llu units, have %llu", (unsigned long long)collateral_needed, (unsigned long long)collateral_in));
                }
            }
            const uint64_t collateral_change = native_collateral ? 0 : (collateral_in - collateral_needed);

            // Output caps (mirror the pure builder, now that collateral_change is known): the 64 AssetTag
            // outputs (2 mints + N asset vaults + C change) and the 128 covenant-output total (+ native change).
            const size_t asset_outputs = 2u + (native_collateral ? 0u : static_cast<size_t>(N)) + (collateral_change > 0 ? 1u : 0u);
            if (asset_outputs > 64u) throw JSONRPCError(RPC_INVALID_PARAMETER, "too many asset outputs for one issuance tx (64 cap)");
            const size_t base_outputs = 2u /*ICU succ*/ + 2u /*mint*/ + static_cast<size_t>(N) /*vaults*/ + (collateral_change > 0 ? 1u : 0u);
            if (base_outputs + 1u > MAX_COVENANT_TX_OUTPUTS) throw JSONRPCError(RPC_INVALID_PARAMETER, "too many outputs for one issuance tx");

            // Planned vExt-bearing outputs (reattached after funding by unique scriptPubKey).
            struct Planned { CTxDestination dest; CScript spk; CAmount value; std::vector<unsigned char> vext; };
            std::vector<Planned> planned;
            auto fresh_planned = [&](CAmount value, std::vector<unsigned char> vext, const char* lbl) {
                const CTxDestination d = FreshBech32(*pwallet, lbl);
                planned.push_back({d, GetScriptForDestination(d), value, std::move(vext)});
            };
            fresh_planned(l_icu.txout.nValue, l_icu.txout.vExt, "scalar L ICU successor");
            fresh_planned(s_icu.txout.nValue, s_icu.txout.vExt, "scalar S ICU successor");
            fresh_planned(dust, assets::BuildAssetTagTlv(terms.long_token_id, N), "scalar L mint");
            fresh_planned(dust, assets::BuildAssetTagTlv(terms.short_token_id, N), "scalar S mint");
            std::vector<CScript> vault_spks;
            for (uint32_t i = 0; i < N; ++i) {
                const ScalarNoteLot lot = DeriveScalarNoteLot(terms, pair_id, i);
                vault_spks.push_back(lot.vault_spk);
                Planned p;
                p.dest = WitnessV1Taproot{lot.vault_key};
                p.spk = lot.vault_spk;
                p.value = vault_value;
                if (!native_collateral) p.vext = assets::BuildAssetTagTlv(terms.collateral_asset_id, terms.vault_im);
                planned.push_back(std::move(p));
            }
            if (collateral_change > 0) {
                fresh_planned(dust, assets::BuildAssetTagTlv(terms.collateral_asset_id, collateral_change), "scalar C change");
            }

            CCoinControl cc;
            cc.m_allow_other_inputs = true;
            cc.m_avoid_asset_utxos = true; // native fees/change only; the pre-added ICU + C vins are kept
            cc.m_change_type = OutputType::BECH32M;
            if (fee_rate_vb) { cc.fOverrideFeeRate = true; cc.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_vb * 1000.0)); }

            std::vector<CRecipient> recipients;
            for (const auto& p : planned) recipients.push_back(CRecipient{p.dest, p.value, false});

            auto txr = FundTransaction(*pwallet, mtx, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, cc);
            if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
            mtx = CMutableTransaction(*txr->tx);
            const unsigned int funded_size = GetVirtualTransactionSize(CTransaction(mtx));
            const CAmount funded_fee = txr->fee;

            // Reattach vExt by unique (scriptPubKey, value). Native vaults carry no vExt (left as-is).
            std::vector<bool> done(planned.size(), false);
            for (auto& o : mtx.vout) {
                if (!o.vExt.empty()) continue;
                for (size_t k = 0; k < planned.size(); ++k) {
                    if (done[k] || planned[k].vext.empty()) continue;
                    if (o.scriptPubKey == planned[k].spk && o.nValue == planned[k].value) { o.vExt = planned[k].vext; done[k] = true; break; }
                }
            }
            for (size_t k = 0; k < planned.size(); ++k) {
                if (!planned[k].vext.empty() && !done[k]) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to reattach an IssuerReg/AssetTag TLV after funding");
            }

            // Re-apply the funded feerate to the larger (vExt-bearing) tx by trimming native change.
            const unsigned int actual_size = GetVirtualTransactionSize(CTransaction(mtx));
            const CFeeRate funded_rate = funded_size > 0 ? CFeeRate(funded_fee, funded_size) : CFeeRate(0);
            const CAmount required_fee = funded_rate.GetFee(actual_size);
            if (required_fee > funded_fee) {
                const CAmount deficit = required_fee - funded_fee;
                bool shaved = false;
                for (auto& o : mtx.vout) {
                    if (o.vExt.empty() && o.nValue > deficit + dust) {
                        // only a native change output (not a native-collateral vault) is eligible
                        bool is_vault = false;
                        for (const auto& vs : vault_spks) if (o.scriptPubKey == vs) { is_vault = true; break; }
                        if (is_vault) continue;
                        o.nValue -= deficit; shaved = true; break;
                    }
                }
                if (!shaved) throw JSONRPCError(RPC_WALLET_ERROR, "no change output to cover the fee for the added asset data; raise fee_rate or add funds");
            }

            // Self-check the assembled tx against the atomicity invariant before signing/broadcast.
            {
                std::string verr;
                if (!ValidateScalarNotePairIssuanceTx(terms, pair_id, CTransaction(mtx), verr)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "assembled issuance tx fails ValidateScalarNotePairIssuanceTx: " + verr);
                }
            }

            // Sign (both child ICUs must be wallet-spendable for a complete signature).
            PartiallySignedTransaction psbtx(mtx);
            bool complete = false;
            const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
            if (fill_err) throw JSONRPCPSBTError(*fill_err);
            if (!complete) throw JSONRPCError(RPC_WALLET_ERROR, "Transaction could not be fully signed (are both child ICUs wallet-spendable?)");
            CMutableTransaction signed_mtx;
            if (!FinalizeAndExtractPSBT(psbtx, signed_mtx)) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize PSBT");
            CTransactionRef tx = MakeTransactionRef(CTransaction(signed_mtx));

            if (broadcast) {
                pwallet->CommitTransaction(tx, /*value_map=*/{}, /*order_form=*/{});
                if (!pwallet->chain().isInMempool(tx->GetHash())) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, strprintf("scalar issuance tx %s was created/recorded but the node rejected it from the mempool", tx->GetHash().ToString()));
                }
            }

            DataStream ds; ds << TX_WITH_WITNESS(*tx);
            UniValue vspks(UniValue::VARR);
            for (const auto& vs : vault_spks) vspks.push_back(HexStr(vs));
            UniValue result(UniValue::VOBJ);
            result.pushKV("pair_id", pair_id.GetHex());
            result.pushKV("lot_count", static_cast<int64_t>(N));
            result.pushKV("vault_spks", vspks);
            result.pushKV("hex", HexStr(ds));
            result.pushKV("txid", tx->GetHash().GetHex());
            result.pushKV("broadcast", broadcast);
            return result;
        },
    };
}

namespace {

//! Parse "txid:vout" → COutPoint (vout decimal, txid display hex).
COutPoint ParseOutPointStr(const std::string& s, const std::string& field)
{
    const size_t colon = s.rfind(':');
    if (colon == std::string::npos) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be \"txid:vout\"");
    const auto h = uint256::FromHex(s.substr(0, colon));
    if (!h) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " txid is not valid hex");
    int64_t vout = -1;
    try { vout = std::stoll(s.substr(colon + 1)); } catch (const std::exception&) { vout = -1; }
    if (vout < 0 || vout > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " vout is invalid");
    return COutPoint(Txid::FromUint256(*h), static_cast<uint32_t>(vout));
}

//! MoneyRange-checked accumulation for the RPC wrappers' native tallies (the pure builders use the same
//! discipline internally; this fails fast/clearly before they are called).
CAmount CheckedAdd(CAmount acc, CAmount v, const char* what)
{
    if (!MoneyRange(v)) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(what) + " out of MoneyRange");
    acc += v;
    if (!MoneyRange(acc)) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(what) + " sum out of MoneyRange");
    return acc;
}

//! Sign the wallet (token + native) inputs and assemble the final tx. The first `k` inputs are
//! signatureless covenant spends (pot / unwind leaf) whose witness `[leaf, control]` is already in
//! `mtx`; they are re-applied as-is (the node validates the covenant on submission). Every other input
//! must finalize AND verify. `spent[i]` is input i's prevout output, in mtx.vin order. (Generalises the
//! option-series SignExtractRedemption.)
CTransactionRef SignExtractCovenant(CWallet& wallet, CMutableTransaction mtx, const std::vector<CTxOut>& spent, size_t k)
{
    std::vector<CScriptWitness> cov_witness(k);
    for (size_t i = 0; i < k; ++i) cov_witness[i] = mtx.vin[i].scriptWitness;
    for (auto& vin : mtx.vin) { vin.scriptSig.clear(); vin.scriptWitness.SetNull(); }

    PartiallySignedTransaction psbtx{mtx};
    for (size_t i = 0; i < psbtx.inputs.size(); ++i) psbtx.inputs[i].witness_utxo = spent[i];
    bool complete = false;
    if (const auto fill_err = wallet.FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/true)) throw JSONRPCPSBTError(*fill_err);
    for (size_t i = 0; i < k; ++i) psbtx.inputs[i].final_script_witness = cov_witness[i];

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    CMutableTransaction final_mtx{*psbtx.tx};
    for (size_t i = 0; i < final_mtx.vin.size(); ++i) {
        const PSBTInput& in = psbtx.inputs[i];
        if (i >= k && !PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("wallet input %u failed to sign and verify", static_cast<unsigned>(i)));
        }
        final_mtx.vin[i].scriptSig = in.final_script_sig;
        final_mtx.vin[i].scriptWitness = in.final_script_witness;
    }
    return MakeTransactionRef(std::move(final_mtx));
}

//! Holder sink for the sweep / change: an explicit `holder_address` option, else a fresh change addr.
CScript ResolveHolderSpk(CWallet& wallet, const UniValue& opts, std::string& addr_out)
{
    if (const UniValue& ha = opts.find_value("holder_address"); !ha.isNull()) {
        const CTxDestination dest = DecodeDestination(ha.get_str());
        if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid holder_address");
        addr_out = ha.get_str();
        return GetScriptForDestination(dest);
    }
    auto dest = wallet.GetNewChangeDestination(OutputType::BECH32M);
    if (!dest) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(dest).original);
    addr_out = EncodeDestination(*dest);
    return GetScriptForDestination(*dest);
}

//! Auto-select the holder's UTXOs of token `token_id` (raw AssetTag) and native fee candidates,
//! excluding the given covenant outpoints. Mirrors the option redeem pool gather.
void GatherTokenAndNative(CWallet& wallet, const uint256& token_id, const std::set<COutPoint>& exclude,
                          std::vector<ScalarFundedInput>& token_pool, std::vector<ScalarFundedInput>& native_pool)
{
    CCoinControl cc;
    cc.m_required_asset_id = token_id;
    LOCK(wallet.cs_wallet);
    for (const COutput& o : AvailableCoinsListUnspent(wallet, &cc).All()) {
        if (!o.spendable) continue;
        if (exclude.count(o.outpoint)) continue;
        if (o.txout.vExt.empty()) {
            native_pool.push_back(ScalarFundedInput{o.outpoint, o.txout});
        } else if (const auto tag = assets::ParseAssetTag(o.txout.vExt); tag && tag->id == token_id && tag->amount > 0) {
            token_pool.push_back(ScalarFundedInput{o.outpoint, o.txout});
        }
    }
}

} // namespace

RPCHelpMan scalar_build_redeem()
{
    return RPCHelpMan{
        "scalar.build_redeem",
        "Redeem one side of a scalar note pair: retire `redeem_long ? L : S` tokens against that side's "
        "settled pots, reclaiming the pro-rata collateral. Reads each requested pot LIVE, auto-selects the "
        "holder's token + native UTXOs, builds the signatureless pot-covenant spend (BuildScalarNoteRedemption), "
        "signs the wallet inputs, and (optionally) broadcasts.",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The note-pair economics",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"redeem_long", RPCArg::Type::BOOL, RPCArg::Optional::NO, "true = redeem L vs long pots; false = redeem S vs short pots"},
            {"pots", RPCArg::Type::ARR, RPCArg::Optional::NO, "Pots to redeem",
                {{"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {{"lot_index", RPCArg::Type::NUM, RPCArg::Optional::NO, ""}, {"pot", RPCArg::Type::STR, RPCArg::Optional::NO, "txid:vout"}}}}},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {{"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, ""}, {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "sat/vB"}, {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "raw tx"}, {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::NUM, "units_retired", ""}, {RPCResult::Type::NUM, "token_change_units", ""},
            {RPCResult::Type::STR_AMOUNT, "fee", ""}, {RPCResult::Type::BOOL, "broadcast", ""}}},
        RPCExamples{HelpExampleCli("scalar.build_redeem", "'{...}' true '[{\"lot_index\":0,\"pot\":\"<txid>:0\"}]' '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const ScalarNotePairTerms terms = ParseScalarNotePairTermsFromJson(request.params[0]);
            const uint256 pair_id = ComputeScalarNotePairId(terms);
            const bool redeem_long = request.params[1].get_bool();
            const uint256 token_id = redeem_long ? terms.long_token_id : terms.short_token_id;
            const UniValue& pots_arg = request.params[2].get_array();
            if (pots_arg.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "pots must list at least one pot");
            const UniValue opts = request.params.size() > 3 && request.params[3].isObject() ? request.params[3] : UniValue(UniValue::VOBJ);
            CFeeRate feerate{1000};
            if (const UniValue& fr = opts.find_value("fee_rate"); !fr.isNull()) { const CAmount r = AmountFromValue(fr, 3); if (r <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be > 0"); feerate = CFeeRate{r}; }
            bool broadcast = false;
            if (const UniValue& b = opts.find_value("broadcast"); !b.isNull()) broadcast = b.get_bool();

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            std::vector<ScalarRedemptionPot> pots;
            std::set<COutPoint> exclude;
            std::set<uint32_t> seen_lots;
            CAmount pot_native = 0;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                for (size_t i = 0; i < pots_arg.size(); ++i) {
                    const UniValue& po = pots_arg[i];
                    if (!po.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "each pot must be {lot_index, pot}");
                    const int64_t li = po.find_value("lot_index").getInt<int64_t>();
                    if (li < 0 || static_cast<uint64_t>(li) >= terms.lot_count) throw JSONRPCError(RPC_INVALID_PARAMETER, "pot lot_index out of range");
                    if (!seen_lots.insert(static_cast<uint32_t>(li)).second) throw JSONRPCError(RPC_INVALID_PARAMETER, "duplicate lot_index");
                    const COutPoint op = ParseOutPointStr(po.find_value("pot").get_str(), "pot");
                    if (!exclude.insert(op).second) throw JSONRPCError(RPC_INVALID_PARAMETER, "duplicate pot outpoint");
                    const auto coin = coins.GetCoin(op);
                    if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "pot outpoint is missing or already spent");
                    pot_native = CheckedAdd(pot_native, coin->out.nValue, "pot value");
                    pots.push_back(ScalarRedemptionPot{static_cast<uint32_t>(li), ScalarFundedInput{op, coin->out}});
                }
            }
            const uint64_t k = pots.size();

            std::string holder_address;
            const CScript holder_spk = ResolveHolderSpk(*pwallet, opts, holder_address);

            std::vector<ScalarFundedInput> token_pool, native_pool;
            GatherTokenAndNative(*pwallet, token_id, exclude, token_pool, native_pool);
            std::sort(token_pool.begin(), token_pool.end(), [](const ScalarFundedInput& a, const ScalarFundedInput& b) {
                return assets::ParseAssetTag(a.txout.vExt)->amount > assets::ParseAssetTag(b.txout.vExt)->amount;
            });
            std::vector<ScalarFundedInput> token_inputs;
            uint64_t token_units = 0; CAmount token_native = 0;
            for (const auto& t : token_pool) {
                if (token_units >= k) break;
                token_inputs.push_back(t);
                token_units += assets::ParseAssetTag(t.txout.vExt)->amount;
                token_native = CheckedAdd(token_native, t.txout.nValue, "token input value");
            }
            if (token_units < k) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf("holder has %llu units; %llu required", (unsigned long long)token_units, (unsigned long long)k));

            const CAmount dust = 546;
            const bool native_collateral = terms.collateral_asset_id.IsNull();
            const size_t asset_outputs = static_cast<size_t>(k) + (token_units > k ? 1u : 0u) + (native_collateral ? 0u : 1u);
            if (asset_outputs > 64u) throw JSONRPCError(RPC_INVALID_PARAMETER, "too many asset outputs for one redemption tx (64 cap)");
            const CAmount asset_out_dust = static_cast<CAmount>(asset_outputs) * dust;

            std::vector<ScalarFundedInput> native_inputs;
            std::set<COutPoint> native_selected;
            CAmount fee = 0;
            CTransactionRef tx_ref;
            bool converged = false;
            for (int pass = 0; pass < 8 && !converged; ++pass) {
                CAmount native_in = CheckedAdd(pot_native, token_native, "native inputs");
                for (const auto& n : native_inputs) native_in = CheckedAdd(native_in, n.txout.nValue, "native inputs");
                const CAmount need = fee + asset_out_dust + dust;
                if (native_in < need) {
                    for (const auto& n : native_pool) {
                        if (native_in >= need) break;
                        if (!native_selected.insert(n.outpoint).second) continue;
                        native_inputs.push_back(n);
                        native_in = CheckedAdd(native_in, n.txout.nValue, "native inputs");
                    }
                    if (native_in < need) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "pots + token + native do not cover fee + per-output dust");
                }
                CMutableTransaction mtx;
                std::string berr;
                if (!BuildScalarNoteRedemption(terms, pair_id, redeem_long, pots, token_inputs, native_inputs, holder_spk, fee, dust, mtx, berr)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Redemption build failed: " + berr);
                }
                std::vector<CTxOut> spent;
                for (const auto& p : pots) spent.push_back(p.pot.txout);
                for (const auto& t : token_inputs) spent.push_back(t.txout);
                for (const auto& n : native_inputs) spent.push_back(n.txout);
                tx_ref = SignExtractCovenant(*pwallet, mtx, spent, k);
                const CAmount want = feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                if (fee >= want) { converged = true; break; }
                fee = want;
            }
            if (!tx_ref || !converged) throw JSONRPCError(RPC_WALLET_ERROR, "Redemption fee did not converge");

            // Actual fee from the serialized tx (in − out), reported alongside the result.
            CAmount total_in = CheckedAdd(pot_native, token_native, "total in");
            for (const auto& n : native_inputs) total_in = CheckedAdd(total_in, n.txout.nValue, "total in");
            CAmount total_out = 0;
            for (const CTxOut& o : tx_ref->vout) total_out = CheckedAdd(total_out, o.nValue, "total out");

            std::string berr;
            if (broadcast && !pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, berr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Broadcast failed: " + berr);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(*tx_ref));
            result.pushKV("txid", tx_ref->GetHash().GetHex());
            result.pushKV("units_retired", static_cast<int64_t>(k));
            result.pushKV("token_change_units", static_cast<int64_t>(token_units - k));
            result.pushKV("fee", ValueFromAmount(total_in - total_out));
            result.pushKV("broadcast", broadcast);
            return result;
        },
    };
}

RPCHelpMan scalar_build_unwind()
{
    return RPCHelpMan{
        "scalar.build_unwind",
        "Permissionless complete-set unwind (§6.3): spend ONE lot vault by presenting 1 L + 1 S, retiring "
        "both to their sinks and reclaiming the full collateral — no fixing, any time. Reads the vault LIVE, "
        "auto-selects 1 L + 1 S + native, builds the signatureless unwind-leaf spend (BuildScalarUnwind), "
        "signs the wallet inputs, and (optionally) broadcasts.",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The note-pair economics",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"lot_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Which lot vault to unwind"},
            {"vault", RPCArg::Type::STR, RPCArg::Optional::NO, "The vault outpoint txid:vout"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {{"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, ""}, {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "sat/vB"}, {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "raw tx"}, {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::NUM, "lot_index", ""}, {RPCResult::Type::BOOL, "broadcast", ""}}},
        RPCExamples{HelpExampleCli("scalar.build_unwind", "'{...}' 0 \"<txid>:0\" '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const ScalarNotePairTerms terms = ParseScalarNotePairTermsFromJson(request.params[0]);
            const uint256 pair_id = ComputeScalarNotePairId(terms);
            const int64_t li = request.params[1].getInt<int64_t>();
            if (li < 0 || static_cast<uint64_t>(li) >= terms.lot_count) throw JSONRPCError(RPC_INVALID_PARAMETER, "lot_index out of range");
            const uint32_t lot_index = static_cast<uint32_t>(li);
            const COutPoint vault_op = ParseOutPointStr(request.params[2].get_str(), "vault");
            const UniValue opts = request.params.size() > 3 && request.params[3].isObject() ? request.params[3] : UniValue(UniValue::VOBJ);
            CFeeRate feerate{1000};
            if (const UniValue& fr = opts.find_value("fee_rate"); !fr.isNull()) { const CAmount r = AmountFromValue(fr, 3); if (r <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be > 0"); feerate = CFeeRate{r}; }
            bool broadcast = false;
            if (const UniValue& b = opts.find_value("broadcast"); !b.isNull()) broadcast = b.get_bool();

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            ScalarFundedInput vault;
            CAmount vault_native = 0;
            {
                LOCK(cs_main);
                const auto coin = chainman.ActiveChainstate().CoinsTip().GetCoin(vault_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault outpoint is missing or already spent");
                vault = ScalarFundedInput{vault_op, coin->out};
                vault_native = CheckedAdd(0, coin->out.nValue, "vault value");
            }

            std::string holder_address;
            const CScript holder_spk = ResolveHolderSpk(*pwallet, opts, holder_address);

            std::set<COutPoint> exclude{vault_op};
            std::vector<ScalarFundedInput> l_pool, s_pool, native_pool, l_unused, s_unused;
            GatherTokenAndNative(*pwallet, terms.long_token_id, exclude, l_pool, native_pool);
            GatherTokenAndNative(*pwallet, terms.short_token_id, exclude, s_pool, s_unused); // native_pool already gathered
            if (l_pool.empty()) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "no L token UTXO to present");
            if (s_pool.empty()) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "no S token UTXO to present");
            const std::vector<ScalarFundedInput> long_token_inputs{l_pool.front()};
            const std::vector<ScalarFundedInput> short_token_inputs{s_pool.front()};
            const CAmount token_native = CheckedAdd(CheckedAdd(0, l_pool.front().txout.nValue, "L token value"), s_pool.front().txout.nValue, "S token value");

            const CAmount dust = 546;
            const bool native_collateral = terms.collateral_asset_id.IsNull();
            const uint64_t mL = assets::ParseAssetTag(l_pool.front().txout.vExt)->amount;
            const uint64_t mS = assets::ParseAssetTag(s_pool.front().txout.vExt)->amount;
            const size_t asset_outputs = 2u + (mL > 1 ? 1u : 0u) + (mS > 1 ? 1u : 0u) + (native_collateral ? 0u : 1u);
            const CAmount asset_out_dust = static_cast<CAmount>(asset_outputs) * dust;

            std::vector<ScalarFundedInput> native_inputs;
            std::set<COutPoint> native_selected;
            CAmount fee = 0;
            CTransactionRef tx_ref;
            bool converged = false;
            for (int pass = 0; pass < 8 && !converged; ++pass) {
                CAmount native_in = CheckedAdd(vault_native, token_native, "native inputs");
                for (const auto& n : native_inputs) native_in = CheckedAdd(native_in, n.txout.nValue, "native inputs");
                const CAmount need = fee + asset_out_dust + dust;
                if (native_in < need) {
                    for (const auto& n : native_pool) {
                        if (native_in >= need) break;
                        if (!native_selected.insert(n.outpoint).second) continue;
                        native_inputs.push_back(n);
                        native_in = CheckedAdd(native_in, n.txout.nValue, "native inputs");
                    }
                    if (native_in < need) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "vault + tokens + native do not cover fee + per-output dust");
                }
                CMutableTransaction mtx;
                std::string berr;
                if (!BuildScalarUnwind(terms, pair_id, lot_index, vault, long_token_inputs, short_token_inputs, native_inputs, holder_spk, fee, dust, mtx, berr)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unwind build failed: " + berr);
                }
                std::vector<CTxOut> spent;
                spent.push_back(vault.txout);
                for (const auto& t : long_token_inputs) spent.push_back(t.txout);
                for (const auto& t : short_token_inputs) spent.push_back(t.txout);
                for (const auto& n : native_inputs) spent.push_back(n.txout);
                tx_ref = SignExtractCovenant(*pwallet, mtx, spent, /*k=*/1);
                const CAmount want = feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                if (fee >= want) { converged = true; break; }
                fee = want;
            }
            if (!tx_ref || !converged) throw JSONRPCError(RPC_WALLET_ERROR, "Unwind fee did not converge");

            std::string berr;
            if (broadcast && !pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, berr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Broadcast failed: " + berr);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(*tx_ref));
            result.pushKV("txid", tx_ref->GetHash().GetHex());
            result.pushKV("lot_index", static_cast<int64_t>(lot_index));
            result.pushKV("broadcast", broadcast);
            return result;
        },
    };
}

RPCHelpMan scalar_build_settlement()
{
    return RPCHelpMan{
        "scalar.build_settlement",
        "Keeper-driven settlement of ONE scalar note-pair vault (signatureless OP_SCALAR_CFD_SETTLE "
        "covenant). Resolves the fixing via the deterministic deadline/fallback rule (real published "
        "scalar if buried + in time, else the committed fallback after deadline+grace), computes the "
        "capped payout, and pays the long/short pots their legs. Reads the vault LIVE; the keeper funds "
        "native fees. ISSUER_PUBLISHED only (CHAIN_INTRINSIC settlement is not yet supported).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The note-pair economics",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"lot_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Which lot vault to settle"},
            {"vault", RPCArg::Type::STR, RPCArg::Optional::NO, "The vault outpoint txid:vout"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {{"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, ""}, {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "sat/vB"}, {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "keeper change address"}}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "raw tx"}, {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::STR, "payout_owner", "owner-leg payout (decimal): sats for native collateral, asset units otherwise"},
            {RPCResult::Type::STR, "payout_cp", "cp-leg payout (decimal): sats for native collateral, asset units otherwise"},
            {RPCResult::Type::BOOL, "is_fallback", "true if the committed fallback fired"}, {RPCResult::Type::BOOL, "broadcast", ""},
            {RPCResult::Type::STR, "long_pot", "long-side settlement pot outpoint txid:vout (empty if that leg paid zero) — redeem L against this"},
            {RPCResult::Type::STR, "short_pot", "short-side settlement pot outpoint txid:vout (empty if that leg paid zero) — redeem S against this"}}},
        RPCExamples{HelpExampleCli("scalar.build_settlement", "'{...}' 0 \"<txid>:0\" '{\"broadcast\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const ScalarNotePairTerms terms = ParseScalarNotePairTermsFromJson(request.params[0]);
            const uint256 pair_id = ComputeScalarNotePairId(terms);
            const int64_t li = request.params[1].getInt<int64_t>();
            if (li < 0 || static_cast<uint64_t>(li) >= terms.lot_count) throw JSONRPCError(RPC_INVALID_PARAMETER, "lot_index out of range");
            const uint32_t lot_index = static_cast<uint32_t>(li);
            const COutPoint vault_op = ParseOutPointStr(request.params[2].get_str(), "vault");
            const UniValue opts = request.params.size() > 3 && request.params[3].isObject() ? request.params[3] : UniValue(UniValue::VOBJ);
            CFeeRate feerate{1000};
            if (const UniValue& fr = opts.find_value("fee_rate"); !fr.isNull()) { const CAmount r = AmountFromValue(fr, 3); if (r <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be > 0"); feerate = CFeeRate{r}; }
            bool broadcast = false;
            if (const UniValue& b = opts.find_value("broadcast"); !b.isNull()) broadcast = b.get_bool();

            const ScalarNoteLot lot = DeriveScalarNoteLot(terms, pair_id, lot_index);

            // The canonical settle leaf is the SINGLE SOURCE OF TRUTH — consensus evaluates the leaf's
            // operands off the stack, so the keeper drives resolution/payout/collateral/locktime/keys from
            // the PARSED leaf, never from `terms` (which only seed the derivation and could drift).
            ScalarCfdLeaf leaf;
            if (!ParseScalarCfdLeaf(lot.settle_leaf, leaf)) throw JSONRPCError(RPC_INTERNAL_ERROR, "derived settle leaf does not parse");
            if (leaf.source_type != static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "only ISSUER_PUBLISHED settlement is supported");
            }
            const bool native_collateral = leaf.collateral_asset_id.IsNull();
            auto p2tr = [](const std::vector<unsigned char>& xonly) { CScript s; s << OP_1 << xonly; return s; };

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            const Consensus::Params& consensus = Params().GetConsensus();

            // Read the live vault + resolve the fixing tip-anchored.
            CTxOut vault_txout;
            std::optional<ResolvedScalar> resolved;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                const auto coin = coins.GetCoin(vault_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault outpoint is missing or already spent");
                vault_txout = coin->out;
                const int ctx_height = chainman.ActiveChain().Height();
                auto reader = [&](const uint256& aid, uint32_t feed, uint64_t epoch) -> std::optional<ScalarRecord> {
                    ScalarRecord r;
                    if (coins.ReadAssetScalar(aid, feed, epoch, r)) return r;
                    return std::nullopt;
                };
                resolved = ResolveScalarFixing(leaf.underlying_asset_id, leaf.feed_id, leaf.fixing_ref,
                                               leaf.publication_deadline_height, leaf.fallback_scalar, leaf.scalar_format_id,
                                               ctx_height, consensus.SCALARCFD_MATURITY_DEPTH, consensus.SCALARCFD_FALLBACK_GRACE, reader);
            }
            if (!resolved) throw JSONRPCError(RPC_INVALID_PARAMETER, "fixing not resolvable yet (no buried in-time publication and deadline+grace not elapsed)");

            // Verify the vault is the derived lot vault with the committed collateral (from the leaf).
            if (vault_txout.scriptPubKey != lot.vault_spk) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault UTXO does not match the derived lot vault");
            if (native_collateral) {
                if (vault_txout.HasAssetTLV() || vault_txout.nValue < 0 || static_cast<uint64_t>(vault_txout.nValue) != leaf.vault_im) throw JSONRPCError(RPC_INVALID_PARAMETER, "native vault value != vault_im");
            } else {
                if (vault_txout.AssetID() != leaf.collateral_asset_id || vault_txout.AssetAmount() != leaf.vault_im) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault collateral != AssetTag(C, vault_im)");
            }

            // Payout: decode K (leaf strike) and X (resolved), compute the capped split — all from the leaf.
            arith_uint256 K, X;
            if (!DecodeScalarValue(leaf.scalar_format_id, leaf.strike, K) || !DecodeScalarValue(resolved->scalar_format_id, resolved->scalar, X)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "scalar decode failed");
            }
            const ScalarLossDenominator denom = leaf.payoff_mode == static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED) ? ScalarLossDenominator::REALIZED : ScalarLossDenominator::STRIKE;
            const CAmount dust = 546;
            ScalarCfdPayout payout;
            if (!ComputeScalarCfdPayout(K, X, denom, leaf.lambda_q, leaf.vault_im, /*short_leg=*/leaf.loss_direction == 0x01, static_cast<uint64_t>(dust), payout)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payout computation rejected the terms");
            }

            // Control block for the settle leaf within the {settle, unwind} taptree.
            TaprootBuilder vb = CreateScalarVaultBuilder(lot.settle_leaf, lot.unwind_leaf);
            if (!vb.IsComplete()) throw JSONRPCError(RPC_INTERNAL_ERROR, "vault builder incomplete");
            const std::vector<unsigned char> settle_bytes(lot.settle_leaf.begin(), lot.settle_leaf.end());
            const auto sd = vb.GetSpendData();
            const auto cit = sd.scripts.find({settle_bytes, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
            if (cit == sd.scripts.end() || cit->second.empty()) throw JSONRPCError(RPC_INTERNAL_ERROR, "could not reconstruct settle control block");
            const std::vector<unsigned char> control = *cit->second.begin();

            std::string holder_address;
            const CScript holder_spk = ResolveHolderSpk(*pwallet, opts, holder_address);
            const CAmount vault_native = CheckedAdd(0, vault_txout.nValue, "vault value");

            // Native fee candidates (keeper-owned, native-only; never the vault).
            std::vector<ScalarFundedInput> native_pool;
            {
                CCoinControl cc;
                LOCK(pwallet->cs_wallet);
                for (const COutput& o : AvailableCoinsListUnspent(*pwallet, &cc).All()) {
                    if (!o.spendable || o.outpoint == vault_op) continue;
                    if (o.txout.vExt.empty()) native_pool.push_back(ScalarFundedInput{o.outpoint, o.txout});
                }
            }

            // Fixed native output total (constant across fee passes): native collateral -> the payout legs
            // themselves (sum == vault_im, both <= MAX_MONEY since the vault output existed); asset
            // collateral -> one dust carrier per non-zero leg (the payout C rides in the AssetTag).
            CAmount native_out_fixed = 0;
            if (native_collateral) {
                if (payout.payout_owner > 0) native_out_fixed = CheckedAdd(native_out_fixed, static_cast<CAmount>(payout.payout_owner), "payout owner");
                if (payout.payout_cp > 0) native_out_fixed = CheckedAdd(native_out_fixed, static_cast<CAmount>(payout.payout_cp), "payout cp");
            } else {
                if (payout.payout_owner > 0) native_out_fixed = CheckedAdd(native_out_fixed, dust, "owner carrier");
                if (payout.payout_cp > 0) native_out_fixed = CheckedAdd(native_out_fixed, dust, "cp carrier");
            }

            std::vector<ScalarFundedInput> native_inputs;
            std::set<COutPoint> native_selected;
            CAmount fee = 0;
            CTransactionRef tx_ref;
            bool converged = false;
            for (int pass = 0; pass < 8 && !converged; ++pass) {
                CAmount native_in = vault_native;
                for (const auto& n : native_inputs) native_in = CheckedAdd(native_in, n.txout.nValue, "native inputs");
                const CAmount need = CheckedAdd(CheckedAdd(native_out_fixed, fee, "need"), dust, "need"); // reserve a non-dust change
                if (native_in < need) {
                    for (const auto& n : native_pool) {
                        if (native_in >= need) break;
                        if (!native_selected.insert(n.outpoint).second) continue;
                        native_inputs.push_back(n);
                        native_in = CheckedAdd(native_in, n.txout.nValue, "native inputs");
                    }
                    if (native_in < need) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "vault + native inputs do not cover the payouts + fee + dust");
                }

                CMutableTransaction mtx;
                mtx.version = 2;
                mtx.nLockTime = static_cast<uint32_t>(leaf.settle_lock_height);
                CTxIn vin(vault_op);
                vin.nSequence = CTxIn::SEQUENCE_FINAL - 1; // locktime-enabled, not RBF-final
                vin.scriptWitness.stack = {settle_bytes, control};
                mtx.vin.push_back(std::move(vin));
                for (const auto& n : native_inputs) mtx.vin.emplace_back(n.outpoint);

                if (payout.payout_owner > 0) {
                    CTxOut o(native_collateral ? static_cast<CAmount>(payout.payout_owner) : dust, p2tr(leaf.owner_key));
                    if (!native_collateral) o.vExt = assets::BuildAssetTagTlv(leaf.collateral_asset_id, payout.payout_owner);
                    mtx.vout.push_back(std::move(o));
                }
                if (payout.payout_cp > 0) {
                    CTxOut o(native_collateral ? static_cast<CAmount>(payout.payout_cp) : dust, p2tr(leaf.cp_key));
                    if (!native_collateral) o.vExt = assets::BuildAssetTagTlv(leaf.collateral_asset_id, payout.payout_cp);
                    mtx.vout.push_back(std::move(o));
                }
                const CAmount change = native_in - native_out_fixed - fee;
                if (change >= dust) mtx.vout.emplace_back(change, holder_spk); // sub-dust change folds into fee

                std::vector<CTxOut> spent;
                spent.push_back(vault_txout);
                for (const auto& n : native_inputs) spent.push_back(n.txout);
                tx_ref = SignExtractCovenant(*pwallet, mtx, spent, /*k=*/1);
                const CAmount want = feerate.GetFee(GetVirtualTransactionSize(*tx_ref));
                if (fee >= want) { converged = true; break; }
                fee = want;
            }
            if (!tx_ref || !converged) throw JSONRPCError(RPC_WALLET_ERROR, "Settlement fee did not converge");

            std::string berr;
            if (broadcast && !pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, berr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Broadcast failed: " + berr);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(*tx_ref));
            result.pushKV("txid", tx_ref->GetHash().GetHex());
            result.pushKV("payout_owner", strprintf("%llu", (unsigned long long)payout.payout_owner)); // uint64 (asset units may exceed INT64_MAX)
            result.pushKV("payout_cp", strprintf("%llu", (unsigned long long)payout.payout_cp));
            result.pushKV("is_fallback", resolved->is_fallback);
            result.pushKV("broadcast", broadcast);
            // Label the two pot outputs so a holder can redeem without hunting the vout. The vout build
            // order above is owner-leg first (if payout_owner>0), then cp-leg (if payout_cp>0); §6.1 maps
            // owner→long iff loss_direction==0 (owner is the long leg). A leg with a zero payout has no
            // output → its pot string is empty.
            {
                const std::string stxid = tx_ref->GetHash().GetHex();
                int owner_vout = -1, cp_vout = -1, vidx = 0;
                if (payout.payout_owner > 0) owner_vout = vidx++;
                if (payout.payout_cp > 0) cp_vout = vidx++;
                auto opstr = [&](int vo) -> std::string { return vo < 0 ? std::string() : stxid + ":" + std::to_string(vo); };
                const bool owner_is_long = (leaf.loss_direction == 0x00);
                result.pushKV("long_pot", owner_is_long ? opstr(owner_vout) : opstr(cp_vout));
                result.pushKV("short_pot", owner_is_long ? opstr(cp_vout) : opstr(owner_vout));
            }
            return result;
        },
    };
}

RPCHelpMan scalar_record_issue()
{
    return RPCHelpMan{
        "scalar.record_issue",
        "Persist a confirmed scalar note-pair issuance into the wallet (after scalar.build_issue). Reads "
        "the confirmed registry for both tokens (issued_total == lot_count), resolves the N lot-vault "
        "outpoints from the confirmed issuance tx by their derived scriptPubKeys + collateral encoding, "
        "and stores the record (terms, both child ICU outpoints, the registration + issuance txids, the N "
        "vault outpoints) so settlement / redemption / unwind can find it after a restart. register_txid "
        "is the single batch registration tx (scalar.build_register).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The note-pair economics",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"issue_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The confirmed issuance txid (scalar.build_issue)"},
            {"register_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The confirmed batch registration txid (scalar.build_register)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pair_id", "The note-pair id"},
                {RPCResult::Type::NUM, "lot_count", "N"},
                {RPCResult::Type::ARR, "lot_vaults", "The N resolved vault outpoints (txid:vout)",
                    {{RPCResult::Type::STR, "", "outpoint"}}},
                {RPCResult::Type::BOOL, "persisted", "true when the record was stored"},
            }},
        RPCExamples{HelpExampleCli("scalar.record_issue", "'{...terms...}' \"<issue_txid>\" \"<register_txid>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const ScalarNotePairTerms terms = ParseScalarNotePairTermsFromJson(request.params[0]);
            const uint256 pair_id = ComputeScalarNotePairId(terms);
            const uint32_t N = terms.lot_count;
            const bool native_collateral = terms.collateral_asset_id.IsNull();
            auto issue_h = uint256::FromHex(request.params[1].get_str());
            auto reg_h = uint256::FromHex(request.params[2].get_str());
            if (!issue_h) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid issue_txid");
            if (!reg_h) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid register_txid");
            const Txid issue_txid = Txid::FromUint256(*issue_h);

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            // Both tokens must be fully issued, with their current ICU successor an output of issue_txid.
            AssetRegistryEntry le, se;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                if (!coins.ReadAssetPolicy(terms.long_token_id, le) || !coins.ReadAssetPolicy(terms.short_token_id, se)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "L/S token not registered/confirmed on chain");
                }
            }
            if (le.issued_total != N || se.issued_total != N) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pair not fully issued (issued_total != lot_count); run scalar.build_issue and let it confirm");
            }
            if (le.icu_outpoint.hash != issue_txid || se.icu_outpoint.hash != issue_txid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "a token ICU successor is not an output of issue_txid (wrong txid or rotated since issuance)");
            }

            CTransactionRef tx;
            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(issue_txid);
                if (!wtx) throw JSONRPCError(RPC_INVALID_PARAMETER, "issue_txid is not a transaction in this wallet");
                if (pwallet->GetTxDepthInMainChain(*wtx) < 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "issue_txid is not confirmed yet");
                tx = wtx->tx;
            }

            // Prove issue_txid IS a genuine issuance of THIS pair: exactly one L + one S IssuerReg
            // successor, exactly N L + N S minted, and exactly the N canonical vaults funded — not a
            // later rotation tx that merely happens to carry vault-shaped outputs.
            {
                std::string verr;
                if (!ValidateScalarNotePairIssuanceTx(terms, pair_id, *tx, verr)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "issue_txid does not satisfy the issuance atomicity invariant: " + verr);
                }
            }

            ScalarNotePairRecord record;
            record.pair_id = pair_id;
            record.terms = terms;
            record.long_icu_outpoint = le.icu_outpoint;
            record.short_icu_outpoint = se.icu_outpoint;
            record.register_long_txid = *reg_h;
            record.register_short_txid = *reg_h; // single batch registration tx covers both children
            record.issue_txid = *issue_h;

            UniValue lot_vaults(UniValue::VARR);
            for (uint32_t i = 0; i < N; ++i) {
                const ScalarNoteLot lot = DeriveScalarNoteLot(terms, pair_id, i);
                int found = -1;
                for (size_t v = 0; v < tx->vout.size(); ++v) {
                    const CTxOut& o = tx->vout[v];
                    if (o.scriptPubKey != lot.vault_spk) continue;
                    const bool ok = native_collateral
                        ? (!o.HasAssetTLV() && o.nValue >= 0 && static_cast<uint64_t>(o.nValue) == terms.vault_im)
                        : (o.AssetID() == terms.collateral_asset_id && o.AssetAmount() == terms.vault_im);
                    if (!ok) continue;
                    if (found >= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("lot %u vault is ambiguous in the issue tx", i));
                    found = static_cast<int>(v);
                }
                if (found < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("lot %u vault not found in the issue tx (wrong terms or txid)", i));
                record.lot_vaults.emplace_back(issue_txid, static_cast<uint32_t>(found));
                lot_vaults.push_back(strprintf("%s:%u", issue_txid.GetHex(), static_cast<uint32_t>(found)));
            }

            // RegisterScalarNotePair validates full coherence (id, register/issue txids, ICU + vault
            // outpoints all from issue_txid, count, dups) and persists; it throws on any inconsistency.
            pwallet->RegisterScalarNotePair(record);

            UniValue result(UniValue::VOBJ);
            result.pushKV("pair_id", pair_id.GetHex());
            result.pushKV("lot_count", static_cast<int64_t>(N));
            result.pushKV("lot_vaults", lot_vaults);
            result.pushKV("persisted", true);
            return result;
        },
    };
}

RPCHelpMan scalar_list()
{
    return RPCHelpMan{
        "scalar.list",
        "List the scalar note pairs persisted in this wallet (recorded via scalar.record_issue). Reads "
        "the wallet's in-memory map, repopulated from disk on load.",
        {},
        RPCResult{RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "pair_id", "The note-pair id"},
                    {RPCResult::Type::NUM, "lot_count", "N"},
                    {RPCResult::Type::STR_HEX, "issue_txid", "The issuance transaction id"},
                    {RPCResult::Type::STR, "long_icu_outpoint", "Token L current ICU (txid:vout)"},
                    {RPCResult::Type::STR, "short_icu_outpoint", "Token S current ICU (txid:vout)"},
                    {RPCResult::Type::ARR, "lot_vaults", "The N persisted vault outpoints (txid:vout)",
                        {{RPCResult::Type::STR, "", "outpoint"}}},
                    {RPCResult::Type::OBJ_DYN, "terms", "The full note-pair terms (incl. derived L/S + pair_id)",
                        {{RPCResult::Type::ELISION, "", ""}}},
                }}}},
        RPCExamples{HelpExampleCli("scalar.list", "")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            UniValue arr(UniValue::VARR);
            for (const ScalarNotePairRecord& rec : pwallet->ListScalarNotePairs()) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("pair_id", rec.pair_id.GetHex());
                o.pushKV("lot_count", static_cast<int64_t>(rec.terms.lot_count));
                o.pushKV("issue_txid", rec.issue_txid.GetHex());
                o.pushKV("long_icu_outpoint", strprintf("%s:%u", rec.long_icu_outpoint.hash.GetHex(), rec.long_icu_outpoint.n));
                o.pushKV("short_icu_outpoint", strprintf("%s:%u", rec.short_icu_outpoint.hash.GetHex(), rec.short_icu_outpoint.n));
                UniValue v(UniValue::VARR);
                for (const COutPoint& op : rec.lot_vaults) v.push_back(strprintf("%s:%u", op.hash.GetHex(), op.n));
                o.pushKV("lot_vaults", v);
                o.pushKV("terms", ScalarNotePairTermsToJson(rec.terms));
                arr.push_back(o);
            }
            return arr;
        },
    };
}

} // namespace wallet
