// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RPCs for the scalar-CFD publication subsystem (CFD_GENERALISATION.md §3, §7.1):
//   scalarpublish_raw  - issuer publishes a scalar feed value (spends current ICU,
//                        recreates the ICU successor verbatim, emits one carrier)
//   scalargetfeed      - read a published (asset, feed, epoch) scalar (+ burial)
//   scalarlistfeeds    - list an asset's feeds and their head (last published epoch)

#include <bitcoin-build-config.h> // IWYU pragma: keep -- defines ENABLE_WALLET (must precede #ifdef)

#include <chainparams.h>
#include <core_io.h>
#include <key_io.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/types.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <util/strencodings.h>
#include <validation.h>

#include <arith_uint256.h>          // DecodeScalarValue out-param
#include <assets/asset.h>
#include <consensus/scalar_cfd.h>   // EncodeScalarToWire / DecodeScalarValue (format byte order)
#include <assets/registry.h>
#include <coins.h>
#include <txdb.h>

#ifdef ENABLE_WALLET
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#endif

#include <univalue.h>

#include <limits>
#include <map>

using node::NodeContext;
using node::TransactionError;

namespace {

// Burial: a publication is settlement-usable once buried >= MATURITY (mirrors the
// difficulty predicate). Pure helper over heights.
bool ScalarBuried(int tip_height, int publication_height, int maturity)
{
    return (tip_height - publication_height) >= maturity && publication_height < tip_height;
}

RPCHelpMan scalargetfeed()
{
    return RPCHelpMan{"scalargetfeed",
        "Read a published scalar feed value from the active chainstate (CFD_GENERALISATION.md §3).",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Underlying asset id (the feed's issuer)"},
            {"feed_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Feed id (u32)"},
            {"epoch", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Scalar epoch (default: latest published epoch)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Underlying asset id"},
                {RPCResult::Type::NUM, "feed_id", "Feed id"},
                {RPCResult::Type::NUM, "epoch", "Epoch returned"},
                {RPCResult::Type::NUM, "last_epoch", "Latest published epoch for this feed (head)"},
                {RPCResult::Type::STR_HEX, "scalar", "Scalar NUMERIC value (decoded from the format's wire bytes; 32-byte display hex)"},
                {RPCResult::Type::STR_HEX, "scalar_wire", "Raw on-chain wire bytes of the scalar (byte order per scalar_format_id)"},
                {RPCResult::Type::NUM, "scalar_format_id", "Scalar encoding id"},
                {RPCResult::Type::NUM, "publication_height", "Block height the publication was confirmed at"},
                {RPCResult::Type::NUM, "confirmations", "Confirmations of the publication"},
                {RPCResult::Type::BOOL, "buried", "Whether the publication is buried >= maturity (settlement-usable)"},
            }
        },
        RPCExamples{HelpExampleCli("scalargetfeed", "\"<asset_id>\" 1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            auto aid = uint256::FromHex(request.params[0].get_str());
            if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id");
            const uint32_t feed_id = request.params[1].getInt<uint32_t>();

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();
            const CCoinsViewCache& tip = active.CoinsTip();

            uint64_t last_epoch = 0;
            if (!tip.ReadAssetScalarHead(*aid, feed_id, last_epoch)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no such scalar feed (asset_id, feed_id)");
            }
            const uint64_t epoch = request.params[2].isNull() ? last_epoch : request.params[2].getInt<uint64_t>();

            ScalarRecord rec;
            if (!tip.ReadAssetScalar(*aid, feed_id, epoch, rec)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no such scalar epoch");
            }
            const int tip_height = active.m_chain.Height();
            const int maturity = chainman.GetConsensus().SCALARCFD_MATURITY_DEPTH;

            UniValue r(UniValue::VOBJ);
            r.pushKV("asset_id", aid->GetHex());
            r.pushKV("feed_id", (uint64_t)feed_id);
            r.pushKV("epoch", epoch);
            r.pushKV("last_epoch", last_epoch);
            // Display the NUMERIC value (decode the format's wire bytes); also surface the raw wire for
            // debugging. A non-canonical stored value (should be impossible post-publication-check) shows
            // its raw bytes only.
            arith_uint256 numeric;
            if (DecodeScalarValue(rec.scalar_format_id, rec.scalar, numeric)) {
                r.pushKV("scalar", ArithToUint256(numeric).GetHex());
            } else {
                r.pushKV("scalar", rec.scalar.GetHex());
            }
            r.pushKV("scalar_wire", rec.scalar.GetHex());
            r.pushKV("scalar_format_id", (int)rec.scalar_format_id);
            r.pushKV("publication_height", rec.publication_height);
            int conf = tip_height - rec.publication_height + 1;
            if (conf < 0) conf = 0;
            r.pushKV("confirmations", conf);
            r.pushKV("buried", ScalarBuried(tip_height, rec.publication_height, maturity));
            return r;
        }
    };
}

RPCHelpMan scalarlistfeeds()
{
    return RPCHelpMan{"scalarlistfeeds",
        "List an asset's scalar feeds and each feed's head (latest published epoch). "
        "Reconciles the on-disk index with the in-memory chainstate overlay.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Underlying asset id"},
        },
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "feed_id", "Feed id"},
                        {RPCResult::Type::NUM, "last_epoch", "Latest published epoch for this feed"},
                    }
                }
            }
        },
        RPCExamples{HelpExampleCli("scalarlistfeeds", "\"<asset_id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            auto aid = uint256::FromHex(request.params[0].get_str());
            if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id");

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            // On-disk feeds, then reconcile staged (unflushed) writes/erases — mirrors
            // listregisteredassets so a just-connected feed is not missed.
            std::map<uint32_t, uint64_t> feeds;
            for (const auto& [feed_id, last_epoch] : active.CoinsDB().GetAssetScalarFeeds(*aid)) {
                feeds[feed_id] = last_epoch;
            }
            std::vector<std::pair<uint32_t, uint64_t>> staged_added;
            std::vector<uint32_t> staged_erased;
            active.CoinsTip().GetStagedScalarHeads(*aid, staged_added, staged_erased);
            for (const auto& [feed_id, last_epoch] : staged_added) feeds[feed_id] = last_epoch;
            for (const uint32_t feed_id : staged_erased) feeds.erase(feed_id);

            UniValue arr(UniValue::VARR);
            for (const auto& [feed_id, last_epoch] : feeds) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("feed_id", (uint64_t)feed_id);
                o.pushKV("last_epoch", last_epoch);
                arr.push_back(std::move(o));
            }
            return arr;
        }
    };
}

#ifdef ENABLE_WALLET
RPCHelpMan scalarpublish_raw()
{
    return RPCHelpMan{"scalarpublish_raw",
        "Publish a scalar feed value. Spends the asset's CURRENT ICU (issuer auth), recreates "
        "the ICU successor with the SAME IssuerReg bytes (no governance change), and emits ONE "
        "ISSUER_SCALAR carrier output. One publication per asset per block (consensus enforces "
        "one IssuerReg per asset per block). The ICU successor's IssuerReg is taken verbatim from "
        "the on-chain ICU output — never rebuilt — so a fixing can never mutate policy/metadata.",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU txid (must equal the asset's current ICU outpoint)"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU vout"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Underlying asset id (feed issuer)"},
            {"new_icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Successor ICU destination address"},
            {"new_icu_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Successor ICU bond amount"},
            {"feed_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Feed id (u32)"},
            {"scalar_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Scalar epoch (u64); must equal current head+1 (or 1 if none)"},
            {"scalar_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Scalar NUMERIC value, 64 hex chars (uint256 display hex). Stored as the format's wire bytes (LE/BE per scalar_format_id); must fit the format width."},
            {"scalar_format_id", RPCArg::Type::NUM, RPCArg::Default{assets::SCALAR_FORMAT_RAW_U256_LE}, "Scalar encoding id (RAW_U256 / U64 / U128, LE or BE)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{false}, "Fund using the loaded wallet"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Sign and broadcast with the loaded wallet"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal RBF"},
                    {"change_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Send the funding change to this address (default: wallet-chosen)"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (funded/signed per options)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast txid if broadcast=true"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const Txid icu_tx = Txid::FromHex(request.params[0].get_str()).value();
            const uint32_t icu_vout = request.params[1].getInt<uint32_t>();
            auto aid = uint256::FromHex(request.params[2].get_str());
            if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id");
            const CTxDestination icu_dest = DecodeDestination(request.params[3].get_str());
            if (!IsValidDestination(icu_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid new_icu_address");
            const CAmount icu_amt = AmountFromValue(request.params[4]);
            const uint32_t feed_id = request.params[5].getInt<uint32_t>();
            const uint64_t scalar_epoch = request.params[6].getInt<uint64_t>();
            if (scalar_epoch == 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "scalar_epoch must be >= 1 (epoch 0 is reserved)");
            auto scalar = uint256::FromHex(request.params[7].get_str());
            if (!scalar) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid scalar_hex (need 64 hex chars)");
            const uint16_t scalar_format_id = request.params[8].isNull()
                ? assets::SCALAR_FORMAT_RAW_U256_LE
                : request.params[8].getInt<uint16_t>(); // getInt<uint16_t> rejects >65535 (no silent truncation)
            if (!assets::IsKnownScalarFormat(scalar_format_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("unknown scalar_format_id %u", scalar_format_id));
            }
            // scalar_hex is a NUMERIC display value; store the format's wire bytes (identity for LE,
            // byte-reversed for BE) so settlement reads back the intended number. Also rejects a value
            // that exceeds the format width, which would otherwise be a non-canonical (unsettleable) feed.
            uint256 wire_scalar;
            if (!EncodeScalarToWire(scalar_format_id, *scalar, wire_scalar)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("scalar exceeds scalar_format_id %u width", scalar_format_id));
            }

            const COutPoint icu_op(icu_tx, icu_vout);

            // --- read + validate against the active chainstate; capture the verbatim
            //     ISSUER_REG bytes for the successor (the five guards). ---
            std::vector<unsigned char> issuer_reg_tlv;
            {
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                Chainstate& active = chainman.ActiveChainstate();
                const CCoinsViewCache& tip = active.CoinsTip();

                AssetRegistryEntry entry;
                if (!tip.ReadAssetPolicy(*aid, entry)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown asset_id");
                if (entry.icu_outpoint != icu_op) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_txid:icu_vout is not the asset's current ICU outpoint");
                }
                const auto coin = tip.GetCoin(icu_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "current ICU coin not in the UTXO set");
                const auto reg = assets::ParseIssuerReg(coin->out.vExt);
                if (!reg || reg->asset_id != *aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU output is not an ISSUER_REG for this asset");

                // Successor bond pre-checks (advisory; ConnectBlock is authoritative).
                const bool unlocked = entry.IsUnlocked();
                if (!unlocked) {
                    // Mirror consensus (validation.cpp:4859): the rotation floor is rotation_min_sats,
                    // or the current ICU's bond value when rotation_min_sats is 0 (legacy/zero entries).
                    const CAmount prev_bond = coin->out.nValue;
                    const CAmount min_bond = entry.rotation_min_sats != 0
                        ? static_cast<CAmount>(entry.rotation_min_sats) : prev_bond;
                    if (icu_amt < min_bond) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                            "new_icu_amount %d below required rotation bond %d (asset not yet unlocked)", icu_amt, min_bond));
                    }
                } else if (icu_amt < 546) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "new_icu_amount below dust (546)");
                }
                if (reg->unlock_fees_sats != std::numeric_limits<uint64_t>::max()
                    && static_cast<uint64_t>(icu_amt) > reg->unlock_fees_sats) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                        "new_icu_amount %d exceeds unlock_fees_sats %d (ConnectBlock requires unlock_fees_sats >= bond)",
                        icu_amt, reg->unlock_fees_sats));
                }

                issuer_reg_tlv = coin->out.vExt; // verbatim — strongest preservation
            }

            // --- build the publication tx: IN current ICU; OUT successor ICU (verbatim
            //     IssuerReg) + one OP_RETURN scalar carrier. ---
            assets::IssuerScalar pub{};
            pub.underlying_asset_id = *aid;
            pub.feed_id = feed_id;
            pub.scalar_epoch = scalar_epoch;
            pub.scalar_format_id = scalar_format_id;
            pub.scalar = wire_scalar; // format-encoded (LE/BE) wire bytes
            const std::vector<unsigned char> carrier_tlv = assets::BuildIssuerScalarTlv(pub);
            const CScript icu_script = GetScriptForDestination(icu_dest);

            CMutableTransaction mtx;
            mtx.vin.emplace_back(icu_op);
            {
                CTxOut icu_out(icu_amt, icu_script);
                icu_out.vExt = issuer_reg_tlv;
                mtx.vout.push_back(icu_out);
            }
            {
                CTxOut carrier(0, CScript() << OP_RETURN);
                carrier.vExt = carrier_tlv;
                mtx.vout.push_back(carrier);
            }

            // --- options ---
            bool autofund = false, broadcast = false;
            std::optional<double> fee_rate_vb;
            std::optional<bool> replaceable;
            CTxDestination change_dest = CNoDestination();
            if (!request.params[9].isNull()) {
                const UniValue& opt = request.params[9];
                autofund = opt.exists("autofund") && opt["autofund"].get_bool();
                broadcast = opt.exists("broadcast") && opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                if (opt.exists("change_address")) {
                    change_dest = DecodeDestination(opt["change_address"].get_str());
                    if (!IsValidDestination(change_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid change_address");
                }
            }

            UniValue result(UniValue::VOBJ);
            if (!autofund && !broadcast) {
                DataStream ds; ds << TX_WITH_WITNESS(mtx);
                result.pushKV("hex", HexStr(ds));
                return result;
            }

            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet required for autofund/broadcast");

            // Fund: FundTransaction requires an empty vout, so stash our two outputs,
            // fund with the ICU as the sole recipient, then reattach the IssuerReg and
            // append the carrier, and shave change to pay for the extra vbytes.
            wallet::CRecipient recipient{icu_dest, icu_amt, false};
            mtx.vout.clear();
            wallet::CCoinControl cc;
            if (fee_rate_vb) { cc.fOverrideFeeRate = true; cc.m_feerate = CFeeRate((CAmount)(*fee_rate_vb * 1000.0)); }
            if (replaceable) cc.m_signal_bip125_rbf = *replaceable;
            cc.m_allow_other_inputs = true;   // add native fee inputs
            cc.m_avoid_asset_utxos = true;     // never auto-select asset/ICU UTXOs for fees
            if (IsValidDestination(change_dest)) cc.destChange = change_dest;
            // Deliberately NOT setting m_required_asset_id / m_allow_icu_selection: the current ICU is
            // preselected via mtx.vin (FundTransaction Select()s it), so publication = ICU rotation +
            // native fee inputs only. Setting m_required_asset_id would admit same-asset holder UTXOs
            // into the pool, which combined with the ICU spend could become an authorized BURN.
            auto txr = wallet::FundTransaction(*pwallet, mtx, {recipient}, std::nullopt, false, cc);
            if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
            CMutableTransaction funded(*txr->tx);
            const std::optional<unsigned int> change_pos = txr->change_pos;

            // Reattach the verbatim IssuerReg to the ICU recipient output, identified as the UNIQUE
            // NON-change output matching both the ICU script AND amount — so a change output that
            // happens to share new_icu_address's script is never mistaken for the ICU successor.
            int icu_idx = -1;
            for (size_t i = 0; i < funded.vout.size(); ++i) {
                if (change_pos && i == *change_pos) continue;
                const CTxOut& o = funded.vout[i];
                if (o.scriptPubKey == icu_script && o.nValue == icu_amt && o.vExt.empty()) {
                    if (icu_idx != -1) throw JSONRPCError(RPC_WALLET_ERROR, "Ambiguous ICU output after funding");
                    icu_idx = static_cast<int>(i);
                }
            }
            if (icu_idx == -1) throw JSONRPCError(RPC_WALLET_ERROR, "ICU recipient output not found after funding");
            funded.vout[icu_idx].vExt = issuer_reg_tlv;

            // Append the single OP_RETURN scalar carrier at the end (existing indices, incl. change_pos, unchanged).
            {
                CTxOut carrier(0, CScript() << OP_RETURN);
                carrier.vExt = carrier_tlv;
                funded.vout.push_back(carrier);
            }

            // Pay for the bytes added AFTER funding (reattached IssuerReg vExt + carrier output + its
            // vExt) by shaving the CHANGE output. These are all NON-WITNESS bytes, so the marginal
            // vsize is exactly the difference of the two unsigned serializations, and the marginal fee
            // is that difference × the funding feerate (GetMinimumFeeRate honours fee_rate / wallet
            // default). Avoids the fee/unsigned-size division pitfall.
            {
                const CFeeRate target = wallet::GetMinimumFeeRate(*pwallet, cc, nullptr);
                const unsigned int funded_size = GetVirtualTransactionSize(CTransaction(*txr->tx));
                const unsigned int actual_size = GetVirtualTransactionSize(CTransaction(funded));
                const CAmount deficit = (actual_size > funded_size) ? target.GetFee(actual_size - funded_size) : 0;
                if (deficit > 0) {
                    if (!change_pos) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "No change output to cover carrier fee; raise fee_rate or add inputs");
                    }
                    CTxOut& chg = funded.vout[*change_pos];
                    if (chg.nValue - deficit < 546) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient change to cover carrier fee; raise fee_rate or add inputs");
                    }
                    chg.nValue -= deficit;
                }
            }

            if (broadcast) {
                PartiallySignedTransaction psbtx(funded);
                bool complete = false;
                const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, true, false);
                if (err) throw JSONRPCPSBTError(*err);
                CMutableTransaction mfinal;
                if (!FinalizeAndExtractPSBT(psbtx, mfinal)) throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                NodeContext& node = EnsureAnyNodeContext(request.context);
                std::string err_string;
                const TransactionError errcode = BroadcastTransaction(node, MakeTransactionRef(CTransaction(mfinal)), err_string, 0, true, true);
                if (errcode != TransactionError::OK) throw JSONRPCError(RPC_VERIFY_ERROR, err_string);
                result.pushKV("txid", CTransaction(mfinal).GetHash().ToString());
                DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                result.pushKV("hex", HexStr(ds));
                return result;
            }

            DataStream ds; ds << TX_WITH_WITNESS(funded);
            result.pushKV("hex", HexStr(ds));
            return result;
        }
    };
}
#endif // ENABLE_WALLET

} // namespace

void RegisterScalarRPC(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &scalargetfeed},
        {"blockchain", &scalarlistfeeds},
#ifdef ENABLE_WALLET
        {"rawtransactions", &scalarpublish_raw},
#endif
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
