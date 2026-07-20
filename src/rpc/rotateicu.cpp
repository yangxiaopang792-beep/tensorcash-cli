#include <core_io.h>
#include <key_io.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/types.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <assets/asset.h>

using node::NodeContext;
using node::TransactionError;

#ifdef ENABLE_WALLET
static std::string DescribeRequestContext(const JSONRPCRequest& request)
{
    if (!request.context.has_value()) return "none";
    const std::type_info& type = request.context.type();
    if (type == typeid(node::NodeContext*)) return "node::NodeContext*";
    if (type == typeid(wallet::WalletContext*)) return "wallet::WalletContext*";
    return type.name();
}

static std::shared_ptr<wallet::CWallet> GetWalletForAssetsRPC(const JSONRPCRequest& request)
{
    try {
        return wallet::GetWalletForJSONRPCRequest(request);
    } catch (const UniValue& err) {
        const UniValue& code = err["code"];
        if (code.isNum() && code.getInt<int>() == RPC_INTERNAL_ERROR) {
            const UniValue& message = err["message"];
            const std::string context_desc = DescribeRequestContext(request);
            const std::string original = message.isStr() ? message.get_str() : "Wallet context not found";
            throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                strprintf("%s (ctx=%s)", original, context_desc));
        }
        throw;
    }
}
#endif // ENABLE_WALLET

static RPCHelpMan rotateicu_raw()
{
    return RPCHelpMan{"rotateicu_raw",
        "Rotate ICU to a new address and/or bond amount (pure rotation, no asset minting/burning).",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current ICU transaction ID"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Current ICU output index"},
            {"new_icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination address"},
            {"new_icu_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "New ICU BTC bond amount"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits (u32)"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{assets::SPK_DEFAULT_ALLOWED}, "Allowed families (u16)"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold sats"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{false}, "Automatically fund using loaded wallet"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing with loaded wallet"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal RBF"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (may be funded/signed depending on options and wallet)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast txid if broadcast=true"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            Txid icu_tx = Txid::FromHex(request.params[0].get_str()).value();
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();
            CTxDestination icu_dest = DecodeDestination(request.params[2].get_str());
            if (!IsValidDestination(icu_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid icu address");
            CAmount icu_amt = AmountFromValue(request.params[3]);
            auto aid = uint256::FromHex(request.params[4].get_str()); if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id");
            uint32_t policy_bits = request.params[5].getInt<uint32_t>();
            uint16_t allowed = request.params[6].isNull() ? assets::SPK_DEFAULT_ALLOWED : request.params[6].getInt<uint16_t>();
            bool has_unlock = (request.params.size() > 7) && !request.params[7].isNull(); uint64_t unlock = has_unlock ? request.params[7].getInt<uint64_t>() : 0;

            // Build transaction: IN: old ICU, OUT: new ICU with IssuerReg (autofund adds change)
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint(icu_tx, icu_vout));
            mtx.vout.emplace_back(icu_amt, GetScriptForDestination(icu_dest));

            // Build IssuerReg TLV
            std::vector<unsigned char> regp; regp.insert(regp.end(), aid->begin(), aid->end());
            unsigned char pb[4]; WriteLE32(pb, policy_bits); regp.insert(regp.end(), pb, pb+4);
            unsigned char ab[2]; ab[0]=allowed&0xFF; ab[1]=(allowed>>8)&0xFF; regp.insert(regp.end(), ab, ab+2);
            if (has_unlock){ unsigned char ub[8]; WriteLE64(ub, unlock); regp.insert(regp.end(), ub, ub+8);}
            std::vector<unsigned char> regtlv;
            regtlv.push_back((uint8_t)assets::OutExtType::ISSUER_REG);
            regtlv.push_back((uint8_t)regp.size());
            regtlv.insert(regtlv.end(), regp.begin(), regp.end());
            mtx.vout[0].vExt = std::move(regtlv);

            UniValue result(UniValue::VOBJ);
            std::shared_ptr<wallet::CWallet> pwallet;
            bool autofund=false, broadcast=false; std::optional<double> fee_rate_vb; std::optional<bool> replaceable;
            if (!request.params[8].isNull()) {
                const UniValue& opt = request.params[8];
                autofund = opt.exists("autofund") && opt["autofund"].get_bool();
                broadcast = opt.exists("broadcast") && opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
            }
            if (autofund || broadcast) {
                pwallet = GetWalletForAssetsRPC(request);
            }
            if (autofund && pwallet) {
                wallet::CRecipient recipient{icu_dest, icu_amt, false};
                // Store the IssuerReg TLV with its scriptPubKey for reattachment
                const CScript icu_script = GetScriptForDestination(icu_dest);
                std::vector<unsigned char> issuer_reg_tlv = mtx.vout[0].vExt;

                mtx.vout.clear();  // Required by FundTransaction assertion
                wallet::CCoinControl cc;
                if (fee_rate_vb){ cc.fOverrideFeeRate=true; cc.m_feerate = CFeeRate((CAmount)(*fee_rate_vb*1000.0)); }
                if (replaceable) cc.m_signal_bip125_rbf=*replaceable;
                if (aid) cc.m_required_asset_id = *aid;
                cc.m_allow_icu_selection = true;
                cc.m_allow_other_inputs = true;
                auto txr = wallet::FundTransaction(*pwallet, mtx, {recipient}, std::nullopt, false, cc);
                if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                CMutableTransaction funded(*txr->tx);

                // Re-attach IssuerReg TLV by matching scriptPubKey only (like rotateicu RPC does)
                bool found_icu_output = false;
                for (auto& out : funded.vout) {
                    if (out.scriptPubKey == icu_script && out.vExt.empty()) {
                        out.vExt = issuer_reg_tlv;
                        found_icu_output = true;
                        break;
                    }
                }
                if (!found_icu_output) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to reattach IssuerReg TLV: ICU output not found after funding");
                }

                if (broadcast) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete=false;
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
            DataStream ds; ds << TX_WITH_WITNESS(mtx);
            result.pushKV("hex", HexStr(ds));
            return result;
        }
    };
}

void RegisterRotateICURPC(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &rotateicu_raw},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
