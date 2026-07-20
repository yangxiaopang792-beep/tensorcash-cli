// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/bip322.h>

#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

/**
 * BIP-322 Simple Signature Verification
 *
 * Implements verification of BIP-322 signatures for any address type.
 * Supports both witness-based (P2WPKH, P2WSH, P2TR) and legacy scriptSig-based (P2PKH, P2SH) signatures.
 *
 * Key features:
 * - Uses raw message byte hashing (BIP-322 spec compliant)
 * - Auto-detects script type and populates scriptSig or witness accordingly
 * - Full consensus verification via VerifyScript with P2SH, witness, and taproot flags
 */

static CMutableTransaction CreateToSpendTransaction(const CScript& scriptPubKey, const std::string& message)
{
    // to_spend: OP_0 OP_SHA256(message)
    // BIP-322: Hash the raw message bytes, not serialized as varstring
    HashWriter ss{};
    ss.write(MakeByteSpan(message));
    uint256 message_hash = ss.GetHash();

    CMutableTransaction to_spend;
    to_spend.version = 0;
    to_spend.nLockTime = 0;
    to_spend.vin.resize(1);
    to_spend.vin[0].prevout.SetNull();
    to_spend.vin[0].scriptSig = CScript() << OP_0 << ToByteVector(message_hash);
    to_spend.vin[0].nSequence = 0;
    to_spend.vout.resize(1);
    to_spend.vout[0].nValue = 0;
    to_spend.vout[0].scriptPubKey = scriptPubKey;

    return to_spend;
}

static CMutableTransaction CreateToSignTransaction(const Txid& to_spend_txid, const CScript& scriptSig, const CScriptWitness& witness)
{
    CMutableTransaction to_sign;
    to_sign.version = 0;
    to_sign.nLockTime = 0;
    to_sign.vin.resize(1);
    to_sign.vin[0].prevout = COutPoint(to_spend_txid, 0);
    to_sign.vin[0].scriptSig = scriptSig;
    to_sign.vin[0].scriptWitness = witness;
    to_sign.vin[0].nSequence = 0;
    to_sign.vout.resize(1);
    to_sign.vout[0].nValue = 0;
    to_sign.vout[0].scriptPubKey = CScript() << OP_RETURN;

    return to_sign;
}

bool VerifyBIP322Signature(const std::string& address, const std::string& signature, const std::string& message)
{
    // Decode address to get scriptPubKey
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        return false;
    }

    CScript scriptPubKey = GetScriptForDestination(dest);

    // Decode signature from base64
    auto sig_data = DecodeBase64(signature);
    if (!sig_data) {
        return false;
    }

    // Determine if this is a witness-based or legacy scriptSig-based signature
    // Witness types: P2WPKH, P2WSH, P2TR
    // Legacy types: P2PKH, P2SH (without witness)
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType script_type = Solver(scriptPubKey, solutions);
    bool is_witness = (script_type == TxoutType::WITNESS_V0_KEYHASH ||
                       script_type == TxoutType::WITNESS_V0_SCRIPTHASH ||
                       script_type == TxoutType::WITNESS_V1_TAPROOT);

    CScript scriptSig;
    CScriptWitness witness;

    try {
        SpanReader stream{*sig_data};

        if (is_witness) {
            // Modern witness-based signature: parse as witness stack
            stream >> witness.stack;
        } else {
            // Legacy scriptSig-based signature: parse as CScript
            stream >> scriptSig;
        }
    } catch (...) {
        return false;
    }

    // Create BIP-322 transactions
    CMutableTransaction to_spend = CreateToSpendTransaction(scriptPubKey, message);
    Txid to_spend_txid = to_spend.GetHash();
    CMutableTransaction to_sign = CreateToSignTransaction(to_spend_txid, scriptSig, witness);

    // Verify the signature
    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    spent_outputs.push_back(to_spend.vout[0]);
    txdata.Init(to_sign, std::move(spent_outputs), /*force=*/true);
    MutableTransactionSignatureChecker checker(&to_sign, 0, to_spend.vout[0].nValue, txdata, MissingDataBehavior::FAIL);

    ScriptError error;
    unsigned int flags = SCRIPT_VERIFY_P2SH |
                         SCRIPT_VERIFY_DERSIG |
                         SCRIPT_VERIFY_NULLDUMMY |
                         SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                         SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                         SCRIPT_VERIFY_WITNESS |
                         SCRIPT_VERIFY_CLEANSTACK |
                         SCRIPT_VERIFY_TAPROOT;

    bool verified = VerifyScript(
        to_sign.vin[0].scriptSig,
        scriptPubKey,
        &to_sign.vin[0].scriptWitness,
        flags,
        checker,
        &error
    );

    if (!verified) {
        LogPrintf("BIP-322 verification failed: %s\n", ScriptErrorString(error));
    }

    return verified;
}

static RPCHelpMan verifymessagebip322()
{
    return RPCHelpMan{"verifymessagebip322",
        "Verify a BIP-322 signed message for any address type (P2PKH, P2WPKH, P2TR, etc.).",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address that signed the message."},
            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The BIP-322 signature in base64 encoding."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "If the signature is verified or not."
        },
        RPCExamples{
            HelpExampleCli("verifymessagebip322", "\"bc1q...\" \"<signature>\" \"TENSORCASH_GOVERNANCE:...\"")
            + HelpExampleRpc("verifymessagebip322", "\"bc1q...\", \"<signature>\", \"TENSORCASH_GOVERNANCE:...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string address = self.Arg<std::string>("address");
            std::string signature = self.Arg<std::string>("signature");
            std::string message = self.Arg<std::string>("message");

            bool verified = VerifyBIP322Signature(address, signature, message);
            return verified;
        },
    };
}

void RegisterBIP322RPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"util", &verifymessagebip322},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
