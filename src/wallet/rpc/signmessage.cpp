// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/signmessage.h>
#include <hash.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <util/strencodings.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <univalue.h>

namespace wallet {
RPCHelpMan signmessage()
{
    return RPCHelpMan{"signmessage",
        "\nSign a message with the private key of an address" +
          HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for the private key."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"my message\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            EnsureWalletIsUnlocked(*pwallet);

            std::string strAddress = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            CTxDestination dest = DecodeDestination(strAddress);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            const PKHash* pkhash = std::get_if<PKHash>(&dest);
            if (!pkhash) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
            }

            std::string signature;
            SigningResult err = pwallet->SignMessage(strMessage, *pkhash, signature);
            if (err == SigningResult::SIGNING_FAILED) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(err));
            } else if (err != SigningResult::OK) {
                throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
            }

            return signature;
        },
    };
}

RPCHelpMan signmessagebip322()
{
    return RPCHelpMan{"signmessagebip322",
        "\nSign a message using BIP-322 format for any address type (P2WPKH, P2WSH, P2TR, etc.)\n"
        "This produces a signature that can be verified with verifymessagebip322." +
        HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for signing."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The BIP-322 signature encoded in base64"
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagebip322", "\"bc1q...\" \"TENSORCASH_GOVERNANCE:...\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessagebip322", "\"bc1q...\" \"<signature>\" \"TENSORCASH_GOVERNANCE:...\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessagebip322", "\"bc1q...\", \"TENSORCASH_GOVERNANCE:...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            std::string strAddress = self.Arg<std::string>("address");
            std::string strMessage = self.Arg<std::string>("message");

            std::string signature;
            std::string error;
            if (!pwallet->SignMessageBIP322(strAddress, strMessage, signature, error)) {
                throw JSONRPCError(RPC_WALLET_ERROR, error);
            }
            return signature;
        },
    };
}
} // namespace wallet
