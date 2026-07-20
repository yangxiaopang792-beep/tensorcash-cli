// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <addresstype.h>
#include <key.h>
#include <key_io.h>
#include <modeldb.h>
#include <policy/rbf.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <rpc/server_util.h>
#include <consensus/params.h>
#include <consensus/model_verification.h>
#include <util/transaction_identifier.h>
#include <util/vector.h>
#include <tinyformat.h>
#include <consensus/validation.h>
#include <consensus/consensus.h>
#include <policy/feerate.h>
#include <node/transaction.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/api_model_registration.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <validationapi.h>
#include <logging.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <script/script.h>

#include <algorithm>
#include <deque>
#include <map>
#include <limits>
#include <optional>
#include <set>

using interfaces::FoundBlock;

namespace wallet {
static void WalletTxToJSON(const CWallet& wallet, const CWalletTx& wtx, UniValue& entry)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    interfaces::Chain& chain = wallet.chain();
    int confirms = wallet.GetTxDepthInMainChain(wtx);
    entry.pushKV("confirmations", confirms);
    if (wtx.IsCoinBase())
        entry.pushKV("generated", true);
    if (auto* conf = wtx.state<TxStateConfirmed>())
    {
        entry.pushKV("blockhash", conf->confirmed_block_hash.GetHex());
        entry.pushKV("blockheight", conf->confirmed_block_height);
        entry.pushKV("blockindex", conf->position_in_block);
        int64_t block_time;
        CHECK_NONFATAL(chain.findBlock(conf->confirmed_block_hash, FoundBlock().time(block_time)));
        entry.pushKV("blocktime", block_time);
    } else {
        entry.pushKV("trusted", CachedTxIsTrusted(wallet, wtx));
    }
    entry.pushKV("txid", wtx.GetHash().GetHex());
    entry.pushKV("wtxid", wtx.GetWitnessHash().GetHex());
    UniValue conflicts(UniValue::VARR);
    for (const Txid& conflict : wallet.GetTxConflicts(wtx))
        conflicts.push_back(conflict.GetHex());
    entry.pushKV("walletconflicts", std::move(conflicts));
    UniValue mempool_conflicts(UniValue::VARR);
    for (const Txid& mempool_conflict : wtx.mempool_conflicts)
        mempool_conflicts.push_back(mempool_conflict.GetHex());
    entry.pushKV("mempoolconflicts", std::move(mempool_conflicts));
    entry.pushKV("time", wtx.GetTxTime());
    entry.pushKV("timereceived", int64_t{wtx.nTimeReceived});

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        RBFTransactionState rbfState = chain.isRBFOptIn(*wtx.tx);
        if (rbfState == RBFTransactionState::UNKNOWN)
            rbfStatus = "unknown";
        else if (rbfState == RBFTransactionState::REPLACEABLE_BIP125)
            rbfStatus = "yes";
    }
    entry.pushKV("bip125-replaceable", rbfStatus);

    for (const std::pair<const std::string, std::string>& item : wtx.mapValue)
        entry.pushKV(item.first, item.second);
}

static std::string ModelStatusToString(ModelRegistrationStatus status)
{
    switch (status) {
    case ModelRegistrationStatus::PendingDeposit:
        return "pending_deposit";
    case ModelRegistrationStatus::PendingVerification:
        return "pending_verification";
    case ModelRegistrationStatus::Registered:
        return "registered";
    case ModelRegistrationStatus::Locked:
        return "locked";
    case ModelRegistrationStatus::Banned:
        return "banned";
    }
    return "unknown";
}

static int GetModelDepositUnlockHeight(const ModelRecord& record, const Consensus::Params& consensus_params)
{
    if (record.deposit_block_height <= 0) {
        return 0;
    }
    return record.deposit_block_height + consensus_params.ModelCommitRefundDelay;
}

struct tallyitem
{
    CAmount nAmount{0};
    int nConf{std::numeric_limits<int>::max()};
    std::vector<Txid> txids;
    bool fIsWatchonly{false};
    tallyitem() = default;
};

static UniValue ListReceived(const CWallet& wallet, const UniValue& params, const bool by_label, const bool include_immature_coinbase) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].getInt<int>();

    // Whether to include empty labels
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;

    if (ParseIncludeWatchonly(params[2], wallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    std::optional<CTxDestination> filtered_address{std::nullopt};
    if (!by_label && !params[3].isNull() && !params[3].get_str().empty()) {
        if (!IsValidDestinationString(params[3].get_str())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "address_filter parameter was invalid");
        }
        filtered_address = DecodeDestination(params[3].get_str());
    }

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const auto& [_, wtx] : wallet.mapWallet) {

        int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (nDepth < nMinDepth)
            continue;

        // Coinbase with less than 1 confirmation is no longer in the main chain
        if ((wtx.IsCoinBase() && (nDepth < 1))
            || (wallet.IsTxImmatureCoinBase(wtx) && !include_immature_coinbase)) {
            continue;
        }

        for (const CTxOut& txout : wtx.tx->vout) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            if (filtered_address && !(filtered_address == address)) {
                continue;
            }

            isminefilter mine = wallet.IsMine(address);
            if (!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> label_tally;

    const auto& func = [&](const CTxDestination& address, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        if (is_change) return; // no change addresses

        auto it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            return;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (by_label) {
            tallyitem& _item = label_tally[label];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        } else {
            UniValue obj(UniValue::VOBJ);
            if (fIsWatchonly) obj.pushKV("involvesWatchonly", true);
            obj.pushKV("address",       EncodeDestination(address));
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label", label);
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end()) {
                for (const Txid& _item : (*it).second.txids) {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.pushKV("txids", std::move(transactions));
            ret.push_back(std::move(obj));
        }
    };

    if (filtered_address) {
        const auto& entry = wallet.FindAddressBookEntry(*filtered_address, /*allow_change=*/false);
        if (entry) func(*filtered_address, entry->GetLabel(), entry->IsChange(), entry->purpose);
    } else {
        // No filtered addr, walk-through the addressbook entry
        wallet.ForEachAddrBookEntry(func);
    }

    if (by_label) {
        for (const auto& entry : label_tally) {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            if (entry.second.fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label",         entry.first);
            ret.push_back(std::move(obj));
        }
    }

    return ret;
}

RPCHelpMan listreceivedbyaddress()
{
    return RPCHelpMan{"listreceivedbyaddress",
                "\nList balances by receiving address.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include addresses that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Whether to include watch-only addresses (see 'importaddress')"},
                    {"address_filter", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If present and non-empty, only return information on this address."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", /*optional=*/true, "Only returns true if imported addresses were involved in transaction"},
                            {RPCResult::Type::STR, "address", "The receiving address"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received by the address"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                            {RPCResult::Type::ARR, "txids", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The ids of transactions received with the address"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleCli("listreceivedbyaddress", "6 true true \"\" true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true, \"" + EXAMPLE_ADDRESS[0] + "\", true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const bool include_immature_coinbase{request.params[4].isNull() ? false : request.params[4].get_bool()};

    LOCK(pwallet->cs_wallet);

    return ListReceived(*pwallet, request.params, false, include_immature_coinbase);
},
    };
}

RPCHelpMan listreceivedbylabel()
{
    return RPCHelpMan{"listreceivedbylabel",
                "\nList received transactions by label.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include labels that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Whether to include watch-only addresses (see 'importaddress')"},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", /*optional=*/true, "Only returns true if imported addresses were involved in transaction"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount received by addresses with this label"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbylabel", "")
            + HelpExampleCli("listreceivedbylabel", "6 true")
            + HelpExampleRpc("listreceivedbylabel", "6, true, true, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const bool include_immature_coinbase{request.params[3].isNull() ? false : request.params[3].get_bool()};

    LOCK(pwallet->cs_wallet);

    return ListReceived(*pwallet, request.params, true, include_immature_coinbase);
},
    };
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest)) {
        entry.pushKV("address", EncodeDestination(dest));
    }
}

/**
 * List transactions based on the given criteria.
 *
 * @param  wallet         The wallet.
 * @param  wtx            The wallet transaction.
 * @param  nMinDepth      The minimum confirmation depth.
 * @param  fLong          Whether to include the JSON version of the transaction.
 * @param  ret            The vector into which the result is stored.
 * @param  filter_ismine  The "is mine" filter flags.
 * @param  filter_label   Optional label string to filter incoming transactions.
 */
template <class Vec>
static void ListTransactions(const CWallet& wallet, const CWalletTx& wtx, int nMinDepth, bool fLong,
                             Vec& ret, const isminefilter& filter_ismine, const std::optional<std::string>& filter_label,
                             bool include_change = false)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CAmount nFee;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    CachedTxGetAmounts(wallet, wtx, listReceived, listSent, nFee, filter_ismine, include_change);

    bool involvesWatchonly = CachedTxIsFromMe(wallet, wtx, ISMINE_WATCH_ONLY);

    // Sent
    if (!filter_label.has_value())
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (wallet.IsMine(s.destination) & ISMINE_WATCH_ONLY)) {
                entry.pushKV("involvesWatchonly", true);
            }
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            const auto* address_book_entry = wallet.FindAddressBookEntry(s.destination);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }
            entry.pushKV("vout", s.vout);
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(std::move(entry));
        }
    }

    // Received
    if (listReceived.size() > 0 && wallet.GetTxDepthInMainChain(wtx) >= nMinDepth) {
        for (const COutputEntry& r : listReceived)
        {
            std::string label;
            const auto* address_book_entry = wallet.FindAddressBookEntry(r.destination);
            if (address_book_entry) {
                label = address_book_entry->GetLabel();
            }
            if (filter_label.has_value() && label != filter_label.value()) {
                continue;
            }
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (wallet.IsMine(r.destination) & ISMINE_WATCH_ONLY)) {
                entry.pushKV("involvesWatchonly", true);
            }
            MaybePushAddress(entry, r.destination);
            PushParentDescriptors(wallet, wtx.tx->vout.at(r.vout).scriptPubKey, entry);
            if (wtx.IsCoinBase())
            {
                if (wallet.GetTxDepthInMainChain(wtx) < 1)
                    entry.pushKV("category", "orphan");
                else if (wallet.IsTxImmatureCoinBase(wtx))
                    entry.pushKV("category", "immature");
                else
                    entry.pushKV("category", "generate");
            }
            else
            {
                entry.pushKV("category", "receive");
            }
            entry.pushKV("amount", ValueFromAmount(r.amount));
            if (address_book_entry) {
                entry.pushKV("label", label);
            }
            entry.pushKV("vout", r.vout);
            entry.pushKV("abandoned", wtx.isAbandoned());
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            ret.push_back(std::move(entry));
        }
    }
}


static std::vector<RPCResult> TransactionDescriptionString()
{
    return{{RPCResult::Type::NUM, "confirmations", "The number of confirmations for the transaction. Negative confirmations means the\n"
               "transaction conflicted that many blocks ago."},
           {RPCResult::Type::BOOL, "generated", /*optional=*/true, "Only present if the transaction's only input is a coinbase one."},
           {RPCResult::Type::BOOL, "trusted", /*optional=*/true, "Whether we consider the transaction to be trusted and safe to spend from.\n"
                "Only present when the transaction has 0 confirmations (or negative confirmations, if conflicted)."},
           {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash containing the transaction."},
           {RPCResult::Type::NUM, "blockheight", /*optional=*/true, "The block height containing the transaction."},
           {RPCResult::Type::NUM, "blockindex", /*optional=*/true, "The index of the transaction in the block that includes it."},
           {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           {RPCResult::Type::STR_HEX, "wtxid", "The hash of serialized transaction, including witness data."},
           {RPCResult::Type::ARR, "walletconflicts", "Confirmed transactions that have been detected by the wallet to conflict with this transaction.",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::STR_HEX, "replaced_by_txid", /*optional=*/true, "Only if 'category' is 'send'. The txid if this tx was replaced."},
           {RPCResult::Type::STR_HEX, "replaces_txid", /*optional=*/true, "Only if 'category' is 'send'. The txid if this tx replaces another."},
           {RPCResult::Type::ARR, "mempoolconflicts", "Transactions in the mempool that directly conflict with either this transaction or an ancestor transaction",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::STR, "to", /*optional=*/true, "If a comment to is associated with the transaction."},
           {RPCResult::Type::NUM_TIME, "time", "The transaction time expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::NUM_TIME, "timereceived", "The time received expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::STR, "comment", /*optional=*/true, "If a comment is associated with the transaction, only present if not empty."},
           {RPCResult::Type::STR, "bip125-replaceable", "(\"yes|no|unknown\") Whether this transaction signals BIP125 replaceability or has an unconfirmed ancestor signaling BIP125 replaceability.\n"
               "May be unknown for unconfirmed transactions not in the mempool because their unconfirmed ancestors are unknown."},
           {RPCResult::Type::ARR, "parent_descs", /*optional=*/true, "Only if 'category' is 'received'. List of parent descriptors for the output script of this coin.", {
               {RPCResult::Type::STR, "desc", "The descriptor string."},
           }},
           };
}

RPCHelpMan listtransactions()
{
    return RPCHelpMan{"listtransactions",
                "\nIf a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
                "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, should be a valid label name to return only incoming transactions\n"
                          "with the specified label, or \"*\" to disable filtering and return all transactions."},
                    {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "The number of transactions to return"},
                    {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of transactions to skip"},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Include transactions to watch-only addresses (see 'importaddress')"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", /*optional=*/true, "Only returns true if imported addresses were involved in transaction."},
                            {RPCResult::Type::STR, "address",  /*optional=*/true, "The bitcoin address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
                            {RPCResult::Type::STR, "category", "The transaction category.\n"
                                "\"send\"                  Transactions sent.\n"
                                "\"receive\"               Non-coinbase transactions received.\n"
                                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                "\"orphan\"                Orphaned coinbase transactions received."},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                "for all other categories"},
                            {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                 "'send' category of transactions."},
                        },
                        TransactionDescriptionString()),
                        {
                            {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                        })},
                    }
                },
                RPCExamples{
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::optional<std::string> filter_label;
    if (!request.params[0].isNull() && request.params[0].get_str() != "*") {
        filter_label.emplace(LabelFromValue(request.params[0]));
        if (filter_label.value().empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Label argument must be a valid label name or \"*\".");
        }
    }
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].getInt<int>();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].getInt<int>();
    isminefilter filter = ISMINE_SPENDABLE;

    if (ParseIncludeWatchonly(request.params[3], *pwallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    std::vector<UniValue> ret;
    {
        LOCK(pwallet->cs_wallet);

        const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
        {
            CWalletTx *const pwtx = (*it).second;
            ListTransactions(*pwallet, *pwtx, 0, true, ret, filter, filter_label);
            if ((int)ret.size() >= (nCount+nFrom)) break;
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    auto txs_rev_it{std::make_move_iterator(ret.rend())};
    UniValue result{UniValue::VARR};
    result.push_backV(txs_rev_it - nFrom - nCount, txs_rev_it - nFrom); // Return oldest to newest
    return result;
},
    };
}

RPCHelpMan listsinceblock()
{
    return RPCHelpMan{"listsinceblock",
                "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
                "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
                "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n",
                {
                    {"blockhash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, the block hash to list transactions since, otherwise list all transactions."},
                    {"target_confirmations", RPCArg::Type::NUM, RPCArg::Default{1}, "Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value"},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Include transactions to watch-only addresses (see 'importaddress')"},
                    {"include_removed", RPCArg::Type::BOOL, RPCArg::Default{true}, "Show transactions that were removed due to a reorg in the \"removed\" array\n"
                                                                       "(not guaranteed to work on pruned nodes)"},
                    {"include_change", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also add entries for change outputs.\n"},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Return only incoming transactions paying to addresses with the specified label.\n"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "transactions", "",
                        {
                            {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                            {
                                {RPCResult::Type::BOOL, "involvesWatchonly", /*optional=*/true, "Only returns true if imported addresses were involved in transaction."},
                                {RPCResult::Type::STR, "address",  /*optional=*/true, "The bitcoin address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                    "\"orphan\"                Orphaned coinbase transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                    "for all other categories"},
                                {RPCResult::Type::NUM, "vout", "the vout value"},
                                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                            },
                            TransactionDescriptionString()),
                            {
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                            })},
                        }},
                        {RPCResult::Type::ARR, "removed", /*optional=*/true, "<structure is the same as \"transactions\" above, only present if include_removed=true>\n"
                            "Note: transactions that were re-added in the active chain will appear as-is in this array, and may thus have a positive confirmation count."
                        , {{RPCResult::Type::ELISION, "", ""},}},
                        {RPCResult::Type::STR_HEX, "lastblock", "The hash of the block (target_confirmations-1) from the best block on the main chain, or the genesis hash if the referenced block does not exist yet. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CWallet& wallet = *pwallet;
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);

    std::optional<int> height;    // Height of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    std::optional<int> altheight; // Height of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    uint256 blockId;
    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        blockId = ParseHashV(request.params[0], "blockhash");
        height = int{};
        altheight = int{};
        if (!wallet.chain().findCommonAncestor(blockId, wallet.GetLastBlockHash(), /*ancestor_out=*/FoundBlock().height(*height), /*block1_out=*/FoundBlock().height(*altheight))) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].getInt<int>();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if (ParseIncludeWatchonly(request.params[2], wallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    bool include_removed = (request.params[3].isNull() || request.params[3].get_bool());
    bool include_change = (!request.params[4].isNull() && request.params[4].get_bool());

    // Only set it if 'label' was provided.
    std::optional<std::string> filter_label;
    if (!request.params[5].isNull()) filter_label.emplace(LabelFromValue(request.params[5]));

    int depth = height ? wallet.GetLastBlockHeight() + 1 - *height : -1;

    UniValue transactions(UniValue::VARR);

    for (const auto& [_, tx] : wallet.mapWallet) {

        if (depth == -1 || abs(wallet.GetTxDepthInMainChain(tx)) < depth) {
            ListTransactions(wallet, tx, 0, true, transactions, filter, filter_label, include_change);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && altheight && *altheight > *height) {
        CBlock block;
        if (!wallet.chain().findBlock(blockId, FoundBlock().data(block)) || block.IsNull()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            auto it = wallet.mapWallet.find(tx->GetHash());
            if (it != wallet.mapWallet.end()) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(wallet, it->second, -100000000, true, removed, filter, filter_label, include_change);
            }
        }
        blockId = block.hashPrevBlock;
        --*altheight;
    }

    uint256 lastblock;
    target_confirms = std::min(target_confirms, wallet.GetLastBlockHeight() + 1);
    CHECK_NONFATAL(wallet.chain().findAncestorByHeight(wallet.GetLastBlockHash(), wallet.GetLastBlockHeight() + 1 - target_confirms, FoundBlock().hash(lastblock)));

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", std::move(transactions));
    if (include_removed) ret.pushKV("removed", std::move(removed));
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
},
    };
}

RPCHelpMan gettransaction()
{
    return RPCHelpMan{"gettransaction",
                "\nGet detailed information about in-wallet transaction <txid>\n",
                {
                    {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"},
                            "Whether to include watch-only addresses in balance calculation and details[]"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false},
                            "Whether to include a `decoded` field containing the decoded transaction (equivalent to RPC decoderawtransaction)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                    {
                        {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                    },
                    TransactionDescriptionString()),
                    {
                        {RPCResult::Type::ARR, "details", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::BOOL, "involvesWatchonly", /*optional=*/true, "Only returns true if imported addresses were involved in transaction."},
                                {RPCResult::Type::STR, "address", /*optional=*/true, "The bitcoin address involved in the transaction."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                    "\"orphan\"                Orphaned coinbase transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                                {RPCResult::Type::NUM, "vout", "the vout value"},
                                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                                    "'send' category of transactions."},
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                                {RPCResult::Type::ARR, "parent_descs", /*optional=*/true, "Only if 'category' is 'received'. List of parent descriptors for the output script of this coin.", {
                                    {RPCResult::Type::STR, "desc", "The descriptor string."},
                                }},
                            }},
                        }},
                        {RPCResult::Type::STR_HEX, "hex", "Raw data for transaction"},
                        {RPCResult::Type::OBJ, "decoded", /*optional=*/true, "The decoded transaction (only present when `verbose` is passed)",
                        {
                            {RPCResult::Type::ELISION, "", "Equivalent to the RPC decoderawtransaction method, or the RPC getrawtransaction method when `verbose` is passed."},
                        }},
                        RESULT_LAST_PROCESSED_BLOCK,
                    })
                },
                RPCExamples{
                    HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" false true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    isminefilter filter = ISMINE_SPENDABLE;

    if (ParseIncludeWatchonly(request.params[1], *pwallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    bool verbose = request.params[2].isNull() ? false : request.params[2].get_bool();

    UniValue entry(UniValue::VOBJ);
    auto it = pwallet->mapWallet.find(hash);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = it->second;

    CAmount nCredit = CachedTxGetCredit(*pwallet, wtx, filter);
    CAmount nDebit = CachedTxGetDebit(*pwallet, wtx, filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (CachedTxIsFromMe(*pwallet, wtx, filter) ? wtx.tx->GetValueOut() - nDebit : 0);

    entry.pushKV("amount", ValueFromAmount(nNet - nFee));
    if (CachedTxIsFromMe(*pwallet, wtx, filter))
        entry.pushKV("fee", ValueFromAmount(nFee));

    WalletTxToJSON(*pwallet, wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(*pwallet, wtx, 0, false, details, filter, /*filter_label=*/std::nullopt);
    entry.pushKV("details", std::move(details));

    entry.pushKV("hex", EncodeHexTx(*wtx.tx));

    if (verbose) {
        UniValue decoded(UniValue::VOBJ);
        TxToUniv(*wtx.tx, /*block_hash=*/uint256(), /*entry=*/decoded, /*include_hex=*/false);
        entry.pushKV("decoded", std::move(decoded));
    }

    AppendLastProcessedBlock(entry, *pwallet);
    return entry;
},
    };
}

RPCHelpMan abandontransaction()
{
    return RPCHelpMan{"abandontransaction",
                "\nMark in-wallet transaction <txid> as abandoned\n"
                "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
                "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
                "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
                "It has no effect on transactions which are already abandoned.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan rescanblockchain()
{
    return RPCHelpMan{"rescanblockchain",
                "\nRescan the local blockchain for wallet related transactions.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
                "The rescan is significantly faster when used on a descriptor wallet\n"
                "and block filters are available (using startup option \"-blockfilterindex=1\").\n",
                {
                    {"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "block height where the rescan should start"},
                    {"stop_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "the last block height that should be scanned. If none is provided it will rescan up to the tip at return time of this call."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "start_height", "The block height where the rescan started (the requested height or 0)"},
                        {RPCResult::Type::NUM, "stop_height", "The height of the last rescanned block. May be null in rare cases if there was a reorg and the call didn't scan any blocks because they were already scanned in the background."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("rescanblockchain", "100000 120000")
            + HelpExampleRpc("rescanblockchain", "100000, 120000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int start_height = 0;
    std::optional<int> stop_height;
    uint256 start_block;

    LOCK(pwallet->m_relock_mutex);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);
        int tip_height = pwallet->GetLastBlockHeight();

        if (!request.params[0].isNull()) {
            start_height = request.params[0].getInt<int>();
            if (start_height < 0 || start_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
            }
        }

        if (!request.params[1].isNull()) {
            stop_height = request.params[1].getInt<int>();
            if (*stop_height < 0 || *stop_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stop_height");
            } else if (*stop_height < start_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be greater than start_height");
            }
        }

        // We can't rescan unavailable blocks, stop and throw an error
        if (!pwallet->chain().hasBlocks(pwallet->GetLastBlockHash(), start_height, stop_height)) {
            if (pwallet->chain().havePruned() && pwallet->chain().getPruneHeight() >= start_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
            }
            if (pwallet->chain().hasAssumedValidChain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks likely due to an in-progress assumeutxo background sync. Check logs or getchainstates RPC for assumeutxo background sync progress and try again later.");
            }
            throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks, potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option).");
        }

        CHECK_NONFATAL(pwallet->chain().findAncestorByHeight(pwallet->GetLastBlockHash(), start_height, FoundBlock().hash(start_block)));
    }

    CWallet::ScanResult result =
        pwallet->ScanForWalletTransactions(start_block, start_height, stop_height, reserver, /*fUpdate=*/true, /*save_progress=*/false);
    switch (result.status) {
    case CWallet::ScanResult::SUCCESS:
        break;
    case CWallet::ScanResult::FAILURE:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
    case CWallet::ScanResult::USER_ABORT:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
        // no default case, so the compiler can warn about missing cases
    }
    UniValue response(UniValue::VOBJ);
    response.pushKV("start_height", start_height);
    response.pushKV("stop_height", result.last_scanned_height ? *result.last_scanned_height : UniValue());
    return response;
},
    };
}

RPCHelpMan abortrescan()
{
    return RPCHelpMan{"abortrescan",
                "Stops current wallet rescan triggered by an RPC call, e.g. by a rescanblockchain call.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n",
                {},
                RPCResult{RPCResult::Type::BOOL, "", "Whether the abort was successful"},
                RPCExamples{
            "\nImport a private key\n"
            + HelpExampleCli("rescanblockchain", "") +
            "\nAbort the running wallet rescan\n"
            + HelpExampleCli("abortrescan", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("abortrescan", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->IsScanning() || pwallet->IsAbortingRescan()) return false;
    pwallet->AbortRescan();
    return true;
},
    };
}

RPCHelpMan createmodeldeposit()
{
    return RPCHelpMan{
        "createmodeldeposit",
        "\nCreate and broadcast a model registration deposit transaction.\n",
        {
            {"model_name", RPCArg::Type::STR, RPCArg::Optional::NO, "Model repository identifier"},
            {"model_commit", RPCArg::Type::STR, RPCArg::Optional::NO, "Model commit hash or version"},
            {"difficulty_multiplier", RPCArg::Type::NUM, RPCArg::Optional::NO, "Declared model difficulty multiplier"},
            {"model_cid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional IPFS CID or reference"},
            {"additional_data", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional metadata blob"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Deposit transaction details", {
            {RPCResult::Type::STR, "txid", "Transaction id of the broadcast deposit"},
            {RPCResult::Type::STR, "model_hash", "Computed model hash"},
            {RPCResult::Type::STR, "deposit_address", "Generated owner address controlling the deposit"},
            {RPCResult::Type::NUM, "deposit_vout", "Output index locking the deposit"},
            {RPCResult::Type::STR_AMOUNT, "deposit_amount", "Amount locked in the deposit output"},
        }},
        RPCExamples{
            HelpExampleCli("createmodeldeposit", "\"tensor/model\" \"commit123\" 1000000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            ModelMetadata metadata;
            metadata.model_name = request.params[0].get_str();
            metadata.model_commit = request.params[1].get_str();
            metadata.difficulty = request.params[2].getInt<int64_t>();
            if (metadata.model_name.empty() || metadata.model_commit.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Model name and commit must be non-empty");
            }
            if (metadata.difficulty <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Difficulty must be positive");
            }
            metadata.cid = request.params.size() > 3 && !request.params[3].isNull() ? request.params[3].get_str() : "";
            metadata.extra = request.params.size() > 4 && !request.params[4].isNull() ? request.params[4].get_str() : "";

            const Consensus::Params& consensus_params = Params().GetConsensus();
            const CAmount deposit_amount = consensus_params.ModelRegistrationDeposit;
            if (deposit_amount <= 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "Consensus deposit amount is not configured");
            }

            const uint256 model_hash = HashSHA256(metadata);
            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }
            if (g_modeldb->Exists(model_hash)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model hash already registered or pending");
            }

            EnsureWalletIsUnlocked(*pwallet);

            CTxDestination owner_dest;
            CPubKey owner_pubkey;
            {
                auto maybe_dest = pwallet->GetNewDestination(OutputType::LEGACY, "model-deposit");
                if (!maybe_dest) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to generate deposit address");
                }
                owner_dest = *maybe_dest;

                const CScript spk = GetScriptForDestination(owner_dest);
                const PKHash* key_hash = std::get_if<PKHash>(&owner_dest);
                if (!key_hash) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Deposit address is not legacy P2PKH");
                }
                std::unique_ptr<SigningProvider> prov = pwallet->GetSolvingProvider(spk);
                if (!prov || !prov->GetPubKey(ToKeyID(*key_hash), owner_pubkey)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to retrieve owner pubkey");
                }
                if (!owner_pubkey.IsFullyValid()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Owner public key invalid");
                }
            }

            const CScript owner_script = GetScriptForDestination(owner_dest);

            // Pre-calculate OP_RETURN scripts to determine their size
            auto op_return_scripts = CreateModelDepositScripts(metadata, owner_pubkey);
            [[maybe_unused]] size_t op_return_size = 0;
            for (const auto& sc : op_return_scripts) {
                // Each output adds: 8 bytes (amount) + CompactSize(scriptPubKey.size()) + scriptPubKey
                op_return_size += 8 + GetSizeOfCompactSize(sc.size()) + sc.size();
            }

            std::vector<CRecipient> recipients;
            recipients.push_back({owner_dest, deposit_amount, /*subtract_fee_from_amount=*/false});

            CCoinControl coin_control;
            coin_control.m_allow_other_inputs = true;
            coin_control.m_signal_bip125_rbf = true;

            // Get base fee rate
            CFeeRate 
            base_fee_rate = pwallet->m_pay_tx_fee.GetFeePerK() > 0 ? pwallet->m_pay_tx_fee : pwallet->chain().estimateSmartFee(6, false);
            if (base_fee_rate.GetFeePerK() == 0) {
                base_fee_rate = CFeeRate(1000); // 1 sat/vB fallback
            }

            // OP_RETURNs add ~700 vbytes. Use higher fee rate to compensate.
            // Multiply fee rate by (estimated_total_size / estimated_base_size)
            // Typical base tx is ~200-250 vbytes, final tx is ~200+700=900 vbytes
            // So multiply by ~4x to be safe
            CAmount multiplied_fee_per_k = base_fee_rate.GetFeePerK() * 4;
            coin_control.fOverrideFeeRate = true;
            coin_control.m_feerate = CFeeRate(multiplied_fee_per_k);

            // Force deterministic output ordering: [deposit, change]
            const std::optional<unsigned int> change_pos{static_cast<unsigned int>(recipients.size())};
            auto tx_res = CreateTransaction(*pwallet, recipients, change_pos, coin_control);
            if (!tx_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(tx_res).original);
            }

            CMutableTransaction mtx(*tx_res->tx);

            // Add OP_RETURN outputs
            for (const auto& sc : op_return_scripts) {
                mtx.vout.emplace_back(0, sc);
            }
            mtx.version = Consensus::MODEL_REGISTER_DEPOSIT_TX_VERSION;

            const bool signed_ok = WITH_LOCK(pwallet->cs_wallet, return pwallet->SignTransaction(mtx));
            if (!signed_ok) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Signing failed");
            }

            auto tx = MakeTransactionRef(mtx);
            pwallet->CommitTransaction(tx, {}, {});

            const uint32_t deposit_vout = 0;
            // Sanity check deterministic layout: deposit must be vout0
            if (tx->vout.size() <= deposit_vout ||
                tx->vout[deposit_vout].scriptPubKey != owner_script ||
                tx->vout[deposit_vout].nValue < deposit_amount) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Deposit output mismatch after signing");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("model_hash", model_hash.ToString());
            result.pushKV("deposit_address", EncodeDestination(owner_dest));
            result.pushKV("deposit_vout", deposit_vout);
            result.pushKV("deposit_amount", ValueFromAmount(tx->vout[deposit_vout].nValue));
            return result;
        }
    };
}
RPCHelpMan createmodelburn()
{
    return RPCHelpMan{
        "createmodelburn",
        "\nCreate and optionally broadcast a burn transaction for a failed model deposit.\n",
        {
            {"model_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Model hash referencing the failed registration"},
            {"broadcast", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Broadcast the transaction (default true)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Burn transaction details", {
            {RPCResult::Type::STR, "txid", "Transaction id of the burn transaction"},
            {RPCResult::Type::STR, "hex", "Raw transaction hex"},
            {RPCResult::Type::STR, "model_hash", "Model hash"},
            {RPCResult::Type::STR, "burn_prevout", "Outpoint being burned"},
            {RPCResult::Type::NUM, "burn_allowed_height", "Height from which burning is permitted"},
            {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast"},
        }},
        RPCExamples{
            HelpExampleCli("createmodelburn", "\"<model_hash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }

            uint256 model_hash = ParseHashV(request.params[0], "model_hash");
            ModelRecord record;
            if (!g_modeldb->ReadModel(model_hash, record)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model hash not found");
            }
            if (record.status != ModelRegistrationStatus::Locked && record.status != ModelRegistrationStatus::Banned) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model deposit is not locked" );
            }
            if (record.burn_txid.IsNull()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Burn output is not yet available");
            }
            if (record.burn_block_height != 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "Deposit already burned");
            }
            if (record.commit_block_height == 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "Missing failure commit height");
            }

            const int current_height = pwallet->chain().getHeight().value_or(0);
            if (current_height <= 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "Chain height unavailable");
            }

            const Consensus::Params& consensus_params = Params().GetConsensus();
            int burn_allowed_height = 0;
            if (record.status == ModelRegistrationStatus::Locked) {
                burn_allowed_height = record.commit_block_height;
            } else if (record.status == ModelRegistrationStatus::Banned) {
                burn_allowed_height = record.burn_block_height > 0 ? record.burn_block_height : record.commit_block_height;
            } else {
                burn_allowed_height = record.commit_block_height + consensus_params.ModelCommitRefundDelay;
            }
            if (current_height < burn_allowed_height) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("Burn available at height %d (current %d)", burn_allowed_height, current_height));
            }

            const Txid burn_txid = Txid::FromUint256(record.burn_txid);
            const COutPoint burn_outpoint{burn_txid, record.burn_vout};

            std::map<COutPoint, Coin> burn_coins;
            burn_coins[burn_outpoint];
            pwallet->chain().findCoins(burn_coins);
            const auto burn_coin_it = burn_coins.find(burn_outpoint);
            if (burn_coin_it == burn_coins.end() || burn_coin_it->second.IsSpent()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Burn output not found in chain state");
            }
            const CScript& burn_prev_script = burn_coin_it->second.out.scriptPubKey;

            CMutableTransaction mtx;
            mtx.version = Consensus::MODEL_REGISTER_BURN_TX_VERSION;
            mtx.vin.emplace_back(burn_outpoint);
            std::vector<unsigned char> burn_payload{77, 82, 69, 71, 95, 66, 85, 82, 78};
            burn_payload.resize(33, 0);
            const CScript burn_script = CScript() << OP_RETURN << burn_payload;
            const CAmount burn_input_value = burn_coin_it->second.out.nValue;
            mtx.vout.emplace_back(burn_input_value, burn_script);

            const bool requires_burn_script_sig = IsModelBurnScriptPubKey(burn_prev_script);
            if (requires_burn_script_sig) {
                mtx.vin[0].scriptSig = CreateModelBurnRedeemScriptSig();
            }

            CFeeRate fee_rate = pwallet->m_pay_tx_fee.GetFeePerK() > 0 ? pwallet->m_pay_tx_fee : pwallet->chain().estimateSmartFee(6, false);
            fee_rate = std::max(fee_rate, pwallet->chain().mempoolMinFee());
            fee_rate = std::max(fee_rate, pwallet->chain().relayMinFee());
            if (fee_rate.GetFeePerK() < 1000) {
                fee_rate = CFeeRate(1000);
            }
            const CAmount fee = fee_rate.GetFee(GetVirtualTransactionSize(CTransaction(mtx)));
            if (fee <= 0 || fee >= burn_input_value) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Burn output too small after fee");
            }
            mtx.vout[0].nValue = burn_input_value - fee;

            if (requires_burn_script_sig) {
                mtx.vin[0].scriptSig = CreateModelBurnRedeemScriptSig();
            }

            bool broadcast = true;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                broadcast = request.params[1].get_bool();
            }

            auto tx = MakeTransactionRef(mtx);
            std::string hex = EncodeHexTx(*tx);
            if (broadcast) {
                std::string err_string;
                if (!pwallet->chain().broadcastTransaction(tx, /*max_tx_fee=*/0, /*relay=*/true, err_string)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, err_string.empty() ? "Burn transaction broadcast failed" : err_string);
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("hex", hex);
            result.pushKV("model_hash", model_hash.ToString());
            result.pushKV("burn_prevout", burn_outpoint.ToString());
            result.pushKV("burn_allowed_height", burn_allowed_height);
            result.pushKV("broadcast", broadcast);
            result.pushKV("current_height", current_height);
            return result;
        }
    };
}

RPCHelpMan createmodelreclaim()
{
    return RPCHelpMan{
        "createmodelreclaim",
        "\nCreate and optionally broadcast a reclaim transaction for a mature registered model deposit owned by this wallet.\n",
        {
            {"model_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Model hash"},
            {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast transaction"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Reclaim transaction", {
            {RPCResult::Type::STR, "txid", "Transaction id"},
            {RPCResult::Type::STR, "hex", "Raw transaction hex"},
            {RPCResult::Type::STR, "model_hash", "Model hash"},
            {RPCResult::Type::STR, "reclaim_address", "Wallet destination receiving the reclaimed funds"},
            {RPCResult::Type::STR_AMOUNT, "reclaim_amount", "Value sent back to the wallet after fee"},
            {RPCResult::Type::NUM, "deposit_unlock_height", "Height where reclaim becomes allowed"},
            {RPCResult::Type::NUM, "current_height", "Current chain height"},
            {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast"},
        }},
        RPCExamples{
            HelpExampleCli("createmodelreclaim", "\"<model_hash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }

            const uint256 model_hash = ParseHashV(request.params[0], "model_hash");
            ModelRecord record;
            if (!g_modeldb->ReadModel(model_hash, record)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model hash not found");
            }
            if (record.status != ModelRegistrationStatus::Registered) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model deposit is not reclaimable");
            }

            int current_height{0};
            if (auto height = pwallet->chain().getHeight()) {
                current_height = *height;
            } else {
                throw JSONRPCError(RPC_MISC_ERROR, "Node context not found");
            }

            const Consensus::Params& consensus_params = Params().GetConsensus();
            const int deposit_unlock_height = GetModelDepositUnlockHeight(record, consensus_params);
            if (deposit_unlock_height <= 0 || current_height < deposit_unlock_height) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   strprintf("Deposit reclaim available at height %d (current %d)",
                                             deposit_unlock_height,
                                             current_height));
            }

            const Txid deposit_txid = Txid::FromUint256(record.deposit_txid);
            const COutPoint deposit_outpoint{deposit_txid, record.deposit_vout};

            std::map<COutPoint, Coin> reclaim_coins;
            reclaim_coins[deposit_outpoint];
            pwallet->chain().findCoins(reclaim_coins);
            const auto reclaim_coin_it = reclaim_coins.find(deposit_outpoint);
            if (reclaim_coin_it == reclaim_coins.end() || reclaim_coin_it->second.IsSpent()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Deposit output not found in chain state");
            }

            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* deposit_wtx = pwallet->GetWalletTx(deposit_txid);
                if (!deposit_wtx || record.deposit_vout >= deposit_wtx->tx->vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Deposit transaction not found in wallet");
                }
                if (!(pwallet->IsMine(deposit_wtx->tx->vout[record.deposit_vout]) & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control the deposit output");
                }
            }

            auto reclaim_dest_res = pwallet->GetNewDestination(OutputType::BECH32, "model-reclaim");
            if (!reclaim_dest_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(reclaim_dest_res).original);
            }
            const CTxDestination reclaim_dest = *reclaim_dest_res;
            const CScript reclaim_script = GetScriptForDestination(reclaim_dest);

            CMutableTransaction mtx;
            mtx.version = CTransaction::CURRENT_VERSION;
            mtx.vin.emplace_back(deposit_outpoint);
            const CAmount input_value = reclaim_coin_it->second.out.nValue;
            mtx.vout.emplace_back(input_value, reclaim_script);

            CFeeRate fee_rate = pwallet->m_pay_tx_fee.GetFeePerK() > 0 ? pwallet->m_pay_tx_fee : pwallet->chain().estimateSmartFee(6, false);
            if (fee_rate.GetFeePerK() == 0) {
                fee_rate = CFeeRate(1000);
            }
            std::map<int, bilingual_str> input_errors;
            mtx.vout[0].nValue = input_value;
            bool signed_ok = WITH_LOCK(pwallet->cs_wallet, return pwallet->SignTransaction(mtx, reclaim_coins, SIGHASH_ALL, input_errors));
            if (!signed_ok || !input_errors.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Signing reclaim transaction failed");
            }

            const CAmount fee = fee_rate.GetFee(GetVirtualTransactionSize(CTransaction(mtx)));
            if (fee <= 0 || fee >= input_value) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Deposit output too small after fee");
            }

            mtx.vout[0].nValue = input_value - fee;
            input_errors.clear();
            signed_ok = WITH_LOCK(pwallet->cs_wallet, return pwallet->SignTransaction(mtx, reclaim_coins, SIGHASH_ALL, input_errors));
            if (!signed_ok || !input_errors.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Signing reclaim transaction failed");
            }

            bool broadcast = true;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                broadcast = request.params[1].get_bool();
            }

            auto tx = MakeTransactionRef(mtx);
            const std::string hex = EncodeHexTx(*tx);
            if (broadcast) {
                pwallet->CommitTransaction(tx, {}, {});
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("hex", hex);
            result.pushKV("model_hash", model_hash.ToString());
            result.pushKV("reclaim_address", EncodeDestination(reclaim_dest));
            result.pushKV("reclaim_amount", ValueFromAmount(mtx.vout[0].nValue));
            result.pushKV("deposit_unlock_height", deposit_unlock_height);
            result.pushKV("current_height", current_height);
            result.pushKV("broadcast", broadcast);
            return result;
        }
    };
}

RPCHelpMan createmodelcommit()
{
    return RPCHelpMan{
        "createmodelcommit",
        "\nCreate and broadcast model registration commit transaction(s) for a model that is still in the registration window.\n",
        {
            {"deposit_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Deposit transaction id"},
            {"deposit_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Deposit output index"},
            {"tx_count", RPCArg::Type::NUM, RPCArg::Default{SUCCESSFUL_COMMITS_COUNT},
                strprintf("Number of commit transactions to create (min 1, max %u)", MODEL_VERIFICATION_BLOCK_COUNT)},
            {"funding_utxos", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional list of wallet UTXOs to prioritize for paying commit fees", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
                }},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Commit transaction details", {
            {RPCResult::Type::ARR, "transactions", "Commit transactions created by the wallet", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "txid", "Transaction id of the commit"},
                    {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex"},
                }},
            }},
            {RPCResult::Type::STR_HEX, "txid", "Transaction id of the first commit (deprecated; use transactions array)"},
            {RPCResult::Type::NUM, "count", "Number of commit transactions created"},
            {RPCResult::Type::STR, "verdict", "Commit verdict: success or failure"},
            {RPCResult::Type::STR_AMOUNT, "refund_amount", "Refund amount immediately returned to the owner (zero until unlock)"},
            {RPCResult::Type::STR, "model_hash", "Model hash associated with the deposit"},
            {RPCResult::Type::NUM, "failure_reason", /*optional=*/true, "Verification failure code (present only on failure)"},
        }},
        RPCExamples{
            HelpExampleCli("createmodelcommit", "\"<txid>\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            Txid deposit_txid{Txid::FromUint256(ParseHashV(request.params[0], "deposit_txid"))};
            uint32_t deposit_vout = request.params[1].getInt<uint32_t>();
            const COutPoint deposit_outpoint{deposit_txid, deposit_vout};

            const int arg_tx_count = request.params[2].isNull() ? SUCCESSFUL_COMMITS_COUNT
                                                                : request.params[2].getInt<int>();
            unsigned int tx_count;
            if (arg_tx_count < 1) {
                tx_count = 1;
            } else {
                tx_count = static_cast<unsigned int>(arg_tx_count);
            }
            tx_count = std::min(tx_count, MODEL_VERIFICATION_BLOCK_COUNT);

            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }

            auto model_lookup = g_modeldb->LookupModelByDeposit(deposit_outpoint);
            if (!model_lookup) {
                throw JSONRPCError(RPC_MISC_ERROR, "Unknown model deposit");
            }
            const uint256 model_hash = *model_lookup;

            ModelRecord record;
            if (!g_modeldb->ReadModel(model_hash, record)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to read model record");
            }
            if (record.status != ModelRegistrationStatus::PendingDeposit &&
                record.status != ModelRegistrationStatus::PendingVerification) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model is not in a commit-eligible state");
            }
            if (record.deposit_txid != deposit_txid.ToUint256() || record.deposit_vout != deposit_vout) {
                throw JSONRPCError(RPC_MISC_ERROR, "Deposit reference mismatch");
            }

            // Prevent the model deposit from being accidentally selected as a funding input
            // by any of the internal CreateTransaction calls (e.g. while provisioning
            // commit funding UTXOs). Wallet locking is the simplest way to ensure the
            // deposit stays untouched even if coin selection ignores our filters.
            std::vector<COutPoint> locked_deposits;
            {
                LOCK(pwallet->cs_wallet);
                if (!pwallet->IsLockedCoin(deposit_outpoint)) {
                    pwallet->LockCoin(deposit_outpoint);
                    locked_deposits.push_back(deposit_outpoint);
                }
            }
            struct DepositUnlocker {
                CWallet& wallet;
                std::vector<COutPoint> coins;
                ~DepositUnlocker()
                {
                    LOCK(wallet.cs_wallet);
                    for (const auto& op : coins) wallet.UnlockCoin(op);
                }
            } deposit_unlocker{*pwallet, std::move(locked_deposits)};

            std::deque<COutPoint> manual_funding;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                const UniValue& funding_param = request.params[3];
                if (!funding_param.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos must be an array");
                }
                std::set<COutPoint> manual_seen;
                for (unsigned int idx = 0; idx < funding_param.size(); ++idx) {
                    const UniValue& entry = funding_param[idx];
                    if (!entry.isObject()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos entries must be objects");
                    }
                    const UniValue& txid_val = entry.find_value("txid");
                    const UniValue& vout_val = entry.find_value("vout");
                    if (!txid_val.isStr() || !vout_val.isNum()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos entries require txid (string) and vout (numeric)");
                    }
                    Txid funding_txid{Txid::FromUint256(ParseHashV(txid_val, "txid"))};
                    uint32_t funding_vout = vout_val.getInt<uint32_t>();
                    COutPoint funding_outpoint{funding_txid, funding_vout};
                    if (funding_outpoint == deposit_outpoint) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos may not include the model deposit UTXO");
                    }
                    if (!manual_seen.insert(funding_outpoint).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate entries detected in funding_utxos");
                    }
                    if (g_modeldb && g_modeldb->LookupModelByDeposit(funding_outpoint)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos may not include model deposit outputs");
                    }
                    {
                        LOCK(pwallet->cs_wallet);
                        const CWalletTx* funding_wtx = pwallet->GetWalletTx(funding_txid);
                        if (!funding_wtx || funding_vout >= funding_wtx->tx->vout.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "funding_utxos entry not found in wallet");
                        }
                        const CTxOut& funding_out = funding_wtx->tx->vout[funding_vout];
                        if (!(pwallet->IsMine(funding_out) & ISMINE_SPENDABLE)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control a funding_utxos entry");
                        }
                        if (pwallet->IsLockedCoin(funding_outpoint)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "funding_utxos entry is locked");
                        }
                    }
                    manual_funding.push_back(funding_outpoint);
                }
            }

            EnsureWalletIsUnlocked(*pwallet);

            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(deposit_txid);
                if (!wtx || deposit_vout >= wtx->tx->vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Deposit transaction not found in wallet");
                }
                if (!(pwallet->IsMine(wtx->tx->vout[deposit_vout]) & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control the deposit output");
                }
            }

            const auto verification = model_verification::VerifyModel(model_hash, record.metadata);
            const bool verification_success = verification.passed;

            UniValue result(UniValue::VOBJ);
            result.pushKV("model_hash", model_hash.ToString());

            auto build_commit_transactions = [&](const std::vector<CScript>& commit_scripts,
                                                 unsigned int commit_target,
                                                 const std::string& verdict,
                                                 const std::optional<uint64_t>& failure_reason) {
                std::vector<CRecipient> recipients;
                recipients.reserve(commit_scripts.size());
                for (const auto& script : commit_scripts) {
                    recipients.push_back({CNoDestination(script), 0, /*subtract_fee_from_amount=*/false});
                }

                static constexpr CAmount COMMIT_FUNDING_TARGET{20'000};
                static constexpr unsigned int MAX_PARENT_CHILDREN{MODEL_VERIFICATION_BLOCK_COUNT};
                static constexpr CAmount COMMIT_FUNDING_MAX{COMMIT_FUNDING_TARGET * MODEL_VERIFICATION_BLOCK_COUNT};
                std::map<Txid, std::deque<COutPoint>> funding_batches;
                std::deque<Txid> parent_cycle;
                std::set<COutPoint> funding_known;
                std::map<Txid, unsigned int> parent_usage;
                for (const auto& manual_op : manual_funding) {
                    funding_known.insert(manual_op);
                }

                const auto funding_available = [&]() -> unsigned int {
                    unsigned int total{0};
                    for (const auto& entry : funding_batches) {
                        total += entry.second.size();
                    }
                    return total;
                };

                const auto refill_funding_pool = [&](unsigned int required) {
                    unsigned int manual_remaining = static_cast<unsigned int>(std::min<size_t>(manual_funding.size(), std::numeric_limits<unsigned int>::max()));
                    if (manual_remaining >= required) {
                        return;
                    }
                    unsigned int needed = required - manual_remaining;
                    {
                        LOCK(pwallet->cs_wallet);
                        CCoinControl snapshot_control;
                        snapshot_control.m_min_depth = 1;
                        snapshot_control.m_include_unsafe_inputs = false;
                        auto snapshot = AvailableCoinsListUnspent(*pwallet, &snapshot_control).All();
                        CAmount total{0};
                        for (const auto& coin : snapshot) total += coin.txout.nValue;
                        LogPrintf("createmodelcommit: wallet has %u spendable outputs totalling %s\n", snapshot.size(), FormatMoney(total));
                    }

                    auto collect_available = [&](unsigned int target) {
                        LOCK(pwallet->cs_wallet);
                        CCoinControl scan_control;
                        scan_control.m_min_depth = 1;
                        scan_control.m_include_unsafe_inputs = false;
                        CoinFilterParams filter;
                        filter.min_amount = COMMIT_FUNDING_TARGET;
                        filter.max_amount = COMMIT_FUNDING_MAX;
                        for (const COutput& coin : AvailableCoinsListUnspent(*pwallet, &scan_control, filter).All()) {
                            if (!coin.spendable) continue;
                            if (coin.outpoint == deposit_outpoint) continue;
                            if (g_modeldb && g_modeldb->LookupModelByDeposit(coin.outpoint)) {
                                continue;
                            }
                            const Txid parent{Txid::FromUint256(coin.outpoint.hash)};
                            if (funding_known.count(coin.outpoint)) continue;
                            if (parent_usage[parent] >= MAX_PARENT_CHILDREN) continue;
                            auto& queue = funding_batches[parent];
                            if (queue.empty()) {
                                parent_cycle.push_back(parent);
                            }
                            if (parent_usage[parent] + queue.size() >= MAX_PARENT_CHILDREN) {
                                continue;
                            }
                            queue.push_back(coin.outpoint);
                            funding_known.insert(coin.outpoint);
                            if (funding_available() >= target) break;
                        }
                    };

                    const unsigned int BATCH_LIMIT{MAX_PARENT_CHILDREN};

                    while (funding_available() < needed) {
                        collect_available(needed);
                        if (funding_available() >= needed) break;

                        const unsigned int missing = needed - funding_available();
                        const unsigned int batch = std::min<unsigned int>(missing, BATCH_LIMIT);
                        if (batch == 0) break;

                        std::vector<CRecipient> split_recipients;
                        split_recipients.reserve(batch);
                        std::vector<CTxDestination> split_dests;
                        split_dests.reserve(batch);
                        for (unsigned int i = 0; i < batch; ++i) {
                            auto maybe_dest = pwallet->GetNewDestination(OutputType::BECH32, "model-commit-funding");
                            if (!maybe_dest) {
                                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to allocate commit funding address");
                            }
                            split_dests.push_back(*maybe_dest);
                            split_recipients.push_back({*maybe_dest, COMMIT_FUNDING_TARGET, /*subtract_fee_from_amount=*/false});
                        }

                        CCoinControl split_control;
                        split_control.m_allow_other_inputs = true;
                        split_control.m_min_depth = 1;
                        split_control.m_include_unsafe_inputs = false;
                        split_control.m_signal_bip125_rbf = true;

                        LogPrintf("createmodelcommit: provisioning %u funding outputs (missing=%u)\n", batch, missing);
                        auto split_res = CreateTransaction(*pwallet, split_recipients, std::nullopt, split_control);
                        if (!split_res) {
                            const std::string err = util::ErrorString(split_res).original;
                            LogPrintf("createmodelcommit: funding provision failed (%s)\n", err);
                            throw JSONRPCError(RPC_WALLET_ERROR, err);
                        }

                        pwallet->CommitTransaction(split_res->tx, {}, {});

                        const Txid split_txid = Txid::FromUint256(split_res->tx->GetHash());
                        std::vector<CScript> expected_scripts;
                        expected_scripts.reserve(split_dests.size());
                        for (const auto& dest : split_dests) {
                            expected_scripts.push_back(GetScriptForDestination(dest));
                        }

                        std::vector<COutPoint> new_outputs;
                        for (unsigned int i = 0; i < split_res->tx->vout.size(); ++i) {
                            const auto& out = split_res->tx->vout[i];
                            auto it = std::find(expected_scripts.begin(), expected_scripts.end(), out.scriptPubKey);
                            if (it == expected_scripts.end()) continue;
                            new_outputs.emplace_back(split_txid, i);
                        }

                        if (new_outputs.size() != split_dests.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate commit funding outputs");
                        }

                        for (const auto& outpoint : new_outputs) {
                            funding_batches[Txid::FromUint256(outpoint.hash)].push_back(outpoint);
                            funding_known.insert(outpoint);
                        }
                    }
                };

                const auto select_manual_or_parent = [&]() -> std::optional<COutPoint> {
                    if (!manual_funding.empty()) {
                        COutPoint next = manual_funding.front();
                        manual_funding.pop_front();
                        funding_known.erase(next);
                        return next;
                    }
                    const size_t cycle_len = parent_cycle.size();
                    for (size_t attempt = 0; attempt < cycle_len; ++attempt) {
                        if (parent_cycle.empty()) break;
                        const Txid parent = parent_cycle.front();
                        parent_cycle.pop_front();
                        auto it_batch = funding_batches.find(parent);
                        if (it_batch == funding_batches.end() || it_batch->second.empty()) {
                            continue;
                        }
                        auto next = it_batch->second.front();
                        it_batch->second.pop_front();
                        if (next == deposit_outpoint) {
                            continue;
                        }
                        if (!it_batch->second.empty()) {
                            parent_cycle.push_back(parent);
                        } else {
                            funding_batches.erase(it_batch);
                        }
                        funding_known.erase(next);
                        parent_usage[parent]++;
                        return next;
                    }
                    return std::nullopt;
                };

                UniValue tx_array(UniValue::VARR);
                std::string first_txid;
                unsigned int created{0};

                for (unsigned int i = 0; i < commit_target; ++i) {
                    refill_funding_pool(commit_target - created);
                    COutPoint funding_input;
                    bool found_input{false};
                    if (!manual_funding.empty()) {
                        funding_input = manual_funding.front();
                        manual_funding.pop_front();
                        funding_known.erase(funding_input);
                        found_input = true;
                    }
                    if (!found_input) {
                        auto maybe_parent = select_manual_or_parent();
                        if (maybe_parent) {
                            funding_input = *maybe_parent;
                            found_input = true;
                        }
                    }

                    if (!found_input) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient commit funding outputs");
                    }

                    CCoinControl coin_control;
                    coin_control.m_allow_other_inputs = false;
                    coin_control.m_include_unsafe_inputs = true;
                    coin_control.m_min_depth = 0;
                    coin_control.m_version = Consensus::MODEL_REGISTER_COMMIT_TX_VERSION;
                    CScript funding_change_script;
                    {
                        LOCK(pwallet->cs_wallet);
                        const CWalletTx* funding_wtx = pwallet->GetWalletTx(Txid::FromUint256(funding_input.hash));
                        if (!funding_wtx || funding_input.n >= funding_wtx->tx->vout.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Funding input not found in wallet");
                        }
                        const CTxOut& funding_out = funding_wtx->tx->vout[funding_input.n];
                        if (funding_out.scriptPubKey.IsUnspendable()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Funding input script is unspendable");
                        }
                        funding_change_script = funding_out.scriptPubKey;
                    }
                    coin_control.destChange = CNoDestination(funding_change_script);
                    coin_control.Select(funding_input);

                    auto tx_res = CreateTransaction(*pwallet, recipients, std::nullopt, coin_control);
                    if (!tx_res) {
                        const std::string err = util::ErrorString(tx_res).original;
                        LogPrintf("createmodelcommit: funding transaction failed (%s)\n", err);
                        throw JSONRPCError(RPC_WALLET_ERROR, err);
                    }
                    for (const auto& vin : tx_res->tx->vin) {
                        if (vin.prevout == deposit_outpoint) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Commit funding transaction must not spend model deposit");
                        }
                    }

                    const std::string txid = tx_res->tx->GetHash().ToString();
                    const std::string hex = EncodeHexTx(*tx_res->tx);

                    pwallet->CommitTransaction(tx_res->tx, {}, {});

                    UniValue tx_entry(UniValue::VOBJ);
                    tx_entry.pushKV("txid", txid);
                    tx_entry.pushKV("hex", hex);
                    tx_array.push_back(std::move(tx_entry));

                    if (first_txid.empty()) {
                        first_txid = txid;
                    }
                    ++created;
                }

                result.pushKV("transactions", std::move(tx_array));
                if (!first_txid.empty()) {
                    result.pushKV("txid", first_txid);
                } else {
                    result.pushKV("txid", "");
                }
                result.pushKV("count", created);
                result.pushKV("verdict", verdict);
                result.pushKV("refund_amount", ValueFromAmount(0));
                if (failure_reason) {
                    result.pushKV("failure_reason", *failure_reason);
                }
            };

            if (verification_success) {
                build_commit_transactions(CreateModelCommitScriptsSuccess(record.metadata), tx_count, "success", std::nullopt);
            } else {
                std::vector<CScript> failure_scripts;
                failure_scripts.emplace_back(CreateModelCommitFailureScript(model_hash, verification.reason_code));
                build_commit_transactions(failure_scripts, 1, "failure", static_cast<uint64_t>(verification.reason_code));
            }

            return result;
        }
    };
}

RPCHelpMan splitutxo()
{
    return RPCHelpMan{
        "splitutxo",
        "\nSplit wallet-controlled funds into multiple outputs belonging to this wallet.\n"
        "If \"txid\" is all zeros, the wallet automatically selects enough inputs and places any remainder into a dedicated additional output.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id of the UTXO to split, or 64 zero hex chars to auto-select inputs"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index (ignored when txid is zero)"},
            {"count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of outputs to create (minimum 2, or minimum 1 in auto-select mode)"},
            {"target_amount_sat", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "Fixed amount (in satoshis) for outputs 1..count-1. In auto-select mode it is required, output 0 receives target_amount_sat plus the split-fee reserve, and any remainder is returned as an additional output."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Details about the split transaction", {
            {RPCResult::Type::STR_HEX, "txid", "Transaction id of the split transaction"},
            {RPCResult::Type::ARR, "outputs", "Newly created outputs belonging to the wallet", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "vout", "Output index in the split transaction"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount assigned to this output"},
                    {RPCResult::Type::STR, "address", "Address that received the output"},
                }},
            }},
            {RPCResult::Type::ARR, "additional_outputs", "Additional wallet outputs created by the split transaction, such as the remainder output in auto-select mode", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "vout", "Output index in the split transaction"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount assigned to this output"},
                    {RPCResult::Type::STR, "address", "Address that received the output"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("splitutxo", "\"<txid>\" 0 5") +
            HelpExampleCli("splitutxo", "\"<txid>\" 0 5 20000") +
            HelpExampleCli("splitutxo", "\"0000000000000000000000000000000000000000000000000000000000000000\" 0 5 20000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            EnsureWalletIsUnlocked(*pwallet);

            const Txid txid{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
            const uint32_t vout = request.params[1].getInt<uint32_t>();
            const int count = request.params[2].getInt<int>();
            const CAmount fixed_output_amount =
                (request.params.size() > 3 && !request.params[3].isNull())
                    ? request.params[3].getInt<int64_t>()
                    : 0;

            const bool auto_select_inputs = txid.IsNull();
            const int min_count = auto_select_inputs ? 1 : 2;
            if (count < min_count) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("count must be at least %d", min_count));
            }
            if (count > 1000) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "count too large");
            }
            if (fixed_output_amount < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "target_amount_sat must be non-negative");
            }

            std::optional<COutPoint> selected_outpoint;
            CAmount utxo_amount{0};

            if (auto_select_inputs) {
                if (fixed_output_amount <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "target_amount_sat is required when txid is zero");
                }
            } else {
                selected_outpoint = COutPoint{txid, vout};
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(txid);
                if (!wtx || vout >= wtx->tx->vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "UTXO not found in wallet");
                }
                const CTxOut& out = wtx->tx->vout[vout];
                if (!(pwallet->IsMine(out) & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control the specified output");
                }
                utxo_amount = out.nValue;
                if (utxo_amount <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "UTXO amount must be positive");
                }
            }

            CAmount first_output_amount{0};
            CAmount other_output_amount{0};
            if (auto_select_inputs) {
                first_output_amount = fixed_output_amount;
                other_output_amount = fixed_output_amount;
            } else if (fixed_output_amount > 0) {
                const CAmount min_required = fixed_output_amount * count;
                if (utxo_amount < min_required) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "UTXO amount too small for requested count and target_amount_sat");
                }
                first_output_amount = utxo_amount - fixed_output_amount * (count - 1);
                other_output_amount = fixed_output_amount;
            } else {
                const CAmount base_share = utxo_amount / count;
                if (base_share == 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "UTXO amount too small for requested count");
                }
                const CAmount remainder = utxo_amount - base_share * count;
                first_output_amount = base_share + remainder;
                other_output_amount = base_share;
            }

            std::vector<CTxDestination> destinations;
            destinations.reserve(count);
            for (int i = 0; i < count; ++i) {
                auto maybe_dest = pwallet->GetNewDestination(OutputType::BECH32, "split-utxo");
                if (!maybe_dest) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to allocate address for split output");
                }
                destinations.push_back(*maybe_dest);
            }

            CCoinControl coin_control;
            coin_control.m_allow_other_inputs = auto_select_inputs;
            coin_control.m_include_unsafe_inputs = true;
            coin_control.m_signal_bip125_rbf = true;
            if (selected_outpoint) {
                coin_control.Select(*selected_outpoint);
            }

            const auto build_recipients = [&](CAmount fee_reserve) {
                std::vector<CRecipient> recipients;
                recipients.reserve(count);
                for (int i = 0; i < count; ++i) {
                    CAmount part_amount = (i == 0) ? first_output_amount : other_output_amount;
                    if (auto_select_inputs && i == 0) {
                        part_amount += fee_reserve;
                    }
                    recipients.push_back({destinations.at(i), part_amount, /*subtract_fee_from_amount=*/false});
                }
                if (!auto_select_inputs) {
                    recipients.front().fSubtractFeeFromAmount = true;
                }
                return recipients;
            };

            std::optional<CreatedTransactionResult> final_tx_res;
            CAmount fee_reserve{0};
            const std::optional<unsigned int> change_pos = auto_select_inputs
                ? std::optional<unsigned int>{static_cast<unsigned int>(count)}
                : std::nullopt;

            for (int attempt_num = 0; attempt_num < 10; ++attempt_num) {
                auto tx_res = CreateTransaction(*pwallet, build_recipients(fee_reserve), change_pos, coin_control);
                if (!tx_res) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(tx_res).original);
                }
                final_tx_res = *tx_res;
                if (!auto_select_inputs || tx_res->fee == fee_reserve) {
                    break;
                }
                fee_reserve = tx_res->fee;
            }

            if (!final_tx_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct split transaction");
            }
            if (auto_select_inputs && final_tx_res->fee != fee_reserve) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to stabilize split fee reserve");
            }

            auto tx = final_tx_res->tx;
            pwallet->CommitTransaction(final_tx_res->tx, {}, {});

            const auto push_output_entry = [](UniValue& target, unsigned int vout_index, const CTxOut& txout) {
                CTxDestination dest;
                if (!ExtractDestination(txout.scriptPubKey, dest)) {
                    return;
                }

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("vout", vout_index);
                entry.pushKV("amount", ValueFromAmount(txout.nValue));
                entry.pushKV("address", EncodeDestination(dest));
                target.push_back(std::move(entry));
            };

            UniValue outputs(UniValue::VARR);
            UniValue additional_outputs(UniValue::VARR);
            for (unsigned int i = 0; i < tx->vout.size(); ++i) {
                const CTxOut& txout = tx->vout[i];
                if (final_tx_res->change_pos && i == *final_tx_res->change_pos) {
                    push_output_entry(additional_outputs, i, txout);
                    continue;
                }

                CTxDestination dest;
                if (!ExtractDestination(txout.scriptPubKey, dest)) {
                    continue;
                }
                auto it = std::find(destinations.begin(), destinations.end(), dest);
                if (it == destinations.end()) {
                    continue;
                }

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("vout", i);
                entry.pushKV("amount", ValueFromAmount(txout.nValue));
                entry.pushKV("address", EncodeDestination(dest));
                outputs.push_back(std::move(entry));
            }

            if (outputs.size() != static_cast<size_t>(count)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Split transaction did not produce the expected number of outputs");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("outputs", std::move(outputs));
            result.pushKV("additional_outputs", std::move(additional_outputs));
            return result;
        }
    };
}

RPCHelpMan createchallengedeposit()
{
    return RPCHelpMan{
        "createchallengedeposit",
        "\nCreate a challenge deposit transaction accusing a block.\n",
        {
            {"block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the block being challenged"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Challenge transaction details", {
            {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
            {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex"},
            {RPCResult::Type::STR_HEX, "block_hash", "Hash of the challenged block"},
            {RPCResult::Type::NUM, "deposit_vout", "Output index holding the challenge deposit"},
            {RPCResult::Type::STR_AMOUNT, "deposit_amount", "Amount committed as the challenge deposit"},
        }},
        RPCExamples{
            HelpExampleCli("createchallengedeposit", "\"<block_hash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            uint256 block_hash = ParseHashV(request.params[0], "block_hash");

            CBlock challenged_block;
            int challenged_height{0};
            bool in_active_chain{false};
            if (!pwallet->chain().findBlock(block_hash, FoundBlock().data(challenged_block).height(challenged_height).inActiveChain(in_active_chain)) || challenged_block.IsNull()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Challenged block not found");
            }
            if (!in_active_chain) {
                throw JSONRPCError(RPC_MISC_ERROR, "Challenged block is not in the active chain");
            }
            const uint256 model_hash = challenged_block.pow.GetModelHash();
            if (model_hash.IsNull()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Challenged block has no associated model");
            }
            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }
            ModelRecord model_record;
            if (!g_modeldb->ReadModel(model_hash, model_record)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model not registered");
            }
            if (model_record.status != ModelRegistrationStatus::Registered) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model is not in registered state");
            }
            const auto current_height = pwallet->chain().getHeight();
            if (!current_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "Unable to determine chain height");
            }
            if (model_record.challenge_verdict_height > 0 && *current_height < model_record.challenge_verdict_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "Active challenge already exists for this model");
            }
            if (g_ValidationApi) {
                ValidationResponseValue status{ValidationResponseValue::Not_Checked};
                if (!g_ValidationApi->GetRequestStatus(block_hash, ValidationReqType::Challenge, status)) {
                    g_ValidationApi->SendApiRequest(challenged_block, ValidationReqType::Challenge, ValidationResponseBehavior::Nothing);
                }
            }

            const Consensus::Params& consensus_params = Params().GetConsensus();
            const CAmount deposit_amount = consensus_params.ModelChallengeDeposit;
            if (deposit_amount <= 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "Consensus challenge deposit is not configured");
            }

            EnsureWalletIsUnlocked(*pwallet);

            // Deposit should be returnable unless challenge fails, so send to a fresh wallet address
            auto refund_dest_res = pwallet->GetNewDestination(OutputType::BECH32, "");
            if (!refund_dest_res) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   "Unable to get new destination for challenge deposit: " +
                                       util::ErrorString(refund_dest_res).original);
            }
            const CTxDestination refund_dest = *refund_dest_res;
            std::vector<CRecipient> recipients;
            recipients.push_back({refund_dest, deposit_amount, /*subtract_fee_from_amount=*/false});
            // Include the challenge OP_RETURN output up-front so fee estimation accounts for its weight
            recipients.push_back({CNoDestination(CreateModelChallengeScript(block_hash)), 0, /*subtract_fee_from_amount=*/false});

            CCoinControl coin_control;
            coin_control.m_allow_other_inputs = true;
            coin_control.m_signal_bip125_rbf = true;

            // Force deterministic output ordering: [deposit, op_return, change]
            const std::optional<unsigned int> change_pos{static_cast<unsigned int>(recipients.size())};
            auto tx_res = CreateTransaction(*pwallet, recipients, change_pos, coin_control);
            if (!tx_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(tx_res).original);
            }

            CMutableTransaction mtx(*tx_res->tx);
            mtx.version = Consensus::MODEL_ACCUSATION_TX_VERSION;

            if (!pwallet->SignTransaction(mtx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Signing failed");
            }

            auto tx = MakeTransactionRef(mtx);
            std::string hex = EncodeHexTx(*tx);

            bool broadcast = true;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                broadcast = request.params[1].get_bool();
            }

            if (broadcast) {
                pwallet->CommitTransaction(tx, {}, {});
            }
        
            const CScript refund_script = GetScriptForDestination(refund_dest);
            const uint32_t deposit_vout = 0;
            // Sanity: ensure the deterministic position matches expectations.
            if (tx->vout.size() <= deposit_vout ||
                tx->vout[deposit_vout].scriptPubKey != refund_script ||
                tx->vout[deposit_vout].nValue < deposit_amount) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Challenge deposit output mismatch after signing");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().ToString());
            result.pushKV("hex", hex);
            result.pushKV("block_hash", block_hash.ToString());
            result.pushKV("deposit_vout", deposit_vout);
            result.pushKV("deposit_amount", ValueFromAmount(tx->vout[deposit_vout].nValue));
            return result;
        }
    };
}

RPCHelpMan createchallengecommits()
{
    return RPCHelpMan{
        "createchallengecommits",
        "\nCreate challenge commit transaction(s) for an active model challenge.\n",
        {
            {"model_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the challenged model"},
            {"tx_count", RPCArg::Type::NUM, RPCArg::Default{CHALLENGE_COMMIT_THRESHOLD},
                strprintf("Number of challenge commit transactions to create (min 1, max %u)", CHALLENGE_VERIFICATION_BLOCK_COUNT)},
            {"funding_utxos", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional list of wallet UTXOs to prioritize for paying commit fees", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
                }},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Challenge commit transaction details", {
            {RPCResult::Type::ARR, "transactions", "Challenge commit transactions", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "txid", "Transaction id of the challenge commit"},
                    {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex"},
                }},
            }},
            {RPCResult::Type::NUM, "count", "Number of transactions created"},
            {RPCResult::Type::STR_HEX, "challenge_txid", "Challenge deposit txid"},
            {RPCResult::Type::NUM, "challenge_vout", "Challenge deposit vout"},
            {RPCResult::Type::STR_HEX, "model_hash", "Model hash"},
        }},
        RPCExamples{
            HelpExampleCli("createchallengecommits", "\"<model_hash>\" 3")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const uint256 model_hash = ParseHashV(request.params[0], "model_hash");
            int arg_tx_count = request.params[1].isNull() ? CHALLENGE_COMMIT_THRESHOLD : request.params[1].getInt<int>();
            if (arg_tx_count < 1) arg_tx_count = 1;
            unsigned int tx_count = static_cast<unsigned int>(arg_tx_count);
            tx_count = std::min<unsigned int>(tx_count, CHALLENGE_VERIFICATION_BLOCK_COUNT);
            
            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }

            ModelRecord record;
            if (!g_modeldb->ReadModel(model_hash, record)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to read model record");
            }
            if (record.status != ModelRegistrationStatus::Registered) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model is not in registered state");
            }
            const auto current_height = pwallet->chain().getHeight();
            if (!current_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "Unable to determine chain height");
            }
            if (record.challenge_verdict_height == 0 || *current_height >= record.challenge_verdict_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "No active challenge window for this model");
            }
            if (record.challenge_deposit_txid.IsNull()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model has no active challenge deposit");
            }
            if (!g_ValidationApi) {
                throw JSONRPCError(RPC_MISC_ERROR, "Validation unavailable");
            }
            const Txid challenge_txid{Txid::FromUint256(record.challenge_deposit_txid)};
            const uint32_t challenge_vout = record.challenge_deposit_vout;
            const COutPoint challenge_outpoint{challenge_txid, challenge_vout};
            
            Txid deposit_txid{Txid::FromUint256(record.deposit_txid)};
            uint32_t deposit_vout = record.deposit_vout;
            const COutPoint deposit_outpoint{deposit_txid, deposit_vout};
            std::vector<COutPoint> locked_deposits;
            {
                LOCK(pwallet->cs_wallet);
                if (!pwallet->IsLockedCoin(deposit_outpoint)) {
                    pwallet->LockCoin(deposit_outpoint);
                    locked_deposits.push_back(deposit_outpoint);
                }
                if (!pwallet->IsLockedCoin(challenge_outpoint)) {
                    pwallet->LockCoin(challenge_outpoint);
                    locked_deposits.push_back(challenge_outpoint);
                }
            }
            struct DepositUnlocker {
                CWallet& wallet;
                std::vector<COutPoint> coins;
                ~DepositUnlocker()
                {
                    LOCK(wallet.cs_wallet);
                    for (const auto& op : coins) wallet.UnlockCoin(op);
                }
            } deposit_unlocker{*pwallet, std::move(locked_deposits)};

            std::deque<COutPoint> manual_funding;
            const bool has_manual_funding_param = request.params.size() > 2 && !request.params[2].isNull();
            if (has_manual_funding_param) {
                const UniValue& funding_param = request.params[2];
                if (!funding_param.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos must be an array");
                }
                std::set<COutPoint> manual_seen;
                for (unsigned int idx = 0; idx < funding_param.size(); ++idx) {
                    const UniValue& entry = funding_param[idx];
                    if (!entry.isObject()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos entries must be objects");
                    }
                    const UniValue& txid_val = entry.find_value("txid");
                    const UniValue& vout_val = entry.find_value("vout");
                    if (!txid_val.isStr() || !vout_val.isNum()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos entries require txid (string) and vout (numeric)");
                    }
                    Txid funding_txid{Txid::FromUint256(ParseHashV(txid_val, "txid"))};
                    uint32_t funding_vout = vout_val.getInt<uint32_t>();
                    COutPoint funding_outpoint{funding_txid, funding_vout};
                    if (funding_outpoint == deposit_outpoint || funding_outpoint == challenge_outpoint) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos may not include the deposit UTXO");
                    }
                    if (!manual_seen.insert(funding_outpoint).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate entries detected in funding_utxos");
                    }
                    if (g_modeldb && g_modeldb->LookupModelByDeposit(funding_outpoint)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_utxos may not include model deposit outputs");
                    }
                    {
                        LOCK(pwallet->cs_wallet);
                        const CWalletTx* funding_wtx = pwallet->GetWalletTx(funding_txid);
                        if (!funding_wtx || funding_vout >= funding_wtx->tx->vout.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "funding_utxos entry not found in wallet");
                        }
                        const CTxOut& funding_out = funding_wtx->tx->vout[funding_vout];
                        if (!(pwallet->IsMine(funding_out) & ISMINE_SPENDABLE)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control a funding_utxos entry");
                        }
                        if (pwallet->IsLockedCoin(funding_outpoint)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "funding_utxos entry is locked");
                        }
                    }
                    manual_funding.push_back(funding_outpoint);
                }
            }

            EnsureWalletIsUnlocked(*pwallet);

            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(challenge_txid);
                if (!wtx || challenge_vout >= wtx->tx->vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Challenge transaction not found in wallet");
                }
                if (!(pwallet->IsMine(wtx->tx->vout[challenge_vout]) & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control thecchallenge deposit output");
                }
            }

            UniValue result(UniValue::VOBJ);

            auto build_commit_transactions = [&](const std::vector<CScript>& commit_scripts,
                                                 unsigned int commit_target) {
                std::vector<CRecipient> recipients;
                recipients.reserve(commit_scripts.size());
                for (const auto& script : commit_scripts) {
                    recipients.push_back({CNoDestination(script), 0, /*subtract_fee_from_amount=*/false});
                }

                static constexpr CAmount COMMIT_FUNDING_TARGET{20'000};
                static constexpr unsigned int MAX_PARENT_CHILDREN{CHALLENGE_VERIFICATION_BLOCK_COUNT};
                static constexpr CAmount COMMIT_FUNDING_MAX{COMMIT_FUNDING_TARGET * MODEL_VERIFICATION_BLOCK_COUNT};
                std::map<Txid, std::deque<COutPoint>> funding_batches;
                std::deque<Txid> parent_cycle;
                std::set<COutPoint> funding_known;
                std::map<Txid, unsigned int> parent_usage;
                for (const auto& manual_op : manual_funding) {
                    funding_known.insert(manual_op);
                }

                const auto funding_available = [&]() -> unsigned int {
                    unsigned int total{0};
                    for (const auto& entry : funding_batches) {
                        total += entry.second.size();
                    }
                    return total;
                };

                const auto refill_funding_pool = [&](unsigned int required) {
                    unsigned int manual_remaining = static_cast<unsigned int>(std::min<size_t>(manual_funding.size(), std::numeric_limits<unsigned int>::max()));
                    if (manual_remaining >= required) {
                        return;
                    }
                    unsigned int needed = required - manual_remaining;
                    {
                        LOCK(pwallet->cs_wallet);
                        CCoinControl snapshot_control;
                        snapshot_control.m_min_depth = 1;
                        snapshot_control.m_include_unsafe_inputs = false;
                        auto snapshot = AvailableCoinsListUnspent(*pwallet, &snapshot_control).All();
                        CAmount total{0};
                        for (const auto& coin : snapshot) total += coin.txout.nValue;
                    }

                    auto collect_available = [&](unsigned int target) {
                        LOCK(pwallet->cs_wallet);
                        CCoinControl scan_control;
                        scan_control.m_min_depth = 1;
                        scan_control.m_include_unsafe_inputs = false;
                        CoinFilterParams filter;
                        filter.min_amount = COMMIT_FUNDING_TARGET;
                        filter.max_amount = COMMIT_FUNDING_MAX;
                        for (const COutput& coin : AvailableCoinsListUnspent(*pwallet, &scan_control, filter).All()) {
                            if (!coin.spendable) continue;
                            if (coin.outpoint == deposit_outpoint || coin.outpoint == challenge_outpoint) continue;
                            if (g_modeldb && g_modeldb->LookupModelByDeposit(coin.outpoint)) {
                                continue;
                            }
                            const Txid parent{Txid::FromUint256(coin.outpoint.hash)};
                            if (funding_known.count(coin.outpoint)) continue;
                            if (parent_usage[parent] >= MAX_PARENT_CHILDREN) continue;
                            auto& queue = funding_batches[parent];
                            if (queue.empty()) {
                                parent_cycle.push_back(parent);
                            }
                            if (parent_usage[parent] + queue.size() >= MAX_PARENT_CHILDREN) {
                                continue;
                            }
                            queue.push_back(coin.outpoint);
                            funding_known.insert(coin.outpoint);
                            if (funding_available() >= target) break;
                        }
                    };

                    const unsigned int BATCH_LIMIT{MAX_PARENT_CHILDREN};

                    while (funding_available() < needed) {
                        collect_available(needed);
                        if (funding_available() >= needed) break;

                        const unsigned int missing = needed - funding_available();
                        const unsigned int batch = std::min<unsigned int>(missing, BATCH_LIMIT);
                        if (batch == 0) break;

                        std::vector<CRecipient> split_recipients;
                        split_recipients.reserve(batch);
                        std::vector<CTxDestination> split_dests;
                        split_dests.reserve(batch);
                        for (unsigned int i = 0; i < batch; ++i) {
                            auto maybe_dest = pwallet->GetNewDestination(OutputType::BECH32, "challenge-commit-funding");
                            if (!maybe_dest) {
                                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to allocate commit funding address");
                            }
                            split_dests.push_back(*maybe_dest);
                            split_recipients.push_back({*maybe_dest, COMMIT_FUNDING_TARGET, /*subtract_fee_from_amount=*/false});
                        }

                        CCoinControl split_control;
                        split_control.m_allow_other_inputs = true;
                        split_control.m_min_depth = 1;
                        split_control.m_include_unsafe_inputs = false;
                        split_control.m_signal_bip125_rbf = true;

                        auto split_res = CreateTransaction(*pwallet, split_recipients, std::nullopt, split_control);
                        if (!split_res) {
                            const std::string err = util::ErrorString(split_res).original;
                            throw JSONRPCError(RPC_WALLET_ERROR, err);
                        }

                        pwallet->CommitTransaction(split_res->tx, {}, {});

                        const Txid split_txid = Txid::FromUint256(split_res->tx->GetHash());
                        std::vector<CScript> expected_scripts;
                        expected_scripts.reserve(split_dests.size());
                        for (const auto& dest : split_dests) {
                            expected_scripts.push_back(GetScriptForDestination(dest));
                        }

                        std::vector<COutPoint> new_outputs;
                        for (unsigned int i = 0; i < split_res->tx->vout.size(); ++i) {
                            const auto& out = split_res->tx->vout[i];
                            auto it = std::find(expected_scripts.begin(), expected_scripts.end(), out.scriptPubKey);
                            if (it == expected_scripts.end()) continue;
                            new_outputs.emplace_back(split_txid, i);
                        }

                        if (new_outputs.size() != split_dests.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate commit funding outputs");
                        }

                        for (const auto& outpoint : new_outputs) {
                            funding_batches[Txid::FromUint256(outpoint.hash)].push_back(outpoint);
                            funding_known.insert(outpoint);
                        }
                    }
                };

                const auto select_manual_or_parent = [&]() -> std::optional<COutPoint> {
                    if (!manual_funding.empty()) {
                        COutPoint next = manual_funding.front();
                        manual_funding.pop_front();
                        funding_known.erase(next);
                        return next;
                    }
                    const size_t cycle_len = parent_cycle.size();
                    for (size_t attempt = 0; attempt < cycle_len; ++attempt) {
                        if (parent_cycle.empty()) break;
                        const Txid parent = parent_cycle.front();
                        parent_cycle.pop_front();
                        auto it_batch = funding_batches.find(parent);
                        if (it_batch == funding_batches.end() || it_batch->second.empty()) {
                            continue;
                        }
                        auto next = it_batch->second.front();
                        it_batch->second.pop_front();
                        if (next == deposit_outpoint) {
                            continue;
                        }
                        if (!it_batch->second.empty()) {
                            parent_cycle.push_back(parent);
                        } else {
                            funding_batches.erase(it_batch);
                        }
                        funding_known.erase(next);
                        parent_usage[parent]++;
                        return next;
                    }
                    return std::nullopt;
                };

                UniValue tx_array(UniValue::VARR);
                std::string first_txid;
                unsigned int created{0};

                for (unsigned int i = 0; i < commit_target; ++i) {
                    refill_funding_pool(commit_target - created);
                    COutPoint funding_input;
                    bool found_input{false};
                        if (!manual_funding.empty()) {
                            funding_input = manual_funding.front();
                            manual_funding.pop_front();
                            funding_known.erase(funding_input);
                            found_input = true;
                        }
                        if (!found_input) {
                            auto maybe_parent = select_manual_or_parent();
                            if (maybe_parent) {
                                funding_input = *maybe_parent;
                                found_input = true;
                            }
                        }

                        if (!found_input) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient commit funding outputs");
                    }

                    CCoinControl coin_control;
                    coin_control.m_allow_other_inputs = false;
                    coin_control.m_include_unsafe_inputs = true;
                    coin_control.m_min_depth = 0;
                    coin_control.m_version = Consensus::MODEL_CHALLENGE_COMMIT_TX_VERSION;
                    CScript funding_change_script;
                    {
                        LOCK(pwallet->cs_wallet);
                        const CWalletTx* funding_wtx = pwallet->GetWalletTx(Txid::FromUint256(funding_input.hash));
                        if (!funding_wtx || funding_input.n >= funding_wtx->tx->vout.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Funding input not found in wallet");
                        }
                        const CTxOut& funding_out = funding_wtx->tx->vout[funding_input.n];
                        if (funding_out.scriptPubKey.IsUnspendable()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Funding input script is unspendable");
                        }
                        funding_change_script = funding_out.scriptPubKey;
                    }
                    coin_control.destChange = CNoDestination(funding_change_script);
                    coin_control.Select(funding_input);

                    auto tx_res = CreateTransaction(*pwallet, recipients, std::nullopt, coin_control);
                    if (!tx_res) {
                        const std::string err = util::ErrorString(tx_res).original;
                        throw JSONRPCError(RPC_WALLET_ERROR, err);
                    }
                    for (const auto& vin : tx_res->tx->vin) {
                        if (vin.prevout == deposit_outpoint) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Commit funding transaction must not spend model deposit");
                        }
                        if (vin.prevout == challenge_outpoint) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Commit funding transaction must not spend challenge deposit");
                        }
                    }

                    const std::string txid = tx_res->tx->GetHash().ToString();
                    const std::string hex = EncodeHexTx(*tx_res->tx);
    
                    pwallet->CommitTransaction(tx_res->tx, {}, {});

                    UniValue tx_entry(UniValue::VOBJ);
                    tx_entry.pushKV("txid", txid);
                    tx_entry.pushKV("hex", hex);
                    tx_array.push_back(std::move(tx_entry));

                    if (first_txid.empty()) {
                        first_txid = txid;
                    }
                    ++created;
                }

                result.pushKV("transactions", std::move(tx_array));
                result.pushKV("count", created);
                result.pushKV("challenge_txid", challenge_txid.ToString());
                result.pushKV("challenge_vout", static_cast<int>(challenge_vout));
                result.pushKV("model_hash", model_hash.ToString());
            };

            build_commit_transactions(CreateModelChallengeCommitScript(model_hash), tx_count);

            return result;
        }
    };
}

RPCHelpMan getmodelregistrationstatus()
{
    return RPCHelpMan{
        "getmodelregistrationstatus",
        "\nQuery the registration status of a model hash.\n",
        {
            {"model_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Model hash"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Model status information", {
            {RPCResult::Type::STR, "model_hash", "Model hash"},
            {RPCResult::Type::STR, "status", "Registration status"},
            {RPCResult::Type::STR, "deposit_txid", "Deposit transaction id"},
            {RPCResult::Type::NUM, "deposit_vout", "Deposit output index"},
            {RPCResult::Type::STR, "deposit_block_hash", "Block hash where the deposit confirmed"},
            {RPCResult::Type::NUM, "deposit_block_height", "Block height where the deposit confirmed"},
            {RPCResult::Type::BOOL, "deposit_unspent", "Whether the deposit output is still unspent in chainstate"},
            {RPCResult::Type::STR, "commit_txid", "Commit transaction id (if any)"},
            {RPCResult::Type::STR, "commit_block_hash", "Block hash where the commit confirmed"},
            {RPCResult::Type::NUM, "commit_block_height", "Block height where the commit confirmed"},
            {RPCResult::Type::NUM, "verification_code", "Verification result code"},
            {RPCResult::Type::STR, "verification_details", "Optional verification details"},
            {RPCResult::Type::STR, "burn_txid", "Burn transaction id"},
            {RPCResult::Type::NUM, "burn_vout", "Burn output index"},
            {RPCResult::Type::NUM, "burn_block_height", "Block height where the burn confirmed"},
            {RPCResult::Type::NUM, "deposit_unlock_height", "Block height where owner reclaim becomes allowed"},
            {RPCResult::Type::BOOL, "owner_reclaim_allowed", "Whether the owner may reclaim the deposit now"},
            {RPCResult::Type::NUM, "burn_allowed_height", "Block height where the burn allowed"},
            {RPCResult::Type::BOOL, "burn_ready", "Burn could be realized flag"},
            {RPCResult::Type::NUM, "successful_commit_count", "Number of successful commit transactions confirmed on-chain"},
            {RPCResult::Type::NUM, "verification_event_height", "Height at which the verification window closes (0 if not scheduled)"},
            {RPCResult::Type::STR, "challenge_block_hash", "Block hash being challenged (zero if none)"},
            {RPCResult::Type::STR, "challenge_deposit_txid", "Challenge deposit transaction id"},
            {RPCResult::Type::NUM, "challenge_deposit_vout", "Challenge deposit output index"},
            {RPCResult::Type::NUM, "challenge_deposit_height", "Block height of the challenge deposit"},
            {RPCResult::Type::NUM, "challenge_verdict_height", "Scheduled height for challenge verdict (0 if none)"},
            {RPCResult::Type::NUM, "challenge_commit_count", "Number of challenge commit transactions observed"},
        }},
        RPCExamples{
            HelpExampleCli("getmodelregistrationstatus", "\"<model_hash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_modeldb) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model database unavailable");
            }

            uint256 model_hash = ParseHashV(request.params[0], "model_hash");

            ModelRecord record;
            if (!g_modeldb->ReadModel(model_hash, record)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Model hash not found");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("model_hash", model_hash.ToString());
            result.pushKV("status", ModelStatusToString(record.status));
            result.pushKV("deposit_txid", record.deposit_txid.ToString());
            result.pushKV("deposit_vout", record.deposit_vout);
            result.pushKV("deposit_block_hash", record.deposit_block_hash.ToString());
            result.pushKV("deposit_block_height", record.deposit_block_height);
            bool deposit_unspent{false};
            if (!record.deposit_txid.IsNull()) {
                const Txid deposit_txid = Txid::FromUint256(record.deposit_txid);
                const COutPoint deposit_outpoint{deposit_txid, record.deposit_vout};
                std::map<COutPoint, Coin> deposit_coins;
                deposit_coins[deposit_outpoint];
                pwallet->chain().findCoins(deposit_coins);
                const auto coin_it = deposit_coins.find(deposit_outpoint);
                deposit_unspent = coin_it != deposit_coins.end() && !coin_it->second.IsSpent();
            }
            result.pushKV("deposit_unspent", deposit_unspent);
            result.pushKV("commit_txid", record.commit_txid.ToString());
            result.pushKV("commit_block_hash", record.commit_block_hash.ToString());
            result.pushKV("commit_block_height", record.commit_block_height);
            result.pushKV("verification_code", record.verification_code);
            result.pushKV("verification_details", record.verification_details);
            result.pushKV("burn_txid", record.burn_txid.ToString());
            result.pushKV("burn_vout", record.burn_vout);
            result.pushKV("burn_block_height", record.burn_block_height);
            const Consensus::Params& consensus_params = Params().GetConsensus();
            int current_height{0};
            if (auto height = pwallet->chain().getHeight()) {
                current_height = *height;
            }
            const int deposit_unlock_height = GetModelDepositUnlockHeight(record, consensus_params);
            const bool owner_reclaim_allowed =
                record.status == ModelRegistrationStatus::Registered &&
                deposit_unspent &&
                deposit_unlock_height > 0 &&
                current_height >= deposit_unlock_height;
            int burn_allowed_height = 0;
            if (record.status == ModelRegistrationStatus::Locked) {
                burn_allowed_height = record.commit_block_height;
            } else if (record.status == ModelRegistrationStatus::Banned) {
                burn_allowed_height = record.burn_block_height > 0 ? record.burn_block_height : record.commit_block_height;
            } else {
                burn_allowed_height = record.commit_block_height == 0 ? 0 : record.commit_block_height + consensus_params.ModelCommitRefundDelay;
            }
            result.pushKV("burn_allowed_height", burn_allowed_height);
            bool burn_ready =
                (record.status == ModelRegistrationStatus::Locked && record.commit_block_height > 0) ||
                (record.status == ModelRegistrationStatus::Banned && record.commit_block_height > 0);
            result.pushKV("burn_ready", burn_ready);
            result.pushKV("deposit_unlock_height", deposit_unlock_height);
            result.pushKV("owner_reclaim_allowed", owner_reclaim_allowed);
            result.pushKV("successful_commit_count", record.successful_commit_count);
            result.pushKV("verification_event_height", record.verification_event_height);
            result.pushKV("challenge_block_hash", record.challenge_block_hash.ToString());
            result.pushKV("challenge_deposit_txid", record.challenge_deposit_txid.ToString());
            result.pushKV("challenge_deposit_vout", record.challenge_deposit_vout);
            result.pushKV("challenge_deposit_height", record.challenge_deposit_height);
            result.pushKV("challenge_verdict_height", record.challenge_verdict_height);
            result.pushKV("challenge_commit_count", record.challenge_commit_count);
            return result;
        }
    };
}

} // namespace wallet
