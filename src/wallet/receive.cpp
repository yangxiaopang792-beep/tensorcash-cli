// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <chainparams.h>
#include <modeldb.h>
#include <wallet/receive.h>
#include <wallet/rpc/api_model_registration.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>
#include <wallet/contract.h>
#include <wallet/vaultregistry.h>

namespace wallet {
namespace {

int GetBalanceViewHeight(const CWallet& wallet)
{
    const std::optional<int> chain_height = wallet.chain().getHeight();
    return chain_height.value_or(0);
}

bool IsModelDepositOutput(const CTransaction& tx, const uint32_t vout_index)
{
    ModelDepositPayload payload;
    return ParseModelDepositTx(tx, payload, Params().GetConsensus()) && payload.deposit_vout == vout_index;
}

bool IsChallengeDepositOutput(const CTransaction& tx, const uint32_t vout_index)
{
    ModelChallengePayload payload;
    return ParseModelChallengeTx(tx, payload, Params().GetConsensus()) && payload.deposit_vout == vout_index;
}

bool IsLockedModelDeposit(const COutPoint& outpoint, const CTransaction& tx, int current_height)
{
    if (!IsModelDepositOutput(tx, outpoint.n)) {
        return false;
    }
    if (!g_modeldb) {
        return true;
    }

    const auto model_hash = g_modeldb->LookupModelByDeposit(outpoint);
    if (!model_hash) {
        return true;
    }

    ModelRecord record;
    if (!g_modeldb->ReadModel(*model_hash, record)) {
        return true;
    }

    if (record.deposit_block_height <= 0) {
        return true;
    }
    if (record.status != ModelRegistrationStatus::Registered) {
        return true;
    }

    const int64_t unlock_height = static_cast<int64_t>(record.deposit_block_height) + Params().GetConsensus().ModelCommitRefundDelay;
    const int64_t spend_height = static_cast<int64_t>(current_height) + 1;
    return spend_height < unlock_height;
}

bool IsLockedChallengeDeposit(const COutPoint& outpoint, const CTransaction& tx, int current_height)
{
    if (!IsChallengeDepositOutput(tx, outpoint.n)) {
        return false;
    }
    if (!g_modeldb) {
        return true;
    }

    const auto model_hash = g_modeldb->LookupModelByChallengeDeposit(outpoint);
    if (!model_hash) {
        return true;
    }

    ModelRecord record;
    if (!g_modeldb->ReadModel(*model_hash, record)) {
        return true;
    }

    if (record.challenge_deposit_height <= 0) {
        return true;
    }
    if (record.challenge_verdict_height <= 0) {
        return true;
    }

    const int64_t spend_height = static_cast<int64_t>(current_height) + 1;
    return spend_height <= static_cast<int64_t>(record.challenge_verdict_height);
}

bool IsBondedSpecialOutput(const COutPoint& outpoint, const CTransaction& tx, int current_height)
{
    return IsLockedModelDeposit(outpoint, tx, current_height) ||
           IsLockedChallengeDeposit(outpoint, tx, current_height);
}

} // namespace

bool IsModelReservedOutput(const COutPoint& outpoint, const CTransaction& creating_tx, int current_height)
{
    // Deposit / challenge-deposit branch (parser-first, fail-closed): see
    // IsLockedModelDeposit / IsLockedChallengeDeposit above. A burn-state
    // deposit is also caught here because its model record has
    // status != Registered (or the deposit-index entry was erased), both of
    // which IsLockedModelDeposit treats as reserved.
    if (IsBondedSpecialOutput(outpoint, creating_tx, current_height)) {
        return true;
    }
    // Defensive belt-and-suspenders: burn-indexed outpoints may only be
    // consumed by a version-7 burn tx (createmodelburn builds that input by
    // hand). Mirrors validation.cpp:LookupModelByBurn.
    if (g_modeldb && g_modeldb->LookupModelByBurn(outpoint)) {
        return true;
    }
    return false;
}

isminetype InputIsMine(const CWallet& wallet, const CTxIn& txin)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* prev = wallet.GetWalletTx(txin.prevout.hash);
    if (prev && txin.prevout.n < prev->tx->vout.size()) {
        return wallet.IsMine(prev->tx->vout[txin.prevout.n]);
    }
    return ISMINE_NO;
}

bool AllInputsMine(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter)
{
    LOCK(wallet.cs_wallet);
    for (const CTxIn& txin : tx.vin) {
        if (!(InputIsMine(wallet, txin) & filter)) return false;
    }
    return true;
}

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout, const isminefilter& filter)
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    LOCK(wallet.cs_wallet);
    return ((wallet.IsMine(txout) & filter) ? txout.nValue : 0);
}

CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter)
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += OutputGetCredit(wallet, txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

bool ScriptIsChange(const CWallet& wallet, const CScript& script)
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;
        if (!wallet.FindAddressBookEntry(address)) {
            return true;
        }
    }
    return false;
}

bool OutputIsChange(const CWallet& wallet, const CTxOut& txout)
{
    return ScriptIsChange(wallet, txout.scriptPubKey);
}

CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (OutputIsChange(wallet, txout) ? txout.nValue : 0);
}

CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += OutputGetChange(wallet, txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

static CAmount GetCachableAmount(const CWallet& wallet, const CWalletTx& wtx, CWalletTx::AmountType type, const isminefilter& filter)
{
    auto& amount = wtx.m_amounts[type];
    if (!amount.m_cached[filter]) {
        amount.Set(filter, type == CWalletTx::DEBIT ? wallet.GetDebit(*wtx.tx, filter) : TxGetCredit(wallet, *wtx.tx, filter));
        wtx.m_is_cache_empty = false;
    }
    return amount.m_value[filter];
}

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    CAmount credit = 0;
    const isminefilter get_amount_filter{filter & ISMINE_ALL};
    if (get_amount_filter) {
        // GetBalance can assume transactions in mapWallet won't change
        credit += GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, get_amount_filter);
    }
    return credit;
}

CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    if (wtx.tx->vin.empty())
        return 0;

    CAmount debit = 0;
    const isminefilter get_amount_filter{filter & ISMINE_ALL};
    if (get_amount_filter) {
        debit += GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, get_amount_filter);
    }
    return debit;
}

CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx)
{
    if (wtx.fChangeCached)
        return wtx.nChangeCached;
    wtx.nChangeCached = TxGetChange(wallet, *wtx.tx);
    wtx.fChangeCached = true;
    return wtx.nChangeCached;
}

CAmount CachedTxGetImmatureCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    if (wallet.IsTxImmatureCoinBase(wtx) && wtx.isConfirmed()) {
        return GetCachableAmount(wallet, wtx, CWalletTx::IMMATURE_CREDIT, filter);
    }

    return 0;
}

CAmount CachedTxGetAvailableCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    // Avoid caching ismine for NO or ALL cases (could remove this check and simplify in the future).
    bool allow_cache = (filter & ISMINE_ALL) && (filter & ISMINE_ALL) != ISMINE_ALL;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    if (allow_cache && wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_cached[filter]) {
        return wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_value[filter];
    }

    bool allow_used_addresses = (filter & ISMINE_USED) || !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    CAmount nCredit = 0;
    Txid hashTx = wtx.GetHash();
    const int current_height = GetBalanceViewHeight(wallet);
    for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
        const CTxOut& txout = wtx.tx->vout[i];
        const COutPoint outpoint(hashTx, i);

        if (IsModelReservedOutput(outpoint, *wtx.tx, current_height)) {
            continue;
        }

        // Skip ICU (Issuer Credential UTXO) outputs from available balance
        // ICU outputs are bonded and not spendable for regular transactions
        std::optional<AssetMetadata> asset_meta = wallet.GetAssetMetadata(outpoint);
        if (asset_meta && asset_meta->is_issuer_credential) {
            continue;
        }

        if (!wallet.IsSpent(outpoint) && (allow_used_addresses || !wallet.IsSpentKey(txout.scriptPubKey))) {
            nCredit += OutputGetCredit(wallet, txout, filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + " : value out of range");
        }
    }

    if (allow_cache) {
        wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].Set(filter, nCredit);
        wtx.m_is_cache_empty = false;
    }

    return nCredit;
}

void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                  std::list<COutputEntry>& listReceived,
                  std::list<COutputEntry>& listSent, CAmount& nFee, const isminefilter& filter,
                  bool include_change)
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    // Compute fee:
    CAmount nDebit = CachedTxGetDebit(wallet, wtx, filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = wtx.tx->GetValueOut();
        nFee = nDebit - nValueOut;
    }

    LOCK(wallet.cs_wallet);
    // Sent/received.
    for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i)
    {
        const CTxOut& txout = wtx.tx->vout[i];
        isminetype fIsMine = wallet.IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            if (!include_change && OutputIsChange(wallet, txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                    wtx.GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    return (CachedTxGetDebit(wallet, wtx, filter) > 0);
}

// NOLINTNEXTLINE(misc-no-recursion)
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<Txid>& trusted_parents)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wtx.isConfirmed()) return true;
    if (wtx.isBlockConflicted()) return false;
    // using wtx's cached debit
    if (!wallet.m_spend_zero_conf_change || !CachedTxIsFromMe(wallet, wtx, ISMINE_ALL)) return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!wtx.InMempool()) return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : wtx.tx->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = wallet.GetWalletTx(txin.prevout.hash);
        if (parent == nullptr) return false;
        const CTxOut& parentOut = parent->tx->vout[txin.prevout.n];
        // Check that this specific input being spent is trusted
        if (wallet.IsMine(parentOut) != ISMINE_SPENDABLE) return false;
        // If we've already trusted this parent, continue
        if (trusted_parents.count(parent->GetHash())) continue;
        // Recurse to check that the parent is also trusted
        if (!CachedTxIsTrusted(wallet, *parent, trusted_parents)) return false;
        trusted_parents.insert(parent->GetHash());
    }
    return true;
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx)
{
    std::set<Txid> trusted_parents;
    LOCK(wallet.cs_wallet);
    return CachedTxIsTrusted(wallet, wtx, trusted_parents);
}

Balance GetBalance(const CWallet& wallet, const int min_depth, bool avoid_reuse)
{
    Balance ret;
    isminefilter reuse_filter = avoid_reuse ? ISMINE_NO : ISMINE_USED;
    {
        LOCK(wallet.cs_wallet);

        // Build map of forward contract_id -> local_side for vault role filtering
        std::map<uint256, ForwardSide> forward_side_by_contract;
        for (const auto& fwd : wallet.ListForwardContracts()) {
            // Only include opened contracts (where vaults are active)
            if (fwd.DerivedState() == ForwardContractState::OPENED) {
                forward_side_by_contract[fwd.contract_id] = fwd.local_side;
            }
        }

        // Build set of opened repo offer IDs where local wallet is borrower
        std::set<uint256> borrower_repo_contracts;
        for (const auto& repo : wallet.ListRepoOffers()) {
            if (repo.DerivedState() == RepoContractState::OPENED) {
                // Determine if local wallet is borrower.
                // Prefer the persisted maker_role marker (combined with the
                // "I am the maker" signal from local_fs_tx_adaptor_secret).
                // For legacy records where maker_role wasn't serialized, fall
                // back to address ownership — that's authoritative across
                // restarts because it derives from the wallet's descriptors.
                const bool i_am_maker = repo.local_fs_tx_adaptor_secret.has_value();
                bool is_borrower;
                if (repo.maker_role == "borrower") {
                    is_borrower = i_am_maker;
                } else if (repo.maker_role == "lender") {
                    is_borrower = !i_am_maker;
                } else {
                    const isminetype borrower_mine = wallet.IsMine(GetScriptForDestination(repo.borrower_dest));
                    const isminetype lender_mine = wallet.IsMine(GetScriptForDestination(repo.lender_dest));
                    if (borrower_mine != ISMINE_NO && lender_mine == ISMINE_NO) {
                        is_borrower = true;
                    } else if (lender_mine != ISMINE_NO && borrower_mine == ISMINE_NO) {
                        is_borrower = false;
                    } else {
                        // Both/neither mine (watch-only or unusual case) — default to !maker.
                        is_borrower = !i_am_maker;
                    }
                }
                if (is_borrower) {
                    borrower_repo_contracts.insert(repo.offer_id);
                }
            }
        }

        std::set<Txid> trusted_parents;
        const int current_height = GetBalanceViewHeight(wallet);
        for (const auto& entry : wallet.mapWallet)
        {
            const CWalletTx& wtx = entry.second;
            const bool is_trusted{CachedTxIsTrusted(wallet, wtx, trusted_parents)};
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};
            const CAmount tx_credit_mine{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_SPENDABLE | reuse_filter)};
            const CAmount tx_credit_watchonly{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_WATCH_ONLY | reuse_filter)};
            if (is_trusted && tx_depth >= min_depth) {
                ret.m_mine_trusted += tx_credit_mine;
                ret.m_watchonly_trusted += tx_credit_watchonly;
            }
            if (!is_trusted && tx_depth == 0 && wtx.InMempool()) {
                ret.m_mine_untrusted_pending += tx_credit_mine;
                ret.m_watchonly_untrusted_pending += tx_credit_watchonly;
            }
            ret.m_mine_immature += CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE);
            ret.m_watchonly_immature += CachedTxGetImmatureCredit(wallet, wtx, ISMINE_WATCH_ONLY);

            // Calculate bonded balance (ICU + contract vaults)
            if (wallet.IsTxImmatureCoinBase(wtx)) continue;
            // Skip abandoned or conflicted transactions
            if (wtx.isAbandoned() || wtx.isBlockConflicted()) continue;

            Txid hashTx = wtx.GetHash();
            for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
                const CTxOut& txout = wtx.tx->vout[i];
                const COutPoint outpoint(hashTx, i);

                // Skip spent outputs
                if (wallet.IsSpent(outpoint)) continue;

                isminetype mine = wallet.IsMine(txout);
                if (!(mine & (ISMINE_SPENDABLE | ISMINE_WATCH_ONLY))) continue;

                if (IsModelReservedOutput(outpoint, *wtx.tx, current_height)) {
                    if (mine & ISMINE_SPENDABLE) {
                        ret.m_mine_bonded += txout.nValue;
                    } else if (mine & ISMINE_WATCH_ONLY) {
                        ret.m_watchonly_bonded += txout.nValue;
                    }
                    continue;
                }

                // Check if this output is an ICU (Issuer Credential UTXO)
                std::optional<AssetMetadata> asset_meta = wallet.GetAssetMetadata(outpoint);
                if (asset_meta && asset_meta->is_issuer_credential) {
                    if (mine & ISMINE_SPENDABLE) {
                        ret.m_mine_bonded += txout.nValue;
                    } else if (mine & ISMINE_WATCH_ONLY) {
                        ret.m_watchonly_bonded += txout.nValue;
                    }
                    continue; // ICU already counted, skip vault check
                }

                // Check if this output is a contract vault (repo collateral or forward IM)
                VaultMetadata vault_meta;
                if (wallet.GetCovenantVaultMetadata(txout.scriptPubKey, vault_meta)) {
                    bool include_in_bonded = false;

                    switch (vault_meta.role) {
                        case VaultRole::REPO_BORROWER:
                            // Include if this wallet is the borrower for this repo
                            include_in_bonded = borrower_repo_contracts.count(vault_meta.contract_id) > 0;
                            break;

                        case VaultRole::FORWARD_LONG: {
                            // Include if this wallet is LONG on this forward contract
                            auto it = forward_side_by_contract.find(vault_meta.contract_id);
                            include_in_bonded = (it != forward_side_by_contract.end() &&
                                                 it->second == ForwardSide::LONG);
                            break;
                        }

                        case VaultRole::FORWARD_SHORT: {
                            // Include if this wallet is SHORT on this forward contract
                            auto it = forward_side_by_contract.find(vault_meta.contract_id);
                            include_in_bonded = (it != forward_side_by_contract.end() &&
                                                 it->second == ForwardSide::SHORT);
                            break;
                        }

                        // Don't include lender vaults or escrow vaults in bonded
                        case VaultRole::REPO_LENDER:
                        case VaultRole::FORWARD_ESCROW_A:
                        case VaultRole::FORWARD_ESCROW_B:
                            include_in_bonded = false;
                            break;
                    }

                    if (include_in_bonded) {
                        if (mine & ISMINE_SPENDABLE) {
                            ret.m_mine_bonded += txout.nValue;
                        } else if (mine & ISMINE_WATCH_ONLY) {
                            ret.m_watchonly_bonded += txout.nValue;
                        }
                    }
                }
            }
        }
    }
    return ret;
}

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet)
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(wallet.cs_wallet);
        std::set<Txid> trusted_parents;
        for (const auto& walletEntry : wallet.mapWallet)
        {
            const CWalletTx& wtx = walletEntry.second;

            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents))
                continue;

            if (wallet.IsTxImmatureCoinBase(wtx))
                continue;

            int nDepth = wallet.GetTxDepthInMainChain(wtx);
            if (nDepth < (CachedTxIsFromMe(wallet, wtx, ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
                const auto& output = wtx.tx->vout[i];
                CTxDestination addr;
                if (!wallet.IsMine(output))
                    continue;
                if(!ExtractDestination(output.scriptPubKey, addr))
                    continue;

                CAmount n = wallet.IsSpent(COutPoint(walletEntry.first, i)) ? 0 : output.nValue;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > GetAddressGroupings(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : wallet.mapWallet)
    {
        const CWalletTx& wtx = walletEntry.second;

        if (wtx.tx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (const CTxIn& txin : wtx.tx->vin)
            {
                CTxDestination address;
                if(!InputIsMine(wallet, txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(wallet.mapWallet.at(txin.prevout.hash).tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               for (const CTxOut& txout : wtx.tx->vout)
                   if (OutputIsChange(wallet, txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : wtx.tx->vout)
            if (wallet.IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (const std::set<CTxDestination>& _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}
} // namespace wallet
