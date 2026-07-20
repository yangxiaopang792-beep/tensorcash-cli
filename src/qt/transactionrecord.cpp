// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionrecord.h>

#include <chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <wallet/types.h>
#include <assets/asset.h> // For ParseAssetTag
#include <primitives/transaction.h> // For CTxOut

#include <stdint.h>
#include <optional>

#include <QDateTime>

using wallet::ISMINE_NO;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction()
{
    // There are currently no cases where we hide transactions, but
    // we may want to use this in the future for things like RBF.
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const interfaces::WalletTx& wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nNet = nCredit - nDebit;
    Txid hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

    bool involvesWatchAddress = false;
    isminetype fAllFromMe = ISMINE_SPENDABLE;
    bool any_from_me = false;
    if (wtx.is_coinbase) {
        fAllFromMe = ISMINE_NO;
    } else {
        for (const isminetype mine : wtx.txin_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllFromMe > mine) fAllFromMe = mine;
            if (mine) any_from_me = true;
        }
    }

    if (fAllFromMe || !any_from_me) {
        for (const isminetype mine : wtx.txout_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        }

        CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

        for(unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];

            if (fAllFromMe) {
                // Change is only really possible if we're the sender
                // Otherwise, someone just sent bitcoins to a change address, which should be shown
                if (wtx.txout_is_change[i]) {
                    continue;
                }

                //
                // Debit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i;
                sub.involvesWatchAddress = involvesWatchAddress;

                // Check for asset tag in this output
                auto asset_tag = assets::ParseAssetTag(txout.vExt);
                if (asset_tag) {
                    sub.is_asset_transfer = true;
                    sub.asset_id = asset_tag->id;
                    sub.asset_units = asset_tag->amount;

                    const std::string truncated = asset_tag->id.ToString().substr(0, 8);
                    sub.asset_ticker = QString::fromStdString(truncated) + "...";
                    sub.asset_has_ticker = false;
                    sub.asset_decimals = 8;
                    sub.asset_is_registered = false;

                    if (i < wtx.asset_details.size()) {
                        const auto& detail = wtx.asset_details[i];
                        if (detail.has_asset) {
                            if (detail.has_ticker && !detail.ticker.empty()) {
                                sub.asset_ticker = QString::fromStdString(detail.ticker);
                                sub.asset_has_ticker = true;
                            }
                            if (detail.has_decimals) {
                                sub.asset_decimals = detail.decimals;
                            }
                            sub.asset_is_registered = detail.is_registered;
                        }
                    }
                }

                if (!std::get_if<CNoDestination>(&wtx.txout_address[i]))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }

            isminetype mine = wtx.txout_is_mine[i];
            if(mine)
            {
                //
                // Credit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i; // vout index
                sub.credit = txout.nValue;
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;

                // Check for asset tag in this output
                auto asset_tag = assets::ParseAssetTag(txout.vExt);
                if (asset_tag) {
                    sub.is_asset_transfer = true;
                    sub.asset_id = asset_tag->id;
                    sub.asset_units = asset_tag->amount;

                    const std::string truncated = asset_tag->id.ToString().substr(0, 8);
                    sub.asset_ticker = QString::fromStdString(truncated) + "...";
                    sub.asset_has_ticker = false;
                    sub.asset_decimals = 8;
                    sub.asset_is_registered = false;

                    if (i < wtx.asset_details.size()) {
                        const auto& detail = wtx.asset_details[i];
                        if (detail.has_asset) {
                            if (detail.has_ticker && !detail.ticker.empty()) {
                                sub.asset_ticker = QString::fromStdString(detail.ticker);
                                sub.asset_has_ticker = true;
                            }
                            if (detail.has_decimals) {
                                sub.asset_decimals = detail.decimals;
                            }
                            sub.asset_is_registered = detail.is_registered;
                        }
                    }
                }

                if (wtx.txout_address_is_mine[i])
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.is_coinbase)
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    } else {
        //
        // Mixed debit transaction, can't break down payees
        //
        parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        parts.last().involvesWatchAddress = involvesWatchAddress;
    }

    // Check if transaction involves ML-DSA inputs/outputs
    bool has_mldsa_input = false;
    bool has_mldsa_output = false;

    // Check for ML-DSA inputs (witness v2 with large signatures)
    for (const auto& txin : wtx.tx->vin) {
        if (!txin.scriptWitness.IsNull() && txin.scriptWitness.stack.size() >= 3) {
            size_t sig_size = txin.scriptWitness.stack[0].size();
            // ML-DSA signatures are 2420-4627 bytes
            if (sig_size >= 2400 && sig_size <= 5000) {
                has_mldsa_input = true;
                break;
            }
        }
    }

    // Check for ML-DSA outputs (witness v2 taproot)
    for (const auto& txout : wtx.tx->vout) {
        CTxDestination dest;
        if (ExtractDestination(txout.scriptPubKey, dest)) {
            if (std::holds_alternative<WitnessV2Taproot>(dest)) {
                has_mldsa_output = true;
                break;
            }
        }
    }

    // Add ML-DSA indicators to all transaction records
    for (auto& part : parts) {
        part.mldsa_input = has_mldsa_input;
        part.mldsa_output = has_mldsa_output;
    }

    return parts;
}

void TransactionRecord::updateStatus(const interfaces::WalletTxStatus& wtx, const uint256& block_hash, int numBlocks, int64_t block_time)
{
    // Determine transaction status

    // Sort order, unrecorded transactions sort to the top
    int typesort;
    switch (type) {
    case SendToAddress: case SendToOther:
        typesort = 2; break;
    case RecvWithAddress: case RecvFromOther:
        typesort = 3; break;
    default:
        typesort = 9;
    }
    status.sortKey = strprintf("%010d-%01d-%010u-%03d-%d",
        wtx.block_height,
        wtx.is_coinbase ? 1 : 0,
        wtx.time_received,
        idx,
        typesort);
    status.countsForBalance = wtx.is_trusted && !(wtx.blocks_to_maturity > 0);
    status.depth = wtx.depth_in_main_chain;
    status.m_cur_block_hash = block_hash;

    // For generated transactions, determine maturity
    if (type == TransactionRecord::Generated) {
        if (wtx.blocks_to_maturity > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.is_in_main_chain)
            {
                status.matures_in = wtx.blocks_to_maturity;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.is_abandoned)
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    status.needsUpdate = false;
}

bool TransactionRecord::statusUpdateNeeded(const uint256& block_hash) const
{
    assert(!block_hash.IsNull());
    return status.m_cur_block_hash != block_hash || status.needsUpdate;
}

QString TransactionRecord::getTxHash() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
