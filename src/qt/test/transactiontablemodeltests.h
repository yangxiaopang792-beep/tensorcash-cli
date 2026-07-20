// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_TRANSACTIONTABLEMODELTESTS_H
#define BITCOIN_QT_TEST_TRANSACTIONTABLEMODELTESTS_H

#include <QObject>
#include <QTest>

class TransactionTableModelTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testAssetTickerRoleWithTicker();
    void testAssetTickerRoleWithoutTicker();
    void testAssetAmountRole();
    void testFormatTxAssetWithDecimals();
    void testFormatTxAssetWithoutDecimals();
    void testAssetTransactionSigning();
    void testMixedBtcAndAssetTransactions();
};

#endif // BITCOIN_QT_TEST_TRANSACTIONTABLEMODELTESTS_H