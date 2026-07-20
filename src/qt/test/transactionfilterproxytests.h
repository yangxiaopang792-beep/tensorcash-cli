// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_TRANSACTIONFILTERPROXYTESTS_H
#define BITCOIN_QT_TEST_TRANSACTIONFILTERPROXYTESTS_H

#include <QObject>
#include <QTest>

class TransactionFilterProxyTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testAssetFilterSingleAsset();
    void testAssetFilterWithTruncatedIds();
    void testAssetFilterWithBtcTransactions();
    void testAssetFilterCombinedWithOtherFilters();
    void testAssetFilterCaseSensitivity();
    void testAssetFilterRealTimeUpdates();
    void testAssetFilterEmptyAndInvalidStates();
};

#endif // BITCOIN_QT_TEST_TRANSACTIONFILTERPROXYTESTS_H