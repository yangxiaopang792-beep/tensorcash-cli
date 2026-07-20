// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/transactionfilterproxytests.h>
#include <qt/test/util.h>

#include <qt/transactionfilterproxy.h>
#include <qt/transactionrecord.h>
#include <qt/transactiontablemodel.h>

#include <QApplication>
#include <QStandardItemModel>
#include <QTest>

void TransactionFilterProxyTests::testAssetFilterSingleAsset()
{
    // Test that asset filter correctly filters by asset ticker
    TransactionFilterProxy proxy;

    // Create a mock source model with test data
    QStandardItemModel sourceModel(3, TransactionTableModel::Amount + 1);

    // Add transactions with different assets
    // Row 0: BTC transaction
    auto item0 = sourceModel.item(0, 0);
    if (!item0) {
        item0 = new QStandardItem();
        sourceModel.setItem(0, 0, item0);
    }
    item0->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item0->setData("", TransactionTableModel::AssetTickerRole);

    // Row 1: TST asset transaction
    auto item1 = sourceModel.item(1, 0);
    if (!item1) {
        item1 = new QStandardItem();
        sourceModel.setItem(1, 0, item1);
    }
    item1->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item1->setData("TST", TransactionTableModel::AssetTickerRole);

    // Row 2: Another TST transaction
    auto item2 = sourceModel.item(2, 0);
    if (!item2) {
        item2 = new QStandardItem();
        sourceModel.setItem(2, 0, item2);
    }
    item2->setData(TransactionRecord::SendToAddress, TransactionTableModel::TypeRole);
    item2->setData("TST", TransactionTableModel::AssetTickerRole);

    proxy.setSourceModel(&sourceModel);

    // Test: No filter - should show all transactions
    proxy.setAssetFilter("");
    QCOMPARE(proxy.rowCount(), 3);

    // Test: Filter by TST - should show only TST transactions
    proxy.setAssetFilter("TST");
    QCOMPARE(proxy.rowCount(), 2);

    // Test: Clear filter - should show all again
    proxy.setAssetFilter("");
    QCOMPARE(proxy.rowCount(), 3);
}

void TransactionFilterProxyTests::testAssetFilterWithTruncatedIds()
{
    // Test filter by truncated asset ID
    TransactionFilterProxy proxy;

    QStandardItemModel sourceModel(2, TransactionTableModel::Amount + 1);

    // Row 0: Asset with truncated ID display
    auto item0 = sourceModel.item(0, 0);
    if (!item0) {
        item0 = new QStandardItem();
        sourceModel.setItem(0, 0, item0);
    }
    item0->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item0->setData("cccccccc...", TransactionTableModel::AssetTickerRole);

    // Row 1: Different asset
    auto item1 = sourceModel.item(1, 0);
    if (!item1) {
        item1 = new QStandardItem();
        sourceModel.setItem(1, 0, item1);
    }
    item1->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item1->setData("TST", TransactionTableModel::AssetTickerRole);

    proxy.setSourceModel(&sourceModel);

    // Set filter to truncated ID format
    proxy.setAssetFilter("cccccccc...");
    QCOMPARE(proxy.rowCount(), 1);
}

void TransactionFilterProxyTests::testAssetFilterWithBtcTransactions()
{
    // Test that BTC transactions are filtered correctly
    TransactionFilterProxy proxy;

    QStandardItemModel sourceModel(3, TransactionTableModel::Amount + 1);

    // Row 0: BTC transaction
    auto item0 = sourceModel.item(0, 0);
    if (!item0) {
        item0 = new QStandardItem();
        sourceModel.setItem(0, 0, item0);
    }
    item0->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item0->setData("", TransactionTableModel::AssetTickerRole);

    // Row 1: Asset transaction
    auto item1 = sourceModel.item(1, 0);
    if (!item1) {
        item1 = new QStandardItem();
        sourceModel.setItem(1, 0, item1);
    }
    item1->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item1->setData("TST", TransactionTableModel::AssetTickerRole);

    // Row 2: Another BTC transaction
    auto item2 = sourceModel.item(2, 0);
    if (!item2) {
        item2 = new QStandardItem();
        sourceModel.setItem(2, 0, item2);
    }
    item2->setData(TransactionRecord::SendToAddress, TransactionTableModel::TypeRole);
    item2->setData("", TransactionTableModel::AssetTickerRole);

    proxy.setSourceModel(&sourceModel);

    // Set any asset filter - should filter out BTC transactions
    proxy.setAssetFilter("TST");
    QCOMPARE(proxy.rowCount(), 1);

    // Clear filter - should show all including BTC
    proxy.setAssetFilter("");
    QCOMPARE(proxy.rowCount(), 3);
}

void TransactionFilterProxyTests::testAssetFilterCombinedWithOtherFilters()
{
    // Test asset filter combined with amount filter
    TransactionFilterProxy proxy;

    QStandardItemModel sourceModel(4, TransactionTableModel::Amount + 1);

    // Setup test data with different assets and amounts
    for (int i = 0; i < 4; ++i) {
        auto item = sourceModel.item(i, 0);
        if (!item) {
            item = new QStandardItem();
            sourceModel.setItem(i, 0, item);
        }
        item->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    }

    // Row 0: TST with small amount
    auto item0 = sourceModel.item(0, 0);
    item0->setData("TST", TransactionTableModel::AssetTickerRole);
    item0->setData(5000000, TransactionTableModel::AmountRole);

    // Row 1: TST with large amount
    auto item1 = sourceModel.item(1, 0);
    item1->setData("TST", TransactionTableModel::AssetTickerRole);
    item1->setData(20000000, TransactionTableModel::AmountRole);

    // Row 2: USD with large amount
    auto item2 = sourceModel.item(2, 0);
    item2->setData("USD", TransactionTableModel::AssetTickerRole);
    item2->setData(15000000, TransactionTableModel::AmountRole);

    // Row 3: BTC with medium amount
    auto item3 = sourceModel.item(3, 0);
    item3->setData("", TransactionTableModel::AssetTickerRole);
    item3->setData(10000000, TransactionTableModel::AmountRole);

    proxy.setSourceModel(&sourceModel);

    // Test: Filter by TST only
    proxy.setAssetFilter("TST");
    QCOMPARE(proxy.rowCount(), 2);

    // Test: Add minimum amount filter (0.1 units = 10000000 satoshis)
    proxy.setMinAmount(10000000);
    // Should only show the TST transaction with amount >= 10000000
    QCOMPARE(proxy.rowCount(), 1);

    // Test: Clear asset filter but keep amount filter
    proxy.setAssetFilter("");
    // Should show all transactions with amount >= 10000000
    QCOMPARE(proxy.rowCount(), 3);

    // Test: Add type filter
    proxy.setTypeFilter(TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress));
    // All our test transactions are RecvWithAddress, so count shouldn't change
    QCOMPARE(proxy.rowCount(), 3);
}

void TransactionFilterProxyTests::testAssetFilterCaseSensitivity()
{
    // Test case sensitivity of asset filter
    TransactionFilterProxy proxy;

    QStandardItemModel sourceModel(3, TransactionTableModel::Amount + 1);

    // Add transactions with different case tickers
    auto item0 = sourceModel.item(0, 0);
    if (!item0) {
        item0 = new QStandardItem();
        sourceModel.setItem(0, 0, item0);
    }
    item0->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item0->setData("TST", TransactionTableModel::AssetTickerRole);

    auto item1 = sourceModel.item(1, 0);
    if (!item1) {
        item1 = new QStandardItem();
        sourceModel.setItem(1, 0, item1);
    }
    item1->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item1->setData("tst", TransactionTableModel::AssetTickerRole);

    auto item2 = sourceModel.item(2, 0);
    if (!item2) {
        item2 = new QStandardItem();
        sourceModel.setItem(2, 0, item2);
    }
    item2->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item2->setData("Tst", TransactionTableModel::AssetTickerRole);

    proxy.setSourceModel(&sourceModel);

    // Test exact match (case sensitive)
    proxy.setAssetFilter("TST");
    QCOMPARE(proxy.rowCount(), 1);

    // Different case
    proxy.setAssetFilter("tst");
    QCOMPARE(proxy.rowCount(), 1);

    // Mixed case
    proxy.setAssetFilter("Tst");
    QCOMPARE(proxy.rowCount(), 1);
}

void TransactionFilterProxyTests::testAssetFilterRealTimeUpdates()
{
    // Test that filter can be updated dynamically
    TransactionFilterProxy proxy;

    QStandardItemModel sourceModel(3, TransactionTableModel::Amount + 1);

    // Add test transactions
    auto item0 = sourceModel.item(0, 0);
    if (!item0) {
        item0 = new QStandardItem();
        sourceModel.setItem(0, 0, item0);
    }
    item0->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item0->setData("TST", TransactionTableModel::AssetTickerRole);

    auto item1 = sourceModel.item(1, 0);
    if (!item1) {
        item1 = new QStandardItem();
        sourceModel.setItem(1, 0, item1);
    }
    item1->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item1->setData("USD", TransactionTableModel::AssetTickerRole);

    auto item2 = sourceModel.item(2, 0);
    if (!item2) {
        item2 = new QStandardItem();
        sourceModel.setItem(2, 0, item2);
    }
    item2->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item2->setData("NEW", TransactionTableModel::AssetTickerRole);

    proxy.setSourceModel(&sourceModel);

    // Initial filter
    proxy.setAssetFilter("TST");
    QCOMPARE(proxy.rowCount(), 1);

    // Update filter
    proxy.setAssetFilter("USD");
    QCOMPARE(proxy.rowCount(), 1);

    // Clear filter
    proxy.setAssetFilter("");
    QCOMPARE(proxy.rowCount(), 3);

    // Set again
    proxy.setAssetFilter("NEW");
    QCOMPARE(proxy.rowCount(), 1);
}

void TransactionFilterProxyTests::testAssetFilterEmptyAndInvalidStates()
{
    // Test empty and special character filters
    TransactionFilterProxy proxy;

    QStandardItemModel sourceModel(3, TransactionTableModel::Amount + 1);

    // Add test transactions
    auto item0 = sourceModel.item(0, 0);
    if (!item0) {
        item0 = new QStandardItem();
        sourceModel.setItem(0, 0, item0);
    }
    item0->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item0->setData("TST", TransactionTableModel::AssetTickerRole);

    auto item1 = sourceModel.item(1, 0);
    if (!item1) {
        item1 = new QStandardItem();
        sourceModel.setItem(1, 0, item1);
    }
    item1->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item1->setData("*", TransactionTableModel::AssetTickerRole);

    auto item2 = sourceModel.item(2, 0);
    if (!item2) {
        item2 = new QStandardItem();
        sourceModel.setItem(2, 0, item2);
    }
    item2->setData(TransactionRecord::RecvWithAddress, TransactionTableModel::TypeRole);
    item2->setData("?", TransactionTableModel::AssetTickerRole);

    proxy.setSourceModel(&sourceModel);

    // Test empty filter (default state) - should show all
    proxy.setAssetFilter("");
    QCOMPARE(proxy.rowCount(), 3);

    // Test whitespace
    proxy.setAssetFilter("   ");
    // Whitespace should match nothing
    QCOMPARE(proxy.rowCount(), 0);

    // Test special characters
    proxy.setAssetFilter("*");
    QCOMPARE(proxy.rowCount(), 1);

    proxy.setAssetFilter("?");
    QCOMPARE(proxy.rowCount(), 1);

    // Test very long filter string
    QString longFilter(100, 'A');
    proxy.setAssetFilter(longFilter);
    // Should match nothing
    QCOMPARE(proxy.rowCount(), 0);

    // Reset to empty
    proxy.setAssetFilter("");
    QCOMPARE(proxy.rowCount(), 3);
}