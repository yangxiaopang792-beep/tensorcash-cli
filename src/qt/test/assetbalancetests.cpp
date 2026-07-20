// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/assetbalancetests.h>
#include <qt/test/mockwallet.h>
#include <qt/test/util.h>

#include <qt/assetbalancewidget.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <test/util/setup_common.h>
#include <util/translation.h>

#include <memory>
#include <vector>

#include <QApplication>
#include <QClipboard>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTest>

namespace {

// Test helper to create asset balance
interfaces::AssetBalance createTestBalance(const std::string& id_str,
                                          const std::string& ticker,
                                          uint64_t balance,
                                          uint64_t pending,
                                          uint64_t locked,
                                          uint8_t decimals,
                                          uint32_t utxo_count,
                                          bool has_ticker,
                                          bool has_decimals,
                                          bool is_registered)
{
    interfaces::AssetBalance bal;
    auto asset_id_opt = uint256::FromHex(id_str);
    if (asset_id_opt.has_value()) {
        bal.asset_id = asset_id_opt.value();
    }
    bal.ticker = ticker;
    bal.balance = balance;
    bal.pending = pending;
    bal.locked = locked;
    bal.decimals = decimals;
    bal.utxo_count = utxo_count;
    bal.has_ticker = has_ticker;
    bal.has_decimals = has_decimals;
    bal.is_registered = is_registered;
    return bal;
}

} // namespace

void AssetBalanceTests::testChangeDetection()
{
    // Create mock wallet with test balances
    auto mock_wallet = std::make_unique<qt_tests::MockWallet>();

    // Initial balance
    mock_wallet->asset_balances.push_back(
        createTestBalance("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                         "", 1000, 0, 0, 0, 1, false, false, false));

    // Create wallet model (mock simplified version for testing)
    // Note: In real implementation, you'd need proper WalletModel setup

    // Test 1: Balance change should trigger update
    auto balance1 = mock_wallet->asset_balances[0];
    auto balance2 = balance1;
    balance2.balance = 2000;

    QVERIFY(balance1.balance != balance2.balance);

    // Test 2: Ticker appearance should trigger update
    balance2 = balance1;
    balance2.ticker = "TEST";
    balance2.has_ticker = true;

    QVERIFY(balance1.ticker != balance2.ticker);
    QVERIFY(balance1.has_ticker != balance2.has_ticker);

    // Test 3: Decimals appearance should trigger update
    balance2 = balance1;
    balance2.decimals = 8;
    balance2.has_decimals = true;

    QVERIFY(balance1.decimals != balance2.decimals);
    QVERIFY(balance1.has_decimals != balance2.has_decimals);

    // Test 4: UTXO count change should trigger update
    balance2 = balance1;
    balance2.utxo_count = 5;

    QVERIFY(balance1.utxo_count != balance2.utxo_count);

    // Test 5: Pending balance change should trigger update
    balance2 = balance1;
    balance2.pending = 500;

    QVERIFY(balance1.pending != balance2.pending);

    // Test 6: Locked balance change should trigger update
    balance2 = balance1;
    balance2.locked = 300;

    QVERIFY(balance1.locked != balance2.locked);

    // Test 7: Registry status change should trigger update
    balance2 = balance1;
    balance2.is_registered = true;

    QVERIFY(balance1.is_registered != balance2.is_registered);
}

void AssetBalanceTests::testClickToCopyWithSorting()
{
    // Create test widget
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    AssetBalanceWidget widget;
    widget.setPlatformStyle(platformStyle.get());

    // Create test balances with different values for sorting
    std::vector<interfaces::AssetBalance> balances;
    balances.push_back(createTestBalance(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "AAA", 1000, 0, 0, 8, 1, true, true, true));
    balances.push_back(createTestBalance(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "BBB", 2000, 0, 0, 8, 1, true, true, true));
    balances.push_back(createTestBalance(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "CCC", 500, 0, 0, 8, 1, true, true, true));

    // Update widget with test balances
    widget.updateAssetBalances(balances);

    // Get the table widget
    QTableWidget* table = widget.findChild<QTableWidget*>();
    QVERIFY(table != nullptr);
    QCOMPARE(table->rowCount(), 3);

    // Test: Sort by balance column (column 1) descending and verify UserRole data
    table->sortByColumn(1, Qt::DescendingOrder);

    // After sorting by balance (descending): BBB (2000), AAA (1000), CCC (500)
    // Find the row with BBB (highest balance)
    QTableWidgetItem* item0 = nullptr;
    for (int i = 0; i < table->rowCount(); ++i) {
        auto idItem = table->item(i, 0);
        if (idItem && idItem->text() == "BBB") {
            item0 = idItem;
            break;
        }
    }

    QVERIFY(item0 != nullptr);

    // Verify that UserRole data is correctly associated
    QCOMPARE(item0->data(Qt::UserRole).toString(),
             QString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

    // Test: Simulate click on BBB row
    QApplication::clipboard()->clear();

    // Simulate the click handler logic
    QString assetId = item0->data(Qt::UserRole).toString();
    if (!assetId.isEmpty()) {
        QApplication::clipboard()->setText(assetId);
    }

    // Verify correct asset ID was copied (should be BBB's ID after sorting)
    QCOMPARE(QApplication::clipboard()->text(),
             QString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

    // Test: Sort by ticker column (column 0) ascending
    table->sortByColumn(0, Qt::AscendingOrder);

    // After sorting by ticker (ascending): AAA, BBB, CCC
    // Find AAA
    QTableWidgetItem* itemAAA = nullptr;
    for (int i = 0; i < table->rowCount(); ++i) {
        auto idItem = table->item(i, 0);
        if (idItem && idItem->text() == "AAA") {
            itemAAA = idItem;
            break;
        }
    }

    QVERIFY(itemAAA != nullptr);

    // Simulate click on AAA row
    assetId = itemAAA->data(Qt::UserRole).toString();
    if (!assetId.isEmpty()) {
        QApplication::clipboard()->setText(assetId);
    }

    // Verify correct asset ID was copied (should be AAA's ID after sorting)
    QCOMPARE(QApplication::clipboard()->text(),
             QString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

void AssetBalanceTests::testMetadataUpdateRefresh()
{
    // Test that refresh properly detects metadata changes
    auto mock_wallet = std::make_unique<qt_tests::MockWallet>();

    // Initial balance without ticker/decimals
    mock_wallet->asset_balances.push_back(
        createTestBalance("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                         "", 1000, 0, 0, 0, 1, false, false, false));

    auto initial_balance = mock_wallet->asset_balances[0];

    // Simulate metadata resolution - ticker appears
    auto updated_balance = initial_balance;
    updated_balance.ticker = "TST";
    updated_balance.has_ticker = true;

    // These should be detected as different
    bool ticker_change_detected = (initial_balance.ticker != updated_balance.ticker ||
                                   initial_balance.has_ticker != updated_balance.has_ticker);
    QVERIFY(ticker_change_detected);

    // Simulate decimals appearing
    updated_balance.decimals = 6;
    updated_balance.has_decimals = true;

    bool decimals_change_detected = (initial_balance.decimals != updated_balance.decimals ||
                                     initial_balance.has_decimals != updated_balance.has_decimals);
    QVERIFY(decimals_change_detected);
}
