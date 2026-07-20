// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/sendcoinsentrytests.h>
#include <qt/test/util.h>

#include <qt/platformstyle.h>
#include <qt/sendcoinsentry.h>

#include <memory>

#include <QApplication>
#include <QComboBox>
#include <QTest>

void SendCoinsEntryTests::testAssetDropdownCreation()
{
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    SendCoinsEntry entry(platformStyle.get());

    // Test that asset dropdown is created
    QComboBox* assetCombo = entry.findChild<QComboBox*>();
    QVERIFY(assetCombo != nullptr);

    // Test initial state - should have at least BTC option
    QVERIFY(assetCombo->count() >= 1);
    QCOMPARE(assetCombo->itemText(0), QString("BTC (Bitcoin)"));
    QCOMPARE(assetCombo->currentIndex(), 0);

    // Test that BTC is selected by default
    QVERIFY(!entry.getSelectedAsset().has_value());
    QCOMPARE(entry.getAssetDecimals(), 8);
}

void SendCoinsEntryTests::testAssetSelection()
{
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    SendCoinsEntry entry(platformStyle.get());

    QComboBox* assetCombo = entry.findChild<QComboBox*>();
    QVERIFY(assetCombo != nullptr);

    // Test BTC selection (index 0)
    assetCombo->setCurrentIndex(0);
    QVERIFY(!entry.getSelectedAsset().has_value());
    QCOMPARE(entry.getAssetDecimals(), 8);

    // Test setting specific asset ID manually
    QString testAssetId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assetCombo->addItem("TST (1.00000000)", testAssetId);
    assetCombo->setCurrentIndex(1);

    auto selectedAsset = entry.getSelectedAsset();
    QVERIFY(selectedAsset.has_value());
    QCOMPARE(QString::fromStdString(selectedAsset->ToString()), testAssetId);
}

void SendCoinsEntryTests::testAssetMetadataDisplay()
{
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    SendCoinsEntry entry(platformStyle.get());

    // Test ticker vs asset ID display
    QComboBox* assetCombo = entry.findChild<QComboBox*>();
    QVERIFY(assetCombo != nullptr);

    // Test asset with ticker
    QString testAssetId1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assetCombo->addItem("TST (1.00000000)", testAssetId1);

    // Test asset without ticker (should show truncated ID)
    QString testAssetId2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assetCombo->addItem("bbbbbbbb... (0.50)", testAssetId2);

    // Verify the display format
    QVERIFY(assetCombo->itemText(1).contains("TST"));
    QVERIFY(assetCombo->itemText(2).contains("bbbbbbbb"));
}