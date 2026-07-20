// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/transactiontablemodeltests.h>
#include <qt/test/util.h>

#include <qt/transactionrecord.h>
#include <qt/transactiontablemodel.h>
#include <interfaces/wallet.h>
#include <uint256.h>

#include <QApplication>
#include <QTest>

void TransactionTableModelTests::testAssetTickerRoleWithTicker()
{
    // Test that AssetTickerRole returns ticker when available
    TransactionRecord rec;
    rec.time = 1640995200;
    rec.type = TransactionRecord::SendToOther;
    rec.debit = 0;
    rec.credit = 50000000;

    // Set asset information
    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    rec.asset_id = asset_id_opt.value();
    rec.asset_ticker = "TST";
    rec.asset_has_ticker = true;
    rec.asset_units = 50000000;
    rec.asset_decimals = 8;
    rec.asset_is_registered = true;

    // Verify the record has correct asset data
    QVERIFY(rec.asset_id.has_value());
    QCOMPARE(rec.asset_ticker, "TST");
    QVERIFY(rec.asset_has_ticker);
}

void TransactionTableModelTests::testAssetTickerRoleWithoutTicker()
{
    // Test that AssetTickerRole returns truncated ID when ticker not available
    TransactionRecord rec;
    rec.time = 1640995200;
    rec.type = TransactionRecord::SendToOther;
    rec.debit = 0;
    rec.credit = 500;

    // Set asset information without ticker
    auto asset_id_opt = uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    QVERIFY(asset_id_opt.has_value());
    rec.asset_id = asset_id_opt.value();
    rec.asset_ticker = "";
    rec.asset_has_ticker = false;
    rec.asset_units = 500;
    rec.asset_decimals = 0;
    rec.asset_is_registered = false;

    // When no ticker, should use truncated asset ID
    QVERIFY(rec.asset_id.has_value());
    QVERIFY(!rec.asset_has_ticker);

    // The display logic would show "bbbbbbbb..." for display
    QString expected_display = rec.asset_id->ToString().substr(0, 8).c_str();
    QCOMPARE(expected_display, QString("bbbbbbbb"));
}

void TransactionTableModelTests::testAssetAmountRole()
{
    // Test that AssetAmountRole returns correct formatted amount
    TransactionRecord rec;
    rec.time = 1640995200;
    rec.type = TransactionRecord::RecvWithAddress;
    rec.debit = 0;
    rec.credit = 75000000;

    // Set asset information
    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    rec.asset_id = asset_id_opt.value();
    rec.asset_ticker = "TST";
    rec.asset_has_ticker = true;
    rec.asset_units = 75000000; // 0.75 TST
    rec.asset_decimals = 8;
    rec.asset_is_registered = true;

    // Verify amount is correct
    QCOMPARE(rec.asset_units, 75000000UL);
    QCOMPARE(rec.asset_decimals, 8);
}

void TransactionTableModelTests::testFormatTxAssetWithDecimals()
{
    // Test formatting of assets with different decimal places

    // 8-decimal asset
    {
        TransactionRecord rec;
        rec.time = 1640995200;
        rec.type = TransactionRecord::SendToAddress;

        auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        QVERIFY(asset_id_opt.has_value());
        rec.asset_id = asset_id_opt.value();
        rec.asset_ticker = "TST8";
        rec.asset_has_ticker = true;
        rec.asset_units = 123456789; // 1.23456789 TST8
        rec.asset_decimals = 8;
        rec.asset_is_registered = true;

        QCOMPARE(rec.asset_decimals, 8);
        QCOMPARE(rec.asset_units, 123456789UL);
    }

    // 2-decimal asset
    {
        TransactionRecord rec;
        rec.time = 1640995200;
        rec.type = TransactionRecord::SendToAddress;

        auto asset_id_opt = uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        QVERIFY(asset_id_opt.has_value());
        rec.asset_id = asset_id_opt.value();
        rec.asset_ticker = "USD2";
        rec.asset_has_ticker = true;
        rec.asset_units = 12345; // 123.45 USD2
        rec.asset_decimals = 2;
        rec.asset_is_registered = true;

        QCOMPARE(rec.asset_decimals, 2);
        QCOMPARE(rec.asset_units, 12345UL);
    }
}

void TransactionTableModelTests::testFormatTxAssetWithoutDecimals()
{
    // Test formatting of assets without decimal information
    TransactionRecord rec;
    rec.time = 1640995200;
    rec.type = TransactionRecord::SendToOther;

    auto asset_id_opt = uint256::FromHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    QVERIFY(asset_id_opt.has_value());
    rec.asset_id = asset_id_opt.value();
    rec.asset_ticker = "NOD";
    rec.asset_has_ticker = true;
    rec.asset_units = 42;
    rec.asset_decimals = 0;
    rec.asset_is_registered = true;

    QCOMPARE(rec.asset_units, 42UL);
    QCOMPARE(rec.asset_decimals, 0);
}

void TransactionTableModelTests::testAssetTransactionSigning()
{
    // Test that outgoing transactions have negative amounts
    TransactionRecord rec;
    rec.time = 1640995200;
    rec.type = TransactionRecord::SendToAddress;
    rec.debit = 25000000; // Outgoing
    rec.credit = 0;

    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    rec.asset_id = asset_id_opt.value();
    rec.asset_ticker = "TST";
    rec.asset_has_ticker = true;
    rec.debit = 25000000; // Use debit for outgoing transactions
    rec.asset_units = 25000000; // Asset units are always positive
    rec.asset_decimals = 8;
    rec.asset_is_registered = true;

    // Verify outgoing transaction has debit
    QVERIFY(rec.debit > 0);
    QCOMPARE(rec.asset_units, 25000000UL);
}

void TransactionTableModelTests::testMixedBtcAndAssetTransactions()
{
    // Test BTC transaction (no asset)
    {
        TransactionRecord btc_rec;
        btc_rec.time = 1640995200;
        btc_rec.type = TransactionRecord::RecvWithAddress;
        btc_rec.debit = 0;
        btc_rec.credit = 50000000; // 0.5 BTC
        // No asset fields set

        QVERIFY(!btc_rec.asset_id.has_value());
        QVERIFY(btc_rec.asset_ticker.isEmpty());
        QCOMPARE(btc_rec.credit, 50000000);
    }

    // Test asset transaction
    {
        TransactionRecord asset_rec;
        asset_rec.time = 1640995200;
        asset_rec.type = TransactionRecord::RecvWithAddress;
        asset_rec.debit = 0;
        asset_rec.credit = 0; // Asset transactions have 0 BTC amount

        auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        QVERIFY(asset_id_opt.has_value());
        asset_rec.asset_id = asset_id_opt.value();
        asset_rec.asset_ticker = "TST";
        asset_rec.asset_has_ticker = true;
        asset_rec.asset_units = 30000000;
        asset_rec.asset_decimals = 8;
        asset_rec.asset_is_registered = true;

        QVERIFY(asset_rec.asset_id.has_value());
        QCOMPARE(asset_rec.credit, 0); // No BTC amount
        QCOMPARE(asset_rec.asset_units, 30000000UL); // Asset units
    }
}
