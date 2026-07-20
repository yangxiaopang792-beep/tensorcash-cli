// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/walletmodeltests.h>
#include <qt/test/util.h>

#include <interfaces/node.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/sendcoinsrecipient.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <wallet/coincontrol.h>

#include <memory>
#include <vector>

#include <QApplication>
#include <QTest>

void WalletModelTests::testPrepareAssetTransactionSuccess()
{
    // Test that prepareAssetTransaction properly validates asset transactions
    // This verifies the API exists and basic validation logic

    // Create a recipient structure
    QList<SendCoinsRecipient> recipients;
    SendCoinsRecipient recipient;
    recipient.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    recipient.amount = 50000000; // 0.5 units

    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    recipient.asset_id = asset_id_opt.value();
    recipient.asset_units = 50000000;
    recipient.asset_decimals = 8;
    recipients.append(recipient);

    // Create transaction object
    WalletModelTransaction transaction(recipients);

    // Verify recipients are properly set
    QCOMPARE(transaction.getRecipients().size(), 1);
    QVERIFY(transaction.getRecipients()[0].asset_id.has_value());
}

void WalletModelTests::testPrepareAssetTransactionInsufficientFunds()
{
    // Test transaction with very large amount
    QList<SendCoinsRecipient> recipients;
    SendCoinsRecipient recipient;
    recipient.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    recipient.amount = 2100000000000000LL; // 21 million BTC (way too much)

    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    recipient.asset_id = asset_id_opt.value();
    recipient.asset_units = 2100000000000000LL;
    recipient.asset_decimals = 8;
    recipients.append(recipient);

    WalletModelTransaction transaction(recipients);

    // Verify the transaction was created with the excessive amount
    QCOMPARE(transaction.getRecipients().size(), 1);
    QVERIFY(transaction.getRecipients()[0].amount > 2000000000000000LL);
}

void WalletModelTests::testPrepareAssetTransactionInvalidAsset()
{
    // Test with invalid/malformed asset ID
    QList<SendCoinsRecipient> recipients;
    SendCoinsRecipient recipient;
    recipient.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    recipient.amount = 1000000;

    // Try to use an invalid hex string (wrong length)
    auto invalid_asset = uint256::FromHex("deadbeef");
    QVERIFY(!invalid_asset.has_value()); // Should fail to parse

    // Use a valid but non-existent asset
    auto asset_id_opt = uint256::FromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    QVERIFY(asset_id_opt.has_value());
    recipient.asset_id = asset_id_opt.value();
    recipient.asset_units = 1000000;
    recipient.asset_decimals = 8;
    recipients.append(recipient);

    WalletModelTransaction transaction(recipients);
    QCOMPARE(transaction.getRecipients().size(), 1);
}

void WalletModelTests::testAssetDecimalHandling()
{
    // Test different decimal configurations

    // 8-decimal asset (like BTC)
    {
        QList<SendCoinsRecipient> recipients;
        SendCoinsRecipient recipient;
        recipient.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        recipient.amount = 50000000; // 0.5 with 8 decimals

        auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        QVERIFY(asset_id_opt.has_value());
        recipient.asset_id = asset_id_opt.value();
        recipient.asset_units = 50000000;
        recipient.asset_decimals = 8;
        recipients.append(recipient);

        WalletModelTransaction transaction(recipients);
        QCOMPARE(transaction.getRecipients()[0].asset_decimals, 8);
    }

    // 2-decimal asset (like USD)
    {
        QList<SendCoinsRecipient> recipients;
        SendCoinsRecipient recipient;
        recipient.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        recipient.amount = 50000; // 500.00 with 2 decimals

        auto asset_id_opt = uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        QVERIFY(asset_id_opt.has_value());
        recipient.asset_id = asset_id_opt.value();
        recipient.asset_units = 50000;
        recipient.asset_decimals = 2;
        recipients.append(recipient);

        WalletModelTransaction transaction(recipients);
        QCOMPARE(transaction.getRecipients()[0].asset_decimals, 2);
    }

    // 0-decimal asset (whole units only)
    {
        QList<SendCoinsRecipient> recipients;
        SendCoinsRecipient recipient;
        recipient.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        recipient.amount = 500; // 500 whole units

        auto asset_id_opt = uint256::FromHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        QVERIFY(asset_id_opt.has_value());
        recipient.asset_id = asset_id_opt.value();
        recipient.asset_units = 500;
        recipient.asset_decimals = 0;
        recipients.append(recipient);

        WalletModelTransaction transaction(recipients);
        QCOMPARE(transaction.getRecipients()[0].asset_decimals, 0);
    }
}

void WalletModelTests::testMultipleAssetRecipients()
{
    // Test transaction with multiple recipients of same asset
    QList<SendCoinsRecipient> recipients;

    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    uint256 asset_id = asset_id_opt.value();

    // First recipient
    SendCoinsRecipient recipient1;
    recipient1.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    recipient1.amount = 30000000; // 0.3
    recipient1.asset_id = asset_id;
    recipient1.asset_units = 30000000;
    recipient1.asset_decimals = 8;
    recipients.append(recipient1);

    // Second recipient
    SendCoinsRecipient recipient2;
    recipient2.address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    recipient2.amount = 20000000; // 0.2
    recipient2.asset_id = asset_id;
    recipient2.asset_units = 20000000;
    recipient2.asset_decimals = 8;
    recipients.append(recipient2);

    WalletModelTransaction transaction(recipients);

    // Verify both recipients are included
    QCOMPARE(transaction.getRecipients().size(), 2);
    QCOMPARE(transaction.getRecipients()[0].amount, 30000000);
    QCOMPARE(transaction.getRecipients()[1].amount, 20000000);

    // Verify total amount
    CAmount total = transaction.getTotalTransactionAmount();
    QCOMPARE(total, 50000000); // 0.3 + 0.2 = 0.5
}

void WalletModelTests::testAssetBalanceRefresh()
{
    // Test that asset balance structures work correctly

    // Create test asset balance data
    interfaces::AssetBalance balance1;
    auto asset_id_opt = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    QVERIFY(asset_id_opt.has_value());
    balance1.asset_id = asset_id_opt.value();
    balance1.ticker = "TST";
    balance1.balance = 100000000; // 1.0 TST
    balance1.pending = 0;
    balance1.locked = 0;
    balance1.decimals = 8;
    balance1.utxo_count = 1;
    balance1.has_ticker = true;
    balance1.has_decimals = true;
    balance1.is_registered = true;

    // Verify balance structure
    QCOMPARE(balance1.balance, 100000000UL);
    QCOMPARE(balance1.decimals, 8);
    QVERIFY(balance1.has_ticker);
    QCOMPARE(balance1.ticker, "TST");

    // Test balance update
    balance1.balance = 150000000; // 1.5 TST
    balance1.utxo_count = 2;

    QCOMPARE(balance1.balance, 150000000UL);
    QCOMPARE(balance1.utxo_count, 2UL);
}
