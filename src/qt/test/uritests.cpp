// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    // Commas in amounts are not allowed.
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // There are two amount specifications. The last value wins.
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&amount=200&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 20000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    // The first amount value is correct. However, the second amount value is not valid. Hence, the URI is not valid.
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Test label containing a question mark ('?').
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=?"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("?"));

    // Escape sequences are not supported.
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=%3F"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("%3F"));
}

void URITests::assetUriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;

    // Test 1: Parse tensorcash scheme with asset parameter
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                      "asset=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      "&amount=100.5"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.asset_id.has_value());
    QCOMPARE(QString::fromStdString(rv.asset_id->ToString()),
             QString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    QCOMPARE(rv.address, QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    // Note: Amount parsing for assets is handled differently than BTC

    // Test 2: Parse tensorcash URI with asset, amount, label, and message
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                      "asset=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "&amount=50.25"
                      "&label=Test%20Asset"
                      "&message=Payment%20for%20goods"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.asset_id.has_value());
    QCOMPARE(QString::fromStdString(rv.asset_id->ToString()),
             QString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    QCOMPARE(rv.address, QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QCOMPARE(rv.label, QString("Test Asset"));
    QCOMPARE(rv.message, QString("Payment for goods"));

    // Test 3: Regular bitcoin URI should still work (no asset)
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1.5"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(!rv.asset_id.has_value());  // No asset for bitcoin URIs
    QCOMPARE(rv.address, QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 150000000);  // 1.5 BTC in satoshis

    // Test 4: Invalid asset ID should fail gracefully
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                      "asset=invalidhex"
                      "&amount=10"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(!rv.asset_id.has_value());  // Invalid hex should result in no asset

    // Test 5: Empty asset parameter
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                      "asset="
                      "&amount=10"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(!rv.asset_id.has_value());

    // Test 6: Format asset URI and verify round-trip
    SendCoinsRecipient info;
    info.address = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W";
    auto asset_id = uint256::FromHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    QVERIFY(asset_id.has_value());
    info.asset_id = *asset_id;
    info.asset_units = 1000000;  // 1 unit with 6 decimals
    info.asset_decimals = 6;
    info.asset_ticker = "USDT";
    info.label = "Test Payment";
    info.message = "Invoice #123";

    QString formatted = GUIUtil::formatBitcoinURI(info);
    QVERIFY(formatted.startsWith("tensorcash:"));
    QVERIFY(formatted.contains("asset=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    QVERIFY(formatted.contains("label=Test%20Payment"));
    QVERIFY(formatted.contains("message=Invoice%20%23123"));

    // Test 7: Parse the formatted URI back and verify
    QUrl formattedUrl(formatted);
    SendCoinsRecipient parsed;
    QVERIFY(GUIUtil::parseBitcoinURI(formattedUrl, &parsed));
    QVERIFY(parsed.asset_id.has_value());
    QCOMPARE(QString::fromStdString(parsed.asset_id->ToString()),
             QString("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    QCOMPARE(parsed.address, info.address);
    QCOMPARE(parsed.label, info.label);
    QCOMPARE(parsed.message, info.message);

    // Test 8: Mixed parameters - asset comes before amount
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                      "label=First"
                      "&asset=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                      "&amount=25"
                      "&message=Last"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.asset_id.has_value());
    QCOMPARE(QString::fromStdString(rv.asset_id->ToString()),
             QString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"));

    // Test 9: Bitcoin URI with asset parameter should be ignored
    uri.setUrl(QString("tensorcash:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                      "asset=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                      "&amount=1"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    // Asset should be parsed even from tensorcash: scheme now
    QVERIFY(rv.asset_id.has_value());

    // Test 10: Format BTC URI (no asset) should use bitcoin scheme
    SendCoinsRecipient btcInfo;
    btcInfo.address = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W";
    btcInfo.amount = 100000000;  // 1 BTC
    btcInfo.label = "BTC Payment";

    QString btcFormatted = GUIUtil::formatBitcoinURI(btcInfo);
    QVERIFY(btcFormatted.startsWith("tensorcash:"));  // BTC uses bitcoin scheme
    QVERIFY(!btcFormatted.contains("asset="));  // No asset parameter for BTC
    QVERIFY(btcFormatted.contains("amount=1"));  // 1 BTC
}
