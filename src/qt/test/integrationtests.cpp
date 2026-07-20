// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/integrationtests.h>

#include <qt/test/mockwallet.h>

#include <common/args.h>
#include <interfaces/node.h>
#include <node/context.h>
#include <key_io.h>
#include <outputtype.h>
#include <qt/bitcoinamountfield.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/walletmodel.h>
#include <qt/sendcoinsrecipient.h>
#include <util/translation.h>
#include <clientversion.h>
#include <streams.h>
#include <span>
#include <serialize.h>
 
#include <QApplication>
#include <QCoreApplication>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QDir>
#include <QSettings>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <memory>

#include <vector>

namespace
{
interfaces::AssetBalance MakeAssetBalance(const std::string& id_hex,
                                          const std::string& ticker,
                                          uint64_t balance,
                                          uint8_t decimals,
                                          bool has_metadata)
{
    interfaces::AssetBalance bal;
    auto asset_id_opt = uint256::FromHex(id_hex);
    if (asset_id_opt.has_value()) {
        bal.asset_id = asset_id_opt.value();
    }
    bal.ticker = ticker;
    bal.balance = balance;
    bal.decimals = decimals;
    bal.has_ticker = has_metadata;
    bal.has_decimals = has_metadata;
    bal.utxo_count = 1;
    bal.is_registered = has_metadata;
    return bal;
}

void CloseReceiveRequestDialogs()
{
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            widget->close();
        }
    }
}
}

IntegrationTests::~IntegrationTests() = default;

void IntegrationTests::initTestCase()
{
    int stage = 0;
    try {
        stage = 1;
        static std::unique_ptr<node::NodeContext> local_ctx;
        node::NodeContext* ctx = m_node.context();
        if (!ctx || ctx->args == nullptr) {
            if (!local_ctx) {
                local_ctx = std::make_unique<node::NodeContext>();
            }
            if (!ctx) {
                m_node.setContext(local_ctx.get());
                ctx = m_node.context();
                if (!ctx) {
                    ctx = local_ctx.get();
                    m_node.setContext(ctx);
                }
            }
            if (ctx->args == nullptr) {
                ctx->args = &gArgs;
            }
        }

        auto wallet_ptr = std::make_unique<qt_tests::MockWallet>();
        wallet_ptr->asset_balances.push_back(
            MakeAssetBalance("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                             "USDt", 1'000'000'000, 6, /*has_metadata=*/true));
        m_walletBackend = wallet_ptr.get();
        m_testAssetId = wallet_ptr->asset_balances.front().asset_id;
        m_testTicker = QString::fromStdString(wallet_ptr->asset_balances.front().ticker);

        stage = 2;
        m_platformStyle.reset(PlatformStyle::instantiate("other"));
        QVERIFY2(m_platformStyle, "PlatformStyle::instantiate returned null");
        m_optionsModel = std::make_unique<OptionsModel>(m_node);
        bilingual_str error;
        bool init_ok = m_optionsModel->Init(error);
        if (!init_ok) {
            QFAIL(QString("OptionsModel init failure: %1").arg(QString::fromStdString(error.original)).toUtf8().constData());
        }

        stage = 3;
        QString settingsPath = QDir::tempPath() + "/qt-tests-" + QString::number(QCoreApplication::applicationPid());
        QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, settingsPath);
        QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, settingsPath);

        try {
            m_clientModel = std::make_unique<ClientModel>(m_node, m_optionsModel.get());
        } catch (const std::exception& ex) {
            QFAIL(QString("ClientModel ctor: %1").arg(ex.what()).toUtf8().constData());
        }

        stage = 4;
        try {
            m_walletModel = std::make_unique<WalletModel>(std::move(wallet_ptr), *m_clientModel, m_platformStyle.get());
            m_walletModel->refreshAssetBalances();
        } catch (const std::exception& ex) {
            QFAIL(QString("WalletModel ctor: %1").arg(ex.what()).toUtf8().constData());
        }

        stage = 5;
        m_receiveDialog = std::make_unique<ReceiveCoinsDialog>(m_platformStyle.get());
        m_receiveDialog->setModel(m_walletModel.get());

        QApplication::processEvents();
    } catch (const std::exception& e) {
        QFAIL(QString("stage %1: %2").arg(stage).arg(QString::fromUtf8(e.what())).toUtf8().constData());
    }
}

void IntegrationTests::cleanupTestCase()
{
    CloseReceiveRequestDialogs();
    m_receiveDialog.reset();
    m_walletModel.reset();
    m_clientModel.reset();
    m_optionsModel.reset();
    m_platformStyle.reset();
    m_walletBackend = nullptr;
}

void IntegrationTests::testCompleteAssetFlow()
{
    // Ensure request state starts empty.
    auto* tableModel = m_walletModel->getRecentRequestsTableModel();
    while (tableModel->rowCount({}) > 0) {
        tableModel->removeRows(0, 1);
    }
    m_walletBackend->receive_requests.clear();

    QComboBox* assetCombo = m_receiveDialog->findChild<QComboBox*>("assetComboBox");
    QVERIFY(assetCombo);
    const QString assetIdHex = QString::fromStdString(m_testAssetId.ToString());
    const int assetIndex = assetCombo->findData(assetIdHex);
    QVERIFY(assetIndex > 0);
    assetCombo->setCurrentIndex(assetIndex);

    BitcoinAmountField* amountField = m_receiveDialog->findChild<BitcoinAmountField*>("reqAmount");
    QVERIFY(amountField);
    // Request 5 units (6 decimals) => field uses 8 decimals -> multiply by 10^(8-6) = 100.
    amountField->setValue(500000000);

    QLineEdit* labelInput = m_receiveDialog->findChild<QLineEdit*>("reqLabel");
    QVERIFY(labelInput);
    labelInput->setText("FOCUS_ASSET");

    QLineEdit* messageInput = m_receiveDialog->findChild<QLineEdit*>("reqMessage");
    QVERIFY(messageInput);
    messageInput->setText("Conference demo");

    QPushButton* receiveButton = m_receiveDialog->findChild<QPushButton*>("receiveButton");
    QVERIFY(receiveButton);
    receiveButton->click();
    QApplication::processEvents();

    ReceiveRequestDialog* requestDialog = nullptr;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            requestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            break;
        }
    }
    QVERIFY(requestDialog);

    QLabel* amountLabel = requestDialog->findChild<QLabel*>("amount_content");
    QVERIFY(amountLabel);
    QCOMPARE(amountLabel->text(), QStringLiteral("5 %1").arg(m_testTicker));

    QLabel* uriLabel = requestDialog->findChild<QLabel*>("uri_content");
    QVERIFY(uriLabel);
    QVERIFY(uriLabel->text().contains("tensorcash:"));
    QVERIFY(uriLabel->text().contains(assetIdHex));

    requestDialog->close();
    QApplication::processEvents();

    auto stored = m_walletBackend->getAddressReceiveRequests();
    QCOMPARE(stored.size(), size_t{1});

    const unsigned char* data_ptr = reinterpret_cast<const unsigned char*>(stored[0].data());
    SpanReader reader(std::span<const unsigned char>(data_ptr, stored[0].size()));
    RecentRequestEntry entry;
    reader >> entry;
    QCOMPARE(entry.recipient.asset_ticker, m_testTicker);
    QCOMPARE(entry.recipient.asset_units, uint64_t{5'000'000});
    QCOMPARE(entry.recipient.asset_decimals, uint8_t{6});
    QCOMPARE(entry.recipient.label, QStringLiteral("FOCUS_ASSET"));
    QCOMPARE(entry.recipient.message, QStringLiteral("Conference demo"));
}

void IntegrationTests::testAssetUriRoundTrip()
{
    auto dest = m_walletModel->wallet().getNewDestination(OutputType::BECH32, "uri-roundtrip");
    QVERIFY(dest.has_value());
    const QString address = QString::fromStdString(EncodeDestination(dest.value()));

    const QString assetIdHex = QString::fromStdString(m_testAssetId.ToString());

    SendCoinsRecipient info;
    info.address = address;
    info.asset_id = m_testAssetId;
    info.asset_units = 1'234'567; // 1.234567 units with 6 decimals
    info.asset_decimals = 6;
    info.asset_ticker = m_testTicker;
    info.label = "URI Roundtrip";
    info.message = "Asset payment";

    QString uri = GUIUtil::formatBitcoinURI(info);
    QVERIFY(uri.startsWith("tensorcash:"));
    QVERIFY(uri.contains(QString::fromStdString(m_testAssetId.ToString())));

    // Debug: Print the generated URI
    qDebug() << "Generated URI:" << uri;

    SendCoinsRecipient parsed;
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &parsed));
    QVERIFY(parsed.asset_id.has_value());
    QCOMPARE(QString::fromStdString(parsed.asset_id->ToString()), assetIdHex);

    // Debug: Print parsed values
    qDebug() << "Parsed asset_units:" << parsed.asset_units;
    qDebug() << "Parsed asset_decimals:" << (int)parsed.asset_decimals;
    qDebug() << "Parsed asset_amount_string:" << parsed.asset_amount_string;

    QCOMPARE(parsed.asset_units, info.asset_units);
    QCOMPARE(parsed.asset_decimals, info.asset_decimals);
    QCOMPARE(parsed.asset_ticker, info.asset_ticker);
    QCOMPARE(parsed.label, info.label);
    QCOMPARE(parsed.message, info.message);
}
