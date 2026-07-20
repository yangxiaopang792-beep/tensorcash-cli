// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/receivedialogtests.h>

#include <qt/test/mockwallet.h>

#include <common/args.h>
#include <interfaces/node.h>
#include <node/context.h>
#include <kernel/context.h>
#include <key.h>
#include <key_io.h>
#include <util/chaintype.h>
#include <chainparams.h>
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

#include <memory>

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QLabel>
#include <QSettings>
#include <QSortFilterProxyModel>
#include <QTableView>

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
} // namespace

ReceiveDialogTests::~ReceiveDialogTests() = default;

void ReceiveDialogTests::initTestCase()
{
    int stage = 0;
    try {
        // Initialize chain parameters before any code that might call Params()
        SelectParams(ChainType::REGTEST);

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
            if (!ctx->kernel) {
                ctx->kernel = std::make_unique<kernel::Context>();
            }
            if (!ctx->ecc_context) {
                ctx->ecc_context = std::make_unique<ECC_Context>();
            }
        }

        auto wallet_ptr = std::make_unique<qt_tests::MockWallet>();
        wallet_ptr->asset_balances.push_back(
            MakeAssetBalance("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                             "USDt", 250000000, 6, /*has_metadata=*/true));
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
        QString settingsPath = QDir::tempPath() + "/qt-tests-" + QString::number(QCoreApplication::applicationPid());
        QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, settingsPath);
        QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, settingsPath);

        try {
            m_clientModel = std::make_unique<ClientModel>(m_node, m_optionsModel.get());
        } catch (const std::exception& ex) {
            QFAIL(QString("ClientModel ctor: %1").arg(ex.what()).toUtf8().constData());
        }

        stage = 3;
        try {
            m_walletModel = std::make_unique<WalletModel>(std::move(wallet_ptr), *m_clientModel, m_platformStyle.get());
            m_walletModel->refreshAssetBalances();
        } catch (const std::exception& ex) {
            QFAIL(QString("WalletModel ctor: %1").arg(ex.what()).toUtf8().constData());
        }

        stage = 4;
        m_receiveDialog = std::make_unique<ReceiveCoinsDialog>(m_platformStyle.get());
        m_receiveDialog->setModel(m_walletModel.get());

        stage = 5;
        m_requestDialog = std::make_unique<ReceiveRequestDialog>();
        m_requestDialog->setModel(m_walletModel.get());

        QApplication::processEvents();
    } catch (const std::exception& e) {
        QFAIL(QString("stage %1: %2").arg(stage).arg(QString::fromUtf8(e.what())).toUtf8().constData());
    }
}

void ReceiveDialogTests::cleanupTestCase()
{
    m_requestDialog.reset();
    m_receiveDialog.reset();
    m_walletModel.reset();
    m_clientModel.reset();
    m_optionsModel.reset();
    m_platformStyle.reset();
    m_walletBackend = nullptr;
}

void ReceiveDialogTests::testAssetSelectionUpdatesLabels()
{
    // Re-initialize chain params (Qt test framework may reset globals between tests)
    try {
        SelectParams(ChainType::REGTEST);
    } catch (...) {
        // If already initialized, that's fine
    }

    QComboBox* assetCombo = m_receiveDialog->findChild<QComboBox*>("assetComboBox");
    QVERIFY(assetCombo);

    const QString assetIdHex = QString::fromStdString(m_testAssetId.ToString());
    const int assetIndex = assetCombo->findData(assetIdHex);
    QVERIFY(assetIndex > 0); // index 0 is BTC

    assetCombo->setCurrentIndex(assetIndex);
    QApplication::processEvents();

    QLabel* amountLabel = m_receiveDialog->findChild<QLabel*>("label");
    QVERIFY(amountLabel);
    QCOMPARE(amountLabel->text(), QString("&Amount (%1):").arg(m_testTicker));
    QVERIFY(amountLabel->toolTip().contains("6"));

    // Ensure tooltips propagate to amount field as well
    BitcoinAmountField* amountField = m_receiveDialog->findChild<BitcoinAmountField*>("reqAmount");
    QVERIFY(amountField);
    QVERIFY(amountField->toolTip().contains(m_testTicker));

    // Clearing the dialog should reset to BTC defaults.
    m_receiveDialog->clear();
    QCOMPARE(assetCombo->currentIndex(), 0);
    QCOMPARE(amountLabel->text(), QString("&Amount (BTC):"));
}

void ReceiveDialogTests::testAssetRequestDialogUri()
{
    qDebug() << "testAssetRequestDialogUri: Starting";
    QVERIFY2(m_walletModel, "m_walletModel is null");
    QVERIFY2(m_requestDialog, "m_requestDialog is null");
    qDebug() << "testAssetRequestDialogUri: Pointers verified";

    // Re-initialize chain params (Qt test framework may reset globals between tests)
    try {
        SelectParams(ChainType::REGTEST);
        qDebug() << "testAssetRequestDialogUri: Chain params selected";
    } catch (...) {
        qDebug() << "testAssetRequestDialogUri: Chain params already initialized";
    }

    // Try to get wallet interface
    qDebug() << "testAssetRequestDialogUri: Getting wallet interface";
    interfaces::Wallet* wallet_interface = nullptr;
    try {
        wallet_interface = &m_walletModel->wallet();
        qDebug() << "testAssetRequestDialogUri: Got wallet interface";
    } catch (const std::exception& e) {
        QFAIL(QString("Failed to get wallet interface: %1").arg(e.what()).toUtf8().constData());
    }
    QVERIFY2(wallet_interface, "wallet_interface is null");

    // Test ECC context is working by trying to generate a key
    qDebug() << "testAssetRequestDialogUri: Testing ECC context";
    try {
        CKey test_key = GenerateRandomKey();
        QVERIFY2(test_key.IsValid(), "Generated key is not valid - ECC context may be broken");
        qDebug() << "testAssetRequestDialogUri: ECC context OK";
    } catch (const std::exception& e) {
        QFAIL(QString("Failed to generate test key: %1").arg(e.what()).toUtf8().constData());
    }

    qDebug() << "testAssetRequestDialogUri: Getting new destination";
    auto dest = wallet_interface->getNewDestination(OutputType::BECH32, "receive-asset");
    qDebug() << "testAssetRequestDialogUri: Got destination result";
    QVERIFY(dest.has_value());
    qDebug() << "testAssetRequestDialogUri: Destination has value";
    const QString address = QString::fromStdString(EncodeDestination(dest.value()));
    qDebug() << "testAssetRequestDialogUri: Encoded address:" << address;

    SendCoinsRecipient recipient;
    recipient.address = address;
    recipient.label = "Focus Group";
    recipient.message = "Asset invoice";
    recipient.asset_id = m_testAssetId;
    recipient.asset_units = 12345678; // 12.345678 units with 6 decimals
    recipient.asset_decimals = 6;
    recipient.asset_ticker = m_testTicker;
    qDebug() << "testAssetRequestDialogUri: Recipient prepared";

    qDebug() << "testAssetRequestDialogUri: Calling setInfo";
    m_requestDialog->setInfo(recipient);
    qDebug() << "testAssetRequestDialogUri: setInfo completed";
    QApplication::processEvents();
    qDebug() << "testAssetRequestDialogUri: processEvents completed";

    QLabel* assetLabel = m_requestDialog->findChild<QLabel*>("asset_content");
    QVERIFY(assetLabel);
    QCOMPARE(assetLabel->text(), m_testTicker);

    QLabel* amountContent = m_requestDialog->findChild<QLabel*>("amount_content");
    QVERIFY(amountContent);
    QString expectedAmount = GUIUtil::formatAssetAmount(recipient.asset_units, recipient.asset_decimals);
    if (expectedAmount.isEmpty()) {
        expectedAmount = QStringLiteral("0");
    }
    expectedAmount.append(QStringLiteral(" %1").arg(m_testTicker));
    QCOMPARE(amountContent->text(), expectedAmount);

    QLabel* uriContent = m_requestDialog->findChild<QLabel*>("uri_content");
    QVERIFY(uriContent);
    QVERIFY(uriContent->text().contains("tensorcash:"));
    QVERIFY(uriContent->text().contains(QString::fromStdString(m_testAssetId.ToString())));

    QLabel* walletContent = m_requestDialog->findChild<QLabel*>("wallet_content");
    QVERIFY(walletContent);
    QCOMPARE(walletContent->text(), QString::fromStdString(m_walletBackend->wallet_name));
}

void ReceiveDialogTests::testRecentRequestsFiltering()
{
    RecentRequestsTableModel* tableModel = m_walletModel->getRecentRequestsTableModel();
    QVERIFY(tableModel);

    QTableView* tableView = m_receiveDialog->findChild<QTableView*>("recentRequestsView");
    QVERIFY(tableView);
    auto* proxyModel = qobject_cast<QSortFilterProxyModel*>(tableView->model());
    QVERIFY(proxyModel);

    // Prepare recipients for asset and BTC requests.
    auto newAssetDest = m_walletModel->wallet().getNewDestination(OutputType::BECH32, "asset-request");
    QVERIFY(newAssetDest.has_value());
    SendCoinsRecipient assetRecipient;
    assetRecipient.address = QString::fromStdString(EncodeDestination(newAssetDest.value()));
    assetRecipient.asset_id = m_testAssetId;
    assetRecipient.asset_units = 5000000; // 5 units
    assetRecipient.asset_decimals = 6;
    assetRecipient.asset_ticker = m_testTicker;
    tableModel->addNewRequest(assetRecipient);

    auto newBtcDest = m_walletModel->wallet().getNewDestination(OutputType::BECH32, "btc-request");
    QVERIFY(newBtcDest.has_value());
    SendCoinsRecipient btcRecipient;
    btcRecipient.address = QString::fromStdString(EncodeDestination(newBtcDest.value()));
    btcRecipient.amount = 20000000; // 0.2 BTC
    tableModel->addNewRequest(btcRecipient);

    QApplication::processEvents();

    QComboBox* filterCombo = m_receiveDialog->findChild<QComboBox*>("assetFilterComboBox");
    QVERIFY(filterCombo);

    // Should show both requests when "All" is selected.
    filterCombo->setCurrentIndex(0);
    QApplication::processEvents();
    QCOMPARE(proxyModel->rowCount(), 2);

    // Filter by custom asset ticker.
    const int assetFilterIndex = filterCombo->findData(m_testTicker);
    QVERIFY(assetFilterIndex >= 0);
    filterCombo->setCurrentIndex(assetFilterIndex);
    QApplication::processEvents();
    QCOMPARE(proxyModel->rowCount(), 1);

    // Filter BTC-only entries.
    const int btcFilterIndex = filterCombo->findData(QStringLiteral("BTC"));
    QVERIFY(btcFilterIndex >= 0);
    filterCombo->setCurrentIndex(btcFilterIndex);
    QApplication::processEvents();
    QCOMPARE(proxyModel->rowCount(), 1);
}
