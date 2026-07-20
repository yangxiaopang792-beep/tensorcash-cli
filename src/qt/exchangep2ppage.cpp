// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/exchangep2ppage.h>
#include <qt/bridgesessionstab.h>
#include <qt/tradeboardtab.h>
#include <qt/bridgesessionmanager.h>
#include <qt/newcontracttab.h>
#include <qt/activecontractstab.h>
#include <qt/assetpricetab.h>
#include <qt/risktab.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QLabel>

ExchangeP2PPage::ExchangeP2PPage(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle)
{
    // Create main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Create tab widget for sub-tabs
    tabWidget = new QTabWidget(this);

    // Create Trade Board tab
    tradeBoardTab = new TradeBoardTab(platformStyle, this);
    tabWidget->addTab(tradeBoardTab, tr("Market"));

    // Create Active Contracts tab
    activeContractsTab = new ActiveContractsTab(platformStyle, this);
    tabWidget->addTab(activeContractsTab, tr("Book"));

    // Create Risk tab
    riskTab = new RiskTab(platformStyle, this);
    tabWidget->addTab(riskTab, tr("Risk"));

    // Create Asset Prices tab
    assetPriceTab = new AssetPriceTab(platformStyle, this);
    tabWidget->addTab(assetPriceTab, tr("Pricing"));

    // Create New Contract tab
    newContractTab = new NewContractTab(platformStyle, this);
    tabWidget->addTab(newContractTab, tr("Structuring"));

    // Create Bridge Sessions tab
    bridgeSessionsTab = new BridgeSessionsTab(platformStyle, this);
    tabWidget->addTab(bridgeSessionsTab, tr("P2P Sessions"));

    mainLayout->addWidget(tabWidget);
    setLayout(mainLayout);
}

ExchangeP2PPage::~ExchangeP2PPage()
{
}

void ExchangeP2PPage::setWalletModel(WalletModel* model)
{
    this->walletModel = model;

    if (walletModel) {
        // Create session manager
        sessionManager = new BridgeSessionManager(walletModel, this);

        // Pass wallet model and session manager to tabs
        bridgeSessionsTab->setWalletModel(walletModel);
        bridgeSessionsTab->setSessionManager(sessionManager);

        tradeBoardTab->setWalletModel(walletModel);
        tradeBoardTab->setSessionManager(sessionManager);
        // Wire live price lookups
        tradeBoardTab->setAssetPriceTab(assetPriceTab);

        newContractTab->setWalletModel(walletModel);
        newContractTab->setSessionManager(sessionManager);

        activeContractsTab->setWalletModel(walletModel);

        assetPriceTab->setWalletModel(walletModel);

        riskTab->setWalletModel(walletModel);
    }
}

void ExchangeP2PPage::gotoBridgeSessionsTab()
{
    tabWidget->setCurrentWidget(bridgeSessionsTab);
}

void ExchangeP2PPage::gotoTradeBoardTab()
{
    tabWidget->setCurrentWidget(tradeBoardTab);
}

void ExchangeP2PPage::gotoNewContractTab()
{
    tabWidget->setCurrentWidget(newContractTab);
}

void ExchangeP2PPage::gotoActiveContractsTab()
{
    tabWidget->setCurrentWidget(activeContractsTab);
}

void ExchangeP2PPage::gotoAssetPricesTab()
{
    tabWidget->setCurrentWidget(assetPriceTab);
}
