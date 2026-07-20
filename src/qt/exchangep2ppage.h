// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_EXCHANGEP2PPAGE_H
#define BITCOIN_QT_EXCHANGEP2PPAGE_H

#include <QWidget>
#include <QTabWidget>

class BridgeSessionsTab;
class BridgeSessionManager;
class NewContractTab;
class ActiveContractsTab;
class TradeBoardTab;
class AssetPriceTab;
class RiskTab;
class PlatformStyle;
class WalletModel;

/**
 * @brief Exchange P2P main page - Container for decentralized financial contract management
 *
 * This page contains five sub-tabs:
 * 1. Bridge Sessions - Manage cosign bridge sessions for secure peer communication
 * 2. Trade Board - Decentralized P2P trading via Nostr bulletin board
 * 3. New Contract - Create new financial contracts (Repo/Forward/Spot)
 * 4. Active Contracts - View and manage active contracts
 * 5. Asset Prices - Configure asset price feeds and reference rates
 */
class ExchangeP2PPage : public QWidget
{
    Q_OBJECT

public:
    explicit ExchangeP2PPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~ExchangeP2PPage();

    void setWalletModel(WalletModel* model);

    /** Get the bridge session manager for access by sub-tabs */
    BridgeSessionManager* getSessionManager() const { return sessionManager; }

    /** Get the asset price tab for price lookups */
    AssetPriceTab* getAssetPriceTab() const { return assetPriceTab; }

public Q_SLOTS:
    /** Switch to Bridge Sessions tab */
    void gotoBridgeSessionsTab();
    /** Switch to Trade Board tab */
    void gotoTradeBoardTab();
    /** Switch to New Contract tab */
    void gotoNewContractTab();
    /** Switch to Active Contracts tab */
    void gotoActiveContractsTab();
    /** Switch to Asset Prices tab */
    void gotoAssetPricesTab();

private:
    WalletModel* walletModel{nullptr};
    const PlatformStyle* platformStyle;

    QTabWidget* tabWidget;
    BridgeSessionManager* sessionManager{nullptr};
    BridgeSessionsTab* bridgeSessionsTab;
    TradeBoardTab* tradeBoardTab;
    NewContractTab* newContractTab;
    ActiveContractsTab* activeContractsTab;
    AssetPriceTab* assetPriceTab;
    RiskTab* riskTab;
};

#endif // BITCOIN_QT_EXCHANGEP2PPAGE_H
