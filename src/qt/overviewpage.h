// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include <interfaces/wallet.h>

#include <QPointer>
#include <QWidget>
#include <memory>

class AssetBalanceWidget;
class ClientModel;
class ContractRegistryModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;

QT_BEGIN_NAMESPACE
class QFrame;
class QLabel;
class QListView;
class QModelIndex;
class QTimer;
QT_END_NAMESPACE

namespace Ui {
    class OverviewPage;
}

class ContractOverviewDelegate;

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void showOutOfSyncWarning(bool fShow);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);
    void setPrivacy(bool privacy);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();
    void assetDoubleClicked(const QString& assetId);
    void contractClicked(const QString& contractId);

protected:
    void changeEvent(QEvent* e) override;

private:
    Ui::OverviewPage *ui;
    ClientModel* clientModel{nullptr};
    // QPointer auto-nulls on WalletModel destruction so refresh slots and
    // pricing callbacks survive wallet unload / app shutdown.
    QPointer<WalletModel> walletModel;
    bool m_privacy{false};

    const PlatformStyle* m_platform_style;

    AssetBalanceWidget* assetBalanceWidget{nullptr};
    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;

    // Wallet MTM section
    QFrame* walletMtmFrame{nullptr};
    QLabel* labelWalletMtmTitle{nullptr};
    QLabel* labelTscMtm{nullptr};
    QLabel* labelAssetMtm{nullptr};
    QLabel* labelContractsMtm{nullptr};
    QLabel* labelTotalMtm{nullptr};
    QTimer* mtmRefreshTimer{nullptr};

    // Off-thread wallet-MTM fetch (mirrors ContractRegistryModel::refresh()).
    // pricing.portfolio.risk can block for the full duration of a node-side
    // stall (e.g. cs_main held across a validator round-trip on a slow
    // network), so it must never run on the GUI thread.
    struct WalletMtmSnapshot {
        bool ok{false};
        double tscMtm{0.0};
        double assetMtm{0.0};
        double contractsMtm{0.0};
        double totalMtm{0.0};
    };
    bool m_mtmFetchInFlight{false};
    bool m_mtmFetchPending{false};
    static WalletMtmSnapshot fetchWalletMtm(WalletModel* wm);
    void dispatchWalletMtmFetch();
    void renderWalletMtm(const WalletMtmSnapshot& snap);

    // Contracts Overview section
    QFrame* contractsOverviewFrame{nullptr};
    QLabel* labelContractsOverviewTitle{nullptr};
    QListView* listContracts{nullptr};
    ContractOverviewDelegate* contractDelegate{nullptr};
    ContractRegistryModel* contractModel{nullptr};

    void setupWalletMtmSection();
    void setupContractsOverviewSection();

private Q_SLOTS:
    void LimitTransactionRows();
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void handleContractClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void setMonospacedFont(const QFont&);
    void refreshOverviewPanels();
    void refreshContractsOverview();
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
