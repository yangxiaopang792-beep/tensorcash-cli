// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ACTIVECONTRACTSTAB_H
#define BITCOIN_QT_ACTIVECONTRACTSTAB_H

#include <QPointer>
#include <QWidget>
#include <QTableView>
#include <QComboBox>
#include <QPushButton>
#include <QTimer>

class WalletModel;
class ContractRegistryModel;
class PlatformStyle;

/**
 * Active Contracts Tab - displays all active contracts in a table.
 * Third sub-tab in Exchange P2P page.
 */
class ActiveContractsTab : public QWidget
{
    Q_OBJECT

public:
    explicit ActiveContractsTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~ActiveContractsTab();

    void setWalletModel(WalletModel* model);

private Q_SLOTS:
    void onFilterChanged();
    void onRefreshClicked();
    void onContractDoubleClicked(const QModelIndex& index);
    void onNewBlock();
    void updateMaturityCountdowns();

private:
    void setupUI();
    void loadContracts();

    const PlatformStyle* platformStyle{nullptr};
    // QPointer auto-nulls on WalletModel destruction so the refresh timer and
    // contract-row action slots survive wallet unload / app shutdown.
    QPointer<WalletModel> walletModel;
    ContractRegistryModel* registryModel{nullptr};

    // UI components
    QComboBox* typeFilterCombo{nullptr};
    QComboBox* statusFilterCombo{nullptr};
    QTableView* contractsTable{nullptr};
    QPushButton* refreshButton{nullptr};
    QPushButton* viewDetailsButton{nullptr};

    // Auto-refresh timer
    QTimer* countdownTimer{nullptr};
};

#endif // BITCOIN_QT_ACTIVECONTRACTSTAB_H
