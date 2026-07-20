// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_BRIDGESESSIONSTAB_H
#define BITCOIN_QT_BRIDGESESSIONSTAB_H

#include <QPointer>
#include <QWidget>
#include <QMap>
#include <QTimer>

class PlatformStyle;
class WalletModel;
class BridgeSessionManager;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QVBoxLayout;
QT_END_NAMESPACE

/**
 * @brief Bridge Sessions tab - Manage cosign bridge sessions
 *
 * Displays bridge status, active sessions table, and provides
 * controls to start new sessions or join existing ones.
 */
class BridgeSessionsTab : public QWidget
{
    Q_OBJECT

public:
    explicit BridgeSessionsTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~BridgeSessionsTab();

    void setWalletModel(WalletModel* model);
    void setSessionManager(BridgeSessionManager* manager);

private Q_SLOTS:
    void onStartNewSession();
    void onJoinSession();
    void onCloseSession();
    void onSessionAction();
    void updateBridgeStatus();
    void updateSessionList();
    void checkBridgeHealth();

private:
    void setupUI();
    QString formatTimestamp(int64_t timestamp);

    // QPointer auto-nulls on WalletModel destruction so the polling timer and
    // status refresh slots don't dereference a freed wallet model.
    QPointer<WalletModel> walletModel;
    BridgeSessionManager* sessionManager{nullptr};
    const PlatformStyle* platformStyle{nullptr};

    // UI components
    QLabel* bridgeStatusLabel{nullptr};
    QLabel* bridgeVersionLabel{nullptr};
    QLabel* bridgeUptimeLabel{nullptr};
    QPushButton* startSessionButton{nullptr};
    QPushButton* joinSessionButton{nullptr};
    QTableWidget* sessionTable{nullptr};

    // Update timer
    QTimer* updateTimer{nullptr};

    // Bridge status cache
    bool bridgeConnected{false};
    QString bridgeVersion;
};

#endif // BITCOIN_QT_BRIDGESESSIONSTAB_H
