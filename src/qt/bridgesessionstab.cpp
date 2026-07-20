// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/bridgesessionstab.h>
#include <qt/bridgesessionmanager.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>

#include <qt/startsessiondialog.h>
#include <qt/joinsessiondialog.h>
#include <qt/sasverificationdialog.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QMessageBox>
#include <QDateTime>
#include <QMenu>
#include <QTimer>

BridgeSessionsTab::BridgeSessionsTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle)
{
    setupUI();

    // Create update timer for periodic status checks (but don't start yet)
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &BridgeSessionsTab::checkBridgeHealth);
    // Timer will be started in setWalletModel() when wallet is ready
}

BridgeSessionsTab::~BridgeSessionsTab()
{
}

void BridgeSessionsTab::setWalletModel(WalletModel* model)
{
    this->walletModel = model;

    if (walletModel) {
        // Initial bridge status check
        updateBridgeStatus();

        // Start the update timer now that wallet is ready
        if (updateTimer && !updateTimer->isActive()) {
            updateTimer->start(5000); // Check every 5 seconds
        }
    }
}

void BridgeSessionsTab::setSessionManager(BridgeSessionManager* manager)
{
    this->sessionManager = manager;

    if (sessionManager) {
        // Connect to session manager signals
        connect(sessionManager, &BridgeSessionManager::sessionsChanged,
                this, &BridgeSessionsTab::updateSessionList);

        // Initial session list update
        updateSessionList();
    }
}

void BridgeSessionsTab::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Bridge Status
    QHBoxLayout* statusLayout = new QHBoxLayout();
    statusLayout->addWidget(new QLabel(tr("Bridge:"), this));

    bridgeStatusLabel = new QLabel(tr("● Disconnected"), this);
    bridgeStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
    statusLayout->addWidget(bridgeStatusLabel);

    bridgeVersionLabel = new QLabel(tr("Version: Unknown"), this);
    statusLayout->addWidget(bridgeVersionLabel);

    bridgeUptimeLabel = new QLabel(tr("Uptime: Unknown"), this);
    statusLayout->addWidget(bridgeUptimeLabel);

    statusLayout->addStretch();
    mainLayout->addLayout(statusLayout);

    // Session Controls
    QHBoxLayout* controlsLayout = new QHBoxLayout();

    startSessionButton = new QPushButton(tr("Start New Session"), this);
    startSessionButton->setToolTip(tr("Create a new cosign session as initiator"));
    connect(startSessionButton, &QPushButton::clicked, this, &BridgeSessionsTab::onStartNewSession);
    controlsLayout->addWidget(startSessionButton);

    joinSessionButton = new QPushButton(tr("Join Session"), this);
    joinSessionButton->setToolTip(tr("Join an existing cosign session via invite link"));
    connect(joinSessionButton, &QPushButton::clicked, this, &BridgeSessionsTab::onJoinSession);
    controlsLayout->addWidget(joinSessionButton);

    controlsLayout->addStretch();

    mainLayout->addLayout(controlsLayout);

    // Active Sessions Table
    QGroupBox* sessionsGroup = new QGroupBox(tr("Active Sessions"), this);
    QVBoxLayout* sessionsLayout = new QVBoxLayout(sessionsGroup);

    sessionTable = new QTableWidget(this);
    sessionTable->setColumnCount(8);
    sessionTable->setHorizontalHeaderLabels({
        tr("Session ID"),
        tr("SAS (Short Auth String)"),
        tr("Contract"),
        tr("Transport"),
        tr("Relay URL"),
        tr("Started"),
        tr("Handshake"),
        tr("Actions")
    });

    sessionTable->horizontalHeader()->setStretchLastSection(false);
    sessionTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    sessionTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    sessionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    sessionTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    sessionTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    sessionTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    sessionTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    sessionTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);

    sessionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    sessionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    sessionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    sessionTable->setAlternatingRowColors(true);
    sessionTable->verticalHeader()->setVisible(false);

    sessionsLayout->addWidget(sessionTable);
    sessionsGroup->setLayout(sessionsLayout);

    mainLayout->addWidget(sessionsGroup);

    setLayout(mainLayout);
}

void BridgeSessionsTab::onStartNewSession()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    if (!sessionManager) {
        QMessageBox::warning(this, tr("Error"), tr("Session manager not available"));
        return;
    }

    // Open Start Session Dialog
    StartSessionDialog dialog(walletModel, this);
    if (dialog.exec() == QDialog::Accepted) {
        // Session created successfully
        QString session_id = dialog.getSessionId();
        QString sas = dialog.getSAS();
        QString sas_numeric = dialog.getSASNumeric();
        QString transport = dialog.getTransport();
        QString relay_url = dialog.getRelayUrl();

        // Add to session manager
        BridgeSessionManager::SessionInfo info;
        info.session_id = session_id;
        info.sas = sas;
        info.sas_numeric = sas_numeric;
        info.transport = transport;
        info.relay_url = relay_url;
        info.started_timestamp = QDateTime::currentSecsSinceEpoch();
        info.handshake_complete = false;
        info.is_initiator = true;  // We called cosign.init, so we are the initiator

        sessionManager->addSession(info);

        QMessageBox::information(this, tr("Session Created"),
            tr("Session created successfully!\n\nSession ID: %1\n\nYou can now share the invite link with your peer.")
            .arg(session_id.left(16) + "..."));
    }
}

void BridgeSessionsTab::onJoinSession()
{
    if (!walletModel) {
        QMessageBox::warning(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    if (!sessionManager) {
        QMessageBox::warning(this, tr("Error"), tr("Session manager not available"));
        return;
    }

    // Open Join Session Dialog
    JoinSessionDialog dialog(walletModel, this);
    if (dialog.exec() == QDialog::Accepted) {
        // Session joined successfully
        QString session_id = dialog.getSessionId();
        QString sas = dialog.getSAS();
        QString sas_numeric = dialog.getSASNumeric();

        // Add to session manager
        BridgeSessionManager::SessionInfo info;
        info.session_id = session_id;
        info.sas = sas;
        info.sas_numeric = sas_numeric;
        info.transport = "";  // Transport not captured for join
        info.relay_url = "";
        info.started_timestamp = QDateTime::currentSecsSinceEpoch();
        info.handshake_complete = false;
        info.is_initiator = false;  // We called cosign.join, so we are NOT the initiator

        sessionManager->addSession(info);

        QMessageBox::information(this, tr("Session Joined"),
            tr("Session joined successfully!\n\nSession ID: %1\n\nVerify the SAS matches with your peer.")
            .arg(session_id.left(16) + "..."));
    }
}

void BridgeSessionsTab::onCloseSession()
{
    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) return;

    QString session_id = button->property("session_id").toString();
    if (session_id.isEmpty()) return;

    if (!walletModel) return;

    // Confirm closure
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Close Session"),
        tr("Are you sure you want to close this session?\n\nSession ID: %1")
        .arg(session_id.left(16) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        // Call cosign.close RPC
        bool success = walletModel->cosignClose(session_id);

        if (success) {
            // Remove from session manager
            if (sessionManager) {
                sessionManager->removeSession(session_id);
            }

            QMessageBox::information(this, tr("Session Closed"),
                tr("Session closed successfully."));
        } else {
            QMessageBox::warning(this, tr("Error"),
                tr("Failed to close session. It may have already been closed."));
        }
    }
}

void BridgeSessionsTab::onSessionAction()
{
    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) return;

    QString session_id = button->property("session_id").toString();
    QString action = button->property("action").toString();

    if (session_id.isEmpty() || action.isEmpty()) return;

    if (action == "handshake") {
        // Perform handshake
        if (!walletModel || !sessionManager) return;

        // Get session info to determine initiator role
        if (!sessionManager->hasSession(session_id)) {
            QMessageBox::warning(this, tr("Error"), tr("Session not found"));
            return;
        }

        BridgeSessionManager::SessionInfo sessionInfo = sessionManager->getSession(session_id);
        bool is_initiator = sessionInfo.is_initiator;

        WalletModel::CosignHandshakeResult result = walletModel->cosignHandshakeAuto(session_id, is_initiator);

        if (result.success && result.handshake_complete) {
            // Update session info with handshake results
            sessionInfo.handshake_complete = true;
            // Update SAS values from handshake (may have more complete info now)
            if (!result.sas.isEmpty()) {
                sessionInfo.sas = result.sas;
            }
            if (!result.sas_numeric.isEmpty()) {
                sessionInfo.sas_numeric = result.sas_numeric;
            }
            sessionManager->updateSession(session_id, sessionInfo);

            // Show SAS with auto-close countdown and Abort option
            SASVerificationDialog sasDialog(result.sas, result.sas_numeric, 12, this);
            sasDialog.exec();
        } else {
            QMessageBox::warning(this, tr("Handshake Failed"),
                tr("Failed to complete handshake:\n%1").arg(result.error));
        }
    }
}

void BridgeSessionsTab::updateBridgeStatus()
{
    if (!walletModel) {
        bridgeStatusLabel->setText(tr("● Not Available"));
        bridgeStatusLabel->setStyleSheet("QLabel { color: #757575; font-weight: bold; }");
        bridgeVersionLabel->setText(tr("Version: Unknown"));
        bridgeUptimeLabel->setText(tr("Uptime: Unknown"));
        startSessionButton->setEnabled(false);
        joinSessionButton->setEnabled(false);
        return;
    }

    WalletModel::CosignPingResult result = walletModel->cosignPing();

    if (result.success && result.bridge_alive) {
        bridgeConnected = true;
        bridgeVersion = result.version;

        bridgeStatusLabel->setText(tr("● Connected"));
        bridgeStatusLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");
        bridgeVersionLabel->setText(tr("Version: %1").arg(result.version));

        // Format uptime
        int uptime = result.uptime_sec;
        int hours = uptime / 3600;
        int mins = (uptime % 3600) / 60;
        int secs = uptime % 60;
        bridgeUptimeLabel->setText(tr("Uptime: %1h %2m %3s").arg(hours).arg(mins).arg(secs));

        startSessionButton->setEnabled(true);
        joinSessionButton->setEnabled(true);
    } else {
        bridgeConnected = false;

        bridgeStatusLabel->setText(tr("● Disconnected"));
        bridgeStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
        bridgeVersionLabel->setText(tr("Version: Unknown"));
        bridgeUptimeLabel->setText(tr("Uptime: Unknown"));

        startSessionButton->setEnabled(false);
        joinSessionButton->setEnabled(false);

        if (!result.error.isEmpty()) {
            bridgeVersionLabel->setText(tr("Error: %1").arg(result.error));
        }
    }
}

void BridgeSessionsTab::updateSessionList()
{
    sessionTable->setRowCount(0);

    if (!sessionManager) {
        return;
    }

    QList<BridgeSessionManager::SessionInfo> sessions = sessionManager->getActiveSessions();

    int row = 0;
    for (const BridgeSessionManager::SessionInfo& info : sessions) {

        sessionTable->insertRow(row);

        // Session ID (truncated)
        QString shortId = info.session_id.left(16) + "...";
        QTableWidgetItem* idItem = new QTableWidgetItem(shortId);
        idItem->setToolTip(info.session_id);
        sessionTable->setItem(row, 0, idItem);

        // SAS
        QTableWidgetItem* sasItem = new QTableWidgetItem(info.sas);
        sasItem->setToolTip(tr("Numeric: %1").arg(info.sas_numeric));
        sessionTable->setItem(row, 1, sasItem);

        // Contract/Governance Reference
        QString contractDisplay;
        QString tooltip;

        if (info.purpose == BridgeSessionManager::SessionPurpose::Governance) {
            // Governance session - show proposal and asset
            if (!info.proposal_id.isEmpty()) {
                contractDisplay = tr("GOV: %1").arg(info.proposal_id.left(8) + "...");
                tooltip = tr("Governance Vote\nProposal: %1\nAsset: %2")
                    .arg(info.proposal_id)
                    .arg(info.asset_id);
            } else {
                contractDisplay = tr("Governance");
            }
        } else if (!info.contract_id.isEmpty()) {
            // Contract session
            QString shortContract = info.contract_id.left(8) + "...";
            if (!info.contract_type.isEmpty()) {
                contractDisplay = tr("%1 (%2)").arg(info.contract_type, shortContract);
            } else {
                contractDisplay = shortContract;
            }
            tooltip = tr("Contract ID: %1\nType: %2").arg(info.contract_id, info.contract_type);
        } else {
            // Trade session (no contract)
            contractDisplay = tr("-");
        }

        QTableWidgetItem* contractItem = new QTableWidgetItem(contractDisplay);
        if (!tooltip.isEmpty()) {
            contractItem->setToolTip(tooltip);
        }
        sessionTable->setItem(row, 2, contractItem);

        // Transport
        QString transportDisplay = info.transport.isEmpty() ? tr("auto") : info.transport;
        QTableWidgetItem* transportItem = new QTableWidgetItem(transportDisplay);
        sessionTable->setItem(row, 3, transportItem);

        // Relay URL
        QString relayDisplay = info.relay_url.isEmpty() ? tr("-") : info.relay_url;
        QTableWidgetItem* relayItem = new QTableWidgetItem(relayDisplay);
        if (!info.relay_url.isEmpty()) {
            relayItem->setToolTip(info.relay_url);
        }
        sessionTable->setItem(row, 4, relayItem);

        // Started time
        QString timeStr = formatTimestamp(info.started_timestamp);
        sessionTable->setItem(row, 5, new QTableWidgetItem(timeStr));

        // Handshake status
        QString handshakeStatus = info.handshake_complete ? tr("Complete") : tr("Pending");
        QTableWidgetItem* handshakeItem = new QTableWidgetItem(handshakeStatus);
        if (info.handshake_complete) {
            handshakeItem->setForeground(QBrush(QColor("#388e3c")));
        } else {
            handshakeItem->setForeground(QBrush(QColor("#d32f2f")));
            handshakeItem->setFont(QFont("Arial", 10, QFont::Bold));
        }
        sessionTable->setItem(row, 6, handshakeItem);

        // Actions
        QWidget* actionsWidget = new QWidget();
        QHBoxLayout* actionsLayout = new QHBoxLayout(actionsWidget);
        actionsLayout->setContentsMargins(4, 2, 4, 2);

        // Only show handshake button for non-governance sessions that haven't completed handshake
        if (!info.handshake_complete && info.purpose != BridgeSessionManager::SessionPurpose::Governance) {
            QPushButton* handshakeBtn = new QPushButton(tr("STEP 2: Handshake"), actionsWidget);
            handshakeBtn->setStyleSheet("QPushButton { background-color: #2196f3; color: white; font-weight: bold; padding: 8px 16px; }");
            handshakeBtn->setProperty("session_id", info.session_id);
            handshakeBtn->setProperty("action", "handshake");
            connect(handshakeBtn, &QPushButton::clicked, this, &BridgeSessionsTab::onSessionAction);
            actionsLayout->addWidget(handshakeBtn);
        }

        // Show session state for governance
        if (info.purpose == BridgeSessionManager::SessionPurpose::Governance) {
            QString displayState = info.state;
            if (info.state == "ballot_published") displayState = tr("Ballot Published");
            else if (info.state == "vote_failed") displayState = tr("Vote Failed");
            else if (info.state == "voting") displayState = tr("Voting");
            else if (info.state == "pending") displayState = tr("Pending");
            QLabel* stateLabel = new QLabel(displayState, actionsWidget);
            if (info.state == "ballot_published") {
                stateLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");
            } else if (info.state == "vote_failed") {
                stateLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
            } else {
                stateLabel->setStyleSheet("QLabel { color: #f57c00; font-weight: bold; }");
            }
            actionsLayout->addWidget(stateLabel);
        }

        QPushButton* closeBtn = new QPushButton(tr("Close"), actionsWidget);
        closeBtn->setProperty("session_id", info.session_id);
        connect(closeBtn, &QPushButton::clicked, this, &BridgeSessionsTab::onCloseSession);
        actionsLayout->addWidget(closeBtn);

        actionsWidget->setLayout(actionsLayout);
        sessionTable->setCellWidget(row, 7, actionsWidget);

        row++;
    }
}

void BridgeSessionsTab::checkBridgeHealth()
{
    if (!isVisible()) return;
    updateBridgeStatus();
}

QString BridgeSessionsTab::formatTimestamp(int64_t timestamp)
{
    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
    QDateTime now = QDateTime::currentDateTime();

    int64_t diff = timestamp - now.toSecsSinceEpoch();
    diff = -diff; // Make positive

    if (diff < 60) {
        return tr("%1s ago").arg(diff);
    } else if (diff < 3600) {
        return tr("%1m ago").arg(diff / 60);
    } else if (diff < 86400) {
        return tr("%1h ago").arg(diff / 3600);
    } else {
        return dt.toString("yyyy-MM-dd HH:mm");
    }
}
