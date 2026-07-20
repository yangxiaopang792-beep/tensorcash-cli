// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/crosschaintradeview.h>
#include <qt/walletmodel.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>
#include <QDateTime>

CrossChainTradeView::CrossChainTradeView(QWidget* parent)
    : QWidget(parent)
{
    setupUI();

    refreshTimer = new QTimer(this);
    refreshTimer->setInterval(15000); // 15 seconds
    connect(refreshTimer, &QTimer::timeout, this, &CrossChainTradeView::refreshRecords);
}

CrossChainTradeView::~CrossChainTradeView()
{
}

void CrossChainTradeView::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);

    // Header
    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(tr("Active Cross-Chain Trades"), this);
    titleLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 11pt; }");
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();

    summaryLabel = new QLabel(this);
    summaryLabel->setStyleSheet("QLabel { color: #666; }");
    headerLayout->addWidget(summaryLabel);

    refreshButton = new QPushButton(tr("Refresh"), this);
    refreshButton->setMaximumWidth(70);
    connect(refreshButton, &QPushButton::clicked, this, &CrossChainTradeView::refreshRecords);
    headerLayout->addWidget(refreshButton);

    layout->addLayout(headerLayout);

    // Records table
    recordsTable = new QTableWidget(0, 9, this);
    recordsTable->setHorizontalHeaderLabels({
        tr("Swap ID"),
        tr("State"),
        tr("Chain"),
        tr("Adapter"),
        tr("Role"),
        tr("Ext Conf"),
        tr("TSC Conf"),
        tr("Fee Level"),
        tr("Updated")
    });
    recordsTable->horizontalHeader()->setStretchLastSection(true);
    recordsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    recordsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    recordsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    recordsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    recordsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    recordsTable->setAlternatingRowColors(true);
    recordsTable->verticalHeader()->setVisible(false);
    recordsTable->verticalHeader()->setDefaultSectionSize(24);

    layout->addWidget(recordsTable);
    setLayout(layout);
}

void CrossChainTradeView::setWalletModel(WalletModel* model)
{
    walletModel = model;
    if (walletModel) {
        refreshRecords();
        refreshTimer->start();
    } else {
        refreshTimer->stop();
    }
}

void CrossChainTradeView::refreshRecords()
{
    if (!walletModel) return;

    QList<WalletModel::CrossChainRecordItem> records = walletModel->crossChainRecordList();

    recordsTable->setRowCount(0);

    int activeCount = 0;

    for (const auto& r : records) {
        int row = recordsTable->rowCount();
        recordsTable->insertRow(row);

        QTableWidgetItem* idItem = new QTableWidgetItem(r.swap_id.left(12) + "...");
        idItem->setData(Qt::UserRole, r.swap_id);
        idItem->setToolTip(r.swap_id);
        recordsTable->setItem(row, 0, idItem);

        QString stateStr = stateToString(r.state);
        QTableWidgetItem* stateItem = new QTableWidgetItem(stateStr);
        stateItem->setForeground(QColor(stateToColor(r.state)));
        recordsTable->setItem(row, 1, stateItem);

        QString chain = r.external_chain.toUpper();
        if (chain == "ETHEREUM") chain = "ETH";
        recordsTable->setItem(row, 2, new QTableWidgetItem(chain));
        recordsTable->setItem(row, 3, new QTableWidgetItem(r.adapter));
        recordsTable->setItem(row, 4, new QTableWidgetItem(r.local_role));

        recordsTable->setItem(row, 5, new QTableWidgetItem(
            QString::number(r.external_conf_depth)));
        recordsTable->setItem(row, 6, new QTableWidgetItem(
            QString::number(r.tsc_conf_depth)));
        recordsTable->setItem(row, 7, new QTableWidgetItem(
            QString::number(r.fee_escalation_level)));

        QDateTime updated = QDateTime::fromSecsSinceEpoch(r.updated_time);
        recordsTable->setItem(row, 8, new QTableWidgetItem(
            updated.toString("yyyy-MM-dd hh:mm")));

        // Count non-terminal swaps (COMPLETED=16, ABORTED=17 are terminal)
        // Terminal states: completed, refunded (15), aborted
        bool isTerminal = (r.state == 15 || r.state == 16 || r.state == 17);
        if (!isTerminal) {
            ++activeCount;
        }
    }

    summaryLabel->setText(tr("%1 records, %2 active")
        .arg(records.size()).arg(activeCount));
}

QString CrossChainTradeView::stateToString(int state) const
{
    const QStringList names = {
        tr("Draft"),                    // 0
        tr("Posted"),                   // 1
        tr("Matched"),                  // 2
        tr("Session Established"),      // 3
        tr("Terms Finalized"),          // 4
        tr("Funding Prepared"),         // 5
        tr("Counterparty Lock Seen"),   // 6
        tr("Counterparty Lock Confirmed"), // 7
        tr("Local Lock Confirmed"),     // 8
        tr("Claim Ready"),              // 9
        tr("Claim Broadcast"),          // 10
        tr("Emergency Claim"),          // 11
        tr("Claim Confirmed"),          // 12
        tr("Refund Ready"),             // 13
        tr("Refund Broadcast"),         // 14
        tr("Refunded"),                 // 15
        tr("Completed"),                // 16
        tr("Aborted")                   // 17
    };

    if (state >= 0 && state < names.size()) {
        return names[state];
    }
    return tr("Unknown (%1)").arg(state);
}

QString CrossChainTradeView::stateToColor(int state) const
{
    if (state <= 5) return "#1976D2";   // Blue: pre-funding
    if (state <= 8) return "#FF9800";   // Orange: funding in progress
    if (state <= 10) return "#E65100";  // Dark orange: claim phase
    if (state == 11) return "#c62828";  // Red: emergency
    if (state == 12) return "#2E7D32";  // Green: claim confirmed
    if (state == 13 || state == 14) return "#c62828"; // Red: refund
    if (state == 15) return "#666";     // Grey: refunded
    if (state == 16) return "#388E3C";  // Green: completed
    if (state == 17) return "#666";     // Grey: aborted
    return "#000";
}
