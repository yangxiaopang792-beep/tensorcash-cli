// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/governancetab.h>
#include <qt/bridgesessionmanager.h>
#include <qt/clientmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>
#include <interfaces/node.h>
#include <logging.h>
#include <univalue.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QMessageBox>
#include <QDateTime>
#include <QTimer>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QCryptographicHash>
#include <QPlainTextEdit>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QClipboard>
#include <QApplication>
#include <QRegularExpression>
#include <QFont>
#include <QStringList>

GovernanceTab::GovernanceTab(const PlatformStyle* _platformStyle, QWidget* parent)
    : QWidget(parent),
      platformStyle(_platformStyle)
{
    setupUI();

    // Create update timer (but don't start yet - wait for wallet model)
    proposalsUpdateTimer = new QTimer(this);
    connect(proposalsUpdateTimer, &QTimer::timeout, this, &GovernanceTab::updateProposalsList);
}

GovernanceTab::~GovernanceTab()
{
}

void GovernanceTab::setWalletModel(WalletModel* model)
{
    this->walletModel = model;

    LogPrintf("GovernanceTab::setWalletModel called, model=%p\n", model);

    if (walletModel) {
        // Update BB status and check if initialized
        updateBulletinBoardStatus();

        // Initial data fetch
        if (bbInitialized) {
            updateProposalsList();
        }

        // Start periodic updates (30 seconds for governance proposals)
        if (proposalsUpdateTimer && !proposalsUpdateTimer->isActive()) {
            proposalsUpdateTimer->start(30000);
        }

        // Initialize cache timestamp
        lastCacheRefresh = QDateTime::currentDateTime();
    }
}

void GovernanceTab::setClientModel(ClientModel* model)
{
    this->clientModel = model;

    LogPrintf("GovernanceTab::setClientModel called, model=%p\n", model);
}

void GovernanceTab::setSessionManager(BridgeSessionManager* manager)
{
    this->sessionManager = manager;
}

void GovernanceTab::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // ========== Bulletin Board Status (Single Line) ==========
    QHBoxLayout* statusLayout = new QHBoxLayout();
    statusLayout->setContentsMargins(6, 6, 6, 6);
    statusLayout->setSpacing(12);

    bbStatusLabel = new QLabel(tr("● Not Connected"), this);
    bbStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
    statusLayout->addWidget(bbStatusLabel);

    bbPubkeyLabel = new QLabel(tr("Pubkey: Unknown"), this);
    bbPubkeyLabel->setStyleSheet("QLabel { color: #666; }");
    statusLayout->addWidget(bbPubkeyLabel);

    bbRelaysLabel = new QLabel(tr("Relays: 0"), this);
    bbRelaysLabel->setStyleSheet("QLabel { color: #666; }");
    statusLayout->addWidget(bbRelaysLabel);

    statusLayout->addStretch();

    forceRefreshButton = new QPushButton(tr("Force Refresh"), this);
    forceRefreshButton->setToolTip(tr("Force immediate refresh from Nostr relays (bypasses 5-minute cache)"));
    forceRefreshButton->setMaximumWidth(120);
    connect(forceRefreshButton, &QPushButton::clicked, this, &GovernanceTab::onForceRefresh);
    statusLayout->addWidget(forceRefreshButton);

    mainLayout->addLayout(statusLayout);

    // ========== Governance Proposals Section ==========
    QGroupBox* proposalsGroup = new QGroupBox(tr("Governance Proposals"), this);
    QVBoxLayout* proposalsLayout = new QVBoxLayout(proposalsGroup);

    // Proposals control buttons
    QHBoxLayout* proposalsControlLayout = new QHBoxLayout();

    refreshProposalsButton = new QPushButton(tr("Refresh"), this);
    refreshProposalsButton->setToolTip(tr("Manually refresh proposals from Nostr relays"));
    connect(refreshProposalsButton, &QPushButton::clicked, this, &GovernanceTab::onRefreshProposals);
    proposalsControlLayout->addWidget(refreshProposalsButton);

    proposalsControlLayout->addStretch();

    // Asset filter dropdown
    QLabel* assetFilterLabel = new QLabel(tr("Asset:"), this);
    proposalsControlLayout->addWidget(assetFilterLabel);

    assetFilterCombo = new QComboBox(this);
    assetFilterCombo->setToolTip(tr("Filter proposals by asset"));
    assetFilterCombo->addItem(tr("All Assets"), "");
    assetFilterCombo->setMinimumWidth(150);
    connect(assetFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &GovernanceTab::onAssetFilterChanged);
    proposalsControlLayout->addWidget(assetFilterCombo);

    proposalsLayout->addLayout(proposalsControlLayout);

    // Proposals Table
    proposalsTable = new QTableWidget(this);
    proposalsTable->setColumnCount(8);
    proposalsTable->setHorizontalHeaderLabels({
        tr("Asset"),
        tr("Issuer"),
        tr("Flow"),
        tr("Policy Changes"),
        tr("Created"),
        tr("Expires"),
        tr("Status"),
        tr("Actions")
    });

    // Enable sorting
    proposalsTable->setSortingEnabled(true);

    // Configure column sizing
    proposalsTable->horizontalHeader()->setStretchLastSection(true);
    proposalsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);  // Asset
    proposalsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);  // Issuer
    proposalsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);  // Flow
    proposalsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);           // Policy Changes
    proposalsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);  // Created
    proposalsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);  // Expires
    proposalsTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);  // Status
    proposalsTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Fixed);             // Actions
    proposalsTable->horizontalHeader()->resizeSection(7, 180);  // Fixed width for Actions buttons

    // Allow row selection
    proposalsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    proposalsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    proposalsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    proposalsTable->setAlternatingRowColors(true);
    proposalsTable->verticalHeader()->setVisible(false);

    proposalsLayout->addWidget(proposalsTable);
    proposalsGroup->setLayout(proposalsLayout);

    mainLayout->addWidget(proposalsGroup);

    // ========== Issuer Audit Log (Collapsible) ==========
    QGroupBox* issuerAuditGroup = new QGroupBox(tr("Issuer Audit Log (Private Governance)"), this);
    issuerAuditGroup->setCheckable(true);
    issuerAuditGroup->setChecked(false);  // Collapsed by default
    issuerAuditGroup->setToolTip(tr("Shows incoming private access requests and auto-sent responses"));
    QVBoxLayout* auditLayout = new QVBoxLayout(issuerAuditGroup);

    // Audit log table
    QTableWidget* auditTable = new QTableWidget(this);
    auditTable->setObjectName("issuerAuditTable");
    auditTable->setColumnCount(5);
    auditTable->setHorizontalHeaderLabels({
        tr("Time"),
        tr("Type"),
        tr("Proposal ID"),
        tr("Holder Pubkey"),
        tr("Status")
    });
    auditTable->horizontalHeader()->setStretchLastSection(true);
    auditTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    auditTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    auditTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    auditTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    auditTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    auditTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    auditTable->setAlternatingRowColors(true);
    auditTable->setMaximumHeight(150);

    auditLayout->addWidget(auditTable);

    QLabel* auditHint = new QLabel(
        tr("This section shows private governance activity as an issuer:\n"
           "• Incoming access requests from asset holders\n"
           "• Automatically sent proposal responses (when ownership verified)"),
        this);
    auditHint->setStyleSheet("QLabel { color: #666; font-size: 10px; padding: 5px; }");
    auditHint->setWordWrap(true);
    auditLayout->addWidget(auditHint);

    mainLayout->addWidget(issuerAuditGroup);

    setLayout(mainLayout);
}

void GovernanceTab::onRefreshProposals()
{
    updateProposalsList();
}

void GovernanceTab::onForceRefresh()
{
    if (!walletModel) return;

    LogPrintf("GovernanceTab::onForceRefresh() Force refreshing governance proposals from Nostr\n");

    // Disable button during refresh
    forceRefreshButton->setEnabled(false);
    forceRefreshButton->setText(tr("Refreshing..."));

    // Call force_refresh_governance RPC to bypass 5-minute cache
    bool success = walletModel->governanceForceRefresh();

    if (success) {
        LogPrintf("GovernanceTab::onForceRefresh() Successfully force refreshed from Nostr\n");
        // Now update the UI with fresh data
        updateProposalsList();
    } else {
        LogPrintf("GovernanceTab::onForceRefresh() ERROR: Force refresh failed\n");
        QMessageBox::warning(this, tr("Refresh Failed"),
            tr("Failed to refresh governance proposals from Nostr relays."));
    }

    // Re-enable button
    forceRefreshButton->setEnabled(true);
    forceRefreshButton->setText(tr("Force Refresh"));
}

void GovernanceTab::onAssetFilterChanged(int index)
{
    if (!assetFilterCombo) return;

    // Get selected asset from combo box data
    currentAssetFilter = assetFilterCombo->currentData().toString();

    LogPrintf("GovernanceTab::onAssetFilterChanged() Filter changed to: %s\n",
              currentAssetFilter.isEmpty() ? "All Assets" : currentAssetFilter.toStdString().c_str());

    // Re-render the proposals table with current filter
    updateProposalsList();
}

void GovernanceTab::updateBulletinBoardStatus()
{
    if (!walletModel) return;

    // Check if bulletin board is initialized by attempting to list governance proposals
    auto result = walletModel->governanceListProposals("", false);

    if (result.success) {
        if (!bbInitialized) {
            LogPrintf("GovernanceTab::updateBulletinBoardStatus() Bulletin board now INITIALIZED\n");
        }
        bbInitialized = true;
        bbStatusLabel->setText(tr("● Connected"));
        bbStatusLabel->setStyleSheet("QLabel { color: #388e3c; font-weight: bold; }");

        // Note: We don't have direct access to pubkey/relay count from governance API
        // but we can infer it's working if the RPC succeeds
        bbPubkeyLabel->setText(tr("Pubkey: Initialized"));
        bbRelaysLabel->setText(tr("Status: Ready"));
    } else {
        if (bbInitialized) {
            LogPrintf("GovernanceTab::updateBulletinBoardStatus() ERROR: Bulletin board became UNINITIALIZED! Error: %s\n",
                      result.error.toStdString().c_str());
        }
        bbInitialized = false;
        bbStatusLabel->setText(tr("● Not Initialized"));
        bbStatusLabel->setStyleSheet("QLabel { color: #d32f2f; font-weight: bold; }");
        bbPubkeyLabel->setText(tr("Pubkey: Unknown"));
        bbRelaysLabel->setText(tr("Status: %1").arg(result.error.left(40)));
    }
}

void GovernanceTab::updateProposalsList()
{
    if (!walletModel) {
        LogPrintf("GovernanceTab::updateProposalsList() ERROR: walletModel is null\n");
        return;
    }
    if (!bbInitialized) {
        LogPrintf("GovernanceTab::updateProposalsList() WARNING: BB not initialized, skipping update\n");
        return;
    }

    LogPrintf("GovernanceTab::updateProposalsList() Calling RPC...\n");

    // Call RPC to list governance proposals (filtered by currentAssetFilter if set)
    auto result = walletModel->governanceListProposals(currentAssetFilter, false);

    if (!result.success) {
        LogPrintf("GovernanceTab::updateProposalsList() RPC FAILED: %s\n", result.error.toStdString().c_str());
        return;
    }

    LogPrintf("GovernanceTab::updateProposalsList() RPC SUCCESS, got %d proposals\n", result.proposals.size());

    // Update cache timestamp on successful fetch
    lastCacheRefresh = QDateTime::currentDateTime();

    // Clear existing proposals
    proposalsTable->setRowCount(0);
    activeProposals.clear();

    // Populate table
    for (const QVariant& proposalVar : result.proposals) {
        QVariantMap proposal = proposalVar.toMap();

        ProposalInfo info;
        info.proposal_id = proposal["proposal_id"].toString();
        info.asset_id = proposal["asset_id"].toString();
        info.issuer_nostr_pubkey = proposal["issuer_nostr_pubkey"].toString();
        info.created_at = proposal["created_at"].toLongLong();
        info.expires_at = proposal["expires_at"].toLongLong();
        info.flow_type = proposal["flow_type"].toString();
        info.title = proposal.value("title").toString();
        info.is_expired = proposal["is_expired"].toBool();
        info.policy_changes = proposal["policy_changes"].toString();
        info.full_proposal = proposal;

        // Verify BIP-322 attestation
        info.bip322_verified = verifyBip322Attestation(proposal);

        // Verify all hashes (canonical ICU, witness bundle, template PSBT)
        verifyProposalHashes(info);

        LogPrintf("GovernanceTab::updateProposalsList() Proposal: id=%s, asset=%s, flow=%s, bip322=%d, hashes=[canonical=%d, witness=%d, psbt=%d]\n",
            info.proposal_id.toStdString().c_str(),
            info.asset_id.toStdString().c_str(),
            info.flow_type.toStdString().c_str(),
            info.bip322_verified,
            info.canonical_icu_hash_verified,
            info.witness_bundle_hash_verified,
            info.template_psbt_hash_verified);

        activeProposals[info.proposal_id] = info;

        // Add row to table
        int row = proposalsTable->rowCount();
        proposalsTable->insertRow(row);

        // Look up ticker from asset registry for friendly display
        QString assetDisplay = info.asset_id.left(16) + "...";
        if (walletModel) {
            QList<WalletModel::AssetInfo> assets = walletModel->listAssets();
            for (const auto& asset : assets) {
                if (asset.asset_id == info.asset_id) {
                    if (!asset.ticker.isEmpty()) {
                        assetDisplay = asset.ticker;
                    }
                    break;
                }
            }
        }
        proposalsTable->setItem(row, 0, new QTableWidgetItem(assetDisplay));
        proposalsTable->setItem(row, 1, new QTableWidgetItem(formatPubkey(info.issuer_nostr_pubkey)));
        proposalsTable->setItem(row, 2, new QTableWidgetItem(info.flow_type.toUpper()));
        proposalsTable->setItem(row, 3, new QTableWidgetItem(info.policy_changes));

        // Created column
        QTableWidgetItem* createdItem = new QTableWidgetItem(formatTimestamp(info.created_at));
        createdItem->setData(Qt::UserRole, QVariant::fromValue(static_cast<qlonglong>(info.created_at)));
        proposalsTable->setItem(row, 4, createdItem);

        // Expires column
        QTableWidgetItem* expiresItem = new QTableWidgetItem(formatTimestamp(info.expires_at));
        expiresItem->setData(Qt::UserRole, QVariant::fromValue(static_cast<qlonglong>(info.expires_at)));
        proposalsTable->setItem(row, 5, expiresItem);

        // Status column - show verification and expiry status
        QString statusText;
        QString statusColor;
        bool allVerified = info.bip322_verified &&
                          info.canonical_icu_hash_verified &&
                          info.witness_bundle_hash_verified &&
                          info.template_psbt_hash_verified;

        if (info.is_expired) {
            statusText = tr("Expired");
            statusColor = "#999";
        } else if (!info.bip322_verified) {
            statusText = tr("Invalid Sig");
            statusColor = "#d32f2f";
        } else if (!allVerified) {
            statusText = tr("Hash Fail");
            statusColor = "#d32f2f";
        } else {
            statusText = tr("Active");
            statusColor = "#388e3c";
        }

        QTableWidgetItem* statusItem = new QTableWidgetItem(statusText);
        statusItem->setForeground(QBrush(QColor(statusColor)));
        statusItem->setToolTip(info.verification_errors);  // Show error details on hover
        proposalsTable->setItem(row, 6, statusItem);

        // Action buttons
        QWidget* actionWidget = new QWidget(this);
        QVBoxLayout* actionLayout = new QVBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setSpacing(3);

        // Top row: Details and Vote buttons
        QHBoxLayout* buttonsRow = new QHBoxLayout();
        buttonsRow->setSpacing(6);

        // Details button (always available)
        QPushButton* detailsBtn = new QPushButton(tr("Details"), actionWidget);
        detailsBtn->setProperty("proposal_id", info.proposal_id);
        connect(detailsBtn, &QPushButton::clicked, this, &GovernanceTab::onViewDetails);
        buttonsRow->addWidget(detailsBtn);

        // Check if this is a private proposal
        QString flow_type = info.full_proposal.value("flow_type").toString();
        bool isPrivate = (flow_type == "private");
        bool hasTemplatePsbt = info.full_proposal.contains("template_psbt") &&
                               !info.full_proposal.value("template_psbt").toString().isEmpty();

        LogPrintf("GovernanceTab: Proposal %s - flow_type='%s', isPrivate=%d, hasTemplatePsbt=%d\n",
                  info.proposal_id.toStdString().substr(0, 16).c_str(),
                  flow_type.toStdString().c_str(),
                  isPrivate ? 1 : 0,
                  hasTemplatePsbt ? 1 : 0);

        // Vote button (only if active and ALL verifications pass)
        if (!info.is_expired && allVerified && hasTemplatePsbt) {
            QPushButton* voteBtn = new QPushButton(tr("Vote"), actionWidget);
            voteBtn->setProperty("proposal_id", info.proposal_id);
            voteBtn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
            connect(voteBtn, &QPushButton::clicked, this, &GovernanceTab::onVote);
            buttonsRow->addWidget(voteBtn);
        }

        actionLayout->addLayout(buttonsRow);

        // Bottom row: Private access status (for private proposals)
        if (isPrivate && !info.is_expired) {
            QLabel* statusLabel = new QLabel(actionWidget);
            statusLabel->setObjectName("privateStatusLabel");  // For easy finding later
            statusLabel->setStyleSheet("QLabel { font-size: 10px; padding: 2px; }");

            if (!hasTemplatePsbt) {
                // No template PSBT yet - need to request access
                statusLabel->setText(tr("🔒 Private - Access Required"));
                statusLabel->setStyleSheet("QLabel { color: #ff6f00; font-size: 10px; font-weight: bold; }");

                // Add "Request Access" button
                QPushButton* requestBtn = new QPushButton(tr("Request Access"), actionWidget);
                requestBtn->setProperty("proposal_id", info.proposal_id);
                requestBtn->setStyleSheet("QPushButton { background-color: #ff6f00; color: white; font-size: 10px; }");
                connect(requestBtn, &QPushButton::clicked, [this, info]() {
                    // This would show the dialog from TreasuryPage
                    QMessageBox::information(this, tr("Request Private Access"),
                        tr("Private access request dialog coming from TreasuryPage.\n\nProposal: %1")
                        .arg(info.proposal_id.left(16) + "..."));
                });
                actionLayout->addWidget(requestBtn);
            } else if (allVerified) {
                // Has template PSBT and verified
                statusLabel->setText(tr("✓ Private Access Granted"));
                statusLabel->setStyleSheet("QLabel { color: #388e3c; font-size: 10px; font-weight: bold; }");
            } else {
                // Has template PSBT but verification failed
                statusLabel->setText(tr("⚠ Received - Verification Failed"));
                statusLabel->setStyleSheet("QLabel { color: #d32f2f; font-size: 10px; }");
            }

            actionLayout->addWidget(statusLabel);
        }

        actionWidget->setLayout(actionLayout);
        proposalsTable->setCellWidget(row, 7, actionWidget);
    }

    // Populate asset filter dropdown from wallet's asset registry
    if (assetFilterCombo && walletModel) {
        QString currentSelection = currentAssetFilter;

        assetFilterCombo->blockSignals(true);

        assetFilterCombo->clear();
        assetFilterCombo->addItem(tr("All Assets"), "");

        QList<WalletModel::AssetInfo> assets = walletModel->listAssets();

        for (const auto& asset : assets) {
            QString displayName = asset.ticker.isEmpty() ? asset.asset_id.left(8) + "..." : asset.ticker;
            assetFilterCombo->addItem(displayName, asset.asset_id);
        }

        // Restore selection
        int index = assetFilterCombo->findData(currentSelection);
        if (index >= 0) {
            assetFilterCombo->setCurrentIndex(index);
        }

        assetFilterCombo->blockSignals(false);
    }

    // PR3 OPTION 3: Poll for private proposal responses and update issuer audit log
    // Check if we've received template PSBTs for any private proposals
    if (clientModel) {
        try {
            UniValue params(UniValue::VARR);
            UniValue dmResult = clientModel->node().executeRpc("cosign.process_governance_dms", params, "");

            // Update issuer audit log table
            QTableWidget* auditTable = this->findChild<QTableWidget*>("issuerAuditTable");
            if (auditTable) {
                // Add incoming access requests
                if (dmResult.exists("access_requests") && dmResult["access_requests"].isArray()) {
                    const UniValue& requests = dmResult["access_requests"];
                    for (size_t i = 0; i < requests.size(); i++) {
                        const UniValue& req = requests[i];
                        int row = auditTable->rowCount();
                        auditTable->insertRow(row);

                        QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
                        QString proposalId = QString::fromStdString(req["proposal_id"].get_str()).left(16) + "...";
                        QString holderPubkey = QString::fromStdString(req["holder_nostr_pubkey"].get_str()).left(16) + "...";
                        bool verified = req.exists("ownership_verified") && req["ownership_verified"].get_bool();

                        auditTable->setItem(row, 0, new QTableWidgetItem(timestamp));
                        auditTable->setItem(row, 1, new QTableWidgetItem(tr("📥 Request")));
                        auditTable->setItem(row, 2, new QTableWidgetItem(proposalId));
                        auditTable->setItem(row, 3, new QTableWidgetItem(holderPubkey));

                        QTableWidgetItem* statusItem = new QTableWidgetItem(
                            verified ? tr("✓ Verified") : tr("✗ Failed")
                        );
                        statusItem->setForeground(QBrush(QColor(verified ? "#388e3c" : "#d32f2f")));
                        auditTable->setItem(row, 4, statusItem);
                    }
                }

                // Add auto-sent responses
                if (dmResult.exists("auto_sent_responses") && dmResult["auto_sent_responses"].isArray()) {
                    const UniValue& sent = dmResult["auto_sent_responses"];
                    for (size_t i = 0; i < sent.size(); i++) {
                        const UniValue& s = sent[i];
                        int row = auditTable->rowCount();
                        auditTable->insertRow(row);

                        QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
                        QString proposalId = QString::fromStdString(s["proposal_id"].get_str()).left(16) + "...";
                        QString holderPubkey = QString::fromStdString(s["holder_pubkey"].get_str()).left(16) + "...";

                        auditTable->setItem(row, 0, new QTableWidgetItem(timestamp));
                        auditTable->setItem(row, 1, new QTableWidgetItem(tr("📤 Auto-Sent")));
                        auditTable->setItem(row, 2, new QTableWidgetItem(proposalId));
                        auditTable->setItem(row, 3, new QTableWidgetItem(holderPubkey));

                        QTableWidgetItem* statusItem = new QTableWidgetItem(tr("✓ Sent"));
                        statusItem->setForeground(QBrush(QColor("#388e3c")));
                        auditTable->setItem(row, 4, statusItem);

                        LogPrintf("GovernanceTab: Audit log - auto-sent proposal %s to %s\n",
                                  proposalId.toStdString(), holderPubkey.toStdString());
                    }
                }

                // Limit table to last 50 entries
                while (auditTable->rowCount() > 50) {
                    auditTable->removeRow(0);
                }
            }

            // Process proposal responses (holder side)
            if (dmResult.exists("proposal_responses") && dmResult["proposal_responses"].isArray()) {
                const UniValue& responses = dmResult["proposal_responses"];

                for (size_t i = 0; i < responses.size(); i++) {
                    const UniValue& resp = responses[i];
                    std::string proposal_id = resp["proposal_id"].get_str();
                    QString qProposalId = QString::fromStdString(proposal_id);

                    // Check if this response is for one of our proposals
                    if (activeProposals.contains(qProposalId)) {
                        ProposalInfo& info = activeProposals[qProposalId];

                        // Merge the private data into our cached proposal
                        if (resp.exists("template_psbt")) {
                            QString template_psbt = QString::fromStdString(resp["template_psbt"].get_str());
                            info.full_proposal["template_psbt"] = template_psbt;

                            LogPrintf("GovernanceTab: Received template_psbt for private proposal %s\n",
                                      proposal_id);
                        }

                        if (resp.exists("template_psbt_hash")) {
                            info.full_proposal["template_psbt_hash"] =
                                QString::fromStdString(resp["template_psbt_hash"].get_str());
                        }

                        if (resp.exists("icu_text")) {
                            info.full_proposal["icu_text"] =
                                QString::fromStdString(resp["icu_text"].get_str());
                        }

                        if (resp.exists("witness_bundle")) {
                            info.full_proposal["witness_bundle"] =
                                QString::fromStdString(resp["witness_bundle"].get_str());
                        }

                        // Re-verify hashes now that we have the full data
                        verifyProposalHashes(info);

                        // Update the row to enable voting if everything verified
                        updateProposalRow(qProposalId, info);
                    }
                }
            }
        } catch (const std::exception& e) {
            LogPrintf("GovernanceTab: Failed to poll for private responses: %s\n", e.what());
            // Don't show error to user - polling is background operation
        }
    }
}

void GovernanceTab::updateProposalRow(const QString& proposal_id, const ProposalInfo& info)
{
    // Find the row for this proposal
    for (int row = 0; row < proposalsTable->rowCount(); row++) {
        QWidget* actionWidget = proposalsTable->cellWidget(row, 7);
        if (!actionWidget) continue;

        QPushButton* detailsBtn = actionWidget->findChild<QPushButton*>();
        if (!detailsBtn) continue;

        if (detailsBtn->property("proposal_id").toString() == proposal_id) {
            // Update status column
            bool allVerified = info.bip322_verified &&
                              info.canonical_icu_hash_verified &&
                              info.witness_bundle_hash_verified &&
                              info.template_psbt_hash_verified;

            QString statusText;
            QString statusColor;

            if (info.is_expired) {
                statusText = tr("Expired");
                statusColor = "#999";
            } else if (!info.bip322_verified) {
                statusText = tr("Invalid Sig");
                statusColor = "#d32f2f";
            } else if (!allVerified) {
                statusText = tr("Hash Fail");
                statusColor = "#d32f2f";
            } else {
                statusText = tr("Active");
                statusColor = "#388e3c";
            }

            QTableWidgetItem* statusItem = proposalsTable->item(row, 6);
            if (statusItem) {
                statusItem->setText(statusText);
                statusItem->setForeground(QBrush(QColor(statusColor)));
                statusItem->setToolTip(info.verification_errors);
            }

            // Update private access status and add Vote button
            QVBoxLayout* vLayout = qobject_cast<QVBoxLayout*>(actionWidget->layout());
            if (vLayout) {
                // Find the buttons row
                QHBoxLayout* buttonsRow = qobject_cast<QHBoxLayout*>(vLayout->itemAt(0)->layout());

                // Add Vote button if it doesn't exist and all verified
                bool hasTemplatePsbt = info.full_proposal.contains("template_psbt") &&
                                      !info.full_proposal.value("template_psbt").toString().isEmpty();

                if (!info.is_expired && allVerified && hasTemplatePsbt && buttonsRow) {
                    // Check if Vote button already exists
                    bool hasVoteButton = false;
                    for (int i = 0; i < buttonsRow->count(); i++) {
                        QWidget* w = buttonsRow->itemAt(i)->widget();
                        if (QPushButton* btn = qobject_cast<QPushButton*>(w)) {
                            if (btn->text() == tr("Vote")) {
                                hasVoteButton = true;
                                break;
                            }
                        }
                    }

                    if (!hasVoteButton) {
                        QPushButton* voteBtn = new QPushButton(tr("Vote"), actionWidget);
                        voteBtn->setProperty("proposal_id", proposal_id);
                        voteBtn->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
                        connect(voteBtn, &QPushButton::clicked, this, &GovernanceTab::onVote);
                        buttonsRow->addWidget(voteBtn);

                        LogPrintf("GovernanceTab: Enabled voting for private proposal %s\n",
                                  proposal_id.toStdString());
                    }
                }

                // Update status label
                QLabel* statusLabel = actionWidget->findChild<QLabel*>("privateStatusLabel");
                if (statusLabel) {
                    if (hasTemplatePsbt && allVerified) {
                        statusLabel->setText(tr("✓ Private Access Granted"));
                        statusLabel->setStyleSheet("QLabel { color: #388e3c; font-size: 10px; font-weight: bold; }");
                    } else if (hasTemplatePsbt) {
                        statusLabel->setText(tr("⚠ Received - Verification Failed"));
                        statusLabel->setStyleSheet("QLabel { color: #d32f2f; font-size: 10px; }");
                    }

                    // Remove "Request Access" button if it exists
                    for (int i = vLayout->count() - 1; i >= 0; i--) {
                        QWidget* w = vLayout->itemAt(i)->widget();
                        if (QPushButton* btn = qobject_cast<QPushButton*>(w)) {
                            if (btn->text() == tr("Request Access")) {
                                btn->deleteLater();
                            }
                        }
                    }
                }
            }

            break;
        }
    }
}

void GovernanceTab::onViewDetails()
{
    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) return;

    QString proposal_id = button->property("proposal_id").toString();
    if (proposal_id.isEmpty() || !activeProposals.contains(proposal_id)) {
        QMessageBox::warning(this, tr("Error"), tr("Proposal not found"));
        return;
    }

    ProposalInfo info = activeProposals[proposal_id];
    showProposalDetailsDialog(info);
}

void GovernanceTab::onVote()
{
    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if (!button) return;

    QString proposal_id = button->property("proposal_id").toString();
    if (proposal_id.isEmpty() || !activeProposals.contains(proposal_id)) {
        QMessageBox::warning(this, tr("Error"), tr("Proposal not found"));
        return;
    }

    ProposalInfo info = activeProposals[proposal_id];

    // Verify BIP-322 attestation one more time before voting
    if (!info.bip322_verified) {
        QMessageBox::warning(this, tr("Vote Failed"),
            tr("Cannot vote: BIP-322 attestation is invalid.\n\nError: %1")
            .arg(info.bip322_error));
        return;
    }

    // Show confirmation with proposal details
    QMessageBox::StandardButton confirm = QMessageBox::question(
        this,
        tr("Confirm Vote"),
        tr("Vote on governance proposal?\n\nAsset: %1\nIssuer: %2\n\nPolicy Changes:\n%3\n\nThis will sign a ballot PSBT voting for this proposal.")
            .arg(info.asset_id.left(16) + "...")
            .arg(formatPubkey(info.issuer_nostr_pubkey))
            .arg(info.policy_changes),
        QMessageBox::Yes | QMessageBox::No
    );

    if (confirm != QMessageBox::Yes) {
        return;
    }

    // Create governance session for tracking (PR2 requirement)
    // Note: For public flow, this is just a tracking session (no crypto handshake needed)
    // PR3 will add real interactive sessions for private flow
    QString sessionId = QString("gov_%1").arg(proposal_id.left(16));

    if (sessionManager) {
        BridgeSessionManager::SessionInfo sessionInfo;
        sessionInfo.session_id = sessionId;
        sessionInfo.sas = tr("N/A (public vote)");
        sessionInfo.sas_numeric = "";
        sessionInfo.state = "ballot_signing";
        sessionInfo.transport = "bulletin_board";
        sessionInfo.relay_url = "";
        sessionInfo.started_timestamp = QDateTime::currentSecsSinceEpoch();
        sessionInfo.handshake_complete = true;  // Public flow has no handshake
        sessionInfo.is_initiator = false;  // Holder is responding to issuer's proposal
        sessionInfo.purpose = BridgeSessionManager::SessionPurpose::Governance;
        sessionInfo.proposal_id = proposal_id;
        sessionInfo.asset_id = info.asset_id;

        sessionManager->addSession(sessionInfo);
        LogPrintf("GovernanceTab::onVote() Created tracking session: %s\n", sessionId.toStdString().c_str());
    }

    try {
        // Extract template PSBT from proposal
        QString template_psbt = info.full_proposal.value("template_psbt").toString();

        // Debug: Log what fields are available
        LogPrintf("GovernanceTab::onVote() Proposal fields available:\n");
        for (const QString& key : info.full_proposal.keys()) {
            LogPrintf("  - %s: %s\n", key.toStdString().c_str(),
                     info.full_proposal.value(key).toString().left(50).toStdString().c_str());
        }

        if (template_psbt.isEmpty()) {
            QString errorDetails = tr("This proposal does not include a template PSBT.\n\n");

            // Check flow type
            QString flow = info.full_proposal.value("flow_type").toString();
            if (flow == "private") {
                errorDetails += tr("This is a PRIVATE flow proposal - private voting will be implemented in PR3.");
            } else {
                errorDetails += tr("Flow type: %1\n").arg(flow);
                errorDetails += tr("Proposal ID: %1\n\n").arg(info.proposal_id);
                errorDetails += tr("Available fields: %1").arg(info.full_proposal.keys().join(", "));
            }

            QMessageBox::warning(this, tr("Vote Failed"), errorDetails);
            return;
        }

        LogPrintf("GovernanceTab::onVote() Template PSBT found, length=%d\n", template_psbt.length());

        // Verify template PSBT hash matches claimed hash in proposal
        QString claimed_hash = info.full_proposal.value("template_psbt_hash").toString();
        if (!claimed_hash.isEmpty()) {
            // Compute SHA256 of template PSBT
            QByteArray psbtBytes = template_psbt.toUtf8();
            QByteArray hashBytes = QCryptographicHash::hash(psbtBytes, QCryptographicHash::Sha256);
            QString computed_hash = hashBytes.toHex();

            if (computed_hash != claimed_hash) {
                QMessageBox::critical(this, tr("Vote Failed"),
                    tr("Template PSBT hash mismatch!\n\n"
                       "The template PSBT does not match the hash committed in the proposal.\n"
                       "This could indicate tampering or corruption.\n\n"
                       "Expected: %1\n"
                       "Got: %2\n\n"
                       "Voting has been aborted for your safety.").arg(claimed_hash).arg(computed_hash));
                return;
            }

            LogPrintf("GovernanceTab::onVote() Template PSBT hash verified: %s\n", computed_hash.toStdString().c_str());
        } else {
            LogPrintf("GovernanceTab::onVote() WARNING: No template_psbt_hash in proposal, skipping verification\n");
        }

        // Get holder's asset UTXOs for voting
        if (!clientModel) {
            throw std::runtime_error("ClientModel not available");
        }

        UniValue listParams(UniValue::VARR);
        UniValue assetArray(UniValue::VARR);
        assetArray.push_back(info.asset_id.toStdString());
        listParams.push_back(assetArray);

        UniValue utxosResult = clientModel->node().executeRpc("listassetutxos",
                                                              listParams,
                                                              walletModel->getWalletName().toStdString());

        if (!utxosResult.isArray() || utxosResult.size() == 0) {
            QMessageBox::warning(this, tr("Vote Failed"),
                tr("You don't own any UTXOs for this asset.\n\n"
                   "You must hold asset units to vote on governance proposals."));
            return;
        }

        // Show UTXO selection dialog for holders to choose which UTXOs to vote with
        QDialog utxoDialog(this);
        utxoDialog.setWindowTitle(tr("Select Voting UTXOs"));
        utxoDialog.resize(600, 400);
        QVBoxLayout* dialogLayout = new QVBoxLayout(&utxoDialog);

        QLabel* instructionLabel = new QLabel(
            tr("Select which UTXOs to use for voting:\n\n"
               "Your voting power is proportional to the asset units in each UTXO.\n"
               "You can select multiple UTXOs to increase your voting weight."),
            &utxoDialog);
        instructionLabel->setWordWrap(true);
        dialogLayout->addWidget(instructionLabel);

        QTableWidget* utxoTable = new QTableWidget(&utxoDialog);
        utxoTable->setColumnCount(5);
        utxoTable->setHorizontalHeaderLabels({tr("Select"), tr("Txid"), tr("Vout"), tr("Asset Units"), tr("Confirmations")});
        utxoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        utxoTable->horizontalHeader()->setStretchLastSection(false);
        utxoTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        utxoTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        utxoTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        utxoTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        utxoTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

        // Populate UTXO table
        for (size_t i = 0; i < utxosResult.size(); ++i) {
            const UniValue& utxo = utxosResult[i];
            int row = utxoTable->rowCount();
            utxoTable->insertRow(row);

            QString txid = QString::fromStdString(utxo["txid"].get_str());
            int vout = utxo["vout"].getInt<int>();
            uint64_t amount = utxo["asset_units"].getInt<uint64_t>();
            int confirmations = utxo.exists("confirmations") ? utxo["confirmations"].getInt<int>() : 0;

            // Checkbox in first column
            QTableWidgetItem* checkItem = new QTableWidgetItem();
            checkItem->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
            checkItem->setCheckState(i == 0 ? Qt::Checked : Qt::Unchecked);  // Pre-select first UTXO
            checkItem->setData(Qt::UserRole, txid);
            checkItem->setData(Qt::UserRole + 1, vout);
            utxoTable->setItem(row, 0, checkItem);

            utxoTable->setItem(row, 1, new QTableWidgetItem(txid.left(16) + "..."));
            utxoTable->setItem(row, 2, new QTableWidgetItem(QString::number(vout)));
            utxoTable->setItem(row, 3, new QTableWidgetItem(QString::number(amount)));
            utxoTable->setItem(row, 4, new QTableWidgetItem(QString::number(confirmations)));
        }

        dialogLayout->addWidget(utxoTable);

        QLabel* totalLabel = new QLabel(&utxoDialog);
        dialogLayout->addWidget(totalLabel);

        // Update total when selection changes
        auto updateTotal = [utxoTable, totalLabel]() {
            uint64_t total = 0;
            int count = 0;
            for (int row = 0; row < utxoTable->rowCount(); ++row) {
                QTableWidgetItem* checkItem = utxoTable->item(row, 0);
                if (checkItem && checkItem->checkState() == Qt::Checked) {
                    QString amountStr = utxoTable->item(row, 3)->text();
                    total += amountStr.toULongLong();
                    count++;
                }
            }
            totalLabel->setText(tr("<b>Total voting power:</b> %1 units (%2 UTXOs selected)")
                .arg(total).arg(count));
        };

        connect(utxoTable, &QTableWidget::itemChanged, updateTotal);
        updateTotal();  // Initial update

        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &utxoDialog);
        connect(buttonBox, &QDialogButtonBox::accepted, &utxoDialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &utxoDialog, &QDialog::reject);
        dialogLayout->addWidget(buttonBox);

        if (utxoDialog.exec() != QDialog::Accepted) {
            return;  // User cancelled
        }

        // Collect selected UTXOs
        UniValue utxoArray(UniValue::VARR);
        for (int row = 0; row < utxoTable->rowCount(); ++row) {
            QTableWidgetItem* checkItem = utxoTable->item(row, 0);
            if (checkItem && checkItem->checkState() == Qt::Checked) {
                UniValue utxoObj(UniValue::VOBJ);
                utxoObj.pushKV("txid", checkItem->data(Qt::UserRole).toString().toStdString());
                utxoObj.pushKV("vout", checkItem->data(Qt::UserRole + 1).toInt());
                utxoArray.push_back(utxoObj);
            }
        }

        if (utxoArray.size() == 0) {
            QMessageBox::warning(this, tr("No Selection"),
                tr("Please select at least one UTXO to vote with."));
            return;
        }

        // Build ballot using the ballot RPC
        // This inserts holder UTXOs as voting inputs and signs with SIGHASH_ANYONECANPAY|ALL
        UniValue ballotParams(UniValue::VARR);
        ballotParams.push_back(template_psbt.toStdString());
        ballotParams.push_back(utxoArray);

        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            QMessageBox::warning(this, tr("Wallet Locked"),
                tr("Please unlock the wallet to sign the governance ballot."));
            return;
        }

        UniValue ballotResult = clientModel->node().executeRpc("ballot",
                                                               ballotParams,
                                                               walletModel->getWalletName().toStdString());

        if (!ballotResult.isObject() || !ballotResult.exists("psbt")) {
            throw std::runtime_error("ballot RPC failed or returned invalid response");
        }

        QString signed_psbt = QString::fromStdString(ballotResult["psbt"].get_str());
        uint64_t ballot_units = ballotResult["ballot_units"].getInt<uint64_t>();

        if (signed_psbt.isEmpty()) {
            throw std::runtime_error("Signed ballot PSBT is empty");
        }

        // PR3: Route ballot based on proposal flow type (private vs public)
        QString flow_type = info.full_proposal.value("flow_type").toString();
        bool isPrivate = (flow_type == "private");

        QString ballot_id;
        UniValue publishResult;

        if (isPrivate) {
            // Private flow: Send ballot via encrypted DM to issuer
            QString issuer_nostr_pubkey = info.full_proposal.value("issuer_nostr_pubkey").toString();
            if (issuer_nostr_pubkey.isEmpty()) {
                throw std::runtime_error("Cannot submit private ballot: issuer nostr pubkey missing");
            }

            UniValue dmParams(UniValue::VARR);
            dmParams.push_back(info.proposal_id.toStdString());
            dmParams.push_back(info.asset_id.toStdString());
            dmParams.push_back(issuer_nostr_pubkey.toStdString());
            dmParams.push_back(signed_psbt.toStdString());
            dmParams.push_back((int64_t)ballot_units);

            publishResult = clientModel->node().executeRpc("cosign.send_governance_ballot_dm",
                                                           dmParams, "");

            if (!publishResult.isObject() || !publishResult.exists("ballot_id")) {
                throw std::runtime_error("Failed to send private ballot via DM");
            }

            ballot_id = QString::fromStdString(publishResult["ballot_id"].get_str());

            LogPrintf("GovernanceTab::onVote() Sent private ballot via DM for proposal %s\n",
                      info.proposal_id.toStdString().c_str());

        } else {
            // Public flow: Publish ballot to bulletin board
            UniValue ballotPayload(UniValue::VOBJ);
            ballotPayload.pushKV("version", 1);
            ballotPayload.pushKV("proposal_id", info.proposal_id.toStdString());
            ballotPayload.pushKV("asset_id", info.asset_id.toStdString());
            ballotPayload.pushKV("signed_psbt", signed_psbt.toStdString());
            ballotPayload.pushKV("ballot_units", ballot_units);
            ballotPayload.pushKV("voter_timestamp", QDateTime::currentSecsSinceEpoch());

            UniValue publishParams(UniValue::VARR);
            publishParams.push_back(ballotPayload);

            publishResult = clientModel->node().executeRpc("cosign.publish_ballot",
                                                           publishParams, "");

            if (!publishResult.isObject() || !publishResult.exists("ballot_id")) {
                throw std::runtime_error("Failed to publish ballot to bulletin board");
            }

            ballot_id = QString::fromStdString(publishResult["ballot_id"].get_str());

            LogPrintf("GovernanceTab::onVote() Published public ballot for proposal %s\n",
                      info.proposal_id.toStdString().c_str());
        }

        // Update governance session to show ballot published
        if (sessionManager) {
            BridgeSessionManager::SessionInfo updatedSession = sessionManager->getSession(sessionId);
            updatedSession.state = "ballot_published";
            sessionManager->updateSession(sessionId, updatedSession);
            LogPrintf("GovernanceTab::onVote() Updated session %s to ballot_published\n", sessionId.toStdString().c_str());
        }

        // Build UTXO summary for success message
        QString utxoSummary;
        if (utxoArray.size() == 1) {
            // Single UTXO - show details
            QString txid = QString::fromStdString(utxoArray[0]["txid"].get_str());
            int vout = utxoArray[0]["vout"].getInt<int>();
            utxoSummary = QString("%1:%2").arg(txid.left(16) + "...").arg(vout);
        } else {
            // Multiple UTXOs - show count
            utxoSummary = tr("%1 UTXOs selected").arg(utxoArray.size());
        }

        // Show success message
        QMessageBox::information(this, tr("Vote Submitted"),
            tr("Your ballot has been signed and published to the bulletin board!\n\n"
               "Proposal ID: %1\n"
               "Ballot ID: %2\n"
               "Voting Units: %3\n"
               "UTXOs: %4\n\n"
               "The issuer can now collect your vote and finalize the rotation if quorum is reached.")
                .arg(info.proposal_id.left(16) + "...")
                .arg(ballot_id.left(16) + "...")
                .arg(ballot_units)
                .arg(utxoSummary));

    } catch (const std::exception& e) {
        // Update session to show error
        if (sessionManager && sessionManager->hasSession(sessionId)) {
            BridgeSessionManager::SessionInfo errorSession = sessionManager->getSession(sessionId);
            errorSession.state = "vote_failed";
            sessionManager->updateSession(sessionId, errorSession);
        }

        QMessageBox::critical(this, tr("Vote Failed"),
            tr("Failed to sign ballot:\n\n%1").arg(QString::fromStdString(e.what())));
    }
}

bool GovernanceTab::verifyBip322Attestation(const QVariantMap& proposal)
{
    if (!walletModel) return false;

    // Extract ICU attestation from proposal
    QVariantMap icu_attestation = proposal.value("icu_attestation").toMap();
    if (icu_attestation.isEmpty()) {
        LogPrintf("GovernanceTab::verifyBip322Attestation() No icu_attestation field\n");
        return false;
    }

    QString address = icu_attestation["address"].toString();
    QString message = icu_attestation["message"].toString();
    QString signature = icu_attestation["signature"].toString();

    if (address.isEmpty() || message.isEmpty() || signature.isEmpty()) {
        LogPrintf("GovernanceTab::verifyBip322Attestation() Missing attestation fields\n");
        return false;
    }

    // Verify expected message format: "TENSORCASH_GOVERNANCE:{proposal_id}"
    QString proposal_id = proposal["proposal_id"].toString();
    QString expected_message = QString("TENSORCASH_GOVERNANCE:%1").arg(proposal_id);
    if (message != expected_message) {
        LogPrintf("GovernanceTab::verifyBip322Attestation() Message mismatch: got '%s', expected '%s'\n",
            message.toStdString().c_str(), expected_message.toStdString().c_str());
        return false;
    }

    // Use proper BIP-322 verification for all address types
    bool verified = walletModel->verifyMessageBip322(address, signature, message);

    LogPrintf("GovernanceTab::verifyBip322Attestation() BIP-322 verification result: %d (address=%s, sig_len=%d)\n",
        verified, address.toStdString().c_str(), signature.length());

    return verified;
}

QString GovernanceTab::computeSha256(const QString& text)
{
    QByteArray bytes = text.toUtf8();
    QByteArray hash = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
    return QString::fromLatin1(hash.toHex());
}

void GovernanceTab::verifyProposalHashes(ProposalInfo& info)
{
    QStringList errors;

    // 1. Verify canonical ICU hash (if both hash and text are provided)
    QString canonical_hash = info.full_proposal.value("canonical_icu_hash").toString();
    QString icu_text = info.full_proposal.value("icu_text").toString();

    if (!canonical_hash.isEmpty()) {
        if (!icu_text.isEmpty()) {
            // Use the SAME RPC the issuance/rotation path uses
            // (buildcanonicalicupayload) so verification hashes the
            // canonicalised text exactly the way the chain stored it.
            // A raw SHA256 over icu_text would skip NFC + CRLF folding
            // and reject every legitimate public proposal.
            QString computed;
            if (clientModel) {
                UniValue witnessUniValue;
                witnessUniValue.read(std::string("{\"version\":\"1.0\",\"canonical_hash\":\"placeholder\"}"));

                UniValue buildParams(UniValue::VARR);
                buildParams.push_back(icu_text.toStdString());
                buildParams.push_back(witnessUniValue);
                buildParams.push_back(0); // visibility doesn't affect canonical_hash

                std::string walletName = walletModel ? walletModel->getWalletName().toStdString() : std::string();
                try {
                    UniValue payloadResult = clientModel->node().executeRpc(
                        "buildcanonicalicupayload", buildParams, walletName);
                    computed = QString::fromStdString(payloadResult["canonical_hash"].get_str());
                } catch (const std::exception& e) {
                    LogPrintf("verifyProposalHashes: buildcanonicalicupayload RPC failed: %s\n", e.what());
                }
            }
            if (computed.isEmpty()) {
                info.canonical_icu_hash_verified = false;
                errors << tr("Canonical ICU hash verification failed (RPC unavailable)");
            } else {
                info.canonical_icu_hash_verified = (computed == canonical_hash);
                if (!info.canonical_icu_hash_verified) {
                    errors << tr("Canonical ICU hash mismatch (expected: %1, got: %2)")
                        .arg(canonical_hash).arg(computed);
                }
            }
        } else {
            // Hash provided but no text - suspicious, but acceptable for private flow
            info.canonical_icu_hash_verified = (info.flow_type != "public");
            if (!info.canonical_icu_hash_verified) {
                errors << tr("Public proposal missing ICU text");
            }
        }
    } else {
        // No hash provided - acceptable
        info.canonical_icu_hash_verified = true;
    }

    // 2. Verify witness bundle hash (if both hash and bundle are provided)
    QString witness_hash = info.full_proposal.value("witness_bundle_hash").toString();
    QString witness_bundle = info.full_proposal.value("witness_bundle").toString();

    if (!witness_hash.isEmpty()) {
        if (!witness_bundle.isEmpty()) {
            QString computed = computeSha256(witness_bundle);
            info.witness_bundle_hash_verified = (computed == witness_hash);
            if (!info.witness_bundle_hash_verified) {
                errors << tr("Witness bundle hash mismatch (expected: %1, got: %2)")
                    .arg(witness_hash).arg(computed);
            }
        } else {
            // Hash provided but no bundle - suspicious
            info.witness_bundle_hash_verified = false;
            errors << tr("Witness bundle hash provided but bundle missing");
        }
    } else {
        // No hash provided - acceptable (witness is optional)
        info.witness_bundle_hash_verified = true;
    }

    // 3. Verify template PSBT hash (if both hash and PSBT are provided)
    QString psbt_hash = info.full_proposal.value("template_psbt_hash").toString();
    QString template_psbt = info.full_proposal.value("template_psbt").toString();

    if (!psbt_hash.isEmpty()) {
        if (!template_psbt.isEmpty()) {
            QString computed = computeSha256(template_psbt);
            info.template_psbt_hash_verified = (computed == psbt_hash);
            if (!info.template_psbt_hash_verified) {
                errors << tr("Template PSBT hash mismatch (expected: %1, got: %2)")
                    .arg(psbt_hash).arg(computed);
            }
        } else {
            // Hash provided but no PSBT - suspicious for public flow
            info.template_psbt_hash_verified = (info.flow_type != "public");
            if (!info.template_psbt_hash_verified) {
                errors << tr("Public proposal missing template PSBT");
            }
        }
    } else {
        // No hash provided - suspicious (all proposals should have template PSBT hash)
        info.template_psbt_hash_verified = false;
        errors << tr("Template PSBT hash missing");
    }

    info.verification_errors = errors.join("; ");

    LogPrintf("GovernanceTab::verifyProposalHashes() proposal_id=%s: canonical=%d, witness=%d, psbt=%d, errors=%s\n",
        info.proposal_id.toStdString().c_str(),
        info.canonical_icu_hash_verified,
        info.witness_bundle_hash_verified,
        info.template_psbt_hash_verified,
        info.verification_errors.toStdString().c_str());
}

void GovernanceTab::showProposalDetailsDialog(const ProposalInfo& info)
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Governance Proposal Details"));
    dialog.resize(900, 720);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    [[maybe_unused]] auto computeSha256 = [](const QString& text) -> QString {
        QByteArray bytes = text.toUtf8();
        QByteArray hash = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
        return QString::fromLatin1(hash.toHex());
    };

    QString summaryHtml;
    summaryHtml += tr("<b>Proposal ID:</b> %1<br>").arg(info.proposal_id);
    summaryHtml += tr("<b>Asset ID:</b> %1<br>").arg(info.asset_id);
    summaryHtml += tr("<b>Issuer Pubkey:</b> %1<br>").arg(info.issuer_nostr_pubkey);
    summaryHtml += tr("<b>Flow Type:</b> %1<br>").arg(info.flow_type.toUpper());
    summaryHtml += tr("<b>Created:</b> %1<br>").arg(QDateTime::fromSecsSinceEpoch(info.created_at).toString());
    summaryHtml += tr("<b>Expires:</b> %1<br>").arg(QDateTime::fromSecsSinceEpoch(info.expires_at).toString());
    summaryHtml += tr("<b>Status:</b> %1<br>").arg(info.is_expired ? tr("EXPIRED") : tr("ACTIVE"));
    if (!info.title.isEmpty()) {
        summaryHtml += tr("<b>Title:</b> %1<br>").arg(info.title);
    }
    // Verification Status Summary
    bool allVerified = info.bip322_verified &&
                      info.canonical_icu_hash_verified &&
                      info.witness_bundle_hash_verified &&
                      info.template_psbt_hash_verified;

    summaryHtml += tr("<br><b>Verification Status:</b><br>");
    summaryHtml += tr("<table style='margin-left: 15px;'>");
    summaryHtml += tr("<tr><td>BIP-322 Signature:</td><td style='color: %2;'><b>%1</b></td></tr>")
        .arg(info.bip322_verified ? tr("✓ Valid") : tr("✗ Invalid"))
        .arg(info.bip322_verified ? "#388e3c" : "#d32f2f");
    summaryHtml += tr("<tr><td>Canonical ICU Hash:</td><td style='color: %2;'><b>%1</b></td></tr>")
        .arg(info.canonical_icu_hash_verified ? tr("✓ Valid") : tr("✗ Invalid"))
        .arg(info.canonical_icu_hash_verified ? "#388e3c" : "#d32f2f");
    summaryHtml += tr("<tr><td>Witness Bundle Hash:</td><td style='color: %2;'><b>%1</b></td></tr>")
        .arg(info.witness_bundle_hash_verified ? tr("✓ Valid") : tr("✗ Invalid"))
        .arg(info.witness_bundle_hash_verified ? "#388e3c" : "#d32f2f");
    summaryHtml += tr("<tr><td>Template PSBT Hash:</td><td style='color: %2;'><b>%1</b></td></tr>")
        .arg(info.template_psbt_hash_verified ? tr("✓ Valid") : tr("✗ Invalid"))
        .arg(info.template_psbt_hash_verified ? "#388e3c" : "#d32f2f");
    summaryHtml += tr("</table>");

    if (!allVerified) {
        summaryHtml += tr("<br><b style='color: #d32f2f;'>⚠ WARNING: DO NOT VOTE ON THIS PROPOSAL</b><br>");
        if (!info.verification_errors.isEmpty()) {
            summaryHtml += tr("<i>Errors: %1</i><br>").arg(info.verification_errors);
        }
    }

    summaryHtml += tr("<br><b>BIP-322 Attestation:</b><br>");
    QVariantMap attestation = info.full_proposal.value("icu_attestation").toMap();
    summaryHtml += tr("Address: %1<br>").arg(attestation.value("address").toString());
    summaryHtml += tr("Message: %1<br>").arg(attestation.value("message").toString());
    summaryHtml += tr("Signature: %1<br>").arg(attestation.value("signature").toString().left(64) + "...");

    summaryHtml += tr("<br><b>Policy Changes:</b><br>%1").arg(info.policy_changes.toHtmlEscaped().replace("\n", "<br>"));

    QLabel* summaryLabel = new QLabel(summaryHtml);
    summaryLabel->setTextFormat(Qt::RichText);
    summaryLabel->setWordWrap(true);
    layout->addWidget(summaryLabel);

    // Governance text viewer
    QString icu_text = info.full_proposal.value("icu_text").toString();
    QString canonical_hash = info.full_proposal.value("canonical_icu_hash").toString();
    QString textHeader = tr("<b>Governance Text</b>");
    if (info.flow_type != "public") {
        textHeader += tr(" (not published for private flows)");
    }
    layout->addWidget(new QLabel(textHeader));

    QString textContent;
    if (!canonical_hash.isEmpty()) {
        textContent += tr("Canonical Hash: %1\n").arg(canonical_hash);
        if (!icu_text.isEmpty()) {
            textContent += tr("Verification: %1\n\n")
                .arg(info.canonical_icu_hash_verified ? tr("✓ VERIFIED (cached)") : tr("✗ FAILED - DO NOT SIGN"));
        } else {
            textContent += tr("Verification: %1\n\n").arg(tr("(No text provided - private flow)"));
        }
    }
    textContent += icu_text;

    QPlainTextEdit* textEdit = new QPlainTextEdit(&dialog);
    textEdit->setReadOnly(true);
    textEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
    textEdit->setFont(QFont("Monospace", 9));
    textEdit->setMinimumHeight(240);
    textEdit->setPlainText(textContent);
    layout->addWidget(textEdit);

    // Witness viewer
    QString witness_bundle = info.full_proposal.value("witness_bundle").toString();
    QPlainTextEdit* witnessEdit = nullptr;
    if (!witness_bundle.isEmpty()) {
        layout->addWidget(new QLabel(tr("<b>Witness Bundle (JSON):</b>")));
        witnessEdit = new QPlainTextEdit(&dialog);
        witnessEdit->setReadOnly(true);
        witnessEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
        witnessEdit->setFont(QFont("Monospace", 9));
        witnessEdit->setMinimumHeight(200);
        witnessEdit->setPlainText(witness_bundle);
        layout->addWidget(witnessEdit);
    } else {
        layout->addWidget(new QLabel(tr("<i>No witness bundle was included with this proposal.</i>")));
    }

    // Actions: save & copy
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    QPushButton* saveButton = new QPushButton(tr("Save to File"), &dialog);
    connect(saveButton, &QPushButton::clicked, [&]() {
        QString suggested = QString("proposal_%1.txt").arg(info.proposal_id.left(16));
        QString fileName = QFileDialog::getSaveFileName(&dialog,
                                                        tr("Save Proposal Details"),
                                                        suggested,
                                                        tr("Text Files (*.txt);;All Files (*)"));
        if (fileName.isEmpty()) {
            return;
        }

        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(&dialog, tr("Save Failed"), tr("Unable to open %1 for writing").arg(fileName));
            return;
        }

        QTextStream out(&file);
        QString plainSummary = summaryLabel->text();
        plainSummary.replace("<br>", "\n");
        plainSummary.remove(QRegularExpression("<[^>]*>"));

        out << "===== GOVERNANCE PROPOSAL =====\n\n";
        out << plainSummary << "\n\n";
        out << "===== GOVERNANCE TEXT =====\n";
        out << textEdit->toPlainText() << "\n\n";
        out << "===== WITNESS BUNDLE =====\n";
        if (witnessEdit) {
            out << witnessEdit->toPlainText() << "\n";
        } else {
            out << "(not provided)\n";
        }
        file.close();
        QMessageBox::information(&dialog, tr("Saved"), tr("Proposal details saved to %1").arg(fileName));
    });
    buttonLayout->addWidget(saveButton);

    QPushButton* copyButton = new QPushButton(tr("Copy to Clipboard"), &dialog);
    connect(copyButton, &QPushButton::clicked, [&]() {
        QString plainSummary = summaryLabel->text();
        plainSummary.replace("<br>", "\n");
        plainSummary.remove(QRegularExpression("<[^>]*>"));

        QString combined;
        combined += "===== GOVERNANCE PROPOSAL =====\n\n";
        combined += plainSummary + "\n\n";
        combined += "===== GOVERNANCE TEXT =====\n";
        combined += textEdit->toPlainText() + "\n\n";
        combined += "===== WITNESS BUNDLE =====\n";
        if (witnessEdit) {
            combined += witnessEdit->toPlainText();
        } else {
            combined += "(not provided)";
        }

        QApplication::clipboard()->setText(combined);
        QMessageBox::information(&dialog, tr("Copied"), tr("Full proposal copied to clipboard"));
    });
    buttonLayout->addWidget(copyButton);

    buttonLayout->addStretch();

    QPushButton* closeButton = new QPushButton(tr("Close"), &dialog);
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    layout->addLayout(buttonLayout);

    dialog.exec();
}

QString GovernanceTab::formatTimestamp(int64_t timestamp)
{
    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
    qint64 secondsAgo = dt.secsTo(QDateTime::currentDateTime());

    if (secondsAgo < 60) {
        return tr("%1s ago").arg(secondsAgo);
    } else if (secondsAgo < 3600) {
        return tr("%1m ago").arg(secondsAgo / 60);
    } else if (secondsAgo < 86400) {
        return tr("%1h ago").arg(secondsAgo / 3600);
    } else {
        return tr("%1d ago").arg(secondsAgo / 86400);
    }
}

QString GovernanceTab::formatPubkey(const QString& pubkey)
{
    if (pubkey.length() <= 16) {
        return pubkey;
    }
    return pubkey.left(8) + "..." + pubkey.right(8);
}

QString GovernanceTab::formatPolicyChanges(const QVariantMap& proposed_policy) const
{
    QStringList changes;

    if (proposed_policy.contains("policy_quorum_bps")) {
        changes << tr("Quorum: %1 bps").arg(proposed_policy["policy_quorum_bps"].toInt());
    }
    if (proposed_policy.contains("issuance_cap_units")) {
        changes << tr("Cap: %1 units").arg(proposed_policy["issuance_cap_units"].toLongLong());
    }
    if (proposed_policy.contains("policy_epoch")) {
        changes << tr("Epoch: %1").arg(proposed_policy["policy_epoch"].toInt());
    }

    return changes.isEmpty() ? tr("(no changes)") : changes.join(", ");
}
