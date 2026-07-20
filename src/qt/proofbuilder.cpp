// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/proofbuilder.h>
#include <qt/walletmodel.h>
#include <logging.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QApplication>

ProofBuilder::ProofBuilder(
    WalletModel* walletModel,
    const QString& asset_id,
    const QString& message_context,
    QWidget* parent)
    : QDialog(parent)
    , m_walletModel(walletModel)
    , m_asset_id(asset_id)
    , m_message_context(message_context)
{
    LogPrintf("[ProofBuilder] Constructor called: asset_id=%s context=%s walletModel=%p\n",
              asset_id.toStdString(), message_context.toStdString(), walletModel);

    setWindowTitle(tr("Build Proof of Funds"));
    setMinimumSize(700, 500);

    setupUI();
    LogPrintf("[ProofBuilder] setupUI completed\n");
    loadUtxos();
    LogPrintf("[ProofBuilder] loadUtxos completed\n");
}

ProofBuilder::~ProofBuilder()
{
}

void ProofBuilder::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Asset info section
    QLabel* titleLabel = new QLabel(tr("<b>Proof of Funds Builder</b>"), this);
    mainLayout->addWidget(titleLabel);

    m_assetLabel = new QLabel(this);
    if (m_asset_id.isEmpty()) {
        m_assetLabel->setText(tr("Asset: <b>TSC (Native Coin)</b>"));
    } else {
        m_assetLabel->setText(tr("Asset ID: %1").arg(m_asset_id.left(16) + "..."));
    }
    m_assetLabel->setWordWrap(true);
    mainLayout->addWidget(m_assetLabel);

    // Instructions
    m_instructionsText = new QTextEdit(this);
    m_instructionsText->setReadOnly(true);
    m_instructionsText->setMaximumHeight(80);
    m_instructionsText->setHtml(
        tr("<p>Select one or more UTXOs to prove ownership of the required asset.</p>"
           "<p><b>Instructions:</b></p>"
           "<ul>"
           "<li>Check the UTXOs you want to include in the proof</li>"
           "<li>Click 'Generate Proofs' to sign with BIP-322</li>"
           "<li>The proof will be attached to your contract offer/request</li>"
           "</ul>")
    );
    mainLayout->addWidget(m_instructionsText);

    // UTXO selection table
    QLabel* utxoLabel = new QLabel(tr("Available UTXOs:"), this);
    mainLayout->addWidget(utxoLabel);

    m_utxoTable = new QTableWidget(this);
    m_utxoTable->setColumnCount(5);
    m_utxoTable->setHorizontalHeaderLabels({
        tr("Select"),
        tr("UTXO"),
        tr("Address"),
        tr("Amount"),
        tr("Confirmations")
    });
    m_utxoTable->horizontalHeader()->setStretchLastSection(false);
    m_utxoTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_utxoTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_utxoTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_utxoTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_utxoTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_utxoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_utxoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mainLayout->addWidget(m_utxoTable);

    connect(m_utxoTable, &QTableWidget::itemChanged, this, &ProofBuilder::onUtxoSelectionChanged);

    // Message preview
    QLabel* messageLabel = new QLabel(tr("Proof message format:"), this);
    mainLayout->addWidget(messageLabel);

    m_messagePreview = new QLineEdit(this);
    m_messagePreview->setReadOnly(true);
    m_messagePreview->setPlaceholderText(tr("Message will be shown after UTXO selection"));
    mainLayout->addWidget(m_messagePreview);

    // Status label
    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    mainLayout->addWidget(m_statusLabel);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_refreshButton = new QPushButton(tr("Refresh UTXOs"), this);
    connect(m_refreshButton, &QPushButton::clicked, this, &ProofBuilder::onRefreshUtxos);
    buttonLayout->addWidget(m_refreshButton);

    m_cancelButton = new QPushButton(tr("Cancel"), this);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(m_cancelButton);

    m_generateButton = new QPushButton(tr("Generate Proofs"), this);
    m_generateButton->setEnabled(false);
    connect(m_generateButton, &QPushButton::clicked, this, &ProofBuilder::onGenerateProofs);
    buttonLayout->addWidget(m_generateButton);

    mainLayout->addLayout(buttonLayout);
}

void ProofBuilder::loadUtxos()
{
    LogPrintf("[ProofBuilder] loadUtxos called\n");

    if (!m_walletModel) {
        LogPrintf("[ProofBuilder] ERROR: walletModel is null\n");
        m_statusLabel->setText(tr("<font color='red'>Error: Wallet model not available</font>"));
        return;
    }

    m_statusLabel->setText(tr("Loading UTXOs..."));
    QApplication::processEvents();

    LogPrintf("[ProofBuilder] Calling listAssetUTXOs for asset: %s\n", m_asset_id.toStdString());
    // Get asset UTXOs from wallet
    QList<QVariant> utxo_list = m_walletModel->listAssetUTXOs(m_asset_id);
    LogPrintf("[ProofBuilder] listAssetUTXOs returned %d UTXOs\n", utxo_list.size());

    // Block signals during clear to prevent crash from itemChanged signal accessing empty m_utxos
    m_utxoTable->blockSignals(true);
    m_utxos.clear();
    m_utxoTable->setRowCount(0);
    m_utxoTable->blockSignals(false);

    if (utxo_list.isEmpty()) {
        m_statusLabel->setText(tr("<font color='orange'>No UTXOs found for this asset in your wallet.</font>"));
        return;
    }

    // Populate table (block signals during population to prevent premature itemChanged signals)
    m_utxoTable->blockSignals(true);
    m_utxoTable->setRowCount(utxo_list.size());

    for (int i = 0; i < utxo_list.size(); ++i) {
        QVariantMap utxo = utxo_list[i].toMap();
        m_utxos.append(utxo);

        QString txid = utxo["txid"].toString();
        int vout = utxo["vout"].toInt();
        QString address = utxo["address"].toString();
        qint64 asset_units = utxo["asset_units"].toLongLong();
        int confirmations = utxo.value("confirmations", 0).toInt();

        // Checkbox
        QTableWidgetItem* checkItem = new QTableWidgetItem();
        checkItem->setCheckState(Qt::Unchecked);
        m_utxoTable->setItem(i, 0, checkItem);

        // UTXO ref
        QString utxo_ref = QString("%1:%2").arg(txid.left(8) + "...").arg(vout);
        m_utxoTable->setItem(i, 1, new QTableWidgetItem(utxo_ref));

        // Address
        QString short_addr = address.left(12) + "..." + address.right(8);
        m_utxoTable->setItem(i, 2, new QTableWidgetItem(short_addr));

        // Amount
        m_utxoTable->setItem(i, 3, new QTableWidgetItem(QString::number(asset_units)));

        // Confirmations
        m_utxoTable->setItem(i, 4, new QTableWidgetItem(QString::number(confirmations)));
    }
    m_utxoTable->blockSignals(false);

    m_statusLabel->setText(tr("Found %1 UTXO(s). Select UTXOs and click 'Generate Proofs'.").arg(utxo_list.size()));
}

void ProofBuilder::onRefreshUtxos()
{
    loadUtxos();
}

void ProofBuilder::onUtxoSelectionChanged()
{
    // Check if any UTXOs are selected
    bool hasSelection = false;
    for (int i = 0; i < m_utxoTable->rowCount(); ++i) {
        if (m_utxoTable->item(i, 0)->checkState() == Qt::Checked) {
            hasSelection = true;
            break;
        }
    }

    m_generateButton->setEnabled(hasSelection);

    // Update message preview with first selected UTXO
    if (hasSelection) {
        for (int i = 0; i < m_utxoTable->rowCount(); ++i) {
            if (m_utxoTable->item(i, 0)->checkState() == Qt::Checked) {
                QString address = m_utxos[i]["address"].toString();
                QString message = constructProofMessage(address, m_asset_id);
                m_messagePreview->setText(message);
                break;
            }
        }
    } else {
        m_messagePreview->clear();
    }
}

QString ProofBuilder::constructProofMessage(const QString& address, const QString& asset_id)
{
    // Format: TENSORCASH_PROOF:{context}:{asset_id}
    // context is provided by caller (e.g., "offer_id:role" or just "offer_id:lender")
    // For native asset, use "TSC" as the asset identifier
    QString asset_identifier = asset_id.isEmpty() ? QStringLiteral("TSC") : asset_id;
    return QString("TENSORCASH_PROOF:%1:%2").arg(m_message_context).arg(asset_identifier);
}

void ProofBuilder::onGenerateProofs()
{
    LogPrintf("[ProofBuilder] onGenerateProofs called\n");

    if (!m_walletModel) {
        LogPrintf("[ProofBuilder] ERROR: walletModel is null in onGenerateProofs\n");
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    m_proofs.clear();
    int successCount = 0;
    int totalSelected = 0;

    // Count selected
    for (int i = 0; i < m_utxoTable->rowCount(); ++i) {
        if (m_utxoTable->item(i, 0)->checkState() == Qt::Checked) {
            totalSelected++;
        }
    }

    if (totalSelected == 0) {
        QMessageBox::warning(this, tr("No Selection"), tr("Please select at least one UTXO."));
        return;
    }

    m_statusLabel->setText(tr("Generating proofs for %1 UTXO(s)...").arg(totalSelected));
    QApplication::processEvents();

    // Generate proof for each selected UTXO
    for (int i = 0; i < m_utxoTable->rowCount(); ++i) {
        if (m_utxoTable->item(i, 0)->checkState() != Qt::Checked) {
            continue;
        }

        QVariantMap utxo = m_utxos[i];
        QString txid = utxo["txid"].toString();
        int vout = utxo["vout"].toInt();
        QString address = utxo["address"].toString();
        qint64 asset_units = utxo["asset_units"].toLongLong();

        // Construct proof message
        QString message = constructProofMessage(address, m_asset_id);

        // Sign with BIP-322
        QString signature = m_walletModel->signMessageBip322(address, message);

        if (signature.isEmpty()) {
            QMessageBox::warning(this, tr("Signature Failed"),
                tr("Failed to sign message for UTXO %1:%2.\n\n"
                   "This may happen if the wallet is locked or the address is not in your wallet.")
                   .arg(txid.left(16) + "...").arg(vout));
            continue;
        }

        // Build proof object
        QVariantMap proof;
        proof["utxo_ref"] = QString("%1:%2").arg(txid).arg(vout);
        proof["address"] = address;
        proof["message"] = message;
        proof["signature"] = signature;
        proof["asset_units"] = asset_units;
        // For native asset, use "TSC" as the asset identifier
        proof["asset_id"] = m_asset_id.isEmpty() ? QStringLiteral("TSC") : m_asset_id;

        m_proofs.append(proof);
        successCount++;
    }

    // Show result
    if (successCount == totalSelected) {
        LogPrintf("[ProofBuilder] Successfully generated %d proofs, calling accept()\n", successCount);
        m_statusLabel->setText(tr("<font color='green'>Successfully generated %1 proof(s).</font>").arg(successCount));
        QMessageBox::information(this, tr("Success"),
            tr("Generated %1 proof(s) successfully.\n\n"
               "These proofs will be attached to your contract offer/request.")
               .arg(successCount));
        accept();  // Close dialog
    } else if (successCount > 0) {
        LogPrintf("[ProofBuilder] Partial success: %d/%d proofs, calling accept()\n", successCount, totalSelected);
        m_statusLabel->setText(tr("<font color='orange'>Generated %1 out of %2 proofs.</font>")
            .arg(successCount).arg(totalSelected));
        QMessageBox::warning(this, tr("Partial Success"),
            tr("Generated %1 out of %2 proofs.\n\n"
               "Some signatures failed. You can proceed with the successful proofs or try again.")
               .arg(successCount).arg(totalSelected));
        accept();  // Close with partial results
    } else {
        m_statusLabel->setText(tr("<font color='red'>Failed to generate any proofs.</font>"));
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to generate any proofs.\n\n"
               "Please check that your wallet is unlocked and try again."));
    }
}

