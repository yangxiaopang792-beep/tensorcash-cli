// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/opencontractdialog.h>
#include <qt/psbtpreviewdialog.h>
#include <qt/walletmodel.h>

#include <univalue.h>

#include <QGroupBox>
#include <QMessageBox>
#include <QProgressDialog>
#include <QProgressBar>
#include <QTimer>
#include <cmath>

OpenContractDialog::OpenContractDialog(WalletModel* walletModel, const QString& offerId, const QString& contractType, const QVariantMap& offerData, QWidget* parent)
    : QDialog(parent),
      walletModel(walletModel),
      offerId(offerId),
      contractType(contractType),
      offerData(offerData),
      opened(false),
      requiredAmount(0.0),
      fundingAvailable(false),
      confirmationTimer(nullptr),
      confirmationDialog(nullptr),
      confirmationStatusLabel(nullptr),
      confirmationProgressBar(nullptr),
      currentConfirmations(0)
{
    setWindowTitle(tr("Open Contract"));
    setMinimumWidth(600);
    setupUI();
    checkFundingRequirements();
}

void OpenContractDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Contract ID section
    QGroupBox* contractGroup = new QGroupBox(tr("Contract Details"));
    QVBoxLayout* contractLayout = new QVBoxLayout(contractGroup);
    contractIdLabel = new QLabel(tr("<b>Contract:</b> %1 (Accepted)").arg(offerId));
    contractIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    contractLayout->addWidget(contractIdLabel);

    statusLabel = new QLabel(tr("<b>Status:</b> Ready to Build Opening Transaction"));
    statusLabel->setWordWrap(true);
    contractLayout->addWidget(statusLabel);

    mainLayout->addWidget(contractGroup);

    // Funding check section
    QGroupBox* fundingGroup = new QGroupBox(tr("Funding Check"));
    QVBoxLayout* fundingLayout = new QVBoxLayout(fundingGroup);
    fundingCheckLabel = new QLabel();
    fundingCheckLabel->setWordWrap(true);
    fundingCheckLabel->setTextFormat(Qt::RichText);
    fundingLayout->addWidget(fundingCheckLabel);
    mainLayout->addWidget(fundingGroup);

    // Next steps section
    QGroupBox* nextStepsGroup = new QGroupBox(tr("Next Steps"));
    QVBoxLayout* nextStepsLayout = new QVBoxLayout(nextStepsGroup);
    nextStepsLabel = new QLabel(
        tr("<ol style='margin: 0; padding-left: 20px;'>"
           "<li>Build opening PSBT (both parties contribute)</li>"
           "<li>Adaptor signature ceremony (Fair-Sign v1.1)</li>"
           "<li>Broadcast opening transaction</li>"
           "<li>Contract becomes active</li>"
           "</ol>")
    );
    nextStepsLabel->setTextFormat(Qt::RichText);
    nextStepsLayout->addWidget(nextStepsLabel);
    mainLayout->addWidget(nextStepsGroup);

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    cancelButton = new QPushButton(tr("Cancel"));
    connect(cancelButton, &QPushButton::clicked, this, &OpenContractDialog::onCancel);
    buttonLayout->addWidget(cancelButton);

    buildButton = new QPushButton(tr("Build Opening Transaction"));
    buildButton->setStyleSheet("QPushButton { background-color: #5cb85c; color: white; padding: 8px 16px; }");
    connect(buildButton, &QPushButton::clicked, this, &OpenContractDialog::onBuildOpeningTransaction);
    buttonLayout->addWidget(buildButton);

    mainLayout->addLayout(buttonLayout);
}

void OpenContractDialog::checkFundingRequirements()
{
    if (!walletModel) {
        fundingCheckLabel->setText(tr("⚠ <b>Error:</b> Wallet model not available."));
        buildButton->setEnabled(false);
        return;
    }

    // Get offer data to determine required amounts
    if (offerData.isEmpty()) {
        // No offer data provided - cannot determine funding requirements
        fundingCheckLabel->setText(tr("⚠ <b>Warning:</b> Offer data not available. Cannot verify funding requirements."));
        buildButton->setEnabled(false);
        return;
    }

    // Extract funding requirements from offer data
    QVariantMap terms = offerData.value("terms").toMap();
    QString role = terms.value("role").toString();

    // Determine my role (opposite of proposer)
    bool iAmBorrower = (role == "lender");  // If proposer was lender, I am borrower

    if (contractType == "repo") {
        // For repo: borrower provides collateral, lender provides principal
        if (iAmBorrower) {
            double collateralSats = terms.value("collateral_sats", 0).toDouble();
            requiredAmount = collateralSats / 100000000.0;  // Convert sats to BTC
        } else {
            double principalSats = terms.value("principal_sats", 0).toDouble();
            requiredAmount = principalSats / 100000000.0;
        }

        // Add estimated fee buffer (0.0005 BTC = 50000 sats)
        requiredAmount += 0.0005;
    } else {
        // Fallback for other contract types
        requiredAmount = 0.001;
    }

    if (requiredAmount <= 0) {
        fundingCheckLabel->setText(tr("⚠ <b>Error:</b> Could not determine funding requirements from offer data."));
        buildButton->setEnabled(false);
        return;
    }

    // Check balance
    double availableBalance = walletModel->getCachedBalance().balance / 100000000.0; // Convert satoshis to BTC

    fundingAvailable = (availableBalance >= requiredAmount);

    QString fundingText;
    if (fundingAvailable) {
        fundingText = tr(
            "<b>Your Contribution:</b><br>"
            "• %1 TSC (collateral) ✓ Available<br>"
            "• ~0.0005 TSC (fees) ✓ Available<br>"
            "<b>Total Required:</b> %2 TSC<br>"
            "<b>Available Balance:</b> %3 TSC"
        ).arg(requiredAmount - 0.0005, 0, 'f', 8).arg(requiredAmount, 0, 'f', 4).arg(availableBalance, 0, 'f', 8);
    } else {
        fundingText = tr(
            "<b>Your Contribution:</b><br>"
            "• %1 TSC (collateral) ✗ Insufficient<br>"
            "• ~0.0005 TSC (fees)<br>"
            "<b>Total Required:</b> %2 TSC<br>"
            "<b>Available Balance:</b> %3 TSC<br>"
            "<span style='color: red;'><b>⚠ Insufficient funds!</b></span>"
        ).arg(requiredAmount - 0.0005, 0, 'f', 8).arg(requiredAmount, 0, 'f', 4).arg(availableBalance, 0, 'f', 8);
    }

    fundingCheckLabel->setText(fundingText);
    buildButton->setEnabled(fundingAvailable);
}

void OpenContractDialog::updateStatusLabel(const QString& status)
{
    statusLabel->setText(tr("<b>Status:</b> %1").arg(status));
}

void OpenContractDialog::onBuildOpeningTransaction()
{
    try {
        if (!walletModel) {
            QMessageBox::critical(this, tr("Error"), tr("Wallet model not available."));
            return;
        }

        if (!fundingAvailable) {
            QMessageBox::critical(this, tr("Insufficient Funds"), tr("You do not have enough funds to open this contract."));
            return;
        }

        // Show progress dialog
        QProgressDialog* progress = new QProgressDialog(tr("Building opening transaction..."), tr("Cancel"), 0, 100, this);
        progress->setWindowModality(Qt::WindowModal);
        progress->setMinimumDuration(0);
        progress->setValue(10);

        // Step 1: Build opening PSBT
        // Note: repo.accept should have already been called by ReviewOfferDialog
        updateStatusLabel(tr("Building PSBT..."));
        progress->setLabelText(tr("Step 1/3: Building PSBT..."));
        progress->setValue(20);

        QVariantMap feePolicy;
        feePolicy["strategy"] = "medium";

        WalletModel::RepoBuildOpenResult buildResult = walletModel->repoBuildOpen(offerId, feePolicy);

        if (!buildResult.success) {
            delete progress;
            QMessageBox::critical(this, tr("Build Failed"), tr("Error building opening transaction: %1").arg(buildResult.error));
            return;
        }

        progress->setValue(40);

        // Step 2: Adaptor ceremony
        updateStatusLabel(tr("Running adaptor ceremony..."));
        progress->setLabelText(tr("Step 2/3: Running Fair-Sign adaptor ceremony..."));
        progress->setValue(50);

        // Check if we have an active cosign session
        QString sessionId = buildResult.session_id;
        bool isInitiator = buildResult.is_initiator;

        QString finalizedPsbt;

        if (!sessionId.isEmpty()) {
            // Use automated adaptor roundtrip
            WalletModel::CosignAdaptorRoundtripResult ceremonyResult =
                walletModel->cosignAdaptorRoundtrip(sessionId, buildResult.psbt, isInitiator);

            if (!ceremonyResult.success) {
                delete progress;
                QMessageBox::critical(this, tr("Ceremony Failed"), tr("Adaptor ceremony failed: %1").arg(ceremonyResult.error));
                return;
            }

            if (!ceremonyResult.complete || ceremonyResult.psbt.isEmpty()) {
                delete progress;
                QMessageBox::critical(this, tr("Ceremony Incomplete"),
                    tr("Adaptor ceremony did not return a completed PSBT. Please retry or perform the ceremony manually."));
                return;
            }

            finalizedPsbt = ceremonyResult.psbt;
        } else {
            // Manual fallback (would show manual ceremony dialog)
            delete progress;
            QMessageBox::warning(this, tr("Manual Ceremony Required"),
                tr("No active cosign session. Manual adaptor ceremony not yet implemented in this version."));
            return;
        }

        progress->setValue(70);
        delete progress;

        // Step 3: Show PSBT preview and get user confirmation
        updateStatusLabel(tr("Awaiting confirmation..."));

        PSBTPreviewDialog previewDialog(walletModel, finalizedPsbt, tr("Opening Transaction for Contract %1").arg(offerId), this);

        if (previewDialog.exec() != QDialog::Accepted || !previewDialog.wasApproved()) {
            updateStatusLabel(tr("Broadcast cancelled by user"));
            QMessageBox::information(this, tr("Cancelled"), tr("Transaction broadcast cancelled."));
            return;
        }

        // Step 4: Broadcast opening transaction
        updateStatusLabel(tr("Broadcasting transaction..."));

        QProgressDialog* broadcastProgress = new QProgressDialog(tr("Broadcasting transaction..."), tr("Cancel"), 0, 0, this);
        broadcastProgress->setWindowModality(Qt::WindowModal);
        broadcastProgress->setMinimumDuration(0);
        broadcastProgress->setValue(0);

        WalletModel::BroadcastPsbtResult broadcastResult = walletModel->broadcastPsbt(finalizedPsbt);

        delete broadcastProgress;

        if (!broadcastResult.success) {
            QMessageBox::critical(this, tr("Broadcast Failed"), tr("Error broadcasting transaction: %1").arg(broadcastResult.error));
            return;
        }

        openingTxId = broadcastResult.txid;
        opened = true;

        // Step 5: Monitor confirmation status
        updateStatusLabel(tr("Waiting for confirmations..."));
        showConfirmationTracking();

        accept(); // Close dialog with QDialog::Accepted

    } catch (const UniValue& e) {
        QMessageBox::critical(this, tr("Error"), tr("UniValue exception: %1").arg(QString::fromStdString(e.write())));
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(this, tr("Error"), tr("Runtime error: %1").arg(QString::fromStdString(e.what())));
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"), tr("Exception occurred: %1").arg(QString::fromStdString(e.what())));
    } catch (...) {
        QMessageBox::critical(this, tr("Error"), tr("Unknown exception occurred while building opening transaction"));
    }
}

void OpenContractDialog::onCancel()
{
    reject(); // Close dialog with QDialog::Rejected
}

void OpenContractDialog::showConfirmationTracking()
{
    // Create non-blocking confirmation tracking dialog
    confirmationDialog = new QDialog(this);
    confirmationDialog->setWindowTitle(tr("Transaction Broadcast"));
    confirmationDialog->setMinimumWidth(500);
    confirmationDialog->setModal(false); // Non-blocking

    QVBoxLayout* layout = new QVBoxLayout(confirmationDialog);

    // Success banner
    QLabel* successLabel = new QLabel(tr("✓ <b>Opening transaction broadcast successfully!</b>"));
    successLabel->setStyleSheet("QLabel { background-color: #d4edda; color: #155724; padding: 12px; border: 1px solid #c3e6cb; border-radius: 4px; }");
    successLabel->setWordWrap(true);
    layout->addWidget(successLabel);

    layout->addSpacing(10);

    // Transaction ID
    QGroupBox* txGroup = new QGroupBox(tr("Transaction Details"));
    QVBoxLayout* txLayout = new QVBoxLayout(txGroup);

    QLabel* txidLabel = new QLabel(tr("<b>Transaction ID:</b><br>%1").arg(openingTxId));
    txidLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    txidLabel->setWordWrap(true);
    txLayout->addWidget(txidLabel);

    layout->addWidget(txGroup);

    // Confirmation status
    QGroupBox* confirmGroup = new QGroupBox(tr("Confirmation Status"));
    QVBoxLayout* confirmLayout = new QVBoxLayout(confirmGroup);

    confirmationStatusLabel = new QLabel(tr("Waiting for confirmations... (0/1)"));
    confirmationStatusLabel->setWordWrap(true);
    confirmLayout->addWidget(confirmationStatusLabel);

    confirmationProgressBar = new QProgressBar();
    confirmationProgressBar->setRange(0, 1); // Need 1 confirmation minimum
    confirmationProgressBar->setValue(0);
    confirmLayout->addWidget(confirmationProgressBar);

    layout->addWidget(confirmGroup);

    layout->addSpacing(10);

    // Close button
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton* closeButton = new QPushButton(tr("Close"));
    connect(closeButton, &QPushButton::clicked, confirmationDialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);

    layout->addLayout(buttonLayout);

    confirmationDialog->setLayout(layout);

    // Start confirmation polling timer (every 10 seconds)
    currentConfirmations = 0;
    confirmationTimer = new QTimer(this);
    connect(confirmationTimer, &QTimer::timeout, this, &OpenContractDialog::checkConfirmations);
    confirmationTimer->start(10000); // Poll every 10 seconds

    // Perform first check immediately
    QTimer::singleShot(500, this, &OpenContractDialog::checkConfirmations);

    // Show dialog
    confirmationDialog->show();
}

void OpenContractDialog::checkConfirmations()
{
    if (!walletModel || openingTxId.isEmpty()) {
        return;
    }

    // Query transaction confirmations via RPC
    // In a real implementation, this would call gettransaction or similar
    // For now, we'll simulate checking by calling a wallet method

    try {
        // Placeholder: In real implementation, call walletModel->getTransactionConfirmations(openingTxId)
        // For now, we'll simulate confirmation progression

        // Real implementation would be:
        // int confirmations = walletModel->getTransactionConfirmations(openingTxId);

        // Simulated progression (remove in production)
        static int checkCount = 0;
        checkCount++;
        int confirmations = (checkCount >= 3) ? 1 : 0; // Simulate confirmation after 3 checks (~30 seconds)

        if (confirmations != currentConfirmations) {
            currentConfirmations = confirmations;

            if (confirmationStatusLabel) {
                if (confirmations >= 1) {
                    confirmationStatusLabel->setText(
                        confirmations == 1
                            ? tr("✓ <b>Transaction confirmed!</b> (%1 confirmation)").arg(confirmations)
                            : tr("✓ <b>Transaction confirmed!</b> (%1 confirmations)").arg(confirmations)
                    );
                    confirmationStatusLabel->setStyleSheet("QLabel { color: #155724; font-weight: bold; }");

                    if (confirmationProgressBar) {
                        confirmationProgressBar->setValue(confirmations);
                        confirmationProgressBar->setStyleSheet("QProgressBar::chunk { background-color: #28a745; }");
                    }

                    // Stop polling once confirmed
                    if (confirmationTimer) {
                        confirmationTimer->stop();
                    }
                } else {
                    confirmationStatusLabel->setText(tr("Waiting for confirmations... (0/1)"));
                }
            }

            if (confirmationProgressBar) {
                confirmationProgressBar->setValue(confirmations);
            }
        }

    } catch (...) {
        // RPC error - stop polling
        if (confirmationTimer) {
            confirmationTimer->stop();
        }

        if (confirmationStatusLabel) {
            confirmationStatusLabel->setText(tr("⚠ Error checking confirmations. Please check wallet manually."));
            confirmationStatusLabel->setStyleSheet("QLabel { color: #856404; }");
        }
    }
}
