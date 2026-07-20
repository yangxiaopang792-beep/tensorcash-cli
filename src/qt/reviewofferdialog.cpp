// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/reviewofferdialog.h>
#include <qt/walletmodel.h>

#include <QGroupBox>
#include <QMessageBox>
#include <QScrollArea>
#include <QTextEdit>
#include <cmath>

ReviewOfferDialog::ReviewOfferDialog(WalletModel* walletModel, const QString& offerId, const QVariantMap& offerData, QWidget* parent)
    : QDialog(parent),
      walletModel(walletModel),
      offerId(offerId),
      offerData(offerData),
      accepted(false)
{
    setWindowTitle(tr("Review Offer"));
    setMinimumWidth(600);
    setupUI();
    populateOfferDetails();
}

void ReviewOfferDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Scroll area for content
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* scrollContent = new QWidget();
    QVBoxLayout* contentLayout = new QVBoxLayout(scrollContent);

    // Offer ID section
    QGroupBox* offerIdGroup = new QGroupBox(tr("Offer Details"));
    QVBoxLayout* offerIdLayout = new QVBoxLayout(offerIdGroup);
    offerIdLabel = new QLabel();
    offerIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    offerIdLayout->addWidget(offerIdLabel);
    sessionInfoLabel = new QLabel();
    sessionInfoLabel->setWordWrap(true);
    offerIdLayout->addWidget(sessionInfoLabel);
    contentLayout->addWidget(offerIdGroup);

    // Terms section
    QGroupBox* termsGroup = new QGroupBox(tr("Contract Terms"));
    QVBoxLayout* termsLayout = new QVBoxLayout(termsGroup);
    termsLabel = new QLabel();
    termsLabel->setWordWrap(true);
    termsLabel->setTextFormat(Qt::RichText);
    termsLayout->addWidget(termsLabel);
    contentLayout->addWidget(termsGroup);

    // Risk assessment section
    QGroupBox* riskGroup = new QGroupBox(tr("Risk Assessment"));
    QVBoxLayout* riskLayout = new QVBoxLayout(riskGroup);
    riskAssessmentLabel = new QLabel();
    riskAssessmentLabel->setWordWrap(true);
    riskAssessmentLabel->setTextFormat(Qt::RichText);
    riskLayout->addWidget(riskAssessmentLabel);
    contentLayout->addWidget(riskGroup);

    scrollContent->setLayout(contentLayout);
    scrollArea->setWidget(scrollContent);
    mainLayout->addWidget(scrollArea);

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    rejectButton = new QPushButton(tr("✗ Reject"));
    rejectButton->setStyleSheet("QPushButton { background-color: #d9534f; color: white; padding: 8px 16px; }");
    connect(rejectButton, &QPushButton::clicked, this, &ReviewOfferDialog::onReject);
    buttonLayout->addWidget(rejectButton);

    acceptButton = new QPushButton(tr("✓ Accept Offer"));
    acceptButton->setStyleSheet("QPushButton { background-color: #5cb85c; color: white; padding: 8px 16px; }");
    connect(acceptButton, &QPushButton::clicked, this, &ReviewOfferDialog::onAcceptOffer);
    buttonLayout->addWidget(acceptButton);

    mainLayout->addLayout(buttonLayout);
}

void ReviewOfferDialog::populateOfferDetails()
{
    // Offer ID
    offerIdLabel->setText(tr("<b>Offer ID:</b> %1").arg(offerId));

    // Session info (if available)
    QString sessionId = offerData.value("session_id", QString()).toString();
    QString sas = offerData.value("sas", QString()).toString();
    if (!sessionId.isEmpty()) {
        sessionInfoLabel->setText(tr("<b>From:</b> Cosign Session %1<br><b>SAS:</b> %2")
                                      .arg(sessionId.left(12) + "...")
                                      .arg(sas));
        sessionInfoLabel->setVisible(true);
    } else {
        sessionInfoLabel->setVisible(false);
    }

    // Extract terms
    QVariantMap terms = offerData.value("terms").toMap();
    QString contractType = offerData.value("contract_type").toString();

    if (contractType == "repo") {
        QString role = terms.value("role").toString();
        bool isBorrower = (role == "lender"); // Opposite role for acceptor

        double collateralSats = terms.value("collateral_sats", 0).toDouble();
        double principalSats = terms.value("principal_sats", 0).toDouble();
        double haircutSats = terms.value("haircut_sats", 0).toDouble();
        double interestSats = terms.value("interest_sats", 0).toDouble();
        int maturity = terms.value("maturity_height", 0).toInt();

        QString collateralAsset = terms.value("collateral_asset", "TSC").toString();
        QString principalAsset = terms.value("principal_asset", "USDT").toString();
        QString interestAsset = terms.value("interest_asset", principalAsset).toString(); // Default to principal asset if not specified

        // Get asset decimals (default 8 for BTC, 6 for USDT)
        int collateralDecimals = (collateralAsset == "TSC") ? 8 : 6;
        int principalDecimals = (principalAsset == "TSC") ? 8 : 6;
        int interestDecimals = (interestAsset == "TSC") ? 8 : 6;

        double collateralAmount = collateralSats / std::pow(10, collateralDecimals);
        double principalAmount = principalSats / std::pow(10, principalDecimals);
        double haircutAmount = haircutSats / std::pow(10, principalDecimals);
        double interestAmount = interestSats / std::pow(10, interestDecimals);
        double netPrincipal = principalAmount - haircutAmount;

        // Only calculate total repay if interest is in same asset as principal
        bool canAddInterestToPrincipal = (interestAsset == principalAsset);
        double repayAmount = canAddInterestToPrincipal ? (principalAmount + interestAmount) : principalAmount;

        QString termsText;
        if (isBorrower) {
            if (canAddInterestToPrincipal) {
                termsText = tr(
                    "<ul style='margin: 0; padding-left: 20px;'>"
                    "<li><b>You Provide (Collateral):</b> %1 %2</li>"
                    "<li><b>You Receive (Net Principal):</b> %3 %4</li>"
                    "<li><b>You Must Repay:</b> %5 %4 before block %6</li>"
                    "<li><b>If Default:</b> Lender seizes %1 %2</li>"
                    "<li><b>Estimated Opening Fee:</b> ~0.0005 TSC</li>"
                    "</ul>"
                ).arg(formatAmount(collateralAmount, collateralDecimals))
                 .arg(collateralAsset)
                 .arg(formatAmount(netPrincipal, principalDecimals))
                 .arg(principalAsset)
                 .arg(formatAmount(repayAmount, principalDecimals))
                 .arg(maturity);
            } else {
                termsText = tr(
                    "<ul style='margin: 0; padding-left: 20px;'>"
                    "<li><b>You Provide (Collateral):</b> %1 %2</li>"
                    "<li><b>You Receive (Net Principal):</b> %3 %4</li>"
                    "<li><b>You Must Repay (Principal):</b> %5 %4 before block %6</li>"
                    "<li><b>You Must Repay (Interest):</b> %7 %8 before block %6</li>"
                    "<li><b>If Default:</b> Lender seizes %1 %2</li>"
                    "<li><b>Estimated Opening Fee:</b> ~0.0005 TSC</li>"
                    "</ul>"
                ).arg(formatAmount(collateralAmount, collateralDecimals))
                 .arg(collateralAsset)
                 .arg(formatAmount(netPrincipal, principalDecimals))
                 .arg(principalAsset)
                 .arg(formatAmount(principalAmount, principalDecimals))
                 .arg(maturity)
                 .arg(formatAmount(interestAmount, interestDecimals))
                 .arg(interestAsset);
            }
        } else {
            if (canAddInterestToPrincipal) {
                termsText = tr(
                    "<ul style='margin: 0; padding-left: 20px;'>"
                    "<li><b>You Provide (Principal):</b> %1 %2</li>"
                    "<li><b>You Receive (Collateral):</b> %3 %4</li>"
                    "<li><b>Borrower Repays:</b> %5 %2 before block %6</li>"
                    "<li><b>If Default:</b> You seize %3 %4</li>"
                    "<li><b>Estimated Opening Fee:</b> ~0.0005 TSC</li>"
                    "</ul>"
                ).arg(formatAmount(principalAmount, principalDecimals))
                 .arg(principalAsset)
                 .arg(formatAmount(collateralAmount, collateralDecimals))
                 .arg(collateralAsset)
                 .arg(formatAmount(repayAmount, principalDecimals))
                 .arg(maturity);
            } else {
                termsText = tr(
                    "<ul style='margin: 0; padding-left: 20px;'>"
                    "<li><b>You Provide (Principal):</b> %1 %2</li>"
                    "<li><b>You Receive (Collateral):</b> %3 %4</li>"
                    "<li><b>Borrower Repays (Principal):</b> %5 %2 before block %6</li>"
                    "<li><b>Borrower Repays (Interest):</b> %7 %8 before block %6</li>"
                    "<li><b>If Default:</b> You seize %3 %4</li>"
                    "<li><b>Estimated Opening Fee:</b> ~0.0005 TSC</li>"
                    "</ul>"
                ).arg(formatAmount(principalAmount, principalDecimals))
                 .arg(principalAsset)
                 .arg(formatAmount(collateralAmount, collateralDecimals))
                 .arg(collateralAsset)
                 .arg(formatAmount(principalAmount, principalDecimals))
                 .arg(maturity)
                 .arg(formatAmount(interestAmount, interestDecimals))
                 .arg(interestAsset);
            }
        }

        termsLabel->setText(termsText);

        // Risk assessment
        QString riskText = calculateRiskMetrics();
        riskAssessmentLabel->setText(riskText);
    } else {
        termsLabel->setText(tr("Contract type not supported in this version."));
        riskAssessmentLabel->setText(tr("N/A"));
    }
}

QString ReviewOfferDialog::formatAmount(double amount, int decimals) const
{
    return QString::number(amount, 'f', decimals);
}

QString ReviewOfferDialog::calculateRiskMetrics()
{
    QVariantMap terms = offerData.value("terms").toMap();

    double collateralSats = terms.value("collateral_sats", 0).toDouble();
    double principalSats = terms.value("principal_sats", 0).toDouble();
    double interestSats = terms.value("interest_sats", 0).toDouble();

    // Simplified risk metrics (would require price oracle in production)
    double ltv = (principalSats / collateralSats) * 100.0;
    double interestRate = (interestSats / principalSats) * 100.0;

    QString riskLevel;
    if (ltv < 30) {
        riskLevel = tr("Low");
    } else if (ltv < 60) {
        riskLevel = tr("Medium");
    } else {
        riskLevel = tr("High");
    }

    return tr(
        "<ul style='margin: 0; padding-left: 20px;'>"
        "<li><b>LTV Ratio:</b> %.1f%% (principal / collateral)</li>"
        "<li><b>Interest Rate:</b> %.2f%%</li>"
        "<li><b>Liquidation Risk:</b> %3 (monitor price volatility)</li>"
        "</ul>"
    ).arg(ltv).arg(interestRate).arg(riskLevel);
}

void ReviewOfferDialog::onAcceptOffer()
{
    QMessageBox::StandardButton confirm = QMessageBox::question(
        this,
        tr("Confirm Acceptance"),
        tr("Are you sure you want to accept this offer? You will be committed to funding the contract."),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (confirm != QMessageBox::Yes) {
        return;
    }

    if (!walletModel) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available."));
        return;
    }

    // Call repo.accept RPC
    WalletModel::RepoAcceptResult result = walletModel->repoAccept(offerId, true);

    if (!result.success) {
        QMessageBox::critical(this, tr("Acceptance Failed"), tr("Error: %1").arg(result.error));
        return;
    }

    acceptanceJson = result.acceptance_json;
    accepted = true;

    QMessageBox::information(this, tr("Offer Accepted"), tr("Offer accepted successfully. Proceed to open the contract."));
    accept(); // Close dialog with QDialog::Accepted
}

void ReviewOfferDialog::onReject()
{
    accepted = false;
    reject(); // Close dialog with QDialog::Rejected
}
