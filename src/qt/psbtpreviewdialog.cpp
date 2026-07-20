// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/psbtpreviewdialog.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QTreeWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QMessageBox>
#include <QDialog>
#include <QFont>

PSBTPreviewDialog::PSBTPreviewDialog(WalletModel* walletModel, const QString& psbt, const QString& context, QWidget* parent)
    : QDialog(parent),
      walletModel(walletModel),
      psbt(psbt),
      context(context)
{
    setWindowTitle(tr("PSBT Preview - Confirm Transaction"));
    setMinimumWidth(700);
    setMinimumHeight(600);

    setupUI();
    analyzePSBT();
}

PSBTPreviewDialog::~PSBTPreviewDialog()
{
}

void PSBTPreviewDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Context label (optional, shows what this transaction is for)
    if (!context.isEmpty()) {
        contextLabel = new QLabel(tr("<h3>%1</h3>").arg(context), this);
        contextLabel->setWordWrap(true);
        mainLayout->addWidget(contextLabel);
    }

    // Warning banner
    warningLabel = new QLabel(
        tr("⚠️ <b>Warning:</b> Broadcasting this transaction is irreversible. "
           "Please review all details carefully before proceeding."), this);
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet("QLabel { background-color: #fff3cd; color: #856404; padding: 12px; border: 1px solid #ffc107; border-radius: 4px; }");
    mainLayout->addWidget(warningLabel);

    mainLayout->addSpacing(10);

    // Transaction summary
    QGroupBox* summaryGroup = new QGroupBox(tr("Transaction Summary"), this);
    QVBoxLayout* summaryLayout = new QVBoxLayout(summaryGroup);

    summaryLabel = new QLabel(this);
    summaryLabel->setTextFormat(Qt::RichText);
    summaryLabel->setWordWrap(true);
    summaryLayout->addWidget(summaryLabel);

    mainLayout->addWidget(summaryGroup);

    // Inputs section
    QGroupBox* inputsGroup = new QGroupBox(tr("Inputs"), this);
    QVBoxLayout* inputsLayout = new QVBoxLayout(inputsGroup);

    inputsTree = new QTreeWidget(this);
    inputsTree->setHeaderLabels({tr("TXID"), tr("Vout"), tr("Amount")});
    inputsTree->setAlternatingRowColors(true);
    inputsTree->setMaximumHeight(150);
    inputsLayout->addWidget(inputsTree);

    mainLayout->addWidget(inputsGroup);

    // Outputs section
    QGroupBox* outputsGroup = new QGroupBox(tr("Outputs"), this);
    QVBoxLayout* outputsLayout = new QVBoxLayout(outputsGroup);

    outputsTree = new QTreeWidget(this);
    outputsTree->setHeaderLabels({tr("Address"), tr("Amount")});
    outputsTree->setAlternatingRowColors(true);
    outputsTree->setMaximumHeight(150);
    outputsLayout->addWidget(outputsTree);

    mainLayout->addWidget(outputsGroup);

    // Fee display
    feeLabel = new QLabel(this);
    feeLabel->setTextFormat(Qt::RichText);
    QFont feeFont = feeLabel->font();
    feeFont.setPointSize(feeFont.pointSize() + 1);
    feeFont.setBold(true);
    feeLabel->setFont(feeFont);
    mainLayout->addWidget(feeLabel);

    mainLayout->addStretch();

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    showRawButton = new QPushButton(tr("Show Raw PSBT"), this);
    connect(showRawButton, &QPushButton::clicked, this, &PSBTPreviewDialog::onShowRawPSBT);
    buttonLayout->addWidget(showRawButton);

    buttonLayout->addStretch();

    cancelButton = new QPushButton(tr("Cancel"), this);
    connect(cancelButton, &QPushButton::clicked, this, &PSBTPreviewDialog::onCancel);
    buttonLayout->addWidget(cancelButton);

    broadcastButton = new QPushButton(tr("Broadcast Transaction"), this);
    broadcastButton->setStyleSheet("QPushButton { background-color: #d32f2f; color: white; padding: 10px 20px; font-weight: bold; }");
    connect(broadcastButton, &QPushButton::clicked, this, &PSBTPreviewDialog::onBroadcast);
    buttonLayout->addWidget(broadcastButton);

    mainLayout->addLayout(buttonLayout);
    setLayout(mainLayout);
}

void PSBTPreviewDialog::analyzePSBT()
{
    // For now, we'll do basic parsing
    // In a full implementation, this would call decodepsbt RPC or similar

    // Placeholder: set some default values
    // Real implementation would parse the PSBT structure
    inputCount = 2;  // Example
    outputCount = 2; // Example
    totalInput = 200000000;  // 2 BTC in sats
    totalOutput = 199950000; // 1.9995 BTC in sats
    fee = totalInput - totalOutput;

    // Update summary
    summaryLabel->setText(
        tr("<b>Inputs:</b> %1<br>"
           "<b>Outputs:</b> %2<br>"
           "<b>Total Input:</b> %3 TSC<br>"
           "<b>Total Output:</b> %4 TSC")
        .arg(inputCount)
        .arg(outputCount)
        .arg(formatAmount(totalInput))
        .arg(formatAmount(totalOutput))
    );

    // Update fee label
    double feeRate = (double)fee / 250.0; // Assume ~250 vbytes for now
    feeLabel->setText(
        tr("<b>Network Fee:</b> %1 TSC (~%2 sat/vB)")
        .arg(formatAmount(fee))
        .arg(QString::number(feeRate, 'f', 1))
    );

    // Add placeholder inputs
    QTreeWidgetItem* input1 = new QTreeWidgetItem(inputsTree);
    input1->setText(0, tr("abcd1234...5678"));
    input1->setText(1, "0");
    input1->setText(2, tr("%1 TSC").arg(formatAmount(100000000)));

    QTreeWidgetItem* input2 = new QTreeWidgetItem(inputsTree);
    input2->setText(0, tr("efgh5678...9012"));
    input2->setText(1, "1");
    input2->setText(2, tr("%1 TSC").arg(formatAmount(100000000)));

    // Add placeholder outputs
    QTreeWidgetItem* output1 = new QTreeWidgetItem(outputsTree);
    output1->setText(0, tr("bc1q...vault"));
    output1->setText(1, tr("%1 TSC").arg(formatAmount(100000000)));

    QTreeWidgetItem* output2 = new QTreeWidgetItem(outputsTree);
    output2->setText(0, tr("bc1q...change"));
    output2->setText(1, tr("%1 TSC").arg(formatAmount(99950000)));

    inputsTree->resizeColumnToContents(0);
    inputsTree->resizeColumnToContents(1);
    outputsTree->resizeColumnToContents(0);
}

QString PSBTPreviewDialog::formatAmount(int64_t sats) const
{
    return QString::number(sats / 100000000.0, 'f', 8);
}

void PSBTPreviewDialog::onBroadcast()
{
    // Double confirmation
    QMessageBox::StandardButton confirm = QMessageBox::warning(this,
        tr("Confirm Broadcast"),
        tr("Are you sure you want to broadcast this transaction?\n\n"
           "This action cannot be undone.\n\n"
           "Fee: %1 TSC\n"
           "Total Output: %2 TSC")
        .arg(formatAmount(fee))
        .arg(formatAmount(totalOutput)),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (confirm == QMessageBox::Yes) {
        approved = true;
        accept();
    }
}

void PSBTPreviewDialog::onCancel()
{
    approved = false;
    reject();
}

void PSBTPreviewDialog::onShowRawPSBT()
{
    QDialog* rawDialog = new QDialog(this);
    rawDialog->setWindowTitle(tr("Raw PSBT (Base64)"));
    rawDialog->setMinimumWidth(600);
    rawDialog->setMinimumHeight(400);

    QVBoxLayout* layout = new QVBoxLayout(rawDialog);

    QLabel* label = new QLabel(tr("Raw PSBT data (Base64 encoded):"), rawDialog);
    layout->addWidget(label);

    QTextEdit* textEdit = new QTextEdit(rawDialog);
    textEdit->setPlainText(psbt);
    textEdit->setReadOnly(true);
    textEdit->setFont(QFont("Courier", 9));
    layout->addWidget(textEdit);

    QPushButton* closeButton = new QPushButton(tr("Close"), rawDialog);
    connect(closeButton, &QPushButton::clicked, rawDialog, &QDialog::accept);
    layout->addWidget(closeButton);

    rawDialog->setLayout(layout);
    rawDialog->exec();
}
