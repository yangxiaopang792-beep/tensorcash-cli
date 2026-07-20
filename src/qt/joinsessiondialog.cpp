// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/joinsessiondialog.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QGroupBox>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>

JoinSessionDialog::JoinSessionDialog(WalletModel* model, QWidget* parent)
    : QDialog(parent),
      walletModel(model)
{
    setWindowTitle(tr("Join Cosign Session"));
    setMinimumWidth(500);

    setupUI();
}

JoinSessionDialog::~JoinSessionDialog()
{
}

void JoinSessionDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    QLabel* currentStepLabel = new QLabel(
        tr("<span style='font-size: 16px; font-weight: bold; color: white; background-color: #2196f3; padding: 6px 12px; border-radius: 3px;'>"
           "STEP 1/3: Paste Invite Link"
           "</span>"),
        this
    );
    currentStepLabel->setStyleSheet("QLabel { margin-bottom: 8px; }");
    mainLayout->addWidget(currentStepLabel);

    QLabel* infoLabel = new QLabel(
        tr("Paste the full invite link from your peer:"),
        this
    );
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);

    // Invite link input group
    QGroupBox* inviteGroup = new QGroupBox(tr("Full Invite Link"), this);
    QVBoxLayout* inviteLayout = new QVBoxLayout(inviteGroup);

    inviteLinkEdit = new QTextEdit(this);
    inviteLinkEdit->setPlaceholderText(tr("Paste full link: cosign:?r=...&t=...#c=..."));
    inviteLinkEdit->setMaximumHeight(80);
    inviteLayout->addWidget(inviteLinkEdit);

    pasteButton = new QPushButton(tr("Paste from Clipboard"), this);
    connect(pasteButton, &QPushButton::clicked, this, &JoinSessionDialog::onPasteFromClipboard);
    inviteLayout->addWidget(pasteButton);

    inviteGroup->setLayout(inviteLayout);
    mainLayout->addWidget(inviteGroup);

    // Optional context
    QFormLayout* formLayout = new QFormLayout();
    contextEdit = new QLineEdit(this);
    contextEdit->setPlaceholderText(tr("e.g., Repo contract negotiation"));
    formLayout->addRow(tr("Context (optional):"), contextEdit);
    mainLayout->addLayout(formLayout);

    mainLayout->addStretch();

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    joinButton = new QPushButton(tr("Join Session"), this);
    joinButton->setDefault(true);
    connect(joinButton, &QPushButton::clicked, this, &JoinSessionDialog::onJoinSession);
    buttonLayout->addWidget(joinButton);

    cancelButton = new QPushButton(tr("Cancel"), this);
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(cancelButton);

    mainLayout->addLayout(buttonLayout);

    setLayout(mainLayout);
}

void JoinSessionDialog::onPasteFromClipboard()
{
    QClipboard* clipboard = QApplication::clipboard();
    QString text = clipboard->text();

    if (!text.isEmpty()) {
        inviteLinkEdit->setPlainText(text.trimmed());
    }
}

void JoinSessionDialog::onJoinSession()
{
    if (!walletModel) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    QString inviteLink = inviteLinkEdit->toPlainText().trimmed();

    if (inviteLink.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Please enter the full invite link"));
        return;
    }

    // Validate it's a proper cosign link
    if (!inviteLink.startsWith("cosign:", Qt::CaseInsensitive)) {
        QMessageBox::warning(this, tr("Error"),
            tr("Invalid invite link. It must start with 'cosign:'\n\n"
               "Get the full link from your peer - the short code alone won't work."));
        return;
    }

    QString context = contextEdit->text();

    // Disable join button to prevent double-clicks
    joinButton->setEnabled(false);
    joinButton->setText(tr("Joining..."));

    // Call RPC to join session
    WalletModel::CosignJoinResult result = walletModel->cosignJoin(inviteLink, context);

    joinButton->setEnabled(true);
    joinButton->setText(tr("Join Session"));

    if (!result.success) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to join session:\n%1").arg(result.error));
        return;
    }

    // Store session data
    sessionId = result.session_id;
    sas = result.sas;
    sasNumeric = result.sas_numeric;

    // Show success message with SAS
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("Session Joined"));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setText(tr("Successfully joined session!"));
    msgBox.setInformativeText(
        tr("Session ID: %1\n\n"
           "SAS (Short Authentication String): %2\n"
           "Numeric SAS: %3\n\n"
           "⚠️ IMPORTANT: Verbally confirm with your peer that the SAS matches before proceeding.")
        .arg(sessionId)
        .arg(sas)
        .arg(sasNumeric)
    );
    msgBox.exec();

    // Accept dialog
    accept();
}
