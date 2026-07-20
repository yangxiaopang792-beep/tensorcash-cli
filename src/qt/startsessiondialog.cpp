// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/startsessiondialog.h>
#include <qt/qrimagewidget.h>
#include <qt/walletmodel.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QTextEdit>
#include <QGroupBox>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QDialog>

StartSessionDialog::StartSessionDialog(WalletModel* model, QWidget* parent)
    : QDialog(parent),
      walletModel(model),
      qrWidget(nullptr)
{
    setWindowTitle(tr("Start New Cosign Session"));
    setMinimumWidth(500);

    setupUI();
    showStep1();
}

StartSessionDialog::~StartSessionDialog()
{
}

void StartSessionDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Step 1: Configuration
    step1Widget = new QWidget(this);
    QVBoxLayout* step1Layout = new QVBoxLayout(step1Widget);

    QGroupBox* configGroup = new QGroupBox(tr("Session Configuration"), step1Widget);
    QFormLayout* configLayout = new QFormLayout(configGroup);

    contextEdit = new QLineEdit(step1Widget);
    contextEdit->setPlaceholderText(tr("e.g., Repo contract negotiation"));
    configLayout->addRow(tr("Context (optional):"), contextEdit);

    transportCombo = new QComboBox(step1Widget);
    transportCombo->addItem(tr("Auto (Recommended)"), "auto");
    transportCombo->addItem(tr("WebSocket"), "ws");
    transportCombo->addItem(tr("Tor Hidden Service"), "tor");
    transportCombo->setCurrentIndex(0);
    connect(transportCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &StartSessionDialog::onTransportChanged);
    configLayout->addRow(tr("Transport:"), transportCombo);

    // Relay server URL (only shown for WebSocket)
    relayUrlLabel = new QLabel(tr("Relay Server:"), step1Widget);
    relayUrlEdit = new QLineEdit(step1Widget);
    relayUrlEdit->setPlaceholderText(tr("wss://relay.tensorcash.org (optional)"));
    relayUrlEdit->setVisible(false);
    relayUrlLabel->setVisible(false);
    configLayout->addRow(relayUrlLabel, relayUrlEdit);

    ttlSpinBox = new QSpinBox(step1Widget);
    ttlSpinBox->setMinimum(60);
    ttlSpinBox->setMaximum(86400);
    ttlSpinBox->setValue(1800);
    ttlSpinBox->setSuffix(tr(" seconds"));
    ttlSpinBox->setToolTip(tr("Session will automatically expire after this time (60-86400 seconds)"));
    configLayout->addRow(tr("TTL (Time to Live):"), ttlSpinBox);

    configGroup->setLayout(configLayout);
    step1Layout->addWidget(configGroup);

    QHBoxLayout* step1ButtonLayout = new QHBoxLayout();
    step1ButtonLayout->addStretch();

    createButton = new QPushButton(tr("Create Session"), step1Widget);
    createButton->setDefault(true);
    connect(createButton, &QPushButton::clicked, this, &StartSessionDialog::onCreateSession);
    step1ButtonLayout->addWidget(createButton);

    cancelButton = new QPushButton(tr("Cancel"), step1Widget);
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    step1ButtonLayout->addWidget(cancelButton);

    step1Layout->addLayout(step1ButtonLayout);
    step1Widget->setLayout(step1Layout);

    // Step 2: Display invite
    step2Widget = new QWidget(this);
    QVBoxLayout* step2Layout = new QVBoxLayout(step2Widget);

    QLabel* currentStepLabel = new QLabel(
        tr("<span style='font-size: 16px; font-weight: bold; color: white; background-color: #2196f3; padding: 6px 12px; border-radius: 3px;'>"
           "STEP 1/3: Share Code"
           "</span>"),
        step2Widget
    );
    currentStepLabel->setStyleSheet("QLabel { margin-bottom: 8px; }");
    step2Layout->addWidget(currentStepLabel);

    // Session ID (small, less prominent)
    sessionIdLabel = new QLabel(step2Widget);
    sessionIdLabel->setWordWrap(true);
    sessionIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    sessionIdLabel->setStyleSheet("QLabel { font-size: 10px; color: #666; }");
    step2Layout->addWidget(sessionIdLabel);

    // Full invite link - this is what they actually need
    QGroupBox* inviteGroup = new QGroupBox(tr("Share This Link With Your Peer"), step2Widget);
    QVBoxLayout* inviteLayout = new QVBoxLayout(inviteGroup);

    inviteLinkEdit = new QTextEdit(step2Widget);
    inviteLinkEdit->setReadOnly(true);
    inviteLinkEdit->setMaximumHeight(80);
    inviteLinkEdit->setStyleSheet("QTextEdit { font-family: 'Courier New', monospace; font-size: 11px; background-color: #f5f5f5; }");
    inviteLayout->addWidget(inviteLinkEdit);

    QHBoxLayout* inviteButtonLayout = new QHBoxLayout();

    copyLinkButton = new QPushButton(tr("Copy Link"), step2Widget);
    copyLinkButton->setStyleSheet("QPushButton { padding: 8px 16px; font-weight: bold; }");
    connect(copyLinkButton, &QPushButton::clicked, this, &StartSessionDialog::onCopyInviteLink);
    inviteButtonLayout->addWidget(copyLinkButton);

    showQRButton = new QPushButton(tr("Show QR Code"), step2Widget);
    connect(showQRButton, &QPushButton::clicked, this, &StartSessionDialog::onShowQRCode);
    inviteButtonLayout->addWidget(showQRButton);

    inviteButtonLayout->addStretch();

    inviteLayout->addLayout(inviteButtonLayout);
    inviteGroup->setLayout(inviteLayout);

    step2Layout->addWidget(inviteGroup);

    QLabel* warningLabel = new QLabel(
        tr("⚠️ <b>Important:</b> Share this link securely with your peer. "
           "Both parties must verify the SAS (Short Authentication String) matches before proceeding."),
        step2Widget
    );
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet("QLabel { background-color: #fff3e0; padding: 8px; border-radius: 4px; }");
    step2Layout->addWidget(warningLabel);

    step2Layout->addStretch();

    QHBoxLayout* step2ButtonLayout = new QHBoxLayout();
    step2ButtonLayout->addStretch();

    doneButton = new QPushButton(tr("Done"), step2Widget);
    doneButton->setDefault(true);
    connect(doneButton, &QPushButton::clicked, this, &QDialog::accept);
    step2ButtonLayout->addWidget(doneButton);

    step2Layout->addLayout(step2ButtonLayout);
    step2Widget->setLayout(step2Layout);

    // Add both steps to main layout (only one will be visible at a time)
    mainLayout->addWidget(step1Widget);
    mainLayout->addWidget(step2Widget);

    setLayout(mainLayout);
}

void StartSessionDialog::showStep1()
{
    step1Widget->setVisible(true);
    step2Widget->setVisible(false);
}

void StartSessionDialog::showStep2()
{
    step1Widget->setVisible(false);
    step2Widget->setVisible(true);
}

void StartSessionDialog::onCreateSession()
{
    if (!walletModel) {
        QMessageBox::critical(this, tr("Error"), tr("Wallet model not available"));
        return;
    }

    QString context = contextEdit->text();
    transport = transportCombo->currentData().toString();
    relay_url = relayUrlEdit->text();
    int ttl = ttlSpinBox->value();

    // Disable create button to prevent double-clicks
    createButton->setEnabled(false);
    createButton->setText(tr("Creating..."));

    // Call RPC to create session
    WalletModel::CosignInitResult result = walletModel->cosignInit(context, transport, ttl, relay_url);

    createButton->setEnabled(true);
    createButton->setText(tr("Create Session"));

    if (!result.success) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to create session:\n%1").arg(result.error));
        return;
    }

    // Store session data
    sessionId = result.session_id;
    inviteLink = result.invite_link;
    sas = result.sas;
    sasNumeric = result.sas_numeric;
    qrData = result.qr_data;

    // Update UI with session info
    sessionIdLabel->setText(tr("Session ID: %1").arg(sessionId.left(16) + "..."));
    inviteLinkEdit->setPlainText(inviteLink);

    // Switch to step 2
    showStep2();
}

void StartSessionDialog::onCopyInviteLink()
{
    QClipboard* clipboard = QApplication::clipboard();
    clipboard->setText(inviteLink);

    QMessageBox::information(this, tr("Copied"),
        tr("Invite link copied to clipboard!\n\nSend this to your peer so they can join."));
}

void StartSessionDialog::onTransportChanged(int index)
{
    QString transport = transportCombo->currentData().toString();

    // Show relay URL field only for WebSocket transport
    bool showRelay = (transport == "ws" || transport == "websocket");
    relayUrlEdit->setVisible(showRelay);
    relayUrlLabel->setVisible(showRelay);
}

void StartSessionDialog::onShowQRCode()
{
    // Create QR code dialog
    QDialog qrDialog(this);
    qrDialog.setWindowTitle(tr("Session Invite QR Code"));

    QVBoxLayout* layout = new QVBoxLayout(&qrDialog);

    QLabel* infoLabel = new QLabel(tr("Scan this QR code with your peer's wallet:"), &qrDialog);
    layout->addWidget(infoLabel);

    QRImageWidget* qrImage = new QRImageWidget(&qrDialog);
    if (qrImage->setQR(qrData, "")) {
        layout->addWidget(qrImage, 0, Qt::AlignCenter);
    } else {
        QLabel* errorLabel = new QLabel(tr("Failed to generate QR code (data may be too long)"), &qrDialog);
        layout->addWidget(errorLabel);
    }

    QLabel* sasLabel2 = new QLabel(tr("<b>SAS:</b> %1<br/><b>Numeric:</b> %2")
        .arg(sas).arg(sasNumeric), &qrDialog);
    sasLabel2->setAlignment(Qt::AlignCenter);
    sasLabel2->setStyleSheet("QLabel { margin-top: 10px; }");
    layout->addWidget(sasLabel2);

    QPushButton* closeButton = new QPushButton(tr("Close"), &qrDialog);
    connect(closeButton, &QPushButton::clicked, &qrDialog, &QDialog::accept);
    layout->addWidget(closeButton);

    qrDialog.setLayout(layout);
    qrDialog.exec();
}
