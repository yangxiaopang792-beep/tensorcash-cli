// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/sasverificationdialog.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QTimer>
#include <QCloseEvent>

SASVerificationDialog::SASVerificationDialog(const QString& _sas, const QString& _sasNumeric, QWidget* parent)
    : QDialog(parent),
      sas(_sas),
      sasNumeric(_sasNumeric)
{
    setWindowTitle(tr("Verify Short Authentication String (SAS)"));
    setMinimumWidth(450);

    setupUI();
}

SASVerificationDialog::SASVerificationDialog(const QString& _sas, const QString& _sasNumeric, int autoCloseSeconds, QWidget* parent)
    : QDialog(parent),
      sas(_sas),
      sasNumeric(_sasNumeric)
{
    setWindowTitle(tr("Verify Short Authentication String (SAS)"));
    setMinimumWidth(450);
    setupUI();

    if (autoCloseSeconds > 0) {
        setupAutoClose(autoCloseSeconds);
    }
}

SASVerificationDialog::~SASVerificationDialog()
{
}

void SASVerificationDialog::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Title
    QLabel* titleLabel = new QLabel(tr("<b>Handshake Complete - Verify SAS</b>"), this);
    titleLabel->setStyleSheet("QLabel { font-size: 14px; }");
    mainLayout->addWidget(titleLabel);

    // Security warning
    QLabel* warningLabel = new QLabel(
        tr("⚠️ <b>SECURITY CHECK</b><br/>"
           "Confirm with your peer over a trusted channel (voice, video, or your existing secure chat/DM) that the SAS (Short Authentication String) matches.<br/>"
           "<b>DO NOT proceed if there is any mismatch!</b>"),
        this
    );
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet(
        "QLabel { "
        "background-color: #fff3e0; "
        "padding: 12px; "
        "border-radius: 4px; "
        "border-left: 4px solid #ff9800; "
        "}"
    );
    mainLayout->addWidget(warningLabel);

    mainLayout->addSpacing(10);

    // SAS display
    QLabel* sasHeaderLabel = new QLabel(tr("Your SAS:"), this);
    sasHeaderLabel->setStyleSheet("QLabel { font-weight: bold; }");
    mainLayout->addWidget(sasHeaderLabel);

    sasLabel = new QLabel(sas, this);
    sasLabel->setStyleSheet(
        "QLabel { "
        "font-size: 20px; "
        "font-weight: bold; "
        "color: #1976d2; "
        "padding: 16px; "
        "background-color: #e3f2fd; "
        "border-radius: 4px; "
        "border: 2px solid #1976d2; "
        "}"
    );
    sasLabel->setAlignment(Qt::AlignCenter);
    sasLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mainLayout->addWidget(sasLabel);

    // Numeric SAS display
    QLabel* numericHeaderLabel = new QLabel(tr("Numeric SAS (alternative):"), this);
    numericHeaderLabel->setStyleSheet("QLabel { font-weight: bold; margin-top: 10px; }");
    mainLayout->addWidget(numericHeaderLabel);

    sasNumericLabel = new QLabel(sasNumeric, this);
    sasNumericLabel->setStyleSheet(
        "QLabel { "
        "font-size: 16px; "
        "font-weight: bold; "
        "color: #388e3c; "
        "padding: 12px; "
        "background-color: #e8f5e9; "
        "border-radius: 4px; "
        "border: 2px solid #388e3c; "
        "}"
    );
    sasNumericLabel->setAlignment(Qt::AlignCenter);
    sasNumericLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mainLayout->addWidget(sasNumericLabel);

    mainLayout->addSpacing(20);

    // Instructions
    QLabel* instructionsLabel = new QLabel(
        tr("1. Call or message your peer\n"
           "2. Read out the SAS word-by-word or digit-by-digit\n"
           "3. Confirm they see the exact same string\n\n"
           "Tip: You can manage the session under Exchange P2P → Bridge Sessions."),
        this);
    instructionsLabel->setWordWrap(true);
    instructionsLabel->setStyleSheet("QLabel { padding: 8px; background-color: #f5f5f5; border-radius: 4px; }");
    mainLayout->addWidget(instructionsLabel);

    mainLayout->addStretch();

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();

    verifiedButton = new QPushButton(tr("✓ Yes, Verified"), this);
    verifiedButton->setStyleSheet(
        "QPushButton { "
        "background-color: #4caf50; "
        "color: white; "
        "font-weight: bold; "
        "padding: 8px 16px; "
        "border-radius: 4px; "
        "}"
        "QPushButton:hover { background-color: #45a049; }"
    );
    verifiedButton->setDefault(true);
    connect(verifiedButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(verifiedButton);

    abortButton = new QPushButton(tr("✗ No, Abort"), this);
    abortButton->setStyleSheet(
        "QPushButton { "
        "background-color: #f44336; "
        "color: white; "
        "font-weight: bold; "
        "padding: 8px 16px; "
        "border-radius: 4px; "
        "}"
        "QPushButton:hover { background-color: #da190b; }"
    );
    connect(abortButton, &QPushButton::clicked, [this]() {
        QMessageBox::critical(this, tr("SAS Mismatch"),
            tr("SAS verification failed!\n\n"
               "This could indicate a man-in-the-middle attack.\n"
               "DO NOT proceed with this session. Close it immediately."));
        Q_EMIT sasAbortRequested();
        reject();
    });
    buttonLayout->addWidget(abortButton);

    mainLayout->addLayout(buttonLayout);

    setLayout(mainLayout);
}

void SASVerificationDialog::setupAutoClose(int seconds)
{
    remainingSeconds = seconds;

    // Hide explicit verification button; show countdown instead
    if (verifiedButton) verifiedButton->setVisible(false);

    // Add countdown label if missing
    if (!countdownLabel) {
        countdownLabel = new QLabel(this);
        countdownLabel->setStyleSheet("QLabel { color: #555; padding: 4px; }");
        layout()->addWidget(countdownLabel);
    }

    auto updateText = [this]() {
        if (remainingSeconds >= 0 && countdownLabel) {
            countdownLabel->setText(tr("This window will close in %1s. You can manage the session under Exchange P2P → Bridge Sessions.").arg(remainingSeconds));
        }
    };

    updateText();

    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [this, timer, updateText]() {
        if (remainingSeconds <= 0) {
            timer->stop();
            accept();
            return;
        }
        --remainingSeconds;
        updateText();
    });
    timer->start(1000);
}
