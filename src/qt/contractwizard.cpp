// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/contractwizard.h>
#include <qt/walletmodel.h>
#include <qt/themehelpers.h>
#include <qt/tormanager.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QTextEdit>
#include <QComboBox>
#include <QMessageBox>
#include <QGroupBox>

ContractWizard::ContractWizard(WalletModel* model, QWidget* parent)
    : QWizard(parent),
      walletModel(model),
      offerFinalized(false)
{
    setWindowTitle(tr("Contract Creation Wizard"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::HaveHelpButton, false);
    setOption(QWizard::NoCancelButtonOnLastPage, false);
}

ContractWizard::~ContractWizard()
{
}

// ============================================================================
// TransportSelectionPage
// ============================================================================

TransportSelectionPage::TransportSelectionPage(ContractWizard* wizard, QWidget* parent)
    : QWizardPage(parent),
      contractWizard(wizard)
{
    setTitle(tr("Session Transport"));
    setSubTitle(tr("Choose how to establish secure bilateral sessions for this offer."));

    setupUI();

    // Connect to TorManager status updates
    connect(TorManager::instance(), &TorManager::statusChanged,
            this, &TransportSelectionPage::onTorStatusChanged);
}

void TransportSelectionPage::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);

    // Transport selection
    QGroupBox* transportGroup = new QGroupBox(tr("Transport Protocol"), this);
    QFormLayout* transportForm = new QFormLayout(transportGroup);

    transportCombo = new QComboBox(this);
    transportCombo->addItem(tr("Auto (Recommended)"), "auto");
    transportCombo->addItem(tr("WebSocket Relay"), "websocket");
    transportCombo->addItem(tr("Tor Hidden Service"), "tor");
    transportCombo->setCurrentIndex(0);
    connect(transportCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TransportSelectionPage::onTransportChanged);

    transportForm->addRow(tr("Protocol:"), transportCombo);
    layout->addWidget(transportGroup);

    // Transport description
    transportDescLabel = new QLabel(this);
    transportDescLabel->setWordWrap(true);
    transportDescLabel->setStyleSheet(QStringLiteral("QLabel { %1 }").arg(ThemeHelpers::infoPanelStyleSheet()));
    layout->addWidget(transportDescLabel);

    // Tor status indicator (initially hidden)
    torStatusLabel = new QLabel(this);
    torStatusLabel->setWordWrap(true);
    torStatusLabel->setStyleSheet("QLabel { padding: 10px; border-radius: 4px; font-weight: bold; }");
    torStatusLabel->hide();
    layout->addWidget(torStatusLabel);

    layout->addStretch();
    setLayout(layout);

    // Initialize display
    onTransportChanged(0);
}

void TransportSelectionPage::initializePage()
{
    // Restore previously selected transport if any
    QString savedTransport = contractWizard->getTransport();
    for (int i = 0; i < transportCombo->count(); ++i) {
        if (transportCombo->itemData(i).toString() == savedTransport) {
            transportCombo->setCurrentIndex(i);
            break;
        }
    }

    updateTorStatus();
}

bool TransportSelectionPage::validatePage()
{
    QString transport = transportCombo->currentData().toString();

    // If Tor is selected, verify it's ready
    if (transport == "tor") {
        if (!TorManager::instance()->isReady()) {
            QMessageBox::warning(this, tr("Tor Not Ready"),
                tr("Tor is not ready. Please wait for Tor to start, or select a different transport.\n\n"
                   "Status: %1").arg(TorManager::instance()->statusString()));
            return false;
        }
    }

    // Save transport to wizard
    contractWizard->setTransport(transport);
    return true;
}

bool TransportSelectionPage::isComplete() const
{
    QString transport = transportCombo->currentData().toString();

    // For Tor transport, require Tor to be ready
    if (transport == "tor") {
        return TorManager::instance()->isReady();
    }

    // Other transports are always available
    return true;
}

void TransportSelectionPage::onTransportChanged(int index)
{
    QString transport = transportCombo->itemData(index).toString();

    // Update description
    if (transport == "auto") {
        transportDescLabel->setText(
            tr("<b>Auto:</b> Uses WebSocket relay for fast, reliable connections. "
               "Best for most trades with encrypted end-to-end sessions."));
        torStatusLabel->hide();
    } else if (transport == "ws") {
        transportDescLabel->setText(
            tr("<b>WebSocket Relay:</b> Fast connection through a central relay server. "
               "Suitable for quick trades. Session data is encrypted end-to-end."));
        torStatusLabel->hide();
    } else if (transport == "tor") {
        transportDescLabel->setText(
            tr("<b>Tor Hidden Service:</b> Maximum privacy using Tor network. "
               "No central relay needed. Slower connection setup (~10-30 seconds)."));
        updateTorStatus();
        torStatusLabel->show();
    }

    Q_EMIT completeChanged();
}

void TransportSelectionPage::onTorStatusChanged(TorManager::Status status)
{
    Q_UNUSED(status);
    updateTorStatus();
    Q_EMIT completeChanged();
}

void TransportSelectionPage::updateTorStatus()
{
    TorManager* tor = TorManager::instance();

    const QString bold = QStringLiteral(" font-weight: bold;");
    switch (tor->status()) {
        case TorManager::Status::NotStarted:
            torStatusLabel->setText(tr("● Tor: Not Started"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::warningPanelStyleSheet(), bold));
            break;
        case TorManager::Status::Starting:
            torStatusLabel->setText(tr("● Tor: Starting... (this may take 10-30 seconds)"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::infoPanelStyleSheet(), bold));
            break;
        case TorManager::Status::Ready:
            torStatusLabel->setText(tr("● Tor: Ready (SOCKS: %1)").arg(tor->socksAddress()));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::successPanelStyleSheet(), bold));
            break;
        case TorManager::Status::Failed:
            torStatusLabel->setText(tr("● Tor: Failed (%1)").arg(tor->lastError()));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::errorPanelStyleSheet(), bold));
            break;
        case TorManager::Status::Stopped:
            torStatusLabel->setText(tr("● Tor: Stopped"));
            torStatusLabel->setStyleSheet(QStringLiteral("QLabel {%1 %2 }").arg(ThemeHelpers::warningPanelStyleSheet(), bold));
            break;
    }
}

// ============================================================================
// ContractReviewPage
// ============================================================================

ContractReviewPage::ContractReviewPage(ContractWizard* wizard, QWidget* parent)
    : QWizardPage(parent),
      contractWizard(wizard)
{
    setTitle(tr("Review && Create Offer"));
    setSubTitle(tr("Review the contract terms below and click 'Finish' to create the offer."));

    QVBoxLayout* layout = new QVBoxLayout(this);

    // Summary display
    QLabel* summaryLabel = new QLabel(tr("<b>Contract Summary:</b>"), this);
    layout->addWidget(summaryLabel);

    summaryEdit = new QTextEdit(this);
    summaryEdit->setReadOnly(true);
    // Remove maximum height to let summary stretch to full window
    layout->addWidget(summaryEdit, 1); // stretch factor 1 to expand

    // Status label (for errors)
    statusLabel = new QLabel(this);
    statusLabel->setWordWrap(true);
    statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
    statusLabel->hide();
    layout->addWidget(statusLabel, 0); // stretch factor 0 to not expand

    setLayout(layout);
}

void ContractReviewPage::initializePage()
{
    // Populate summary from wizard field values
    QString summary = formatOfferSummary();
    summaryEdit->setHtml(summary);
    statusLabel->hide();
}

bool ContractReviewPage::validatePage()
{
    // Call wizard's createOffer() method
    statusLabel->setText(tr("Creating offer..."));
    statusLabel->setStyleSheet(ThemeHelpers::accentLabelStyleSheet(/*bold=*/false));
    statusLabel->show();

    if (!contractWizard->createOffer()) {
        statusLabel->setText(tr("Failed to create offer. Check error details above."));
        statusLabel->setStyleSheet("QLabel { color: #d32f2f; }");
        return false;
    }

    if (contractWizard->hasFinalOffer()) {
        statusLabel->setText(tr("Offer created successfully!"));
        statusLabel->setStyleSheet("QLabel { color: #388e3c; }");
    } else {
        statusLabel->setText(tr("Term sheet prepared. Counterparty address required to finalize."));
        statusLabel->setStyleSheet("QLabel { color: #f9a825; }");
    }

    return true;
}

QString ContractReviewPage::formatOfferSummary() const
{
    // Default implementation - subclasses override
    return tr("<i>Summary not available</i>");
}
