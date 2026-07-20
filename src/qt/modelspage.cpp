// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/modelspage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <consensus/amount.h>
#include <core_io.h>
#include <interfaces/node.h>
#include <chainparams.h>
#include <modeldb.h>
#include <node/interface_ui.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <wallet/rpc/api_model_registration.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QHeaderView>
#include <QTextEdit>
#include <QComboBox>
#include <QStringList>
#include <QMessageBox>
#include <QInputDialog>
#include <QDateTime>
#include <QSpinBox>
#include <QGroupBox>
#include <QFrame>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDebug>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTimer>
#include <QShowEvent>
#include <QThread>
#include <QSettings>
#include <QTextBrowser>
#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <cmath>

namespace {

// Reusable regex for 64-char hex hash validation (scope_id, model_hash, etc.)
static const QRegularExpression kHex64Re("^[0-9a-fA-F]{64}$");

bool IsValidModelIdentifier(const QString& value)
{
    const QString trimmed = value.trimmed();
    const int sep = trimmed.lastIndexOf('@');
    return sep > 0 && sep < trimmed.size() - 1;
}

int ComputeCommitPhaseTimeoutMs()
{
    static constexpr int64_t kMinTimeoutMs{18'000'000}; // 5 hours
    static constexpr int64_t kWaitBlocks{5};
    const int64_t spacing_seconds = std::max<int64_t>(1, Params().GetConsensus().nPowTargetSpacing);
    const int64_t dynamic_timeout_ms = spacing_seconds * 1000 * kWaitBlocks;
    const int64_t timeout_ms = std::max<int64_t>(kMinTimeoutMs, dynamic_timeout_ms);
    return static_cast<int>(std::min<int64_t>(timeout_ms, std::numeric_limits<int>::max()));
}

QWidget* TopLevelDialogParent(QWidget* widget)
{
    return widget && widget->window() ? widget->window() : widget;
}

using StatusOpt = std::optional<ModelRegistrationStatus>;

StatusOpt StatusFromInt(int value)
{
    switch (value) {
    case static_cast<int>(ModelRegistrationStatus::PendingDeposit):
        return ModelRegistrationStatus::PendingDeposit;
    case static_cast<int>(ModelRegistrationStatus::PendingVerification):
        return ModelRegistrationStatus::PendingVerification;
    case static_cast<int>(ModelRegistrationStatus::Registered):
        return ModelRegistrationStatus::Registered;
    case static_cast<int>(ModelRegistrationStatus::Locked):
        return ModelRegistrationStatus::Locked;
    case static_cast<int>(ModelRegistrationStatus::Banned):
        return ModelRegistrationStatus::Banned;
    default:
        return std::nullopt;
    }
}

StatusOpt StatusFromString(const QString& status)
{
    const QString normalized = status.trimmed().toLower();
    if (normalized == "pending" || normalized == "pending_deposit") {
        return ModelRegistrationStatus::PendingDeposit;
    }
    if (normalized == "pending_verification" || normalized == "verifying") {
        return ModelRegistrationStatus::PendingVerification;
    }
    if (normalized == "registered") {
        return ModelRegistrationStatus::Registered;
    }
    if (normalized == "locked") {
        return ModelRegistrationStatus::Locked;
    }
    if (normalized == "banned") {
        return ModelRegistrationStatus::Banned;
    }
    return std::nullopt;
}

QString FormatRpcError(const UniValue& objError)
{
    try {
        const UniValue& message = objError.find_value("message");
        if (message.isStr()) {
            return QString::fromStdString(message.get_str());
        }
    } catch (...) {
    }

    try {
        return QString::fromStdString(objError.write());
    } catch (...) {
        return QString("Unknown RPC error");
    }
}

} // namespace

ModelsPage::ModelsPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_platform_style(platformStyle)
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    tabWidget = new QTabWidget(this);

    setupRegisterTab();
   setupCommitTab();
   setupMyDepositsTab();
   setupRegistryTab();
    setupChallengeTab();
    setupDiscussionTab();

    tabWidget->addTab(registerTab, tr("Register"));
    tabWidget->addTab(commitTab, tr("Commit"));
    tabWidget->addTab(myDepositsTab, tr("My Deposits"));
    tabWidget->addTab(registryTab, tr("Registry"));
    tabWidget->addTab(challengeTab, tr("Challenge"));
    tabWidget->addTab(discussionTab, tr("Discussion"));

    mainLayout->addWidget(tabWidget);
    connect(tabWidget, &QTabWidget::currentChanged, this, &ModelsPage::onTabChanged);

    // Setup maturity countdown timer (update every 10 seconds)
    maturityTimer = new QTimer(this);
    connect(maturityTimer, &QTimer::timeout, this, &ModelsPage::onMaturityTimerTick);
    maturityTimer->start(10000);

    // Install wheel event filters to prevent accidental changes while scrolling
    GUIUtil::InstallWheelEventFilter(myDepositsFilterCombo);
    GUIUtil::InstallWheelEventFilter(registryFilterCombo);

}

ModelsPage::~ModelsPage()
{
}

void ModelsPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (event->spontaneous()) {
        return;
    }

    if (tabWidget) {
        QTimer::singleShot(0, this, [this]() {
            if (tabWidget && isVisible()) {
                onTabChanged(tabWidget->currentIndex());
            }
        });
    }
}

void ModelsPage::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

void ModelsPage::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (clientModel) {
        connect(clientModel, &ClientModel::numBlocksChanged, this, &ModelsPage::onNumBlocksChanged);
    }
}

void ModelsPage::setupRegisterTab()
{
    registerTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(registerTab);

    // Input form
    QGroupBox* formGroup = new QGroupBox(tr("Model Registration Details"));
    QGridLayout* formLayout = new QGridLayout(formGroup);

    formLayout->addWidget(new QLabel(tr("Model Name:")), 0, 0);
    regNameEdit = new QLineEdit();
    regNameEdit->setPlaceholderText(tr("e.g., tensor/gpt-model (max 80 bytes, printable ASCII)"));
    formLayout->addWidget(regNameEdit, 0, 1);

    formLayout->addWidget(new QLabel(tr("Model Commit:")), 1, 0);
    regCommitEdit = new QLineEdit();
    regCommitEdit->setPlaceholderText(tr("e.g., v1.0.0 or commit hash (max 80 bytes, printable ASCII)"));
    formLayout->addWidget(regCommitEdit, 1, 1);

    formLayout->addWidget(new QLabel(tr("Difficulty Multiplier:")), 2, 0);
    regDifficultyEdit = new QLineEdit();
    regDifficultyEdit->setPlaceholderText(tr("Positive integer (e.g., 1000000)"));
    formLayout->addWidget(regDifficultyEdit, 2, 1);

    formLayout->addWidget(new QLabel(tr("IPFS CID (optional):")), 3, 0);
    regCidEdit = new QLineEdit();
    regCidEdit->setPlaceholderText(tr("e.g., QmYwAPJzv... (max 80 bytes)"));
    formLayout->addWidget(regCidEdit, 3, 1);

    formLayout->addWidget(new QLabel(tr("Extra Metadata (optional):")), 4, 0);
    regExtraEdit = new QTextEdit();
    regExtraEdit->setPlaceholderText(tr("Additional metadata (max 80 bytes, printable ASCII)"));
    regExtraEdit->setMaximumHeight(80);
    formLayout->addWidget(regExtraEdit, 4, 1);

    layout->addWidget(formGroup);

    // Action buttons
    QHBoxLayout* actionLayout = new QHBoxLayout();
    regHowItWorksButton = new QPushButton(tr("How it works"));
    regValidateButton = new QPushButton(tr("Validate Model Data"));
    regCreateButton = new QPushButton(tr("Create Deposit Transaction"));
    regCreateButton->setEnabled(false);
    actionLayout->addWidget(regHowItWorksButton);
    actionLayout->addWidget(regValidateButton);
    actionLayout->addWidget(regCreateButton);
    layout->addLayout(actionLayout);

    // Status text
    regStatusText = new QTextEdit();
    regStatusText->setReadOnly(true);
    regStatusText->setMaximumHeight(200);
    regStatusText->setPlaceholderText(tr("Status and transaction details will appear here..."));
    layout->addWidget(regStatusText);

    layout->addStretch();

    // Connect signals
    connect(regNameEdit, &QLineEdit::textChanged, this, &ModelsPage::onRegisterFieldChanged);
    connect(regCommitEdit, &QLineEdit::textChanged, this, &ModelsPage::onRegisterFieldChanged);
    connect(regDifficultyEdit, &QLineEdit::textChanged, this, &ModelsPage::onRegisterFieldChanged);
    connect(regHowItWorksButton, &QPushButton::clicked, this, &ModelsPage::onRegisterHowItWorks);
    connect(regValidateButton, &QPushButton::clicked, this, &ModelsPage::onValidateDepositFields);
    connect(regCreateButton, &QPushButton::clicked, this, &ModelsPage::onCreateDeposit);
}

void ModelsPage::setupCommitTab()
{
    commitTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(commitTab);

    QLabel* infoLabel = new QLabel(tr("Select a pending deposit from your wallet to complete registration:"));
    layout->addWidget(infoLabel);

    // Pending deposits table
    commitDepositTable = new QTableWidget(0, 6);
    commitDepositTable->setHorizontalHeaderLabels({tr("Model Hash"), tr("Name@Commit"), tr("Deposit TX"), tr("Vout"), tr("Amount"), tr("Status")});
    commitDepositTable->horizontalHeader()->setStretchLastSection(true);
    commitDepositTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    commitDepositTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(commitDepositTable);

    QGroupBox* summaryGroup = new QGroupBox(tr("Selected Deposit"));
    QVBoxLayout* summaryLayout = new QVBoxLayout(summaryGroup);
    commitSelectedSummaryLabel = new QLabel(tr("No deposit selected. Choose a pending deposit to see the next available action."));
    commitSelectedSummaryLabel->setWordWrap(true);
    summaryLayout->addWidget(commitSelectedSummaryLabel);
    layout->addWidget(summaryGroup);

    // Action buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    commitRefreshButton = new QPushButton(tr("Refresh"));
    commitCreateButton = new QPushButton(tr("Create Commits"));
    commitCreateButton->setEnabled(false);
    commitCreateButton->setToolTip(tr("Select a deposit to create commit transactions."));
    buttonLayout->addWidget(commitRefreshButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(commitCreateButton);
    layout->addLayout(buttonLayout);

    // Status text
    commitStatusText = new QTextEdit();
    commitStatusText->setReadOnly(true);
    commitStatusText->setMaximumHeight(150);
    commitStatusText->setPlaceholderText(tr("Selection details, progress and commit results will appear here..."));
    layout->addWidget(commitStatusText);

    // Connect signals
    connect(commitRefreshButton, &QPushButton::clicked, this, &ModelsPage::onCommitRefresh);
    connect(commitCreateButton, &QPushButton::clicked, this, &ModelsPage::onCreateCommit);
    connect(commitDepositTable, &QTableWidget::cellClicked, this, &ModelsPage::onCommitDepositSelected);
}

void ModelsPage::setupMyDepositsTab()
{
    myDepositsTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(myDepositsTab);

    // Filter and refresh
    QHBoxLayout* topLayout = new QHBoxLayout();
    topLayout->addWidget(new QLabel(tr("Filter:")));
    myDepositsFilterCombo = new QComboBox();
    myDepositsFilterCombo->addItem(tr("All"), -1);
    myDepositsFilterCombo->addItem(tr("Pending Deposit"), static_cast<int>(ModelRegistrationStatus::PendingDeposit));
    myDepositsFilterCombo->addItem(tr("Pending Verification"), static_cast<int>(ModelRegistrationStatus::PendingVerification));
    myDepositsFilterCombo->addItem(tr("Registered"), static_cast<int>(ModelRegistrationStatus::Registered));
    myDepositsFilterCombo->addItem(tr("Locked"), static_cast<int>(ModelRegistrationStatus::Locked));
    myDepositsFilterCombo->addItem(tr("Banned"), static_cast<int>(ModelRegistrationStatus::Banned));
    topLayout->addWidget(myDepositsFilterCombo);
    topLayout->addSpacing(16);
    topLayout->addWidget(new QLabel(tr("Search:")));
    myDepositsSearchEdit = new QLineEdit();
    myDepositsSearchEdit->setPlaceholderText(tr("Model name, hash or txid..."));
    topLayout->addWidget(myDepositsSearchEdit);
    topLayout->addStretch();
    myDepositsRefreshButton = new QPushButton(tr("Refresh"));
    topLayout->addWidget(myDepositsRefreshButton);
    layout->addLayout(topLayout);

    // Deposits table
    myDepositsTable = new QTableWidget(0, 8);
    myDepositsTable->setHorizontalHeaderLabels({tr("Model Hash"), tr("Name@Commit"), tr("Deposit TX"), tr("Status"), tr("Block Height"), tr("Maturity"), tr("Verification"), tr("Action")});
    myDepositsTable->horizontalHeader()->setStretchLastSection(true);
    myDepositsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    myDepositsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(myDepositsTable);

    // Details text
    myDepositsDetailsText = new QTextEdit();
    myDepositsDetailsText->setReadOnly(true);
    myDepositsDetailsText->setMaximumHeight(150);
    myDepositsDetailsText->setPlaceholderText(tr("Select a deposit to view details..."));
    layout->addWidget(myDepositsDetailsText);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->addStretch();
    myDepositsReclaimButton = new QPushButton(tr("Reclaim Deposit"));
    myDepositsReclaimButton->setEnabled(false);
    myDepositsReclaimButton->setToolTip(tr("Available only for registered deposits after the unlock height is reached."));
    actionLayout->addWidget(myDepositsReclaimButton);
    layout->addLayout(actionLayout);

    // Connect signals
    connect(myDepositsRefreshButton, &QPushButton::clicked, this, &ModelsPage::onMyDepositsRefresh);
    connect(myDepositsFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ModelsPage::onMyDepositsFilterChanged);
    connect(myDepositsSearchEdit, &QLineEdit::textChanged, this, &ModelsPage::onMyDepositsRefresh);
    connect(myDepositsTable, &QTableWidget::cellClicked, this, &ModelsPage::onMyDepositSelected);
    connect(myDepositsReclaimButton, &QPushButton::clicked, this, &ModelsPage::onMyDepositReclaim);
}

void ModelsPage::setupRegistryTab()
{
    registryTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(registryTab);

    // Top controls
    QHBoxLayout* topLayout = new QHBoxLayout();

    registryCurrentHeightLabel = new QLabel(tr("Current Height: -"));
    topLayout->addWidget(registryCurrentHeightLabel);
    topLayout->addSpacing(20);

    topLayout->addWidget(new QLabel(tr("Filter:")));
    registryFilterCombo = new QComboBox();
    registryFilterCombo->addItem(tr("All"), -1);
    registryFilterCombo->addItem(tr("Pending Deposit"), static_cast<int>(ModelRegistrationStatus::PendingDeposit));
    registryFilterCombo->addItem(tr("Pending Verification"), static_cast<int>(ModelRegistrationStatus::PendingVerification));
    registryFilterCombo->addItem(tr("Registered"), static_cast<int>(ModelRegistrationStatus::Registered));
    registryFilterCombo->addItem(tr("Locked"), static_cast<int>(ModelRegistrationStatus::Locked));
    registryFilterCombo->addItem(tr("Banned"), static_cast<int>(ModelRegistrationStatus::Banned));
    topLayout->addWidget(registryFilterCombo);

    topLayout->addSpacing(20);
    topLayout->addWidget(new QLabel(tr("Search:")));
    registrySearchEdit = new QLineEdit();
    registrySearchEdit->setPlaceholderText(tr("Model name or hash..."));
    topLayout->addWidget(registrySearchEdit);

    registryBurnButton = new QPushButton(tr("Burn deposit"));
    registryBurnButton->setEnabled(false);
    topLayout->addWidget(registryBurnButton);

    topLayout->addStretch();
    registryRefreshButton = new QPushButton(tr("Refresh"));
    topLayout->addWidget(registryRefreshButton);
    layout->addLayout(topLayout);

    // Registry table
    registryTable = new QTableWidget(0, 7);
    registryTable->setHorizontalHeaderLabels({tr("Model Hash"), tr("Name"), tr("Commit"), tr("Difficulty"), tr("Status"), tr("Registered Height"), tr("Maturity")});
    registryTable->horizontalHeader()->setStretchLastSection(true);
    registryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    registryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(registryTable);

    // Details text
    registryDetailsText = new QTextEdit();
    registryDetailsText->setReadOnly(true);
    registryDetailsText->setMaximumHeight(150);
    registryDetailsText->setPlaceholderText(tr("Select a model to view details..."));
    layout->addWidget(registryDetailsText);

    // Connect signals
    connect(registryRefreshButton, &QPushButton::clicked, this, &ModelsPage::onRegistryRefresh);
    connect(registryFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ModelsPage::onRegistryFilterChanged);
    connect(registrySearchEdit, &QLineEdit::textChanged, this, &ModelsPage::onRegistrySearchChanged);
    connect(registryTable, &QTableWidget::cellClicked, this, &ModelsPage::onRegistryModelSelected);
    connect(registryBurnButton, &QPushButton::clicked, this, &ModelsPage::onRegistryBurn);
}

void ModelsPage::setupChallengeTab()
{
    challengeTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(challengeTab);

    QHBoxLayout* topLayout = new QHBoxLayout();
    challengeCountLabel = new QLabel(tr("Registered (non-default): 0"));
    challengeRefreshButton = new QPushButton(tr("Refresh"));
    challengeLoadBlocksButton = new QPushButton(tr("Load blocks"));
    challengeLoadBlocksButton->setEnabled(false);
    challengeCreateButton = new QPushButton(tr("Challenge Deposit"));
    challengeCreateButton->setEnabled(false);
    challengeSeveralCommitButton = new QPushButton(tr("Create Challenge Commits"));
    challengeSeveralCommitButton->setEnabled(false);
    challengeHowItWorksButton = new QPushButton(tr("How it works"));
    topLayout->addWidget(challengeHowItWorksButton);
    topLayout->addWidget(challengeCountLabel);
    topLayout->addStretch();
    topLayout->addWidget(challengeCreateButton);
    topLayout->addWidget(challengeSeveralCommitButton);
    topLayout->addWidget(challengeLoadBlocksButton);
    topLayout->addWidget(challengeRefreshButton);
    layout->addLayout(topLayout);

    QGroupBox* statusGroup = new QGroupBox(tr("Challenge Status"));
    QGridLayout* statusLayout = new QGridLayout(statusGroup);
    statusLayout->addWidget(new QLabel(tr("Deposit:")), 0, 0);
    challengeStatusLabel = new QLabel(tr("Select a model to see challenge status."));
    challengeStatusLabel->setWordWrap(true);
    statusLayout->addWidget(challengeStatusLabel, 0, 1);
    statusLayout->addWidget(new QLabel(tr("Deposit outpoint:")), 1, 0);
    challengeDepositLabel = new QLabel(tr("-"));
    challengeDepositLabel->setWordWrap(true);
    statusLayout->addWidget(challengeDepositLabel, 1, 1);
    statusLayout->addWidget(new QLabel(tr("Next action:")), 2, 0);
    challengeActionLabel = new QLabel(tr("Select a model."));
    challengeActionLabel->setWordWrap(true);
    statusLayout->addWidget(challengeActionLabel, 2, 1);
    layout->addWidget(statusGroup);

    challengeTable = new QTableWidget(0, 6);
    challengeTable->setHorizontalHeaderLabels({tr("Model Hash"), tr("Name"), tr("Commit"), tr("Registered Height"), tr("Challenge"), tr("Verdict")});
    challengeTable->horizontalHeader()->setStretchLastSection(true);
    challengeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    challengeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(challengeTable);

    challengeBlocksLabel = new QLabel(tr("Blocks (latest 0):"));
    layout->addWidget(challengeBlocksLabel);

    challengeBlocksTable = new QTableWidget(0, 3);
    challengeBlocksTable->setHorizontalHeaderLabels({tr("Height"), tr("Hash"), tr("Time")});
    challengeBlocksTable->horizontalHeader()->setStretchLastSection(true);
    challengeBlocksTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    challengeBlocksTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(challengeBlocksTable);

    connect(challengeRefreshButton, &QPushButton::clicked, this, &ModelsPage::onChallengeRefresh);
    connect(challengeLoadBlocksButton, &QPushButton::clicked, this, &ModelsPage::onChallengeLoadBlocks);
    connect(challengeTable, &QTableWidget::cellClicked, this, &ModelsPage::onChallengeModelSelected);
    connect(challengeBlocksTable, &QTableWidget::cellClicked, this, &ModelsPage::onChallengeBlockSelected);
    connect(challengeCreateButton, &QPushButton::clicked, this, &ModelsPage::onChallengeCreate);
    connect(challengeSeveralCommitButton, &QPushButton::clicked, this, &ModelsPage::onChallengeCreateSeveralCommits);
    connect(challengeHowItWorksButton, &QPushButton::clicked, this, &ModelsPage::onChallengeHowItWorks);
}

// ===== REGISTER TAB SLOTS =====

void ModelsPage::onRegisterFieldChanged()
{
    resetRegisterValidationState();
}

void ModelsPage::resetRegisterValidationState(bool clearStatus)
{
    regDepositValidated = false;
    if (regCreateButton) {
        regCreateButton->setEnabled(false);
    }
    if (!regStatusText) {
        return;
    }

    if (clearStatus) {
        regStatusText->clear();
        regStatusText->setStyleSheet("");
        return;
    }

    const bool has_input = !(regNameEdit->text().trimmed().isEmpty() &&
                             regCommitEdit->text().trimmed().isEmpty() &&
                             regDifficultyEdit->text().trimmed().isEmpty());
    if (!has_input) {
        regStatusText->clear();
        regStatusText->setStyleSheet("");
        return;
    }

    regStatusText->setStyleSheet("");
    regStatusText->setText(tr("Fields changed. Click <b>Validate Model Data</b> to re-check and enable registration."));
}

void ModelsPage::validateDepositFields()
{
    QString name = regNameEdit->text().trimmed();
    QString commit = regCommitEdit->text().trimmed();
    QString diffStr = regDifficultyEdit->text().trimmed();
    QString cid = regCidEdit->text().trimmed();
    QString extra = regExtraEdit->toPlainText();

    bool valid = true;
    QStringList errors;

    // Name validation
    if (name.isEmpty()) {
        errors << tr("• Model name is required");
        valid = false;
    } else if (name.toUtf8().size() > 80) {
        errors << tr("• Name exceeds 80 bytes (OP_RETURN limit)");
        valid = false;
    } else {
        for (QChar c : name) {
            if (!c.isPrint() && c != ' ' && c != '\n') {
                errors << tr("• Name contains non-printable characters");
                valid = false;
                break;
            }
        }
    }

    // Commit validation
    if (commit.isEmpty()) {
        errors << tr("• Model commit is required");
        valid = false;
    } else if (commit.toUtf8().size() > 80) {
        errors << tr("• Commit exceeds 80 bytes (OP_RETURN limit)");
        valid = false;
    } else {
        for (QChar c : commit) {
            if (!c.isPrint() && c != ' ' && c != '\n') {
                errors << tr("• Commit contains non-printable characters");
                valid = false;
                break;
            }
        }
    }

    // Difficulty validation
    if (diffStr.isEmpty()) {
        errors << tr("• Difficulty is required");
        valid = false;
    } else {
        bool ok;
        int64_t diff = diffStr.toLongLong(&ok);
        if (!ok || diff <= 0) {
            errors << tr("• Difficulty must be a positive integer");
            valid = false;
        }
    }

    // CID validation (optional)
    if (!cid.isEmpty() && cid.toUtf8().size() > 80) {
        errors << tr("• CID exceeds 80 bytes (OP_RETURN limit)");
        valid = false;
    }

    // Extra validation (optional)
    if (!extra.isEmpty()) {
        if (extra.toUtf8().size() > 80) {
            errors << tr("• Extra metadata exceeds 80 bytes (OP_RETURN limit)");
            valid = false;
        } else {
            for (QChar c : extra) {
                if (!c.isPrint() && c != ' ' && c != '\n') {
                    errors << tr("• Extra metadata contains non-printable characters");
                    valid = false;
                    break;
                }
            }
        }
    }

    if (valid) {
        if (!clientModel) {
            errors << tr("• Node interface is not available for registry lookup");
            valid = false;
        } else {
            try {
                UniValue params(UniValue::VARR);
                params.push_back(true);
                UniValue models = clientModel->node().executeRpc("getmodelslist", params, "");
                for (size_t i = 0; i < models.size(); ++i) {
                    const UniValue& model = models[i];
                    if (!model.exists("model_name") || !model.exists("model_commit")) {
                        continue;
                    }
                    const QString existing_name = QString::fromStdString(model["model_name"].get_str());
                    const QString existing_commit = QString::fromStdString(model["model_commit"].get_str());
                    if (existing_name == name && existing_commit == commit) {
                        errors << tr("• Model with the same name and commit already exists in the registry");
                        valid = false;
                        break;
                    }
                }
            } catch (const UniValue& objError) {
                errors << tr("• Failed to query model registry: %1").arg(FormatRpcError(objError));
                valid = false;
            } catch (const std::exception& e) {
                errors << tr("• Failed to query model registry: %1").arg(QString::fromStdString(e.what()));
                valid = false;
            }
        }
    }

    regDepositValidated = valid;
    regCreateButton->setEnabled(valid);

    if (!errors.isEmpty()) {
        regStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        regStatusText->setText(tr("<b>Validation Errors:</b><br>") + errors.join("<br>"));
    } else if (valid) {
        regStatusText->setStyleSheet("QTextEdit { color: #2E7D32; }");
        regStatusText->setText(tr("<b>✓ Validation passed - model deposit can now be created</b>"));
    } else {
        regStatusText->clear();
        regStatusText->setStyleSheet("");
    }
}

void ModelsPage::onValidateDepositFields()
{
    validateDepositFields();
}

void ModelsPage::onRegisterHowItWorks()
{
    QMessageBox::information(
        this,
        tr("Model Registration Flow"),
        tr("<b>How model registration works</b><br><br>"
           "1. <b>Create Deposit Transaction</b> locks the model deposit on-chain.<br>"
           "2. After the deposit is confirmed, the model appears on the <b>Commit</b> tab.<br>"
           "3. Use <b>Create Commits</b> to create commit transactions for that model.<br>"
           "4. A model needs <b>%1 commits</b> to satisfy the registration threshold.<br>"
           "5. Final registration is checked after <b>%2 blocks</b> from the verification window.<br><br>"
           "<b>Tip:</b> you can reopen this explanation any time by pressing <b>How it works</b>.<br><br>"
           "<b>Important:</b> if registration conditions are not met, the model may remain unregistered or become locked.")
            .arg(Params().GetConsensus().ModelSuccessfulCommitsThreshold)
            .arg(Params().GetConsensus().ModelVerificationBlockCount));
}

void ModelsPage::onCreateDeposit()
{
    if (!walletModel) {
        showError(tr("Wallet model not available"));
        return;
    }
    if (!regDepositValidated) {
        showError(tr("Validate the model data before creating the deposit"));
        return;
    }

    QString name = regNameEdit->text().trimmed();
    QString commit = regCommitEdit->text().trimmed();
    QString diffStr = regDifficultyEdit->text().trimmed();
    QString cid = regCidEdit->text().trimmed();
    QString extra = regExtraEdit->toPlainText();

    bool ok;
    int64_t difficulty = diffStr.toLongLong(&ok);
    if (!ok) {
        showError(tr("Invalid difficulty value"));
        return;
    }

    // === FIRST CONFIRMATION: Show warning dialog with 10-second countdown ===
    QDialog* warningDialog = new QDialog(TopLevelDialogParent(this));
    warningDialog->setWindowTitle(tr("⚠️ CRITICAL WARNING - Model Deposit"));
    warningDialog->setModal(true);
    warningDialog->setMinimumWidth(600);

    QVBoxLayout* dialogLayout = new QVBoxLayout(warningDialog);

    // Warning text
    QLabel* warningLabel = new QLabel(
        tr("<b style='font-size: 14pt; color: #C62828;'>⚠️ CRITICAL WARNING</b><br><br>"
           "Model registration LOCKS FUNDS (5 TSC deposit) on-chain.<br><br>"
           "<b>UNRECOVERABLE RISKS:</b><br>"
           "• Invalid metadata format = FUNDS PERMANENTLY LOCKED<br>"
           "• Failed validation = DEPOSIT BURNED (no refund)<br>"
           "• Malformed values cannot be recovered<br><br>"
           "Only basic field validation (length, format) is performed in wallet.<br>"
           "Full model validation happens externally - BEYOND WALLET CONTROL.<br><br>"
           "<b style='color: #C62828;'>Proceed ONLY if you understand these risks.</b>")
    );
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet("QLabel { padding: 15px; background-color: #FFEBEE; border: 2px solid #C62828; border-radius: 5px; }");
    dialogLayout->addWidget(warningLabel);

    dialogLayout->addSpacing(20);

    // Countdown label and button
    QLabel* countdownLabel = new QLabel(tr("Please wait 10 seconds before proceeding..."));
    countdownLabel->setAlignment(Qt::AlignCenter);
    countdownLabel->setStyleSheet("QLabel { font-size: 12pt; color: #F57C00; font-weight: bold; }");
    dialogLayout->addWidget(countdownLabel);

    QPushButton* proceedButton = new QPushButton(tr("I Understand - Proceed (10)"));
    proceedButton->setEnabled(false);
    proceedButton->setStyleSheet("QPushButton:disabled { background-color: #BDBDBD; }");

    QPushButton* cancelButton = new QPushButton(tr("Cancel"));

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(proceedButton);
    dialogLayout->addLayout(buttonLayout);

    // Setup countdown timer (stack-based to avoid dangling pointers)
    QTimer countdownTimer;
    countdownTimer.setParent(warningDialog);
    int countdown = 10;

    connect(&countdownTimer, &QTimer::timeout, [&]() {
        countdown--;
        if (countdown > 0) {
            proceedButton->setText(tr("I Understand - Proceed (%1)").arg(countdown));
            countdownLabel->setText(tr("Please wait %1 seconds before proceeding...").arg(countdown));
        } else {
            countdownTimer.stop();
            proceedButton->setEnabled(true);
            proceedButton->setText(tr("I Understand - Proceed"));
            proceedButton->setStyleSheet("QPushButton { background-color: #FF6600; color: white; font-weight: bold; }");
            countdownLabel->setText(tr("You may now proceed if you understand the risks."));
            countdownLabel->setStyleSheet("QLabel { font-size: 12pt; color: #2E7D32; font-weight: bold; }");
        }
    });
    connect(warningDialog, &QDialog::finished, &countdownTimer, &QTimer::stop);
    countdownTimer.start(1000);

    connect(cancelButton, &QPushButton::clicked, warningDialog, &QDialog::reject);
    connect(proceedButton, &QPushButton::clicked, warningDialog, &QDialog::accept);

    int firstResult = warningDialog->exec();

    if (firstResult != QDialog::Accepted) {
        return; // User cancelled
    }

    // === SECOND CONFIRMATION: Final confirmation with transaction details ===
    QMessageBox finalConfirmBox(TopLevelDialogParent(this));
    finalConfirmBox.setWindowTitle(tr("Final Confirmation"));
    finalConfirmBox.setIcon(QMessageBox::Question);

    QString confirmMsg = tr("<b>Please confirm the following deposit details:</b><br><br>");
    confirmMsg += tr("<b>Model Name:</b> %1<br>").arg(name);
    confirmMsg += tr("<b>Model Commit:</b> %1<br>").arg(commit);
    confirmMsg += tr("<b>Difficulty:</b> %1<br>").arg(difficulty);
    if (!cid.isEmpty()) {
        confirmMsg += tr("<b>IPFS CID:</b> %1<br>").arg(cid);
    }
    if (!extra.isEmpty()) {
        confirmMsg += tr("<b>Extra Metadata:</b> %1<br>").arg(extra.left(100) + (extra.length() > 100 ? "..." : ""));
    }
    confirmMsg += tr("<br><b>Deposit Amount:</b> ~5 TSC<br><br>");
    confirmMsg += tr("<b style='color: #C62828;'>This action cannot be undone. Proceed?</b>");

    finalConfirmBox.setText(confirmMsg);
    finalConfirmBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    finalConfirmBox.setDefaultButton(QMessageBox::No);

    if (finalConfirmBox.exec() != QMessageBox::Yes) {
        return; // User cancelled
    }

    // === PROCEED WITH TRANSACTION ===
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        showError(tr("Wallet unlock was cancelled."));
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(name.toStdString());
        params.push_back(commit.toStdString());
        params.push_back(difficulty);
        if (!cid.isEmpty()) {
            params.push_back(cid.toStdString());
        }
        if (!extra.isEmpty()) {
            if (cid.isEmpty()) {
                params.push_back(""); // placeholder for cid
            }
            params.push_back(extra.toStdString());
        }

        UniValue result = clientModel->node().executeRpc("createmodeldeposit", params, walletModel->getWalletName().toStdString());

        QString txid = QString::fromStdString(result["txid"].get_str());
        QString modelHash = QString::fromStdString(result["model_hash"].get_str());
        QString depositAddr = QString::fromStdString(result["deposit_address"].get_str());
        int depositVout = result["deposit_vout"].getInt<int>();
        QString depositAmount = QString::fromStdString(result["deposit_amount"].getValStr());

        regStatusText->setStyleSheet("QTextEdit { color: #2E7D32; font-family: monospace; }");
        regStatusText->setText(
            tr("<b>✓ Deposit Transaction Created Successfully</b><br><br>") +
            tr("<b>Transaction ID:</b> %1<br>").arg(txid) +
            tr("<b>Model Hash:</b> %2<br>").arg(modelHash) +
            tr("<b>Deposit Address:</b> %3<br>").arg(depositAddr) +
            tr("<b>Deposit Output:</b> %4<br>").arg(depositVout) +
            tr("<b>Deposit Amount:</b> %5 TSC<br><br>").arg(depositAmount) +
            tr("<b>Raw Hex:</b><br>%1<br><br>").arg(txid) +
            tr("⏳ <b>Next Step:</b> Wait for confirmation, then go to Commit tab to complete registration.")
        );

        regDepositValidated = false;
        regCreateButton->setEnabled(false);

        showSuccess(tr("Deposit transaction broadcast successfully"));

    } catch (const UniValue& objError) {
        const QString err = FormatRpcError(objError);
        regStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        regStatusText->setText(tr("<b>✗ Error Creating Deposit:</b><br>%1").arg(err));
        showError(err);
    } catch (const std::exception& e) {
        regStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        regStatusText->setText(tr("<b>✗ Error Creating Deposit:</b><br>%1").arg(QString::fromStdString(e.what())));
        showError(QString::fromStdString(e.what()));
    }
}

void ModelsPage::onTabChanged(int index)
{
    if (!tabWidget) {
        return;
    }

    QWidget* current = tabWidget->widget(index);
    if (current == registerTab) {
        resetRegisterValidationState();
        if (!regHowItWorksShownOnce) {
            regHowItWorksShownOnce = true;
            onRegisterHowItWorks();
        }
        return;
    }

    if (current == commitTab) {
        onCommitRefresh();
        return;
    }

    if (current == myDepositsTab) {
        onMyDepositsRefresh();
        return;
    }

    if (current == registryTab) {
        onRegistryRefresh();
        return;
    }

    if (current == challengeTab) {
        if (!challengeHowItWorksShownOnce) {
            challengeHowItWorksShownOnce = true;
            onChallengeHowItWorks();
        }
        onChallengeRefresh();
        return;
    }

    if (current == discussionTab) {
        onDiscussionLoadActiveScopes(false);
        onDiscussionRefresh();
        return;
    }
}

// ===== COMMIT TAB SLOTS =====

void ModelsPage::onCommitRefresh()
{
    if (!walletModel) {
        showError(tr("Wallet model not available"));
        return;
    }

    commitDepositTable->setRowCount(0);
    selectedDepositTxid.clear();
    selectedDepositVout = -1;
    selectedDepositModelHash.clear();
    commitCreateButton->setEnabled(false);

    try {
        const std::string walletName = walletModel->getWalletName().toStdString();
        const QString zeroHash(64, QChar('0'));

        // Load the full on-chain registry and keep only deposits belonging to this wallet.
        UniValue params(UniValue::VARR);
        params.push_back(false); // extended view
        UniValue models = clientModel->node().executeRpc("getmodelslist", params, "");

        const auto isWalletTx = [&](const QString& txid) -> bool {
            if (txid.isEmpty() || txid == zeroHash) return false;
            try {
                UniValue getTxParams(UniValue::VARR);
                getTxParams.push_back(txid.toStdString());
                getTxParams.push_back(true);
                clientModel->node().executeRpc("gettransaction", getTxParams, walletName);
                return true;
            } catch (...) {
                return false;
            }
        };

        for (size_t i = 0; i < models.size(); ++i) {
            const UniValue& model = models[i];
            if (!model.isObject() || !model.exists("model_hash") || !model.exists("model_name") ||
                !model.exists("model_commit") || !model.exists("status") ||
                !model.exists("deposit_txid") || !model.exists("deposit_vout")) {
                continue;
            }

            const int status = model["status"].getInt<int>();
            if (status != static_cast<int>(ModelRegistrationStatus::PendingDeposit) &&
                status != static_cast<int>(ModelRegistrationStatus::PendingVerification)) {
                continue;
            }

            const QString txid = QString::fromStdString(model["deposit_txid"].get_str());
            const int vout = model["deposit_vout"].getInt<int>();
            if (!isWalletTx(txid) || vout < 0) {
                continue;
            }

            const QString modelHash = QString::fromStdString(model["model_hash"].get_str());
            const QString modelName = QString::fromStdString(model["model_name"].get_str());
            const QString modelCommit = QString::fromStdString(model["model_commit"].get_str());
            const CAmount depositAmountSats = model.exists("deposit_amount")
                                                  ? model["deposit_amount"].getInt<int64_t>()
                                                  : 0;
            const QString depositAmount = BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, depositAmountSats);

            int row = commitDepositTable->rowCount();
            commitDepositTable->insertRow(row);

            QTableWidgetItem* hashItem = new QTableWidgetItem(modelHash.left(16) + "...");
            hashItem->setData(Qt::UserRole, modelHash);
            hashItem->setToolTip(modelHash);
            commitDepositTable->setItem(row, 0, hashItem);

            commitDepositTable->setItem(row, 1, new QTableWidgetItem(modelName + "@" + modelCommit));

            QTableWidgetItem* txidItem = new QTableWidgetItem(txid.left(16) + "...");
            txidItem->setData(Qt::UserRole, txid);
            txidItem->setToolTip(txid);
            commitDepositTable->setItem(row, 2, txidItem);

            QTableWidgetItem* voutItem = new QTableWidgetItem(QString::number(vout));
            voutItem->setData(Qt::UserRole, vout);
            commitDepositTable->setItem(row, 3, voutItem);

            commitDepositTable->setItem(row, 4, new QTableWidgetItem(depositAmount));
            commitDepositTable->setItem(row, 5, new QTableWidgetItem(getStatusString(status)));
        }

        commitStatusText->setStyleSheet("QTextEdit { color: #1976D2; }");
        commitStatusText->setText(tr("Found %1 deposit(s) awaiting commit/verification in wallet").arg(commitDepositTable->rowCount()));
        if (commitSelectedSummaryLabel && selectedDepositTxid.isEmpty()) {
            commitSelectedSummaryLabel->setText(tr("No deposit selected. Choose a pending deposit to see the next available action."));
        }

    } catch (const UniValue& objError) {
        const QString err = FormatRpcError(objError);
        commitStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        commitStatusText->setText(tr("Error: %1").arg(err));
    } catch (const std::exception& e) {
        commitStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        commitStatusText->setText(tr("Error: %1").arg(QString::fromStdString(e.what())));
    }
}

void ModelsPage::onCommitDepositSelected(int row, int column)
{
    Q_UNUSED(column);

    if (row < 0 || row >= commitDepositTable->rowCount()) {
        return;
    }

    selectedDepositTxid = commitDepositTable->item(row, 2)->data(Qt::UserRole).toString();
    selectedDepositVout = commitDepositTable->item(row, 3)->data(Qt::UserRole).toInt();
    selectedDepositModelHash = commitDepositTable->item(row, 0)->data(Qt::UserRole).toString();
    if (!commitFlowInProgress) {
        commitCreateButton->setEnabled(true);
        commitCreateButton->setToolTip(tr("Choose how many commit transactions to create for the selected deposit."));
    }

    QString modelHash = commitDepositTable->item(row, 0)->data(Qt::UserRole).toString();
    QString nameCommit = commitDepositTable->item(row, 1)->text();
    QString amount = commitDepositTable->item(row, 4)->text();
    QString status = commitDepositTable->item(row, 5)->text();
    if (commitSelectedSummaryLabel) {
        commitSelectedSummaryLabel->setText(
            tr("<b>Model:</b> %1<br>"
               "<b>Deposit:</b> %2:%3<br>"
               "<b>Amount:</b> %4<br>"
               "<b>Status:</b> %5<br>"
               "<b>Next step:</b> Use <i>Create Commits</i> to choose how many commit transactions to create for this deposit.")
                .arg(nameCommit)
                .arg(selectedDepositTxid)
                .arg(selectedDepositVout)
                .arg(amount)
                .arg(status));
    }
    commitStatusText->setStyleSheet("QTextEdit { color: #1976D2; }");
    commitStatusText->setText(
        tr("<b>Selected Deposit:</b><br>") +
        tr("Model: %1<br>").arg(nameCommit) +
        tr("Transaction: %1<br>").arg(selectedDepositTxid) +
        tr("Output: %2<br>").arg(selectedDepositVout) +
        tr("Amount: %1<br>").arg(amount) +
        tr("Current status: %1<br>").arg(status) +
        tr("Model Hash: %3<br><br>").arg(modelHash) +
        tr("Click <b>Create Commits</b> to choose the number of commit transactions to create.")
    );
}

void ModelsPage::onCreateCommit()
{
    if (commitFlowInProgress) {
        showError(tr("A commit flow is already in progress. Please wait for it to finish."));
        return;
    }

    if (!walletModel || selectedDepositTxid.isEmpty() || selectedDepositVout < 0) {
        showError(tr("No deposit selected"));
        return;
    }

    const auto& consensus = Params().GetConsensus();
    bool ok = false;
    const int txCount = QInputDialog::getInt(
        this,
        tr("Create Commits"),
        tr("Number of commit transactions to create (1-%1):").arg(consensus.ModelVerificationBlockCount),
        static_cast<int>(consensus.ModelSuccessfulCommitsThreshold),
        1,
        static_cast<int>(consensus.ModelVerificationBlockCount),
        1,
        &ok);

    if (!ok) {
        return;
    }

    if (txCount < 1 || txCount > static_cast<int>(consensus.ModelVerificationBlockCount)) {
        showError(tr("Commit count must be a positive integer not greater than %1.")
                      .arg(consensus.ModelVerificationBlockCount));
        return;
    }

    runModelCommitFundingFlow(static_cast<unsigned int>(txCount), tr("Create Commits"));
}

void ModelsPage::runModelCommitFundingFlow(unsigned int txCount, const QString& flowLabel)
{
    if (commitFlowInProgress) {
        showError(tr("A commit flow is already in progress. Please wait for it to finish."));
        return;
    }

    if (!walletModel || !clientModel || selectedDepositTxid.isEmpty() || selectedDepositVout < 0) {
        showError(tr("No deposit selected"));
        return;
    }
    const auto& consensus = Params().GetConsensus();
    if (txCount < 1 || txCount > consensus.ModelVerificationBlockCount) {
        showError(tr("Commit count must be between 1 and %1.").arg(consensus.ModelVerificationBlockCount));
        return;
    }

    static constexpr CAmount COMMIT_FUNDING_TARGET{20'000};
    const int commitPhaseTimeoutMs = ComputeCommitPhaseTimeoutMs();
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        showError(tr("Wallet unlock was cancelled."));
        return;
    }

    commitFlowInProgress = true;
    const auto finish_commit_flow = [&]() {
        commitFlowInProgress = false;
        const bool has_selection = !selectedDepositTxid.isEmpty() && selectedDepositVout >= 0;
        if (commitCreateButton) {
            commitCreateButton->setEnabled(has_selection);
        }
    };

    const std::string walletName = walletModel->getWalletName().toStdString();
    commitStatusText->setStyleSheet("QTextEdit { color: #1976D2; font-family: monospace; }");
    commitStatusText->setText(tr("Starting %1...\nRequested commit count: %2\n").arg(flowLabel).arg(txCount));

    UniValue lockedUtxoList(UniValue::VARR);
    const auto unlockDeposit = [&]() {
        try {
            if (lockedUtxoList.empty()) {
                return;
            }
            UniValue unlockParams(UniValue::VARR);
            unlockParams.push_back(true); // unlock
            unlockParams.push_back(lockedUtxoList);
            clientModel->node().executeRpc("lockunspent", unlockParams, walletName);
        } catch (...) {
            // best effort unlock
        }
    };

    try {
        QString commitDepositTxid = selectedDepositTxid;
        int commitDepositVout = selectedDepositVout;
        const QString zeroHash(64, QChar('0'));
        if (!selectedDepositModelHash.isEmpty()) {
            UniValue statusParams(UniValue::VARR);
            statusParams.push_back(selectedDepositModelHash.toStdString());
            UniValue statusResult =
                clientModel->node().executeRpc("getmodelregistrationstatus", statusParams, walletName);
            if (statusResult.isObject() && statusResult.exists("deposit_txid") && statusResult.exists("deposit_vout")) {
                const QString statusDepositTxid =
                    QString::fromStdString(statusResult["deposit_txid"].get_str());
                const int statusDepositVout = statusResult["deposit_vout"].getInt<int>();
                if (!statusDepositTxid.isEmpty() && statusDepositTxid != zeroHash && statusDepositVout >= 0) {
                    commitDepositTxid = statusDepositTxid;
                    commitDepositVout = statusDepositVout;
                }
            }
        }
        if (commitDepositTxid.isEmpty() || commitDepositTxid == zeroHash || commitDepositVout < 0) {
            throw std::runtime_error("Selected model has empty or invalid deposit outpoint");
        }

        // Lock all wallet-owned model deposits so coin selection cannot accidentally use
        // any registration deposit as a funding input for the temporary funding tx.
        const auto isWalletOutpointUnspent = [&](const QString& txid, int vout) -> bool {
            if (txid.isEmpty() || vout < 0) {
                return false;
            }
            try {
                UniValue getTxParams(UniValue::VARR);
                getTxParams.push_back(txid.toStdString());
                getTxParams.push_back(true);
                clientModel->node().executeRpc("gettransaction", getTxParams, walletName);

                UniValue getTxOutParams(UniValue::VARR);
                getTxOutParams.push_back(txid.toStdString());
                getTxOutParams.push_back(vout);
                getTxOutParams.push_back(true);
                UniValue txout = clientModel->node().executeRpc("gettxout", getTxOutParams, walletName);
                return !txout.isNull();
            } catch (...) {
                return false;
            }
        };

        UniValue walletTxParams(UniValue::VARR);
        walletTxParams.push_back("*");
        walletTxParams.push_back(1000);
        walletTxParams.push_back(0);
        walletTxParams.push_back(true);
        UniValue walletTxs = clientModel->node().executeRpc("listtransactions", walletTxParams, walletName);

        QSet<QString> alreadyLockedOutpoints;
        {
            UniValue listLockedParams(UniValue::VARR);
            UniValue currentlyLocked = clientModel->node().executeRpc("listlockunspent", listLockedParams, walletName);
            for (size_t i = 0; i < currentlyLocked.size(); ++i) {
                const UniValue& locked = currentlyLocked[i];
                if (!locked.isObject() || !locked.exists("txid") || !locked.exists("vout")) {
                    continue;
                }
                const QString lockedTxid = QString::fromStdString(locked["txid"].get_str());
                const int lockedVout = locked["vout"].getInt<int>();
                alreadyLockedOutpoints.insert(QStringLiteral("%1:%2").arg(lockedTxid).arg(lockedVout));
            }
        }

        const QString selectedOutpointKey = QStringLiteral("%1:%2").arg(commitDepositTxid).arg(commitDepositVout);
        if (alreadyLockedOutpoints.contains(selectedOutpointKey)) {
            // This outpoint was left locked before this flow (stale lock). Unlock only the current deposit.
            UniValue unlockParams(UniValue::VARR);
            unlockParams.push_back(true);
            UniValue utxo(UniValue::VOBJ);
            utxo.pushKV("txid", commitDepositTxid.toStdString());
            utxo.pushKV("vout", commitDepositVout);
            UniValue utxoList(UniValue::VARR);
            utxoList.push_back(utxo);
            unlockParams.push_back(utxoList);
            clientModel->node().executeRpc("lockunspent", unlockParams, walletName);
            alreadyLockedOutpoints.remove(selectedOutpointKey);
        }
        QSet<QString> processedWalletTxids;
        QSet<QString> seenLockedOutpoints;
        for (size_t i = 0; i < walletTxs.size(); ++i) {
            const UniValue& tx = walletTxs[i];
            const QString walletTxid = QString::fromStdString(tx["txid"].get_str());
            if (walletTxid.isEmpty() || processedWalletTxids.contains(walletTxid)) {
                continue;
            }
            processedWalletTxids.insert(walletTxid);

            QString modelHash, modelName, modelCommit, cid, extra, depositAmount;
            int64_t difficulty{0};
            int depositVout{-1};
            const int txVout = tx.exists("vout") ? tx["vout"].getInt<int>() : -1;
            if (!parseDepositTransaction(walletTxid, txVout, modelHash, modelName, modelCommit, difficulty,
                                         cid, extra, depositVout, depositAmount)) {
                continue;
            }

            const QString outpointKey = QStringLiteral("%1:%2").arg(walletTxid).arg(depositVout);
            if (seenLockedOutpoints.contains(outpointKey)) {
                continue;
            }
            if (alreadyLockedOutpoints.contains(outpointKey)) {
                continue;
            }
            if (!isWalletOutpointUnspent(walletTxid, depositVout)) {
                continue;
            }
            seenLockedOutpoints.insert(outpointKey);

            UniValue utxo(UniValue::VOBJ);
            utxo.pushKV("txid", walletTxid.toStdString());
            utxo.pushKV("vout", depositVout);
            lockedUtxoList.push_back(utxo);
        }

        if (lockedUtxoList.size() > 0) {
            UniValue lockParams(UniValue::VARR);
            lockParams.push_back(false); // lock
            lockParams.push_back(lockedUtxoList);
            clientModel->node().executeRpc("lockunspent", lockParams, walletName);
        }

        // Step 1: auto-select wallet inputs and split directly into funding outputs.
        UniValue splitParams(UniValue::VARR);
        splitParams.push_back(zeroHash.toStdString());
        splitParams.push_back(0);
        splitParams.push_back(static_cast<int>(txCount));
        splitParams.push_back(static_cast<int64_t>(COMMIT_FUNDING_TARGET));
        UniValue splitResult = clientModel->node().executeRpc("splitutxo", splitParams, walletName);
        const QString splitTxid = QString::fromStdString(splitResult["txid"].get_str());

        commitStatusText->append(tr("Funding split transaction created: %1\nWaiting for split transaction confirmation...").arg(splitTxid));
        if (!waitForTxConfirmation(splitTxid, walletName, 1, commitPhaseTimeoutMs, tr("Split confirmation"))) {
            unlockDeposit();
            finish_commit_flow();
            showError(tr("Timeout waiting for split transaction confirmation"));
            return;
        }

        UniValue fundingArray(UniValue::VARR);
        const UniValue& outputs = splitResult["outputs"];
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& out = outputs[i];
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("txid", splitTxid.toStdString());
            entry.pushKV("vout", out["vout"].getInt<int>());
            fundingArray.push_back(entry);
        }

        // Step 2: create commit transactions using split outputs as funding_utxos.
        UniValue commitParams(UniValue::VARR);
        commitParams.push_back(commitDepositTxid.toStdString());
        commitParams.push_back(commitDepositVout);
        commitParams.push_back(static_cast<int>(txCount));
        commitParams.push_back(fundingArray);

        UniValue result = clientModel->node().executeRpc("createmodelcommit", commitParams, walletName);

        QString commitTxid = QString::fromStdString(result["txid"].get_str());
        QString verdict = QString::fromStdString(result["verdict"].get_str());
        QString refundAmount = QString::fromStdString(result["refund_amount"].getValStr());
        QString modelHash = QString::fromStdString(result["model_hash"].get_str());

        commitStatusText->setStyleSheet("QTextEdit { color: #2E7D32; font-family: monospace; }");
        commitStatusText->setText(
            tr("<b>✓ %1 Completed</b><br><br>").arg(flowLabel) +
            tr("<b>Commit Tx:</b> %1<br>").arg(commitTxid) +
            tr("<b>Commit Count:</b> %1<br>").arg(txCount) +
            tr("<b>Verdict:</b> %1<br>").arg(verdict) +
            tr("<b>Refund Amount:</b> %1 TSC<br>").arg(refundAmount) +
            tr("<b>Model Hash:</b> %1<br>").arg(modelHash) +
            tr("<br><b>Funding Split Tx:</b> %1<br><br>").arg(splitTxid) +
            tr("Used %1 split funding UTXO(s).").arg(fundingArray.size())
        );

        unlockDeposit();
        finish_commit_flow();
        const QString successMessage = tr("%1 broadcast successfully").arg(flowLabel);
        QTimer::singleShot(0, this, [this, successMessage]() {
            showSuccess(successMessage);
            onCommitRefresh();
        });

    } catch (const UniValue& objError) {
        unlockDeposit();
        const QString err = FormatRpcError(objError);
        commitStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        commitStatusText->setText(tr("<b>✗ Error in temporary flow:</b><br>%1").arg(err));
        finish_commit_flow();
        showError(err);
    } catch (const std::exception& e) {
        unlockDeposit();
        commitStatusText->setStyleSheet("QTextEdit { color: #C62828; }");
        commitStatusText->setText(tr("<b>✗ Error in temporary flow:</b><br>%1").arg(QString::fromStdString(e.what())));
        finish_commit_flow();
        showError(QString::fromStdString(e.what()));
    }
}

// ===== MY DEPOSITS TAB SLOTS =====

void ModelsPage::onMyDepositsRefresh()
{
    refreshMyDeposits();
}

void ModelsPage::refreshMyDeposits()
{
    if (!walletModel) {
        return;
    }

    myDepositsSelectedModelHash.clear();
    myDepositsSelectedReclaimAllowed = false;
    if (myDepositsReclaimButton) {
        myDepositsReclaimButton->setEnabled(false);
    }
    myDepositsTable->setRowCount(0);
    int filterStatus = myDepositsFilterCombo->currentData().toInt();
    int currentHeight = getCurrentHeight();
    const QString searchText = myDepositsSearchEdit ? myDepositsSearchEdit->text().trimmed().toLower() : QString();

    try {
        const std::string walletName = walletModel->getWalletName().toStdString();
        const QString zeroHash(64, QChar('0'));

        UniValue params(UniValue::VARR);
        params.push_back(false); // extended view
        UniValue models = clientModel->node().executeRpc("getmodelslist", params, "");

        const auto isWalletTx = [&](const QString& txid) -> bool {
            if (txid.isEmpty() || txid == zeroHash) return false;
            try {
                UniValue getTxParams(UniValue::VARR);
                getTxParams.push_back(txid.toStdString());
                getTxParams.push_back(true);
                clientModel->node().executeRpc("gettransaction", getTxParams, walletName);
                return true;
            } catch (...) {
                return false;
            }
        };

        for (size_t i = 0; i < models.size(); ++i) {
            const UniValue& model = models[i];
            if (!model.isObject() || !model.exists("model_hash") || !model.exists("model_name") ||
                !model.exists("model_commit") || !model.exists("deposit_txid") || !model.exists("deposit_vout")) {
                continue;
            }

            const QString txid = QString::fromStdString(model["deposit_txid"].get_str());
            const int vout = model["deposit_vout"].getInt<int>();
            if (!isWalletTx(txid) || vout < 0) {
                continue;
            }

            const QString modelHash = QString::fromStdString(model["model_hash"].get_str());
            const QString modelName = QString::fromStdString(model["model_name"].get_str());
            const QString modelCommit = QString::fromStdString(model["model_commit"].get_str());

            UniValue statusParams(UniValue::VARR);
            statusParams.push_back(modelHash.toStdString());

            try {
                UniValue statusResult = clientModel->node().executeRpc("getmodelregistrationstatus", statusParams, walletName);

                QString statusStr = QString::fromStdString(statusResult["status"].get_str());
                const auto statusOpt = StatusFromString(statusStr);
                const int statusValue = statusOpt ? static_cast<int>(*statusOpt) : -1;

                if (filterStatus != -1 && statusValue != filterStatus) {
                    continue;
                }

                if (!searchText.isEmpty()) {
                    if (!modelName.toLower().contains(searchText) &&
                        !modelHash.toLower().contains(searchText) &&
                        !txid.toLower().contains(searchText)) {
                        continue;
                    }
                }

                const CAmount depositAmountSats = model.exists("deposit_amount")
                                                      ? model["deposit_amount"].getInt<int64_t>()
                                                      : 0;
                const QString depositAmount = BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, depositAmountSats);

                int row = myDepositsTable->rowCount();
                myDepositsTable->insertRow(row);

                QTableWidgetItem* hashItem = new QTableWidgetItem(modelHash.left(16) + "...");
                hashItem->setData(Qt::UserRole, modelHash);
                hashItem->setToolTip(modelHash);
                hashItem->setData(Qt::UserRole + 1, txid); // Store txid for details
                myDepositsTable->setItem(row, 0, hashItem);

                myDepositsTable->setItem(row, 1, new QTableWidgetItem(modelName + "@" + modelCommit));

                QTableWidgetItem* txidItem = new QTableWidgetItem(txid.left(16) + "...");
                txidItem->setToolTip(txid);
                myDepositsTable->setItem(row, 2, txidItem);

                QTableWidgetItem* statusItem = new QTableWidgetItem(statusOpt ? getStatusString(statusValue) : statusStr);
                statusItem->setForeground(QColor(getStatusColor(statusValue)));
                myDepositsTable->setItem(row, 3, statusItem);

                int blockHeight = statusResult.exists("deposit_block_height") ?
                                 statusResult["deposit_block_height"].getInt<int>() : 0;
                myDepositsTable->setItem(row, 4, new QTableWidgetItem(QString::number(blockHeight)));

                const int unlockHeight = statusResult.exists("deposit_unlock_height")
                                            ? statusResult["deposit_unlock_height"].getInt<int>()
                                            : 0;
                const bool ownerReclaimAllowed = statusResult.exists("owner_reclaim_allowed") &&
                                                 statusResult["owner_reclaim_allowed"].get_bool();
                QString maturity = "-";
                if (statusOpt && *statusOpt == ModelRegistrationStatus::Registered && unlockHeight > 0 && currentHeight > 0) {
                    int remaining = unlockHeight - currentHeight;
                    if (remaining > 0) {
                        maturity = tr("%1 blocks").arg(remaining);
                    } else {
                        maturity = tr("✓ Mature");
                    }
                }
                QTableWidgetItem* maturityItem = new QTableWidgetItem(maturity);
                maturityItem->setData(Qt::UserRole, unlockHeight);
                maturityItem->setData(Qt::UserRole + 1, ownerReclaimAllowed);
                myDepositsTable->setItem(row, 5, maturityItem);

                QString verif = statusResult.exists("verification_code") ?
                               QString::number(statusResult["verification_code"].getInt<int>()) : "-";
                myDepositsTable->setItem(row, 6, new QTableWidgetItem(verif));

                QString action = tr("No action");
                if (statusOpt) {
                    switch (*statusOpt) {
                    case ModelRegistrationStatus::PendingDeposit:
                        action = tr("Create commit");
                        break;
                    case ModelRegistrationStatus::PendingVerification:
                        action = tr("Wait verification");
                        break;
                    case ModelRegistrationStatus::Registered:
                        action = ownerReclaimAllowed ? tr("Reclaim deposit") : tr("Wait maturity");
                        break;
                    case ModelRegistrationStatus::Locked:
                    case ModelRegistrationStatus::Banned:
                        action = tr("No action");
                        break;
                    }
                }
                myDepositsTable->setItem(row, 7, new QTableWidgetItem(action));

            } catch (...) {
                // Skip if status lookup fails
            }
        }

    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    }
}

void ModelsPage::onMyDepositsFilterChanged(int index)
{
    Q_UNUSED(index);
    refreshMyDeposits();
}

void ModelsPage::onMyDepositSelected(int row, int column)
{
    Q_UNUSED(column);

    if (row < 0 || row >= myDepositsTable->rowCount()) {
        return;
    }

    QString modelHash = myDepositsTable->item(row, 0)->data(Qt::UserRole).toString();
    QString txid = myDepositsTable->item(row, 0)->data(Qt::UserRole + 1).toString();
    myDepositsSelectedModelHash = modelHash;
    myDepositsSelectedReclaimAllowed = false;
    if (myDepositsReclaimButton) {
        myDepositsReclaimButton->setEnabled(false);
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(modelHash.toStdString());

        UniValue result = clientModel->node().executeRpc("getmodelregistrationstatus", params, walletModel->getWalletName().toStdString());
        const int currentHeight = getCurrentHeight();

        myDepositsDetailsText->setStyleSheet("QTextEdit { font-family: sans-serif; }");

        const QString status = QString::fromStdString(result["status"].get_str());
        const int depositHeight = result.exists("deposit_block_height") ? result["deposit_block_height"].getInt<int>() : 0;
        const int commitHeight = result.exists("commit_block_height") ? result["commit_block_height"].getInt<int>() : 0;
        const int unlockHeight = result.exists("deposit_unlock_height") ? result["deposit_unlock_height"].getInt<int>() : 0;
        const bool ownerReclaimAllowed = result.exists("owner_reclaim_allowed") && result["owner_reclaim_allowed"].get_bool();
        const QString verificationCode = result.exists("verification_code")
                                             ? QString::number(result["verification_code"].getInt<int>())
                                             : tr("-");
        const QString verificationDetails = result.exists("verification_details") && !result["verification_details"].get_str().empty()
                                                ? QString::fromStdString(result["verification_details"].get_str())
                                                : QString();

        QString lifecycle;
        if (status == QStringLiteral("pending_deposit") || status == QStringLiteral("pending")) {
            lifecycle = tr("Next step: create a commit transaction from the Commit tab.");
        } else if (status == QStringLiteral("pending_verification")) {
            lifecycle = tr("Next step: wait for verification to complete.");
        } else if (status == QStringLiteral("registered")) {
            if (ownerReclaimAllowed) {
                lifecycle = tr("Deposit is mature. You can reclaim it now.");
            } else if (unlockHeight > 0 && currentHeight < unlockHeight) {
                lifecycle = tr("Next step: wait until block %1 for maturity (%2 blocks left).")
                                .arg(unlockHeight)
                                .arg(unlockHeight - currentHeight);
            } else {
                lifecycle = tr("Deposit is registered and waiting for unlock height.");
            }
        } else {
            lifecycle = tr("No action available for this deposit.");
        }

        QString details = tr("<b>Model Registration Details</b><br><br>");
        details += tr("<b>Model Hash:</b> %1<br>").arg(modelHash);
        details += tr("<b>Status:</b> %1<br>").arg(status);
        details += tr("<b>Deposit TX:</b> %1<br>").arg(QString::fromStdString(result["deposit_txid"].get_str()));
        details += tr("<b>Deposit Vout:</b> %1<br>").arg(result["deposit_vout"].getInt<int>());
        details += tr("<b>Viewed TXID:</b> %1<br>").arg(txid);

        if (depositHeight > 0) {
            details += tr("<b>Deposit Height:</b> %1<br>").arg(depositHeight);
        }
        if (unlockHeight > 0) {
            details += tr("<b>Deposit Unlock Height:</b> %1<br>").arg(unlockHeight);
        }

        if (result.exists("commit_txid") && !result["commit_txid"].get_str().empty()) {
            details += tr("<b>Commit TX:</b> %1<br>").arg(QString::fromStdString(result["commit_txid"].get_str()));
        }

        if (commitHeight > 0) {
            details += tr("<b>Commit Height:</b> %1<br>").arg(commitHeight);
        }

        details += tr("<b>Verification Code:</b> %1<br>").arg(verificationCode);

        details += tr("<br><b>Lifecycle</b><br>%1<br>").arg(lifecycle);

        if (!verificationDetails.isEmpty()) {
            details += tr("<br><b>Verification Details:</b><br>%1<br>").arg(verificationDetails.toHtmlEscaped());
        }

        myDepositsDetailsText->setHtml(details);
        myDepositsSelectedReclaimAllowed = ownerReclaimAllowed;
        if (myDepositsReclaimButton) {
            myDepositsReclaimButton->setEnabled(ownerReclaimAllowed);
            myDepositsReclaimButton->setToolTip(ownerReclaimAllowed
                                                    ? tr("Broadcast a reclaim transaction for this mature deposit.")
                                                    : tr("Available only for registered deposits after the unlock height is reached."));
        }

    } catch (const UniValue& objError) {
        const QString err = FormatRpcError(objError);
        myDepositsDetailsText->setText(tr("Error: %1").arg(err));
    } catch (const std::exception& e) {
        myDepositsDetailsText->setText(tr("Error: %1").arg(QString::fromStdString(e.what())));
    }
}

void ModelsPage::onMyDepositReclaim()
{
    if (!walletModel || !clientModel || myDepositsSelectedModelHash.isEmpty()) {
        return;
    }
    if (!myDepositsSelectedReclaimAllowed) {
        showError(tr("This deposit is not reclaimable yet."));
        return;
    }

    const auto choice = QMessageBox::question(this,
                                              tr("Reclaim Deposit"),
                                              tr("Broadcast a reclaim transaction for the selected mature model deposit?"),
                                              QMessageBox::Yes | QMessageBox::No,
                                              QMessageBox::No);
    if (choice != QMessageBox::Yes) {
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        showError(tr("Wallet unlock was cancelled."));
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(myDepositsSelectedModelHash.toStdString());
        UniValue result = clientModel->node().executeRpc("createmodelreclaim", params, walletModel->getWalletName().toStdString());
        const QString txid = QString::fromStdString(result["txid"].get_str());
        showSuccess(tr("Reclaim transaction broadcast: %1").arg(txid));
        onMyDepositsRefresh();
    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    }
}

// ===== REGISTRY TAB SLOTS =====

void ModelsPage::onRegistryRefresh()
{
    refreshRegistry();
}

void ModelsPage::refreshRegistry()
{
    if (!walletModel) {
        return;
    }

    registrySelectedModelHash.clear();
    registrySelectedBurnReady = false;
    registrySelectedBurnAllowedHeight = 0;
    if (registryBurnButton) registryBurnButton->setEnabled(false);

    registryTable->setRowCount(0);
    int filterStatus = registryFilterCombo->currentData().toInt();
    QString searchText = registrySearchEdit->text().trimmed().toLower();
    int currentHeight = getCurrentHeight();

    registryCurrentHeightLabel->setText(tr("Current Height: %1").arg(currentHeight));

    try {
        UniValue params(UniValue::VARR);
        params.push_back(false); // extended view

        UniValue result = clientModel->node().executeRpc("getmodelslist", params, "");

        for (size_t i = 0; i < result.size(); ++i) {
            const UniValue& model = result[i];

            QString modelHash = QString::fromStdString(model["model_hash"].get_str());
            QString modelName = QString::fromStdString(model["model_name"].get_str());
            QString modelCommit = QString::fromStdString(model["model_commit"].get_str());
            int status = model["status"].getInt<int>();
            const auto statusOpt = StatusFromInt(status);

            // Apply filters
            if (filterStatus != -1 && status != filterStatus) {
                continue;
            }

            if (!searchText.isEmpty()) {
                if (!modelName.toLower().contains(searchText) &&
                    !modelHash.toLower().contains(searchText)) {
                    continue;
                }
            }

            int row = registryTable->rowCount();
            registryTable->insertRow(row);

            QTableWidgetItem* hashItem = new QTableWidgetItem(modelHash.left(16) + "...");
            hashItem->setData(Qt::UserRole, modelHash);
            hashItem->setToolTip(modelHash);
            registryTable->setItem(row, 0, hashItem);

            registryTable->setItem(row, 1, new QTableWidgetItem(modelName));
            registryTable->setItem(row, 2, new QTableWidgetItem(modelCommit));

            int64_t difficulty = model["difficulty"].getInt<int64_t>();
            registryTable->setItem(row, 3, new QTableWidgetItem(QString::number(difficulty)));

            QString statusStr = getStatusString(status);
            QTableWidgetItem* statusItem = new QTableWidgetItem(statusStr);
            statusItem->setData(Qt::UserRole, status);
            statusItem->setForeground(QColor(getStatusColor(status)));
            registryTable->setItem(row, 4, statusItem);

            int commitHeight = model.exists("commit_block_height") ? model["commit_block_height"].getInt<int>() : 0;
            registryTable->setItem(row, 5, new QTableWidgetItem(commitHeight > 0 ? QString::number(commitHeight) : "-"));

            QString maturity = "-";
            if (statusOpt && *statusOpt == ModelRegistrationStatus::Registered && commitHeight > 0 && currentHeight > 0) {
                int maturityHeight = commitHeight + 100;
                int remaining = maturityHeight - currentHeight;
                if (remaining > 0) {
                    maturity = tr("%1 blocks").arg(remaining);
                } else {
                    maturity = tr("✓ Mature");
                }
            }
            registryTable->setItem(row, 6, new QTableWidgetItem(maturity));
        }

    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    }
}

void ModelsPage::onRegistryFilterChanged(int index)
{
    Q_UNUSED(index);
    refreshRegistry();
}

void ModelsPage::onRegistrySearchChanged()
{
    refreshRegistry();
}

void ModelsPage::onRegistryModelSelected(int row, int column)
{
    Q_UNUSED(column);

    if (row < 0 || row >= registryTable->rowCount()) {
        return;
    }

    QString modelHash = registryTable->item(row, 0)->data(Qt::UserRole).toString();
    registrySelectedModelHash = modelHash;
    registrySelectedBurnReady = false;
    registrySelectedBurnAllowedHeight = 0;
    if (registryBurnButton) registryBurnButton->setEnabled(false);

    QString detailText;
    try {
        UniValue params(UniValue::VARR);
        params.push_back(modelHash.toStdString());

        UniValue result = clientModel->node().executeRpc("getmodelinfo", params, "");

        registryDetailsText->setStyleSheet("QTextEdit { font-family: monospace; }");
        detailText = QString::fromStdString(result.write(2));

    } catch (const UniValue& objError) {
        registryDetailsText->setText(tr("Error: %1").arg(FormatRpcError(objError)));
        return;
    } catch (const std::exception& e) {
        registryDetailsText->setText(tr("Error: %1").arg(QString::fromStdString(e.what())));
        return;
    }

    // Fetch burn readiness from registration status
    if (walletModel && clientModel) {
        try {
            UniValue statusParams(UniValue::VARR);
            statusParams.push_back(modelHash.toStdString());
            UniValue status = clientModel->node().executeRpc("getmodelregistrationstatus", statusParams, walletModel->getWalletName().toStdString());
            const bool rpcBurnReady = status.exists("burn_ready") && status["burn_ready"].get_bool();
            const int burnBlockHeight = status.exists("burn_block_height") ? status["burn_block_height"].getInt<int>() : 0;
            const bool alreadyBurned = burnBlockHeight > 0;
            registrySelectedBurnReady = rpcBurnReady && !alreadyBurned;
            registrySelectedBurnAllowedHeight = status.exists("burn_allowed_height") ? status["burn_allowed_height"].getInt<int>() : 0;
            if (registryBurnButton) {
                registryBurnButton->setEnabled(registrySelectedBurnReady);
            }
            detailText += "\n---\n";
            detailText += tr("Burn ready: %1 (allowed at height %2, current %3)")
                              .arg(registrySelectedBurnReady ? tr("yes") : tr("no"))
                              .arg(registrySelectedBurnAllowedHeight)
                              .arg(getCurrentHeight());
            if (alreadyBurned) {
                detailText += tr("\nBurn already confirmed at height %1").arg(burnBlockHeight);
            }
        } catch (const UniValue& objError) {
            if (registryBurnButton) registryBurnButton->setEnabled(false);
            detailText += "\n---\n";
            detailText += tr("Burn status error: %1").arg(FormatRpcError(objError));
        } catch (const std::exception& e) {
            if (registryBurnButton) registryBurnButton->setEnabled(false);
            detailText += "\n---\n";
            detailText += tr("Burn status error: %1").arg(QString::fromStdString(e.what()));
        }
    }

    registryDetailsText->setStyleSheet("QTextEdit { font-family: monospace; }");
    registryDetailsText->setText(detailText);
}

void ModelsPage::onRegistryBurn()
{
    if (!walletModel || !clientModel) {
        showError(tr("Wallet or client model not available"));
        return;
    }
    if (registrySelectedModelHash.isEmpty()) {
        showError(tr("Select a model first"));
        return;
    }

    try {
        UniValue statusParams(UniValue::VARR);
        statusParams.push_back(registrySelectedModelHash.toStdString());
        UniValue status = clientModel->node().executeRpc("getmodelregistrationstatus", statusParams, walletModel->getWalletName().toStdString());

        const bool burnReady = status.exists("burn_ready") && status["burn_ready"].get_bool();
        const int burnBlockHeight = status.exists("burn_block_height") ? status["burn_block_height"].getInt<int>() : 0;
        const int burnAllowedHeight = status.exists("burn_allowed_height") ? status["burn_allowed_height"].getInt<int>() : 0;
        const int currentHeight = getCurrentHeight();
        if (burnBlockHeight > 0) {
            showError(tr("Deposit has already been burned at height %1.").arg(burnBlockHeight));
            if (registryBurnButton) registryBurnButton->setEnabled(false);
            return;
        }
        if (!burnReady) {
            showError(tr("Burn not available yet. Allowed at height %1 (current %2).")
                          .arg(burnAllowedHeight)
                          .arg(currentHeight));
            if (registryBurnButton) registryBurnButton->setEnabled(false);
            return;
        }

        QString burnOutpoint;
        if (status.exists("burn_txid") && status.exists("burn_vout")) {
            burnOutpoint = QString("%1:%2")
                               .arg(QString::fromStdString(status["burn_txid"].get_str()))
                               .arg(status["burn_vout"].getInt<int>());
        }

        QString prompt = tr("Create burn transaction for model:\n%1").arg(registrySelectedModelHash);
        if (!burnOutpoint.isEmpty()) {
            prompt += tr("\nBurn outpoint: %1").arg(burnOutpoint);
        }
        prompt += tr("\nThis action is irreversible. Proceed?");

        auto choice = QMessageBox::question(TopLevelDialogParent(this), tr("Burn deposit"), prompt, QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (choice != QMessageBox::Yes) {
            return;
        }

        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            showError(tr("Wallet unlock was cancelled."));
            return;
        }

        UniValue burnParams(UniValue::VARR);
        burnParams.push_back(registrySelectedModelHash.toStdString());
        UniValue result = clientModel->node().executeRpc("createmodelburn", burnParams, walletModel->getWalletName().toStdString());
        QString txid = QString::fromStdString(result.exists("txid") ? result["txid"].get_str() : "");
        showSuccess(tr("Burn transaction created: %1").arg(txid));
        refreshRegistry();
    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    }
}

// ===== CHALLENGE TAB SLOTS =====

void ModelsPage::onChallengeRefresh()
{
    refreshChallengeList();
}

void ModelsPage::onChallengeModelSelected(int row, int column)
{
    Q_UNUSED(column);
    if (row < 0 || row >= challengeTable->rowCount()) {
        return;
    }
    QTableWidgetItem* hashItem = challengeTable->item(row, 0);
    if (!hashItem) return;
    challengeSelectedHash = hashItem->data(Qt::UserRole).toString();
    challengeSelectedIdentifier = hashItem->data(Qt::UserRole + 1).toString();
    challengeSelectedBlockHash.clear();
    challengeLoadBlocksButton->setEnabled(!challengeSelectedIdentifier.isEmpty());
    challengeCreateButton->setEnabled(false);
    challengeSeveralCommitButton->setEnabled(false);
    challengeCreateButton->setToolTip(tr("Select a challenge block first."));
    challengeSeveralCommitButton->setToolTip(tr("No active challenge deposit for this model."));
    challengeSelectedModelDepositTxid.clear();
    challengeSelectedModelDepositVout = -1;
    challengeSelectedDepositTxid.clear();
    challengeSelectedDepositVout = -1;
    challengeBlocksTable->setRowCount(0);
    if (challengeBlocksLabel) {
        challengeBlocksLabel->setText(tr("Blocks (latest 0):"));
    }
    if (challengeStatusLabel) {
        challengeStatusLabel->setText(tr("Checking challenge deposit status..."));
    }
    if (challengeDepositLabel) {
        challengeDepositLabel->setText(tr("-"));
    }
    if (challengeActionLabel) {
        challengeActionLabel->setText(tr("Load blocks and choose a block if you want to create a new challenge deposit."));
    }

    // Try to load challenge deposit info for the selected model to enable commit generation.
    try {
        const std::string walletName = walletModel->getWalletName().toStdString();
        UniValue params(UniValue::VARR);
        params.push_back(challengeSelectedHash.toStdString());
        UniValue statusResult = clientModel->node().executeRpc("getmodelregistrationstatus", params, walletName);
        int challengeDepositHeight = statusResult.exists("challenge_deposit_height") ? statusResult["challenge_deposit_height"].getInt<int>() : 0;
        int challengeVerdictHeight = statusResult.exists("challenge_verdict_height") ? statusResult["challenge_verdict_height"].getInt<int>() : 0;
        challengeSelectedModelDepositTxid = statusResult.exists("deposit_txid")
                                                ? QString::fromStdString(statusResult["deposit_txid"].get_str())
                                                : QString();
        challengeSelectedModelDepositVout = statusResult.exists("deposit_vout")
                                                ? statusResult["deposit_vout"].getInt<int>()
                                                : -1;
        QString challengeDepositTxid = statusResult.exists("challenge_deposit_txid")
                                           ? QString::fromStdString(statusResult["challenge_deposit_txid"].get_str())
                                           : QString();
        int challengeDepositVout = statusResult.exists("challenge_deposit_vout") ? statusResult["challenge_deposit_vout"].getInt<int>() : -1;
        const QString zeroHash = QStringLiteral("0000000000000000000000000000000000000000000000000000000000000000");
        const bool hasDepositTx = !challengeDepositTxid.isEmpty() && challengeDepositTxid != zeroHash && challengeDepositVout >= 0;

        // Treat as active only if the challenge deposit is confirmed and still within its verdict window.
        bool hasActiveChallenge = hasDepositTx && challengeDepositHeight > 0;
        int currentHeight = 0;
        if (challengeVerdictHeight > 0) {
            try {
                UniValue heightResult = clientModel->node().executeRpc("getblockcount", UniValue(UniValue::VARR), walletModel->getWalletName().toStdString());
                currentHeight = heightResult.getInt<int>();
                hasActiveChallenge = hasActiveChallenge && (currentHeight < challengeVerdictHeight);
            } catch (...) {
                // If height lookup fails, require the confirmed deposit and allow the current state to stand.
            }
        }

        if (hasActiveChallenge) {
            challengeSelectedDepositTxid = challengeDepositTxid;
            challengeSelectedDepositVout = challengeDepositVout;
            challengeSeveralCommitButton->setEnabled(true);
            challengeSeveralCommitButton->setToolTip(tr("Choose how many challenge commits to create for the active challenge deposit."));
        }

        if (challengeStatusLabel) {
            if (!hasDepositTx) {
                challengeStatusLabel->setText(tr("No challenge deposit created for this model."));
            } else if (challengeDepositHeight == 0) {
                challengeStatusLabel->setText(tr("Challenge deposit created and waiting for confirmation."));
            } else if (hasActiveChallenge) {
                challengeStatusLabel->setText(tr("Challenge deposit is active until verdict height %1.").arg(challengeVerdictHeight > 0 ? QString::number(challengeVerdictHeight) : tr("unknown")));
            } else {
                challengeStatusLabel->setText(tr("Challenge cycle completed for this model."));
            }
        }
        if (challengeDepositLabel) {
            if (hasDepositTx) {
                challengeDepositLabel->setText(QStringLiteral("%1:%2").arg(challengeDepositTxid).arg(challengeDepositVout));
            } else {
                challengeDepositLabel->setText(tr("-"));
            }
        }
        if (challengeActionLabel) {
            if (!hasDepositTx) {
                challengeActionLabel->setText(tr("Load blocks, select a block, then create a challenge deposit."));
            } else if (challengeDepositHeight == 0) {
                challengeActionLabel->setText(tr("Wait for the challenge deposit to confirm before creating challenge commits."));
            } else if (hasActiveChallenge) {
                challengeActionLabel->setText(tr("Challenge deposit is active. Use Create Challenge Commits to choose how many challenge commits to create."));
            } else if (challengeVerdictHeight > 0) {
                challengeActionLabel->setText(tr("Challenge finished at height %1. Create a new challenge deposit only for a future cycle.").arg(challengeVerdictHeight));
            } else {
                challengeActionLabel->setText(tr("Challenge status is incomplete. Refresh this tab if needed."));
            }
        }
    } catch (...) {
        if (challengeStatusLabel) {
            challengeStatusLabel->setText(tr("Challenge status unavailable."));
        }
        if (challengeDepositLabel) {
            challengeDepositLabel->setText(tr("-"));
        }
        if (challengeActionLabel) {
            challengeActionLabel->setText(tr("Refresh the tab and try again."));
        }
    }
}

void ModelsPage::onChallengeLoadBlocks()
{
    refreshChallengeBlocks();
}

void ModelsPage::refreshChallengeList()
{
    if (!walletModel || !clientModel) {
        return;
    }

    challengeTable->setRowCount(0);
    int registeredCount = 0;
    challengeSelectedIdentifier.clear();
    challengeSelectedHash.clear();
    challengeSelectedModelDepositTxid.clear();
    challengeSelectedModelDepositVout = -1;
    challengeSelectedDepositTxid.clear();
    challengeSelectedDepositVout = -1;
    challengeLoadBlocksButton->setEnabled(false);
    challengeCreateButton->setEnabled(false);
    challengeSeveralCommitButton->setEnabled(false);
    challengeCreateButton->setToolTip(tr("Select a model and block first."));
    challengeSeveralCommitButton->setToolTip(tr("Select a model with an active challenge deposit."));
    challengeBlocksTable->setRowCount(0);
    if (challengeBlocksLabel) {
        challengeBlocksLabel->setText(tr("Blocks (latest 0):"));
    }
    if (challengeStatusLabel) {
        challengeStatusLabel->setText(tr("Select a model to see challenge status."));
    }
    if (challengeDepositLabel) {
        challengeDepositLabel->setText(tr("-"));
    }
    if (challengeActionLabel) {
        challengeActionLabel->setText(tr("Select a model."));
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(false); // extended view to get deposit fields
        UniValue result = clientModel->node().executeRpc("getmodelslist", params, "");

        const int registeredStatus = static_cast<int>(ModelRegistrationStatus::Registered);

        for (size_t i = 0; i < result.size(); ++i) {
            const UniValue& model = result[i];
            int status = model["status"].getInt<int>();
            if (status != registeredStatus) continue;

            int64_t depositAmount = model.exists("deposit_amount") ? model["deposit_amount"].getInt<int64_t>() : 0;
            int depositHeight = model.exists("deposit_block_height") ? model["deposit_block_height"].getInt<int>() : 0;
            // Default model has zero deposit and height; exclude it.
            if (depositAmount == 0 && depositHeight == 0) continue;

            QString modelHash = QString::fromStdString(model["model_hash"].get_str());
            QString modelName = QString::fromStdString(model["model_name"].get_str());
            QString modelCommit = QString::fromStdString(model["model_commit"].get_str());
            QString identifier = modelName + "@" + modelCommit;
            const QString challengeDepositTxid = model.exists("challenge_deposit_txid")
                                                     ? QString::fromStdString(model["challenge_deposit_txid"].get_str())
                                                     : QString();
            const int challengeDepositHeight = model.exists("challenge_deposit_height") ? model["challenge_deposit_height"].getInt<int>() : 0;
            const int challengeVerdictHeight = model.exists("challenge_verdict_height") ? model["challenge_verdict_height"].getInt<int>() : 0;
            const QString zeroHash = QStringLiteral("0000000000000000000000000000000000000000000000000000000000000000");
            QString challengeState = tr("None");
            if (!challengeDepositTxid.isEmpty() && challengeDepositTxid != zeroHash) {
                if (challengeDepositHeight == 0) {
                    challengeState = tr("Pending confirm");
                } else if (challengeVerdictHeight > 0 && getCurrentHeight() >= challengeVerdictHeight) {
                    challengeState = tr("Finished");
                } else {
                    challengeState = tr("Active");
                }
            }

            int row = challengeTable->rowCount();
            challengeTable->insertRow(row);

            QTableWidgetItem* hashItem = new QTableWidgetItem(modelHash.left(16) + "...");
            hashItem->setToolTip(modelHash);
            hashItem->setData(Qt::UserRole, modelHash);
            hashItem->setData(Qt::UserRole + 1, identifier);
            challengeTable->setItem(row, 0, hashItem);
            challengeTable->setItem(row, 1, new QTableWidgetItem(modelName));
            challengeTable->setItem(row, 2, new QTableWidgetItem(modelCommit));
            challengeTable->setItem(row, 3, new QTableWidgetItem(depositHeight > 0 ? QString::number(depositHeight) : "-"));
            challengeTable->setItem(row, 4, new QTableWidgetItem(challengeState));
            challengeTable->setItem(row, 5, new QTableWidgetItem(challengeVerdictHeight > 0 ? QString::number(challengeVerdictHeight) : "-"));

            registeredCount++;
        }

        challengeCountLabel->setText(tr("Registered (non-default): %1").arg(registeredCount));

    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    }
}

void ModelsPage::refreshChallengeBlocks()
{
    if (!clientModel || challengeSelectedIdentifier.isEmpty()) {
        return;
    }

    static constexpr int CHALLENGE_BLOCK_LOOKBACK_LIMIT = 200;

    challengeBlocksTable->setRowCount(0);
    int found = 0;
    int currentHeight = getCurrentHeight();
    const int minHeight = std::max(0, currentHeight - CHALLENGE_BLOCK_LOOKBACK_LIMIT + 1);

    try {
        for (int h = currentHeight; h >= minHeight && found < 50; --h) {
            UniValue paramsHash(UniValue::VARR);
            paramsHash.push_back(h);
            UniValue hashResult = clientModel->node().executeRpc("getblockhash", paramsHash, "");
            std::string blockHashStr = hashResult.get_str();

            UniValue paramsBlock(UniValue::VARR);
            paramsBlock.push_back(blockHashStr);
            paramsBlock.push_back(1); // verbosity 1
            UniValue blockResult = clientModel->node().executeRpc("getblock", paramsBlock, "");

            std::string identifier = blockResult.exists("tst") ? blockResult["tst"].get_str() : "";
            if (identifier != challengeSelectedIdentifier.toStdString()) {
                continue;
            }

            int row = challengeBlocksTable->rowCount();
            challengeBlocksTable->insertRow(row);
            challengeBlocksTable->setItem(row, 0, new QTableWidgetItem(QString::number(h)));

            QString hashShort = QString::fromStdString(blockHashStr).left(16) + "...";
            QTableWidgetItem* hashItem = new QTableWidgetItem(hashShort);
            hashItem->setToolTip(QString::fromStdString(blockHashStr));
            challengeBlocksTable->setItem(row, 1, hashItem);

            uint64_t time = blockResult.exists("time") ? blockResult["time"].getInt<uint64_t>() : 0;
            QString timeStr = time > 0 ? QDateTime::fromSecsSinceEpoch(time).toString(Qt::ISODate) : "-";
            challengeBlocksTable->setItem(row, 2, new QTableWidgetItem(timeStr));

            found++;
        }

        if (challengeBlocksLabel) {
            challengeBlocksLabel->setText(tr("Blocks (latest %1):").arg(found));
        }
        if (challengeActionLabel) {
            if (found == 0) {
                challengeActionLabel->setText(
                    tr("No matching blocks found for the selected model in the last %1 blocks.")
                        .arg(CHALLENGE_BLOCK_LOOKBACK_LIMIT)
                );
            } else {
                challengeActionLabel->setText(
                    tr("Found %1 matching block(s). Select a block to create a challenge deposit.")
                        .arg(found)
                );
            }
        }
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    }
}

void ModelsPage::onChallengeBlockSelected(int row, int column)
{
    Q_UNUSED(column);
    if (row < 0 || row >= challengeBlocksTable->rowCount()) {
        return;
    }
    QTableWidgetItem* hashItem = challengeBlocksTable->item(row, 1);
    if (!hashItem) return;
    challengeSelectedBlockHash = hashItem->toolTip();
    challengeCreateButton->setEnabled(!challengeSelectedBlockHash.isEmpty());
    challengeCreateButton->setToolTip(challengeSelectedBlockHash.isEmpty()
                                          ? tr("Select a challenge block first.")
                                          : tr("Create a challenge deposit for the selected block."));
}

void ModelsPage::onChallengeCreate()
{
    if (!walletModel || !clientModel || challengeSelectedBlockHash.isEmpty()) {
        return;
    }

    // Warning dialog with countdown
    QDialog warningDialog(this);
    warningDialog.setWindowTitle(tr("Challenge Deposit Warning"));
    warningDialog.setModal(true);
    warningDialog.setMinimumWidth(500);

    QVBoxLayout* layout = new QVBoxLayout(&warningDialog);
    QLabel* warningLabel = new QLabel(
        tr("<b style='color:#C62828;'>Important:</b><br>"
           "Submitting a challenge deposit will lock funds on-chain.<br>"
           "If the challenge <b>fails</b>, the deposit will be burned and cannot be recovered.<br>"
           "Proceed only if you understand and accept this risk."));
    warningLabel->setWordWrap(true);
    layout->addWidget(warningLabel);

    QLabel* countdownLabel = new QLabel(tr("Please wait 10 seconds..."));
    countdownLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(countdownLabel);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* cancelBtn = new QPushButton(tr("Cancel"));
    QPushButton* proceedBtn = new QPushButton(tr("Proceed (10)"));
    proceedBtn->setEnabled(false);
    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelBtn);
    buttonLayout->addWidget(proceedBtn);
    layout->addLayout(buttonLayout);

    QTimer countdownTimer;
    int remaining = 10;
    connect(&countdownTimer, &QTimer::timeout, [&]() {
        remaining--;
        if (remaining > 0) {
            proceedBtn->setText(tr("Proceed (%1)").arg(remaining));
            countdownLabel->setText(tr("Please wait %1 seconds...").arg(remaining));
        } else {
            countdownTimer.stop();
            proceedBtn->setEnabled(true);
            proceedBtn->setText(tr("Proceed"));
            countdownLabel->setText(tr("You may proceed now."));
        }
    });
    countdownTimer.start(1000);

    connect(cancelBtn, &QPushButton::clicked, &warningDialog, &QDialog::reject);
    connect(proceedBtn, &QPushButton::clicked, &warningDialog, &QDialog::accept);

    int res = warningDialog.exec();
    if (res != QDialog::Accepted) {
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        showError(tr("Wallet unlock was cancelled."));
        return;
    }

    try {
        const QString previousSelectedModelHash = challengeSelectedHash;
        UniValue params(UniValue::VARR);
        params.push_back(challengeSelectedBlockHash.toStdString());
        // broadcast default (true)
        UniValue result = clientModel->node().executeRpc("createchallengedeposit", params, walletModel->getWalletName().toStdString());
        QString txid = QString::fromStdString(result.exists("txid") ? result["txid"].get_str() : "");
        showSuccess(tr("Challenge deposit transaction created: %1").arg(txid));
        refreshChallengeList();
        if (!previousSelectedModelHash.isEmpty()) {
            for (int row = 0; row < challengeTable->rowCount(); ++row) {
                QTableWidgetItem* hashItem = challengeTable->item(row, 0);
                if (!hashItem) continue;
                if (hashItem->data(Qt::UserRole).toString() == previousSelectedModelHash) {
                    challengeTable->selectRow(row);
                    onChallengeModelSelected(row, 0);
                    break;
                }
            }
        }
        refreshChallengeBlocks();
    } catch (const UniValue& objError) {
        showError(FormatRpcError(objError));
    } catch (const std::exception& e) {
        showError(QString::fromStdString(e.what()));
    }
}

void ModelsPage::onChallengeCreateSeveralCommits()
{
    if (!walletModel || !clientModel) {
        return;
    }
    if (challengeSelectedHash.isEmpty()) {
        showError(tr("No model selected for challenge commits."));
        return;
    }

    bool ok = false;
    const int txCount = QInputDialog::getInt(
        this,
        tr("Create Challenge Commits"),
        tr("Number of challenge commit transactions to create (1-%1):").arg(CHALLENGE_VERIFICATION_BLOCK_COUNT),
        static_cast<int>(CHALLENGE_COMMIT_THRESHOLD),
        1,
        static_cast<int>(CHALLENGE_VERIFICATION_BLOCK_COUNT),
        1,
        &ok);

    if (!ok) {
        return;
    }

    if (txCount < 1 || txCount > static_cast<int>(CHALLENGE_VERIFICATION_BLOCK_COUNT)) {
        showError(tr("Challenge commit count must be a positive integer not greater than %1.")
                      .arg(CHALLENGE_VERIFICATION_BLOCK_COUNT));
        return;
    }

    runChallengeCommitFundingFlow(static_cast<unsigned int>(txCount), tr("Create Challenge Commits"));
}

void ModelsPage::onChallengeHowItWorks()
{
    QMessageBox::information(
        this,
        tr("Challenge Flow"),
        tr("<b>How challenge works</b><br><br>"
           "1. Select a registered model.<br>"
           "2. Load recent blocks and choose the block you want to challenge.<br>"
           "3. <b>Challenge Deposit</b> creates and broadcasts a challenge deposit transaction.<br>"
           "4. Wait until that challenge deposit is confirmed and active.<br>"
           "5. Use <b>Create Challenge Commits</b> to create challenge commit transactions.<br>"
           "6. A challenge needs <b>%1 commits</b> to satisfy the challenge threshold.<br>"
           "7. Challenge verdict is evaluated after <b>%2 blocks</b>.<br><br>"
           "<b>Tip:</b> you can reopen this explanation any time by pressing <b>How it works</b>.<br><br>"
           "<b>Important:</b> if a challenge fails, the challenge deposit may be burned.")
            .arg(CHALLENGE_COMMIT_THRESHOLD)
            .arg(CHALLENGE_VERIFICATION_BLOCK_COUNT));
}

void ModelsPage::runChallengeCommitFundingFlow(unsigned int txCount, const QString& flowLabel)
{
    if (!walletModel || !clientModel) {
        return;
    }
    const QString selectedModelHash = challengeSelectedHash;
    if (selectedModelHash.isEmpty()) {
        showError(tr("No model selected for challenge commits."));
        return;
    }
    if (txCount < 1 || txCount > CHALLENGE_VERIFICATION_BLOCK_COUNT) {
        showError(tr("Challenge commit count must be between 1 and %1.").arg(CHALLENGE_VERIFICATION_BLOCK_COUNT));
        return;
    }

    const std::string walletName = walletModel->getWalletName().toStdString();
    static constexpr CAmount COMMIT_FUNDING_TARGET{20'000};
    const int commitPhaseTimeoutMs = ComputeCommitPhaseTimeoutMs();
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        showError(tr("Wallet unlock was cancelled."));
        return;
    }
    qInfo() << "[ChallengeCommits] start for model hash"
            << selectedModelHash
            << "flow" << flowLabel
            << "txCount" << txCount;

    bool challengeDepositsLocked{false};
    QString lockedModelDepositTxid;
    int lockedModelDepositVout{-1};
    QString lockedChallengeDepositTxid;
    int lockedChallengeDepositVout{-1};
    auto unlockChallengeDeposits = [&]() {
        try {
            if (!challengeDepositsLocked) {
                return;
            }
            UniValue unlockParams(UniValue::VARR);
            unlockParams.push_back(true); // unlock
            UniValue utxoList(UniValue::VARR);

            if (!lockedModelDepositTxid.isEmpty() && lockedModelDepositVout >= 0) {
                UniValue modelDeposit(UniValue::VOBJ);
                modelDeposit.pushKV("txid", lockedModelDepositTxid.toStdString());
                modelDeposit.pushKV("vout", lockedModelDepositVout);
                utxoList.push_back(modelDeposit);
            }

            if (!lockedChallengeDepositTxid.isEmpty() && lockedChallengeDepositVout >= 0) {
                UniValue challengeDeposit(UniValue::VOBJ);
                challengeDeposit.pushKV("txid", lockedChallengeDepositTxid.toStdString());
                challengeDeposit.pushKV("vout", lockedChallengeDepositVout);
                utxoList.push_back(challengeDeposit);
            }

            if (utxoList.size() > 0) {
                unlockParams.push_back(utxoList);
                clientModel->node().executeRpc("lockunspent", unlockParams, walletName);
            }
            challengeDepositsLocked = false;
        } catch (...) {
            // best effort unlock
        }
    };

    try {
        UniValue statusParams(UniValue::VARR);
        statusParams.push_back(selectedModelHash.toStdString());
        UniValue statusResult = clientModel->node().executeRpc("getmodelregistrationstatus", statusParams, walletName);
        challengeSelectedModelDepositTxid = statusResult.exists("deposit_txid")
                                                ? QString::fromStdString(statusResult["deposit_txid"].get_str())
                                                : QString();
        challengeSelectedModelDepositVout = statusResult.exists("deposit_vout")
                                                ? statusResult["deposit_vout"].getInt<int>()
                                                : -1;

        const QString refreshedChallengeDepositTxid = statusResult.exists("challenge_deposit_txid")
                                                          ? QString::fromStdString(statusResult["challenge_deposit_txid"].get_str())
                                                          : QString();
        const int refreshedChallengeDepositVout = statusResult.exists("challenge_deposit_vout")
                                                      ? statusResult["challenge_deposit_vout"].getInt<int>()
                                                      : -1;
        const int refreshedChallengeDepositHeight = statusResult.exists("challenge_deposit_height")
                                                        ? statusResult["challenge_deposit_height"].getInt<int>()
                                                        : 0;
        const int refreshedChallengeVerdictHeight = statusResult.exists("challenge_verdict_height")
                                                        ? statusResult["challenge_verdict_height"].getInt<int>()
                                                        : 0;
        const QString zeroHash = QStringLiteral("0000000000000000000000000000000000000000000000000000000000000000");
        if (refreshedChallengeDepositTxid.isEmpty() ||
            refreshedChallengeDepositTxid == zeroHash ||
            refreshedChallengeDepositVout < 0 ||
            refreshedChallengeDepositHeight <= 0 ||
            refreshedChallengeVerdictHeight <= 0) {
            challengeSelectedDepositTxid.clear();
            challengeSelectedDepositVout = -1;
            throw std::runtime_error("No active confirmed challenge deposit for this model");
        }
        challengeSelectedDepositTxid = refreshedChallengeDepositTxid;
        challengeSelectedDepositVout = refreshedChallengeDepositVout;
        lockedModelDepositTxid = challengeSelectedModelDepositTxid;
        lockedModelDepositVout = challengeSelectedModelDepositVout;
        lockedChallengeDepositTxid = challengeSelectedDepositTxid;
        lockedChallengeDepositVout = challengeSelectedDepositVout;

        const auto isWalletOutpointUnspent = [&](const QString& txid, int vout) -> bool {
            if (txid.isEmpty() || vout < 0) {
                return false;
            }
            try {
                UniValue walletTxParams(UniValue::VARR);
                walletTxParams.push_back(txid.toStdString());
                walletTxParams.push_back(true);
                UniValue walletTx = clientModel->node().executeRpc("gettransaction", walletTxParams, walletName);
                if (!walletTx.isObject()) {
                    return false;
                }
                UniValue getTxOutParams(UniValue::VARR);
                getTxOutParams.push_back(txid.toStdString());
                getTxOutParams.push_back(vout);
                getTxOutParams.push_back(true);
                UniValue txout = clientModel->node().executeRpc("gettxout", getTxOutParams, walletName);
                return !txout.isNull();
            } catch (...) {
                return false;
            }
        };

        if (!isWalletOutpointUnspent(challengeSelectedModelDepositTxid, challengeSelectedModelDepositVout)) {
            challengeSelectedModelDepositTxid.clear();
            challengeSelectedModelDepositVout = -1;
        }
        if (!isWalletOutpointUnspent(challengeSelectedDepositTxid, challengeSelectedDepositVout)) {
            challengeSelectedDepositTxid.clear();
            challengeSelectedDepositVout = -1;
            throw std::runtime_error("No active unspent challenge deposit for this model");
        }

        // Prevent coin selection from using the frozen model/challenge deposits as funding inputs.
        if ((!lockedModelDepositTxid.isEmpty() && lockedModelDepositVout >= 0) ||
            (!lockedChallengeDepositTxid.isEmpty() && lockedChallengeDepositVout >= 0)) {
            // If these exact outpoints were left locked by a previous failed flow,
            // unlock them first, then lock again under this flow scope.
            try {
                UniValue listLockedParams(UniValue::VARR);
                UniValue currentlyLocked = clientModel->node().executeRpc("listlockunspent", listLockedParams, walletName);
                UniValue staleUnlockList(UniValue::VARR);
                for (size_t i = 0; i < currentlyLocked.size(); ++i) {
                    const UniValue& locked = currentlyLocked[i];
                    if (!locked.isObject() || !locked.exists("txid") || !locked.exists("vout")) {
                        continue;
                    }
                    const QString lockedTxid = QString::fromStdString(locked["txid"].get_str());
                    const int lockedVout = locked["vout"].getInt<int>();
                    const bool isCurrentModelDeposit =
                        (lockedTxid == lockedModelDepositTxid && lockedVout == lockedModelDepositVout);
                    const bool isCurrentChallengeDeposit =
                        (lockedTxid == lockedChallengeDepositTxid && lockedVout == lockedChallengeDepositVout);
                    if (!isCurrentModelDeposit && !isCurrentChallengeDeposit) {
                        continue;
                    }
                    UniValue utxo(UniValue::VOBJ);
                    utxo.pushKV("txid", lockedTxid.toStdString());
                    utxo.pushKV("vout", lockedVout);
                    staleUnlockList.push_back(utxo);
                }
                if (staleUnlockList.size() > 0) {
                    UniValue unlockParams(UniValue::VARR);
                    unlockParams.push_back(true);
                    unlockParams.push_back(staleUnlockList);
                    clientModel->node().executeRpc("lockunspent", unlockParams, walletName);
                }
            } catch (...) {
                // best effort stale unlock
            }

            UniValue lockParams(UniValue::VARR);
            lockParams.push_back(false); // lock
            UniValue utxoList(UniValue::VARR);

            if (!lockedModelDepositTxid.isEmpty() && lockedModelDepositVout >= 0) {
                UniValue modelDeposit(UniValue::VOBJ);
                modelDeposit.pushKV("txid", lockedModelDepositTxid.toStdString());
                modelDeposit.pushKV("vout", lockedModelDepositVout);
                utxoList.push_back(modelDeposit);
            }

            if (!lockedChallengeDepositTxid.isEmpty() && lockedChallengeDepositVout >= 0) {
                UniValue challengeDeposit(UniValue::VOBJ);
                challengeDeposit.pushKV("txid", lockedChallengeDepositTxid.toStdString());
                challengeDeposit.pushKV("vout", lockedChallengeDepositVout);
                utxoList.push_back(challengeDeposit);
            }

            lockParams.push_back(utxoList);
            clientModel->node().executeRpc("lockunspent", lockParams, walletName);
            challengeDepositsLocked = true;
        }

        // Step 1: auto-select wallet inputs and split directly into funding outputs.
        UniValue splitParams(UniValue::VARR);
        splitParams.push_back(zeroHash.toStdString());
        splitParams.push_back(0);
        splitParams.push_back(static_cast<int>(txCount));
        splitParams.push_back(static_cast<int64_t>(COMMIT_FUNDING_TARGET));
        UniValue splitResult = clientModel->node().executeRpc("splitutxo", splitParams, walletName);
        const QString splitTxid = QString::fromStdString(splitResult["txid"].get_str());
        qInfo() << "[ChallengeCommits] split tx" << splitTxid << "parts" << txCount;

        if (!waitForTxConfirmation(splitTxid, walletName, 1, commitPhaseTimeoutMs, tr("Split confirmation"))) {
            unlockChallengeDeposits();
            showError(tr("Timeout waiting for split transaction confirmation"));
            return;
        }
        qInfo() << "[ChallengeCommits] split tx confirmed" << splitTxid;

        UniValue fundingArray(UniValue::VARR);
        const UniValue& outputs = splitResult["outputs"];
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& out = outputs[i];
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("txid", splitTxid.toStdString());
            entry.pushKV("vout", out["vout"].getInt<int>());
            fundingArray.push_back(entry);
        }
        qInfo() << "[ChallengeCommits] collected funding outputs"
                << static_cast<int>(outputs.size());

        // Step 2: create commit transactions using split outputs as funding_utxos.
        UniValue commitParams(UniValue::VARR);
        commitParams.push_back(selectedModelHash.toStdString());
        commitParams.push_back(static_cast<int>(txCount));
        commitParams.push_back(fundingArray);

        UniValue result = clientModel->node().executeRpc("createchallengecommits", commitParams, walletName);

        QString modelHash = QString::fromStdString(result["model_hash"].get_str());
        const int createdCount = result.exists("count") ? result["count"].getInt<int>() : -1;
        qInfo() << "[ChallengeCommits] RPC result count"
                << createdCount
                << "model" << modelHash;

        showSuccess(tr("%1 completed: %2 challenge commit(s) created for model %3.")
                        .arg(flowLabel)
                        .arg(createdCount >= 0 ? createdCount : static_cast<int>(txCount))
                        .arg(modelHash));
        unlockChallengeDeposits();

    } catch (const UniValue& objError) {
        unlockChallengeDeposits();
        const QString err = FormatRpcError(objError);
        showError(err);
    } catch (const std::exception& e) {
        unlockChallengeDeposits();
        showError(QString::fromStdString(e.what()));
    }
}

// ===== HELPER METHODS =====

bool ModelsPage::parseDepositTransaction(const QString& txid, int targetVout, QString& modelHash, QString& modelName,
                                          QString& modelCommit, int64_t& difficulty, QString& cid,
                                          QString& extra, int& vout, QString& depositAmount)
{
    if (!walletModel) return false;

    try {
        UniValue params(UniValue::VARR);
        params.push_back(txid.toStdString());
        params.push_back(true);

        UniValue result = clientModel->node().executeRpc("gettransaction", params, walletModel->getWalletName().toStdString());
        QString hex = QString::fromStdString(result["hex"].get_str());

        // Simple version check - version 5 is model deposit
        // In actual implementation, would use proper transaction decoding
        // For now, try to get model info from RPC

        // Try to find model hash by scanning getmodelslist
        UniValue listParams(UniValue::VARR);
        listParams.push_back(false);
        UniValue models = clientModel->node().executeRpc("getmodelslist", listParams, "");

        for (size_t i = 0; i < models.size(); ++i) {
            const UniValue& model = models[i];
            QString depositTxid = QString::fromStdString(model["deposit_txid"].get_str());
            const int modelVout = model["deposit_vout"].getInt<int>();

            if (depositTxid != txid) {
                continue;
            }
            if (targetVout >= 0 && modelVout != targetVout) {
                continue;
            }

            modelHash = QString::fromStdString(model["model_hash"].get_str());
            modelName = QString::fromStdString(model["model_name"].get_str());
            modelCommit = QString::fromStdString(model["model_commit"].get_str());
            difficulty = model["difficulty"].getInt<int64_t>();
            cid = model.exists("cid") ? QString::fromStdString(model["cid"].get_str()) : "";
            extra = model.exists("extra") ? QString::fromStdString(model["extra"].get_str()) : "";
            vout = modelVout;
            const CAmount depositAmountSats = model["deposit_amount"].getInt<int64_t>();
            depositAmount = BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, depositAmountSats);
            return true;
        }

        return false;

    } catch (...) {
        return false;
    }
}

QString ModelsPage::getStatusString(int status) const
{
    const auto statusOpt = StatusFromInt(status);
    if (!statusOpt) {
        return tr("Unknown");
    }

    switch (*statusOpt) {
    case ModelRegistrationStatus::PendingDeposit:
        return tr("Pending Deposit");
    case ModelRegistrationStatus::PendingVerification:
        return tr("Pending Verification");
    case ModelRegistrationStatus::Registered:
        return tr("Registered");
    case ModelRegistrationStatus::Locked:
        return tr("Locked");
    case ModelRegistrationStatus::Banned:
        return tr("Banned");
    }
    return tr("Unknown");
}

QString ModelsPage::getStatusColor(int status) const
{
    const auto statusOpt = StatusFromInt(status);
    if (!statusOpt) {
        return "#757575";
    }

    switch (*statusOpt) {
    case ModelRegistrationStatus::PendingDeposit:
        return "#F57C00"; // Orange
    case ModelRegistrationStatus::PendingVerification:
        return "#0288D1"; // Blue
    case ModelRegistrationStatus::Registered:
        return "#2E7D32"; // Green
    case ModelRegistrationStatus::Locked:
        return "#C62828"; // Red
    case ModelRegistrationStatus::Banned:
        return "#6A1B9A"; // Purple
    }
    return "#757575";
}

int ModelsPage::getCurrentHeight() const
{
    if (!clientModel) return 0;
    return clientModel->getNumBlocks();
}

bool ModelsPage::waitForBlockAdvance(int startingHeight, int timeoutMs, const QString& phaseLabel)
{
    if (!clientModel) {
        commitStatusText->append(tr("%1: client model unavailable").arg(phaseLabel));
        return false;
    }

    bool advanced = false;
    QElapsedTimer timer;
    timer.start();

    while (timer.elapsed() < timeoutMs) {
        if (clientModel->getNumBlocks() > startingHeight) {
            advanced = true;
            break;
        }

        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
        QThread::msleep(100);
    }

    if (!advanced) {
        commitStatusText->append(tr("%1: timeout waiting for new block").arg(phaseLabel));
    }
    return advanced;
}

bool ModelsPage::waitForTxConfirmation(const QString& txid, const std::string& walletName, int minConfirmations, int timeoutMs, const QString& phaseLabel)
{
    if (!clientModel) {
        if (commitStatusText) {
            commitStatusText->append(tr("%1: client model unavailable").arg(phaseLabel));
        }
        return false;
    }

    bool confirmed = false;
    bool dropped = false;

    auto check_tx = [&]() {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(txid.toStdString());
            UniValue result = clientModel->node().executeRpc("gettransaction", params, walletName);
            const int confirmations = result.exists("confirmations") ? result["confirmations"].getInt<int>() : 0;
            if (confirmations >= minConfirmations) {
                confirmed = true;
                return;
            }

            if (confirmations <= 0) {
                try {
                    UniValue mempoolParams(UniValue::VARR);
                    mempoolParams.push_back(txid.toStdString());
                    clientModel->node().executeRpc("getmempoolentry", mempoolParams, "");
                } catch (...) {
                    dropped = true;
                    return;
                }
            }
        } catch (...) {
            // Keep polling until timeout; transaction may not be indexed immediately.
        }
    };

    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        check_tx();
        if (confirmed || dropped) {
            break;
        }

        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
        QThread::msleep(1000);
    }

    if (dropped && commitStatusText) {
        commitStatusText->append(tr("%1: transaction %2 is no longer in the mempool and has no confirmations")
                                     .arg(phaseLabel)
                                     .arg(txid));
    }

    if (!confirmed && commitStatusText) {
        if (!dropped) {
            commitStatusText->append(tr("%1: timeout waiting for transaction %2 to reach %3 confirmation(s)")
                                         .arg(phaseLabel)
                                         .arg(txid)
                                         .arg(minConfirmations));
        }
    }
    return confirmed;
}

void ModelsPage::showError(const QString& message)
{
    Q_EMIT this->message(tr("Error"), message, CClientUIInterface::MSG_ERROR);
}

void ModelsPage::showSuccess(const QString& message)
{
    Q_EMIT this->message(tr("Success"), message, CClientUIInterface::MSG_INFORMATION);
}

void ModelsPage::updateMaturityCountdowns()
{
    // Update My Deposits tab maturity column
    int currentHeight = getCurrentHeight();
    for (int row = 0; row < myDepositsTable->rowCount(); ++row) {
        const QTableWidgetItem* statusItem = myDepositsTable->item(row, 3);
        const QTableWidgetItem* maturityItem = myDepositsTable->item(row, 5);
        if (statusItem && maturityItem) {
            const auto statusOpt = StatusFromString(statusItem->text());
            if (!statusOpt || *statusOpt != ModelRegistrationStatus::Registered) {
                continue;
            }
            int maturityHeight = maturityItem->data(Qt::UserRole).toInt();
            if (maturityHeight > 0) {
                int remaining = maturityHeight - currentHeight;
                QString maturity = remaining > 0 ? tr("%1 blocks").arg(remaining) : tr("✓ Mature");
                myDepositsTable->item(row, 5)->setText(maturity);
            }
        }
    }

    // Update Registry tab maturity column
    for (int row = 0; row < registryTable->rowCount(); ++row) {
        int statusVal = registryTable->item(row, 4)->data(Qt::UserRole).toInt();
        if (statusVal == static_cast<int>(ModelRegistrationStatus::Registered)) {
            QString heightStr = registryTable->item(row, 5)->text();
            if (heightStr != "-") {
                int blockHeight = heightStr.toInt();
                int maturityHeight = blockHeight + 100;
                int remaining = maturityHeight - currentHeight;
                QString maturity = remaining > 0 ? tr("%1 blocks").arg(remaining) : tr("✓ Mature");
                registryTable->item(row, 6)->setText(maturity);
            }
        }
    }
}

// ===== BLOCK UPDATE SLOT =====

void ModelsPage::onNumBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state)
{
    Q_UNUSED(blockDate);
    Q_UNUSED(nVerificationProgress);
    Q_UNUSED(header);
    Q_UNUSED(sync_state);

    registryCurrentHeightLabel->setText(tr("Current Height: %1").arg(count));
    updateMaturityCountdowns();
}

void ModelsPage::onMaturityTimerTick()
{
    updateMaturityCountdowns();
}

QString ModelsPage::discussionScopeAliasKey(const QString& scopeType, const QString& scopeId) const
{
    return scopeType + ":" + scopeId;
}

QString ModelsPage::lookupDiscussionScopeAlias(const QString& scopeType, const QString& scopeId) const
{
    return discScopeAliases.value(discussionScopeAliasKey(scopeType, scopeId));
}

void ModelsPage::rememberDiscussionScopeAlias(const QString& scopeType, const QString& scopeId, const QString& alias)
{
    const QString trimmed = alias.trimmed();
    if (trimmed.isEmpty()) return;

    const QString key = discussionScopeAliasKey(scopeType, scopeId);
    discScopeAliases.insert(key, trimmed);

    QSettings settings;
    settings.beginGroup("discussion/scope_aliases");
    settings.setValue(key, trimmed);
    settings.endGroup();
}

void ModelsPage::loadDiscussionScopeAliases(bool force)
{
    if (discScopeAliasesLoaded && !force) return;

    if (!discScopeAliasesLoaded || force) {
        discScopeAliases.clear();
        QSettings settings;
        settings.beginGroup("discussion/scope_aliases");
        const QStringList keys = settings.childKeys();
        for (const QString& key : keys) {
            const QString alias = settings.value(key).toString().trimmed();
            if (!alias.isEmpty()) {
                discScopeAliases.insert(key, alias);
            }
        }
        settings.endGroup();
        discScopeAliasesLoaded = true;
    }

    if (!clientModel) return;

    try {
        UniValue params(UniValue::VARR);
        params.push_back(true); // short_view
        UniValue models = clientModel->node().executeRpc("getmodelslist", params, "");
        if (!models.isArray()) return;

        for (size_t i = 0; i < models.size(); ++i) {
            const UniValue& model = models[i];
            if (!model.isObject() || !model.exists("model_hash") ||
                !model.exists("model_name") || !model.exists("model_commit")) {
                continue;
            }

            const QString scopeId = QString::fromStdString(model["model_hash"].get_str());
            const QString alias = QString("%1@%2")
                .arg(QString::fromStdString(model["model_name"].get_str()))
                .arg(QString::fromStdString(model["model_commit"].get_str()));
            rememberDiscussionScopeAlias("model_prealert", scopeId, alias);
            rememberDiscussionScopeAlias("model_challenge", scopeId, alias);
        }
    } catch (...) {
    }
}

QString ModelsPage::buildDiscussionScopeLabel(const QString& scopeType, const QString& scopeId, uint64_t postCount, const QString& preview) const
{
    Q_UNUSED(preview);
    const QString alias = lookupDiscussionScopeAlias(scopeType, scopeId);
    const QString typeLabel =
        scopeType == "model_prealert" ? tr("Pre-alert") :
        scopeType == "model_challenge" ? tr("Challenge") :
        scopeType;

    if (!IsValidModelIdentifier(alias)) {
        return QString();
    }

    QString label;
    label = QString("%1: %2 [%3]").arg(typeLabel, alias, scopeId.left(12) + "...");

    if (postCount > 0) {
        label += QString(" (%1)").arg(postCount);
    }
    return label;
}

void ModelsPage::syncDiscussionIdentifierFromScope()
{
    if (discSyncingDiscussionFields || !discModelIdentifierEdit || !discScopeTypeCombo || !discScopeIdEdit) return;

    const QString scopeType = discScopeTypeCombo->currentData().toString();
    const QString scopeId = discScopeIdEdit->text().trimmed();
    discModelIdentifierEdit->setPlaceholderText(tr("model_name@commit_id"));
    if (!kHex64Re.match(scopeId).hasMatch()) {
        discSyncingDiscussionFields = true;
        discModelIdentifierEdit->clear();
        discSyncingDiscussionFields = false;
        return;
    }

    loadDiscussionScopeAliases(false);
    QString alias = lookupDiscussionScopeAlias(scopeType, scopeId);
    if (alias.isEmpty() && clientModel) {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(scopeId.toStdString());
            UniValue result = clientModel->node().executeRpc("getmodelinfo", params, "");
            if (result.isObject() && result.exists("model_name") && result.exists("model_commit")) {
                alias = QString("%1@%2")
                    .arg(QString::fromStdString(result["model_name"].get_str()))
                    .arg(QString::fromStdString(result["model_commit"].get_str()));
                rememberDiscussionScopeAlias(scopeType, scopeId, alias);
            }
        } catch (...) {
        }
    }

    discSyncingDiscussionFields = true;
    discModelIdentifierEdit->setText(alias);
    discSyncingDiscussionFields = false;
}

void ModelsPage::syncDiscussionScopeFromIdentifier()
{
    if (discSyncingDiscussionFields || !discModelIdentifierEdit || !discScopeTypeCombo || !discScopeIdEdit) return;

    const QString identifier = discModelIdentifierEdit->text().trimmed();
    if (!IsValidModelIdentifier(identifier)) {
        discSyncingDiscussionFields = true;
        discScopeIdEdit->clear();
        discSyncingDiscussionFields = false;
        return;
    }
    const int sep = identifier.lastIndexOf('@');
    const std::string model_name = identifier.left(sep).toStdString();
    const std::string model_commit = identifier.mid(sep + 1).toStdString();
    const uint256 scopeHash = HashSHA256(model_name, model_commit);
    const QString scopeId = QString::fromStdString(scopeHash.ToString());
    const QString scopeType = discScopeTypeCombo->currentData().toString();

    discSyncingDiscussionFields = true;
    discScopeIdEdit->setText(scopeId);
    discSyncingDiscussionFields = false;

    rememberDiscussionScopeAlias(scopeType, scopeId, identifier);
}

bool ModelsPage::discussionChallengeScopeExists(const QString& scopeId) const
{
    if (!clientModel || !kHex64Re.match(scopeId).hasMatch()) {
        return false;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(scopeId.toStdString());
        UniValue result = clientModel->node().executeRpc("getmodelinfo", params, "");
        return result.isObject() && result.exists("model_hash");
    } catch (...) {
        return false;
    }
}

void ModelsPage::openDiscussionThread(const QString& scopeType, const QString& scopeHash, const QString& modelIdentifier)
{
    if (!tabWidget || !discussionTab || !discScopeTypeCombo || !discScopeIdEdit || !discModelIdentifierEdit) {
        return;
    }
    if (!kHex64Re.match(scopeHash).hasMatch()) {
        showError(tr("Cannot open discussion: invalid scope hash"));
        return;
    }

    tabWidget->setCurrentWidget(discussionTab);

    int targetIndex = -1;
    for (int i = 0; i < discScopeTypeCombo->count(); ++i) {
        if (discScopeTypeCombo->itemData(i).toString() == scopeType) {
            targetIndex = i;
            break;
        }
    }
    if (targetIndex < 0) {
        targetIndex = 0;
    }

    discSyncingDiscussionFields = true;
    discScopeTypeCombo->setCurrentIndex(targetIndex);
    discScopeIdEdit->setText(scopeHash);
    if (!modelIdentifier.trimmed().isEmpty()) {
        discModelIdentifierEdit->setText(modelIdentifier.trimmed());
        rememberDiscussionScopeAlias(scopeType, scopeHash, modelIdentifier.trimmed());
    }
    discSyncingDiscussionFields = false;

    onDiscussionScopeChanged();
    onDiscussionRefresh(true);
    onDiscussionLoadActiveScopes(false);
}

// ===== DISCUSSION TAB =====

void ModelsPage::setupDiscussionTab()
{
    discussionTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(discussionTab);
    layout->setSpacing(10);

    QLabel* introLabel = new QLabel(
        tr("Browse active relay discussions, open a thread, then read or post with an attached proof automatically."));
    introLabel->setWordWrap(true);
    introLabel->setStyleSheet("color: #5f6b7a;");
    layout->addWidget(introLabel);

    // Discovery / browse controls
    QGroupBox* browseGroup = new QGroupBox(tr("Browse Discussions"));
    QGridLayout* browseLayout = new QGridLayout(browseGroup);
    browseLayout->setColumnStretch(1, 1);
    browseLayout->setColumnStretch(3, 1);

    browseLayout->addWidget(new QLabel(tr("Active:")), 0, 0);
    discActiveScopesCombo = new QComboBox();
    discActiveScopesCombo->setMinimumWidth(420);
    discActiveScopesCombo->addItem(tr("(select an active discussion from relay)"), "");
    browseLayout->addWidget(discActiveScopesCombo, 0, 1);

    discActiveScopesRefreshButton = new QPushButton(tr("Reload"));
    browseLayout->addWidget(discActiveScopesRefreshButton, 0, 2);

    discHideScopesWithoutLiveVerifiedCheck = new QCheckBox(tr("Live only"));
    discHideScopesWithoutLiveVerifiedCheck->setChecked(false);
    discHideScopesWithoutLiveVerifiedCheck->setToolTip(tr("Hide scopes that do not contain verified, unexpired messages."));
    browseLayout->addWidget(discHideScopesWithoutLiveVerifiedCheck, 0, 3);

    browseLayout->addWidget(new QLabel(tr("Recent:")), 1, 0);
    discRecentScopesCombo = new QComboBox();
    discRecentScopesCombo->setMinimumWidth(350);
    discRecentScopesCombo->addItem(tr("(select a recent discussion scope)"), "");
    loadDiscussionScopeAliases(false);
    QSettings settings;
    QStringList recentScopes = settings.value("discussion/recent_scopes").toStringList();
    for (const QString& entry : recentScopes) {
        int sep = entry.indexOf(':');
        if (sep > 0 && entry.length() > sep + 1) {
            QString type = entry.left(sep);
            QString id = entry.mid(sep + 1);
            QString label = buildDiscussionScopeLabel(type, id, 0, QString());
            if (!label.isEmpty()) {
                discRecentScopesCombo->addItem(label, entry);
            }
        }
    }
    browseLayout->addWidget(discRecentScopesCombo, 1, 1, 1, 2);

    QPushButton* howItWorksButton = new QPushButton(tr("How it works"));
    browseLayout->addWidget(howItWorksButton, 1, 3, Qt::AlignRight);
    layout->addWidget(browseGroup);

    // Current thread / manual open controls
    QGroupBox* scopeGroup = new QGroupBox(tr("Current Thread"));
    QGridLayout* scopeLayout = new QGridLayout(scopeGroup);
    scopeLayout->setColumnStretch(1, 1);

    scopeLayout->addWidget(new QLabel(tr("Type:")), 0, 0);
    discScopeTypeCombo = new QComboBox();
    discScopeTypeCombo->addItem(tr("Model Pre-alert"), "model_prealert");
    discScopeTypeCombo->addItem(tr("Model Challenge"), "model_challenge");
    scopeLayout->addWidget(discScopeTypeCombo, 0, 1);

    discRefreshButton = new QPushButton(tr("Refresh Thread"));
    scopeLayout->addWidget(discRefreshButton, 0, 2, Qt::AlignRight);

    scopeLayout->addWidget(new QLabel(tr("Model Identifier:")), 1, 0);
    discModelIdentifierEdit = new QLineEdit();
    discModelIdentifierEdit->setPlaceholderText(tr("Required: model_name@commit_id"));
    discModelIdentifierEdit->setToolTip(tr("Required for both discussion types. For model pre-alert threads it is also converted to the matching scope hash automatically."));
    scopeLayout->addWidget(discModelIdentifierEdit, 1, 1, 1, 2);

    scopeLayout->addWidget(new QLabel(tr("Scope Hash:")), 2, 0);
    discScopeIdEdit = new QLineEdit();
    discScopeIdEdit->setPlaceholderText(tr("Auto-filled from model identifier, or paste a 64-char model/challenge hash"));
    discScopeIdEdit->setMinimumWidth(400);
    scopeLayout->addWidget(discScopeIdEdit, 2, 1, 1, 2);

    QLabel* threadHintLabel = new QLabel(
        tr("Tip: Model Identifier is the primary selector for both discussion types. When it is valid, Scope Hash is filled automatically. You can also paste Scope Hash manually for direct lookup."));
    threadHintLabel->setWordWrap(true);
    threadHintLabel->setStyleSheet("color: #5f6b7a;");
    scopeLayout->addWidget(threadHintLabel, 3, 0, 1, 2);

    discStatusLabel = new QLabel(tr("Select a discussion scope to begin"));
    discStatusLabel->setWordWrap(true);
    discStatusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    scopeLayout->addWidget(discStatusLabel, 3, 2);
    layout->addWidget(scopeGroup);

    // Filter controls
    QGroupBox* filterGroup = new QGroupBox(tr("Visible Messages"));
    QHBoxLayout* filterLayout = new QHBoxLayout(filterGroup);
    discHideUnverifiedCheck = new QCheckBox(tr("Verified only"));
    discHideUnverifiedCheck->setChecked(false);
    discHideUnverifiedCheck->setToolTip(tr("Hide messages whose attached proofs did not verify."));
    filterLayout->addWidget(discHideUnverifiedCheck);

    discHideExpiredCheck = new QCheckBox(tr("Hide expired"));
    discHideExpiredCheck->setChecked(true);
    discHideExpiredCheck->setToolTip(tr("Hide messages whose proof expiry height has already passed."));
    filterLayout->addWidget(discHideExpiredCheck);

    filterLayout->addSpacing(10);
    filterLayout->addWidget(new QLabel(tr("Min verified stake (sats):")));
    discMinStakeSpin = new QSpinBox();
    discMinStakeSpin->setRange(0, 100000000);
    discMinStakeSpin->setValue(10000);
    discMinStakeSpin->setSingleStep(10000);
    filterLayout->addWidget(discMinStakeSpin);
    filterLayout->addStretch();
    layout->addWidget(filterGroup);

    // Posts table
    discPostsTable = new QTableWidget();
    discPostsTable->setColumnCount(6);
    discPostsTable->setHorizontalHeaderLabels({
        tr("Time"), tr("Author"), tr("Message"), tr("Stake"), tr("Expiry"), tr("Status")
    });
    discPostsTable->horizontalHeader()->setStretchLastSection(false);
    discPostsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    discPostsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    discPostsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    discPostsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    discPostsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    discPostsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    discPostsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    discPostsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    discPostsTable->verticalHeader()->setVisible(false);
    discPostsTable->setAlternatingRowColors(true);
    discPostsTable->setWordWrap(false);
    layout->addWidget(discPostsTable, 1);

    // Compose area
    QGroupBox* composeGroup = new QGroupBox(tr("Reply to Current Discussion"));
    QVBoxLayout* composeLayout = new QVBoxLayout(composeGroup);
    QLabel* composeHint = new QLabel(
        tr("A BIP-322 ownership proof is attached automatically from a confirmed UTXO that meets the stake requirement."));
    composeHint->setWordWrap(true);
    composeHint->setStyleSheet("color: #5f6b7a;");
    composeLayout->addWidget(composeHint);

    discComposeEdit = new QTextEdit();
    discComposeEdit->setPlaceholderText(tr("Write a message for this thread (max 4096 characters)..."));
    discComposeEdit->setMaximumHeight(96);
    composeLayout->addWidget(discComposeEdit);

    QHBoxLayout* postActionLayout = new QHBoxLayout();
    QLabel* composeStatus = new QLabel(tr("Posting becomes available once the scope is valid and the message is not empty."));
    composeStatus->setWordWrap(true);
    composeStatus->setStyleSheet("color: #5f6b7a;");
    postActionLayout->addWidget(composeStatus, 1);
    discPostButton = new QPushButton(tr("Post to Discussion"));
    discPostButton->setEnabled(false);
    postActionLayout->addWidget(discPostButton);
    composeLayout->addLayout(postActionLayout);
    layout->addWidget(composeGroup);

    // Connections
    connect(discRefreshButton, &QPushButton::clicked, this, [this]() { onDiscussionRefresh(true); });
    connect(discPostButton, &QPushButton::clicked, this, &ModelsPage::onDiscussionPost);
    connect(discScopeTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ModelsPage::onDiscussionTypeChanged);
    connect(discScopeIdEdit, &QLineEdit::textChanged, this, &ModelsPage::onDiscussionScopeIdEdited);
    connect(discModelIdentifierEdit, &QLineEdit::textChanged, this, &ModelsPage::onDiscussionModelIdentifierChanged);
    connect(discComposeEdit, &QTextEdit::textChanged, this, &ModelsPage::onDiscussionComposeChanged);
    connect(discHideUnverifiedCheck, &QCheckBox::stateChanged, this, [this](int) { onDiscussionRefresh(); });
    connect(discHideExpiredCheck, &QCheckBox::stateChanged, this, [this](int) { onDiscussionRefresh(); });
    connect(discMinStakeSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) { onDiscussionRefresh(); });
    connect(discRecentScopesCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ModelsPage::onDiscussionRecentScopeSelected);
    connect(discActiveScopesCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ModelsPage::onDiscussionActiveScopeSelected);
    connect(discActiveScopesRefreshButton, &QPushButton::clicked, this, [this]() {
        onDiscussionLoadActiveScopes(true);
    });
    connect(discHideScopesWithoutLiveVerifiedCheck, &QCheckBox::stateChanged, this, [this](int) {
        onDiscussionLoadActiveScopes(true);
    });
    connect(discPostsTable, &QTableWidget::cellDoubleClicked,
            this, &ModelsPage::onDiscussionPostDoubleClicked);
    connect(howItWorksButton, &QPushButton::clicked, this, &ModelsPage::onDiscussionHowItWorks);

    // Auto-refresh timer (30 seconds)
    discRefreshTimer = new QTimer(this);
    connect(discRefreshTimer, &QTimer::timeout, this, &ModelsPage::onDiscussionAutoRefresh);
    discScopesRefreshTimer = new QTimer(this);
    connect(discScopesRefreshTimer, &QTimer::timeout, this, [this]() { onDiscussionLoadActiveScopes(true); });
    discScopesRefreshTimer->start(30000);

    GUIUtil::InstallWheelEventFilter(discScopeTypeCombo);
    GUIUtil::InstallWheelEventFilter(discMinStakeSpin);
    GUIUtil::InstallWheelEventFilter(discRecentScopesCombo);
    GUIUtil::InstallWheelEventFilter(discActiveScopesCombo);

}

void ModelsPage::onDiscussionTypeChanged(int index)
{
    Q_UNUSED(index);
    discSyncingDiscussionFields = true;
    if (discModelIdentifierEdit) discModelIdentifierEdit->clear();
    if (discScopeIdEdit) discScopeIdEdit->clear();
    discSyncingDiscussionFields = false;
    onDiscussionScopeChanged();
    onDiscussionRefresh();
}

void ModelsPage::onDiscussionScopeChanged()
{
    QString scopeId = discScopeIdEdit->text().trimmed();
    QString scopeType = discScopeTypeCombo->currentData().toString();
    const bool validIdentifier = IsValidModelIdentifier(discModelIdentifierEdit ? discModelIdentifierEdit->text() : QString());
    bool validScope = (scopeId.length() == 64);
    // Validate hex content
    if (validScope) {
            validScope = kHex64Re.match(scopeId).hasMatch();
    }
    if (validScope && scopeType == "model_challenge") {
        validScope = discussionChallengeScopeExists(scopeId);
    }
    discPostButton->setEnabled(validScope && validIdentifier && !discComposeEdit->toPlainText().trimmed().isEmpty());

    // Start/stop auto-refresh based on valid scope
    if (validScope) {
        if (!discRefreshTimer->isActive()) {
            discRefreshTimer->start(30000);
        }
    } else {
        discRefreshTimer->stop();
    }
}

void ModelsPage::onDiscussionScopeIdEdited(const QString& text)
{
    Q_UNUSED(text);
    if (!discSyncingDiscussionFields) {
        syncDiscussionIdentifierFromScope();
    }
    onDiscussionScopeChanged();
    onDiscussionRefresh();
}

void ModelsPage::onDiscussionModelIdentifierChanged(const QString& text)
{
    Q_UNUSED(text);
    if (!discSyncingDiscussionFields) {
        syncDiscussionScopeFromIdentifier();
    }
    onDiscussionScopeChanged();
    onDiscussionRefresh();
}

void ModelsPage::onDiscussionComposeChanged()
{
    onDiscussionScopeChanged();
}

void ModelsPage::onDiscussionAutoRefresh()
{
    // Only auto-refresh if the discussion tab is visible
    if (tabWidget && tabWidget->currentWidget() == discussionTab) {
        onDiscussionRefresh();
    }
}

void ModelsPage::onDiscussionRecentScopeSelected(int index)
{
    if (index <= 0) return; // "(select a recent discussion scope)" placeholder
    QString entry = discRecentScopesCombo->currentData().toString();
    int sep = entry.indexOf(':');
    if (sep <= 0) return;

    QString scopeType = entry.left(sep);
    QString scopeId = entry.mid(sep + 1);

    // Set the scope type combo
    for (int i = 0; i < discScopeTypeCombo->count(); i++) {
        if (discScopeTypeCombo->itemData(i).toString() == scopeType) {
            discScopeTypeCombo->setCurrentIndex(i);
            break;
        }
    }
    discScopeIdEdit->setText(scopeId);

    // Reset combo to placeholder so user can re-select the same entry
    discRecentScopesCombo->blockSignals(true);
    discRecentScopesCombo->setCurrentIndex(0);
    discRecentScopesCombo->blockSignals(false);

    // Trigger refresh
    onDiscussionRefresh(true);
}

void ModelsPage::onDiscussionActiveScopeSelected(int index)
{
    if (index <= 0) return;
    QString entry = discActiveScopesCombo->currentData().toString();
    int sep = entry.indexOf(':');
    if (sep <= 0) return;

    QString scopeType = entry.left(sep);
    QString scopeId = entry.mid(sep + 1);

    for (int i = 0; i < discScopeTypeCombo->count(); i++) {
        if (discScopeTypeCombo->itemData(i).toString() == scopeType) {
            discScopeTypeCombo->setCurrentIndex(i);
            break;
        }
    }
    discScopeIdEdit->setText(scopeId);

    discActiveScopesCombo->blockSignals(true);
    discActiveScopesCombo->setCurrentIndex(0);
    discActiveScopesCombo->blockSignals(false);

    onDiscussionRefresh(true);
}

void ModelsPage::onDiscussionLoadActiveScopes(bool force)
{
    if (!clientModel || !walletModel || !discActiveScopesCombo) return;

    loadDiscussionScopeAliases(force);
    if (discRecentScopesCombo) {
        for (int i = discRecentScopesCombo->count() - 1; i >= 1; --i) {
            const QString entry = discRecentScopesCombo->itemData(i).toString();
            const int sep = entry.indexOf(':');
            if (sep <= 0) continue;
            const QString scopeType = entry.left(sep);
            const QString scopeId = entry.mid(sep + 1);
            const QString label = buildDiscussionScopeLabel(scopeType, scopeId, 0, QString());
            if (label.isEmpty()) {
                discRecentScopesCombo->removeItem(i);
            } else {
                discRecentScopesCombo->setItemText(i, label);
            }
        }
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(0);   // since
        params.push_back(50);  // limit
        params.push_back(force);
        params.push_back(discHideScopesWithoutLiveVerifiedCheck &&
                         discHideScopesWithoutLiveVerifiedCheck->isChecked());

        UniValue result = clientModel->node().executeRpc("cosign.discussion_scopes", params, "");
        if (!result.isObject() || !result.exists("scopes") || !result["scopes"].isArray()) {
            return;
        }

        discActiveScopesCombo->blockSignals(true);
        discActiveScopesCombo->clear();
        discActiveScopesCombo->addItem(tr("(load active discussions from relay)"), "");
        QSet<QString> currentScopes;
        QStringList newDiscussionLabels;

        const UniValue& scopes = result["scopes"];
        for (size_t i = 0; i < scopes.size(); i++) {
            const UniValue& scope = scopes[i];
            if (!scope.isObject() || !scope.exists("scope_type") || !scope.exists("scope_id")) {
                continue;
            }

            const QString scopeType = QString::fromStdString(scope["scope_type"].get_str());
            const QString scopeId = QString::fromStdString(scope["scope_id"].get_str());
            const QString preview = (scope.exists("latest_content_preview") && scope["latest_content_preview"].isStr())
                ? QString::fromStdString(scope["latest_content_preview"].get_str())
                : QString();
            const uint64_t postCount = (scope.exists("post_count"))
                ? scope["post_count"].getInt<uint64_t>()
                : 0;
            if (scope.exists("model_identifier") && scope["model_identifier"].isStr()) {
                rememberDiscussionScopeAlias(scopeType, scopeId, QString::fromStdString(scope["model_identifier"].get_str()));
            }

            QString label = buildDiscussionScopeLabel(scopeType, scopeId, postCount, preview);
            if (label.isEmpty()) {
                continue;
            }

            const QString entry = scopeType + ":" + scopeId;
            currentScopes.insert(entry);
            if (discKnownDiscussionScopesInitialized && !discKnownDiscussionScopes.contains(entry)) {
                newDiscussionLabels.push_back(label);
            }
            discActiveScopesCombo->addItem(label, QVariant(entry));
        }
        discActiveScopesCombo->blockSignals(false);

        if (discKnownDiscussionScopesInitialized && !newDiscussionLabels.isEmpty()) {
            const int totalNew = newDiscussionLabels.size();
            QString body;
            const int previewCount = std::min(totalNew, 3);
            for (int i = 0; i < previewCount; ++i) {
                if (!body.isEmpty()) body += "\n";
                body += "- " + newDiscussionLabels[i];
            }
            if (totalNew > previewCount) {
                body += tr("\n...and %1 more").arg(totalNew - previewCount);
            }
            Q_EMIT this->message(tr("New discussions"), body, CClientUIInterface::MSG_INFORMATION);
        }

        discKnownDiscussionScopes = currentScopes;
        discKnownDiscussionScopesInitialized = true;
    } catch (...) {
        if (discActiveScopesCombo) {
            discActiveScopesCombo->blockSignals(true);
            discActiveScopesCombo->clear();
            discActiveScopesCombo->addItem(tr("(failed to load active discussions)"), "");
            discActiveScopesCombo->blockSignals(false);
        }
    }
}

void ModelsPage::onDiscussionHowItWorks()
{
    auto* dialog = new QDialog(TopLevelDialogParent(this));
    dialog->setWindowTitle(tr("Discussion Channel — How it works"));
    dialog->setModal(true);
    dialog->resize(840, 640);

    auto* dialogLayout = new QVBoxLayout(dialog);

    auto* browser = new QTextBrowser(dialog);
    browser->setOpenExternalLinks(false);
    browser->setReadOnly(true);
    browser->setHtml(tr("<h3>Relay-Based Discussion Threads</h3>"
                        "<p>The Discussion tab lets you read and post messages in off-chain discussion threads "
                        "for model pre-alerts and model challenges.</p>"
                        "<h4>Opening a thread</h4>"
                        "<ul>"
                        "<li><b>Active</b> loads discussion scopes discovered from public relays and is the "
                        "easiest way to open an existing thread.</li>"
                        "<li><b>Recent</b> contains scopes you viewed locally before.</li>"
                        "<li><b>Model Identifier</b> in the form <code>model_name@commit_id</code> is the "
                        "primary selector for both discussion types. When valid, it automatically fills the "
                        "matching <b>Scope Hash</b>.</li>"
                        "<li>You can still paste a 64-character <b>Scope Hash</b> manually for direct lookup. "
                        "If the discussion already exists and carries a valid identifier, the identifier field "
                        "can be filled back from relay data.</li>"
                        "</ul>"
                        "<h4>How messages are published</h4>"
                        "<ul>"
                        "<li>Each post includes a <b>BIP-322 ownership proof</b> created automatically from a "
                        "confirmed UTXO that meets the stake requirement.</li>"
                        "<li>Each post also carries a required <b>Model Identifier</b> "
                        "(<code>model_name@commit_id</code>) so discussion lists can show a human-readable "
                        "thread name instead of only a hash.</li>"
                        "<li>The proof is bound to the exact scope and your Nostr pseudonym, so it cannot be "
                        "replayed in another thread.</li>"
                        "<li>Messages are published to public Nostr relays as discussion events.</li>"
                        "</ul>"
                        "<h4>How verification works</h4>"
                        "<ul>"
                        "<li>Every refresh re-checks each message locally: network, scope, proof format, "
                        "BIP-322 signature, backing UTXO, and expiry height.</li>"
                        "<li>If the proof expires, the message remains visible but is treated as expired.</li>"
                        "<li>If the backing UTXO is later spent or the proof is otherwise invalid, the message "
                        "is marked <b>Rejected</b>.</li>"
                        "</ul>"
                        "<h4>Filters and active discussions</h4>"
                        "<ul>"
                        "<li><b>Verified only</b>, <b>Hide expired</b>, and <b>Min verified stake</b> affect "
                        "only what is shown in the current table.</li>"
                        "<li><b>Live only</b> in the Active list hides scopes that do not currently contain at "
                        "least one verified, unexpired message.</li>"
                        "<li>Discussion lists only show threads that have a valid "
                        "<code>model_name@commit_id</code> identifier.</li>"
                        "</ul>"
                        "<h4>Relay refresh and cached results</h4>"
                        "<ul>"
                        "<li>The node tries to refresh threads from relays when you open or refresh them.</li>"
                        "<li>If relay refresh fails but cached results already exist, the tab can show cached "
                        "messages and will warn you in the status line.</li>"
                        "</ul>"
                        "<h4>Privacy</h4>"
                        "<ul>"
                        "<li>Your Nostr identity is a local pseudonym and is not automatically tied to your "
                        "wallet identity.</li>"
                        "<li>Readers verify that some stake backs the message, but they do not learn your full "
                        "wallet ownership graph from the discussion proof alone.</li>"
                        "</ul>"));
    dialogLayout->addWidget(browser, 1);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok, dialog);
    connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    dialogLayout->addWidget(buttons);

    dialog->exec();
}

void ModelsPage::onDiscussionRefresh(bool force)
{
    if (!clientModel || !walletModel) return;

    QString scopeId = discScopeIdEdit->text().trimmed();
    QString scopeType = discScopeTypeCombo->currentData().toString();
    if (!kHex64Re.match(scopeId).hasMatch()) {
        discStatusLabel->setText(tr("Enter a valid 64-char hex hash to view discussion"));
        discPostsTable->setRowCount(0);
        return;
    }
    if (scopeType == "model_challenge" && !discussionChallengeScopeExists(scopeId)) {
        discStatusLabel->setText(tr("Challenge discussion requires an existing model hash in ModelDB"));
        discPostsTable->setRowCount(0);
        return;
    }
    discStatusLabel->setText(tr("Loading..."));

    const auto fetchDiscussionPosts = [this, &scopeType, &scopeId, force]() {
        // Call cosign.discussion_list RPC
        UniValue params(UniValue::VARR);
        params.push_back(scopeType.toStdString());
        params.push_back(scopeId.toStdString());
        params.push_back(0);   // since
        params.push_back(200); // limit
        params.push_back(force); // force_refresh — bypasses bridge cache on manual Refresh

        return clientModel->node().executeRpc("cosign.discussion_list", params, "");
    };

    try {
        UniValue result;
        try {
            result = fetchDiscussionPosts();
            discBbInitialized = true;
        } catch (const UniValue& e) {
            const QString err = FormatRpcError(e);
            const bool needsInit =
                err.contains("init_bb first", Qt::CaseInsensitive) ||
                err.contains("not initialized", Qt::CaseInsensitive);

            if (!needsInit) {
                throw;
            }

            QStringList defaultRelays = {
                "wss://relay.damus.io",
                "wss://nos.lol",
                "wss://relay.snort.social"
            };
            auto initResult = walletModel->bulletinBoardInit(defaultRelays);
            if (!initResult.success) {
                discStatusLabel->setText(tr("Bulletin board init failed: %1").arg(initResult.error));
                discPostsTable->setRowCount(0);
                return;
            }

            discBbInitialized = true;
            result = fetchDiscussionPosts();
        }

        if (!result.isObject() || !result.exists("posts")) {
            discStatusLabel->setText(tr("No posts or bridge unavailable"));
            discPostsTable->setRowCount(0);
            return;
        }

        int currentHeight = result.exists("current_height") ? result["current_height"].getInt<int>() : 0;
        const UniValue& posts = result["posts"];

        if (scopeType == "model_prealert" && discModelIdentifierEdit) {
            QString remoteIdentifier;
            for (size_t i = 0; i < posts.size(); ++i) {
                const UniValue& post = posts[i];
                if (post.exists("model_identifier") && post["model_identifier"].isStr()) {
                    remoteIdentifier = QString::fromStdString(post["model_identifier"].get_str()).trimmed();
                }
            }
            if (!remoteIdentifier.isEmpty()) {
                rememberDiscussionScopeAlias(scopeType, scopeId, remoteIdentifier);
                discSyncingDiscussionFields = true;
                discModelIdentifierEdit->setText(remoteIdentifier);
                discSyncingDiscussionFields = false;
            }
        }

        // Apply local filters
        bool hideUnverified = discHideUnverifiedCheck->isChecked();
        bool hideExpired = discHideExpiredCheck->isChecked();
        uint64_t minStake = static_cast<uint64_t>(discMinStakeSpin->value());

        std::vector<const UniValue*> filtered;
        for (size_t i = 0; i < posts.size(); i++) {
            const UniValue& post = posts[i];

            bool verified = post.exists("verified") && post["verified"].get_bool();
            if (hideUnverified && !verified) continue;

            if (hideExpired && post.exists("expiry_height")) {
                int expiry = post["expiry_height"].getInt<int>();
                if (currentHeight >= expiry) continue;
            }

            if (minStake > 0 && verified && post.exists("verified_units")) {
                uint64_t units = post["verified_units"].getInt<uint64_t>();
                if (units < minStake) continue;
            }

            filtered.push_back(&post);
        }

        // Populate table
        discPostsTable->setRowCount(static_cast<int>(filtered.size()));

        for (int row = 0; row < static_cast<int>(filtered.size()); row++) {
            const UniValue& post = *filtered[row];

            // Time
            uint64_t created_at = post.exists("created_at") ? post["created_at"].getInt<uint64_t>() : 0;
            QDateTime dt = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(created_at));
            QTableWidgetItem* timeItem = new QTableWidgetItem(dt.toString("yyyy-MM-dd hh:mm"));
            timeItem->setToolTip(dt.toString(Qt::ISODate));
            discPostsTable->setItem(row, 0, timeItem);

            // Author (truncated pubkey)
            QString fullAuthor = post.exists("author_pubkey") ?
                QString::fromStdString(post["author_pubkey"].get_str()) : "?";
            QString author = fullAuthor;
            if (author.length() > 12) {
                author = author.left(6) + "..." + author.right(4);
            }
            discPostsTable->setItem(row, 1, new QTableWidgetItem(author));

            // Message
            QString content = post.exists("content") ?
                QString::fromStdString(post["content"].get_str()) : "";
            const bool verified = post.exists("verified") && post["verified"].get_bool();
            QTableWidgetItem* msgItem = new QTableWidgetItem(content);
            msgItem->setToolTip(content);
            msgItem->setData(Qt::UserRole, content);
            msgItem->setData(Qt::UserRole + 1, fullAuthor);
            msgItem->setData(Qt::UserRole + 2, post.exists("post_id") ? QString::fromStdString(post["post_id"].get_str()) : QString());
            msgItem->setData(Qt::UserRole + 3, post.exists("model_identifier") ? QString::fromStdString(post["model_identifier"].get_str()) : QString());
            msgItem->setData(Qt::UserRole + 4, post.exists("has_proof") ? post["has_proof"].get_bool() : false);
            msgItem->setData(Qt::UserRole + 5, verified);
            msgItem->setData(Qt::UserRole + 6, post.exists("verified_units") ? QString::number(post["verified_units"].getInt<uint64_t>()) : QString());
            msgItem->setData(Qt::UserRole + 7, post.exists("expiry_height") ? QString::number(post["expiry_height"].getInt<int>()) : QString());
            msgItem->setData(Qt::UserRole + 8, post.exists("rejected_reason") ? QString::fromStdString(post["rejected_reason"].get_str()) : QString());
            msgItem->setData(Qt::UserRole + 9, dt.toString(Qt::ISODate));
            discPostsTable->setItem(row, 2, msgItem);

            // Stake
            QString stakeStr;
            if (verified && post.exists("verified_units")) {
                uint64_t units = post["verified_units"].getInt<uint64_t>();
                stakeStr = QString::number(units / 100000000.0, 'f', 4) + " TSC";
            } else {
                stakeStr = "-";
            }
            discPostsTable->setItem(row, 3, new QTableWidgetItem(stakeStr));

            // Expiry height
            QString expiryStr;
            if (post.exists("expiry_height")) {
                int expiry = post["expiry_height"].getInt<int>();
                if (currentHeight >= expiry) {
                    expiryStr = QString::number(expiry) + " (passed)";
                } else {
                    int remaining = expiry - currentHeight;
                    expiryStr = QString::number(expiry) + " (~" + QString::number(remaining) + " blk)";
                }
            } else {
                expiryStr = "-";
            }
            discPostsTable->setItem(row, 4, new QTableWidgetItem(expiryStr));

            // Status
            QString statusStr;
            QColor statusColor;
            if (verified) {
                statusStr = "Verified";
                statusColor = QColor(0, 128, 0);
            } else if (post.exists("rejected_reason")) {
                QString reason = QString::fromStdString(post["rejected_reason"].get_str());
                if (reason.contains("Expired")) {
                    statusStr = "Expired";
                    statusColor = QColor(128, 128, 128);
                } else if (reason.contains("No proof")) {
                    statusStr = "No proof";
                    statusColor = QColor(200, 150, 0);
                } else {
                    statusStr = "Rejected";
                    statusColor = QColor(200, 0, 0);
                }
            } else {
                statusStr = "Unknown";
                statusColor = QColor(128, 128, 128);
            }
            QTableWidgetItem* statusItem = new QTableWidgetItem(statusStr);
            statusItem->setForeground(statusColor);
            if (post.exists("rejected_reason")) {
                statusItem->setToolTip(QString::fromStdString(post["rejected_reason"].get_str()));
            }
            discPostsTable->setItem(row, 5, statusItem);
        }

        QString statusText = tr("%1 posts (%2 shown)")
            .arg(posts.size())
            .arg(filtered.size());
        if (result.exists("stale") && result["stale"].get_bool()) {
            QString refreshError;
            if (result.exists("refresh_error") && result["refresh_error"].isStr()) {
                refreshError = QString::fromStdString(result["refresh_error"].get_str());
            }
            statusText += refreshError.isEmpty()
                ? tr(" | Warning: showing cached results")
                : tr(" | Warning: showing cached results (%1)").arg(refreshError);
        }
        discStatusLabel->setText(statusText);

        // Persist this scope to recent list (max 10 entries, most recent first)
        {
            if (discModelIdentifierEdit) {
                rememberDiscussionScopeAlias(scopeType, scopeId, discModelIdentifierEdit->text());
            }

            QString entry = scopeType + ":" + scopeId;
            QSettings settings;
            QStringList recent = settings.value("discussion/recent_scopes").toStringList();
            recent.removeAll(entry); // deduplicate
            recent.prepend(entry);
            while (recent.size() > 10) recent.removeLast();
            settings.setValue("discussion/recent_scopes", recent);

            // Update combo (avoid duplicate entries)
            bool found = false;
            for (int i = 1; i < discRecentScopesCombo->count(); i++) {
                if (discRecentScopesCombo->itemData(i).toString() == entry) {
                    const QString label = buildDiscussionScopeLabel(scopeType, scopeId, 0, QString());
                    if (label.isEmpty()) {
                        discRecentScopesCombo->removeItem(i);
                    } else {
                        discRecentScopesCombo->setItemText(i, label);
                    }
                    found = true;
                    break;
                }
            }
            if (!found) {
                QString label = buildDiscussionScopeLabel(scopeType, scopeId, 0, QString());
                if (!label.isEmpty()) {
                    discRecentScopesCombo->insertItem(1, label, entry);
                    // Trim combo to 10 + placeholder
                    while (discRecentScopesCombo->count() > 11) {
                        discRecentScopesCombo->removeItem(discRecentScopesCombo->count() - 1);
                    }
                }
            }
        }

    } catch (const UniValue& e) {
        discStatusLabel->setText(tr("Error: %1").arg(FormatRpcError(e)));
        discPostsTable->setRowCount(0);
    } catch (const std::exception& e) {
        discStatusLabel->setText(tr("Error: %1").arg(e.what()));
        discPostsTable->setRowCount(0);
    }
}

void ModelsPage::onDiscussionPost()
{
    if (!clientModel || !walletModel) return;

    QString content = discComposeEdit->toPlainText().trimmed();
    if (content.isEmpty()) {
        showError(tr("Message cannot be empty"));
        return;
    }
    if (content.length() > 4096) {
        showError(tr("Message too long (max 4096 characters)"));
        return;
    }

    QString scopeId = discScopeIdEdit->text().trimmed();
    if (!kHex64Re.match(scopeId).hasMatch()) {
        showError(tr("Scope ID must be a 64-character hex hash"));
        return;
    }

    QString scopeType = discScopeTypeCombo->currentData().toString();
    if (scopeType == "model_challenge" && !discussionChallengeScopeExists(scopeId)) {
        showError(tr("Challenge discussion requires Scope Hash to match an existing model in ModelDB"));
        return;
    }
    QString modelIdentifier = discModelIdentifierEdit ? discModelIdentifierEdit->text().trimmed() : QString();
    if (!IsValidModelIdentifier(modelIdentifier)) {
        showError(tr("Model Identifier must be provided in model_name@commit_id format"));
        return;
    }

    // Confirm with user — show message preview and min stake requirement
    QString preview = content.length() > 200 ? content.left(200) + "..." : content;
    QMessageBox::StandardButton reply = QMessageBox::question(
        TopLevelDialogParent(this),
        tr("Post Discussion Message"),
        tr("Post this message to the %1 thread?\n\n"
           "Model Identifier: %2\n"
           "Scope: %3\n\n"
           "Message:\n%4\n\n"
           "Min stake: %5 sat\n\n"
           "This will create a BIP-322 proof-of-funds and publish to Nostr relays.")
            .arg(scopeType)
            .arg(modelIdentifier)
            .arg(scopeId.left(16) + "...")
            .arg(preview)
            .arg(discMinStakeSpin->value()),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) return;

    discPostButton->setEnabled(false);
    discStatusLabel->setText(tr("Posting..."));
    const bool restartScopesTimer = discScopesRefreshTimer && discScopesRefreshTimer->isActive();
    const bool restartThreadTimer = discRefreshTimer && discRefreshTimer->isActive();
    if (restartScopesTimer) {
        discScopesRefreshTimer->stop();
    }
    if (restartThreadTimer) {
        discRefreshTimer->stop();
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(scopeType.toStdString());
        params.push_back(scopeId.toStdString());
        params.push_back(content.toStdString());
        params.push_back(200); // expiry_blocks
        params.push_back(discMinStakeSpin->value()); // min_stake
        params.push_back(modelIdentifier.toStdString());

        UniValue result = clientModel->node().executeRpc(
            "cosign.discussion_post", params,
            walletModel->getWalletName().toStdString());

        discComposeEdit->clear();
        discStatusLabel->setText(tr("Posted successfully"));
        onDiscussionLoadActiveScopes(false);

        // Refresh to show new post (force to bypass cache)
        QTimer::singleShot(1000, this, [this]() { onDiscussionRefresh(true); });

    } catch (const UniValue& e) {
        showError(tr("Failed to post: %1").arg(FormatRpcError(e)));
        discStatusLabel->setText(tr("Post failed"));
    } catch (const std::exception& e) {
        showError(tr("Failed to post: %1").arg(e.what()));
        discStatusLabel->setText(tr("Post failed"));
    }

    if (restartScopesTimer && discScopesRefreshTimer && !discScopesRefreshTimer->isActive()) {
        discScopesRefreshTimer->start(30000);
    }
    if (restartThreadTimer && discRefreshTimer && !discRefreshTimer->isActive()) {
        discRefreshTimer->start(30000);
    }

    // Re-evaluate button state based on current form contents
    onDiscussionScopeChanged();
}

void ModelsPage::onDiscussionPostDoubleClicked(int row, int /*column*/)
{
    if (!discPostsTable || row < 0 || row >= discPostsTable->rowCount()) return;

    QTableWidgetItem* msgItem = discPostsTable->item(row, 2);
    if (!msgItem) return;

    const QString messageText = msgItem->data(Qt::UserRole).toString();
    const QString senderPubkey = msgItem->data(Qt::UserRole + 1).toString();
    const QString postId = msgItem->data(Qt::UserRole + 2).toString();
    const QString modelIdentifier = msgItem->data(Qt::UserRole + 3).toString();
    const bool hasProof = msgItem->data(Qt::UserRole + 4).toBool();
    const bool verified = msgItem->data(Qt::UserRole + 5).toBool();
    const QString verifiedUnits = msgItem->data(Qt::UserRole + 6).toString();
    const QString expiryHeight = msgItem->data(Qt::UserRole + 7).toString();
    const QString rejectedReason = msgItem->data(Qt::UserRole + 8).toString();
    const QString createdAtIso = msgItem->data(Qt::UserRole + 9).toString();

    QDialog dialog(TopLevelDialogParent(this));
    dialog.setWindowTitle(tr("Discussion Message Details"));
    dialog.resize(840, 520);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    QLabel* paramsLabel = new QLabel(tr("Sender parameters:"));
    paramsLabel->setStyleSheet("font-weight: 600;");
    layout->addWidget(paramsLabel);

    QStringList senderDetails;
    senderDetails << tr("Post ID: %1").arg(postId.isEmpty() ? "-" : postId);
    senderDetails << tr("Author pubkey: %1").arg(senderPubkey.isEmpty() ? "-" : senderPubkey);
    senderDetails << tr("Created at: %1").arg(createdAtIso.isEmpty() ? "-" : createdAtIso);
    senderDetails << tr("Model identifier: %1").arg(modelIdentifier.isEmpty() ? "-" : modelIdentifier);
    senderDetails << tr("Has proof: %1").arg(hasProof ? "true" : "false");
    senderDetails << tr("Verified: %1").arg(verified ? "true" : "false");
    senderDetails << tr("Verified units (sats): %1").arg(verifiedUnits.isEmpty() ? "-" : verifiedUnits);
    senderDetails << tr("Expiry height: %1").arg(expiryHeight.isEmpty() ? "-" : expiryHeight);
    senderDetails << tr("Rejected reason: %1").arg(rejectedReason.isEmpty() ? "-" : rejectedReason);

    QTextEdit* senderView = new QTextEdit();
    senderView->setReadOnly(true);
    senderView->setPlainText(senderDetails.join('\n'));
    senderView->setMinimumHeight(190);
    layout->addWidget(senderView);

    QLabel* messageLabel = new QLabel(tr("Message text:"));
    messageLabel->setStyleSheet("font-weight: 600;");
    layout->addWidget(messageLabel);

    QTextEdit* messageView = new QTextEdit();
    messageView->setReadOnly(true);
    messageView->setPlainText(messageText);
    layout->addWidget(messageView, 1);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    layout->addWidget(buttons);

    dialog.exec();
}
