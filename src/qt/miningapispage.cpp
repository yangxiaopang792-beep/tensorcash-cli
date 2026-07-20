// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/miningapispage.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <interfaces/node.h>
#include <node/context.h>
#include <node/extapi.h>
#include <node/interface_ui.h>
#include <validationadvisory.h>
#include <validationapi.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QTextEdit>
#include <QMessageBox>
#include <QDateTime>
#include <QGroupBox>
#include <QFrame>
#include <QTimer>
#include <QInputDialog>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QNetworkRequest>
#include <QUrl>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>

#include <algorithm>
#include <cstdlib>

namespace {
constexpr int MODEL_STATUS_REGISTERED = 2;
constexpr QNetworkRequest::Attribute ATTR_MINING_TARGETS = QNetworkRequest::User;
constexpr QNetworkRequest::Attribute ATTR_MINING_PAYLOAD = static_cast<QNetworkRequest::Attribute>(QNetworkRequest::User + 1);

int HeaderInt(const QByteArray& raw, int fallback = 0)
{
    bool ok{false};
    const int value = QString::fromUtf8(raw).toInt(&ok);
    return ok ? value : fallback;
}

bool IsRemoteVerifierMode()
{
    // Remote/orchestrator mode is active when external validator base URL is set.
    // In this mode operator decisions are made on orchestrator side.
    const char* base_url = std::getenv("VALIDATOR_BASE_URL");
    if (!base_url) return false;
    const QString value = QString::fromUtf8(base_url).trimmed();
    return !value.isEmpty();
}
}

MiningApisPage::MiningApisPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_platform_style(platformStyle)
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    tabWidget = new QTabWidget(this);

    setupMiningStatusTab();
    setupVerificationStatusTab();
    setupConfigurationTab();
    setupMetricsTab();
    setupReorgAdvisoryTab();

    tabWidget->addTab(miningStatusTab, tr("Mining API"));
    tabWidget->addTab(verificationStatusTab, tr("Verification API"));
    tabWidget->addTab(configurationTab, tr("Configuration"));
    tabWidget->addTab(metricsTab, tr("Metrics && Logs"));
    tabWidget->addTab(reorgAdvisoryTab, tr("Reorg Advisory"));
    m_operatorReviewEnabled = !IsRemoteVerifierMode();
    if (m_operatorReviewEnabled) {
        setupOperatorReviewTab();
        tabWidget->addTab(operatorReviewTab, tr("Operator Review"));
    }

    mainLayout->addWidget(tabWidget);

    // Setup status update timer (5 seconds for uptime only - very lightweight)
    statusUpdateTimer = new QTimer(this);
    connect(statusUpdateTimer, &QTimer::timeout, this, &MiningApisPage::onStatusTimerTick);
    // Don't start timer yet - will start when page becomes visible

    // Setup metrics update timer (30 seconds for metrics - only when visible)
    metricsUpdateTimer = new QTimer(this);
    connect(metricsUpdateTimer, &QTimer::timeout, this, &MiningApisPage::onMetricsTimerTick);
    // Don't start timer yet - will start when page becomes visible

    // Setup network manager for miner proxy metrics
    networkManager = new QNetworkAccessManager(this);
    connect(networkManager, &QNetworkAccessManager::finished, this, &MiningApisPage::onMinerProxyReply);

    // Setup network manager for operator review API
    if (m_operatorReviewEnabled) {
        operatorNetworkManager = new QNetworkAccessManager(this);
        connect(operatorNetworkManager, &QNetworkAccessManager::finished, this, &MiningApisPage::onOperatorReply);

        // Operator review polling should run even when this page/tab is not visible.
        operatorReviewsTimer = new QTimer(this);
        connect(operatorReviewsTimer, &QTimer::timeout, this, &MiningApisPage::onOperatorAutoRefreshTick);
        operatorReviewsTimer->start(30000);
    }
}

void MiningApisPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    // Start timers when page becomes visible
    if (!statusUpdateTimer->isActive()) {
        statusUpdateTimer->start(5000);
    }
    if (!metricsUpdateTimer->isActive()) {
        metricsUpdateTimer->start(30000);
        // Do immediate update when showing
        onMetricsTimerTick();
    }
}

void MiningApisPage::hideEvent(QHideEvent* event)
{
    QWidget::hideEvent(event);
    // Stop timers when page is hidden to not waste CPU
    statusUpdateTimer->stop();
    metricsUpdateTimer->stop();
}

MiningApisPage::~MiningApisPage()
{
}

void MiningApisPage::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (clientModel) {
        if (m_operatorReviewEnabled && operatorReviewsTimer && !operatorReviewsTimer->isActive()) {
            operatorReviewsTimer->start(30000);
        }
        // Initial update
        updateMiningStatus();
        updateMetrics();
        updateValidationStatus();
        updateMinerProxyMetrics();
        refreshMiningRegisteredModels();
        refreshMiningActiveModel();
        updateReorgAdvisories();
        if (m_operatorReviewEnabled) {
            refreshOperatorReviews();
        }
    }
}

void MiningApisPage::setupMiningStatusTab()
{
    miningStatusTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(miningStatusTab);

    // Two-column layout
    QHBoxLayout* columnsLayout = new QHBoxLayout();

    // ===== LEFT COLUMN - Mining Status =====
    QGroupBox* statusGroup = new QGroupBox(tr("Mining Status"));
    QVBoxLayout* statusLayout = new QVBoxLayout(statusGroup);

    QGridLayout* statusGrid = new QGridLayout();
    statusGrid->addWidget(new QLabel(tr("Status:")), 0, 0);
    miningStatusLabel = new QLabel(tr("● Stopped"));
    miningStatusLabel->setStyleSheet("QLabel { color: #757575; font-weight: bold; }");
    statusGrid->addWidget(miningStatusLabel, 0, 1);

    statusGrid->addWidget(new QLabel(tr("Address:")), 1, 0);
    miningAddressLabel = new QLabel(tr("None"));
    miningAddressLabel->setWordWrap(true);
    statusGrid->addWidget(miningAddressLabel, 1, 1);

    statusGrid->addWidget(new QLabel(tr("Uptime:")), 2, 0);
    miningUptimeLabel = new QLabel(tr("0s"));
    statusGrid->addWidget(miningUptimeLabel, 2, 1);

    statusLayout->addLayout(statusGrid);
    statusLayout->addSpacing(10);

    // Mining control buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    startMiningButton = new QPushButton(tr("Start Mining"));
    stopMiningButton = new QPushButton(tr("Stop Mining"));
    stopMiningButton->setEnabled(false);
    buttonLayout->addWidget(startMiningButton);
    buttonLayout->addWidget(stopMiningButton);
    statusLayout->addLayout(buttonLayout);

    statusGroup->setMaximumHeight(200);
    columnsLayout->addWidget(statusGroup);

    // ===== RIGHT COLUMN - Mining Metrics =====
    QGroupBox* metricsGroup = new QGroupBox(tr("Mining Metrics"));
    QVBoxLayout* metricsLayout = new QVBoxLayout(metricsGroup);

    QGridLayout* metricsGrid = new QGridLayout();
    metricsGrid->addWidget(new QLabel(tr("Solutions Received:")), 0, 0);
    solutionsReceivedLabel = new QLabel(tr("0"));
    metricsGrid->addWidget(solutionsReceivedLabel, 0, 1);

    metricsGrid->addWidget(new QLabel(tr("Usable Solutions:")), 1, 0);
    solutionsUsableLabel = new QLabel(tr("0"));
    metricsGrid->addWidget(solutionsUsableLabel, 1, 1);

    metricsGrid->addWidget(new QLabel(tr("Invalid Responses:")), 2, 0);
    solutionsInvalidLabel = new QLabel(tr("0"));
    metricsGrid->addWidget(solutionsInvalidLabel, 2, 1);

    metricsGrid->addWidget(new QLabel(tr("Late Duplicates:")), 3, 0);
    solutionsDuplicateLabel = new QLabel(tr("0"));
    metricsGrid->addWidget(solutionsDuplicateLabel, 3, 1);

    metricsGrid->addWidget(new QLabel(tr("Usable Rate:")), 4, 0);
    usableRateLabel = new QLabel(tr("N/A"));
    metricsGrid->addWidget(usableRateLabel, 4, 1);

    metricsGrid->addWidget(new QLabel(tr("Rate Limited:")), 5, 0);
    rateLimitedLabel = new QLabel(tr("0"));
    metricsGrid->addWidget(rateLimitedLabel, 5, 1);

    metricsGrid->addWidget(new QLabel(tr("Network Errors:")), 6, 0);
    networkErrorsLabel = new QLabel(tr("0"));
    metricsGrid->addWidget(networkErrorsLabel, 6, 1);

    metricsGrid->addWidget(new QLabel(tr("Last Solution:")), 7, 0);
    lastSolutionLabel = new QLabel(tr("Never"));
    metricsGrid->addWidget(lastSolutionLabel, 7, 1);

    metricsLayout->addLayout(metricsGrid);
    metricsLayout->addSpacing(5);

    refreshMetricsButton = new QPushButton(tr("Refresh"));
    metricsLayout->addWidget(refreshMetricsButton);

    metricsGroup->setMaximumHeight(280);
    columnsLayout->addWidget(metricsGroup);

    layout->addLayout(columnsLayout);

    // ===== MINER PROXY THROUGHPUT =====
    QGroupBox* throughputGroup = new QGroupBox(tr("Miner Throughput (vLLM)"));
    QVBoxLayout* throughputLayout = new QVBoxLayout(throughputGroup);

    QGridLayout* throughputGrid = new QGridLayout();
    // Row 0: Hashrate (primary metric) and Tokens/sec
    throughputGrid->addWidget(new QLabel(tr("Hashrate:")), 0, 0);
    hashRateLabel = new QLabel(tr("--"));
    hashRateLabel->setStyleSheet("QLabel { font-weight: bold; color: #2E7D32; font-size: 14px; }");
    throughputGrid->addWidget(hashRateLabel, 0, 1);

    throughputGrid->addWidget(new QLabel(tr("Tokens/sec:")), 0, 2);
    tokensPerSecLabel = new QLabel(tr("--"));
    tokensPerSecLabel->setStyleSheet("QLabel { font-weight: bold; color: #1976D2; }");
    throughputGrid->addWidget(tokensPerSecLabel, 0, 3);

    // Row 1: Total hashes and Active requests
    throughputGrid->addWidget(new QLabel(tr("Total Hashes:")), 1, 0);
    totalHashesLabel = new QLabel(tr("--"));
    throughputGrid->addWidget(totalHashesLabel, 1, 1);

    throughputGrid->addWidget(new QLabel(tr("Active Requests:")), 1, 2);
    activeRequestsLabel = new QLabel(tr("--"));
    throughputGrid->addWidget(activeRequestsLabel, 1, 3);

    throughputLayout->addLayout(throughputGrid);
    layout->addWidget(throughputGroup);

    // ===== ACTIVE MINING MODEL (RUNTIME SWITCH) =====
    QGroupBox* modelGroup = new QGroupBox(tr("Active Mining Model"));
    QVBoxLayout* modelLayout = new QVBoxLayout(modelGroup);

    QGridLayout* modelGrid = new QGridLayout();
    modelGrid->addWidget(new QLabel(tr("Registered Model:")), 0, 0);
    miningRegisteredModelCombo = new QComboBox();
    miningRegisteredModelCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    miningRegisteredModelCombo->setMinimumContentsLength(36);
    miningRegisteredModelCombo->setPlaceholderText(tr("Select registered model"));
    modelGrid->addWidget(miningRegisteredModelCombo, 0, 1);
    modelLayout->addLayout(modelGrid);

    QHBoxLayout* modelButtons = new QHBoxLayout();
    refreshMiningModelButton = new QPushButton(tr("Refresh"));
    applyMiningModelButton = new QPushButton(tr("Apply"));
    modelButtons->addWidget(refreshMiningModelButton);
    modelButtons->addWidget(applyMiningModelButton);
    miningForceModelSwitchCheck = new QCheckBox(tr("Force switch"));
    miningForceModelSwitchCheck->setChecked(false);
    modelButtons->addWidget(miningForceModelSwitchCheck);
    modelButtons->addStretch();
    modelLayout->addLayout(modelButtons);

    miningCurrentModelLabel = new QLabel(tr("Current model: unknown"));
    miningCurrentModelLabel->setWordWrap(true);
    modelLayout->addWidget(miningCurrentModelLabel);

    miningActiveModelStateLabel = new QLabel(tr("Runtime model state: unknown"));
    miningActiveModelStateLabel->setWordWrap(true);
    miningActiveModelStateLabel->setStyleSheet("QLabel { color: #757575; }");
    modelLayout->addWidget(miningActiveModelStateLabel);
    layout->addWidget(modelGroup);

    // ===== CONNECTION PARAMETERS =====
    QGroupBox* connectionGroup = new QGroupBox(tr("Mining API Endpoints"));
    QVBoxLayout* connectionLayout = new QVBoxLayout(connectionGroup);

    QGridLayout* endpointsGrid = new QGridLayout();
    endpointsGrid->addWidget(new QLabel(tr("Job Push:")), 0, 0);
    miningJobPushLabel = new QLabel(tr("tcp://localhost:6000"));
    endpointsGrid->addWidget(miningJobPushLabel, 0, 1);

    endpointsGrid->addWidget(new QLabel(tr("Sol Pull:")), 1, 0);
    miningSolPullLabel = new QLabel(tr("tcp://*:7000"));
    endpointsGrid->addWidget(miningSolPullLabel, 1, 1);

    connectionLayout->addLayout(endpointsGrid);
    connectionLayout->addSpacing(5);

    miningHealthLabel = new QLabel(tr("Connection Health: ✓ OK"));
    miningHealthLabel->setStyleSheet("QLabel { color: #2E7D32; font-weight: bold; }");
    connectionLayout->addWidget(miningHealthLabel);

    layout->addWidget(connectionGroup);
    layout->addStretch();

    // Connect signals
    connect(startMiningButton, &QPushButton::clicked, this, &MiningApisPage::onStartMining);
    connect(stopMiningButton, &QPushButton::clicked, this, &MiningApisPage::onStopMining);
    connect(refreshMetricsButton, &QPushButton::clicked, this, &MiningApisPage::onRefreshMetrics);
    connect(refreshMiningModelButton, &QPushButton::clicked, this, &MiningApisPage::onRefreshMiningModel);
    connect(applyMiningModelButton, &QPushButton::clicked, this, &MiningApisPage::onApplyMiningModel);
    connect(miningRegisteredModelCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        updateMiningModelControlsState();
    });
    updateMiningModelControlsState();
}

void MiningApisPage::setupVerificationStatusTab()
{
    verificationStatusTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(verificationStatusTab);

    // ===== CONNECTION STATUS =====
    QGroupBox* connectionGroup = new QGroupBox(tr("Verification API Endpoints"));
    QVBoxLayout* connectionLayout = new QVBoxLayout(connectionGroup);

    QGridLayout* endpointsGrid = new QGridLayout();
    endpointsGrid->addWidget(new QLabel(tr("Request Push:")), 0, 0);
    verifyReqPushLabel = new QLabel(tr("tcp://localhost:5000"));
    endpointsGrid->addWidget(verifyReqPushLabel, 0, 1);

    endpointsGrid->addWidget(new QLabel(tr("Result Pull:")), 1, 0);
    verifySolPullLabel = new QLabel(tr("tcp://*:5001"));
    endpointsGrid->addWidget(verifySolPullLabel, 1, 1);

    connectionLayout->addLayout(endpointsGrid);
    connectionLayout->addSpacing(5);

    verifyHealthLabel = new QLabel(tr("API Status: ● Active"));
    verifyHealthLabel->setStyleSheet("QLabel { color: #2E7D32; font-weight: bold; }");
    connectionLayout->addWidget(verifyHealthLabel);

    layout->addWidget(connectionGroup);

    // ===== VALIDATION QUEUE STATUS =====
    QGroupBox* queueGroup = new QGroupBox(tr("Pending Validations"));
    QVBoxLayout* queueLayout = new QVBoxLayout(queueGroup);

    QGridLayout* queueGrid = new QGridLayout();
    queueGrid->addWidget(new QLabel(tr("Quick Validations:")), 0, 0);
    quickQueueLabel = new QLabel(tr("0 pending"));
    queueGrid->addWidget(quickQueueLabel, 0, 1);

    queueGrid->addWidget(new QLabel(tr("Full Validations:")), 1, 0);
    fullQueueLabel = new QLabel(tr("0 pending"));
    queueGrid->addWidget(fullQueueLabel, 1, 1);

    queueGrid->addWidget(new QLabel(tr("Model Validations:")), 2, 0);
    modelQueueLabel = new QLabel(tr("0 pending"));
    queueGrid->addWidget(modelQueueLabel, 2, 1);

    queueGrid->addWidget(new QLabel(tr("Challenge Validations:")), 3, 0);
    challengeQueueLabel = new QLabel(tr("0 pending"));
    queueGrid->addWidget(challengeQueueLabel, 3, 1);

    queueLayout->addLayout(queueGrid);
    queueLayout->addSpacing(5);

    refreshQueuesButton = new QPushButton(tr("Refresh Queues"));
    queueLayout->addWidget(refreshQueuesButton);

    layout->addWidget(queueGroup);

    // ===== RECENT VALIDATIONS TABLE =====
    QLabel* recentLabel = new QLabel(tr("Recent Validations:"));
    layout->addWidget(recentLabel);

    recentValidationsTable = new QTableWidget(0, 4);
    recentValidationsTable->setHorizontalHeaderLabels({tr("Type"), tr("Block/Model Hash"), tr("Status"), tr("Timestamp")});
    // Stretch all columns proportionally to fill the table width
    recentValidationsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    recentValidationsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    recentValidationsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // Let table expand to fill available space
    recentValidationsTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    recentValidationsTable->setMinimumHeight(200);
    layout->addWidget(recentValidationsTable, 1);  // Stretch factor 1 to take remaining space

    // Connect signals
    connect(refreshQueuesButton, &QPushButton::clicked, this, &MiningApisPage::onRefreshQueues);
    connect(recentValidationsTable, &QTableWidget::cellClicked, this, &MiningApisPage::onValidationSelected);
}

void MiningApisPage::setupConfigurationTab()
{
    configurationTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(configurationTab);

    // ===== MINING API CONFIGURATION =====
    QGroupBox* miningConfigGroup = new QGroupBox(tr("Mining API Configuration"));
    QVBoxLayout* miningConfigLayout = new QVBoxLayout(miningConfigGroup);

    miningConfigDisplay = new QTextEdit();
    miningConfigDisplay->setReadOnly(true);
    miningConfigDisplay->setMaximumHeight(200);
    miningConfigLayout->addWidget(miningConfigDisplay);

    layout->addWidget(miningConfigGroup);

    // ===== VERIFICATION API CONFIGURATION =====
    QGroupBox* verificationConfigGroup = new QGroupBox(tr("Verification API Configuration"));
    QVBoxLayout* verificationConfigLayout = new QVBoxLayout(verificationConfigGroup);

    verificationConfigDisplay = new QTextEdit();
    verificationConfigDisplay->setReadOnly(true);
    verificationConfigDisplay->setMaximumHeight(200);
    verificationConfigLayout->addWidget(verificationConfigDisplay);

    layout->addWidget(verificationConfigGroup);

    // Note label
    QLabel* noteLabel = new QLabel(tr("Note: Configuration is read from environment variables"));
    noteLabel->setStyleSheet("QLabel { color: #757575; font-style: italic; padding: 10px; }");
    layout->addWidget(noteLabel);

    layout->addStretch();

    // Populate configuration displays
    miningConfigDisplay->setText(
        tr("Push Host: localhost\n"
           "Push Port: 6000\n"
           "Pull Bind: *\n"
           "Pull Port: 7000\n"
           "\n"
           "Timeout (ms): 600000\n"
           "Max Request ID: 10000000\n"
           "\n"
           "Environment Variables:\n"
           "- MINING_HOST\n"
           "- MINING_PUSH_PORT\n"
           "- MINING_PULL_PORT\n"
           "- MINING_PULL_BIND")
    );

    verificationConfigDisplay->setText(
        tr("Push Host: localhost\n"
           "Push Port: 5000\n"
           "Pull Bind: *\n"
           "Pull Port: 5001\n"
           "\n"
           "Request Delay: 1000 ms\n"
           "Max Attempts:\n"
           "  - Quick: 10\n"
           "  - Full: 20\n"
           "  - Model: 10\n"
           "\n"
           "Environment Variables:\n"
           "- VALIDATION_HOST\n"
           "- VALIDATION_PUSH_PORT\n"
           "- VALIDATION_PULL_PORT\n"
           "- VALIDATION_PULL_BIND")
    );
}

void MiningApisPage::setupMetricsTab()
{
    metricsTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(metricsTab);

    QLabel* logsLabel = new QLabel(tr("System Logs (Last 100):"));
    layout->addWidget(logsLabel);

    logsDisplay = new QTextEdit();
    logsDisplay->setReadOnly(true);
    logsDisplay->setPlaceholderText(tr("System logs will appear here..."));
    layout->addWidget(logsDisplay);

    // Log control buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    exportLogsButton = new QPushButton(tr("Export Logs"));
    clearLogsButton = new QPushButton(tr("Clear"));
    buttonLayout->addWidget(exportLogsButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(clearLogsButton);
    layout->addLayout(buttonLayout);

    // Connect signals
    connect(exportLogsButton, &QPushButton::clicked, this, &MiningApisPage::onExportLogs);
    connect(clearLogsButton, &QPushButton::clicked, this, &MiningApisPage::onClearLogs);
}

void MiningApisPage::setupOperatorReviewTab()
{
    operatorReviewTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(operatorReviewTab);

    QGroupBox* connGroup = new QGroupBox(tr("Operator API"));
    QGridLayout* connLayout = new QGridLayout(connGroup);
    connLayout->addWidget(new QLabel(tr("Base URL:")), 0, 0);
    operatorApiBaseUrlEdit = new QLineEdit(operatorApiBaseUrl());
    connLayout->addWidget(operatorApiBaseUrlEdit, 0, 1);

    connLayout->addWidget(new QLabel(tr("Bearer API Key:")), 1, 0);
    operatorApiKeyEdit = new QLineEdit(operatorApiKey());
    operatorApiKeyEdit->setEchoMode(QLineEdit::Password);
    connLayout->addWidget(operatorApiKeyEdit, 1, 1);

    operatorRefreshButton = new QPushButton(tr("Refresh Requests"));
    connLayout->addWidget(operatorRefreshButton, 0, 2, 2, 1);
    layout->addWidget(connGroup);

    QGroupBox* pendingGroup = new QGroupBox(tr("Pending Decisions"));
    QVBoxLayout* pendingLayout = new QVBoxLayout(pendingGroup);
    operatorReviewsTable = new QTableWidget(0, 6);
    operatorReviewsTable->setHorizontalHeaderLabels({
        tr("Type"), tr("Model Hash"), tr("Model"), tr("Difficulty"), tr("Status"), tr("Submitted")
    });
    operatorReviewsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    operatorReviewsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    operatorReviewsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    operatorReviewsTable->setMinimumHeight(180);
    pendingLayout->addWidget(operatorReviewsTable);
    layout->addWidget(pendingGroup);

    QGroupBox* detailGroup = new QGroupBox(tr("Audit Report"));
    QVBoxLayout* detailLayout = new QVBoxLayout(detailGroup);
    operatorReviewStatusLabel = new QLabel(tr("Select a pending request to inspect the audit report."));
    operatorReviewStatusLabel->setWordWrap(true);
    detailLayout->addWidget(operatorReviewStatusLabel);

    // Collapsible legend explaining each audit metric. The audit_report JSON
    // below has nested keys like difficulty.{claimed,expected,ratio,verdict},
    // flops.{total_flops,flops_per_token,active_ratio}, salient_weights, validity,
    // file_size_check — operators need a quick reference for what each means and
    // what good/bad looks like before approving or rejecting.
    QToolButton* metricGuideToggle = new QToolButton();
    metricGuideToggle->setCheckable(true);
    metricGuideToggle->setChecked(false);
    metricGuideToggle->setArrowType(Qt::RightArrow);
    metricGuideToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    metricGuideToggle->setAutoRaise(true);
    metricGuideToggle->setText(tr("What am I looking at? (metric guide)"));
    detailLayout->addWidget(metricGuideToggle);

    QLabel* metricGuide = new QLabel();
    metricGuide->setWordWrap(true);
    metricGuide->setTextFormat(Qt::RichText);
    metricGuide->setText(tr(
        "<b>Difficulty Validation</b> — chain enforces "
        "<i>expected_difficulty = normalizer × genesis_fpt / measured_fpt</i>. "
        "<b>Good:</b> ratio ≈ 1.0 within tolerance (±5%). "
        "<b>Bad:</b> ratio ≫ 1.0 → miner inflated the claim. "
        "<b>SKIP:</b> worker has no GENESIS_BASELINES env set."
        "<br><br>"
        "<b>FLOPs Analysis</b> — forward-pass FLOPs/token (≈ matmul-param count for dense). "
        "<b>Good:</b> matches the model's published architecture. "
        "<b>Bad:</b> implausibly low → model is faking its size."
        "<br><br>"
        "<b>Salient Weights</b> — fraction of weights whose ablation hurts loss. "
        "<b>Good:</b> 60–90% for well-trained dense models. "
        "<b>Bad:</b> &lt;30% → over-pruned, undertrained, or padded with random tensors."
        "<br><br>"
        "<b>Validity Tests</b> — sanity probes that the model is a real LM. "
        "<i>Input/Single-Token KL</i> &gt; 0 means the model responds to its input. "
        "<i>Permutation PPL Ratio</i> ≫ 1 means the model learned word order. "
        "<b>Bad:</b> any test ≈ 0 or PPL ratio ≈ 1 → constant-output / bag-of-words impostor."
        "<br><br>"
        "<b>File Size Check</b> — on-disk bytes vs <i>salient_weights × bits/8</i>. "
        "<b>Good:</b> Disk/Expected ≈ 1.0. "
        "<b>Bad:</b> ≫ 1 → padded with junk; ≪ 1 → quantized below claimed precision."
    ));
    metricGuide->setStyleSheet("QLabel { background-color: palette(alternate-base); padding: 8px; border: 1px solid palette(mid); border-radius: 4px; }");
    metricGuide->setVisible(false);
    detailLayout->addWidget(metricGuide);

    connect(metricGuideToggle, &QToolButton::toggled, this, [metricGuide, metricGuideToggle](bool checked) {
        metricGuide->setVisible(checked);
        metricGuideToggle->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
    });

    operatorReviewDetails = new QTextEdit();
    operatorReviewDetails->setReadOnly(true);
    operatorReviewDetails->setPlaceholderText(tr("Audit report details will appear here..."));
    detailLayout->addWidget(operatorReviewDetails);

    QHBoxLayout* actionsLayout = new QHBoxLayout();
    operatorApproveButton = new QPushButton(tr("Approve"));
    operatorRejectButton = new QPushButton(tr("Reject"));
    operatorOpenDiscussionButton = new QPushButton(tr("Open Discussion"));
    actionsLayout->addWidget(operatorApproveButton);
    actionsLayout->addWidget(operatorRejectButton);
    actionsLayout->addWidget(operatorOpenDiscussionButton);
    actionsLayout->addStretch();
    detailLayout->addLayout(actionsLayout);
    layout->addWidget(detailGroup, 1);

    setOperatorButtonsEnabled(false);
    connect(operatorRefreshButton, &QPushButton::clicked, this, &MiningApisPage::onRefreshOperatorReviews);
    connect(operatorReviewsTable, &QTableWidget::cellClicked, this, &MiningApisPage::onOperatorReviewSelected);
    connect(operatorApproveButton, &QPushButton::clicked, this, &MiningApisPage::onOperatorApprove);
    connect(operatorRejectButton, &QPushButton::clicked, this, &MiningApisPage::onOperatorReject);
    connect(operatorOpenDiscussionButton, &QPushButton::clicked, this, &MiningApisPage::onOperatorOpenDiscussion);
}

// ===== SLOTS IMPLEMENTATION =====

void MiningApisPage::onStartMining()
{
    if (!clientModel) {
        showError(tr("Client model not available"));
        return;
    }

    // Confirm with user about address rotation
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Start Mining"),
        tr("Start mining with automatic address rotation?\n\n"
           "A new P2WPKH address will be generated for EACH block mined.\n"
           "This maximizes privacy and is the recommended approach."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("startminingwithrotation", params, "");

        miningActive = true;
        miningStartTime = QDateTime::currentSecsSinceEpoch();
        currentMiningAddress = tr("Rotating (new per block)");

        startMiningButton->setEnabled(false);
        stopMiningButton->setEnabled(true);

        miningStatusLabel->setText(tr("● Active"));
        miningStatusLabel->setStyleSheet("QLabel { color: #2E7D32; font-weight: bold; }");
        miningAddressLabel->setText(tr("Rotating (P2WPKH per block)"));

        showSuccess(tr("Mining started with address rotation"));
        addLogEntry(tr("Mining started with automatic P2WPKH rotation"));
    } catch (const UniValue& objError) {
        showError(tr("Failed to start mining: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        showError(tr("Failed to start mining: %1").arg(e.what()));
    }
}

void MiningApisPage::onStopMining()
{
    if (!clientModel) {
        showError(tr("Client model not available"));
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("stopmining", params, "");

        miningActive = false;
        miningStartTime = 0;
        currentMiningAddress.clear();

        startMiningButton->setEnabled(true);
        stopMiningButton->setEnabled(false);

        miningStatusLabel->setText(tr("● Stopped"));
        miningStatusLabel->setStyleSheet("QLabel { color: #757575; font-weight: bold; }");
        miningAddressLabel->setText(tr("None"));
        miningUptimeLabel->setText(tr("0s"));

        showSuccess(tr("Mining stopped successfully"));
        addLogEntry(tr("Mining stopped"));
    } catch (const UniValue& objError) {
        showError(tr("Failed to stop mining: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        showError(tr("Failed to stop mining: %1").arg(e.what()));
    }
}

void MiningApisPage::onRefreshMetrics()
{
    updateMetrics();
}

void MiningApisPage::onRefreshMiningModel()
{
    refreshMiningRegisteredModels();
    refreshMiningActiveModel();
}

void MiningApisPage::onApplyMiningModel()
{
    if (!networkManager) return;
    if (!miningRegisteredModelCombo || miningRegisteredModelCombo->count() == 0) {
        showError(tr("No registered models available. Refresh the list from node first."));
        return;
    }
    const int selectedIndex = miningRegisteredModelCombo->currentIndex();
    if (selectedIndex < 0) {
        showError(tr("Select a registered model to apply."));
        return;
    }
    const QVariantMap modelData = miningRegisteredModelCombo->currentData(Qt::UserRole).toMap();
    const QString modelName = modelData.value("model_name").toString().trimmed();
    const QString modelCommit = modelData.value("model_commit").toString().trimmed();
    if (modelName.isEmpty() || modelCommit.isEmpty()) {
        showError(tr("Selected model entry is invalid. Refresh and retry."));
        return;
    }

    QJsonObject payload{
        {"model_name", modelName},
        {"model_commit", modelCommit},
        {"force_switch", miningForceModelSwitchCheck && miningForceModelSwitchCheck->isChecked()}
    };

    sendMiningActiveModelRequest("set_active_model", true, QJsonDocument(payload).toJson(QJsonDocument::Compact), miningApiBaseUrls(), 0);

    if (miningActiveModelStateLabel) {
        const bool forceSwitch = miningForceModelSwitchCheck && miningForceModelSwitchCheck->isChecked();
        miningActiveModelStateLabel->setText(
            forceSwitch
                ? tr("Applying runtime model selection (force): %1@%2").arg(modelName, modelCommit)
                : tr("Applying runtime model selection (graceful): %1@%2").arg(modelName, modelCommit));
        miningActiveModelStateLabel->setStyleSheet("QLabel { color: #1976D2; }");
    }
}

void MiningApisPage::onRefreshQueues()
{
    updateValidationStatus();
}

void MiningApisPage::onValidationSelected(int row, int column)
{
    // Future: Show validation details in a dialog
}

void MiningApisPage::onExportLogs()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Export Logs"), QString(),
        tr("Text Files") + QLatin1String(" (*.txt)"), nullptr);

    if (filename.isEmpty()) {
        return;
    }

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        showError(tr("Could not open file for writing"));
        return;
    }

    QTextStream out(&file);
    out << logsDisplay->toPlainText();
    file.close();

    showSuccess(tr("Logs exported successfully"));
}

void MiningApisPage::onClearLogs()
{
    logsDisplay->clear();
    addLogEntry(tr("Logs cleared"));
}

void MiningApisPage::onStatusTimerTick()
{
    // Update uptime if mining is active
    if (miningActive && miningStartTime > 0) {
        qint64 currentTime = QDateTime::currentSecsSinceEpoch();
        qint64 uptime = currentTime - miningStartTime;
        miningUptimeLabel->setText(formatUptime(uptime));
    }
}

void MiningApisPage::onMetricsTimerTick()
{
    // Only update if this widget is visible to avoid slowing down the UI
    if (!isVisible()) {
        return;
    }

    updateMetrics();
    updateValidationStatus();
    updateMinerProxyMetrics();
    refreshMiningActiveModel();
    updateReorgAdvisories();
    updatePendingReorgStatus();  // Check for pending reorg decisions
    refreshOperatorReviews();
}

// ===== UPDATE METHODS =====

void MiningApisPage::updateMiningStatus()
{
    // This will be called when the page loads or when we need to sync state
    // For now, we assume mining is stopped unless we started it via the GUI
    updateMiningConnectionStatus();
}

void MiningApisPage::updateMetrics()
{
    if (!clientModel) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("getminingmetrics", params, "");

        uint64_t received = result["solutions_received"].getInt<uint64_t>();
        uint64_t usable = result["solutions_usable"].getInt<uint64_t>();
        uint64_t invalid = result["solutions_invalid"].getInt<uint64_t>();
        uint64_t duplicates = result["solutions_duplicates"].getInt<uint64_t>();
        double usable_rate = result["usable_rate"].get_real();
        uint64_t rate_limited = result["rate_limited"].getInt<uint64_t>();
        uint64_t network_errors = result["network_errors"].getInt<uint64_t>();
        uint64_t last_solution_time = result["last_solution_time"].getInt<uint64_t>();

        solutionsReceivedLabel->setText(QString::number(received));
        solutionsUsableLabel->setText(QString::number(usable));
        solutionsInvalidLabel->setText(QString::number(invalid));
        solutionsDuplicateLabel->setText(QString::number(duplicates));

        if (received > 0) {
            usableRateLabel->setText(QString::number(usable_rate, 'f', 1) + "%");
        } else {
            usableRateLabel->setText(tr("N/A"));
        }

        rateLimitedLabel->setText(QString::number(rate_limited));
        networkErrorsLabel->setText(QString::number(network_errors));

        if (last_solution_time > 0) {
            lastSolutionLabel->setText(formatTimestamp(last_solution_time));
        } else {
            lastSolutionLabel->setText(tr("Never"));
        }

        // Only log significant events, not every update
    } catch (const UniValue& objError) {
        addLogEntry(tr("Failed to update metrics: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        addLogEntry(tr("Failed to update metrics: %1").arg(e.what()));
    }
}

void MiningApisPage::updateValidationStatus()
{
    if (!clientModel) {
        return;
    }

    updateVerificationConnectionStatus();
    updateQueueCounts();
    updateRecentValidations();
}

void MiningApisPage::updateMiningConnectionStatus()
{
    if (!clientModel) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("getminingapiinfo", params, "");

        bool available = result["available"].get_bool();
        bool healthy = result["connection_healthy"].get_bool();

        if (available && healthy) {
            miningHealthLabel->setText(tr("Connection Health: ✓ OK (last check: now)"));
            miningHealthLabel->setStyleSheet("QLabel { color: #2E7D32; font-weight: bold; }");

            miningJobPushLabel->setText(QString::fromStdString(result["job_push_endpoint"].get_str()));
            miningSolPullLabel->setText(QString::fromStdString(result["solution_pull_endpoint"].get_str()));
        } else if (available) {
            miningHealthLabel->setText(tr("Connection Health: ⚠ Degraded"));
            miningHealthLabel->setStyleSheet("QLabel { color: #F57C00; font-weight: bold; }");
        } else {
            miningHealthLabel->setText(tr("Connection Health: ✗ Unavailable"));
            miningHealthLabel->setStyleSheet("QLabel { color: #C62828; font-weight: bold; }");
        }
    } catch (...) {
        miningHealthLabel->setText(tr("Connection Health: ? Unknown"));
        miningHealthLabel->setStyleSheet("QLabel { color: #757575; font-weight: bold; }");
    }
}

void MiningApisPage::updateVerificationConnectionStatus()
{
    if (!clientModel) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("getvalidationapiinfo", params, "");

        bool available = result["available"].get_bool();
        bool healthy = result["connection_healthy"].get_bool();
        bool desktopMode = result["desktop_mode"].get_bool();
        std::string mode = result["mode"].get_str();

        if (available && healthy) {
            if (desktopMode) {
                // Desktop mode uses HTTPS for full/model validation
                verifyHealthLabel->setText(tr("API Status: ● Desktop Mode (HTTPS)"));
                verifyHealthLabel->setStyleSheet("QLabel { color: #1976D2; font-weight: bold; }");
                verifyReqPushLabel->setText(tr("Local quick validation + HTTPS gateway"));
                verifySolPullLabel->setText(tr("Full/Model validation via HTTPS"));
            } else if (mode == "mock") {
                // Mock mode for testing
                verifyHealthLabel->setText(tr("API Status: ● Mock Mode"));
                verifyHealthLabel->setStyleSheet("QLabel { color: #7B1FA2; font-weight: bold; }");
                verifyReqPushLabel->setText(tr("In-process mock validation"));
                verifySolPullLabel->setText(tr("Deterministic responses"));
            } else {
                // Real ZMQ mode
                verifyHealthLabel->setText(tr("API Status: ● Active"));
                verifyHealthLabel->setStyleSheet("QLabel { color: #2E7D32; font-weight: bold; }");
                verifyReqPushLabel->setText(QString::fromStdString(result["request_push_endpoint"].get_str()));
                verifySolPullLabel->setText(QString::fromStdString(result["result_pull_endpoint"].get_str()));
            }
        } else if (available) {
            verifyHealthLabel->setText(tr("API Status: ⚠ Degraded"));
            verifyHealthLabel->setStyleSheet("QLabel { color: #F57C00; font-weight: bold; }");
        } else {
            verifyHealthLabel->setText(tr("API Status: ✗ Unavailable"));
            verifyHealthLabel->setStyleSheet("QLabel { color: #C62828; font-weight: bold; }");
        }
    } catch (...) {
        verifyHealthLabel->setText(tr("API Status: ? Unknown"));
        verifyHealthLabel->setStyleSheet("QLabel { color: #757575; font-weight: bold; }");
    }
}

void MiningApisPage::updateQueueCounts()
{
    if (!clientModel) {
        return;
    }

    try {
        // First check the validation mode
        UniValue infoParams(UniValue::VARR);
        UniValue infoResult = clientModel->node().executeRpc("getvalidationapiinfo", infoParams, "");
        std::string mode = infoResult["mode"].get_str();

        if (mode == "mock") {
            // Mock mode processes instantly, no queues to display
            quickQueueLabel->setText(tr("Mock: instant"));
            fullQueueLabel->setText(tr("Mock: instant"));
            modelQueueLabel->setText(tr("Mock: instant"));
            challengeQueueLabel->setText(tr("Mock: instant"));
            quickQueueLabel->setStyleSheet("QLabel { color: #7B1FA2; }");
            fullQueueLabel->setStyleSheet("QLabel { color: #7B1FA2; }");
            modelQueueLabel->setStyleSheet("QLabel { color: #7B1FA2; }");
            challengeQueueLabel->setStyleSheet("QLabel { color: #7B1FA2; }");
            return;
        }

        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("getvalidationqueues", params, "");

        uint64_t quick_pending = result["quick_pending"].getInt<uint64_t>();
        uint64_t quick_smell_pending = result["quick_smell_pending"].getInt<uint64_t>();
        uint64_t full_pending = result["full_pending"].getInt<uint64_t>();
        uint64_t model_pending = result["model_pending"].getInt<uint64_t>();
        uint64_t challenge_pending = result["challenge_pending"].getInt<uint64_t>();

        // Combine quick and quick_smell for display
        uint64_t total_quick = quick_pending + quick_smell_pending;

        quickQueueLabel->setText(tr("%1 pending").arg(total_quick));
        fullQueueLabel->setText(tr("%1 pending").arg(full_pending));
        modelQueueLabel->setText(tr("%1 pending").arg(model_pending));
        challengeQueueLabel->setText(tr("%1 pending").arg(challenge_pending));

        // Reset style
        quickQueueLabel->setStyleSheet("");
        fullQueueLabel->setStyleSheet("");
        modelQueueLabel->setStyleSheet("");
        challengeQueueLabel->setStyleSheet("");
    } catch (...) {
        quickQueueLabel->setText(tr("? pending"));
        fullQueueLabel->setText(tr("? pending"));
        modelQueueLabel->setText(tr("? pending"));
        challengeQueueLabel->setText(tr("? pending"));
    }
}

void MiningApisPage::updateRecentValidations()
{
    if (!clientModel || !recentValidationsTable) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(10);  // Get last 10 validations
        UniValue result = clientModel->node().executeRpc("getrecentvalidations", params, "");

        // Clear existing rows
        recentValidationsTable->setRowCount(0);

        if (!result.isArray()) {
            return;
        }

        for (size_t i = 0; i < result.size(); ++i) {
            const UniValue& entry = result[i];
            if (!entry.isObject()) continue;

            int row = recentValidationsTable->rowCount();
            recentValidationsTable->insertRow(row);

            // Type column
            QString type = QString::fromStdString(entry["type"].get_str());
            QTableWidgetItem* typeItem = new QTableWidgetItem(type.toUpper());
            if (type == "quick") {
                typeItem->setForeground(QBrush(QColor("#1976D2")));
            } else {
                typeItem->setForeground(QBrush(QColor("#7B1FA2")));
            }
            recentValidationsTable->setItem(row, 0, typeItem);

            // Block hash column (truncated)
            QString hash = QString::fromStdString(entry["block_hash"].get_str());
            QString truncatedHash = hash.left(8) + "..." + hash.right(8);
            recentValidationsTable->setItem(row, 1, new QTableWidgetItem(truncatedHash));

            // Status column
            QString status;
            QColor statusColor;
            if (type == "quick") {
                QString quick = QString::fromStdString(entry["quick_status"].get_str());
                QString smell = QString::fromStdString(entry["smell_status"].get_str());
                if (quick == "ok" && smell == "ok") {
                    status = tr("OK");
                    statusColor = QColor("#2E7D32");
                } else if (quick == "ok") {
                    status = tr("Quick OK");
                    statusColor = QColor("#1976D2");
                } else {
                    status = tr("FAIL");
                    statusColor = QColor("#C62828");
                }
            } else {
                QString full = QString::fromStdString(entry["full_status"].get_str());
                if (full == "green") {
                    status = tr("GREEN");
                    statusColor = QColor("#2E7D32");
                } else if (full == "amber") {
                    status = tr("AMBER");
                    statusColor = QColor("#F57C00");
                } else if (full == "red") {
                    status = tr("RED");
                    statusColor = QColor("#C62828");
                } else {
                    status = tr("PENDING");
                    statusColor = QColor("#757575");
                }
            }
            QTableWidgetItem* statusItem = new QTableWidgetItem(status);
            statusItem->setForeground(QBrush(statusColor));
            recentValidationsTable->setItem(row, 2, statusItem);

            // Timestamp column
            int64_t ts = entry["timestamp"].getInt<int64_t>();
            QString timeStr = formatTimestamp(ts);
            recentValidationsTable->setItem(row, 3, new QTableWidgetItem(timeStr));
        }
        // Note: Column sizing handled by QHeaderView::Stretch mode
    } catch (...) {
        // Silently fail - table remains as-is
    }
}

// ===== HELPER METHODS =====

void MiningApisPage::addLogEntry(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString logEntry = QString("[%1] %2").arg(timestamp, message);
    logsDisplay->append(logEntry);

    // Keep only last 100 lines
    QString text = logsDisplay->toPlainText();
    QStringList lines = text.split('\n');
    if (lines.size() > 100) {
        lines = lines.mid(lines.size() - 100);
        logsDisplay->setPlainText(lines.join('\n'));
    }
}

QString MiningApisPage::formatUptime(qint64 seconds) const
{
    qint64 hours = seconds / 3600;
    qint64 minutes = (seconds % 3600) / 60;
    qint64 secs = seconds % 60;

    if (hours > 0) {
        return tr("%1h %2m %3s").arg(hours).arg(minutes).arg(secs);
    } else if (minutes > 0) {
        return tr("%1m %2s").arg(minutes).arg(secs);
    } else {
        return tr("%1s").arg(secs);
    }
}

QString MiningApisPage::formatTimestamp(qint64 timestamp) const
{
    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp);
    qint64 now = QDateTime::currentSecsSinceEpoch();
    qint64 diff = now - timestamp;

    if (diff < 60) {
        return tr("%1s ago").arg(diff);
    } else if (diff < 3600) {
        return tr("%1m ago").arg(diff / 60);
    } else if (diff < 86400) {
        return tr("%1h ago").arg(diff / 3600);
    } else {
        return dt.toString("MMM dd HH:mm");
    }
}

void MiningApisPage::showError(const QString& message)
{
    addLogEntry(tr("ERROR: %1").arg(message));
    Q_EMIT this->message(tr("Error"), message, CClientUIInterface::MSG_ERROR);
}

void MiningApisPage::showSuccess(const QString& message)
{
    addLogEntry(tr("SUCCESS: %1").arg(message));
    Q_EMIT this->message(tr("Success"), message, CClientUIInterface::MSG_INFORMATION);
}

QString MiningApisPage::formatTokenCount(uint64_t tokens) const
{
    if (tokens >= 1000000000) {
        return QString::number(tokens / 1000000000.0, 'f', 2) + "B";
    } else if (tokens >= 1000000) {
        return QString::number(tokens / 1000000.0, 'f', 2) + "M";
    } else if (tokens >= 1000) {
        return QString::number(tokens / 1000.0, 'f', 1) + "K";
    }
    return QString::number(tokens);
}

void MiningApisPage::updateMinerProxyMetrics()
{
    // Fetch from miner proxy /status endpoint
    // MINER_HOST is the docker service name (default: miner-proxy)
    // HTTP_PORT is the miner proxy HTTP port (default: 8030 in docker-compose)
    QString minerProxyHost = QString::fromStdString(getenv("MINER_HOST") ? getenv("MINER_HOST") : "miner-proxy");
    QString minerProxyPort = QString::fromStdString(getenv("HTTP_PORT") ? getenv("HTTP_PORT") : "8030");
    QUrl url(QString("http://%1:%2/status").arg(minerProxyHost, minerProxyPort));

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("X-Mining-Page-Action", "status_metrics");
    networkManager->get(request);
}

void MiningApisPage::refreshMiningActiveModel()
{
    if (!networkManager) return;
    sendMiningActiveModelRequest("get_active_model", false, QByteArray{}, miningApiBaseUrls(), 0);
}

QStringList MiningApisPage::miningApiBaseUrls() const
{
    const QString envHost = QString::fromStdString(getenv("MINER_HOST") ? getenv("MINER_HOST") : "miner-proxy").trimmed();
    const QString envPort = QString::fromStdString(getenv("HTTP_PORT") ? getenv("HTTP_PORT") : "").trimmed();
    const QString envMinerApiPort = QString::fromStdString(getenv("MINER_API_HTTP_PORT") ? getenv("MINER_API_HTTP_PORT") : "").trimmed();
    const QString hostPort = QString::fromStdString(getenv("MINER_PROXY_HOST_PORT") ? getenv("MINER_PROXY_HOST_PORT") : "").trimmed();

    QStringList targets;
    QStringList candidatePorts;
    if (!envPort.isEmpty()) candidatePorts.push_back(envPort);
    if (!envMinerApiPort.isEmpty()) candidatePorts.push_back(envMinerApiPort);
    // Default ports used by compose variants:
    // - vLLM stack: 8030
    // - llama.cpp stack: 8080
    candidatePorts.push_back(QStringLiteral("8030"));
    candidatePorts.push_back(QStringLiteral("8080"));
    candidatePorts.removeDuplicates();

    for (const QString& port : candidatePorts) {
        if (!envHost.isEmpty() && !port.isEmpty()) {
            targets.push_back(QString("http://%1:%2").arg(envHost, port));
        }
    }

    if (!hostPort.isEmpty()) {
        targets.push_back(QString("http://127.0.0.1:%1").arg(hostPort));
        targets.push_back(QString("http://localhost:%1").arg(hostPort));
    } else {
        for (const QString& port : candidatePorts) {
            if (!port.isEmpty()) {
                targets.push_back(QString("http://127.0.0.1:%1").arg(port));
                targets.push_back(QString("http://localhost:%1").arg(port));
            }
        }
    }

    targets.removeDuplicates();
    return targets;
}

void MiningApisPage::sendMiningActiveModelRequest(const QString& action, bool isPost, const QByteArray& payload, const QStringList& targets, int targetIndex)
{
    if (!networkManager || targets.isEmpty() || targetIndex < 0 || targetIndex >= targets.size()) {
        miningModelApiReachable = false;
        if (miningCurrentModelLabel) {
            miningCurrentModelLabel->setText(tr("Current model: unavailable"));
        }
        if (miningActiveModelStateLabel) {
            miningActiveModelStateLabel->setText(tr("Runtime model endpoint is unavailable"));
            miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
        }
        updateMiningModelControlsState();
        return;
    }

    const QUrl url(QString("%1/v1/mining/active-model").arg(targets.at(targetIndex)));
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("X-Mining-Page-Action", action.toUtf8());
    request.setRawHeader("X-Mining-Page-Target-Index", QByteArray::number(targetIndex));
    request.setRawHeader("X-Mining-Page-Target-Count", QByteArray::number(targets.size()));
    request.setAttribute(ATTR_MINING_TARGETS, targets);
    request.setAttribute(ATTR_MINING_PAYLOAD, payload);

    if (isPost) {
        networkManager->post(request, payload);
    } else {
        networkManager->get(request);
    }
}

void MiningApisPage::refreshMiningRegisteredModels()
{
    if (!clientModel || !miningRegisteredModelCombo) return;

    QString prevName;
    QString prevCommit;
    const QVariantMap prevData = miningRegisteredModelCombo->currentData(Qt::UserRole).toMap();
    prevName = prevData.value("model_name").toString();
    prevCommit = prevData.value("model_commit").toString();

    miningRegisteredModelCombo->clear();

    try {
        UniValue params(UniValue::VARR);
        params.push_back(true); // short_view
        UniValue models = clientModel->node().executeRpc("getmodelslist", params, "");
        if (!models.isArray()) {
            miningActiveModelStateLabel->setText(tr("Failed to load registered models: invalid RPC response"));
            miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
            updateMiningModelControlsState();
            return;
        }

        int selectedIndex = -1;
        int row = 0;
        for (size_t i = 0; i < models.size(); ++i) {
            const UniValue& model = models[i];
            if (!model.isObject() || !model.exists("status") ||
                !model.exists("model_name") || !model.exists("model_commit")) {
                continue;
            }

            int status = -1;
            try {
                status = model["status"].getInt<int>();
            } catch (...) {
                continue;
            }
            if (status != MODEL_STATUS_REGISTERED) {
                continue;
            }

            const QString modelName = QString::fromStdString(model["model_name"].get_str());
            const QString modelCommit = QString::fromStdString(model["model_commit"].get_str());
            const QString modelHash = model.exists("model_hash")
                ? QString::fromStdString(model["model_hash"].get_str())
                : QString();

            const QString label = modelHash.isEmpty()
                ? QString("%1@%2").arg(modelName, modelCommit)
                : QString("%1@%2 [%3]").arg(modelName, modelCommit, modelHash.left(12) + "...");
            QVariantMap modelData;
            modelData.insert("model_name", modelName);
            modelData.insert("model_commit", modelCommit);
            modelData.insert("model_hash", modelHash);
            miningRegisteredModelCombo->addItem(label, modelData);

            if (!prevName.isEmpty() && !prevCommit.isEmpty() &&
                modelName == prevName && modelCommit == prevCommit) {
                selectedIndex = row;
            }
            ++row;
        }

        if (selectedIndex >= 0) {
            miningRegisteredModelCombo->setCurrentIndex(selectedIndex);
        } else if (miningRegisteredModelCombo->count() > 0) {
            miningRegisteredModelCombo->setCurrentIndex(0);
        }

        if (miningRegisteredModelCombo->count() == 0) {
            miningActiveModelStateLabel->setText(tr("No registered models found on node."));
            miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
        }
        updateMiningModelControlsState();
    } catch (const UniValue& objError) {
        miningActiveModelStateLabel->setText(
            tr("Failed to load registered models: %1")
                .arg(QString::fromStdString(objError["message"].get_str())));
        miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
        updateMiningModelControlsState();
    } catch (const std::exception& e) {
        miningActiveModelStateLabel->setText(
            tr("Failed to load registered models: %1").arg(e.what()));
        miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
        updateMiningModelControlsState();
    }
}

void MiningApisPage::updateMiningModelControlsState()
{
    const bool hasSelection = miningRegisteredModelCombo && miningRegisteredModelCombo->count() > 0 &&
                              miningRegisteredModelCombo->currentIndex() >= 0;
    bool selectedDiffers = false;

    if (hasSelection) {
        const QVariantMap selected = miningRegisteredModelCombo->currentData(Qt::UserRole).toMap();
        const QString selectedName = selected.value("model_name").toString();
        const QString selectedCommit = selected.value("model_commit").toString();
        if (miningRuntimeAutoSelect) {
            selectedDiffers = true;
        } else {
            selectedDiffers = (selectedName != miningRuntimeModelName || selectedCommit != miningRuntimeModelCommit);
        }
    }

    if (applyMiningModelButton) {
        // Allow apply even when runtime endpoint is currently unreachable:
        // user should still be able to attempt switch after selecting a model.
        applyMiningModelButton->setEnabled(hasSelection && selectedDiffers);
    }
}

void MiningApisPage::onMinerProxyReply(QNetworkReply* reply)
{
    const QString action = QString::fromUtf8(reply->request().rawHeader("X-Mining-Page-Action"));
    const QByteArray data = reply->readAll();
    const bool ok = (reply->error() == QNetworkReply::NoError);
    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString errString = reply->errorString();
    reply->deleteLater();

    if (action == "get_active_model" || action == "set_active_model") {
        const QStringList targets = reply->request().attribute(ATTR_MINING_TARGETS).toStringList();
        const QByteArray payload = reply->request().attribute(ATTR_MINING_PAYLOAD).toByteArray();
        const int targetIndex = HeaderInt(reply->request().rawHeader("X-Mining-Page-Target-Index"), 0);
        const int targetCount = HeaderInt(reply->request().rawHeader("X-Mining-Page-Target-Count"), targets.size());
        if (!ok || (httpStatus >= 400 && httpStatus < 600)) {
            // Endpoint failover policy:
            // - get_active_model: try all candidates (probing).
            // - set_active_model: retry only on transport errors (HTTP 0).
            //   If server responded with HTTP 4xx/5xx, endpoint is reachable;
            //   surface the actual API error instead of masking it as "unreachable".
            const bool transportError = (httpStatus == 0);
            const bool canTryNext = (targetIndex + 1 < targetCount);
            const bool shouldFailover =
                canTryNext &&
                (action == QLatin1String("get_active_model") ||
                 (action == QLatin1String("set_active_model") && transportError));
            if (shouldFailover) {
                sendMiningActiveModelRequest(action, action == "set_active_model", payload, targets, targetIndex + 1);
                return;
            }

            miningModelApiReachable = false;
            const QString body = QString::fromUtf8(data).trimmed();
            const QString endpoint = targetIndex >= 0 && targetIndex < targets.size() ? targets[targetIndex] : QStringLiteral("n/a");
            if (miningCurrentModelLabel) {
                miningCurrentModelLabel->setText(tr("Current model: unavailable"));
            }
            if (miningActiveModelStateLabel) {
                if (httpStatus == 0) {
                    miningActiveModelStateLabel->setText(
                        tr("Runtime model API is unreachable (%1). Last endpoint: %2")
                            .arg(action)
                            .arg(endpoint));
                } else {
                    miningActiveModelStateLabel->setText(
                        tr("Runtime model request failed (%1) at %2: HTTP %3, %4")
                            .arg(action)
                            .arg(endpoint)
                            .arg(httpStatus)
                            .arg(errString));
                }
                miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
            }
            if (!body.isEmpty()) {
                addLogEntry(tr("Mining model API error: %1").arg(body.left(240)));
            }
            updateMiningModelControlsState();
            return;
        }

        miningModelApiReachable = true;
        QJsonParseError parseError{};
        const QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            if (miningActiveModelStateLabel) {
                miningActiveModelStateLabel->setText(tr("Runtime model response is not valid JSON"));
                miningActiveModelStateLabel->setStyleSheet("QLabel { color: #C62828; }");
            }
            updateMiningModelControlsState();
            return;
        }

        QJsonObject root = doc.object();
        if (root.contains("active_model") && root.value("active_model").isObject()) {
            root = root.value("active_model").toObject();
        }
        const QString modelName = root.value("model_name").toString();
        const QString modelCommit = root.value("model_commit").toString();
        const bool pinned = root.value("pinned").toBool(false);
        const bool autoSelect = root.value("auto_select").toBool(!pinned);
        const bool switchInProgress = root.value("switch_in_progress").toBool(false);
        const QJsonObject pendingSwitch = root.value("pending_switch").toObject();
        const QString source = root.value("source").toString().trimmed().toLower();
        const QString sourceLabel =
            (source == QLatin1String("persisted")) ? tr("persisted") :
            (source == QLatin1String("runtime")) ? tr("runtime") :
            tr("env");
        miningRuntimeAutoSelect = autoSelect;
        miningRuntimeModelName = modelName;
        miningRuntimeModelCommit = modelCommit;

        bool modelFoundInCombo = false;
        if (miningRegisteredModelCombo) {
            for (int i = 0; i < miningRegisteredModelCombo->count(); ++i) {
                const QVariantMap modelData = miningRegisteredModelCombo->itemData(i, Qt::UserRole).toMap();
                if (modelData.value("model_name").toString() == modelName &&
                    modelData.value("model_commit").toString() == modelCommit) {
                    miningRegisteredModelCombo->setCurrentIndex(i);
                    modelFoundInCombo = true;
                    break;
                }
            }
        }
        if (miningActiveModelStateLabel) {
            if (switchInProgress) {
                miningActiveModelStateLabel->setText(tr("Runtime model switch in progress..."));
                miningActiveModelStateLabel->setStyleSheet("QLabel { color: #1976D2; }");
            } else if (!pendingSwitch.isEmpty()) {
                const QString pendingName = pendingSwitch.value("model_name").toString();
                const QString pendingCommit = pendingSwitch.value("model_commit").toString();
                const QString pendingMode = pendingSwitch.value("mode").toString();
                miningActiveModelStateLabel->setText(
                    tr("Runtime switch scheduled (%1): %2@%3")
                        .arg(pendingMode.isEmpty() ? tr("graceful") : pendingMode, pendingName, pendingCommit));
                miningActiveModelStateLabel->setStyleSheet("QLabel { color: #1976D2; }");
            } else
            if (autoSelect) {
                miningActiveModelStateLabel->setText(
                    tr("Runtime model: auto-select (%1)").arg(sourceLabel));
                miningActiveModelStateLabel->setStyleSheet("QLabel { color: #1976D2; }");
                if (miningCurrentModelLabel) {
                    miningCurrentModelLabel->setText(tr("Current model: auto-select"));
                }
            } else {
                if (modelFoundInCombo) {
                    miningActiveModelStateLabel->setText(
                        tr("Runtime model pinned (%1): %2@%3")
                            .arg(sourceLabel, modelName, modelCommit));
                } else {
                    miningActiveModelStateLabel->setText(
                        tr("Runtime model pinned (%1, not in registered list): %2@%3")
                            .arg(sourceLabel, modelName, modelCommit));
                }
                miningActiveModelStateLabel->setStyleSheet("QLabel { color: #2E7D32; }");
                if (miningCurrentModelLabel) {
                    miningCurrentModelLabel->setText(tr("Current model: %1@%2").arg(modelName, modelCommit));
                }
            }
        }
        updateMiningModelControlsState();
        return;
    }

    if (!ok) {
        // Miner proxy not available - show placeholder
        hashRateLabel->setText(tr("N/A"));
        hashRateLabel->setStyleSheet("QLabel { font-weight: bold; color: #757575; font-size: 14px; }");
        tokensPerSecLabel->setText(tr("N/A"));
        totalHashesLabel->setText(tr("N/A"));
        activeRequestsLabel->setText(tr("N/A"));
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        return;
    }

    QJsonObject root = doc.object();
    QJsonObject proxy = root["proxy"].toObject();
    QJsonObject throughput = proxy["throughput"].toObject();
    QJsonObject totals = proxy["totals"].toObject();

    // Update throughput labels
    double hashesPerSec = throughput["hashes_per_sec"].toDouble();
    double tokensPerSec = throughput["total_tokens_per_sec"].toDouble();
    uint64_t totalHashes = static_cast<uint64_t>(totals["hashes"].toDouble());
    int activeRequests = proxy["active_requests"].toInt();

    // Format hashrate with appropriate units
    QString hashRateStr;
    if (hashesPerSec >= 1.0) {
        hashRateStr = QString::number(hashesPerSec, 'f', 2) + " H/s";
    } else if (hashesPerSec > 0) {
        hashRateStr = QString::number(hashesPerSec * 1000, 'f', 2) + " mH/s";
    } else {
        hashRateStr = "0 H/s";
    }

    hashRateLabel->setText(hashRateStr);
    tokensPerSecLabel->setText(QString::number(tokensPerSec, 'f', 1));
    totalHashesLabel->setText(formatTokenCount(totalHashes));  // Reuse formatTokenCount for large numbers
    activeRequestsLabel->setText(QString::number(activeRequests));

    // Color the hashrate based on activity
    if (hashesPerSec >= 1.0) {
        hashRateLabel->setStyleSheet("QLabel { font-weight: bold; color: #2E7D32; font-size: 14px; }");  // Green - good hashrate
    } else if (hashesPerSec > 0) {
        hashRateLabel->setStyleSheet("QLabel { font-weight: bold; color: #1976D2; font-size: 14px; }");  // Blue - some activity
    } else {
        hashRateLabel->setStyleSheet("QLabel { font-weight: bold; color: #757575; font-size: 14px; }");  // Gray - idle
    }

    // Color tokens/sec based on activity
    if (tokensPerSec > 100) {
        tokensPerSecLabel->setStyleSheet("QLabel { font-weight: bold; color: #2E7D32; }");  // Green - high throughput
    } else if (tokensPerSec > 0) {
        tokensPerSecLabel->setStyleSheet("QLabel { font-weight: bold; color: #1976D2; }");  // Blue - normal
    } else {
        tokensPerSecLabel->setStyleSheet("QLabel { font-weight: bold; color: #757575; }");  // Gray - idle
    }
}

QString MiningApisPage::operatorApiBaseUrl() const
{
    const char* env_url = std::getenv("OPERATOR_API_BASE_URL");
    if (env_url && env_url[0] != '\0') return QString::fromUtf8(env_url).trimmed();
    return QStringLiteral("http://verification-api:9090");
}

QString MiningApisPage::operatorApiKey() const
{
    const char* op_key = std::getenv("OPERATOR_API_KEY");
    if (op_key && op_key[0] != '\0') return QString::fromUtf8(op_key);
    const char* validator_key = std::getenv("VALIDATOR_API_KEY");
    if (validator_key && validator_key[0] != '\0') return QString::fromUtf8(validator_key);
    const char* api_key = std::getenv("API_KEY");
    if (api_key && api_key[0] != '\0') return QString::fromUtf8(api_key);
    return QString();
}

void MiningApisPage::setOperatorButtonsEnabled(bool enabled)
{
    if (!operatorApproveButton || !operatorRejectButton || !operatorOpenDiscussionButton) {
        return;
    }
    operatorApproveButton->setEnabled(enabled);
    operatorRejectButton->setEnabled(enabled);
    operatorOpenDiscussionButton->setEnabled(enabled);
}

QString MiningApisPage::reviewAuditToText(const QJsonObject& reviewObj) const
{
    const QJsonValue auditValue = reviewObj.value("audit_report");
    if (auditValue.isUndefined() || auditValue.isNull()) {
        return tr("No audit_report payload found.");
    }

    // Preferred path: already structured JSON object/array.
    if (auditValue.isObject()) {
        return QString::fromUtf8(QJsonDocument(auditValue.toObject()).toJson(QJsonDocument::Indented));
    }
    if (auditValue.isArray()) {
        return QString::fromUtf8(QJsonDocument(auditValue.toArray()).toJson(QJsonDocument::Indented));
    }

    // Fallback path: audit_report came as a string. Try to parse it as JSON.
    if (auditValue.isString()) {
        const QString raw = auditValue.toString();
        const QByteArray utf8 = raw.toUtf8();
        QJsonParseError parseError{};
        const QJsonDocument parsed = QJsonDocument::fromJson(utf8, &parseError);
        if (parseError.error == QJsonParseError::NoError && !parsed.isNull()) {
            return QString::fromUtf8(parsed.toJson(QJsonDocument::Indented));
        }
        // Not valid JSON: show as-is for operator readability/debugging.
        return raw;
    }

    // Last resort: scalar types (number/bool/etc).
    return QString::fromUtf8(QJsonDocument(reviewObj).toJson(QJsonDocument::Indented));
}

void MiningApisPage::refreshOperatorReviews()
{
    if (!m_operatorReviewEnabled) return;
    if (!operatorNetworkManager || !operatorApiBaseUrlEdit || !operatorApiKeyEdit) return;
    const QString base = operatorApiBaseUrlEdit->text().trimmed();
    if (base.isEmpty()) {
        operatorReviewStatusLabel->setText(tr("Operator API base URL is empty"));
        return;
    }
    if (operatorApiKeyEdit->text().trimmed().isEmpty()) {
        operatorReviewStatusLabel->setText(tr("Operator API key is empty"));
        return;
    }

    QUrl url(base + "/v1/operator/reviews");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QString("Bearer %1").arg(operatorApiKeyEdit->text().trimmed()).toUtf8());
    request.setRawHeader("X-Mining-Page-Action", "fetch_reviews");
    operatorReviewStatusLabel->setText(tr("Refreshing from %1 ...").arg(url.toString()));
    operatorNetworkManager->get(request);
}

void MiningApisPage::onRefreshOperatorReviews()
{
    refreshOperatorReviews();
}

void MiningApisPage::onOperatorReviewSelected(int row, int column)
{
    Q_UNUSED(column);
    if (row < 0 || !operatorReviewsTable) return;
    QTableWidgetItem* typeItem = operatorReviewsTable->item(row, 0);
    QTableWidgetItem* hashItem = operatorReviewsTable->item(row, 1);
    QTableWidgetItem* modelItem = operatorReviewsTable->item(row, 2);
    if (!hashItem || !modelItem) return;

    m_selectedModelHash = hashItem->data(Qt::UserRole).toString();
    m_selectedReviewType = typeItem ? typeItem->data(Qt::UserRole).toString().trimmed().toLower() : QStringLiteral("model");
    const QString tableModelName = modelItem->text().trimmed();
    m_selectedModelIdentifier = tableModelName;

    operatorReviewDetails->setPlainText(tr("Loading audit report..."));
    const QString selectedTypeLabel = (m_selectedReviewType == QLatin1String("challenge"))
        ? tr("challenge")
        : tr("model");
    operatorReviewStatusLabel->setText(
        tr("Selected %1 review for %2 (%3)")
            .arg(selectedTypeLabel,
                 m_selectedModelIdentifier.isEmpty() ? tr("unknown") : m_selectedModelIdentifier,
                 m_selectedModelHash.left(16) + "...")
    );
    setOperatorButtonsEnabled(!m_selectedModelHash.isEmpty());

    QUrl url(operatorApiBaseUrlEdit->text().trimmed() + "/v1/operator/reviews/" + m_selectedModelHash);
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QString("Bearer %1").arg(operatorApiKeyEdit->text().trimmed()).toUtf8());
    request.setRawHeader("X-Mining-Page-Action", "fetch_review_detail");
    request.setRawHeader("X-Review-Model-Hash", m_selectedModelHash.toUtf8());
    operatorNetworkManager->get(request);
}

void MiningApisPage::onOperatorApprove()
{
    if (m_selectedModelHash.isEmpty()) {
        showError(tr("Select a pending request first"));
        return;
    }
    QUrl url(operatorApiBaseUrlEdit->text().trimmed() + "/v1/operator/reviews/" + m_selectedModelHash + "/approve");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QString("Bearer %1").arg(operatorApiKeyEdit->text().trimmed()).toUtf8());
    request.setRawHeader("X-Mining-Page-Action", "approve_review");
    operatorNetworkManager->post(request, QByteArray("{}"));
}

void MiningApisPage::onOperatorReject()
{
    if (m_selectedModelHash.isEmpty()) {
        showError(tr("Select a pending request first"));
        return;
    }
    QUrl url(operatorApiBaseUrlEdit->text().trimmed() + "/v1/operator/reviews/" + m_selectedModelHash + "/reject");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QString("Bearer %1").arg(operatorApiKeyEdit->text().trimmed()).toUtf8());
    request.setRawHeader("X-Mining-Page-Action", "reject_review");
    operatorNetworkManager->post(request, QByteArray("{}"));
}

void MiningApisPage::onOperatorOpenDiscussion()
{
    if (m_selectedModelHash.isEmpty()) {
        showError(tr("Select a pending request first"));
        return;
    }
    const QString scopeType = (m_selectedReviewType == QLatin1String("challenge"))
        ? QStringLiteral("model_challenge")
        : QStringLiteral("model_prealert");
    Q_EMIT openDiscussionRequested(scopeType, m_selectedModelHash, m_selectedModelIdentifier);
}

void MiningApisPage::onOperatorAutoRefreshTick()
{
    if (!m_operatorReviewEnabled || !clientModel) return;
    refreshOperatorReviews();
}

void MiningApisPage::onOperatorReply(QNetworkReply* reply)
{
    const QString action = QString::fromUtf8(reply->request().rawHeader("X-Mining-Page-Action"));
    const QString requestedModelHash = QString::fromUtf8(reply->request().rawHeader("X-Review-Model-Hash"));
    const QByteArray data = reply->readAll();
    const bool ok = (reply->error() == QNetworkReply::NoError);
    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString errString = reply->errorString();
    reply->deleteLater();

    if (!ok || (httpStatus >= 400 && httpStatus < 600)) {
        const QString body = QString::fromUtf8(data.left(300)).trimmed();
        addLogEntry(tr("Operator API request failed (%1): %2")
                        .arg(action, errString));
        operatorReviewStatusLabel->setText(
            tr("Operator API failed (%1): HTTP %2, %3")
                .arg(action)
                .arg(httpStatus)
                .arg(errString)
        );
        if (!body.isEmpty()) {
            operatorReviewDetails->setPlainText(body);
        }
        return;
    }

    QJsonParseError parseError{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        addLogEntry(tr("Operator API invalid JSON response (%1)").arg(action));
        operatorReviewStatusLabel->setText(tr("Operator API invalid JSON (%1)").arg(action));
        operatorReviewDetails->setPlainText(QString::fromUtf8(data));
        return;
    }
    const QJsonObject root = doc.object();

    if (action == "fetch_reviews") {
        const QJsonArray reviews = root.value("reviews").toArray();
        QSet<QString> currentReviewHashes;
        QStringList newReviewLabels;
        operatorReviewsTable->setRowCount(0);
        m_selectedModelHash.clear();
        m_selectedModelIdentifier.clear();
        m_selectedReviewType.clear();
        setOperatorButtonsEnabled(false);

        for (const QJsonValue& value : reviews) {
            if (!value.isObject()) continue;
            const QJsonObject review = value.toObject();
            const QString reviewType = review.value("review_type").toString().trimmed().toLower();
            const bool isChallengeReview = (reviewType == QLatin1String("challenge"));
            const QString modelHash = review.value("model_hash").toString();
            const QString modelName = review.value("model_name").toString();
            const QString difficulty = QString::number(static_cast<qlonglong>(review.value("claimed_difficulty").toDouble()));
            const QString status = review.value("status").toString();
            const qint64 submittedAt = static_cast<qint64>(review.value("submitted_at").toDouble());
            currentReviewHashes.insert(modelHash);
            if (m_pendingReviewsInitialized && !m_knownPendingReviewHashes.contains(modelHash)) {
                const QString label = modelName.isEmpty()
                    ? modelHash.left(16) + "..."
                    : QString("%1 (%2...)").arg(modelName, modelHash.left(12));
                newReviewLabels.push_back(label);
            }

            const int row = operatorReviewsTable->rowCount();
            operatorReviewsTable->insertRow(row);
            auto* typeItem = new QTableWidgetItem(isChallengeReview ? tr("Challenge") : tr("Model"));
            typeItem->setData(Qt::UserRole, isChallengeReview ? QStringLiteral("challenge") : QStringLiteral("model"));
            operatorReviewsTable->setItem(row, 0, typeItem);

            auto* hashItem = new QTableWidgetItem(modelHash.left(16) + "...");
            hashItem->setData(Qt::UserRole, modelHash);
            operatorReviewsTable->setItem(row, 1, hashItem);
            operatorReviewsTable->setItem(row, 2, new QTableWidgetItem(modelName));
            operatorReviewsTable->setItem(row, 3, new QTableWidgetItem(difficulty));
            operatorReviewsTable->setItem(row, 4, new QTableWidgetItem(status));
            operatorReviewsTable->setItem(row, 5, new QTableWidgetItem(formatTimestamp(submittedAt)));
        }

        if (m_pendingReviewsInitialized && !newReviewLabels.isEmpty()) {
            const int totalNew = newReviewLabels.size();
            QString body;
            const int previewCount = std::min(totalNew, 3);
            for (int i = 0; i < previewCount; ++i) {
                if (!body.isEmpty()) body += "\n";
                body += "- " + newReviewLabels[i];
            }
            if (totalNew > previewCount) {
                body += tr("\n...and %1 more").arg(totalNew - previewCount);
            }
            Q_EMIT this->message(tr("New operator reviews"), body, CClientUIInterface::MSG_INFORMATION);
        }
        m_knownPendingReviewHashes = currentReviewHashes;
        m_pendingReviewsInitialized = true;

        operatorReviewStatusLabel->setText(tr("Loaded %1 pending operator requests").arg(operatorReviewsTable->rowCount()));
        if (operatorReviewsTable->rowCount() > 0) {
            operatorReviewsTable->selectRow(0);
            onOperatorReviewSelected(0, 0);
        } else {
            operatorReviewDetails->clear();
        }
        return;
    }

    if (action == "fetch_review_detail") {
        const QString responseHash = root.value("model_hash").toString();
        if (!responseHash.isEmpty() && !requestedModelHash.isEmpty() && responseHash != requestedModelHash) {
            operatorReviewStatusLabel->setText(tr("Audit report mismatch for selected review"));
            operatorReviewDetails->setPlainText(QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented)));
            return;
        }
        QString modelName = root.value("model_name").toString().trimmed();
        QString modelCommit = root.value("model_commit").toString().trimmed();
        m_selectedReviewType = root.value("review_type").toString().trimmed().toLower();
        const QJsonObject audit = root.value("audit_report").toObject();
        if (modelName.isEmpty() && audit.contains("model_name")) {
            modelName = audit.value("model_name").toString().trimmed();
        }
        if (modelCommit.isEmpty() && audit.contains("model_commit")) {
            modelCommit = audit.value("model_commit").toString().trimmed();
        }
        if (!modelName.isEmpty() && !modelCommit.isEmpty()) {
            m_selectedModelIdentifier = modelName + "@" + modelCommit;
        } else {
            m_selectedModelIdentifier.clear();
        }
        operatorReviewDetails->setPlainText(reviewAuditToText(root));
        return;
    }

    if (action == "approve_review" || action == "reject_review") {
        const QString status = root.value("status").toString();
        if (!status.isEmpty()) {
            showSuccess(tr("Operator decision submitted: %1").arg(status));
        }
        refreshOperatorReviews();
    }
}
// ===== REORG ADVISORY TAB =====

void MiningApisPage::setupReorgAdvisoryTab()
{
    reorgAdvisoryTab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(reorgAdvisoryTab);

    // ===== PENDING REORG DECISION (GATING) =====
    // This section is only visible when a deep reorg is awaiting operator decision
    pendingReorgGroup = new QGroupBox(tr("⚠️ PENDING REORG DECISION REQUIRED"));
    pendingReorgGroup->setStyleSheet(
        "QGroupBox { "
        "  background-color: #fff3e0; "
        "  border: 2px solid #ff9800; "
        "  border-radius: 6px; "
        "  margin-top: 10px; "
        "  font-weight: bold; "
        "  font-size: 14px; "
        "} "
        "QGroupBox::title { "
        "  color: #e65100; "
        "  subcontrol-origin: margin; "
        "  padding: 5px 10px; "
        "}"
    );
    QVBoxLayout* pendingLayout = new QVBoxLayout(pendingReorgGroup);

    pendingReorgStatusLabel = new QLabel(tr("A deep chain reorganization has been detected. The node is paused awaiting your decision."));
    pendingReorgStatusLabel->setStyleSheet("QLabel { font-weight: bold; color: #e65100; }");
    pendingReorgStatusLabel->setWordWrap(true);
    pendingLayout->addWidget(pendingReorgStatusLabel);

    pendingReorgDetailsLabel = new QLabel();
    pendingReorgDetailsLabel->setWordWrap(true);
    pendingReorgDetailsLabel->setStyleSheet("QLabel { padding: 10px; background-color: #ffffff; border: 1px solid #ddd; border-radius: 4px; }");
    pendingLayout->addWidget(pendingReorgDetailsLabel);

    pendingReorgTimeoutLabel = new QLabel();
    pendingReorgTimeoutLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    pendingLayout->addWidget(pendingReorgTimeoutLabel);

    QHBoxLayout* pendingButtonLayout = new QHBoxLayout();
    acceptReorgButton = new QPushButton(tr("✓ ACCEPT REORG"));
    acceptReorgButton->setStyleSheet(
        "QPushButton { "
        "  background-color: #4CAF50; "
        "  color: white; "
        "  font-weight: bold; "
        "  padding: 10px 20px; "
        "  border-radius: 4px; "
        "  font-size: 13px; "
        "} "
        "QPushButton:hover { background-color: #45a049; }"
    );
    acceptReorgButton->setToolTip(tr("Accept the reorganization and switch to the new chain"));

    rejectReorgButton = new QPushButton(tr("✗ REJECT REORG"));
    rejectReorgButton->setStyleSheet(
        "QPushButton { "
        "  background-color: #f44336; "
        "  color: white; "
        "  font-weight: bold; "
        "  padding: 10px 20px; "
        "  border-radius: 4px; "
        "  font-size: 13px; "
        "} "
        "QPushButton:hover { background-color: #da190b; }"
    );
    rejectReorgButton->setToolTip(tr("Reject the reorganization and stay on the current chain"));

    pendingButtonLayout->addStretch();
    pendingButtonLayout->addWidget(acceptReorgButton);
    pendingButtonLayout->addWidget(rejectReorgButton);
    pendingButtonLayout->addStretch();
    pendingLayout->addLayout(pendingButtonLayout);

    // Initially hidden - shown only when pending
    pendingReorgGroup->setVisible(false);
    layout->addWidget(pendingReorgGroup);

    // Connect pending decision buttons
    connect(acceptReorgButton, &QPushButton::clicked, this, &MiningApisPage::onAcceptReorg);
    connect(rejectReorgButton, &QPushButton::clicked, this, &MiningApisPage::onRejectReorg);

    // ===== HEADER WITH STATUS SUMMARY =====
    QGroupBox* summaryGroup = new QGroupBox(tr("Reorg Advisory Status"));
    QVBoxLayout* summaryLayout = new QVBoxLayout(summaryGroup);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    advisoryCountLabel = new QLabel(tr("No advisories recorded"));
    advisoryCountLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 14px; }");
    headerLayout->addWidget(advisoryCountLabel);
    headerLayout->addStretch();

    refreshAdvisoriesButton = new QPushButton(tr("Refresh"));
    clearAdvisoriesButton = new QPushButton(tr("Clear All"));
    headerLayout->addWidget(refreshAdvisoriesButton);
    headerLayout->addWidget(clearAdvisoriesButton);
    summaryLayout->addLayout(headerLayout);

    latestAdvisorySummary = new QLabel(tr("System monitoring for chain reorganizations..."));
    latestAdvisorySummary->setWordWrap(true);
    latestAdvisorySummary->setStyleSheet("QLabel { padding: 10px; background-color: #f5f5f5; border-radius: 4px; }");
    summaryLayout->addWidget(latestAdvisorySummary);

    layout->addWidget(summaryGroup);

    // ===== ADVISORY HISTORY TABLE =====
    QGroupBox* historyGroup = new QGroupBox(tr("Advisory History"));
    QVBoxLayout* historyLayout = new QVBoxLayout(historyGroup);

    advisoryTable = new QTableWidget(0, 6);
    advisoryTable->setHorizontalHeaderLabels({
        tr("Time"), tr("Severity"), tr("Depth"), tr("Fork Depth"),
        tr("TX Overlap"), tr("LCA Height")
    });
    advisoryTable->horizontalHeader()->setStretchLastSection(true);
    advisoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    advisoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    advisoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    advisoryTable->setMaximumHeight(200);
    historyLayout->addWidget(advisoryTable);

    layout->addWidget(historyGroup);

    // ===== TWO COLUMN LAYOUT: DETAILS AND RECOMMENDATIONS =====
    QHBoxLayout* detailsRecommendLayout = new QHBoxLayout();

    // Left: Advisory Details
    QGroupBox* detailsGroup = new QGroupBox(tr("Selected Advisory Details"));
    QVBoxLayout* detailsLayout = new QVBoxLayout(detailsGroup);

    advisoryDetailsDisplay = new QTextEdit();
    advisoryDetailsDisplay->setReadOnly(true);
    advisoryDetailsDisplay->setPlaceholderText(tr("Select an advisory from the table above to view details..."));
    detailsLayout->addWidget(advisoryDetailsDisplay);

    detailsRecommendLayout->addWidget(detailsGroup);

    // Right: Recommendations & Actions
    QGroupBox* recommendGroup = new QGroupBox(tr("Recommendations & Actions"));
    QVBoxLayout* recommendLayout = new QVBoxLayout(recommendGroup);

    recommendationDisplay = new QTextEdit();
    recommendationDisplay->setReadOnly(true);
    recommendationDisplay->setStyleSheet("QTextEdit { background-color: #fffde7; }");
    recommendationDisplay->setPlaceholderText(tr("Recommendations will appear here based on advisory data..."));
    recommendLayout->addWidget(recommendationDisplay);

    // Action buttons
    QHBoxLayout* actionLayout = new QHBoxLayout();
    acknowledgeAdvisoryButton = new QPushButton(tr("Acknowledge"));
    acknowledgeAdvisoryButton->setEnabled(false);
    acknowledgeAdvisoryButton->setToolTip(tr("Mark this advisory as reviewed"));
    actionLayout->addWidget(acknowledgeAdvisoryButton);
    actionLayout->addStretch();
    recommendLayout->addLayout(actionLayout);

    detailsRecommendLayout->addWidget(recommendGroup);

    layout->addLayout(detailsRecommendLayout);

    // ===== LEGEND =====
    QLabel* legendLabel = new QLabel(
        tr("<b>Severity Levels:</b> "
           "<span style='color: #4CAF50;'>● Low (4-5 blocks)</span> | "
           "<span style='color: #FF9800;'>● Medium (6-10 blocks)</span> | "
           "<span style='color: #f44336;'>● High (>10 blocks)</span>")
    );
    legendLabel->setStyleSheet("QLabel { padding: 5px; font-size: 11px; }");
    layout->addWidget(legendLabel);

    // Connect signals
    connect(refreshAdvisoriesButton, &QPushButton::clicked, this, &MiningApisPage::onRefreshAdvisories);
    connect(clearAdvisoriesButton, &QPushButton::clicked, this, &MiningApisPage::onClearAdvisories);
    connect(acknowledgeAdvisoryButton, &QPushButton::clicked, this, &MiningApisPage::onAcknowledgeAdvisory);
    connect(advisoryTable, &QTableWidget::cellClicked, this, &MiningApisPage::onAdvisorySelected);
}

void MiningApisPage::onRefreshAdvisories()
{
    updateReorgAdvisories();
    addLogEntry(tr("Reorg advisories refreshed"));
}

void MiningApisPage::onClearAdvisories()
{
    if (!clientModel) {
        showError(tr("Client model not available"));
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Clear Advisories"),
        tr("Are you sure you want to clear all reorg advisories?\n\nThis action cannot be undone."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("clearreorgadvisories", params, "");

        int cleared = result["cleared"].getInt<int>();
        showSuccess(tr("Cleared %1 advisories").arg(cleared));
        addLogEntry(tr("Cleared %1 reorg advisories").arg(cleared));

        updateReorgAdvisories();
    } catch (const UniValue& objError) {
        showError(tr("Failed to clear advisories: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        showError(tr("Failed to clear advisories: %1").arg(e.what()));
    }
}

void MiningApisPage::onAcknowledgeAdvisory()
{
    // For now, just log the acknowledgment - could be extended to mark advisories as reviewed
    int row = advisoryTable->currentRow();
    if (row >= 0) {
        QString depth = advisoryTable->item(row, 2)->text();
        addLogEntry(tr("Advisory acknowledged (depth=%1)").arg(depth));
        showSuccess(tr("Advisory acknowledged and logged"));
    }
}

void MiningApisPage::onAdvisorySelected(int row, int column)
{
    Q_UNUSED(column);

    if (row < 0 || !clientModel) {
        return;
    }

    acknowledgeAdvisoryButton->setEnabled(true);

    try {
        UniValue params(UniValue::VARR);
        params.push_back(10);  // Get up to 10 advisories
        UniValue result = clientModel->node().executeRpc("getreorgadvisories", params, "");

        const UniValue& advisories = result["advisories"];
        if (row >= 0 && row < (int)advisories.size()) {
            const UniValue& adv = advisories[row];

            // Build detailed display
            QString details;
            details += tr("<b>Reorg Advisory Details</b><br><br>");
            details += tr("<b>LCA Height:</b> %1<br>").arg(adv["lca_height"].getInt<int>());
            details += tr("<b>Current Chain Depth:</b> %1 blocks orphaned<br>").arg(adv["depth_current"].getInt<int>());
            details += tr("<b>Fork Chain Depth:</b> %1 blocks<br>").arg(adv["depth_fork"].getInt<int>());
            details += tr("<b>Transaction Overlap:</b> %1%<br>").arg(adv["tx_overlap_pct"].get_real(), 0, 'f', 1);
            details += tr("<b>First Block Delay:</b> %1 seconds<br><br>").arg(adv["first_block_delay_secs"].getInt<int64_t>());

            // Segment stats
            if (adv.exists("segment_current")) {
                const UniValue& seg = adv["segment_current"];
                details += tr("<b>Current Segment:</b><br>");
                details += tr("  Blocks: %1, Clock time: %2s<br>").arg(
                    seg["block_count"].getInt<int>()).arg(seg["clock_time_secs"].getInt<int64_t>());
            }

            if (adv.exists("segment_fork")) {
                const UniValue& seg = adv["segment_fork"];
                details += tr("<b>Fork Segment:</b><br>");
                details += tr("  Blocks: %1, Clock time: %2s<br>").arg(
                    seg["block_count"].getInt<int>()).arg(seg["clock_time_secs"].getInt<int64_t>());
            }

            // Calibration info
            if (adv.exists("calibration")) {
                const UniValue& cal = adv["calibration"];
                bool calValid = cal["valid"].get_bool();
                details += tr("<br><b>Calibration:</b> %1<br>").arg(calValid ? tr("Valid") : tr("Invalid"));
                if (calValid) {
                    details += tr("  Hashrate current: %1%<br>").arg(adv["hashrate_current_pct"].get_real(), 0, 'f', 1);
                    details += tr("  Hashrate fork: %1%<br>").arg(adv["hashrate_fork_pct"].get_real(), 0, 'f', 1);
                }
            }

            advisoryDetailsDisplay->setHtml(details);

            // Update recommendations
            int depth = adv["depth_current"].getInt<int>();
            double overlap = adv["tx_overlap_pct"].get_real();
            int forkDepth = adv["depth_fork"].getInt<int>();
            recommendationDisplay->setHtml(getRecommendation(depth, overlap, forkDepth));
        }
    } catch (const std::exception& e) {
        advisoryDetailsDisplay->setText(tr("Error loading advisory details: %1").arg(e.what()));
    }
}

void MiningApisPage::updateReorgAdvisories()
{
    if (!clientModel) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back(10);  // Get up to 10 advisories
        UniValue result = clientModel->node().executeRpc("getreorgadvisories", params, "");

        int total = result["total_stored"].getInt<int>();
        const UniValue& advisories = result["advisories"];

        // Update count label
        if (total == 0) {
            advisoryCountLabel->setText(tr("No advisories recorded"));
            advisoryCountLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 14px; color: #4CAF50; }");
            latestAdvisorySummary->setText(tr("✓ No chain reorganizations detected. System operating normally."));
            latestAdvisorySummary->setStyleSheet("QLabel { padding: 10px; background-color: #e8f5e9; border-radius: 4px; color: #2E7D32; }");
        } else {
            advisoryCountLabel->setText(tr("%1 advisory(ies) recorded").arg(total));

            // Get the latest advisory for summary
            if (advisories.size() > 0) {
                const UniValue& latest = advisories[0];
                int depth = latest["depth_current"].getInt<int>();
                QString severity = (depth > 10) ? tr("HIGH") : (depth > 5) ? tr("MEDIUM") : tr("LOW");
                QString color = getSeverityStyle(depth);

                advisoryCountLabel->setStyleSheet(QString("QLabel { font-weight: bold; font-size: 14px; %1 }").arg(color));

                latestAdvisorySummary->setText(tr("⚠ Latest: %1 severity reorg detected. Depth: %2 blocks, TX Overlap: %3%")
                    .arg(severity)
                    .arg(depth)
                    .arg(latest["tx_overlap_pct"].get_real(), 0, 'f', 1));
                latestAdvisorySummary->setStyleSheet(QString("QLabel { padding: 10px; border-radius: 4px; %1 }").arg(
                    depth > 10 ? "background-color: #ffebee; color: #c62828;" :
                    depth > 5 ? "background-color: #fff3e0; color: #e65100;" :
                    "background-color: #fffde7; color: #f57f17;"));
            }
        }

        // Populate table
        advisoryTable->setRowCount(0);
        for (size_t i = 0; i < advisories.size(); ++i) {
            const UniValue& adv = advisories[i];
            int row = advisoryTable->rowCount();
            advisoryTable->insertRow(row);

            // Time (use since_last_block_secs as relative indicator)
            QTableWidgetItem* timeItem = new QTableWidgetItem(tr("Event %1").arg(i + 1));
            advisoryTable->setItem(row, 0, timeItem);

            // Severity
            int depth = adv["depth_current"].getInt<int>();
            QString severity = (depth > 10) ? tr("● HIGH") : (depth > 5) ? tr("● MEDIUM") : tr("● LOW");
            QTableWidgetItem* severityItem = new QTableWidgetItem(severity);
            severityItem->setForeground(QBrush(
                depth > 10 ? QColor("#f44336") : depth > 5 ? QColor("#FF9800") : QColor("#4CAF50")));
            advisoryTable->setItem(row, 1, severityItem);

            // Depth
            advisoryTable->setItem(row, 2, new QTableWidgetItem(QString::number(depth)));

            // Fork Depth
            advisoryTable->setItem(row, 3, new QTableWidgetItem(QString::number(adv["depth_fork"].getInt<int>())));

            // TX Overlap
            advisoryTable->setItem(row, 4, new QTableWidgetItem(
                QString::number(adv["tx_overlap_pct"].get_real(), 'f', 1) + "%"));

            // LCA Height
            advisoryTable->setItem(row, 5, new QTableWidgetItem(QString::number(adv["lca_height"].getInt<int>())));
        }

        // If there are advisories, auto-select the first one
        if (advisories.size() > 0) {
            advisoryTable->selectRow(0);
            onAdvisorySelected(0, 0);
        } else {
            advisoryDetailsDisplay->clear();
            recommendationDisplay->clear();
            acknowledgeAdvisoryButton->setEnabled(false);
        }

    } catch (const UniValue& objError) {
        addLogEntry(tr("Failed to update advisories: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        addLogEntry(tr("Failed to update advisories: %1").arg(e.what()));
    }
}

QString MiningApisPage::getRecommendation(int depth, double overlap, int forkDepth) const
{
    QString recommendation;
    recommendation += tr("<b>Operator Recommendations</b><br><br>");

    // Severity-based recommendations
    if (depth > 10) {
        recommendation += tr("<span style='color: #c62828;'><b>⚠ HIGH SEVERITY REORG</b></span><br><br>");
        recommendation += tr("A significant chain reorganization has occurred. This may indicate:<br>");
        recommendation += tr("• A network attack (51% attack, selfish mining)<br>");
        recommendation += tr("• Major network partition that has been resolved<br>");
        recommendation += tr("• Consensus issues requiring investigation<br><br>");

        recommendation += tr("<b>Recommended Actions:</b><br>");
        recommendation += tr("1. <b>PAUSE</b> accepting high-value transactions temporarily<br>");
        recommendation += tr("2. <b>VERIFY</b> recent transactions have not been reversed<br>");
        recommendation += tr("3. <b>CHECK</b> network connectivity and peer diversity<br>");
        recommendation += tr("4. <b>MONITOR</b> for additional reorg events<br>");
        recommendation += tr("5. <b>CONSIDER</b> increasing confirmation requirements<br>");

    } else if (depth > 5) {
        recommendation += tr("<span style='color: #e65100;'><b>⚠ MEDIUM SEVERITY REORG</b></span><br><br>");
        recommendation += tr("A notable chain reorganization has occurred. This could be:<br>");
        recommendation += tr("• Natural network latency causing temporary forks<br>");
        recommendation += tr("• Mining variance with competing blocks<br><br>");

        recommendation += tr("<b>Recommended Actions:</b><br>");
        recommendation += tr("1. <b>REVIEW</b> recent transaction confirmations<br>");
        recommendation += tr("2. <b>MONITOR</b> for repeated events<br>");
        recommendation += tr("3. <b>VERIFY</b> your node has good peer connectivity<br>");

    } else {
        recommendation += tr("<span style='color: #388e3c;'><b>✓ LOW SEVERITY REORG</b></span><br><br>");
        recommendation += tr("This is a minor chain reorganization, which is normal network behavior.<br><br>");

        recommendation += tr("<b>Recommended Actions:</b><br>");
        recommendation += tr("• No immediate action required<br>");
        recommendation += tr("• Continue normal operations<br>");
        recommendation += tr("• Standard confirmation requirements remain adequate<br>");
    }

    // TX Overlap analysis
    recommendation += tr("<br><b>Transaction Analysis:</b><br>");
    if (overlap > 90) {
        recommendation += tr("✓ High TX overlap (%1%) - Most transactions were included in both chains. "
                            "Minimal double-spend risk.<br>").arg(overlap, 0, 'f', 1);
    } else if (overlap > 50) {
        recommendation += tr("⚠ Moderate TX overlap (%1%) - Some transactions may have been affected. "
                            "Review recent confirmations.<br>").arg(overlap, 0, 'f', 1);
    } else {
        recommendation += tr("⚠ Low TX overlap (%1%) - Significant transaction differences between chains. "
                            "Verify all recent transactions.<br>").arg(overlap, 0, 'f', 1);
    }

    // Fork comparison
    if (forkDepth > depth) {
        recommendation += tr("<br><b>Note:</b> The winning fork (%1 blocks) was longer than the orphaned chain (%2 blocks). "
                            "This is expected Nakamoto consensus behavior.<br>").arg(forkDepth).arg(depth);
    }

    return recommendation;
}

QString MiningApisPage::getSeverityStyle(int depth) const
{
    if (depth > 10) {
        return "color: #c62828;";  // Red for high
    } else if (depth > 5) {
        return "color: #e65100;";  // Orange for medium
    } else {
        return "color: #388e3c;";  // Green for low
    }
}

// ===== PENDING REORG DECISION FUNCTIONS =====

void MiningApisPage::updatePendingReorgStatus()
{
    if (!clientModel) {
        pendingReorgGroup->setVisible(false);
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        UniValue result = clientModel->node().executeRpc("getpendingreorg", params, "");

        if (result.isNull()) {
            // No pending reorg
            pendingReorgGroup->setVisible(false);
            return;
        }

        // There's a pending reorg - show the decision UI
        pendingReorgGroup->setVisible(true);

        int depthCurrent = result["depth_current"].getInt<int>();
        int depthFork = result["depth_fork"].getInt<int>();
        double txOverlap = result["tx_overlap_pct"].get_real();
        double hashrateCurrent = result["hashrate_current_pct"].get_real();
        double hashrateFork = result["hashrate_fork_pct"].get_real();
        int64_t timeoutRemaining = result["timeout_remaining"].getInt<int64_t>();

        QString details = tr(
            "<b>Reorg Details:</b><br>"
            "• Current chain depth to fork: <b>%1 blocks</b><br>"
            "• Competing chain depth: <b>%2 blocks</b><br>"
            "• Transaction overlap: <b>%3%</b><br>"
            "• Current chain hashrate: <b>%4%</b> of baseline<br>"
            "• Fork chain hashrate: <b>%5%</b> of baseline<br><br>"
            "<b>Candidate tip:</b> %6<br>"
            "<b>Current tip:</b> %7"
        )
        .arg(depthCurrent)
        .arg(depthFork)
        .arg(txOverlap, 0, 'f', 1)
        .arg(hashrateCurrent, 0, 'f', 1)
        .arg(hashrateFork, 0, 'f', 1)
        .arg(QString::fromStdString(result["candidate_tip"].get_str()).left(16) + "...")
        .arg(QString::fromStdString(result["current_tip"].get_str()).left(16) + "...");

        pendingReorgDetailsLabel->setText(details);

        // Format timeout
        int minutes = timeoutRemaining / 60;
        int seconds = timeoutRemaining % 60;
        pendingReorgTimeoutLabel->setText(tr("Decision timeout: %1:%2 remaining")
            .arg(minutes)
            .arg(seconds, 2, 10, QLatin1Char('0')));

    } catch (const UniValue& objError) {
        pendingReorgGroup->setVisible(false);
    } catch (const std::exception& e) {
        pendingReorgGroup->setVisible(false);
    }
}

void MiningApisPage::onAcceptReorg()
{
    if (!clientModel) {
        showError(tr("Client model not available"));
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::warning(this,
        tr("Accept Reorganization"),
        tr("Are you sure you want to ACCEPT this chain reorganization?\n\n"
           "The node will switch to the competing chain. This may affect recent transactions."),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back("accept");
        UniValue result = clientModel->node().executeRpc("submitreorgdecision", params, "");

        if (result["success"].get_bool()) {
            showSuccess(tr("Decision submitted: ACCEPT. Node will proceed with chain switch."));
            addLogEntry(tr("Operator accepted pending reorg - chain switch proceeding"));
            pendingReorgGroup->setVisible(false);
        } else {
            showError(tr("Failed to submit decision: %1").arg(
                QString::fromStdString(result["message"].get_str())));
        }
    } catch (const UniValue& objError) {
        showError(tr("RPC error: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        showError(tr("Error: %1").arg(e.what()));
    }
}

void MiningApisPage::onRejectReorg()
{
    if (!clientModel) {
        showError(tr("Client model not available"));
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::warning(this,
        tr("Reject Reorganization"),
        tr("Are you sure you want to REJECT this chain reorganization?\n\n"
           "The node will stay on the current chain and ignore the competing fork."),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (reply != QMessageBox::Yes) {
        return;
    }

    try {
        UniValue params(UniValue::VARR);
        params.push_back("reject");
        UniValue result = clientModel->node().executeRpc("submitreorgdecision", params, "");

        if (result["success"].get_bool()) {
            showSuccess(tr("Decision submitted: REJECT. Node will stay on current chain."));
            addLogEntry(tr("Operator rejected pending reorg - staying on current chain"));
            pendingReorgGroup->setVisible(false);
        } else {
            showError(tr("Failed to submit decision: %1").arg(
                QString::fromStdString(result["message"].get_str())));
        }
    } catch (const UniValue& objError) {
        showError(tr("RPC error: %1").arg(QString::fromStdString(objError["message"].get_str())));
    } catch (const std::exception& e) {
        showError(tr("Error: %1").arg(e.what()));
    }
}
