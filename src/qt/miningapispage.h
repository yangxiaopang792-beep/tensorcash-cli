// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MININGAPISPAGE_H
#define BITCOIN_QT_MININGAPISPAGE_H

#include <QWidget>
#include <QTabWidget>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSet>
#include <memory>

class ClientModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QTextEdit;
class QGroupBox;
class QVBoxLayout;
class QLineEdit;
class QComboBox;
class QCheckBox;
QT_END_NAMESPACE

/** Mining APIs page for monitoring mining and verification API status */
class MiningApisPage : public QWidget
{
    Q_OBJECT

public:
    explicit MiningApisPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~MiningApisPage();

    void setClientModel(ClientModel* clientModel);

public Q_SLOTS:
    void updateMiningStatus();
    void updateMetrics();
    void updateValidationStatus();

Q_SIGNALS:
    void message(const QString& title, const QString& message, unsigned int style);
    void openDiscussionRequested(const QString& scopeType, const QString& scopeHash, const QString& modelIdentifier);

private:
    ClientModel* clientModel{nullptr};
    const PlatformStyle* m_platform_style;

    // Main tab widget
    QTabWidget* tabWidget{nullptr};

    // ===== MINING STATUS TAB =====
    QWidget* miningStatusTab{nullptr};
    QLabel* miningStatusLabel{nullptr};
    QLabel* miningAddressLabel{nullptr};
    QLabel* miningUptimeLabel{nullptr};
    QPushButton* startMiningButton{nullptr};
    QPushButton* stopMiningButton{nullptr};

    // Mining Metrics
    QLabel* solutionsReceivedLabel{nullptr};
    QLabel* solutionsUsableLabel{nullptr};
    QLabel* solutionsInvalidLabel{nullptr};
    QLabel* solutionsDuplicateLabel{nullptr};
    QLabel* usableRateLabel{nullptr};
    QLabel* rateLimitedLabel{nullptr};
    QLabel* networkErrorsLabel{nullptr};
    QLabel* lastSolutionLabel{nullptr};
    QPushButton* refreshMetricsButton{nullptr};

    // Miner Proxy Throughput Metrics
    QLabel* hashRateLabel{nullptr};
    QLabel* tokensPerSecLabel{nullptr};
    QLabel* totalHashesLabel{nullptr};
    QLabel* activeRequestsLabel{nullptr};
    QNetworkAccessManager* networkManager{nullptr};

    // Mining Active Model Runtime Control
    QComboBox* miningRegisteredModelCombo{nullptr};
    QLabel* miningCurrentModelLabel{nullptr};
    QLabel* miningActiveModelStateLabel{nullptr};
    QPushButton* refreshMiningModelButton{nullptr};
    QPushButton* applyMiningModelButton{nullptr};
    QCheckBox* miningForceModelSwitchCheck{nullptr};
    bool miningModelApiReachable{false};
    bool miningRuntimeAutoSelect{true};
    QString miningRuntimeModelName;
    QString miningRuntimeModelCommit;

    // Mining Connection Parameters
    QLabel* miningJobPushLabel{nullptr};
    QLabel* miningSolPullLabel{nullptr};
    QLabel* miningHealthLabel{nullptr};

    // ===== VERIFICATION STATUS TAB =====
    QWidget* verificationStatusTab{nullptr};

    // Verification Connection Parameters
    QLabel* verifyReqPushLabel{nullptr};
    QLabel* verifySolPullLabel{nullptr};
    QLabel* verifyHealthLabel{nullptr};

    // Validation Queue Status
    QLabel* quickQueueLabel{nullptr};
    QLabel* fullQueueLabel{nullptr};
    QLabel* modelQueueLabel{nullptr};
    QLabel* challengeQueueLabel{nullptr};
    QPushButton* refreshQueuesButton{nullptr};

    // Recent Validations Table
    QTableWidget* recentValidationsTable{nullptr};

    // ===== CONFIGURATION TAB =====
    QWidget* configurationTab{nullptr};
    QTextEdit* miningConfigDisplay{nullptr};
    QTextEdit* verificationConfigDisplay{nullptr};

    // ===== METRICS & DIAGNOSTICS TAB =====
    QWidget* metricsTab{nullptr};
    QTextEdit* logsDisplay{nullptr};
    QPushButton* exportLogsButton{nullptr};
    QPushButton* clearLogsButton{nullptr};

    // ===== REORG ADVISORY TAB =====
    QWidget* reorgAdvisoryTab{nullptr};
    QTableWidget* advisoryTable{nullptr};
    QLabel* advisoryCountLabel{nullptr};
    QLabel* latestAdvisorySummary{nullptr};
    QTextEdit* advisoryDetailsDisplay{nullptr};
    QTextEdit* recommendationDisplay{nullptr};
    QPushButton* refreshAdvisoriesButton{nullptr};
    QPushButton* clearAdvisoriesButton{nullptr};
    QPushButton* acknowledgeAdvisoryButton{nullptr};

    // Pending Reorg Decision UI (for gating)
    QGroupBox* pendingReorgGroup{nullptr};
    QLabel* pendingReorgStatusLabel{nullptr};
    QLabel* pendingReorgDetailsLabel{nullptr};
    QLabel* pendingReorgTimeoutLabel{nullptr};
    QPushButton* acceptReorgButton{nullptr};
    QPushButton* rejectReorgButton{nullptr};

    // ===== OPERATOR REVIEW TAB =====
    QWidget* operatorReviewTab{nullptr};
    QTableWidget* operatorReviewsTable{nullptr};
    QTextEdit* operatorReviewDetails{nullptr};
    QLabel* operatorReviewStatusLabel{nullptr};
    QPushButton* operatorRefreshButton{nullptr};
    QPushButton* operatorApproveButton{nullptr};
    QPushButton* operatorRejectButton{nullptr};
    QPushButton* operatorOpenDiscussionButton{nullptr};
    QLineEdit* operatorApiBaseUrlEdit{nullptr};
    QLineEdit* operatorApiKeyEdit{nullptr};
    QNetworkAccessManager* operatorNetworkManager{nullptr};

    QString m_selectedModelHash;
    QString m_selectedModelIdentifier;
    QString m_selectedReviewType;
    QSet<QString> m_knownPendingReviewHashes;
    bool m_pendingReviewsInitialized{false};
    bool m_operatorReviewEnabled{true};

    // Timers
    QTimer* statusUpdateTimer{nullptr};  // 1 second for uptime and status
    QTimer* metricsUpdateTimer{nullptr}; // 5 seconds for metrics
    QTimer* operatorReviewsTimer{nullptr}; // 30 seconds for operator review polling (always on)

    // Mining tracking
    bool miningActive{false};
    qint64 miningStartTime{0};
    QString currentMiningAddress;

    // UI setup methods
    void setupMiningStatusTab();
    void setupVerificationStatusTab();
    void setupConfigurationTab();
    void setupMetricsTab();
    void setupReorgAdvisoryTab();
    void setupOperatorReviewTab();

    // Helper methods
    void updateMiningConnectionStatus();
    void updateVerificationConnectionStatus();
    void updateQueueCounts();
    void updateRecentValidations();
    void updateMinerProxyMetrics();
    void refreshMiningActiveModel();
    void refreshMiningRegisteredModels();
    void sendMiningActiveModelRequest(const QString& action, bool isPost, const QByteArray& payload, const QStringList& targets, int targetIndex);
    QStringList miningApiBaseUrls() const;
    void updateMiningModelControlsState();
    void addLogEntry(const QString& message);
    QString formatUptime(qint64 seconds) const;
    QString formatTimestamp(qint64 timestamp) const;
    QString formatTokenCount(uint64_t tokens) const;
    void showError(const QString& message);
    void showSuccess(const QString& message);
    QString operatorApiBaseUrl() const;
    QString operatorApiKey() const;
    QString reviewAuditToText(const QJsonObject& reviewObj) const;
    void refreshOperatorReviews();
    void setOperatorButtonsEnabled(bool enabled);

private Q_SLOTS:
    // Mining Status tab slots
    void onStartMining();
    void onStopMining();
    void onRefreshMetrics();
    void onRefreshMiningModel();
    void onApplyMiningModel();

    // Verification Status tab slots
    void onRefreshQueues();
    void onValidationSelected(int row, int column);

    // Metrics tab slots
    void onExportLogs();
    void onClearLogs();

    // Reorg Advisory tab slots
    void onRefreshAdvisories();
    void onClearAdvisories();
    void onAcknowledgeAdvisory();
    void onAdvisorySelected(int row, int column);
    void updateReorgAdvisories();
    QString getRecommendation(int depth, double overlap, int forkDepth) const;
    QString getSeverityStyle(int depth) const;

    // Pending Reorg Decision slots
    void onAcceptReorg();
    void onRejectReorg();
    void updatePendingReorgStatus();
    void onRefreshOperatorReviews();
    void onOperatorReviewSelected(int row, int column);
    void onOperatorApprove();
    void onOperatorReject();
    void onOperatorOpenDiscussion();
    void onOperatorAutoRefreshTick();

    // Timer slots
    void onStatusTimerTick();
    void onMetricsTimerTick();

    // Network slots
    void onMinerProxyReply(QNetworkReply* reply);
    void onOperatorReply(QNetworkReply* reply);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;
};

#endif // BITCOIN_QT_MININGAPISPAGE_H
