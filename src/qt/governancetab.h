// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_GOVERNANCETAB_H
#define BITCOIN_QT_GOVERNANCETAB_H

#include <QPointer>
#include <QWidget>
#include <QMap>
#include <QTimer>
#include <QVariant>
#include <QDateTime>

class PlatformStyle;
class WalletModel;
class ClientModel;
class BridgeSessionManager;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QVBoxLayout;
class QComboBox;
QT_END_NAMESPACE

/**
 * @brief Governance tab - Asset governance proposals and voting
 *
 * Displays governance proposals from the bulletin board (Nostr),
 * shows policy changes, validates BIP-322 attestations, and enables
 * one-click ballot signing for holders to vote on policy rotations.
 */
class GovernanceTab : public QWidget
{
    Q_OBJECT

public:
    explicit GovernanceTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~GovernanceTab();

    void setWalletModel(WalletModel* model);
    void setClientModel(ClientModel* model);
    void setSessionManager(BridgeSessionManager* manager);

private Q_SLOTS:
    void onRefreshProposals();
    void onForceRefresh();
    void onViewDetails();
    void onVote();
    void onAssetFilterChanged(int index);
    void updateProposalsList();
    void updateBulletinBoardStatus();

private:
    struct ProposalInfo {
        QString proposal_id;
        QString asset_id;
        QString issuer_nostr_pubkey;
        int64_t created_at;
        int64_t expires_at;
        QString flow_type;      // "public" or "private"
        QString title;
        bool is_expired;
        QString policy_changes;  // Human-readable summary

        // BIP-322 verification status
        bool bip322_verified{false};
        QString bip322_error;

        // Hash verification status (cached)
        bool canonical_icu_hash_verified{false};
        bool witness_bundle_hash_verified{false};
        bool template_psbt_hash_verified{false};
        QString verification_errors;  // Human-readable errors

        // Full proposal data (for details dialog)
        QVariantMap full_proposal;
    };

    void setupUI();
    QString formatTimestamp(int64_t timestamp);
    QString formatPubkey(const QString& pubkey);
    QString formatPolicyChanges(const QVariantMap& proposed_policy) const;
    bool verifyBip322Attestation(const QVariantMap& proposal);
    void verifyProposalHashes(ProposalInfo& info);
    QString computeSha256(const QString& text);
    void showProposalDetailsDialog(const ProposalInfo& info);
    void updateProposalRow(const QString& proposal_id, const ProposalInfo& info);

    // QPointer auto-nulls when the WalletModel QObject is destroyed; existing
    // null checks then handle wallet unload/shutdown safely.
    QPointer<WalletModel> walletModel;
    ClientModel* clientModel{nullptr};
    BridgeSessionManager* sessionManager{nullptr};
    const PlatformStyle* platformStyle;

    // UI components - Status section
    QLabel* bbStatusLabel;
    QLabel* bbPubkeyLabel;
    QLabel* bbRelaysLabel;
    QPushButton* forceRefreshButton;

    // UI components - Proposals section
    QPushButton* refreshProposalsButton;
    QComboBox* assetFilterCombo;
    QTableWidget* proposalsTable;

    // Filter state
    QString currentAssetFilter;

    // Data tracking
    QMap<QString, ProposalInfo> activeProposals;

    // Update timer
    QTimer* proposalsUpdateTimer;

    // Bulletin Board status cache
    bool bbInitialized{false};
    QString bbPubkey;
    int bbRelayCount{0};
    QDateTime lastCacheRefresh;
};

#endif // BITCOIN_QT_GOVERNANCETAB_H
