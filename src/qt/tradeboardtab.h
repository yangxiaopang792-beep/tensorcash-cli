// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_TRADEBOARDTAB_H
#define BITCOIN_QT_TRADEBOARDTAB_H

#include <QPointer>
#include <QWidget>
#include <QtGlobal>
#include <QMap>
#include <QHash>
#include <QList>
#include <QSet>
#include <QTimer>
#include <QVariant>
#include <QDateTime>
#include <QJsonObject>
#include <QByteArray>
#include <optional>

#include <qt/walletmodel.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

class PlatformStyle;
class BridgeSessionManager;
class AssetPriceTab;
class CrossChainTradeView;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QTableWidget;
class QVBoxLayout;
class QComboBox;
QT_END_NAMESPACE

/**
 * @brief Trade Board tab - Decentralized P2P trading via Nostr
 *
 * Displays available trade offers from the bulletin board (Nostr),
 * allows posting new offers, requesting trades, and managing trade requests.
 * Automatically joins bilateral sessions when maker accepts.
 */
class TradeBoardTab : public QWidget
{
    Q_OBJECT

public:
    explicit TradeBoardTab(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~TradeBoardTab();

    void setWalletModel(WalletModel* model);
    void setSessionManager(BridgeSessionManager* manager);
    void setAssetPriceTab(AssetPriceTab* tab) { assetPriceTab = tab; }

    // Ceremony phase tracking (public for TradeCeremonyRunner access)
    enum class CeremonyPhase {
        NONE,
        PHASE0_BASE,        // Base PSBT exchange
        PHASE1_ATTEST,      // BIP-322 attestation
        PHASE2_NONCE,       // Nonce exchange
        PHASE3_PARTIAL,     // Partial signature exchange
        PHASE4_COMPLETE     // Final completion
    };

Q_SIGNALS:
    void message(const QString &title, const QString &message, unsigned int style);

private Q_SLOTS:
    void onForceRefresh();
    void onForceRestart();
    void onRequestTrade();
    void onDeleteOffer();
    void onContractTypeChanged(int index);
    void onCreateContract();
    void updateBulletinBoardStatus();
    void updateTorStatus();
    void updateOffersList();
    void updateTradeRequestsList();
    void checkForAutoJoin();
    void updateCacheTimer();
    void pollSessionMessages();
    void clearStuckTradeRequests();
    void showFilterDialog();

private:
    struct OfferInfo {
        QString offer_id;
        QString maker_pubkey;
        QString offer_type;      // "buy", "sell", "swap", or "repocontract", "forwardcontract", "spotcontract"
        QString asset_send;
        QString asset_recv;
        double amount;
        double price;
        int64_t created_at;
        int64_t expires_at;
        QString state;

        // Contract-specific fields
        QString contract_type;   // "repo", "forward", "spot"
        QString maker_role;      // "lender", "borrower"
        double apr{0.0};         // Annual percentage rate
        double ltv{0.0};         // Loan-to-value ratio
        int tenor_days{0};       // Days to maturity
        int maturity_height{0};  // Block height at maturity (immutable blockchain param)
        QString contract_payload; // Full contract JSON (for review dialog)

        // Repo-specific fields (parsed from contract_payload)
        QString collateral_asset{};
        QString collateral_asset_id{};  // Actual asset ID for comparison (empty for native)
        double collateral_qty{0.0};
        QString principal_asset{};
        QString principal_asset_id{};   // Actual asset ID for comparison (empty for native)
        double principal_qty{0.0};
        QString interest_asset{};
        QString interest_asset_id{};    // Actual asset ID for comparison (empty for native)
        double interest_qty{0.0};

        // Forward/Option-specific fields
        // Long party
        QString long_deliver_asset;
        QString long_deliver_asset_id;  // Actual asset ID for comparison
        double long_deliver_qty{0.0};
        QString long_margin_asset;
        QString long_margin_asset_id;
        double long_margin_qty{0.0};
        QString long_margin_dest;        // Address for IM recovery
        QString long_settlement_dest;    // Address to receive settlement asset

        // Short party
        QString short_deliver_asset;
        QString short_deliver_asset_id;
        double short_deliver_qty{0.0};
        QString short_margin_asset;
        QString short_margin_asset_id;
        double short_margin_qty{0.0};
        QString short_margin_dest;
        QString short_settlement_dest;

        // Premium (optional)
        double premium_amount{0.0};
        QString premium_asset;
        QString premium_asset_id;
        QString premium_payer;          // "long" or "short"
        QString premium_payee_dest;

        // Deadlines (replace single maturity_height for forwards)
        int deadline_short{0};
        int deadline_long{0};
        int safety_k{0};
        int reorg_conf{0};

        // Derived metrics for display
        double long_im_percent{0.0};    // IM as % of deliver leg
        double short_im_percent{0.0};
        int tenor_days_short{0};        // Days until deadline_short
        int tenor_days_long{0};         // Days until deadline_long

        // Spot-specific fields (for atomic swaps)
        QString alice_send_asset_id;    // Asset ID that Alice sends (empty for native)
        int64_t alice_send_units{0};    // Base units Alice sends
        QString bob_send_asset_id;      // Asset ID that Bob sends (empty for native)
        int64_t bob_send_units{0};      // Base units Bob sends

        // Term sheet support
        bool is_term_sheet{false};
        QString term_sheet_json;
        QVariantMap term_sheet_terms;
        QVariantMap term_sheet_metrics;

        // Proof of funds support
        QVariantList proof_of_funds;
        bool proof_verified{false};
        uint64_t proof_verified_units{0};
        QString proof_verified_asset;
        QString proof_verification_error;
        qint64 proof_verified_at{0};
    };

    struct TradeRequestInfo {
        QString request_id;
        QString offer_id;
        QString direction;       // "incoming" or "outgoing"
        QString maker_pubkey;
        QString taker_pubkey;
        QString counterparty_pubkey;
        QString status;            // "pending", "accepted", "rejected", "cancelled"
        QString message;
        QString contract_type;     // "repo", "forward", "spot", "option"
        int64_t timestamp{0};      // Original request timestamp
        int64_t updated_at{0};     // Last update timestamp
        QString invite_link;       // Present when maker accepts
        int64_t invite_expires_at{0};
        QVariantMap offer_summary;
        bool auto_joined{false};   // Track if we've already auto-joined
        QString maker_role;
        CeremonyPhase ceremony_phase{CeremonyPhase::NONE};

        // Normalised terms (repo)
        bool terms_available{false};
        double principal_qty{0.0};
        QString principal_asset;
        double collateral_qty{0.0};
        QString collateral_asset;
        double interest_qty{0.0};
        QString interest_asset;
        double apr{0.0};
        double ltv{0.0};
        int tenor_days{0};
        int maturity_height{0};

        // Proof of funds
        QVariantList proof_of_funds;

        // Taker-supplied details
        QString taker_message_json;
        QString borrower_address;
        QString lender_address;
        bool taker_ready_for_ceremony{false};
        bool ceremony_ready_sent{false};
        bool waiting_for_base_notice_sent{false};

        // Cooperative non-atomic signing path. Set on the taker when the user
        // chooses "Pre-sign and Continue" in the Non-Taproot Funding Detected
        // dialog, and serialized into ceremony_ready as signing_mode. Set on
        // the maker only after the user accepts the downgrade modal.
        // The flag is asymmetric by design: taker sets to request, maker sets
        // to consent. The TradeCeremonyRunner reads it to switch from the
        // atomic adaptor ceremony to the asymmetric cooperative signing path
        // (taker signs first → maker signs last → maker broadcasts).
        bool cooperative_consent{false};

        // Forward/Option-specific fields (same as OfferInfo)
        // Long party
        QString long_deliver_asset;
        QString long_deliver_asset_id;
        double long_deliver_qty{0.0};
        QString long_margin_asset;
        QString long_margin_asset_id;
        double long_margin_qty{0.0};
        QString long_margin_dest;
        QString long_settlement_dest;

        // Short party
        QString short_deliver_asset;
        QString short_deliver_asset_id;
        double short_deliver_qty{0.0};
        QString short_margin_asset;
        QString short_margin_asset_id;
        double short_margin_qty{0.0};
        QString short_margin_dest;
        QString short_settlement_dest;

        // Premium
        double premium_amount{0.0};
        QString premium_asset;
        QString premium_asset_id;
        QString premium_payer;
        QString premium_payee_dest;

        // Deadlines
        int deadline_short{0};
        int deadline_long{0};
        int safety_k{0};
        int reorg_conf{0};

        // Derived metrics
        double long_im_percent{0.0};
        double short_im_percent{0.0};
        int tenor_days_short{0};
        int tenor_days_long{0};

        // Spot-specific addresses (from spot_taker_details_v1)
        QString spot_alice_address;
        QString spot_bob_address;

        // Vault indices for ceremony
        int alice_vault_index{-1};
        int bob_vault_index{-1};
        int premium_output_index{-1};

        // Final offer delivery
        QString final_offer_json;
        QString final_offer_id;
        bool final_offer_processed{false};

        // Outgoing acceptance tracking (taker)
        QString last_acceptance_envelope;
        bool acceptance_sent{false};

        // Maker-side ceremony invite tracking
        QString last_ceremony_invite;
        bool ceremony_invite_sent{false};
        bool recovering_session{false};
        QString staged_local_base_psbt;
        bool staged_local_base_ready{false};
        QString staged_peer_base_psbt;
        bool staged_peer_base_ready{false};

        // PSBT immutability (match functional test pattern)
        QString maker_base_psbt;           // Maker's initial base PSBT (from posted offer)
        QString augmented_psbt;            // Taker-augmented immutable PSBT (locked after lift)
        QString augmented_psbt_hash;       // Hash for immutability verification
        bool psbt_locked{false};           // True after taker lift completes
        QString merged_ceremony_psbt;      // Phase-0 merged PSBT used for ceremony retries/recovery
        QString merged_ceremony_psbt_hash;

        bool proof_verified{false};
        uint64_t proof_verified_units{0};
        QString proof_verified_asset;
        QString proof_verification_error;
        qint64 proof_verified_at{0};

        // Taker's chosen fee strategy for funding their side
        QString taker_fee_strategy{"medium"};
    };

    /**
     * @brief Immutable snapshot of finalized contract for modal dialogs
     *
     * This structure is created BEFORE any modal dialog is shown and contains
     * all data needed for the dialog and subsequent workflow. It is completely
     * detached from activeRequests, preventing timer-induced corruption.
     *
     * Design principles:
     * - Parse JSON once, extract all fields upfront
     * - Never reference activeRequests after creation
     * - Safe to pass across modal boundaries (exec())
     * - Enables timer-safe workflows
     */
    struct FinalContractSnapshot {
        // Identity
        QString contract_id;           // Offer ID
        QString request_id;            // Trade request ID
        QString session_id;            // Cosign session ID
        QString contract_type;         // "repo", "forward", "spot", "option"
        QString user_role;             // "lender", "borrower", "long", "short", "alice", "bob"

        // Raw JSON (immutable, for RPC calls and logging)
        QString offer_json;            // Complete finalized offer JSON
        QString acceptance_json;       // Complete acceptance JSON (maker-side only)
        QJsonObject offer_obj;         // Parsed offer for easy access
        QJsonObject acceptance_obj;    // Parsed acceptance (maker-side only)

        // Display data (pre-rendered, never recomputed)
        QString summary_html;          // Human-readable contract summary
        QStringList critical_checks;   // Address ownership checks, etc.
        QString raw_json_pretty;       // Pretty-printed JSON for "View JSON" button
        QString extra_json_pretty;     // Acceptance JSON (maker) or empty (taker)
        QString extra_json_title;      // "Acceptance JSON" or ""

        // Workflow state
        QString selected_fee_strategy; // "low", "medium", "high"
        bool is_taker;                 // true if this wallet is taker, false if maker
        bool is_maker;                 // true if this wallet is maker, false if taker

        // Repo-specific fields (populated if contract_type == "repo")
        struct RepoTerms {
            double principal_qty{0.0};
            QString principal_asset;
            double collateral_qty{0.0};
            QString collateral_asset;
            double interest_qty{0.0};
            QString interest_asset;
            double apr{0.0};
            double ltv{0.0};
            int tenor_days{0};
            int maturity_height{0};
            QString borrower_address;
            QString lender_address;
        } repo;

        // Forward/Option-specific fields (populated if contract_type == "forward" || "option")
        struct ForwardTerms {
            // Long party
            QString long_deliver_asset;
            QString long_deliver_asset_id;
            double long_deliver_qty{0.0};
            QString long_margin_asset;
            QString long_margin_asset_id;
            double long_margin_qty{0.0};
            double long_im_percent{0.0};
            QString long_margin_dest;
            QString long_settlement_dest;

            // Short party
            QString short_deliver_asset;
            QString short_deliver_asset_id;
            double short_deliver_qty{0.0};
            QString short_margin_asset;
            QString short_margin_asset_id;
            double short_margin_qty{0.0};
            double short_im_percent{0.0};
            QString short_margin_dest;
            QString short_settlement_dest;

            // Premium (options only)
            double premium_amount{0.0};
            QString premium_asset;
            QString premium_asset_id;
            QString premium_payer;       // "long" or "short"
            QString premium_payee_dest;

            // Deadlines
            int deadline_short{0};
            int deadline_long{0};
            int safety_k{0};
            int reorg_conf{0};
            int maturity_height{0};      // deadline_long for display
        } forward;

        // Spot-specific fields (populated if contract_type == "spot")
        struct SpotTerms {
            QString alice_send_asset;
            QString alice_send_asset_id;
            double alice_send_qty{0.0};
            QString alice_recv_asset;
            QString alice_recv_asset_id;
            double alice_recv_qty{0.0};
            QString alice_dest;

            QString bob_send_asset;
            QString bob_send_asset_id;
            double bob_send_qty{0.0};
            QString bob_recv_asset;
            QString bob_recv_asset_id;
            double bob_recv_qty{0.0};
            QString bob_dest;
        } spot;

        // Maker-side specific data (for immutability pattern)
        QString maker_base_psbt;       // Maker's base PSBT to send to taker
    };

    void setupUI();
    QString formatTimestamp(int64_t timestamp);
    QString formatPubkey(const QString& pubkey);
    QString formatOfferSummary(const QVariantMap& offer, const QString& fallbackId) const;
    QString formatStatusLabel(const TradeRequestInfo& info) const;
    void populateRepoTermsFromSummary(TradeRequestInfo& info, const QVariantMap& summary);
    void populateRepoTermsFromJson(TradeRequestInfo& info, const QJsonObject& obj);
    void populateForwardTermsFromJson(TradeRequestInfo& info, const QJsonObject& obj);
    void populateForwardTermsFromJson(OfferInfo& info, const QJsonObject& obj);
    void populateSpotTermsFromJson(TradeRequestInfo& info, const QJsonObject& obj);
    void populateSpotTermsFromJson(FinalContractSnapshot& snapshot, const QJsonObject& obj);
    QString describeRepoTerms(const TradeRequestInfo& info, const QString& perspectiveRole) const;
    QString describeForwardTerms(const TradeRequestInfo& info, const QString& perspectiveRole) const;

    // Computed metrics from immutable blockchain parameters
    struct ComputedMetrics {
        double apr{0.0};
        double ltv{0.0};
        int tenor_days{0};
        int maturity_height{0};
        bool computed{false};  // false if immutable params missing
    };
    ComputedMetrics computeMetricsFromImmutables(
        double principal_qty, const QString& principal_asset,
        double collateral_qty, const QString& collateral_asset,
        double interest_qty, const QString& interest_asset,
        int maturity_height) const;

    void scheduleRepoMtmUpdate(QTableWidget* table, int row, const OfferInfo& info, const QVariantMap& inlineTerms);
    void applyRepoMtmResult(QTableWidget* table, int row, const QString& offerId,
                            const std::optional<double>& markMtm,
                            const std::optional<double>& marketMtm);

    void scheduleForwardMtmUpdate(QTableWidget* table, int row, const OfferInfo& info, const QVariantMap& inlineTerms);
    void applyForwardMtmResult(QTableWidget* table, int row, const QString& offerId, const QString& makerRole,
                               const std::optional<double>& markMtm,
                               const std::optional<double>& marketMtm);

    void scheduleSpotMtmUpdate(QTableWidget* table, int row, const OfferInfo& info);
    void applySpotMtmResult(QTableWidget* table, int row, const QString& offerId,
                            const std::optional<double>& markMtm,
                            const std::optional<double>& marketMtm);

    qulonglong convertToAtomicUnits(double amount, const QString& asset_id) const;
    int assetDecimals(const QString& asset_id) const;
    QByteArray hashInlineTerms(const QVariantMap& inlineTerms) const;

    // Helper to get asset price in TSC from AssetPriceTab or QSettings
    double priceInTSC(const QString& symbolRaw) const;

    // Contract flavor cache - canonical contract type keyed by contract ID
    // This survives UI refreshes and ensures both maker/taker see consistent classification
    struct ContractFlavor {
        QString contract_type;      // "repo", "forward", "option", or "spot" (canonical)
        QString contract_id;        // final_offer_id or offer_id
        QString full_payload_json;  // Full contract JSON for reference
        int64_t cached_at{0};       // Timestamp when cached

        bool isRepo() const { return contract_type == "repo"; }
        bool isForward() const { return contract_type == "forward" || contract_type == "option"; }
        bool isSpot() const { return contract_type == "spot"; }
    };

    // Contract flavor detection and caching
    ContractFlavor detectContractFlavor(const QString& contractId, const QVariantMap& summary, const QString& payloadJson);
    void cacheContractFlavor(const QString& contractId,
                             const QString& contractType,
                             const QString& payloadJson,
                             const QString& legacyOfferId = QString());
    QString getCanonicalContractType(const QString& contractId);
    bool ensureContractFlavorLoaded(const QString& contractId, const QString& fallbackSummaryType = QString());

    // Snapshot builder functions - parse JSON into immutable snapshot
    FinalContractSnapshot createTakerSnapshot(
        const QString& request_id,
        const QString& session_id,
        const QString& offer_id,
        const QString& offer_json,
        const QString& maker_base_psbt,
        const QString& user_role,
        const QString& fee_strategy,
        const TradeRequestInfo& fallbackInfo,
        const QString& contract_type_hint = QString());

    FinalContractSnapshot createMakerSnapshot(
        const QString& request_id,
        const QString& session_id,
        const QString& offer_id,
        const QString& offer_json,
        const QString& acceptance_json,
        const QString& user_role);

    // Helper to build summary HTML from snapshot
    QString buildSummaryHtml(const FinalContractSnapshot& snapshot) const;
    QStringList buildCriticalChecks(const FinalContractSnapshot& snapshot) const;

    void handleFinalizedOfferReceived(const QString& session_id, const QString& request_id, const QString& offer_json, const QString& makerBasePsbt);
    void handleAcceptanceReceived(const QString& session_id, const QString& request_id, const QString& acceptance_json);
    // Maker side of the difficulty session flow: import the taker's acceptance, build the maker's base
    // (difficulty.build_open[_option]), and send the standard maker_base_psbt so the generic ceremony runs.
    void handleDifficultyAcceptanceReceived(const QString& session_id, const QString& request_id, const QJsonObject& msg);
    void handleCeremonyInviteReceived(const QString& session_id, const QString& invite_json);
    void launchOpeningCeremony(const QString& offer_id, const QString& session_id, const QString& maker_role);
    void launchOpeningCeremonyTaker(const QString& offer_id, const QString& session_id, const QString& maker_role);
    void maybeStartTakerCeremony(const QString& session_id, const QString& maker_role = QString());
    void startPreparedTakerCeremony(const QString& offer_id,
                                    const QString& session_id,
                                    TradeRequestInfo& info,
                                    const QString& maker_role);
    void sendCeremonyError(const QString& session_id,
                           const QString& stage,
                           const QString& detail) const;
    // NEW snapshot-based workflows (timer-safe)
    void startTakerAcceptanceWorkflow(const FinalContractSnapshot& snapshot);
    void startMakerConfirmationWorkflow(const FinalContractSnapshot& snapshot);

    // OLD workflows (DEPRECATED - will be removed after migration)
    void startTakerAcceptanceWorkflow(const QString& request_id,
                                      const QString& offer_id,
                                      const QString& session_id,
                                      const QString& offer_json,
                                      const TradeRequestInfo& reqInfo,
                                      const QString& fee_strategy = "medium");
    void startMakerConfirmationWorkflow(const QString& request_id,
                                        const QString& offer_id,
                                        const QString& session_id,
                                        const QString& maker_role,
                                        const QString& acceptancePayloadJson,
                                        TradeRequestInfo reqInfo);
    void handleSessionLoss(const QString& session_id,
                           const QString& request_id,
                           const QString& errorText);

    // Cross-chain session message handlers
    void handleXchainAccept(const QString& session_id, const QString& request_id, const QJsonObject& msg);
    void handleXchainParams(const QString& session_id, const QString& request_id, const QJsonObject& msg);
    void recoverTakerSession(const QString& request_id);
    void recoverMakerSession(const QString& request_id);
    void showNonBlockingInfo(const QString& title, const QString& text);
    void showAutoClosingInfo(const QString& title, const QString& text, int milliseconds = 3000);
    void showNonBlockingDecision(const QString& title, const QString& text, const QString& acceptLabel, const std::function<void()>& onAccept, const QString& rejectLabel, const std::function<void()>& onReject = {});
    void onHandshakeCompleteMaker(const QString& session_id, const QString& request_id, const QString& finalizedOfferId, const QString& finalizedOfferJson, const QVariantMap& handshakeResult);
    void onHandshakeCompleteTaker(const QString& session_id, const QString& request_id, const QVariantMap& handshakeResult);

    // Timer control for modal dialog safety
    void pauseUpdateTimers();
    void resumeUpdateTimers();

    // QPointer auto-nulls on WalletModel QObject destruction. Existing
    // `if (!walletModel)` checks in timer slots / async callbacks then catch
    // a destroyed wallet model instead of dereferencing freed memory.
    QPointer<WalletModel> walletModel;
    BridgeSessionManager* sessionManager{nullptr};
    AssetPriceTab* assetPriceTab{nullptr};
    const PlatformStyle* platformStyle{nullptr};
    mutable QHash<QString, int> assetDecimalsCache;
    struct RepoMtmCacheEntry {
        QByteArray terms_hash;
        std::optional<double> mark_mtm;
        std::optional<double> market_mtm;
    };
    QHash<QString, RepoMtmCacheEntry> repoMtmCache;
    QSet<QString> repoMtmPending;

    struct ForwardMtmCacheEntry {
        QByteArray terms_hash;
        std::optional<double> mark_mtm;
        std::optional<double> market_mtm;
    };
    QHash<QString, ForwardMtmCacheEntry> forwardMtmCache;
    QSet<QString> forwardMtmPending;

    // Transport preferences per offer (offer_id → transport: "ws", "tor", "auto")
    // Stores user's wizard selection so we use the same transport when accepting requests
    QHash<QString, QString> offerTransportPreferences;

    // UI components - Status section
    QLabel* bbStatusLabel{nullptr};
    QLabel* bbPubkeyLabel{nullptr};
    QLabel* bbRelaysLabel{nullptr};
    QLabel* bbCacheTimerLabel{nullptr};
    QLabel* torStatusLabel{nullptr};
    QPushButton* forceRestartButton{nullptr};
    QPushButton* forceRefreshButton{nullptr};

    // UI components - Offers section
    QPushButton* spotButton{nullptr};
    QPushButton* repoButton{nullptr};
    QPushButton* forwardButton{nullptr};
    QPushButton* optionButton{nullptr};
    QPushButton* crossChainButton{nullptr};
    QPushButton* difficultyButton{nullptr};
    QPushButton* profilesButton{nullptr};
    QPushButton* startManagerButton{nullptr};
    QPushButton* createContractButton{nullptr};
    QPushButton* offersRefreshButton{nullptr};
    QTableWidget* repoTable{nullptr};
    QTableWidget* forwardTable{nullptr};
    QTableWidget* optionsTable{nullptr};
    QTableWidget* spotTable{nullptr};
    QTableWidget* crossChainTable{nullptr};
    QTableWidget* difficultyTable{nullptr};
    CrossChainTradeView* crossChainTradeView{nullptr};

    // UI components - Trade Requests section
    QTableWidget* requestsTable{nullptr};

    // Filter state
    QString currentContractType;  // "repo", "forward", "options", "spot", "cross_chain"

    // Filter settings
    struct FilterSettings {
        bool filterNonRegistryAssets{true};  // Hide assets not in registry
        bool filterByMinAmount{false};
        double minAmount{0.0};
        bool filterByMaxAmount{false};
        double maxAmount{0.0};
        QString assetFilter;  // Asset symbol or ID filter
        QString roleFilter;   // "all", "lender", "borrower", "long", "short"
    } filterSettings;

    // Data tracking
    QMap<QString, OfferInfo> activeOffers;
    QMap<QString, TradeRequestInfo> activeRequests;
    // Contract flavor cache keyed by both bulletin-board offer UUID and canonical 32-byte contract id
    QMap<QString, ContractFlavor> contractFlavorCache;

    // Update timers
    QTimer* offersUpdateTimer{nullptr};
    QTimer* requestsUpdateTimer{nullptr};
    QTimer* cacheTimerUpdateTimer{nullptr};
    QTimer* sessionPollTimer{nullptr};

    // Pending cross-chain requests (request_id set, waiting for session)
    QSet<QString> pendingXchainRequests;

    // Bulletin Board status cache
    bool bbInitialized{false};
    QString bbPubkey;
    int bbRelayCount{0};
    QDateTime lastCacheRefresh;

    // Active session tracking for message polling
    QMap<QString, QString> activeSessions; // session_id -> request_id
    QSet<QString> ceremonySessions;

    // Track sessions that have shown handshake failure - prevent infinite popups
    QSet<QString> handshakeFailureShown;

    // Auto-join is driven by the request refresh timer. Keep request/session
    // attempts outside activeRequests so a failed handshake cannot be retried
    // every refresh after activeRequests is rebuilt from bulletin-board data.
    // Request keys include the invite link, so a genuinely new invite can run.
    QSet<QString> autoJoinAttemptedRequests;
    QSet<QString> autoJoinInFlightRequests;
    QSet<QString> autoJoinAttemptedSessions;
    QSet<QString> autoJoinInFlightSessions;

    // In-flight async work tracking. Several methods kick off body lambdas
    // via QtConcurrent::run([this, ...]) that read TradeBoardTab state on a
    // thread-pool thread. If `this` is destroyed while a body is still
    // running, the lambda dereferences freed memory — undefined behaviour
    // that has manifested as shutdown SIGABRT (QObject::~QObject ->
    // std::terminate, see 2026-05-23 crash 7BB19689-...). The counter +
    // condition variable below let the destructor wait (bounded) until
    // every running body has finished before destroying members.
    //
    // Each tracked call site captures a shared_ptr<InflightGuard> by value
    // into its body lambda. The guard's ctor increments the counter, its
    // dtor decrements — so the count is symmetric even if the body throws.
    // The finished lambda risk (queued slot fires after this is destroyed)
    // is mitigated separately by parenting QFutureWatchers to this so Qt's
    // child cleanup disconnects them before any queued slot can fire.
    int m_inflight_count{0};
    mutable std::mutex m_inflight_mutex;
    std::condition_variable m_inflight_cv;

    // Session polling is split across threads so the 500ms timer never blocks
    // the GUI thread on per-session cosignRecv() bridge round-trips:
    //   pollSessionMessages()          — GUI thread: snapshot sessions, dispatch
    //   (QtConcurrent body)            — worker:     run the blocking cosignRecv batch
    //   processPolledSessionMessages() — GUI thread: run the message state machine
    // All of m_sessionPollInFlight / m_sessionsBeingPolled / m_deferredCeremony-
    // Starts are GUI-thread-only state (mutated solely from the timer slot and
    // the watcher's finished slot, both on the GUI thread) — no locking needed.
    struct PolledSessionRecv {
        QString session_id;
        WalletModel::CosignRecvResult result;
    };
    // Skips a 500ms tick while a batch is in flight so ticks can't pile up behind
    // the cosign bridge's serialized mutex.
    bool m_sessionPollInFlight{false};
    // Sessions whose next frame is being (or has been) consumed off-thread by the
    // current poll batch. While a session is here, cosignRecv() may have already
    // popped its frame, so launchOpeningCeremony()/startPreparedTakerCeremony()
    // must NOT take ownership — they defer until the poll continuation releases
    // the claim and applies the frame.
    QSet<QString> m_sessionsBeingPolled;
    // Ceremony starts deferred because their session was mid-poll; replayed by
    // drainDeferredCeremonyStarts() once the poll continuation releases the claim.
    struct PendingCeremonyStart {
        bool isMaker;
        QString offer_id;
        QString session_id;
        QString request_id;   // taker only: re-resolve TradeRequestInfo at replay
        QString maker_role;
    };
    QList<PendingCeremonyStart> m_deferredCeremonyStarts;
    void processPolledSessionMessages(const QList<PolledSessionRecv>& polled);
    void drainDeferredCeremonyStarts();

    // updateTradeRequestsList() fetches the bulletin board off-thread (cosign
    // bridge round-trip) and renders in renderTradeRequests() on the GUI thread.
    // In-flight skips overlapping fetches; pending records that a refresh was
    // requested mid-fetch so the continuation re-dispatches (no lost refresh).
    // Both are GUI-thread-only.
    bool m_tradeRequestsUpdateInFlight{false};
    bool m_tradeRequestsUpdatePending{false};
    void renderTradeRequests(WalletModel::BulletinBoardListRequestsResult result);

    // updateOffersList() fetches the bulletin board off-thread (cosign bridge ->
    // Nostr relay round-trip) and rebuilds the offer tables in renderOffers() on
    // the GUI thread — same shape as the trade-requests path above. In-flight skips
    // overlapping fetches; pending records that a refresh was requested mid-fetch so
    // the continuation re-dispatches (no lost refresh). Both are GUI-thread-only.
    bool m_offersUpdateInFlight{false};
    bool m_offersUpdatePending{false};
    // Latches force-refresh intent for a coalesced request so the continuation's
    // re-dispatch does not silently degrade a user's force refresh into a cached one.
    bool m_offersUpdatePendingForceRefresh{false};
    // Set when renderOffers() drops a completed fetch because a modal was open
    // (see renderOffers()); resumeUpdateTimers() re-dispatches so the tables don't
    // stay stale until the next periodic tick.
    bool m_offersRenderDeferredByModal{false};
    // Shared async dispatcher behind updateOffersList() (force_refresh=false) and
    // onForceRefresh() (force_refresh=true). Runs the relay fetch off-thread.
    void dispatchOffersFetch(bool force_refresh);
    void renderOffers(WalletModel::BulletinBoardListOffersResult result);

    class InflightGuard {
    public:
        explicit InflightGuard(TradeBoardTab* tab) noexcept;
        ~InflightGuard();
        InflightGuard(const InflightGuard&) = delete;
        InflightGuard& operator=(const InflightGuard&) = delete;
        InflightGuard(InflightGuard&&) = delete;
        InflightGuard& operator=(InflightGuard&&) = delete;
    private:
        TradeBoardTab* m_tab;
    };

    void incrementInflight();
    void decrementInflight();
    // Block (up to 5 seconds) until in-flight bodies complete. Called from
    // the destructor before Qt's child-cleanup cascade. If the timeout
    // expires with outstanding work, logs the count and proceeds anyway —
    // the try/catch in BitcoinApplication::~BitcoinApplication is the
    // last-line backstop for the resulting throw.
    void waitForInflightShutdown();
};

#endif // BITCOIN_QT_TRADEBOARDTAB_H
