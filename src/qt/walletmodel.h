// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODEL_H
#define BITCOIN_QT_WALLETMODEL_H

#include <key.h>

#include <qt/walletmodeltransaction.h>

#include <interfaces/wallet.h>
#include <support/allocators/secure.h>
#include <util/transaction_identifier.h>

#include <mutex>
#include <vector>

#include <QCache>
#include <QObject>
#include <QPair>
#include <QVariantMap>
#include <QStringList>

enum class OutputType;

class AddressTableModel;
class ClientModel;
class OptionsModel;
class PlatformStyle;
class RecentRequestsTableModel;
class SendCoinsRecipient;
class TransactionTableModel;
class WalletModelTransaction;

class CKeyID;
class COutPoint;
class CPubKey;
class uint256;

namespace interfaces {
class Node;
} // namespace interfaces
namespace wallet {
class CCoinControl;
} // namespace wallet

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

/** Interface to Bitcoin wallet from Qt view code. */
class WalletModel : public QObject
{
    Q_OBJECT

public:
    explicit WalletModel(std::unique_ptr<interfaces::Wallet> wallet, ClientModel& client_model, const PlatformStyle *platformStyle, QObject *parent = nullptr);
    ~WalletModel();

    enum StatusCode // Returned by sendCoins
    {
        OK,
        InvalidAmount,
        InvalidAddress,
        AmountExceedsBalance,
        AmountWithFeeExceedsBalance,
        DuplicateAddress,
        TransactionCreationFailed, // Error returned when wallet is still locked
        AbsurdFee
    };

    enum EncryptionStatus
    {
        NoKeys,       // wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)
        Unencrypted,  // !wallet->IsCrypted()
        Locked,       // wallet->IsCrypted() && wallet->IsLocked()
        Unlocked      // wallet->IsCrypted() && !wallet->IsLocked()
    };

    OptionsModel* getOptionsModel() const;
    AddressTableModel* getAddressTableModel() const;
    TransactionTableModel* getTransactionTableModel() const;
    RecentRequestsTableModel* getRecentRequestsTableModel() const;

    EncryptionStatus getEncryptionStatus() const;

    // Check address for validity
    bool validateAddress(const QString& address) const;

    // Return status record for SendCoins, contains error id + information
    struct SendCoinsReturn
    {
        SendCoinsReturn(StatusCode _status = OK, QString _reasonCommitFailed = "")
            : status(_status),
              reasonCommitFailed(_reasonCommitFailed)
        {
        }
        StatusCode status;
        QString reasonCommitFailed;
    };

    // prepare transaction for getting txfee before sending coins
    SendCoinsReturn prepareTransaction(WalletModelTransaction &transaction, const wallet::CCoinControl& coinControl);

    // prepare asset transaction
    SendCoinsReturn prepareAssetTransaction(WalletModelTransaction &transaction, const wallet::CCoinControl& coinControl, const uint256& asset_id);

    // Send coins to a list of recipients
    void sendCoins(WalletModelTransaction& transaction);

    // Wallet encryption
    bool setWalletEncrypted(const SecureString& passphrase);
    // Passphrase only needed when unlocking
    bool setWalletLocked(bool locked, const SecureString &passPhrase=SecureString());
    bool changePassphrase(const SecureString &oldPass, const SecureString &newPass);

    // RAII object for unlocking wallet, returned by requestUnlock()
    class UnlockContext
    {
    public:
        UnlockContext(WalletModel *wallet, bool valid, bool relock);
        ~UnlockContext();

        bool isValid() const { return valid; }

        // Disable unused copy/move constructors/assignments explicitly.
        UnlockContext(const UnlockContext&) = delete;
        UnlockContext(UnlockContext&&) = delete;
        UnlockContext& operator=(const UnlockContext&) = delete;
        UnlockContext& operator=(UnlockContext&&) = delete;

    private:
        WalletModel *wallet;
        const bool valid;
        const bool relock;
    };

    UnlockContext requestUnlock();

    bool bumpFee(Txid hash, Txid& new_hash);
    void displayAddress(std::string sAddress) const;

    static bool isWalletEnabled();

    interfaces::Node& node() const { return m_node; }
    interfaces::Wallet& wallet() const { return *m_wallet; }
    ClientModel& clientModel() const { return *m_client_model; }
    void setClientModel(ClientModel* client_model);

    QString getWalletName() const;
    bool unlockCoins(const QList<QPair<QString, int>>& outputs) const;
    QString getDisplayName() const;

    bool isMultiwallet() const;

    void refresh(bool pk_hash_only = false);

    uint256 getLastBlockProcessed() const;

    // Retrieve the cached wallet balance
    interfaces::WalletBalances getCachedBalance() const;

    // If coin control has selected outputs, searches the total amount inside the wallet.
    // Otherwise, uses the wallet's cached available balance.
    CAmount getAvailableBalance(const wallet::CCoinControl* control);

    // Asset balance methods
    std::vector<interfaces::AssetBalance> getAssetBalances() const;
    void refreshAssetBalances();

    // ML-DSA (Post-Quantum) address generation
    struct MLDSAAddressInfo {
        QString address;
        QString pubkey;
        QString scriptPubKey;
        QString tapscript;
        QString internal_pubkey;
        QString merkle_root;
        QString output_pubkey;
        QString leaf_hash;
        QString encoded_pubkey;
        int level;
        bool parity;
        QString warning;
        bool success;
        QString error;
    };

    MLDSAAddressInfo generateMLDSAAddress(int level = 65);
    bool mldsaEnabled() const;

    // Cosign bridge RPC wrappers
    struct CosignInitResult {
        bool success{false};
        QString session_id;
        QString invite_link;
        QString invite_code;
        QString qr_data;
        QString sas;
        QString sas_numeric;
        QString transport_selected;
        QString error;
    };

    struct CosignJoinResult {
        bool success{false};
        QString session_id;
        QString sas;
        QString sas_numeric;
        QString transport;
        QString relay_url;
        QString error;
    };

    struct CosignHandshakeResult {
        bool success{false};
        bool handshake_complete{false};
        QString sas;
        QString sas_numeric;
        QString message;
        QString error;
    };

    struct CosignSendResult {
        bool success{false};
        bool ok{false};
        int seq{0};
        QString error;
    };

    struct CosignRecvResult {
        bool success{false};
        QString payload_json;
        QString error;
    };

    struct CosignStatusResult {
        bool success{false};
        QString state;
        bool peer_verified{false};
        int messages_sent{0};
        int messages_received{0};
        int age_sec{0};
        int ttl_sec{0};
        QString transport;
        QString error;
    };

    struct CosignPingResult {
        bool success{false};
        bool bridge_alive{false};
        QString version;
        QStringList transports;
        int uptime_sec{0};
        QStringList capabilities;
        QString error;
    };

    struct CosignAttestResult {
        bool success{false};
        QString challenge;      // Step 1: challenge to sign
        bool verified{false};   // Step 2: verification result
        QString error;
    };

    CosignInitResult cosignInit(const QString& context = "", const QString& transport = "auto", int ttl_sec = 1800, const QString& relay_url = "");
    CosignJoinResult cosignJoin(const QString& invite_link, const QString& context = "");
    CosignHandshakeResult cosignHandshakeAuto(const QString& session_id, bool is_initiator = false);
    CosignSendResult cosignSend(const QString& session_id, const QString& payload_json);
    CosignRecvResult cosignRecv(const QString& session_id, int timeout_ms = 30000);
    bool cosignClose(const QString& session_id);
    CosignStatusResult cosignStatus(const QString& session_id);
    CosignPingResult cosignPing();
    CosignAttestResult cosignAttest(const QString& session_id, const QString& address, const QString& signature = "");

    // Bulletin Board Trading RPCs
    struct BulletinBoardInitResult {
        bool success{false};
        QString pubkey;
        QStringList relays;
        QString error;
    };

    struct BulletinBoardPostOfferResult {
        bool success{false};
        QString offer_id;
        QString error;
    };

    struct BulletinBoardListOffersResult {
        bool success{false};
        QVariantList offers;  // List of offer objects
        QString error;
    };

    struct BulletinBoardRequestTradeResult {
        bool success{false};
        QString request_id;
        QString error;
    };

    struct BulletinBoardListRequestsResult {
        bool success{false};
        QVariantList requests;  // List of request objects
        QString error;
    };

    struct BulletinBoardAcceptRequestResult {
        bool success{false};
        QString invite_link;
        QString session_id;
        QString transport;
        QString relay_url;
        QString error;
        // NOTE: SAS is NOT included here because it's meaningless before handshake.
        // SAS will be available after calling cosignHandshakeAuto on this session.
    };

    BulletinBoardInitResult bulletinBoardInit(const QStringList& relays, const QString& key_path = "");
    BulletinBoardPostOfferResult bulletinBoardPostOffer(const QString& offer_type, const QString& asset_label, const QString& amount, const QString& price_btc, const QString& memo = "");
    BulletinBoardPostOfferResult bulletinBoardPostContractOffer(const QString& contract_type, const QString& contract_payload, const QString& maker_role, double apr = 0.0, double ltv = 0.0, int tenor_days = 0, const QVariantList& proof_of_funds = QVariantList());
    BulletinBoardListOffersResult bulletinBoardListOffers(const QString& offer_type = "", const QString& asset_label = "", int since = 0, bool force_refresh = false);

    // Cross-chain settlement
    struct CrossChainPostResult {
        bool success{false};
        QString offer_id;
        QString schema;
        QString external_chain;
        QString adapter;
        QString funding_order;
        QString error;
    };

    struct CrossChainValidateResult {
        bool valid{false};
        QString schema;
        QString external_chain;
        QString error;
    };

    struct CrossChainOfferItem {
        QString offer_id;
        QString maker_pubkey;
        QString network;
        QVariantMap payload;  // Parsed cross_chain_payload
    };

    struct CrossChainListResult {
        bool success{false};
        QList<CrossChainOfferItem> offers;
        QString error;
    };

    struct SettlementProfileItem {
        QString profile_id;
        QString label;
        QString chain;
        QString address;
        QString signer_ref;
        QString preferred_asset;
        QString fee_speed;
    };

    CrossChainPostResult crossChainPostOffer(const QString& payload_json, const QVariantList& proof_of_funds = QVariantList());
    CrossChainValidateResult crossChainValidatePayload(const QString& payload_json);
    CrossChainListResult crossChainListOffers(const QString& external_chain = "", const QString& adapter = "", bool force_refresh = false);

    struct SettlementProfileAddResult {
        bool success{false};
        QString error;
    };

    SettlementProfileAddResult settlementProfileAdd(const QString& profile_id, const QString& label, const QString& chain, const QString& address, const QString& signer_ref, const QString& preferred_asset, const QString& fee_speed = "normal");
    bool settlementProfileRemove(const QString& profile_id);
    QList<SettlementProfileItem> settlementProfileList();

    // Cross-chain execution records (wallet-persisted, restart-safe)
    struct CrossChainRecordItem {
        QString swap_id;
        QString offer_id;
        int state{0};
        QString local_role;
        QString counterparty_pubkey;
        QString external_chain;
        QString adapter;
        QString tsc_funding_txid;
        QString external_funding_txid;
        int external_conf_depth{0};
        int tsc_conf_depth{0};
        int fee_escalation_level{0};
        qint64 created_time{0};
        qint64 updated_time{0};
        QString payload_json;         // Full payload for detail view
        QString oracle_attestation;
        QString adaptor_secret_ref;
        // HTLC execution artifacts (V2)
        QString htlc_contract_address;
        QString htlc_swap_id;
        QString external_signer_ref;
        QString claim_tx_hash;
        QString refund_tx_hash;
        QString external_lock_tx_hash;
        qint64 htlc_timelock{0};
    };

    QList<CrossChainRecordItem> crossChainRecordList();
    std::optional<CrossChainRecordItem> crossChainRecordGet(const QString& swap_id);

    // ETH HTLC read-only operations (status queries, attestation verification)
    struct EthInitResult { bool success{false}; QString rpc_url; QString error; };
    struct EthSwapStatusResult {
        bool success{false};
        int state{0};
        QString state_name;
        QString sender;
        QString recipient;
        QString token_address;
        QString amount;
        QString secret_hash;
        qint64 timelock{0};
        qint64 confirmation_depth{-1};
        QString error;
    };
    struct EthVerifyAttestationResult { bool valid{false}; QString swap_id; qint64 confirmation_depth{0}; QString error; };

    EthInitResult ethInit(const QString& rpc_url);
    EthSwapStatusResult ethGetSwapStatus(const QString& htlc_address, const QString& swap_id, const QString& lock_tx_hash = "");
    EthVerifyAttestationResult ethVerifyAttestation(const QString& oracle_pubkey, const QVariantMap& attestation);

    // HTLC mutation methods are intentionally NOT exposed through the Qt
    // GUI layer.  Lock/claim/refund operations are driven exclusively by
    // the CrossChainSwapManager through the HtlcBackend interface, which
    // uses signer_ref from the persisted CrossChainRecord.  The signing
    // key never transits the Qt/RPC boundary.
    //
    // Read-only operations (ethInit, ethGetSwapStatus, ethVerifyAttestation)
    // are safe to expose to the UI.

    // ETH lock — user-initiated, taker locks ETH into HTLC
    struct EthLockHtlcResult {
        bool success{false};
        QString tx_hash;
        QString from;
        QString error;
    };
    EthLockHtlcResult ethLockHtlc(
        const QString& htlc_address, const QString& swap_id,
        const QString& recipient, const QString& secret_hash,
        qint64 timelock, const QString& amount_wei,
        const QString& signing_key,
        const QString& token_address = "");

    // Cross-chain session automation helpers
    struct CrossChainCreateRecordResult { bool success{false}; QString error; };
    CrossChainCreateRecordResult crossChainCreateRecord(
        const QString& swap_id, const QString& offer_id,
        const QString& chain, const QString& adapter,
        const QString& funding_order, const QString& role,
        const QString& payload_json);
    bool crossChainSetHtlcParams(
        const QString& swap_id, const QString& htlc_address,
        const QString& htlc_swap_id, const QString& signer_ref,
        const QString& claim_secret,
        const QString& expected_secret_hash = "",
        const QString& expected_recipient = "",
        const QString& expected_amount = "",
        const QString& expected_token_address = "");
    bool crossChainRegisterSwap(const QString& swap_id);
    bool crossChainUpdateSessionAddresses(const QString& swap_id,
                                          const QString& taker_tsc_address,
                                          const QString& taker_refund_address);

    // Manager bootstrap
    struct CrossChainStartManagerResult {
        bool success{false};
        int active_swaps{0};
        QString mode;
        bool dual_provider{false};
        QString error;
    };
    CrossChainStartManagerResult crossChainStartManager(
        const QString& eth_rpc_url,
        const QString& eth_rpc_url_secondary = "",
        const QString& oracle_pubkey = "",
        const QString& eth_derivation_seed = "");

    BulletinBoardRequestTradeResult bulletinBoardRequestTrade(const QString& offer_id, const QString& message = "", const QVariantList& proof_of_funds = QVariantList());
    BulletinBoardListRequestsResult bulletinBoardListRequests(const QString& filter = "all");
    BulletinBoardAcceptRequestResult bulletinBoardAcceptRequest(const QString& request_id, const QString& transport = "auto");
    bool bulletinBoardRejectRequest(const QString& request_id);
    bool bulletinBoardCancelRequest(const QString& request_id);
    bool bulletinBoardDeleteOffer(const QString& offer_id);

    // Governance RPCs
    struct GovernanceListProposalsResult {
        bool success{false};
        QVariantList proposals;  // List of proposal summary objects
        QString error;
    };

    GovernanceListProposalsResult governanceListProposals(const QString& asset_id = "", bool include_expired = false);
    bool governanceForceRefresh();
    bool verifyMessage(const QString& address, const QString& signature, const QString& message);
    bool verifyMessageBip322(const QString& address, const QString& signature, const QString& message);
    QString signMessageBip322(const QString& address, const QString& message);
    QString getBridgeNostrPubkey();  // Get holder's nostr pubkey from bridge

    // Ownership proof verification (blockchain-scoped via gettxout).
    // Implements the same strict rules as proof_verify::VerifyOwnershipProof()
    // but uses interfaces::Node RPC path. Both must produce identical verdicts.
    struct OwnershipProofVerifyResult {
        bool verified{false};
        QString error;
        uint64_t actual_units{0};
        QString actual_address;
        QString bestblock;
    };
    OwnershipProofVerifyResult verifyOwnershipProof(const QString& utxo_ref, const QString& address, const QString& message, const QString& signature, const QString& asset_id, uint64_t claimed_units);

    struct AggregateProofVerifyResult {
        bool all_verified{false};
        uint64_t total_verified_units{0};
        QString asset_id;
        int verified_count{0};
        int failed_count{0};
        QString error;
    };
    AggregateProofVerifyResult verifyProofList(const QVariantList& proofs);

    // Per-proof verification result, cached inside verifyProofList() so
    // repeated updateTradeRequestsList() ticks within the same block don't
    // re-issue gettxout RPCs for the same UTXOs. Stored as values inside
    // a QCache keyed by (utxo_ref, address, sha256(signature), asset_id,
    // claimed_units). Stale on chain reorg, but the cache value carries
    // the bestblock hash it was computed against, so a tip change invalidates
    // entries on lookup.
    struct CachedProofEntry {
        bool verified{false};
        uint64_t actual_units{0};
        QString error;
        QString actual_address;
        QString bestblock;
    };

    struct CreateProofOfFundsResult {
        bool success{false};
        QVariantList proofs;
        uint64_t total_units{0};
        QString error;
    };
    CreateProofOfFundsResult createProofOfFunds(const QString& asset_id, uint64_t required_units, const QString& context);

    /** Create a BIP-322 discussion proof with canonical TENSORCASH_DISCUSS:v1:... message.
     *  Signs over native TSC UTXOs to prove stake for discussion posting rights. */
    CreateProofOfFundsResult createDiscussionProof(
        const QString& scope_type,     // "model_prealert" or "model_challenge"
        const QString& scope_id,       // model_hash or challenge_block_hash (hex)
        const QString& network,        // "main", "signet", "testnet3", "regtest"
        const QString& nostr_pubkey,   // hex Nostr pubkey from bridge
        int expiry_height,             // block height after which proof expires
        uint64_t min_units);           // minimum stake in satoshis

    // Asset UTXO methods
    QList<QVariant> listAssetUTXOs(const QString& asset_id);

    // Repo contract RPCs
    struct RepoProposeResult {
        bool success{false};
        QString offer_id;
        QString offer_json;
        QVariantMap offer_data;
        QString error;
    };

    struct RepoImportOfferResult {
        bool success{false};
        QString offer_id;
        QString error;
    };

    struct RepoAcceptResult {
        bool success{false};
        QString acceptance_id;
        QString acceptance_json;  // Full JSON string (may include wrapper)
        QString acceptance_obj_json;  // Just the "acceptance" object as JSON
        QVariantMap acceptance_data;
        QString error;
    };

    struct RepoImportAcceptanceResult {
        bool success{false};
        QString acceptance_id;
        QString error;
    };

    struct RepoBuildOpenResult {
        bool success{false};
        QString psbt;
        QString session_id;
        bool is_initiator{false};
        QString error;
    };

    struct ForwardBuildOpenResult {
        bool success{false};
        QString psbt;
        int alice_vault_index{-1};  // Long party IM vault output index
        int bob_vault_index{-1};    // Short party IM vault output index
        int premium_output_index{-1};  // Premium payment output index (optional, -1 if none)
        QString error;
        QVariantMap raw_response;  // Full RPC response for debugging
    };

    struct CosignAdaptorRoundtripResult {
        bool success{false};
        QString psbt;
        bool complete{false};
        bool cancelled{false};
        bool session_lost{false};
        QString error;
        // Set true by the cooperative non-atomic signing path on the maker
        // side after broadcastPsbt has already submitted the transaction.
        // The post-ceremony handler MUST check this and short-circuit the
        // sign-again / broadcast block, otherwise a successful trade gets
        // broadcast twice and the second attempt surfaces a false-negative
        // "broadcast failed" dialog. txid carries the on-chain identifier.
        bool already_broadcast{false};
        QString txid;
    };

    struct AdaptorPrepareResult {
        bool success{false};
        QString psbt;
        QString error;
    };

    struct AdaptorPartialResult {
        bool success{false};
        QString psbt;
        bool complete{false};
        QString error;
    };

    struct AdaptorCompleteResult {
        bool success{false};
        QString psbt;
        bool complete{false};
        QString error;
    };

    struct CombinePsbtResult {
        bool success{false};
        QString psbt;
        QString error;
    };

    struct WalletProcessPsbtResult {
        bool success{false};
        QString psbt;
        QString error;
        bool complete{false};
    };

    struct BroadcastPsbtResult {
        bool success{false};
        QString txid;
        QString error;
    };

    RepoProposeResult repoPropose(const QVariantMap& terms);
    RepoImportOfferResult repoImportOffer(const QString& offer_json);
    RepoAcceptResult repoAccept(const QString& offer_id, bool confirmed);
    RepoImportAcceptanceResult repoImportAcceptance(const QString& acceptance_json);
    RepoBuildOpenResult repoBuildOpen(const QString& offer_id, const QVariantMap& fee_policy);

    // Forward/Options contract RPC wrappers
    ForwardBuildOpenResult forwardBuildOpen(const QString& offer_id, const QVariantMap& options);

    CosignAdaptorRoundtripResult cosignAdaptorRoundtrip(const QString& session_id, const QString& psbt, bool is_initiator);

    // Adaptor ceremony step-by-step methods
    AdaptorPrepareResult adaptorPrepare(const QString& psbt);
    AdaptorPartialResult adaptorPartial(const QString& psbt);
    AdaptorCompleteResult adaptorComplete(const QString& psbt);
    CombinePsbtResult combinePsbt(const QStringList& psbts);
    WalletProcessPsbtResult walletProcessPsbt(const QString& psbt,
                                              bool sign,
                                              const QString& sighash,
                                              bool bip32derivs,
                                              bool finalize);

    BroadcastPsbtResult broadcastPsbt(const QString& psbt);

    // Repo contract lifecycle operations
    struct RepoBuildResult {
        bool success{false};
        QString error;
        QString psbt;
        QString txid;
        bool complete{false};
        QString hex;
        int repayOutputIndex{-1};
        int collateralOutputIndex{-1};
        int sweepOutputIndex{-1};
        int vaultInputIndex{-1};
    };

    RepoBuildResult repoBuildRepayRelease(const QString& contractId, double feeRate = 2.0, const QVariantMap& extraOptions = QVariantMap());
    RepoBuildResult repoBuildDefaultSweep(const QString& contractId, double feeRate = 2.0, const QVariantMap& extraOptions = QVariantMap());

    // Forward contract RPC wrappers
    struct ForwardProposeResult {
        bool success{false};
        QString offer_id;
        QString offer_json;
        QVariantMap offer_data;
        QString error;
    };

    struct ForwardImportOfferResult {
        bool success{false};
        QString offer_id;
        QString error;
    };

    // Forward settlement result structures
    struct ForwardBuildSelfDeliveryResult {
        bool success{false};
        QString psbt;
        QString side; // "long" or "short"
        int vault_input_index{-1};
        int escrow_output_index{-1};
        int margin_output_index{-1};
        bool complete{false};
        QString hex;
        QString txid;
        QString error;
        QList<QPair<QString, int>> lockedInputs;
    };

    struct ForwardBuildEscrowClaimResult {
        bool success{false};
        QString psbt;
        int payment_output_index{-1};
        bool complete{false};
        QString hex;
        QString txid;
        QString error;
    };

    struct ForwardBuildEscrowRefundResult {
        bool success{false};
        QString psbt;
        int refund_output_index{-1};
        bool complete{false};
        QString hex;
        QString txid;
        QString error;
    };

    struct ForwardBuildIMTimeoutResult {
        bool success{false};
        QString psbt;
        int penalty_output_index{-1};
        bool complete{false};
        QString hex;
        QString txid;
        QString error;
    };

    struct ForwardAcceptResult {
        bool success{false};
        QString acceptance_id;
        QString acceptance_json;  // Full JSON string (may include wrapper)
        QString acceptance_obj_json;  // Just the "acceptance" object as JSON
        QVariantMap acceptance_data;
        QString error;
    };

    struct ForwardImportAcceptanceResult {
        bool success{false};
        QString acceptance_id;
        QString error;
    };

    ForwardProposeResult forwardPropose(const QVariantMap& terms);
    ForwardImportOfferResult forwardImportOffer(const QString& offer_json);
    ForwardAcceptResult forwardAccept(const QString& offer_id, bool confirmed = false);
    ForwardImportAcceptanceResult forwardImportAcceptance(const QString& acceptance_json);

    // Forward settlement RPC wrappers
    ForwardBuildSelfDeliveryResult forwardBuildSelfDelivery(const QString& contract_id, const QVariantMap& options = QVariantMap());
    ForwardBuildEscrowClaimResult forwardBuildEscrowClaim(const QString& contract_id, const QString& escrow_txid, int escrow_vout, const QVariantMap& options = QVariantMap());
    ForwardBuildEscrowRefundResult forwardBuildEscrowRefund(const QString& contract_id, const QString& escrow_txid, int escrow_vout, const QVariantMap& options = QVariantMap());
    ForwardBuildIMTimeoutResult forwardBuildIMTimeout(const QString& contract_id, const QString& vault_type, const QVariantMap& options = QVariantMap());

    // ── Difficulty-derivative RPC wrappers (CFD + option) ───────────────────────────────────────────────
    // Thin typed pass-throughs over the difficulty.* RPCs. Amounts are in native TSC (not BTC). The CFD
    // economics come in as a QVariantMap with keys: strike_nbits, fixing_height, settle_lock_height,
    // long_im (TSC), long_lambda_q, short_im (TSC), short_lambda_q. The option economics use: strike_nbits,
    // fixing_height, settle_lock_height, im (TSC), lambda_q, premium (TSC), writer_side ("long"/"short").
    struct DifficultyProposeResult {
        bool success{false};
        QString offer_json;       // the "offer" object as JSON, to hand to the counterparty
        QString error;
    };
    struct DifficultyAcceptResult {
        bool success{false};
        QString contract_id;
        QString acceptance_json;  // the "acceptance" object as JSON (empty when not confirmed)
        QString action_required;  // set when called without confirm (review step)
        bool confirmed{false};
        QString error;
    };
    struct DifficultyImportResult {
        bool success{false};
        QString contract_id;
        QString state;
        QString error;
    };
    struct DifficultyPsbtResult {
        bool success{false};
        QString psbt;
        QString hex;              // present for sign_coop (when complete) and finalize_settlement
        bool complete{false};
        QString leg;              // build_open: leg funded
        QString role;             // build_open_option: role funded ("writer"/"buyer")
        double fee{0.0};          // native TSC
        int vault_index{-1};      // build_open: vout of this leg's IM vault in the PSBT
        int vault_input_index{-1};// build_settlement: vin index of the spent vault
        double payout_owner{0.0}; // build_settlement: amount returned to the leg owner (TSC)
        double payout_cp{0.0};    // build_settlement: amount paid to the counterparty (TSC)
        QString error;
    };
    struct DifficultyRecordOpenResult {
        bool success{false};
        QString error;
    };

    DifficultyProposeResult difficultyPropose(const QVariantMap& econ, const QString& role,
                                              const QString& owner_addr, const QString& cp_addr);
    DifficultyProposeResult difficultyProposeOption(const QVariantMap& econ, const QString& role,
                                                    const QString& payout_addr);
    DifficultyAcceptResult difficultyAccept(const QString& offer_json, const QString& owner_addr,
                                            const QString& cp_addr, bool confirmed = false);
    DifficultyAcceptResult difficultyAcceptOption(const QString& offer_json, const QString& payout_addr,
                                                  bool confirmed = false);
    DifficultyImportResult difficultyImportAcceptance(const QString& offer_json, const QString& acceptance_json);
    DifficultyPsbtResult difficultyBuildOpen(const QString& contract_id, const QString& leg,
                                             const QString& partial_psbt = QString(), double fee_rate = 0.0);
    DifficultyPsbtResult difficultyBuildOpenOption(const QString& contract_id, const QString& role,
                                                   const QString& partial_psbt = QString(), double fee_rate = 0.0);
    DifficultyRecordOpenResult difficultyRecordOpen(const QString& contract_id, const QString& open_txid);
    DifficultyPsbtResult difficultyBuildSettlement(const QString& contract_id, const QString& leg, double fee_rate = 0.0);
    DifficultyPsbtResult difficultyFinalizeSettlement(const QString& psbt);
    DifficultyPsbtResult difficultyBuildCoopClose(const QString& contract_id, const QString& leg,
                                                  const QVariantList& outputs);
    DifficultyPsbtResult difficultySignCoop(const QString& contract_id, const QString& leg, const QString& psbt);

    // Sensible RPC-valid defaults for the difficulty wizard: the current chain height and the current
    // compact target (a canonical strike that decodes within powLimit, so a freshly-built offer validates).
    struct DifficultyChainDefaults {
        bool success{false};
        int height{0};
        QString strike_nbits;  // current compact target as 8-hex, e.g. "1d00ffff"
        QString error;
    };
    DifficultyChainDefaults difficultyChainDefaults();

    // ── Option-series (tokenized option) RPC wrappers ───────────────────────────────────────────────────
    // Thin typed pass-throughs over the optionseries.* RPCs (the GUI create/issue wizard). The series terms
    // are collected in OptionSeriesTermsInput; amounts (lot_im, reference_premium) are native TSC. writer_key
    // accepts an x-only hex key OR a P2TR (bech32m) address — for self-issuance it must be a wallet address so
    // the wallet can sign the ICU rotation / mint (and later settle/buy-back).
    struct OptionSeriesTermsInput {
        QString writer_key;            // 64-hex x-only OR a bech32m P2TR address
        quint32 strike_nbits{0};
        quint32 fixing_height{0};
        quint32 settle_lock_height{0};
        quint32 lambda_q{0};
        qint64  lot_im_sats{0};        // per-lot collateral, in sats (exact — these bytes go into the descriptor)
        quint32 lot_count{0};          // N
        qint64  reference_premium_sats{0}; // display/listing only, in sats
        QString series_salt;           // 64-hex (the dialog auto-generates one if left blank)
        int     direction{0};          // 0 = call (writer short), 1 = put (writer long) — descriptor v2
    };
    struct OptionSeriesDeriveResult {
        bool success{false};
        QString asset_id;              // canonical (descriptor) hex
        QString registry_asset_id;     // registry/display hex
        QString descriptor;            // the §2 descriptor bytes
        int lot_count{0};
        QString error;
    };
    struct OptionSeriesRegisterResult {
        bool success{false};
        QString asset_id;
        QString registry_asset_id;
        QString ticker;                // ROOT.SUFFIX
        QString icu_text;              // human-readable terms committed in the ICU
        QString txid;                  // registration tx (may be "(pending)")
        int lot_count{0};
        QString error;
    };
    struct OptionSeriesIssueResult {
        bool success{false};
        QString asset_id;
        QString registry_asset_id;
        int lot_count{0};
        double per_lot_im{0.0};        // TSC
        QString txid;                  // issuance (mint) tx
        QString error;
    };
    struct OptionSeriesRecordResult {
        bool success{false};
        QString asset_id;
        int lot_count{0};
        bool persisted{false};
        QString error;
    };

    OptionSeriesDeriveResult optionSeriesDerive(const OptionSeriesTermsInput& terms);
    OptionSeriesRegisterResult optionSeriesBuildRegister(const OptionSeriesTermsInput& terms, const QString& root,
                                                         const QString& suffix, qint64 child_bond_sats = 0,
                                                         double fee_rate = 0.0, bool broadcast = true);
    OptionSeriesIssueResult optionSeriesBuildIssue(const OptionSeriesTermsInput& terms, double fee_rate = 0.0,
                                                   bool broadcast = true);
    OptionSeriesRecordResult optionSeriesRecordIssue(const OptionSeriesTermsInput& terms, const QString& issue_txid);

    // One recorded series (optionseries.list).
    struct OptionSeriesListEntry {
        QString asset_id;
        QString registry_asset_id;
        int lot_count{0};
        QString issue_txid;
        QString icu_outpoint;
        int vault_count{0};
        QString terms_json;          // the full terms (round-trips into build_settlement/redeem/buyback)
    };
    struct OptionSeriesListResult {
        bool success{false};
        QList<OptionSeriesListEntry> series;
        QString error;
    };
    // The on-chain backing verdict (optionseries.verify + check_backing, against the published ICU band).
    struct OptionSeriesBackingResult {
        bool success{false};
        bool authentic{false};      // recomputed asset_id matches the queried id
        bool registered{false};
        bool invariants_ok{false};  // §2.5 registry invariants (cap=N / decimals0 / MINT / no-burn / quorum0 / public / P2TR)
        qint64 issued_total{0};
        int vaults_funded{0};
        int vaults_expected{0};
        bool verified{false};       // the gated overall verdict
        QString reason;
        QString resolved_asset_id;  // (verify-by-id) the resolved registry asset id
        QString ticker;             // (verify-by-id) the resolved ticker, if any
        int lot_count{0};           // N, for a holder redeem lot range
        QString terms_json;         // parser-compatible terms recovered from the on-chain descriptor -> redeem
        QString error;
    };
    OptionSeriesListResult optionSeriesList();
    // Verify backing for a recorded series: fetches its on-chain ICU metadata band and runs
    // optionseries.verify(asset_id, {icu_metadata}, {check_backing:true}) — a fraud-check against what is
    // actually published on chain, not the wallet's local record.
    OptionSeriesBackingResult optionSeriesVerifyBacking(const QString& registry_asset_id, const QString& asset_id);
    // Pre-purchase fraud check for ANY series (no wallet record needed): resolve a ticker or asset id via
    // getassetinfo, fetch its ICU metadata, and run optionseries.verify(..., {check_backing:true}).
    OptionSeriesBackingResult optionSeriesVerifyById(const QString& identifier);

    // A lifecycle action result (settle / redeem / buy-back). `txid` is the broadcast transaction id.
    struct OptionSeriesActionResult {
        bool success{false};
        QString txid;
        QString detail;        // a human summary for the status log
        QString pot_outpoint;  // (settle, ITM) the funded pot "txid:vout" — feeds redeem
        QString error;
    };
    // Settle ONE lot (keeper flow): build_settlement -> walletprocesspsbt -> difficulty.finalize_settlement
    // -> sendrawtransaction. The series' fixing must be buried and the CLTV open (the RPC enforces both).
    OptionSeriesActionResult optionSeriesSettle(const QString& terms_json, int lot_index, double fee_rate = 0.0);
    // The writer's early unwind of ONE lot (build_buyback, broadcast). Requires control of writer_key + >=1 unit.
    OptionSeriesActionResult optionSeriesBuyback(const QString& terms_json, int lot_index);
    // Redeem ONE settlement pot (build_redeem, broadcast): retire 1 unit to the sink, sweep the pot.
    OptionSeriesActionResult optionSeriesRedeem(const QString& terms_json, int lot_index, const QString& pot_outpoint);

    // ── Scalar note-pair (securitised CFD asset series) RPC wrappers ─────────────────────────────────────
    // Typed pass-throughs over the scalar.* securitisation RPCs (CFD_GENERALISATION.md §6/§7): a TWO-sided
    // tokenised CFD that mints a long token L and a short token S against per-lot OP_SCALAR_CFD_SETTLE vaults.
    // Structurally mirrors the option-series wizard (register → issue → record), but two-sided, settled on an
    // issuer-published scalar feed (or the committed fallback), with a permissionless complete-set unwind.
    // All hash/amount fields are carried as the RPC's own encodings: 64-hex ids, scalar values as 64-hex
    // (display hex of the uint256), `vault_im` in C's units (sats if native), strike/fallback in scalar_format_id.
    struct ScalarNotePairTermsInput {
        int      source_type{0};        // 0 ISSUER_PUBLISHED / 1 CHAIN_INTRINSIC
        int      payoff_mode{0};        // 0 STRIKE / 1 REALIZED
        int      loss_direction{0};     // owner leg: 0 long / 1 short
        QString  underlying_asset_id;   // U (64-hex; empty/zero iff CHAIN_INTRINSIC)
        quint32  feed_id{0};
        quint64  fixing_ref{0};         // ISSUER: scalar_epoch; CHAIN: window-end height
        quint32  publication_deadline_height{0};
        quint32  settle_lock_height{0};
        int      scalar_format_id{0};
        QString  strike;                // K, 64-hex in scalar_format_id's encoding
        QString  fallback_scalar;       // 64-hex (fires iff no in-time real fixing, §3.4)
        quint32  lambda_q{0};           // Q16 leverage
        QString  collateral_asset_id;   // C (64-hex; empty/zero = native TSC sentinel)
        quint64  vault_im{0};           // per-lot IM in C's units (sats if native)
        quint32  lot_count{0};          // N
        QString  series_salt;           // 64-hex (the dialog auto-generates one if left blank)
    };
    struct ScalarNotePairRegisterResult {
        bool success{false};
        QString pair_id;
        QString long_token_id, short_token_id;
        QString long_ticker, short_ticker;
        QString txid;                   // register tx (may be "(pending)")
        QString error;
    };
    struct ScalarNotePairIssueResult {
        bool success{false};
        QString pair_id;
        int lot_count{0};               // N units minted per side = N vaults funded
        QString txid;                   // issuance (mint) tx
        QString error;
    };
    struct ScalarNotePairRecordResult {
        bool success{false};
        QString pair_id;
        int lot_count{0};
        bool persisted{false};
        QString error;
    };
    struct ScalarNotePairListEntry {
        QString pair_id;
        int lot_count{0};
        QString issue_txid;
        QString long_icu_outpoint, short_icu_outpoint;
        QStringList lot_vaults;         // the N per-lot vault outpoints "txid:vout" (lot_vaults[i] = lot i)
        QString terms_json;             // the full terms (round-trips into build_settlement/redeem/unwind)
    };
    struct ScalarNotePairListResult {
        bool success{false};
        QList<ScalarNotePairListEntry> pairs;
        QString error;
    };
    // A lifecycle action result (settle / redeem / unwind). `txid` is the broadcast transaction id.
    struct ScalarNotePairActionResult {
        bool success{false};
        QString txid;
        QString detail;                 // a human summary for the status log
        QString long_pot, short_pot;    // (settle) the two settlement-pot outpoints, for one-click redeem
        QString error;
    };

    ScalarNotePairRegisterResult scalarNotePairBuildRegister(const ScalarNotePairTermsInput& terms, const QString& root,
                                                             const QString& long_suffix, const QString& short_suffix,
                                                             qint64 child_bond_sats = 0, double fee_rate = 0.0, bool broadcast = true);
    ScalarNotePairIssueResult scalarNotePairBuildIssue(const ScalarNotePairTermsInput& terms, qint64 vault_native_sats = 546,
                                                       double fee_rate = 0.0, bool broadcast = true);
    ScalarNotePairRecordResult scalarNotePairRecordIssue(const ScalarNotePairTermsInput& terms, const QString& issue_txid,
                                                         const QString& register_txid = QString());
    ScalarNotePairListResult scalarNotePairList();
    // Keeper settlement of ONE lot vault (scalar.build_settlement, broadcast): folds the buried fixing (or the
    // committed fallback) and pays both pots. `vault_outpoint` is the lot's "txid:vout" (from scalar.list).
    ScalarNotePairActionResult scalarNotePairSettle(const QString& terms_json, int lot_index, const QString& vault_outpoint,
                                                    double fee_rate = 0.0);
    // Redeem ONE side's token against its settlement pot (scalar.build_redeem, broadcast).
    ScalarNotePairActionResult scalarNotePairRedeem(const QString& terms_json, bool redeem_long, int lot_index,
                                                    const QString& pot_outpoint, const QString& holder_address, double fee_rate = 0.0);
    // Permissionless complete-set unwind of ONE lot vault (scalar.build_unwind, broadcast): retire 1 L + 1 S,
    // reclaim the full collateral — no fixing required.
    ScalarNotePairActionResult scalarNotePairUnwind(const QString& terms_json, int lot_index, const QString& vault_outpoint,
                                                    const QString& holder_address, double fee_rate = 0.0);

    // ── Scalar feed (issuer-published oracle) RPC wrappers ──────────────────────────────────────────────
    struct ScalarFeedPublishResult {
        bool success{false};
        QString txid;                   // broadcast txid if broadcast=true
        QString hex;                    // raw transaction hex
        QString error;
    };
    struct ScalarFeedEntry {
        quint32 feed_id{0};
        quint64 last_epoch{0};
    };
    struct ScalarFeedListResult {
        bool success{false};
        QList<ScalarFeedEntry> feeds;
        QString error;
    };
    struct ScalarFeedGetResult {
        bool success{false};
        quint64 epoch{0}, last_epoch{0};
        QString scalar;                 // 64-hex display value
        int scalar_format_id{0};
        qint64 publication_height{0};
        bool buried{false};             // settlement-usable (buried >= maturity)
        QString error;
    };
    // Publish a scalar feed value (scalarpublish_raw): spends the asset's current ICU, recreates the successor
    // verbatim, and emits one ISSUER_SCALAR carrier. autofund + broadcast use the loaded wallet.
    ScalarFeedPublishResult scalarPublish(const QString& asset_id, const QString& icu_txid, int icu_vout,
                                          const QString& new_icu_address, qint64 new_icu_amount_sats,
                                          quint32 feed_id, quint64 scalar_epoch, const QString& scalar_hex,
                                          int scalar_format_id, double fee_rate = 0.0);
    ScalarFeedListResult scalarListFeeds(const QString& asset_id);
    // Read a published (asset, feed, epoch) scalar; pass epoch < 0 for the latest (head).
    ScalarFeedGetResult scalarGetFeed(const QString& asset_id, quint32 feed_id, qint64 epoch = -1);

    // ── Bilateral scalar CFD (scalarcfd.*) RPC wrappers ─────────────────────────────────────────────────
    // Two-party CFD on an issuer-published FX cross rate X = base/quote (CFD_GENERALISATION.md §7): a long
    // and a short leg, each its own OP_SCALAR_CFD_SETTLE vault, with Fair-Sign atomic open + a 2-of-2
    // cooperative close. Distinct from the securitised note pair above (that mints tradeable L/S tokens).
    struct ScalarCfdLegInput { qint64 im_sats{0}; quint32 lambda_q{0}; };
    struct ScalarCfdTermsInput {
        int      source_type{0};            // 0 = ISSUER_PUBLISHED (only supported)
        int      payoff_mode{0};            // 0 = STRIKE denom, 1 = REALIZED denom
        QString  underlying_asset_id;       // U (64-hex)
        quint32  feed_id{0};
        quint64  fixing_ref{0};             // scalar epoch the contract settles against
        quint32  publication_deadline_height{0};
        quint32  settle_lock_height{0};
        int      scalar_format_id{0};
        QString  strike;                    // K, 64-hex
        QString  fallback_scalar;           // 64-hex
        QString  collateral_asset_id;       // C (64-hex); empty = native TSC
        ScalarCfdLegInput long_leg;
        ScalarCfdLegInput short_leg;
    };
    struct ScalarCfdProposeResult { bool success{false}; QString offer_json; QString error; };
    struct ScalarCfdAcceptResult { bool success{false}; QString contract_id, acceptance_json, action_required, error; };
    struct ScalarCfdImportResult { bool success{false}; QString contract_id, state, error; };
    struct ScalarCfdOpenResult { bool success{false}; QString psbt, fee, leg, error; int vault_index{-1}; };
    struct ScalarCfdRecordOpenResult { bool success{false}; QString long_vault, short_vault, error; };
    struct ScalarCfdSettlementResult { bool success{false}; QString psbt, fee, payout_owner, payout_cp, error;
                                       bool is_fallback{false}; int vault_input_index{-1}; };
    struct ScalarCfdFinalizeResult { bool success{false}; QString hex, error; };
    struct ScalarCfdCoopCloseResult { bool success{false}; QString psbt, fee, error; };
    struct ScalarCfdSignCoopResult { bool success{false}; bool complete{false}; QString psbt, hex, error; };
    struct ScalarCfdPriceResult {
        bool success{false};
        double current_ratio{0.0}, forecast_ratio{0.0};
        double intrinsic_long_mtm{0.0}, intrinsic_short_mtm{0.0}, expected_long_mtm{0.0}, expected_short_mtm{0.0};
        double sigma{0.0}, tau_years{0.0}, discount_factor{1.0};
        double long_delta_to_cross_rate{0.0}, long_vega{0.0}, long_theta{0.0};
        double short_delta_to_cross_rate{0.0}, short_vega{0.0}, short_theta{0.0};
        QString forward_provenance, contract_id;
        bool fixing_reached{false}, is_fallback{false}, model_unreliable{false}, collateral_is_native{true};
        QStringList warnings;
        QString error;
    };
    // propose: proposer defines economics + side + its two P2TR payout addresses (owner = leg it posts; cp =
    // its claim on the counterparty's leg). Returns the offer JSON to hand out-of-band.
    ScalarCfdProposeResult scalarCfdPropose(const ScalarCfdTermsInput& terms, bool proposerIsShort,
                                            const QString& ownerAddr, const QString& cpAddr);
    ScalarCfdAcceptResult scalarCfdAccept(const QString& offer_json, const QString& ownerAddr,
                                          const QString& cpAddr, bool confirmed);
    ScalarCfdImportResult scalarCfdImportAcceptance(const QString& offer_json, const QString& acceptance_json);
    ScalarCfdOpenResult scalarCfdBuildOpen(const QString& contract_id, bool isShort,
                                           const QString& priorPsbt = QString(), double fee_rate = 0.0);
    ScalarCfdRecordOpenResult scalarCfdRecordOpen(const QString& contract_id, const QString& txid);
    ScalarCfdSettlementResult scalarCfdBuildSettlement(const QString& contract_id, bool isShort, double fee_rate = 0.0);
    ScalarCfdFinalizeResult scalarCfdFinalizeSettlement(const QString& psbt);
    ScalarCfdCoopCloseResult scalarCfdBuildCoopClose(const QString& contract_id, bool isShort,
                                                     const QList<QPair<QString, qint64>>& outputs);
    ScalarCfdSignCoopResult scalarCfdSignCoop(const QString& contract_id, bool isShort, const QString& psbt);
    // price: any of sigma / forward_cross_rate / discount_factor < 0 is omitted (resolved from curves/chain).
    ScalarCfdPriceResult scalarCfdPrice(const QString& contract_id, double sigma = -1.0,
                                        double forward_cross_rate = -1.0, double discount_factor = -1.0);

    // Spot contract RPC wrappers
    struct SpotProposeResult {
        bool success{false};
        QString offer_id;
        QString offer_json;
        QString error;
    };

    struct SpotImportOfferResult {
        bool success{false};
        QString offer_id;
        QString error;
    };

    struct SpotAcceptResult {
        bool success{false};
        QString accept_id;
        QString acceptance_json;
        QString error;
    };

    struct SpotImportAcceptanceResult {
        bool success{false};
        QString accept_id;
        QString error;
    };

    struct SpotBuildAtomicResult {
        bool success{false};
        QString psbt;
        int asset_change_index{-1};
        QString my_role;
        bool complete{false};
        QString error;
    };

    struct SpotMarkExecutedResult {
        bool success{false};
        QString error;
    };

    SpotProposeResult spotPropose(const QVariantMap& terms);
    SpotImportOfferResult spotImportOffer(const QString& offer_json);
    SpotAcceptResult spotAccept(const QString& offer_id, bool confirmed = false, const QString& bobAddress = QString());
    SpotImportAcceptanceResult spotImportAcceptance(const QString& offer_id, const QString& acceptance_json);
    SpotBuildAtomicResult spotBuildAtomic(const QString& offer_id, const QVariantMap& options = {});
    SpotMarkExecutedResult spotMarkExecuted(const QString& offer_id, const QString& txid);

    // Contract state query
    struct ContractStatusResult {
        bool success{false};
        QString id;
        QString kind;    // contract family: "repo", "forward", "spot", "difficulty"
        QString product; // difficulty sub-kind: "cfd" or "option" (empty for other families)
        QString state;   // "proposed", "accepted", "opened", "repaid", "defaulted", "closed"
        QVariantMap offer;
        QVariantMap deadlines;
        QVariantList utxos;  // List of {txid, vout, amount}
        QVariantMap closure; // Optional closure metadata
        int confs{0};
        QString error;
    };
    ContractStatusResult getContractStatus(const QString& contract_id);

    // Asset helper methods
    struct AssetInfo {
        QString asset_id;
        QString ticker;
        //! Fractional digits the asset uses. Distinct from `has_decimals`:
        //! `decimals==0` is a perfectly valid value (e.g. integer-only tokens
        //! like NEWCO) and must NOT be conflated with "RPC didn't tell us".
        //! Use `has_decimals` to discriminate "we know" vs "we don't".
        int decimals{8};
        //! True iff getassetinfo / listassets actually returned a decimals
        //! field for this asset. Callers that previously wrote
        //!     info.decimals > 0 ? info.decimals : 8
        //! must instead check
        //!     info.has_decimals ? info.decimals : 8
        //! so that an asset with `decimals==0` isn't silently scaled by 10^8.
        bool has_decimals{false};
        QString issuer;
    };

    QString getNewAddress(const QString& label = "", const QString& addressType = "bech32m");
    QList<AssetInfo> listAssets();
    AssetInfo getAssetInfo(const QString& asset_id);
    bool assetRequiresKeywrap(const QString& asset_id);

    // Contract registry methods
    QList<QVariantMap> listContracts();
    int getNumBlocks() const;

    // Spot commitment proof methods (for WRAP_REQUIRED assets)
    QVariantMap spotAddCommitmentProof(const QString& psbt, const QString& offerId);
    QVariantMap decodePsbt(const QString& psbt);

    // Pricing RPC methods
    struct PricingRepoQuoteResult {
        bool success{false};
        double principal_pv{0.0};
        double interest_pv{0.0};
        double collateral_pv{0.0};
        double collateral_option{0.0};
        double lender_mtm{0.0};
        double borrower_mtm{0.0};
        double coverage_ratio{0.0};
        double ltv_pct{0.0};
        double over_collat_pct{0.0};
        QVariantMap collateral_greeks;
        QVariantList warnings;
        QString error;
    };

    struct PricingForwardQuoteResult {
        bool success{false};
        double pv_receive{0.0};
        double pv_pay{0.0};
        double net_spread_value{0.0};
        double premium_pv{0.0};
        double alice_short_call_value{0.0};
        double alice_long_put_value{0.0};
        double alice_mtm{0.0};
        double bob_mtm{0.0};
        double im_coverage_alice{0.0};
        double im_coverage_bob{0.0};
        QVariantMap spread_greeks_call;
        QVariantMap spread_greeks_put;
        QVariantList warnings;
        QString error;
    };

    struct PricingDifficultyQuoteResult {
        bool success{false};
        QString kind;
        QString writer_side;
        double expected_long_mtm{0.0};
        double expected_short_mtm{0.0};
        double expected_writer_mtm{0.0};
        double expected_buyer_mtm{0.0};
        double long_delta_to_difficulty{0.0};
        double short_delta_to_difficulty{0.0};
        double writer_delta_to_difficulty{0.0};
        double buyer_delta_to_difficulty{0.0};
        double long_vega{0.0};
        double short_vega{0.0};
        double writer_vega{0.0};
        double buyer_vega{0.0};
        double long_theta{0.0};
        double short_theta{0.0};
        double writer_theta{0.0};
        double buyer_theta{0.0};
        double sigma{0.0};
        double tau_years{0.0};
        double discount_factor{1.0};
        double current_difficulty_ratio{0.0};
        double forecast_difficulty_ratio{0.0};
        QString forward_provenance;
        bool fixing_reached{false};
        qlonglong current_nbits{0};
        qlonglong forecast_nbits{0};
        bool model_unreliable{false};
        QVariantList warnings;
        QString error;
    };

    struct PricingMarketStatusResult {
        bool success{false};
        QVariantMap curves;
        QVariantMap fx_quotes;
        QVariantMap vol_surfaces;
        QVariantMap correlation;
        int total_curves{0};
        int total_fx{0};
        int total_vol_surfaces{0};
        bool has_correlation{false};
        QString error;
    };

    struct PricingMarketCalibrateResult {
        bool success{false};
        int curves_updated{0};
        int fx_updated{0};
        int vol_surfaces_updated{0};
        bool correlation_updated{false};
        QVariantList warnings;
        QString error;
    };

    PricingRepoQuoteResult pricingRepoQuote(const QString& source_type,
                                            const QString& registry_id,
                                            const QVariantMap& inline_terms,
                                            const QString& report_asset = "",
                                            bool report_is_native = false,
                                            bool compute_greeks = true,
                                            const QString& price_source = QStringLiteral("mark"),
                                            bool include_inception_cashflows = false);

    PricingForwardQuoteResult pricingForwardQuote(const QString& source_type,
                                                   const QString& registry_id,
                                                   const QVariantMap& inline_terms,
                                                   const QString& report_asset = "",
                                                   bool report_is_native = false,
                                                   bool compute_greeks = true,
                                                   const QString& price_source = QStringLiteral("mark"));

    PricingDifficultyQuoteResult pricingDifficultyQuote(const QString& source_type,
                                                        const QString& registry_id,
                                                        const QVariantMap& inline_terms,
                                                        bool compute_greeks = true,
                                                        quint32 forecast_nbits = 0,
                                                        const QString& price_source = QStringLiteral("market"));

    PricingMarketStatusResult pricingMarketStatus();

    PricingMarketCalibrateResult pricingMarketCalibrate(const QString& source = "nostr",
                                                         double max_age_hours = 24.0,
                                                         double decay_tau = 6.0,
                                                         uint64_t min_volume = 0);

    /**
     * Push FX quote to pricing engine
     * @param base_asset Base asset ID (hex) - ignored if base_is_native=true
     * @param quote_asset Quote asset ID (hex) - ignored if quote_is_native=true
     * @param spot_rate Spot FX rate (base/quote)
     * @param bid_ask_bps Bid-ask spread in bps
     * @param source "mark" for manual prices, "market" for calibrated prices
     * @param base_is_native True if base is native BTC/TSC
     * @param quote_is_native True if quote is native BTC/TSC
     * @return success bool
     */
    bool pricingMarketPushFX(const QString& base_asset,
                            const QString& quote_asset,
                            double spot_rate,
                            double bid_ask_bps = 0.0,
                            const QString& source = "mark",
                            bool base_is_native = false,
                            bool quote_is_native = false);

    /**
     * Push volatility surface to pricing engine
     * @param asset_id Asset ID (hex)
     * @param volatility Flat volatility (for now, single value)
     * @param source "mark" for manual prices, "market" for calibrated prices
     * @return success bool
     */
    bool pricingMarketPushVolSurface(const QString& asset_id,
                                    double volatility,
                                    const QString& source = "mark");

    /**
     * Push discount curve to pricing engine
     * @param asset_id Asset ID (hex)
     * @param is_native True if native BTC
     * @param interest_rate Flat interest rate (for now, single value)
     * @param source "mark" for manual prices, "market" for calibrated prices
     * @return success bool
     */
    bool pricingMarketPushCurve(const QString& asset_id,
                               bool is_native,
                               double interest_rate,
                               const QString& source = "mark");

    /**
     * Push rate term structure to pricing engine
     * @param asset_id Asset ID hex (or empty for native)
     * @param is_native True if native BTC/TSC
     * @param tenors_days Tenor grid in days
     * @param rates Interest rates for each tenor (% p.a.)
     * @param source "mark" for manual prices, "market" for calibrated prices
     * @return success bool
     */
    bool pricingMarketPushCurve(const QString& asset_id,
                               bool is_native,
                               const QVector<int>& tenors_days,
                               const QVector<double>& rates,
                               const QString& source = "mark");

    /**
     * Push correlation matrix to pricing engine
     * @param asset_ids List of asset IDs in matrix order
     * @param correlation_matrix NxN matrix of correlations (symmetric, PSD)
     * @return success bool
     */
    bool pricingMarketPushCorrelation(const QStringList& asset_ids,
                                     const QVector<QVector<double>>& correlation_matrix);

    /**
     * Resolve asset ticker or hex ID to asset ID hex
     * @param symbol_or_id Ticker symbol (e.g., "BTC") or 64-char hex asset ID
     * @return Asset ID hex string, or empty string if not found
     */
    QString resolveAssetId(const QString& symbol_or_id);

private:
    std::unique_ptr<interfaces::Wallet> m_wallet;
    std::unique_ptr<interfaces::Handler> m_handler_unload;
    std::unique_ptr<interfaces::Handler> m_handler_status_changed;
    std::unique_ptr<interfaces::Handler> m_handler_address_book_changed;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    std::unique_ptr<interfaces::Handler> m_handler_show_progress;
    std::unique_ptr<interfaces::Handler> m_handler_can_get_addrs_changed;
    ClientModel* m_client_model;
    interfaces::Node& m_node;
    QString m_bulletin_board_key_path;
    QString m_bulletin_board_pubkey;
    QStringList m_bulletin_board_relays;

    // Executes a bulletin-board RPC and, on a "bulletin board not initialized"
    // error from the bridge (e.g. after a bridge process respawn), transparently
    // replays cosign.init_bb with the cached relays + key path and retries once.
    UniValue executeBulletinBoardRpc(const std::string& method, const UniValue& params);

    bool fForceCheckBalanceChanged{false};

    // Wallet has an options model for wallet-specific options
    // (transaction fee, for example)
    OptionsModel *optionsModel;

    AddressTableModel* addressTableModel{nullptr};
    TransactionTableModel* transactionTableModel{nullptr};
    RecentRequestsTableModel* recentRequestsTableModel{nullptr};

    // Cache some values to be able to detect changes
    interfaces::WalletBalances m_cached_balances;
    std::vector<interfaces::AssetBalance> m_cached_asset_balances;
    EncryptionStatus cachedEncryptionStatus{Unencrypted};
    QTimer* timer;

    // Block hash denoting when the last balance update was done.
    uint256 m_cached_last_update_tip{};

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
    void checkBalanceChanged(const interfaces::WalletBalances& new_balances);

    // Helper function to convert UniValue to QVariantMap
    QVariantMap uniValueToVariantMap(const UniValue& uv);

    // Proof-of-funds verification cache. verifyProofList() iterates each
    // request's proofs and hits gettxout (chainstate read) per UTXO. With
    // many active requests × many proofs per request, this scales linearly
    // and was triggering the GUI watchdog (60s main-thread stall) when run
    // synchronously every poll tick. The cache reduces post-cold-start
    // ticks to O(1) cache lookups per proof until the tip advances.
    // Mutex guards concurrent access from background threads.
    mutable std::mutex m_proof_cache_mutex;
    QCache<QString, CachedProofEntry> m_proof_cache{2000};

Q_SIGNALS:
    // Signal that balance in wallet changed
    void balanceChanged(const interfaces::WalletBalances& balances);

    // Signal that asset balances changed
    void assetBalancesChanged(const std::vector<interfaces::AssetBalance>& balances);

    // Encryption status of wallet changed
    void encryptionStatusChanged();

    // Signal emitted when wallet needs to be unlocked
    // It is valid behaviour for listeners to keep the wallet locked after this signal;
    // this means that the unlocking failed or was cancelled.
    void requireUnlock();

    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

    // Coins sent: from wallet, to recipient, in (serialized) transaction:
    void coinsSent(WalletModel* wallet, SendCoinsRecipient recipient, QByteArray transaction);

    // Show progress dialog e.g. for rescan
    void showProgress(const QString &title, int nProgress);

    // Signal that wallet is about to be removed
    void unload();

    // Notify that there are now keys in the keypool
    void canGetAddressesChanged();

    void timerTimeout();

public Q_SLOTS:
    /* Starts a timer to periodically update the balance */
    void startPollBalance();

    /* Wallet status might have changed */
    void updateStatus();
    /* New transaction, or transaction changed status */
    void updateTransaction();
    /* New, updated or removed address book entry */
    void updateAddressBook(const QString &address, const QString &label, bool isMine, wallet::AddressPurpose purpose, int status);
    /* Current, immature or unconfirmed balance might have changed - emit 'balanceChanged' if so */
    void pollBalanceChanged();
};

#endif // BITCOIN_QT_WALLETMODEL_H
