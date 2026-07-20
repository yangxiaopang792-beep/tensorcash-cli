// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_CROSSCHAINMANAGER_H
#define BITCOIN_WALLET_CROSSCHAINMANAGER_H

#include <wallet/contract.h>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class CWallet;

namespace wallet {

/**
 * Abstract chain backend interface for external chain monitoring.
 *
 * Each adapter (BTC/ETH/TRON) provides its own backend implementation.
 * V1 BTC backend uses Electrum; ETH/TRON uses JSON-RPC.
 */
class ExternalChainBackend
{
public:
    virtual ~ExternalChainBackend() = default;

    struct TxStatus {
        std::string txid;
        int confirmations{0};
        bool is_conflicted{false};
        bool is_replaced{false};
        int64_t block_height{-1};
        int64_t block_time{0};
    };

    /// Query confirmation status of a transaction.
    virtual TxStatus GetTxStatus(const std::string& txid) = 0;

    /// Broadcast a raw transaction. Returns txid on success.
    virtual std::string BroadcastTx(const std::string& raw_tx_hex) = 0;

    /// Check if a specific output is still unspent.
    virtual bool IsOutputUnspent(const std::string& txid, int vout) = 0;

    /// Get current best block height.
    virtual int64_t GetBestBlockHeight() = 0;

    /// Get chain identifier (for logging).
    virtual std::string GetChainName() const = 0;
};

/**
 * Abstract HTLC backend interface for ETH/TRON adapter operations.
 *
 * Provides contract-level operations (lock, claim, refund, status query)
 * that the CrossChainSwapManager uses to drive the swap lifecycle.
 *
 * Implementations wrap cosign bridge commands (cosign.eth_*).
 */
class HtlcBackend
{
public:
    virtual ~HtlcBackend() = default;

    struct HtlcStatus {
        int state{0};            // 0=empty, 1=locked, 2=claimed, 3=refunded
        std::string state_name;
        std::string sender;
        std::string recipient;
        std::string token_address;
        std::string amount;
        std::string secret_hash;
        int64_t timelock{0};
        int64_t confirmation_depth{-1};
        std::string lock_tx_hash; // Discovered from Locked event scan
    };

    struct HtlcTxResult {
        bool success{false};
        std::string tx_hash;
        std::string from_address;
        std::string error;
    };

    /// Initialize the RPC connection to the external chain node.
    virtual bool Init(const std::string& rpc_url) = 0;

    /// Query HTLC contract state and confirmation depth.
    virtual HtlcStatus GetSwapStatus(const std::string& htlc_address,
                                     const std::string& swap_id,
                                     const std::string& lock_tx_hash = "") = 0;

    /// Lock funds into the HTLC contract.
    virtual HtlcTxResult LockHTLC(const std::string& htlc_address,
                                  const std::string& swap_id,
                                  const std::string& recipient,
                                  const std::string& secret_hash,
                                  int64_t timelock,
                                  const std::string& amount_wei,
                                  const std::string& signing_key,
                                  const std::string& token_address = "",
                                  int64_t gas_limit = 200000,
                                  int64_t max_fee_gwei = 50,
                                  int64_t max_priority_fee_gwei = 2) = 0;

    /// Claim locked funds by revealing the secret.
    virtual HtlcTxResult ClaimHTLC(const std::string& htlc_address,
                                   const std::string& swap_id,
                                   const std::string& secret,
                                   const std::string& signing_key,
                                   int64_t gas_limit = 100000,
                                   int64_t max_fee_gwei = 50,
                                   int64_t max_priority_fee_gwei = 2) = 0;

    /// Refund locked funds after timelock expiry.
    virtual HtlcTxResult RefundHTLC(const std::string& htlc_address,
                                    const std::string& swap_id,
                                    const std::string& signing_key,
                                    int64_t gas_limit = 100000,
                                    int64_t max_fee_gwei = 50,
                                    int64_t max_priority_fee_gwei = 2) = 0;

    struct AttestationResult {
        bool valid{false};
        std::string swap_id;
        int64_t confirmation_depth{0};
        std::string error;
    };

    /// Verify an oracle attestation against the configured oracle pubkey.
    virtual AttestationResult VerifyAttestation(
        const std::string& oracle_pubkey,
        const std::string& attestation_json) = 0;

    /// Resolve a signer_ref to a raw signing key hex string.
    /// For "derived:auto", derives from the wallet seed via the bridge.
    /// For raw hex keys (testnet), passes through unchanged.
    virtual std::string ResolveSignerRef(const std::string& signer_ref) = 0;

    /// Get chain identifier (for logging).
    virtual std::string GetChainName() const = 0;
};

/**
 * Swap monitoring event, emitted by the manager on state changes.
 *
 * Qt (or any other UI layer) subscribes to these events via
 * RegisterSwapEventCallback().
 */
struct SwapEvent {
    enum Type {
        STATE_CHANGED,
        CONFIRMATION_UPDATE,
        FEE_ESCALATION,
        REFUND_TRIGGERED,
        EMERGENCY_CLAIM,
        ERROR,
        COMPLETED,
    };

    Type type;
    std::string swap_id;
    CrossChainState old_state;
    CrossChainState new_state;
    int external_conf_depth{0};
    int tsc_conf_depth{0};
    int fee_escalation_level{0};
    std::string message;
};

using SwapEventCallback = std::function<void(const SwapEvent&)>;

/**
 * Background cross-chain swap orchestration manager.
 *
 * Owns:
 *   - swap lifecycle progression (state machine)
 *   - restart recovery from persisted CrossChainRecords
 *   - external chain monitoring via adapters
 *   - fee escalation scheduling
 *   - refund and emergency-claim execution
 *
 * Does NOT own:
 *   - bulletin board posting/listing (that stays in cosign bridge)
 *   - session negotiation (that stays in cosign session layer)
 *   - wallet DB persistence (delegates to CWallet methods)
 *
 * Thread safety: All public methods are safe to call from any thread.
 * Internal state is protected by m_cs_manager.
 */
class CrossChainSwapManager
{
public:
    explicit CrossChainSwapManager(CWallet& wallet);
    ~CrossChainSwapManager();

    // ---- Lifecycle ----

    /// Start the background monitoring thread.
    /// Must be called after wallet is fully loaded.
    void Start();

    /// Stop the background monitoring thread.
    /// Called during wallet shutdown.
    void Stop();

    /// Reload all persisted CrossChainRecords from the wallet.
    /// Called on startup and after crash recovery.
    void ReloadFromWallet();

    // ---- Swap registration ----

    /// Register a new swap after offer acceptance and session establishment.
    /// The record must already be persisted in the wallet before calling this.
    bool RegisterSwap(const std::string& swap_id);

    /// Attempt to advance a swap to the next state.
    /// Returns true if the transition was valid and persisted.
    bool AdvanceState(const std::string& swap_id, CrossChainState target_state);

    // ---- Monitoring ----

    /// Register a UTXO-based chain backend (BTC).
    void RegisterChainBackend(CrossChainKind chain,
                              std::shared_ptr<ExternalChainBackend> backend);

    /// Register an HTLC-based chain backend (ETH/TRON).
    void RegisterHtlcBackend(CrossChainKind chain,
                             std::shared_ptr<HtlcBackend> backend);

    /// Set the oracle pubkey for ETH/TRON attestation verification (phase 3).
    /// For v1 trusted-RPC mode, this can be empty — direct verification is used.
    void SetOraclePubkey(const std::string& pubkey);

    /// Register a secondary HTLC backend for dual-provider verification.
    /// Critical state transitions (COUNTERPARTY_LOCK_CONFIRMED → CLAIM_READY)
    /// require both providers to agree on on-chain facts before advancing.
    void RegisterSecondaryHtlcBackend(CrossChainKind chain,
                                      std::shared_ptr<HtlcBackend> backend);

    /// Subscribe to swap events (thread-safe, multiple callbacks supported).
    void RegisterSwapEventCallback(SwapEventCallback cb);

    // ---- Queries ----

    /// Get the current state of a swap.
    std::optional<CrossChainState> GetSwapState(const std::string& swap_id) const;

    /// Get all active (non-terminal) swap IDs.
    std::vector<std::string> GetActiveSwapIds() const;

    /// Check if any swaps need attention (stuck, near timeout, etc.).
    struct SwapHealth {
        std::string swap_id;
        CrossChainState state;
        int64_t seconds_until_refund_deadline{-1};
        bool needs_fee_bump{false};
        bool is_stuck{false};
        std::string diagnostic;
    };
    std::vector<SwapHealth> GetSwapHealthReport() const;

private:
    // The wallet that owns the persisted records
    CWallet& m_wallet;

    // Mutex protecting all manager state
    mutable std::mutex m_cs_manager;

    // Chain backends keyed by chain type
    std::map<CrossChainKind, std::shared_ptr<ExternalChainBackend>> m_backends;

    // HTLC backends keyed by chain type (ETH/TRON)
    std::map<CrossChainKind, std::shared_ptr<HtlcBackend>> m_htlc_backends;

    // Secondary HTLC backends for dual-provider verification (optional)
    std::map<CrossChainKind, std::shared_ptr<HtlcBackend>> m_secondary_htlc_backends;

    // Configured oracle pubkey for ETH/TRON attestation verification
    // (32-byte x-only hex, set at wallet init time)
    std::string m_oracle_pubkey;

    // Event subscribers
    std::vector<SwapEventCallback> m_event_callbacks;

    // Active swap tracking (swap_id -> cached monitoring state).
    //
    // HTLC execution artifacts (contract address, htlc_swap_id, claim_secret,
    // claim/refund tx hashes, timelock) are persisted in CrossChainRecord
    // and loaded on demand from the wallet.  The SwapContext caches only
    // monitoring-loop-owned fields to avoid duplicating persisted state.
    struct SwapContext {
        CrossChainState state;
        CrossChainKind external_chain{CrossChainKind::BTC};
        CrossChainAdapter adapter{CrossChainAdapter::BTC_SCRIPTLESS_V1};
        CrossChainFundingOrder funding_order{CrossChainFundingOrder::TSC_FIRST};
        uint32_t external_conf_depth{0};
        uint32_t tsc_conf_depth{0};
        uint32_t fee_escalation_level{0};
        int64_t last_check_time{0};
        int64_t last_state_change_time{0};
        int64_t last_fee_bump_time{0};
        std::string external_funding_txid;
        std::string tsc_funding_txid;

        // Timeout policy (parsed from payload_json on load)
        int64_t claim_budget_seconds{0};
        int64_t reorg_margin_seconds{0};
        uint32_t external_min_conf{0};
        uint32_t tsc_min_conf{0};
    };
    std::map<std::string, SwapContext> m_active_swaps;

    // Background thread
    std::thread m_monitor_thread;
    std::atomic<bool> m_running{false};

    // ---- Internal methods ----
    // MonitorLoop, CheckSwap, CheckExternalConfirmations, and
    // EvaluateFeeEscalation operate on snapshot copies of SwapContext
    // WITHOUT holding m_cs_manager, so backend I/O and event emission
    // cannot deadlock against callers that re-enter the manager.

    /// Main monitoring loop (runs in background thread).
    void MonitorLoop();

    /// Check and advance a single swap (no lock held).
    void CheckSwap(const std::string& swap_id, SwapContext& ctx,
                   const std::map<CrossChainKind, std::shared_ptr<ExternalChainBackend>>& backends);

    /// Check external chain confirmation progress (no lock held).
    void CheckExternalConfirmations(const std::string& swap_id, SwapContext& ctx,
                                    const std::map<CrossChainKind, std::shared_ptr<ExternalChainBackend>>& backends);

    /// Check TSC chain confirmation progress (no lock held).
    void CheckTscConfirmations(const std::string& swap_id, SwapContext& ctx);

    /// Evaluate whether fee escalation is needed (no lock held).
    void EvaluateFeeEscalation(const std::string& swap_id, SwapContext& ctx);

    /// Evaluate timeout proximity and trigger refund if needed (no lock held).
    /// Returns true if state was changed (caller must stop processing this swap).
    bool EvaluateTimeouts(const std::string& swap_id, SwapContext& ctx);

    /// HTLC-specific swap orchestration for ETH/TRON (no lock held).
    void CheckSwapHtlc(const std::string& swap_id, SwapContext& ctx,
                       const std::shared_ptr<HtlcBackend>& htlc,
                       const std::shared_ptr<HtlcBackend>& htlc_secondary,
                       const std::string& oracle_pubkey);

    /// Direct RPC verification of on-chain HTLC facts against negotiated terms.
    /// If a secondary provider is configured, requires both to agree.
    /// Returns true if verification passes, false with error message if not.
    bool VerifyLockOnChain(const std::shared_ptr<HtlcBackend>& primary,
                           const std::shared_ptr<HtlcBackend>& secondary,
                           const std::string& htlc_addr,
                           const std::string& htlc_sid,
                           const std::string& lock_tx_hash,
                           const CrossChainRecord& record,
                           std::string& error_out);

    /// Parse timeout and HTLC params from the payload JSON into SwapContext.
    static void ParsePayloadIntoContext(const std::string& payload_json, SwapContext& ctx);

    /// Emit an event to all subscribers (acquires lock only to copy callback list).
    void EmitEvent(const SwapEvent& event);

    /// Determine if a state is terminal (completed, refunded, aborted).
    static bool IsTerminal(CrossChainState state);
};

} // namespace wallet

#endif // BITCOIN_WALLET_CROSSCHAINMANAGER_H
