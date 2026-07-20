// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/crosschainmanager.h>
#include <wallet/wallet.h>
#include <logging.h>
#include <uint256.h>
#include <util/time.h>

#include <chrono>

namespace wallet {

// ============================================================================
// JSON helpers — minimal parser for persisted payload_json
// ============================================================================

namespace {

static int64_t JsonInt(const std::string& json, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return 0;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    try { return std::stoll(json.substr(pos)); } catch (...) { return 0; }
}

} // anonymous namespace

// ============================================================================
// Payload parsing — timeout/confirmation policy only
// ============================================================================

void CrossChainSwapManager::ParsePayloadIntoContext(
    const std::string& payload_json, SwapContext& ctx)
{
    ctx.claim_budget_seconds = JsonInt(payload_json, "claim_budget_seconds");
    ctx.reorg_margin_seconds = JsonInt(payload_json, "reorg_margin_seconds");
    ctx.external_min_conf = static_cast<uint32_t>(JsonInt(payload_json, "external_min_conf"));
    ctx.tsc_min_conf = static_cast<uint32_t>(JsonInt(payload_json, "tsc_min_conf"));

    if (ctx.external_min_conf == 0) ctx.external_min_conf = 6;
    if (ctx.tsc_min_conf == 0) ctx.tsc_min_conf = 1;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

CrossChainSwapManager::CrossChainSwapManager(CWallet& wallet)
    : m_wallet(wallet)
{
}

CrossChainSwapManager::~CrossChainSwapManager()
{
    Stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void CrossChainSwapManager::Start()
{
    if (m_running.exchange(true)) {
        return;
    }

    ReloadFromWallet();

    m_monitor_thread = std::thread([this]() {
        LogPrintf("CrossChainSwapManager: Monitor thread started\n");
        MonitorLoop();
        LogPrintf("CrossChainSwapManager: Monitor thread exited\n");
    });
}

void CrossChainSwapManager::Stop()
{
    if (!m_running.exchange(false)) {
        return;
    }

    if (m_monitor_thread.joinable()) {
        m_monitor_thread.join();
    }
}

void CrossChainSwapManager::ReloadFromWallet()
{
    std::lock_guard<std::mutex> lock(m_cs_manager);

    m_active_swaps.clear();

    auto records = m_wallet.ListCrossChainRecords();
    for (const auto& record : records) {
        const std::string& swap_id = record.swap_id;
        if (IsTerminal(record.state)) {
            continue;
        }

        SwapContext ctx;
        ctx.state = record.state;
        ctx.external_chain = record.external_chain;
        ctx.adapter = record.adapter;
        ctx.funding_order = record.funding_order;
        ctx.external_conf_depth = record.external_conf_depth;
        ctx.tsc_conf_depth = record.tsc_conf_depth;
        ctx.fee_escalation_level = record.fee_escalation_level;
        ctx.last_state_change_time = GetTime();
        if (record.external_funding_txid) {
            ctx.external_funding_txid = record.external_funding_txid->ToString();
        }
        if (record.tsc_funding_txid) {
            ctx.tsc_funding_txid = record.tsc_funding_txid->ToString();
        }

        ParsePayloadIntoContext(record.payload_json, ctx);

        m_active_swaps[swap_id] = ctx;

        LogPrintf("CrossChainSwapManager: Reloaded swap %s in state %d\n",
                  swap_id.c_str(), static_cast<int>(record.state));
    }

    LogPrintf("CrossChainSwapManager: Loaded %d active swaps from wallet\n",
              m_active_swaps.size());
}

// ============================================================================
// Swap registration
// ============================================================================

bool CrossChainSwapManager::RegisterSwap(const std::string& swap_id)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);

    auto record = m_wallet.FindCrossChainRecord(swap_id);
    if (!record) {
        LogPrintf("CrossChainSwapManager: Cannot register swap %s — not found in wallet\n",
                  swap_id.c_str());
        return false;
    }

    SwapContext ctx;
    ctx.state = record->state;
    ctx.external_chain = record->external_chain;
    ctx.adapter = record->adapter;
    ctx.funding_order = record->funding_order;
    ctx.external_conf_depth = record->external_conf_depth;
    ctx.tsc_conf_depth = record->tsc_conf_depth;
    ctx.fee_escalation_level = record->fee_escalation_level;
    ctx.last_state_change_time = GetTime();
    if (record->external_funding_txid) {
        ctx.external_funding_txid = record->external_funding_txid->ToString();
    }
    if (record->tsc_funding_txid) {
        ctx.tsc_funding_txid = record->tsc_funding_txid->ToString();
    }

    ParsePayloadIntoContext(record->payload_json, ctx);

    m_active_swaps[swap_id] = ctx;

    LogPrintf("CrossChainSwapManager: Registered swap %s in state %d\n",
              swap_id.c_str(), static_cast<int>(ctx.state));

    return true;
}

bool CrossChainSwapManager::AdvanceState(const std::string& swap_id,
                                         CrossChainState target_state)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);

    auto it = m_active_swaps.find(swap_id);
    if (it == m_active_swaps.end()) {
        LogPrintf("CrossChainSwapManager: Cannot advance unknown swap %s\n",
                  swap_id.c_str());
        return false;
    }

    CrossChainState old_state = it->second.state;

    if (!m_wallet.UpdateCrossChainState(swap_id, target_state)) {
        LogPrintf("CrossChainSwapManager: State transition %d -> %d rejected for swap %s\n",
                  static_cast<int>(old_state), static_cast<int>(target_state),
                  swap_id.c_str());
        return false;
    }

    it->second.state = target_state;
    it->second.last_state_change_time = GetTime();

    SwapEvent event;
    event.type = SwapEvent::STATE_CHANGED;
    event.swap_id = swap_id;
    event.old_state = old_state;
    event.new_state = target_state;
    event.external_conf_depth = it->second.external_conf_depth;
    event.tsc_conf_depth = it->second.tsc_conf_depth;
    EmitEvent(event);

    if (IsTerminal(target_state)) {
        m_active_swaps.erase(it);

        SwapEvent completed;
        completed.type = (target_state == CrossChainState::COMPLETED)
            ? SwapEvent::COMPLETED : SwapEvent::STATE_CHANGED;
        completed.swap_id = swap_id;
        completed.old_state = old_state;
        completed.new_state = target_state;
        EmitEvent(completed);
    }

    LogPrintf("CrossChainSwapManager: Swap %s transitioned %d -> %d\n",
              swap_id.c_str(), static_cast<int>(old_state),
              static_cast<int>(target_state));

    return true;
}

// ============================================================================
// Monitoring registration
// ============================================================================

void CrossChainSwapManager::RegisterChainBackend(
    CrossChainKind chain,
    std::shared_ptr<ExternalChainBackend> backend)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    m_backends[chain] = std::move(backend);
    LogPrintf("CrossChainSwapManager: Registered chain backend for %d\n",
              static_cast<int>(chain));
}

void CrossChainSwapManager::RegisterHtlcBackend(
    CrossChainKind chain,
    std::shared_ptr<HtlcBackend> backend)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    m_htlc_backends[chain] = std::move(backend);
    LogPrintf("CrossChainSwapManager: Registered HTLC backend for %d\n",
              static_cast<int>(chain));
}

void CrossChainSwapManager::RegisterSecondaryHtlcBackend(
    CrossChainKind chain,
    std::shared_ptr<HtlcBackend> backend)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    m_secondary_htlc_backends[chain] = std::move(backend);
    LogPrintf("CrossChainSwapManager: Registered secondary HTLC backend for %d\n",
              static_cast<int>(chain));
}

void CrossChainSwapManager::SetOraclePubkey(const std::string& pubkey)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    m_oracle_pubkey = pubkey;
    LogPrintf("CrossChainSwapManager: Oracle pubkey set (%d chars)\n",
              pubkey.size());
}

void CrossChainSwapManager::RegisterSwapEventCallback(SwapEventCallback cb)
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    m_event_callbacks.push_back(std::move(cb));
}

// ============================================================================
// Queries
// ============================================================================

std::optional<CrossChainState> CrossChainSwapManager::GetSwapState(
    const std::string& swap_id) const
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    auto it = m_active_swaps.find(swap_id);
    if (it != m_active_swaps.end()) {
        return it->second.state;
    }
    auto record = m_wallet.FindCrossChainRecord(swap_id);
    if (record) {
        return record->state;
    }
    return std::nullopt;
}

std::vector<std::string> CrossChainSwapManager::GetActiveSwapIds() const
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    std::vector<std::string> ids;
    ids.reserve(m_active_swaps.size());
    for (const auto& [id, ctx] : m_active_swaps) {
        ids.push_back(id);
    }
    return ids;
}

std::vector<CrossChainSwapManager::SwapHealth>
CrossChainSwapManager::GetSwapHealthReport() const
{
    std::lock_guard<std::mutex> lock(m_cs_manager);
    std::vector<SwapHealth> report;

    for (const auto& [swap_id, ctx] : m_active_swaps) {
        SwapHealth health;
        health.swap_id = swap_id;
        health.state = ctx.state;
        health.needs_fee_bump = (ctx.fee_escalation_level > 0);

        int64_t now = GetTime();
        health.is_stuck = (ctx.last_state_change_time > 0 &&
                          (now - ctx.last_state_change_time) > 1800);

        // Compute refund deadline from persisted record
        auto record = m_wallet.FindCrossChainRecord(swap_id);
        if (record && record->htlc_timelock > 0) {
            health.seconds_until_refund_deadline = record->htlc_timelock - now;
        }

        if (health.is_stuck) {
            health.diagnostic = "No progress for 30+ minutes";
        } else if (health.seconds_until_refund_deadline >= 0 &&
                   health.seconds_until_refund_deadline < ctx.reorg_margin_seconds) {
            health.diagnostic = "Approaching refund deadline";
        } else if (health.needs_fee_bump) {
            health.diagnostic = "Fee escalation level " +
                std::to_string(ctx.fee_escalation_level);
        }

        report.push_back(health);
    }

    return report;
}

// ============================================================================
// Monitor loop
// ============================================================================

void CrossChainSwapManager::MonitorLoop()
{
    while (m_running.load()) {
        std::vector<std::pair<std::string, SwapContext>> snapshot;
        std::map<CrossChainKind, std::shared_ptr<ExternalChainBackend>> backends;
        std::map<CrossChainKind, std::shared_ptr<HtlcBackend>> htlc_backends;
        std::map<CrossChainKind, std::shared_ptr<HtlcBackend>> htlc_secondary;
        std::string oracle_pubkey;
        {
            std::lock_guard<std::mutex> lock(m_cs_manager);
            snapshot.reserve(m_active_swaps.size());
            for (const auto& [id, ctx] : m_active_swaps) {
                snapshot.emplace_back(id, ctx);
            }
            backends = m_backends;
            htlc_backends = m_htlc_backends;
            htlc_secondary = m_secondary_htlc_backends;
            oracle_pubkey = m_oracle_pubkey;
        }

        for (auto& [swap_id, ctx] : snapshot) {
            ctx.last_check_time = GetTime();

            bool is_htlc = (ctx.adapter == CrossChainAdapter::ETH_HTLC_V1 ||
                            ctx.adapter == CrossChainAdapter::TRON_HTLC_V1);
            if (is_htlc) {
                auto htlc_it = htlc_backends.find(ctx.external_chain);
                if (htlc_it != htlc_backends.end()) {
                    auto sec_it = htlc_secondary.find(ctx.external_chain);
                    auto sec_ptr = (sec_it != htlc_secondary.end()) ? sec_it->second : nullptr;
                    CheckSwapHtlc(swap_id, ctx, htlc_it->second, sec_ptr, oracle_pubkey);
                }
            } else {
                CheckSwap(swap_id, ctx, backends);
            }
        }

        // Merge monitoring-only fields back
        {
            std::lock_guard<std::mutex> lock(m_cs_manager);
            for (const auto& [swap_id, ctx] : snapshot) {
                auto it = m_active_swaps.find(swap_id);
                if (it == m_active_swaps.end()) continue;

                it->second.external_conf_depth = ctx.external_conf_depth;
                it->second.tsc_conf_depth = ctx.tsc_conf_depth;
                it->second.fee_escalation_level = ctx.fee_escalation_level;
                it->second.last_check_time = ctx.last_check_time;
                it->second.last_fee_bump_time = ctx.last_fee_bump_time;
            }
        }

        for (int i = 0; i < 100 && m_running.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// ============================================================================
// UTXO-chain swap checking (BTC adapter)
// ============================================================================

void CrossChainSwapManager::CheckSwap(
    const std::string& swap_id, SwapContext& ctx,
    const std::map<CrossChainKind, std::shared_ptr<ExternalChainBackend>>& backends)
{
    switch (ctx.state) {
    case CrossChainState::COUNTERPARTY_LOCK_SEEN:
    case CrossChainState::COUNTERPARTY_LOCK_CONFIRMED:
        CheckExternalConfirmations(swap_id, ctx, backends);
        break;

    case CrossChainState::LOCAL_LOCK_CONFIRMED:
    case CrossChainState::CLAIM_READY:
        CheckTscConfirmations(swap_id, ctx);
        EvaluateTimeouts(swap_id, ctx);
        break;

    case CrossChainState::CLAIM_BROADCAST:
        CheckExternalConfirmations(swap_id, ctx, backends);
        EvaluateFeeEscalation(swap_id, ctx);
        break;

    case CrossChainState::EMERGENCY_CLAIM:
        EvaluateFeeEscalation(swap_id, ctx);
        break;

    case CrossChainState::REFUND_READY:
    case CrossChainState::REFUND_BROADCAST:
        EvaluateFeeEscalation(swap_id, ctx);
        break;

    default:
        break;
    }
}

// ============================================================================
// HTLC-chain swap orchestration (ETH/TRON adapter)
//
// All HTLC execution artifacts (contract address, htlc_swap_id, secrets,
// tx hashes, timelock) are read from the persisted CrossChainRecord on
// every check cycle.  When the manager produces new artifacts (e.g. a
// claim tx hash), it persists them via UpdateCrossChainHtlcArtifacts()
// before acting on them — write-before-mutate.
// ============================================================================

void CrossChainSwapManager::CheckSwapHtlc(
    const std::string& swap_id, SwapContext& ctx,
    const std::shared_ptr<HtlcBackend>& htlc,
    const std::shared_ptr<HtlcBackend>& htlc_secondary,
    const std::string& oracle_pubkey)
{
    // Load persisted HTLC artifacts from wallet on every cycle.
    // This ensures restart safety: all fields come from the DB.
    auto record = m_wallet.FindCrossChainRecord(swap_id);
    if (!record) return;

    const std::string& htlc_addr = record->htlc_contract_address;
    const std::string& htlc_sid = record->htlc_swap_id;

    // Cannot proceed without session-negotiated HTLC parameters
    if (htlc_addr.empty() || htlc_sid.empty()) {
        return;
    }

    // [Finding 3] Refresh tsc_funding_txid from the record each cycle,
    // in case the session layer funded TSC after initial registration.
    if (record->tsc_funding_txid && ctx.tsc_funding_txid.empty()) {
        ctx.tsc_funding_txid = record->tsc_funding_txid->ToString();
    }

    switch (ctx.state) {

    // -- Waiting for counterparty to lock the HTLC --
    case CrossChainState::FUNDING_PREPARED: {
        // GetSwapStatus will auto-scan for lock tx hash when state=Locked
        auto status = htlc->GetSwapStatus(htlc_addr, htlc_sid);
        if (status.state == 1) { // Locked
            // [Finding 1] Persist lock_tx_hash + on-chain timelock.
            // The bridge scans for the Locked event and returns the tx hash.
            if (!m_wallet.UpdateCrossChainHtlcArtifacts(
                    swap_id, htlc_addr, htlc_sid,
                    record->external_signer_ref, record->claim_secret,
                    record->claim_tx_hash, record->refund_tx_hash,
                    status.lock_tx_hash,  // Discovered from Locked event scan
                    status.timelock)) {
                LogPrintf("CrossChainSwapManager: CRITICAL — failed to persist lock "
                          "artifacts for %s, not advancing\n", swap_id);
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Lock detected but persistence failed — will retry";
                EmitEvent(event);
                break;
            }

            LogPrintf("CrossChainSwapManager: Counterparty lock detected for %s "
                      "tx=%s timelock=%lld\n",
                      swap_id, status.lock_tx_hash, status.timelock);
            AdvanceState(swap_id, CrossChainState::COUNTERPARTY_LOCK_SEEN);
        }
        break;
    }

    // -- Polling external confirmations on counterparty lock --
    case CrossChainState::COUNTERPARTY_LOCK_SEEN: {
        auto status = htlc->GetSwapStatus(
            htlc_addr, htlc_sid, record->external_lock_tx_hash);

        if (status.state != 1) {
            SwapEvent event;
            event.type = SwapEvent::ERROR;
            event.swap_id = swap_id;
            event.old_state = ctx.state;
            event.new_state = ctx.state;
            event.message = "HTLC lock no longer active (state=" +
                           std::to_string(status.state) + ")";
            EmitEvent(event);
            break;
        }

        uint32_t primary_depth = (status.confirmation_depth >= 0)
            ? static_cast<uint32_t>(status.confirmation_depth) : 0;

        // Dual-provider: use the MINIMUM of both providers' reported depth.
        // A lying or stale primary cannot push the swap forward if the
        // secondary disagrees.
        uint32_t effective_depth = primary_depth;
        if (htlc_secondary) {
            auto status2 = htlc_secondary->GetSwapStatus(
                htlc_addr, htlc_sid, record->external_lock_tx_hash);
            if (status2.state != 1) {
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Secondary provider: HTLC not locked (state=" +
                               std::to_string(status2.state) + ")";
                EmitEvent(event);
                break;
            }
            uint32_t secondary_depth = (status2.confirmation_depth >= 0)
                ? static_cast<uint32_t>(status2.confirmation_depth) : 0;
            effective_depth = std::min(primary_depth, secondary_depth);
        }

        uint32_t old_depth = ctx.external_conf_depth;
        ctx.external_conf_depth = effective_depth;

        if (ctx.external_conf_depth != old_depth) {
            m_wallet.UpdateCrossChainMonitoring(
                swap_id, ctx.external_conf_depth, ctx.tsc_conf_depth,
                ctx.fee_escalation_level);

            SwapEvent event;
            event.type = SwapEvent::CONFIRMATION_UPDATE;
            event.swap_id = swap_id;
            event.old_state = ctx.state;
            event.new_state = ctx.state;
            event.external_conf_depth = ctx.external_conf_depth;
            EmitEvent(event);
        }

        if (ctx.external_conf_depth >= ctx.external_min_conf) {
            LogPrintf("CrossChainSwapManager: External lock confirmed for %s "
                      "(depth %d >= %d%s)\n",
                      swap_id, ctx.external_conf_depth, ctx.external_min_conf,
                      htlc_secondary ? ", dual-provider agreed" : "");
            AdvanceState(swap_id, CrossChainState::COUNTERPARTY_LOCK_CONFIRMED);
        }
        break;
    }

    // -- Counterparty lock confirmed.
    //    v1 (trusted-RPC mode): verify on-chain facts directly against
    //    the configured RPC provider(s). If a secondary provider is
    //    configured, both must agree before advancing.
    //    Phase 3 (oracle mode): verify cryptographic attestation instead.
    case CrossChainState::COUNTERPARTY_LOCK_CONFIRMED: {
        // v1: direct RPC verification (no oracle needed)
        if (oracle_pubkey.empty() || record->oracle_attestation.empty()) {
            std::string verify_error;
            if (!VerifyLockOnChain(htlc, htlc_secondary,
                                   htlc_addr, htlc_sid,
                                   record->external_lock_tx_hash,
                                   *record, verify_error)) {
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Direct verification failed: " + verify_error;
                EmitEvent(event);
                break;
            }

            LogPrintf("CrossChainSwapManager: Direct RPC verification passed for %s\n",
                      swap_id);
        } else {
            // Phase 3: oracle attestation mode
            auto att_result = htlc->VerifyAttestation(
                oracle_pubkey, record->oracle_attestation);
            if (!att_result.valid) {
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Oracle attestation verification failed: " + att_result.error;
                EmitEvent(event);
                break;
            }
            if (att_result.swap_id != htlc_sid) {
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Oracle attestation swap_id mismatch: expected " +
                               htlc_sid + " got " + att_result.swap_id;
                EmitEvent(event);
                break;
            }
            LogPrintf("CrossChainSwapManager: Oracle attestation verified for %s\n",
                      swap_id);
        }

        // Verification passed — proceed based on funding order
        if (!ctx.tsc_funding_txid.empty()) {
            CheckTscConfirmations(swap_id, ctx);
            if (ctx.tsc_conf_depth >= ctx.tsc_min_conf) {
                AdvanceState(swap_id, CrossChainState::CLAIM_READY);
            }
        }
        EvaluateTimeouts(swap_id, ctx);
        break;
    }

    // -- Both legs funded, waiting for TSC confirmations --
    case CrossChainState::LOCAL_LOCK_CONFIRMED: {
        // Re-verify external lock is still valid before advancing further.
        // v1: direct RPC. Phase 3: oracle attestation.
        if (oracle_pubkey.empty() || record->oracle_attestation.empty()) {
            std::string verify_error;
            if (!VerifyLockOnChain(htlc, htlc_secondary,
                                   htlc_addr, htlc_sid,
                                   record->external_lock_tx_hash,
                                   *record, verify_error)) {
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Re-verification failed: " + verify_error;
                EmitEvent(event);
                break;
            }
        } else {
            auto att_result = htlc->VerifyAttestation(
                oracle_pubkey, record->oracle_attestation);
            if (!att_result.valid || att_result.swap_id != htlc_sid) break;
        }

        CheckTscConfirmations(swap_id, ctx);
        if (ctx.tsc_conf_depth >= ctx.tsc_min_conf) {
            AdvanceState(swap_id, CrossChainState::CLAIM_READY);
        }
        EvaluateTimeouts(swap_id, ctx);
        break;
    }

    // -- Ready to claim: reveal secret on external chain --
    case CrossChainState::CLAIM_READY: {
        // [Finding 1] Check timeouts FIRST. If EvaluateTimeouts transitions
        // to REFUND_READY, we MUST NOT proceed to reveal the secret.
        if (EvaluateTimeouts(swap_id, ctx)) {
            break; // State changed — stop processing this swap this cycle
        }

        if (record->claim_secret.empty() || record->external_signer_ref.empty()) {
            break;
        }

        LogPrintf("CrossChainSwapManager: Attempting HTLC claim for %s\n", swap_id);
        auto result = htlc->ClaimHTLC(
            htlc_addr, htlc_sid, record->claim_secret,
            record->external_signer_ref);

        if (result.success) {
            // [Finding 2] Persist claim_tx_hash BEFORE advancing state.
            // If persistence fails, do NOT advance — write-before-mutate.
            if (!m_wallet.UpdateCrossChainHtlcArtifacts(
                    swap_id, htlc_addr, htlc_sid,
                    record->external_signer_ref, record->claim_secret,
                    result.tx_hash, record->refund_tx_hash,
                    record->external_lock_tx_hash, record->htlc_timelock)) {
                LogPrintf("CrossChainSwapManager: CRITICAL — claim tx %s broadcast "
                          "but failed to persist for %s\n",
                          result.tx_hash, swap_id);
                // Emit error but DO NOT advance — next cycle will retry persistence
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Claim broadcast but persistence failed — will retry";
                EmitEvent(event);
                break;
            }

            LogPrintf("CrossChainSwapManager: Claim broadcast for %s tx=%s\n",
                      swap_id, result.tx_hash);
            AdvanceState(swap_id, CrossChainState::CLAIM_BROADCAST);
        } else {
            SwapEvent event;
            event.type = SwapEvent::ERROR;
            event.swap_id = swap_id;
            event.old_state = ctx.state;
            event.new_state = ctx.state;
            event.message = "Claim failed: " + result.error;
            EmitEvent(event);
        }
        break;
    }

    // -- Claim broadcast, waiting for confirmation --
    case CrossChainState::CLAIM_BROADCAST: {
        if (!record->claim_tx_hash.empty()) {
            auto status = htlc->GetSwapStatus(
                htlc_addr, htlc_sid, record->claim_tx_hash);

            if (status.state == 2) {
                LogPrintf("CrossChainSwapManager: Claim confirmed for %s\n", swap_id);
                AdvanceState(swap_id, CrossChainState::CLAIM_CONFIRMED);
                AdvanceState(swap_id, CrossChainState::COMPLETED);
                break;
            }
        }
        EvaluateFeeEscalation(swap_id, ctx);
        EvaluateTimeouts(swap_id, ctx);
        break;
    }

    // -- Emergency claim: aggressive fee bumping --
    case CrossChainState::EMERGENCY_CLAIM: {
        if (!record->claim_tx_hash.empty()) {
            auto status = htlc->GetSwapStatus(
                htlc_addr, htlc_sid, record->claim_tx_hash);
            if (status.state == 2) {
                AdvanceState(swap_id, CrossChainState::CLAIM_CONFIRMED);
                AdvanceState(swap_id, CrossChainState::COMPLETED);
                break;
            }
        }

        if (!record->claim_secret.empty() && !record->external_signer_ref.empty()) {
            int64_t escalated_fee = 50 + 25 * ctx.fee_escalation_level;
            int64_t escalated_priority = 2 + 3 * ctx.fee_escalation_level;
            auto result = htlc->ClaimHTLC(
                htlc_addr, htlc_sid, record->claim_secret,
                record->external_signer_ref,
                100000, escalated_fee, escalated_priority);
            if (result.success && result.tx_hash != record->claim_tx_hash) {
                // [Finding 2] Check persistence success
                m_wallet.UpdateCrossChainHtlcArtifacts(
                    swap_id, htlc_addr, htlc_sid,
                    record->external_signer_ref, record->claim_secret,
                    result.tx_hash, record->refund_tx_hash,
                    record->external_lock_tx_hash, record->htlc_timelock);
                // Non-fatal if persistence fails here — we already have a
                // persisted claim_tx_hash from the initial broadcast.
            }
        }
        EvaluateFeeEscalation(swap_id, ctx);
        break;
    }

    // -- Refund ready: broadcast refund tx --
    case CrossChainState::REFUND_READY: {
        if (record->external_signer_ref.empty()) break;

        LogPrintf("CrossChainSwapManager: Attempting HTLC refund for %s\n", swap_id);
        int64_t escalated_fee = 50 + 25 * ctx.fee_escalation_level;
        int64_t escalated_priority = 2 + 3 * ctx.fee_escalation_level;
        auto result = htlc->RefundHTLC(
            htlc_addr, htlc_sid, record->external_signer_ref,
            100000, escalated_fee, escalated_priority);

        if (result.success) {
            // [Finding 2] Persist refund_tx_hash BEFORE advancing state.
            if (!m_wallet.UpdateCrossChainHtlcArtifacts(
                    swap_id, htlc_addr, htlc_sid,
                    record->external_signer_ref, record->claim_secret,
                    record->claim_tx_hash, result.tx_hash,
                    record->external_lock_tx_hash, record->htlc_timelock)) {
                LogPrintf("CrossChainSwapManager: CRITICAL — refund tx %s broadcast "
                          "but failed to persist for %s\n",
                          result.tx_hash, swap_id);
                SwapEvent event;
                event.type = SwapEvent::ERROR;
                event.swap_id = swap_id;
                event.old_state = ctx.state;
                event.new_state = ctx.state;
                event.message = "Refund broadcast but persistence failed — will retry";
                EmitEvent(event);
                break;
            }

            LogPrintf("CrossChainSwapManager: Refund broadcast for %s tx=%s\n",
                      swap_id, result.tx_hash);
            AdvanceState(swap_id, CrossChainState::REFUND_BROADCAST);
        } else {
            SwapEvent event;
            event.type = SwapEvent::ERROR;
            event.swap_id = swap_id;
            event.old_state = ctx.state;
            event.new_state = ctx.state;
            event.message = "Refund failed: " + result.error;
            EmitEvent(event);
        }
        EvaluateFeeEscalation(swap_id, ctx);
        break;
    }

    // -- Refund broadcast, waiting for confirmation --
    case CrossChainState::REFUND_BROADCAST: {
        if (!record->refund_tx_hash.empty()) {
            auto status = htlc->GetSwapStatus(
                htlc_addr, htlc_sid, record->refund_tx_hash);
            if (status.state == 3) {
                LogPrintf("CrossChainSwapManager: Refund confirmed for %s\n", swap_id);
                AdvanceState(swap_id, CrossChainState::REFUNDED);
                break;
            }
        }
        EvaluateFeeEscalation(swap_id, ctx);
        break;
    }

    default:
        break;
    }
}

// ============================================================================
// External chain confirmation tracking (UTXO-based backends)
// ============================================================================

void CrossChainSwapManager::CheckExternalConfirmations(
    const std::string& swap_id, SwapContext& ctx,
    const std::map<CrossChainKind, std::shared_ptr<ExternalChainBackend>>& backends)
{
    if (ctx.external_funding_txid.empty()) return;

    auto backend_it = backends.find(ctx.external_chain);
    if (backend_it == backends.end()) return;

    auto status = backend_it->second->GetTxStatus(ctx.external_funding_txid);

    if (status.is_conflicted || status.is_replaced) {
        SwapEvent event;
        event.type = SwapEvent::ERROR;
        event.swap_id = swap_id;
        event.old_state = ctx.state;
        event.new_state = ctx.state;
        event.message = "External funding tx " + ctx.external_funding_txid +
                       " has been " + (status.is_replaced ? "replaced" : "conflicted");
        EmitEvent(event);
        return;
    }

    uint32_t old_depth = ctx.external_conf_depth;
    ctx.external_conf_depth = static_cast<uint32_t>(status.confirmations);

    if (ctx.external_conf_depth != old_depth) {
        m_wallet.UpdateCrossChainMonitoring(
            swap_id, ctx.external_conf_depth, ctx.tsc_conf_depth,
            ctx.fee_escalation_level);

        SwapEvent event;
        event.type = SwapEvent::CONFIRMATION_UPDATE;
        event.swap_id = swap_id;
        event.old_state = ctx.state;
        event.new_state = ctx.state;
        event.external_conf_depth = ctx.external_conf_depth;
        event.tsc_conf_depth = ctx.tsc_conf_depth;
        EmitEvent(event);
    }
}

// ============================================================================
// TSC confirmation tracking
// ============================================================================

void CrossChainSwapManager::CheckTscConfirmations(
    const std::string& swap_id, SwapContext& ctx)
{
    if (ctx.tsc_funding_txid.empty()) return;

    auto record = m_wallet.FindCrossChainRecord(swap_id);
    if (!record || !record->tsc_funding_txid) return;

    uint32_t old_depth = ctx.tsc_conf_depth;
    ctx.tsc_conf_depth = record->tsc_conf_depth;

    if (ctx.tsc_conf_depth != old_depth) {
        m_wallet.UpdateCrossChainMonitoring(
            swap_id, ctx.external_conf_depth, ctx.tsc_conf_depth,
            ctx.fee_escalation_level);

        SwapEvent event;
        event.type = SwapEvent::CONFIRMATION_UPDATE;
        event.swap_id = swap_id;
        event.old_state = ctx.state;
        event.new_state = ctx.state;
        event.external_conf_depth = ctx.external_conf_depth;
        event.tsc_conf_depth = ctx.tsc_conf_depth;
        EmitEvent(event);
    }
}

// ============================================================================
// Fee escalation
// ============================================================================

void CrossChainSwapManager::EvaluateFeeEscalation(
    const std::string& swap_id, SwapContext& ctx)
{
    int64_t now = GetTime();

    if (ctx.last_fee_bump_time == 0) {
        ctx.last_fee_bump_time = now;
        return;
    }

    int64_t time_since_last_bump = now - ctx.last_fee_bump_time;
    int escalation_interval = 300 * (1 << std::min(ctx.fee_escalation_level, 4u));

    if (time_since_last_bump >= escalation_interval) {
        ctx.fee_escalation_level++;
        ctx.last_fee_bump_time = now;

        m_wallet.UpdateCrossChainMonitoring(
            swap_id, ctx.external_conf_depth, ctx.tsc_conf_depth,
            ctx.fee_escalation_level);

        SwapEvent event;
        event.type = SwapEvent::FEE_ESCALATION;
        event.swap_id = swap_id;
        event.old_state = ctx.state;
        event.new_state = ctx.state;
        event.fee_escalation_level = ctx.fee_escalation_level;
        event.message = "Fee escalation level " +
                       std::to_string(ctx.fee_escalation_level);
        EmitEvent(event);

        LogPrintf("CrossChainSwapManager: Fee escalation level %d for swap %s\n",
                  ctx.fee_escalation_level, swap_id.c_str());
    }
}

// ============================================================================
// Timeout evaluation
//
// Uses the on-chain HTLC timelock (persisted as htlc_timelock) as the
// canonical refund deadline.  This is set from the HTLC contract state
// when the counterparty lock is first detected, not from GetTime().
// ============================================================================

bool CrossChainSwapManager::EvaluateTimeouts(
    const std::string& swap_id, SwapContext& ctx)
{
    auto record = m_wallet.FindCrossChainRecord(swap_id);
    if (!record || record->htlc_timelock <= 0) {
        return false;
    }

    int64_t now = GetTime();
    int64_t refund_deadline = record->htlc_timelock;
    int64_t seconds_remaining = refund_deadline - now;

    // If within reorg_margin of the refund deadline, trigger refund path
    if (seconds_remaining <= ctx.reorg_margin_seconds) {
        if (ctx.state == CrossChainState::LOCAL_LOCK_CONFIRMED ||
            ctx.state == CrossChainState::CLAIM_READY) {
            LogPrintf("CrossChainSwapManager: Refund deadline approaching for %s "
                      "(%lld seconds remaining, margin=%lld)\n",
                      swap_id, seconds_remaining, ctx.reorg_margin_seconds);

            SwapEvent event;
            event.type = SwapEvent::REFUND_TRIGGERED;
            event.swap_id = swap_id;
            event.old_state = ctx.state;
            event.new_state = CrossChainState::REFUND_READY;
            event.message = "Refund deadline in " + std::to_string(seconds_remaining) + "s";
            EmitEvent(event);

            AdvanceState(swap_id, CrossChainState::REFUND_READY);
            return true; // State changed — caller must stop
        }
    }

    // If within claim_budget window, escalate to emergency claim
    if (seconds_remaining <= (ctx.claim_budget_seconds + ctx.reorg_margin_seconds) &&
        seconds_remaining > ctx.reorg_margin_seconds) {
        if (ctx.state == CrossChainState::CLAIM_BROADCAST) {
            LogPrintf("CrossChainSwapManager: Emergency claim for %s "
                      "(%lld seconds remaining)\n", swap_id, seconds_remaining);

            SwapEvent event;
            event.type = SwapEvent::EMERGENCY_CLAIM;
            event.swap_id = swap_id;
            event.old_state = ctx.state;
            event.new_state = CrossChainState::EMERGENCY_CLAIM;
            event.message = "Claim deadline pressure — " +
                           std::to_string(seconds_remaining) + "s to refund boundary";
            EmitEvent(event);

            AdvanceState(swap_id, CrossChainState::EMERGENCY_CLAIM);
            return true; // State changed
        }
    }

    return false; // No state change
}

// ============================================================================
// Event emission
// ============================================================================

void CrossChainSwapManager::EmitEvent(const SwapEvent& event)
{
    std::vector<SwapEventCallback> callbacks;
    {
        std::lock_guard<std::mutex> lock(m_cs_manager);
        callbacks = m_event_callbacks;
    }

    for (const auto& cb : callbacks) {
        try {
            cb(event);
        } catch (const std::exception& e) {
            LogPrintf("CrossChainSwapManager: Event callback exception: %s\n",
                      e.what());
        }
    }
}

bool CrossChainSwapManager::IsTerminal(CrossChainState state)
{
    return state == CrossChainState::COMPLETED ||
           state == CrossChainState::REFUNDED ||
           state == CrossChainState::ABORTED;
}

bool CrossChainSwapManager::VerifyLockOnChain(
    const std::shared_ptr<HtlcBackend>& primary,
    const std::shared_ptr<HtlcBackend>& secondary,
    const std::string& htlc_addr,
    const std::string& htlc_sid,
    const std::string& lock_tx_hash,
    const CrossChainRecord& record,
    std::string& error_out)
{
    // Primary provider check
    auto status = primary->GetSwapStatus(htlc_addr, htlc_sid, lock_tx_hash);

    if (status.state != 1) {
        error_out = "Primary: HTLC not in Locked state (state=" +
                    std::to_string(status.state) + ")";
        return false;
    }

    // Validate on-chain facts against negotiated terms
    if (!record.expected_secret_hash.empty() &&
        status.secret_hash != record.expected_secret_hash) {
        error_out = "Primary: secret_hash mismatch — on-chain=" + status.secret_hash +
                    " expected=" + record.expected_secret_hash;
        return false;
    }

    if (!record.expected_recipient.empty() &&
        status.recipient != record.expected_recipient) {
        error_out = "Primary: recipient mismatch — on-chain=" + status.recipient +
                    " expected=" + record.expected_recipient;
        return false;
    }

    if (!record.expected_amount.empty() &&
        status.amount != record.expected_amount) {
        error_out = "Primary: amount mismatch — on-chain=" + status.amount +
                    " expected=" + record.expected_amount;
        return false;
    }

    if (record.htlc_timelock > 0 && status.timelock != record.htlc_timelock) {
        error_out = "Primary: timelock mismatch — on-chain=" +
                    std::to_string(status.timelock) + " expected=" +
                    std::to_string(record.htlc_timelock);
        return false;
    }

    if (!record.expected_token_address.empty() &&
        status.token_address != record.expected_token_address) {
        error_out = "Primary: token_address mismatch — on-chain=" + status.token_address +
                    " expected=" + record.expected_token_address;
        return false;
    }

    // Dual-provider agreement (if secondary configured)
    if (secondary) {
        auto status2 = secondary->GetSwapStatus(htlc_addr, htlc_sid, lock_tx_hash);

        if (status2.state != status.state) {
            error_out = "Provider disagreement on state: primary=" +
                        std::to_string(status.state) + " secondary=" +
                        std::to_string(status2.state);
            return false;
        }

        if (status2.secret_hash != status.secret_hash) {
            error_out = "Provider disagreement on secret_hash";
            return false;
        }

        if (status2.recipient != status.recipient) {
            error_out = "Provider disagreement on recipient";
            return false;
        }

        if (status2.amount != status.amount) {
            error_out = "Provider disagreement on amount";
            return false;
        }

        if (status2.timelock != status.timelock) {
            error_out = "Provider disagreement on timelock";
            return false;
        }

        if (status2.token_address != status.token_address) {
            error_out = "Provider disagreement on token_address";
            return false;
        }

        LogPrintf("CrossChainSwapManager: Dual-provider verification passed for %s\n",
                  htlc_sid);
    }

    return true;
}

} // namespace wallet
