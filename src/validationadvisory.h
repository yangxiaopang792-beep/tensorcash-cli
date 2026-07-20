// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONADVISORY_H
#define BITCOIN_VALIDATIONADVISORY_H

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <deque>
#include <optional>
#include <set>
#include <map>
#include <functional>
#include <string>
#include <vector>

class ChainstateManager;

namespace node {
class BlockManager;
} // namespace node

// Default knobs for advisory/gating.
//! Default reorg depth threshold for advisory + operator gating. Raised from 3
//! to 6: a hashrate spike (faster blocks before difficulty retargets, plus
//! partition heals) makes benign reorgs of depth 4-6 common, so a depth-3 gate
//! fires on legitimate reorgs and — with the default timeout action REJECT — an
//! unattended node can stall on a stale tip. 6 is the same depth at which the
//! SPV body-sampling corroboration already engages, keeping the two aligned.
//! This is local operator policy (non-consensus); override with
//! -reorgadvisorydepth / -reorgadvisorygatingdepth.
constexpr int ADVISORY_DEPTH_THRESHOLD = 6;
//! Default offline threshold (seconds) - if exceeded, skip advisory.
constexpr int64_t ADVISORY_OFFLINE_THRESHOLD_SECS = 6 * 60 * 60;  // 6 hours
//! Default calibration window (blocks).
constexpr int ADVISORY_CALIBRATION_WINDOW = 2000;
//! Minimum calibration window size (blocks) to derive sec_per_tick.
constexpr int ADVISORY_CALIBRATION_MIN_WINDOW = 100;
//! Default maximum blocks to read for txid collection to limit disk I/O.
//! For deep reorgs, we sample recent blocks rather than reading all.
//! Can be overridden via -reorgadvisorytxidblocks.
constexpr int DEFAULT_MAX_BLOCKS_FOR_TXIDS = 100;
//! Maximum number of recent advisories to retain for RPC query.
constexpr size_t MAX_STORED_ADVISORIES = 100;

// Forward declarations for argument defaults.
int GetMaxBlocksForTxids();

/**
 * Statistics for a chain segment (between LCA and a tip).
 * Used by the reorg advisory system to compare competing branches.
 */
struct SegmentStats {
    //! Number of blocks in this segment (tip - LCA).
    int block_count{0};

    //! Cumulative chainwork difference: tip.nChainWork - lca.nChainWork
    arith_uint256 work_diff{0};

    //! Cumulative VDF tick difference: tip.cumulative_tick - lca.cumulative_tick
    uint64_t ticks_diff{0};

    //! Wall-clock time (seconds) based on first_seen_ts: first_seen(tip) - first_seen(lca)
    //! 0 if either first_seen is unknown.
    int64_t clock_time_secs{0};

    //! Miner-reported time (seconds): tip.nTime - lca.nTime
    int64_t miner_time_secs{0};

    //! Set of non-coinbase transaction IDs in this segment.
    //! Limited to first MAX_BLOCKS_FOR_TXIDS blocks from tip to avoid excessive disk I/O.
    std::set<uint256> txids;

    //! Number of blocks successfully read for txid collection.
    int blocks_read_for_txids{0};

    //! Number of blocks that couldn't be read (pruned or error).
    int blocks_pruned{0};

    //! Whether txid collection was capped due to segment size.
    bool txids_capped{false};

    //! Whether all required data was available to compute this segment.
    bool data_complete{false};

    //! Estimated hashrate (work/time) using clock time. 0 if clock_time <= 0.
    //! Note: Returns relative hashrate units; for percentage comparison use baseline.
    double HashRateFromClock() const {
        if (clock_time_secs <= 0) return 0.0;
        if (work_diff == arith_uint256(0)) return 0.0;
        // Use GetLow64() for approximate comparison - sufficient for relative metrics
        return static_cast<double>(work_diff.GetLow64()) / static_cast<double>(clock_time_secs);
    }

    //! Estimated hashrate using tick-derived time. 0 if ticks_diff <= 0.
    double HashRateFromTicks(double sec_per_tick) const {
        if (sec_per_tick <= 0.0 || ticks_diff == 0) return 0.0;
        double time_from_ticks = static_cast<double>(ticks_diff) * sec_per_tick;
        if (time_from_ticks <= 0.0) return 0.0;
        if (work_diff == arith_uint256(0)) return 0.0;
        return static_cast<double>(work_diff.GetLow64()) / time_from_ticks;
    }
};

/**
 * Calibration data for tick-to-time conversion, computed from a window of blocks.
 */
struct TickTimeCalibration {
    //! Seconds per VDF tick, estimated from historical data.
    double sec_per_tick{0.0};

    //! Baseline network hashrate (work per second) at the LCA.
    double baseline_hashrate{0.0};

    //! Number of blocks used in calibration window.
    int window_blocks{0};

    //! Whether calibration data is reliable.
    bool is_valid{false};

    //! Human-readable reason if not valid.
    std::string invalid_reason;
};

/**
 * Full advisory payload for a deep reorg event.
 */
struct ReorgAdvisory {
    //! Height of the last common ancestor.
    int lca_height{-1};

    //! Reorg depth on current chain (current_tip - lca).
    int depth_current{0};

    //! Reorg depth on new fork (fork_tip - lca).
    int depth_fork{0};

    //! Transaction overlap percentage (Jaccard index: intersection/union * 100).
    double tx_overlap_pct{0.0};

    //! Delay (seconds) before first competing block was seen.
    //! max(first_seen - miner_ts, first_seen - tick_expected_ts)
    int64_t first_block_delay_secs{0};

    //! Estimated hashrate on current segment as % of baseline.
    double hashrate_current_pct{0.0};

    //! Estimated hashrate on fork segment as % of baseline.
    double hashrate_fork_pct{0.0};

    //! Tick-to-time calibration used.
    TickTimeCalibration calibration;

    //! Segment statistics for current chain.
    SegmentStats seg_current;

    //! Segment statistics for new fork.
    SegmentStats seg_fork;

    //! Seconds since we last saw a block (for liveness check).
    int64_t since_last_block_secs{0};

    //! Whether advisory computation succeeded.
    bool is_valid{false};

    //! Human-readable summary for logging.
    std::string Summary() const;
};

/**
 * Block data source interface used by advisory computation.
 * Allows plugging in caching or test fakes without touching ChainstateManager.
 */
class BlockDataSource
{
public:
    virtual ~BlockDataSource() = default;

    /** Read a full block for the given index. */
    virtual bool ReadBlock(const CBlockIndex& index, CBlock& block) const = 0;

    /** Get the first-seen timestamp for a block, or 0 if unknown. */
    virtual int64_t GetFirstSeenTs(const uint256& block_hash) const = 0;
};

/**
 * Cached block data source backed by ChainstateManager/BlockManager.
 * Maintains a small LRU to reduce disk reads during advisory computation.
 */
class CachedBlockDataSource : public BlockDataSource
{
private:
    ChainstateManager& m_chainman;
    const node::BlockManager& m_blockman;
    size_t m_max_entries;
    mutable Mutex m_mutex;
    mutable std::deque<uint256> m_order GUARDED_BY(m_mutex);
    mutable std::map<uint256, CBlock> m_cache GUARDED_BY(m_mutex);

    void TouchEntry(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Trim() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    CachedBlockDataSource(ChainstateManager& chainman,
                          const node::BlockManager& blockman,
                          size_t max_entries = 256);

    bool ReadBlock(const CBlockIndex& index, CBlock& block) const override;
    int64_t GetFirstSeenTs(const uint256& block_hash) const override;
};

/**
 * Lambda-backed data source for unit tests.
 */
class LambdaBlockDataSource : public BlockDataSource
{
private:
    std::function<bool(const CBlockIndex&, CBlock&)> m_reader;
    std::function<int64_t(const uint256&)> m_first_seen;

public:
    LambdaBlockDataSource(std::function<bool(const CBlockIndex&, CBlock&)> reader,
                          std::function<int64_t(const uint256&)> first_seen)
        : m_reader(std::move(reader)), m_first_seen(std::move(first_seen)) {}

    bool ReadBlock(const CBlockIndex& index, CBlock& block) const override { return m_reader(index, block); }
    int64_t GetFirstSeenTs(const uint256& block_hash) const override { return m_first_seen(block_hash); }
};

/**
 * Calibrate tick-to-time conversion using a window of blocks before LCA.
 *
 * @param source Block data source with caching.
 * @param lca Last common ancestor block index.
 * @param window_blocks Number of blocks to use for calibration (default 2000).
 * @param min_window Minimum acceptable window size (default ADVISORY_CALIBRATION_MIN_WINDOW).
 * @return Calibration data.
 */
TickTimeCalibration CalibrateTickToTime(
    const BlockDataSource& source,
    const CBlockIndex* lca,
    int window_blocks = ADVISORY_CALIBRATION_WINDOW,
    int min_window = ADVISORY_CALIBRATION_MIN_WINDOW);

/**
 * Compute statistics for a chain segment between LCA and tip.
 *
 * @param source Block data source with caching.
 * @param lca Last common ancestor.
 * @param tip Segment tip.
 * @param sec_per_tick Tick-to-time calibration factor.
 * @param max_blocks_for_txids Limit for txid collection to bound disk I/O.
 * @return Segment statistics.
 */
SegmentStats ComputeSegmentStats(
    const BlockDataSource& source,
    const CBlockIndex* lca,
    const CBlockIndex* tip,
    double sec_per_tick,
    int max_blocks_for_txids = GetMaxBlocksForTxids());

/**
 * Compute transaction overlap between two segments (Jaccard index).
 *
 * @param seg_a First segment stats.
 * @param seg_b Second segment stats.
 * @return Overlap percentage (0-100).
 */
double ComputeTxOverlap(const SegmentStats& seg_a, const SegmentStats& seg_b);

/**
 * Compute the delay before the first competing block was seen.
 *
 * @param source Block data source with caching.
 * @param lca Last common ancestor.
 * @param first_fork_block First block on the fork after LCA.
 * @param sec_per_tick Tick-to-time calibration factor.
 * @return Delay in seconds (max of timestamp-based and tick-based estimates).
 */
int64_t ComputeFirstBlockDelay(
    const BlockDataSource& source,
    const CBlockIndex* lca,
    const CBlockIndex* first_fork_block,
    double sec_per_tick);

/**
 * Generate a full reorg advisory for a proposed chain switch.
 *
 * @param source Block data source (may include caching).
 * @param current_tip Current active chain tip.
 * @param fork_tip Proposed new tip (competing fork).
 * @param lca Last common ancestor.
 * @param calibration_window Window size for sec_per_tick estimation.
 * @param calibration_min_window Minimum acceptable window.
 * @return ReorgAdvisory with all computed metrics.
 */
ReorgAdvisory GenerateReorgAdvisory(
    const BlockDataSource& source,
    const CBlockIndex* current_tip,
    const CBlockIndex* fork_tip,
    const CBlockIndex* lca,
    int calibration_window = ADVISORY_CALIBRATION_WINDOW,
    int calibration_min_window = ADVISORY_CALIBRATION_MIN_WINDOW);

// Convenience wrapper for production callers using ChainstateManager/BlockManager.
ReorgAdvisory GenerateReorgAdvisory(
    ChainstateManager& chainman,
    const node::BlockManager& blockman,
    const CBlockIndex* current_tip,
    const CBlockIndex* fork_tip,
    const CBlockIndex* lca);

/**
 * Compute and log a reorg advisory.
 *
 * Advisory computation happens synchronously (using chainman/blockman references),
 * but logging and storing to the global advisory store happens asynchronously
 * to minimize time holding cs_main.
 *
 * Safe to call while holding cs_main; logging runs in a background task.
 */
void AsyncLogReorgAdvisory(
    ChainstateManager& chainman,
    const node::BlockManager& blockman,
    const CBlockIndex* current_tip,
    const CBlockIndex* fork_tip,
    const CBlockIndex* lca);

/**
 * Configuration for reorg advisory system, read from command-line args.
 */
struct ReorgAdvisoryConfig {
    //! Whether advisory system is enabled.
    bool enabled{true};

    //! Minimum reorg depth to trigger advisory logging.
    int depth_threshold{ADVISORY_DEPTH_THRESHOLD};

    //! Skip advisory if offline longer than this (seconds).
    int64_t offline_threshold_secs{ADVISORY_OFFLINE_THRESHOLD_SECS};
};

/**
 * Get the current reorg advisory configuration.
 * Reads from gArgs on each call (not cached).
 */
ReorgAdvisoryConfig GetReorgAdvisoryConfig();

/**
 * Check if a reorg should trigger advisory logging.
 *
 * @param depth_current Reorg depth on current chain.
 * @param since_last_block Seconds since last block was seen.
 * @param config Optional config; if not provided, reads from gArgs.
 * @return true if advisory should be generated (enabled AND depth > threshold AND since_last < offline_threshold).
 */
bool ShouldTriggerAdvisory(int depth_current, int64_t since_last_block,
                           const std::optional<ReorgAdvisoryConfig>& config = std::nullopt);

/**
 * Thread-safe storage for recent reorg advisories.
 * Stores the most recent MAX_STORED_ADVISORIES entries in a circular buffer.
 */
class ReorgAdvisoryStore
{
private:
    mutable Mutex m_mutex;
    std::deque<ReorgAdvisory> m_advisories GUARDED_BY(m_mutex);

public:
    /**
     * Store a new advisory. If at capacity, removes the oldest entry.
     */
    void Add(const ReorgAdvisory& advisory);

    /**
     * Get the most recent advisory, if any.
     */
    std::optional<ReorgAdvisory> GetLatest() const;

    /**
     * Get the N most recent advisories (newest first).
     * @param count Maximum number to return.
     */
    std::vector<ReorgAdvisory> GetRecent(size_t count) const;

    /**
     * Get all stored advisories (newest first).
     */
    std::vector<ReorgAdvisory> GetAll() const;

    /**
     * Get count of stored advisories.
     */
    size_t Size() const;

    /**
     * Clear all stored advisories.
     */
    void Clear();
};

/**
 * Global store for recent reorg advisories.
 * Used by AsyncLogReorgAdvisory and RPC.
 */
ReorgAdvisoryStore& GetReorgAdvisoryStore();

/**
 * Background worker pool for async advisory logging.
 * Uses a single worker thread with a bounded queue to prevent
 * thread proliferation and ensure clean shutdown.
 */
class AdvisoryWorkerPool
{
private:
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<ReorgAdvisory> m_queue GUARDED_BY(m_mutex);
    std::thread m_worker;
    std::atomic<bool> m_shutdown{false};
    std::atomic<bool> m_started{false};

    //! Maximum queue size to prevent unbounded memory growth.
    static constexpr size_t MAX_QUEUE_SIZE = 100;

    void WorkerLoop();

public:
    AdvisoryWorkerPool() = default;
    ~AdvisoryWorkerPool();

    /**
     * Start the worker thread. Idempotent.
     */
    void Start();

    /**
     * Stop the worker thread and drain the queue.
     * Blocks until worker exits. Called during shutdown.
     */
    void Stop();

    /**
     * Submit an advisory for async logging/storing.
     * If queue is full, drops oldest entry to make room.
     */
    void Submit(ReorgAdvisory advisory);

    /**
     * Check if the worker is running.
     */
    bool IsRunning() const { return m_started.load() && !m_shutdown.load(); }
};

/**
 * Global advisory worker pool instance.
 */
AdvisoryWorkerPool& GetAdvisoryWorkerPool();

/**
 * Stop the advisory worker pool (call during Shutdown).
 */
void StopAdvisoryWorkerPool();

// ============================================================================
// REORG GATING - Operator decision required before chain switch
// ============================================================================

/**
 * Operator decision for a pending reorg.
 */
enum class ReorgDecision {
    NONE,    //!< No decision yet (pending)
    ACCEPT,  //!< Accept the reorg, switch to fork
    REJECT,  //!< Reject the reorg, stay on current chain
    TIMEOUT, //!< Decision timed out, use default action
    ABORT    //!< Shutdown interrupt: no decision, no approval, stay on current tip
};

/**
 * How an armed gate constrains the node.
 */
enum class ReorgGatingMode {
    BLOCK, //!< Legacy: park ActivateBestChain until decision (interrupt-aware)
    MASK   //!< Non-blocking: exclude the gated subtree from fork choice, keep validating
};

/**
 * Gate lifecycle state.
 */
enum class ReorgGateState {
    PENDING, //!< Awaiting an operator decision; candidate subtree masked (mask mode)
    VETOED   //!< Operator REJECT: TTL-bound local veto with growth/raw-work escape
};

/**
 * Classification of a gate's anchor for moot-gate pruning.
 */
enum class ReorgGateAnchorStatus {
    KEEP,            //!< Anchor is live and off the active chain: the gate stands
    INVALIDATED,     //!< Anchor carries BLOCK_FAILED_MASK: the candidate subtree can never be selected
    ON_ACTIVE_CHAIN, //!< Anchor is on the active chain: the operator already followed the branch
};

/**
 * Work comparison between the active tip and a gate's candidate, taken under
 * cs_main. Raw work (CBlockIndex::nChainWorkRaw) is the never-policy-mutated
 * consensus chainwork; policy work is nChainWork after Full_Red / challenge
 * zero-work demotion, with nChainPenalty subtracted by the fork-choice
 * comparator on top.
 */
struct ReorgGateWorkSnapshot {
    arith_uint256 current_work{};        //!< Policy nChainWork of the active tip
    arith_uint256 candidate_work{};      //!< Policy nChainWork of the candidate tip
    arith_uint256 current_penalty{};     //!< nChainPenalty of the active tip
    arith_uint256 candidate_penalty{};   //!< nChainPenalty of the candidate tip
    arith_uint256 current_raw_work{};    //!< nChainWorkRaw of the active tip
    arith_uint256 candidate_raw_work{};  //!< nChainWorkRaw of the candidate tip

    //! Candidate wins on policy-effective work but does not win on raw work:
    //! the reorg is manufactured by local penalty/policy demotion, not by
    //! genuine consensus work. Such a candidate must never be auto-accepted.
    bool penalty_or_policy_driven{false};
};

/**
 * One reorg gate, keyed by {fork point, candidate subtree anchor}. The anchor
 * is the fork-point child on the candidate branch: the branch keeps growing
 * while gated, so every extension stays covered by the same gate until a
 * decision (or, for a veto, until the growth / raw-work escape fires). Same
 * anchoring discipline as ReorgApprovalState.
 */
struct ReorgGateEntry {
    //! Monotonic identifier; RPC decisions target a gate by id so a decision
    //! can never hit the wrong fork when multiple gates exist.
    uint64_t gate_id{0};

    //! Generation nonce, bumped by every operator decision. A scheduler
    //! timeout may only transition the gate if its armed generation still
    //! matches, which makes timeout-vs-operator races no-ops by construction.
    uint64_t generation{0};

    ReorgGateState gate_state{ReorgGateState::PENDING};

    //! The advisory computed when the gate was armed.
    ReorgAdvisory advisory;

    //! Hash of the fork point (last common ancestor of current and candidate tips).
    uint256 fork_point_hash;

    //! Hash of the candidate subtree anchor (fork-point child on the candidate branch).
    uint256 anchor_hash;

    //! Hash of the candidate (fork) tip when the gate was last armed/refreshed.
    uint256 candidate_tip_hash;

    //! Height of that candidate tip (growth-escape baseline bookkeeping).
    int candidate_height{0};

    //! Hash of the active tip at time of detection.
    uint256 current_tip_hash;

    //! Work comparison at arm/refresh time.
    ReorgGateWorkSnapshot work;

    //! Timestamp when the gate was armed.
    int64_t pending_since{0};

    //! The operator's decision (NONE while pending; consumed by the BLOCK-mode waiter).
    ReorgDecision decision{ReorgDecision::NONE};

    // Veto state (gate_state == VETOED).
    //! Timestamp when the veto was recorded.
    int64_t vetoed_at{0};
    //! Candidate tip height at veto time; the veto escapes early when the
    //! branch extends >= veto_growth_blocks beyond this.
    int veto_candidate_height{0};
    //! Whether the candidate led the tip on raw work at veto time.
    bool veto_margin_positive{false};
    //! Raw-work margin of the candidate over the tip at veto time; the veto
    //! escapes early when the live margin grows past this baseline.
    arith_uint256 veto_raw_margin{};
};

/**
 * A durable record of an operator ACCEPT decision, anchored to the reorg's
 * fork point. A deep competing chain's block bodies arrive incrementally over
 * P2P, so a single reorg re-enters the gate once per arriving segment while
 * the tip is still on the old branch. The fork point is invariant across all
 * segments of one reorg, so one ACCEPT recorded here covers every later
 * segment that extends the approved candidate.
 */
struct ReorgApprovalState {
    //! Whether an approval is recorded (and not yet expired).
    bool is_valid{false};

    //! Fork point of the approved reorg (invariant across its segments).
    uint256 fork_point_hash;

    //! Candidate tip the operator saw when approving. Later candidates must
    //! descend from this block to be covered by the approval.
    uint256 candidate_tip_hash;

    //! Active tip whose replacement the operator approved. The approval only
    //! covers switches away from this exact tip, so it cannot leak onto a
    //! later switch from a different branch within the TTL.
    uint256 current_tip_hash;

    //! Timestamp when the approval was recorded.
    int64_t approved_at{0};
};

//! Default timeout for operator decision (30 minutes).
constexpr int64_t DEFAULT_REORG_DECISION_TIMEOUT_SECS = 30 * 60;

//! Default action on timeout: true = accept, false = reject.
constexpr bool DEFAULT_REORG_TIMEOUT_ACTION_ACCEPT = false;

//! Default operator gating for deep reorgs.
constexpr bool DEFAULT_REORG_GATING_ENABLED = true;

//! Default auto-follow policy for reorgs that look like sane partition recovery.
constexpr bool DEFAULT_REORG_AUTOFOLLOW_SANE_PARTITIONS = true;

//! Candidate fork hashrate must be plausible relative to the calibrated baseline.
constexpr int DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_HASHRATE_PCT = 25;
constexpr int DEFAULT_REORG_AUTOFOLLOW_MAX_FORK_HASHRATE_PCT = 400;

//! Candidate fork hashrate must materially exceed the local branch hashrate.
constexpr int DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_TO_CURRENT_RATIO_PCT = 125;

//! A sane partition should have delayed first visibility of the competing branch.
constexpr int64_t DEFAULT_REORG_AUTOFOLLOW_MIN_FIRST_BLOCK_DELAY_SECS = 20 * 60;

//! Default validity window for a recorded reorg approval (1 hour).
constexpr int64_t DEFAULT_REORG_APPROVAL_TTL_SECS = 60 * 60;

//! Default gating mode. MASK keeps every validation thread live: a gated
//! branch is excluded from fork choice until a decision instead of parking
//! ActivateBestChain. BLOCK is the one-release escape hatch back to the old
//! parked behavior (with an interrupt-aware wait).
constexpr ReorgGatingMode DEFAULT_REORG_GATING_MODE = ReorgGatingMode::MASK;

//! Default TTL for an operator REJECT veto (1 hour), clamped like the approval TTL.
constexpr int64_t DEFAULT_REORG_VETO_TTL_SECS = 60 * 60;

//! Default growth escape: a vetoed branch that extends this many blocks past
//! its length at veto time escapes the veto early and re-prompts (once).
constexpr int DEFAULT_REORG_VETO_GROWTH_BLOCKS = 6;

/**
 * Gating configuration read from command-line args.
 */
struct ReorgGatingConfig {
    //! Whether gating is enabled (-reorgadvisorygating=1).
    bool enabled{DEFAULT_REORG_GATING_ENABLED};

    //! Timeout for operator decision in seconds.
    int64_t timeout_secs{DEFAULT_REORG_DECISION_TIMEOUT_SECS};

    //! Default action on timeout: true = accept fork, false = reject (stay on current).
    bool timeout_accept{DEFAULT_REORG_TIMEOUT_ACTION_ACCEPT};

    //! Minimum depth to trigger gating (can be different from advisory threshold).
    int gating_depth_threshold{ADVISORY_DEPTH_THRESHOLD};

    //! Auto-follow reorgs classified as sane partition recovery instead of blocking.
    bool autofollow_sane_partitions{DEFAULT_REORG_AUTOFOLLOW_SANE_PARTITIONS};

    //! Plausible candidate fork hashrate band, as percentage of calibrated baseline.
    int autofollow_min_fork_hashrate_pct{DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_HASHRATE_PCT};
    int autofollow_max_fork_hashrate_pct{DEFAULT_REORG_AUTOFOLLOW_MAX_FORK_HASHRATE_PCT};

    //! Candidate fork hashrate must be at least this percentage of current-branch hashrate.
    int autofollow_min_fork_to_current_ratio_pct{DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_TO_CURRENT_RATIO_PCT};

    //! Minimum delay before the first competing block was seen.
    int64_t autofollow_min_first_block_delay_secs{DEFAULT_REORG_AUTOFOLLOW_MIN_FIRST_BLOCK_DELAY_SECS};

    //! How long a recorded ACCEPT keeps covering later segments of the same reorg.
    int64_t approval_ttl_secs{DEFAULT_REORG_APPROVAL_TTL_SECS};

    //! Whether the gate constrains fork choice (MASK) or parks activation (BLOCK).
    ReorgGatingMode gating_mode{DEFAULT_REORG_GATING_MODE};

    //! How long an operator REJECT veto masks the branch before it may re-prompt.
    int64_t veto_ttl_secs{DEFAULT_REORG_VETO_TTL_SECS};

    //! Blocks of growth beyond the veto-time candidate tip that escape the veto early.
    int veto_growth_blocks{DEFAULT_REORG_VETO_GROWTH_BLOCKS};
};

/**
 * Get the current reorg gating configuration.
 */
ReorgGatingConfig GetReorgGatingConfig();

/**
 * Thread-safe manager for reorg gates.
 *
 * Holds a keyed map {fork point, anchor} -> gate entry. In MASK mode no
 * validation thread ever waits: FindMostWorkChain skips candidates that
 * descend through a pending/vetoed anchor at selection time, and decisions
 * (operator RPC, scheduler timeout) transition gates under m_mutex and kick
 * ActivateBestChain from the scheduler thread. In BLOCK mode the legacy
 * parked wait is kept, sliced into 1s ticks with an interrupt check.
 *
 * Gates, vetoes and masks are in-memory only: a restart clears them and may
 * re-prompt for a still-live gated branch, but never auto-accepts one.
 */
class ReorgGatingManager
{
public:
    //! Outcome of resolving/applying an operator action against the gate map.
    enum class SubmitStatus {
        OK,           //!< Action applied
        NO_GATE,      //!< No gate exists (or none in the required state)
        UNKNOWN_GATE, //!< gate_id does not match any live gate
        AMBIGUOUS,    //!< Bare form used while multiple gates are live
        BAD_STATE     //!< Gate exists but is not in a state this action applies to
    };

private:
    //! Gate key: {fork point hash, candidate subtree anchor hash}.
    using GateKey = std::pair<uint256, uint256>;

    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::map<GateKey, ReorgGateEntry> m_gates GUARDED_BY(m_mutex);
    uint64_t m_next_gate_id GUARDED_BY(m_mutex){1};
    uint64_t m_next_generation GUARDED_BY(m_mutex){1};
    ReorgApprovalState m_approval GUARDED_BY(m_mutex);
    ReorgGatingConfig m_config;

    //! Scheduler hooks, wired at init; absent in unit tests (no timers fire,
    //! tests drive HandleTimeout directly).
    std::function<void(std::function<void()>, int64_t)> m_schedule_fn GUARDED_BY(m_mutex);
    //! Runs ActivateBestChain after a gate clears. Executed on the dedicated
    //! kick thread, NEVER on the scheduler thread: the scheduler drains the
    //! validation-interface queue (SerialTaskRunner), and ActivateBestChain
    //! waits on that queue, so running it there self-deadlocks.
    std::function<void()> m_kick_fn GUARDED_BY(m_mutex);
    //! Fresh work snapshot (takes cs_main) for decision-time guardrails.
    std::function<std::optional<ReorgGateWorkSnapshot>(const uint256&)> m_snapshot_fn GUARDED_BY(m_mutex);

    //! Dedicated one-task worker that runs m_kick_fn off both the RPC and
    //! scheduler threads. Started by SetAsyncHooks, joined by ResetAsyncHooks
    //! (i.e. before the chainman the kick references is torn down).
    std::thread m_kick_thread;
    bool m_kick_requested GUARDED_BY(m_mutex){false};
    bool m_kick_stop GUARDED_BY(m_mutex){false};

    void KickWorker();

    ReorgGateEntry* FindGateById(uint64_t gate_id) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    //! Resolve an optional gate_id to a live gate (bare form allowed only when
    //! exactly one gate exists).
    std::pair<SubmitStatus, ReorgGateEntry*> ResolveGate(const std::optional<uint64_t>& gate_id)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void RecordApprovalFromEntry(const ReorgGateEntry& entry) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ConvertToVeto(ReorgGateEntry& entry, const char* origin) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ArmTimeout(uint64_t gate_id, uint64_t generation);

public:
    ReorgGatingManager();
    //! Test constructor: fixed config, never reads gArgs.
    explicit ReorgGatingManager(const ReorgGatingConfig& config);
    //! Joins the kick thread if ResetAsyncHooks was never reached (a joinable
    //! std::thread at destruction would std::terminate).
    ~ReorgGatingManager();

    /**
     * Check if gating is enabled.
     */
    bool IsEnabled() const;

    /**
     * The configured gating mode (BLOCK or MASK).
     */
    ReorgGatingMode GatingMode() const;

    /**
     * Wire the scheduler/chainstate hooks. Called once at init after the
     * scheduler and chainman exist; reset before they are torn down.
     */
    void SetAsyncHooks(std::function<void(std::function<void()>, int64_t)> schedule_fn,
                       std::function<void()> kick_fn,
                       std::function<std::optional<ReorgGateWorkSnapshot>(const uint256&)> snapshot_fn);
    void ResetAsyncHooks();

    /**
     * Arm (or refresh) the gate for {fork_point, anchor}. Idempotent: an
     * existing entry keeps its gate_id/generation and only refreshes the
     * candidate tip/advisory/work snapshot; a vetoed entry is left untouched.
     * In MASK mode a newly armed gate also arms its scheduler timeout.
     *
     * @return gate_id of the (new or existing) gate.
     */
    uint64_t SetPending(const ReorgAdvisory& advisory,
                        const uint256& candidate_tip_hash,
                        int candidate_height,
                        const uint256& current_tip_hash,
                        const uint256& fork_point_hash,
                        const uint256& anchor_hash,
                        const ReorgGateWorkSnapshot& work);

    /**
     * Snapshot of all live gates (pending and vetoed), gate_id ascending.
     */
    std::vector<ReorgGateEntry> GetGates() const;

    /**
     * Copy of a single gate by id, if live.
     */
    std::optional<ReorgGateEntry> GetGate(uint64_t gate_id) const;

    /**
     * {gate_id, anchor hash} of every live gate. Cheap accessor for the
     * FindMostWorkChain selection loop (GetGates copies full advisories).
     */
    std::vector<std::pair<uint64_t, uint256>> GetGateAnchors() const;

    /**
     * Number of live gates (pending and vetoed).
     */
    size_t GateCount() const;

    /**
     * Check if any gate is awaiting an operator decision.
     */
    bool HasPending() const;

    /**
     * Submit an operator decision (ACCEPT or REJECT) for one gate.
     * Bare form (no gate_id) is sugar allowed only when exactly one gate is
     * live. In MASK mode the transition is applied inline: ACCEPT records the
     * durable approval, drops the gate and kicks ActivateBestChain; REJECT
     * converts the gate to a TTL veto. In BLOCK mode the parked waiter applies
     * the transition. Idempotent: a decision against a gate that already
     * transitioned reports UNKNOWN_GATE and changes nothing. Every operator
     * decision bumps the gate generation, so a stale armed timeout is a no-op.
     *
     * @param[out] out_gate_id The resolved gate id (set on OK).
     */
    SubmitStatus SubmitDecision(const std::optional<uint64_t>& gate_id, ReorgDecision decision,
                                uint64_t* out_gate_id = nullptr);

    /**
     * Drop a VETOED gate so the branch may re-prompt on the next activation.
     * Kicks ActivateBestChain so the re-prompt does not wait for a new block.
     */
    SubmitStatus ClearVeto(const std::optional<uint64_t>& gate_id, uint64_t* out_gate_id = nullptr);

    /**
     * Drop a gate unconditionally (any state). Safe to call for an id that no
     * longer exists.
     *
     * @return true if a gate was removed.
     */
    bool RemoveGate(uint64_t gate_id, const std::string& reason);

    /**
     * Sweep gates (pending and vetoed) whose anchor the classifier reports as
     * moot: INVALIDATED (the operator marked the anchor or an ancestor
     * BLOCK_FAILED, so the candidate subtree can never be selected) or
     * ON_ACTIVE_CHAIN (the operator already forced the branch active). The
     * classifier runs without the gate mutex held, so it may take cs_main.
     *
     * @return number of gates removed.
     */
    size_t PruneMootGates(const std::function<ReorgGateAnchorStatus(const uint256& anchor_hash)>& classify);

    /**
     * BLOCK mode only: wait for an operator decision, timeout, or interrupt
     * on the sole pending gate. The wait is sliced into 1s ticks; when
     * interrupted() reports true the wait aborts WITHOUT deciding and returns
     * ABORT (callers must clear the gate and stay on the current tip).
     *
     * @return ACCEPT, REJECT, TIMEOUT, ABORT, or NONE if no gate is pending.
     */
    ReorgDecision WaitForDecision(const std::function<bool()>& interrupted);

    /**
     * MASK mode selection-time check for one gate. PENDING gates always mask,
     * and are refreshed from the live candidate seen here (the mask prevents
     * ActivateBestChainStep from re-arming the gate, so this is where the
     * gate tracks the growing branch the operator will decide on). A VETOED
     * gate masks until its TTL expires or an escape fires (branch extended
     * >= veto_growth_blocks, or its raw-work margin over the tip grew past
     * the veto-time baseline); an expired/escaped veto is dropped here so the
     * branch re-prompts (once) through ActivateBestChainStep.
     *
     * @return true if candidates descending through this gate's anchor must be
     *         skipped by FindMostWorkChain.
     */
    bool EvaluateMask(uint64_t gate_id, const uint256& candidate_hash, int candidate_height,
                      const arith_uint256& candidate_raw_work,
                      const arith_uint256& tip_raw_work);

    /**
     * Scheduler timeout for a MASK-mode gate. Transitions the gate only if it
     * is still PENDING and its generation matches the one the timer was armed
     * with (an operator decision bumps the generation, so a stale timer is a
     * no-op). Default action is veto-REJECT; with timeout_accept=1 the gate
     * auto-accepts only when TimeoutAcceptAllowed passes on a fresh work
     * snapshot, and vetoes otherwise.
     */
    void HandleTimeout(uint64_t gate_id, uint64_t generation);

    /**
     * BLOCK mode: record a durable approval from the sole gate.
     * Called on ACCEPT (operator or timeout-accept) BEFORE ClearPending, so
     * that later segments of the same reorg skip the gate instead of
     * re-prompting the operator once per segment.
     */
    void RecordApprovalFromPending();

    /**
     * BLOCK mode: drop the sole gate after its decision has been processed
     * (or on interrupt, without any decision).
     */
    void ClearPending();

    /**
     * Get the recorded approval, if any.
     * Returns a default (is_valid=false) state when none is recorded or the
     * approval has outlived its TTL.
     */
    ReorgApprovalState GetApproval() const;

    /**
     * Drop any recorded approval.
     */
    void ClearApproval();

    /**
     * Reload configuration from gArgs.
     */
    void ReloadConfig();

    /**
     * Get remaining time until timeout (seconds) for the oldest pending gate.
     * Returns 0 if no pending gate or already timed out.
     */
    int64_t GetTimeoutRemaining() const;

    /**
     * §3.5 timeout-accept guardrail: a timeout may auto-accept only a
     * candidate that is strictly heavier in RAW consensus work and not
     * penalty/policy-driven. Everything else times out as veto-REJECT.
     */
    static bool TimeoutAcceptAllowed(const ReorgGateWorkSnapshot& work);
};

/**
 * Global reorg gating manager instance.
 */
ReorgGatingManager& GetReorgGatingManager();

/**
 * Work comparison between two block indexes (active tip vs candidate tip).
 * Uses the policy comparator for the effective-work side and nChainWorkRaw for
 * the raw side, so penalty_or_policy_driven is exactly "candidate wins on
 * effective work but not on raw work".
 */
ReorgGateWorkSnapshot ComputeReorgGateWorkSnapshot(const CBlockIndex& current_tip,
                                                   const CBlockIndex& candidate_tip);

/**
 * Fresh snapshot of a candidate against the CURRENT active tip; nullopt when
 * either index is unavailable. Requires cs_main.
 */
std::optional<ReorgGateWorkSnapshot> ComputeReorgGateWorkSnapshot(ChainstateManager& chainman,
                                                                  const uint256& candidate_tip_hash)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/**
 * Eagerly drop gates made moot by an operator chain action: anchor (or an
 * ancestor) marked BLOCK_FAILED by invalidateblock, or anchor forced onto the
 * active chain by reconsiderblock. Called from the operator RPC wrappers
 * after the chain action and ActivateBestChain complete, so a dead gate never
 * lingers in getpendingreorg until timeout/TTL. The lazy check in
 * Chainstate::IsReorgGateMaskedCandidate remains as a backstop.
 * Lock order: cs_main outer, gate mutex inner.
 */
void PruneMootReorgGates(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/**
 * Check if a reorg should be gated (require operator decision).
 *
 * @param depth_current Reorg depth on current chain.
 * @param since_last_block Seconds since last block was seen.
 * @param disconnect_only True when the candidate chain is an ancestor of the current tip.
 * @param config Optional config; if not provided, reads from gArgs.
 * @return true if gating is enabled and thresholds are met.
 */
bool ShouldGateReorg(int depth_current, int64_t since_last_block, bool disconnect_only = false,
                     const std::optional<ReorgGatingConfig>& config = std::nullopt);

/**
 * Check if an otherwise-gated reorg should auto-follow as sane partition recovery.
 *
 * This intentionally ignores transaction overlap as an accept signal because empty
 * block segments report 100% overlap.
 *
 * @param advisory Full advisory metrics for the candidate reorg.
 * @param config Optional config; if not provided, reads from gArgs.
 * @return true if the candidate looks like a plausible higher-work public branch
 *         catching up after local partition, rather than an anomalous reorg.
 */
bool ShouldAutoFollowSanePartitionReorg(const ReorgAdvisory& advisory,
                                        const std::optional<ReorgGatingConfig>& config = std::nullopt);

/**
 * RAII guard marking the current thread as executing an operator-initiated
 * chain action (invalidateblock/reconsiderblock). While a guard is alive,
 * ShouldGateReorg returns false on this thread: the gate exists to obtain
 * operator sign-off, which the operator's own RPC call already carries, so
 * routing it back through the gate would only block the RPC thread until the
 * decision timeout.
 */
class ReorgGateOperatorAction
{
public:
    ReorgGateOperatorAction();
    ~ReorgGateOperatorAction();
    ReorgGateOperatorAction(const ReorgGateOperatorAction&) = delete;
    ReorgGateOperatorAction& operator=(const ReorgGateOperatorAction&) = delete;
};

/**
 * True while the current thread is inside a ReorgGateOperatorAction scope.
 */
bool ReorgGateOperatorActionActive();

#endif // BITCOIN_VALIDATIONADVISORY_H
