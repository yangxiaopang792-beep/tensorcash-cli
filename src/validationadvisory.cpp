// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validationadvisory.h>

#include <chain.h>
#include <common/args.h>
#include <common/system.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cmath>
#include <thread>
#include <map>

using util::ReplaceAll;

// ---------------------------------------------------------------------------
// Block data sources
// ---------------------------------------------------------------------------

CachedBlockDataSource::CachedBlockDataSource(ChainstateManager& chainman,
                                             const node::BlockManager& blockman,
                                             size_t max_entries)
    : m_chainman(chainman), m_blockman(blockman), m_max_entries(max_entries) {}

void CachedBlockDataSource::TouchEntry(const uint256& hash) const
{
    // Move hash to front of order deque
    for (auto it = m_order.begin(); it != m_order.end(); ++it) {
        if (*it == hash) {
            m_order.erase(it);
            break;
        }
    }
    m_order.push_front(hash);
}

void CachedBlockDataSource::Trim() const
{
    while (m_cache.size() > m_max_entries && !m_order.empty()) {
        const uint256& evict = m_order.back();
        m_cache.erase(evict);
        m_order.pop_back();
    }
}

bool CachedBlockDataSource::ReadBlock(const CBlockIndex& index, CBlock& block) const
{
    const uint256 hash = index.GetBlockHash();
    {
        LOCK(m_mutex);
        auto it = m_cache.find(hash);
        if (it != m_cache.end()) {
            block = it->second;
            TouchEntry(hash);
            return true;
        }
    }

    if (!m_blockman.ReadBlock(block, index)) {
        return false;
    }

    {
        LOCK(m_mutex);
        m_cache.emplace(hash, block);
        TouchEntry(hash);
        Trim();
    }
    return true;
}

int64_t CachedBlockDataSource::GetFirstSeenTs(const uint256& block_hash) const
{
    return m_blockman.GetBlockFirstSeenTs(block_hash);
}

std::string ReorgAdvisory::Summary() const
{
    if (!is_valid) {
        return "ReorgAdvisory: invalid/incomplete data";
    }

    // Build data quality suffix
    std::string data_notes;
    if (seg_current.txids_capped || seg_fork.txids_capped) {
        data_notes += " [txids_capped]";
    }
    int total_pruned = seg_current.blocks_pruned + seg_fork.blocks_pruned;
    if (total_pruned > 0) {
        data_notes += strprintf(" [%d_blocks_pruned]", total_pruned);
    }

    return strprintf(
        "ReorgAdvisory: LCA=%d, depth_cur=%d, depth_fork=%d, "
        "tx_overlap=%.1f%%, first_block_delay=%llds, "
        "hashrate_cur=%.1f%%, hashrate_fork=%.1f%%, "
        "sec_per_tick=%.6f, calibration_ok=%s%s",
        lca_height, depth_current, depth_fork,
        tx_overlap_pct, first_block_delay_secs,
        hashrate_current_pct, hashrate_fork_pct,
        calibration.sec_per_tick,
        calibration.is_valid ? "true" : "false",
        data_notes
    );
}

TickTimeCalibration CalibrateTickToTime(
    const BlockDataSource& source,
    const CBlockIndex* lca,
    int window_blocks,
    int min_window)
{
    TickTimeCalibration result;
    result.window_blocks = window_blocks;

    if (!lca) {
        result.invalid_reason = "LCA is null";
        return result;
    }

    // Try progressively smaller windows if blocks are pruned
    int try_window = window_blocks;

    while (try_window >= min_window) {
        const CBlockIndex* end_block = lca;
        const CBlockIndex* start_block = lca;
        int actual_window = 0;

        // Walk back try_window blocks from LCA
        for (int i = 0; i < try_window && start_block->pprev; ++i) {
            start_block = start_block->pprev;
            ++actual_window;
        }

        if (actual_window < min_window) {
            result.invalid_reason = strprintf("Window too small: %d blocks", actual_window);
            return result;
        }

        result.window_blocks = actual_window;

        // Try to read blocks - if pruned, reduce window
        CBlock end_blk, start_blk;
        if (!source.ReadBlock(*end_block, end_blk)) {
            // End block pruned - can't calibrate
            result.invalid_reason = "End block (LCA) pruned";
            return result;
        }

        if (!source.ReadBlock(*start_block, start_blk)) {
            // Start block pruned - try smaller window
            try_window /= 2;
            continue;
        }

        // Compute tick difference
        if (end_blk.cumulative_tick <= start_blk.cumulative_tick) {
            result.invalid_reason = "Non-positive tick difference";
            return result;
        }
        uint64_t ticks_diff = end_blk.cumulative_tick - start_blk.cumulative_tick;

        // Compute time difference from miner timestamps (always available from CBlockIndex)
        int64_t time_diff = static_cast<int64_t>(end_block->nTime) - static_cast<int64_t>(start_block->nTime);
        if (time_diff <= 0) {
            result.invalid_reason = "Non-positive time difference";
            return result;
        }

        // Compute sec_per_tick
        result.sec_per_tick = static_cast<double>(time_diff) / static_cast<double>(ticks_diff);

        // Compute baseline hashrate (work per second)
        // nChainWork is always available from CBlockIndex, no disk read needed
        arith_uint256 work_diff = end_block->nChainWork - start_block->nChainWork;
        if (work_diff == arith_uint256(0)) {
            result.invalid_reason = "Zero work difference";
            return result;
        }

        // Convert work to double for hashrate calculation (use full precision).
        double work_approx = work_diff.getdouble();
        result.baseline_hashrate = work_approx / static_cast<double>(time_diff);

        result.is_valid = true;
        return result;
    }

    result.invalid_reason = "All calibration windows pruned";
    return result;
}

SegmentStats ComputeSegmentStats(
    const BlockDataSource& source,
    const CBlockIndex* lca,
    const CBlockIndex* tip,
    double sec_per_tick,
    int max_blocks_for_txids)
{
    SegmentStats result;

    if (!lca || !tip) {
        return result;
    }

    // Compute block count
    result.block_count = tip->nHeight - lca->nHeight;
    if (result.block_count <= 0) {
        return result;
    }

    // Compute work difference
    result.work_diff = tip->nChainWork - lca->nChainWork;

    // Compute miner time difference
    result.miner_time_secs = static_cast<int64_t>(tip->nTime) - static_cast<int64_t>(lca->nTime);

    // Get first_seen timestamps
    int64_t lca_first_seen = source.GetFirstSeenTs(lca->GetBlockHash());
    int64_t tip_first_seen = source.GetFirstSeenTs(tip->GetBlockHash());

    if (lca_first_seen > 0 && tip_first_seen > 0) {
        result.clock_time_secs = tip_first_seen - lca_first_seen;
    }

    // Read LCA block for cumulative_tick (baseline)
    CBlock lca_blk;
    bool have_lca = source.ReadBlock(*lca, lca_blk);

    // Collect transaction IDs from blocks in the segment.
    // Limit to configurable max to avoid excessive disk I/O on deep reorgs.
    // For very deep reorgs, we sample the most recent blocks which are most
    // likely to be unpruned and most relevant for overlap analysis.
    //
    // We read tip first for cumulative_tick, then reuse it for txids to avoid
    // reading the same block twice.
    const CBlockIndex* pindex = tip;
    int blocks_attempted = 0;
    bool have_tip = false;
    uint64_t tip_cumulative_tick = 0;

    while (pindex && pindex != lca && (max_blocks_for_txids == 0 || blocks_attempted < max_blocks_for_txids)) {
        CBlock blk;
        if (source.ReadBlock(*pindex, blk)) {
            // Capture tip's cumulative_tick on first iteration
            if (pindex == tip) {
                have_tip = true;
                tip_cumulative_tick = blk.cumulative_tick;
            }

            // Collect non-coinbase txids
            for (size_t i = 1; i < blk.vtx.size(); ++i) {
                result.txids.insert(blk.vtx[i]->GetHash());
            }
            ++result.blocks_read_for_txids;
        } else {
            // Block is pruned or couldn't be read - track but continue
            if (pindex == tip) {
                // Tip is pruned - can't get tick data
                have_tip = false;
            }
            ++result.blocks_pruned;
        }
        pindex = pindex->pprev;
        ++blocks_attempted;
    }

    // Compute ticks_diff if we have both endpoints
    if (have_lca && have_tip) {
        result.ticks_diff = tip_cumulative_tick - lca_blk.cumulative_tick;
    }

    // Check if we hit the limit before reaching LCA
    if (pindex && pindex != lca) {
        result.txids_capped = true;
    }

    // Data is complete if we have tick data and timestamps.
    // Txid data may be partial (pruned or capped) but that's acceptable.
    result.data_complete = have_lca && have_tip && (lca_first_seen > 0) && (tip_first_seen > 0);
    return result;
}

double ComputeTxOverlap(const SegmentStats& seg_a, const SegmentStats& seg_b)
{
    if (seg_a.txids.empty() && seg_b.txids.empty()) {
        return 100.0;  // Both empty - degenerate case
    }

    // Compute intersection
    std::set<uint256> intersection;
    std::set_intersection(
        seg_a.txids.begin(), seg_a.txids.end(),
        seg_b.txids.begin(), seg_b.txids.end(),
        std::inserter(intersection, intersection.begin())
    );

    // Compute union size
    std::set<uint256> union_set;
    std::set_union(
        seg_a.txids.begin(), seg_a.txids.end(),
        seg_b.txids.begin(), seg_b.txids.end(),
        std::inserter(union_set, union_set.begin())
    );

    if (union_set.empty()) {
        return 100.0;
    }

    // Jaccard index
    return 100.0 * static_cast<double>(intersection.size()) / static_cast<double>(union_set.size());
}

int64_t ComputeFirstBlockDelay(
    const BlockDataSource& source,
    const CBlockIndex* lca,
    const CBlockIndex* first_fork_block,
    double sec_per_tick)
{
    if (!first_fork_block) {
        return 0;
    }

    int64_t first_seen = source.GetFirstSeenTs(first_fork_block->GetBlockHash());
    if (first_seen <= 0) {
        return 0;  // Unknown first_seen
    }

    // Delay vs miner timestamp (always available from CBlockIndex, no disk read)
    int64_t delta1 = std::max<int64_t>(0, first_seen - static_cast<int64_t>(first_fork_block->nTime));

    // Delay vs VDF-based expected time (requires disk reads, may fail on pruned nodes)
    int64_t delta2 = 0;
    if (lca && sec_per_tick > 0.0) {
        CBlock lca_blk, fork_blk;
        bool have_lca = source.ReadBlock(*lca, lca_blk);
        bool have_fork = source.ReadBlock(*first_fork_block, fork_blk);

        if (have_lca && have_fork) {
            uint64_t ticks_since_lca = fork_blk.cumulative_tick - lca_blk.cumulative_tick;
            double expected_time_from_ticks = static_cast<double>(lca->nTime) +
                                              static_cast<double>(ticks_since_lca) * sec_per_tick;
            delta2 = std::max<int64_t>(0, first_seen - static_cast<int64_t>(expected_time_from_ticks));
        }
        // If blocks are pruned, we fall back to delta1 (miner timestamp-based delay)
    }

    return std::max(delta1, delta2);
}

ReorgAdvisory GenerateReorgAdvisory(
    ChainstateManager& chainman,
    const node::BlockManager& blockman,
    const CBlockIndex* current_tip,
    const CBlockIndex* fork_tip,
    const CBlockIndex* lca)
{
    CachedBlockDataSource source(chainman, blockman);
    return GenerateReorgAdvisory(source, current_tip, fork_tip, lca);
}

ReorgAdvisory GenerateReorgAdvisory(
    const BlockDataSource& source,
    const CBlockIndex* current_tip,
    const CBlockIndex* fork_tip,
    const CBlockIndex* lca,
    int calibration_window,
    int calibration_min_window)
{
    ReorgAdvisory result;

    if (!current_tip || !fork_tip || !lca) {
        return result;
    }

    result.lca_height = lca->nHeight;
    result.depth_current = current_tip->nHeight - lca->nHeight;
    result.depth_fork = fork_tip->nHeight - lca->nHeight;

    // Calibrate tick-to-time
    result.calibration = CalibrateTickToTime(source, lca, calibration_window, calibration_min_window);

    double sec_per_tick = result.calibration.is_valid ? result.calibration.sec_per_tick : 0.0;

    // Compute segment stats
    result.seg_current = ComputeSegmentStats(source, lca, current_tip, sec_per_tick);
    result.seg_fork = ComputeSegmentStats(source, lca, fork_tip, sec_per_tick);

    // Transaction overlap
    result.tx_overlap_pct = ComputeTxOverlap(result.seg_current, result.seg_fork);

    // First block delay - find first block on fork after LCA
    const CBlockIndex* first_fork_block = fork_tip;
    while (first_fork_block && first_fork_block->pprev != lca) {
        first_fork_block = first_fork_block->pprev;
    }
    result.first_block_delay_secs = ComputeFirstBlockDelay(
        source, lca, first_fork_block, sec_per_tick);

    // Hashrate percentages (relative to baseline)
    // Use full arith_uint256 conversion to double for better accuracy.
    if (result.calibration.is_valid && result.calibration.baseline_hashrate > 0.0) {
        // Current segment hashrate using min(clock_time, tick_time) for upper bound
        double time_current = 0.0;
        if (result.seg_current.clock_time_secs > 0) {
            double tick_time = result.calibration.sec_per_tick * static_cast<double>(result.seg_current.ticks_diff);
            time_current = (tick_time > 0) ?
                std::min(static_cast<double>(result.seg_current.clock_time_secs), tick_time) :
                static_cast<double>(result.seg_current.clock_time_secs);
        } else if (result.seg_current.miner_time_secs > 0) {
            // Fallback to miner timestamps if first_seen unavailable
            time_current = static_cast<double>(result.seg_current.miner_time_secs);
        }

        if (time_current > 0.0 && result.seg_current.work_diff != arith_uint256(0)) {
            double work_approx = result.seg_current.work_diff.getdouble();
            double hashrate_current = work_approx / time_current;
            result.hashrate_current_pct = 100.0 * hashrate_current / result.calibration.baseline_hashrate;
        }

        // Fork segment hashrate (use clock time, fallback to miner time)
        double time_fork = 0.0;
        if (result.seg_fork.clock_time_secs > 0) {
            time_fork = static_cast<double>(result.seg_fork.clock_time_secs);
        } else if (result.seg_fork.miner_time_secs > 0) {
            time_fork = static_cast<double>(result.seg_fork.miner_time_secs);
        }

        if (time_fork > 0.0 && result.seg_fork.work_diff != arith_uint256(0)) {
            double work_approx = result.seg_fork.work_diff.getdouble();
            double hashrate_fork = work_approx / time_fork;
            result.hashrate_fork_pct = 100.0 * hashrate_fork / result.calibration.baseline_hashrate;
        }
    }

    // Since last block - fallback to miner timestamp if first_seen unavailable
    int64_t current_tip_first_seen = source.GetFirstSeenTs(current_tip->GetBlockHash());
    if (current_tip_first_seen > 0) {
        result.since_last_block_secs = GetTime() - current_tip_first_seen;
    } else {
        // Fallback: use miner timestamp
        result.since_last_block_secs = GetTime() - static_cast<int64_t>(current_tip->nTime);
    }

    // Advisory is valid if we have calibration and at least partial segment data
    result.is_valid = result.calibration.is_valid &&
                      (result.seg_current.block_count > 0 || result.seg_fork.block_count > 0);
    return result;
}

void AsyncLogReorgAdvisory(
    ChainstateManager& chainman,
    const node::BlockManager& blockman,
    const CBlockIndex* current_tip,
    const CBlockIndex* fork_tip,
    const CBlockIndex* lca)
{
    // Compute advisory synchronously to safely use chainman/blockman references.
    // Only the logging/storing is done asynchronously to avoid blocking cs_main.
    //
    // This design ensures:
    // - No dangling references (computation happens while references are valid)
    // - cs_main is released before I/O-heavy logging
    // - Advisory store updates happen off the hot path
    // - Clean shutdown via worker pool instead of detached threads
    ReorgAdvisory advisory;
    try {
        advisory = GenerateReorgAdvisory(chainman, blockman, current_tip, fork_tip, lca);
    } catch (const std::exception& e) {
        LogPrintf("REORG ADVISORY: Failed to compute advisory: %s\n", e.what());
        return;
    } catch (...) {
        LogPrintf("REORG ADVISORY: Failed to compute advisory: unknown error\n");
        return;
    }

    // Submit to worker pool for async logging/storing.
    // Worker pool handles queue management and clean shutdown.
    GetAdvisoryWorkerPool().Submit(std::move(advisory));
}

ReorgAdvisoryConfig GetReorgAdvisoryConfig()
{
    ReorgAdvisoryConfig config;

    // Read enabled flag (default: true)
    config.enabled = gArgs.GetBoolArg("-reorgadvisory", true);

    // Read depth threshold (default: 3)
    config.depth_threshold = gArgs.GetIntArg("-reorgadvisorydepth", ADVISORY_DEPTH_THRESHOLD);

    // Read offline threshold in seconds (default: 6 hours = 21600 seconds)
    config.offline_threshold_secs = gArgs.GetIntArg("-reorgadvisoryoffline", ADVISORY_OFFLINE_THRESHOLD_SECS);

    return config;
}

int GetMaxBlocksForTxids()
{
    int val = gArgs.GetIntArg("-reorgadvisorytxidblocks", DEFAULT_MAX_BLOCKS_FOR_TXIDS);
    // Clamp to reasonable range: 0 means unlimited (not recommended), max 10000
    if (val < 0) val = 0;
    if (val > 10000) val = 10000;
    return val;
}

bool ShouldTriggerAdvisory(int depth_current, int64_t since_last_block,
                           const std::optional<ReorgAdvisoryConfig>& config_opt)
{
    // Get config from parameter or read from gArgs
    ReorgAdvisoryConfig config = config_opt.value_or(GetReorgAdvisoryConfig());

    // Check if advisory system is enabled
    if (!config.enabled) {
        return false;
    }

    // Skip advisory if we've been offline too long
    if (since_last_block > config.offline_threshold_secs) {
        return false;
    }

    // Only trigger for deep reorgs (> threshold blocks)
    return depth_current > config.depth_threshold;
}

// ============================================================================
// ReorgAdvisoryStore implementation
// ============================================================================

void ReorgAdvisoryStore::Add(const ReorgAdvisory& advisory)
{
    LOCK(m_mutex);
    m_advisories.push_front(advisory);  // Newest at front
    while (m_advisories.size() > MAX_STORED_ADVISORIES) {
        m_advisories.pop_back();  // Remove oldest
    }
}

std::optional<ReorgAdvisory> ReorgAdvisoryStore::GetLatest() const
{
    LOCK(m_mutex);
    if (m_advisories.empty()) {
        return std::nullopt;
    }
    return m_advisories.front();
}

std::vector<ReorgAdvisory> ReorgAdvisoryStore::GetRecent(size_t count) const
{
    LOCK(m_mutex);
    std::vector<ReorgAdvisory> result;
    result.reserve(std::min(count, m_advisories.size()));
    for (size_t i = 0; i < count && i < m_advisories.size(); ++i) {
        result.push_back(m_advisories[i]);
    }
    return result;
}

std::vector<ReorgAdvisory> ReorgAdvisoryStore::GetAll() const
{
    LOCK(m_mutex);
    return std::vector<ReorgAdvisory>(m_advisories.begin(), m_advisories.end());
}

size_t ReorgAdvisoryStore::Size() const
{
    LOCK(m_mutex);
    return m_advisories.size();
}

void ReorgAdvisoryStore::Clear()
{
    LOCK(m_mutex);
    m_advisories.clear();
}

ReorgAdvisoryStore& GetReorgAdvisoryStore()
{
    static ReorgAdvisoryStore store;
    return store;
}

// ============================================================================
// AdvisoryWorkerPool implementation
// ============================================================================

AdvisoryWorkerPool::~AdvisoryWorkerPool()
{
    Stop();
}

void AdvisoryWorkerPool::Start()
{
    bool expected = false;
    if (!m_started.compare_exchange_strong(expected, true)) {
        return;  // Already started
    }

    m_shutdown.store(false);
    m_worker = std::thread([this]() { WorkerLoop(); });
}

void AdvisoryWorkerPool::Stop()
{
    if (!m_started.load()) {
        return;  // Never started
    }

    {
        LOCK(m_mutex);
        m_shutdown.store(true);
    }
    m_cv.notify_all();

    if (m_worker.joinable()) {
        m_worker.join();
    }
    m_started.store(false);
}

void AdvisoryWorkerPool::Submit(ReorgAdvisory advisory)
{
    // Start worker on first submit if not already running
    if (!m_started.load()) {
        Start();
    }

    {
        LOCK(m_mutex);
        if (m_shutdown.load()) {
            return;  // Don't accept new work during shutdown
        }

        // If queue is full, drop oldest to make room
        while (m_queue.size() >= MAX_QUEUE_SIZE) {
            m_queue.pop_front();
            LogPrintf("REORG ADVISORY: Queue full, dropping oldest advisory\n");
        }
        m_queue.push_back(std::move(advisory));
    }
    m_cv.notify_one();
}

void AdvisoryWorkerPool::WorkerLoop()
{
    util::ThreadRename("advisory-worker");

    while (true) {
        ReorgAdvisory advisory;
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                return m_shutdown.load() || !m_queue.empty();
            });

            if (m_shutdown.load() && m_queue.empty()) {
                break;  // Shutdown and queue drained
            }

            if (m_queue.empty()) {
                continue;
            }

            advisory = std::move(m_queue.front());
            m_queue.pop_front();
        }

        // Process the advisory (outside the lock)
        try {
            // Store in global advisory store for RPC access
            GetReorgAdvisoryStore().Add(advisory);

            // Log the advisory summary
            LogPrintf("REORG ADVISORY: %s\n", advisory.Summary());

            // Detailed log for debugging
            LogDebug(BCLog::VALIDATION,
                "ReorgAdvisory details: lca_height=%d, depth_cur=%d, depth_fork=%d, "
                "tx_overlap=%.2f%%, first_block_delay=%llds, "
                "seg_cur_blocks=%d, seg_fork_blocks=%d, "
                "seg_cur_txs=%zu, seg_fork_txs=%zu, "
                "calibration_valid=%s, sec_per_tick=%.6f\n",
                advisory.lca_height, advisory.depth_current, advisory.depth_fork,
                advisory.tx_overlap_pct, advisory.first_block_delay_secs,
                advisory.seg_current.block_count, advisory.seg_fork.block_count,
                advisory.seg_current.txids.size(), advisory.seg_fork.txids.size(),
                advisory.calibration.is_valid ? "true" : "false",
                advisory.calibration.sec_per_tick
            );

#if HAVE_SYSTEM
            // Execute operator notify command if configured
            std::string notify_cmd = gArgs.GetArg("-reorgadvisorynotify", "");
            if (!notify_cmd.empty()) {
                // Replace placeholders: %d=depth, %h=lca_height, %f=fork_depth, %o=overlap_pct
                ReplaceAll(notify_cmd, "%d", std::to_string(advisory.depth_current));
                ReplaceAll(notify_cmd, "%h", std::to_string(advisory.lca_height));
                ReplaceAll(notify_cmd, "%f", std::to_string(advisory.depth_fork));
                ReplaceAll(notify_cmd, "%o", std::to_string(static_cast<int>(advisory.tx_overlap_pct)));
                LogDebug(BCLog::VALIDATION, "Executing reorg advisory notify: %s\n", notify_cmd);
                runCommand(notify_cmd);
            }
#endif
        } catch (const std::exception& e) {
            LogPrintf("REORG ADVISORY: Error processing advisory: %s\n", e.what());
        } catch (...) {
            LogPrintf("REORG ADVISORY: Unknown error processing advisory\n");
        }
    }

    LogDebug(BCLog::VALIDATION, "Advisory worker pool stopped\n");
}

AdvisoryWorkerPool& GetAdvisoryWorkerPool()
{
    static AdvisoryWorkerPool pool;
    return pool;
}

void StopAdvisoryWorkerPool()
{
    GetAdvisoryWorkerPool().Stop();
}

// ============================================================================
// REORG GATING IMPLEMENTATION
// ============================================================================

ReorgGatingConfig GetReorgGatingConfig()
{
    ReorgGatingConfig config;
    // Reorg gating is an operator-safety feature for live networks: a deep reorg
    // blocks the node until a human answers the gate (or it times out). On regtest
    // there is no operator, so an automated deep reorg would stall for the full
    // decision timeout. Default gating off on regtest; an explicit
    // -reorgadvisorygating= still wins for tests that exercise gating directly.
    const bool gating_default{gArgs.GetChainType() == ChainType::REGTEST
                                  ? false
                                  : DEFAULT_REORG_GATING_ENABLED};
    config.enabled = gArgs.GetBoolArg("-reorgadvisorygating", gating_default);
    config.timeout_secs = gArgs.GetIntArg("-reorgadvisorytimeout", DEFAULT_REORG_DECISION_TIMEOUT_SECS);
    config.timeout_accept = gArgs.GetBoolArg("-reorgadvisorytimeoutaccept", DEFAULT_REORG_TIMEOUT_ACTION_ACCEPT);
    config.gating_depth_threshold = gArgs.GetIntArg("-reorgadvisorygatingdepth", ADVISORY_DEPTH_THRESHOLD);
    config.autofollow_sane_partitions = gArgs.GetBoolArg("-reorgadvisoryautofollow", DEFAULT_REORG_AUTOFOLLOW_SANE_PARTITIONS);
    config.autofollow_min_fork_hashrate_pct = gArgs.GetIntArg("-reorgadvisoryautofollowminforkhashrate", DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_HASHRATE_PCT);
    config.autofollow_max_fork_hashrate_pct = gArgs.GetIntArg("-reorgadvisoryautofollowmaxforkhashrate", DEFAULT_REORG_AUTOFOLLOW_MAX_FORK_HASHRATE_PCT);
    config.autofollow_min_fork_to_current_ratio_pct = gArgs.GetIntArg("-reorgadvisoryautofollowminratio", DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_TO_CURRENT_RATIO_PCT);
    config.autofollow_min_first_block_delay_secs = gArgs.GetIntArg("-reorgadvisoryautofollowmindelay", DEFAULT_REORG_AUTOFOLLOW_MIN_FIRST_BLOCK_DELAY_SECS);
    config.approval_ttl_secs = gArgs.GetIntArg("-reorgadvisoryapprovalttl", DEFAULT_REORG_APPROVAL_TTL_SECS);

    // Anything other than the explicit legacy escape hatch selects the
    // non-blocking mask: an operator typo must not silently re-enable thread
    // parking.
    const std::string mode_str{gArgs.GetArg("-reorgadvisorygatingmode",
                                            DEFAULT_REORG_GATING_MODE == ReorgGatingMode::MASK ? "mask" : "block")};
    if (mode_str == "block") {
        config.gating_mode = ReorgGatingMode::BLOCK;
    } else {
        if (mode_str != "mask") {
            LogPrintf("REORG GATING: Unknown -reorgadvisorygatingmode=%s; using 'mask'.\n", mode_str);
        }
        config.gating_mode = ReorgGatingMode::MASK;
    }
    config.veto_ttl_secs = gArgs.GetIntArg("-reorgadvisoryvetottl", DEFAULT_REORG_VETO_TTL_SECS);
    config.veto_growth_blocks = gArgs.GetIntArg("-reorgadvisoryvetogrowth", DEFAULT_REORG_VETO_GROWTH_BLOCKS);

    // Clamp timeout to reasonable range (1 minute to 24 hours)
    if (config.timeout_secs < 60) config.timeout_secs = 60;
    if (config.timeout_secs > 24 * 60 * 60) config.timeout_secs = 24 * 60 * 60;
    if (config.approval_ttl_secs < 60) config.approval_ttl_secs = 60;
    if (config.approval_ttl_secs > 24 * 60 * 60) config.approval_ttl_secs = 24 * 60 * 60;
    if (config.veto_ttl_secs < 60) config.veto_ttl_secs = 60;
    if (config.veto_ttl_secs > 24 * 60 * 60) config.veto_ttl_secs = 24 * 60 * 60;
    if (config.veto_growth_blocks < 1) config.veto_growth_blocks = 1;
    if (config.autofollow_min_fork_hashrate_pct < 1) config.autofollow_min_fork_hashrate_pct = 1;
    if (config.autofollow_max_fork_hashrate_pct < config.autofollow_min_fork_hashrate_pct) {
        config.autofollow_max_fork_hashrate_pct = config.autofollow_min_fork_hashrate_pct;
    }
    if (config.autofollow_min_fork_to_current_ratio_pct < 1) config.autofollow_min_fork_to_current_ratio_pct = 1;
    if (config.autofollow_min_first_block_delay_secs < 0) config.autofollow_min_first_block_delay_secs = 0;

    return config;
}

namespace {
const char* DecisionName(ReorgDecision decision)
{
    switch (decision) {
    case ReorgDecision::NONE: return "NONE";
    case ReorgDecision::ACCEPT: return "ACCEPT";
    case ReorgDecision::REJECT: return "REJECT";
    case ReorgDecision::TIMEOUT: return "TIMEOUT";
    case ReorgDecision::ABORT: return "ABORT";
    }
    return "UNKNOWN";
}
} // namespace

ReorgGatingManager::ReorgGatingManager()
{
    ReloadConfig();
}

ReorgGatingManager::ReorgGatingManager(const ReorgGatingConfig& config)
{
    m_config = config;
}

ReorgGatingManager::~ReorgGatingManager()
{
    {
        LOCK(m_mutex);
        m_kick_stop = true;
    }
    m_cv.notify_all();
    if (m_kick_thread.joinable()) {
        m_kick_thread.join();
    }
}

void ReorgGatingManager::ReloadConfig()
{
    m_config = GetReorgGatingConfig();
}

bool ReorgGatingManager::IsEnabled() const
{
    return m_config.enabled;
}

ReorgGatingMode ReorgGatingManager::GatingMode() const
{
    return m_config.gating_mode;
}

void ReorgGatingManager::SetAsyncHooks(std::function<void(std::function<void()>, int64_t)> schedule_fn,
                                       std::function<void()> kick_fn,
                                       std::function<std::optional<ReorgGateWorkSnapshot>(const uint256&)> snapshot_fn)
{
    {
        LOCK(m_mutex);
        m_schedule_fn = std::move(schedule_fn);
        m_kick_fn = std::move(kick_fn);
        m_snapshot_fn = std::move(snapshot_fn);
        m_kick_stop = false;
        m_kick_requested = false;
    }
    if (!m_kick_thread.joinable()) {
        m_kick_thread = std::thread([this] { KickWorker(); });
    }
}

void ReorgGatingManager::ResetAsyncHooks()
{
    {
        LOCK(m_mutex);
        m_kick_stop = true;
    }
    m_cv.notify_all();
    if (m_kick_thread.joinable()) {
        m_kick_thread.join();
    }
    LOCK(m_mutex);
    m_schedule_fn = nullptr;
    m_kick_fn = nullptr;
    m_snapshot_fn = nullptr;
    m_kick_stop = false;
    m_kick_requested = false;
}

void ReorgGatingManager::KickWorker()
{
    util::ThreadRename("reorggate-kick");
    while (true) {
        std::function<void()> kick;
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                return m_kick_stop || m_kick_requested;
            });
            if (m_kick_stop) break;
            m_kick_requested = false;
            kick = m_kick_fn;
        }
        // Run ActivateBestChain outside m_mutex on this dedicated thread: the
        // scheduler thread must stay free to drain the validation-interface
        // queue that ActivateBestChain waits on.
        if (kick) kick();
    }
}

ReorgGateEntry* ReorgGatingManager::FindGateById(uint64_t gate_id)
{
    for (auto& [key, entry] : m_gates) {
        if (entry.gate_id == gate_id) return &entry;
    }
    return nullptr;
}

std::pair<ReorgGatingManager::SubmitStatus, ReorgGateEntry*>
ReorgGatingManager::ResolveGate(const std::optional<uint64_t>& gate_id)
{
    if (gate_id) {
        // An explicit id that no longer resolves is "unknown gate" even when
        // the map is empty: the gate most likely already transitioned, which
        // is the message the operator needs.
        ReorgGateEntry* entry = FindGateById(*gate_id);
        if (!entry) return {SubmitStatus::UNKNOWN_GATE, nullptr};
        return {SubmitStatus::OK, entry};
    }
    if (m_gates.empty()) return {SubmitStatus::NO_GATE, nullptr};
    // Bare form is sugar for the single-gate case only: with several live
    // gates a decision must name its target so it can never hit the wrong fork.
    if (m_gates.size() > 1) return {SubmitStatus::AMBIGUOUS, nullptr};
    return {SubmitStatus::OK, &m_gates.begin()->second};
}

void ReorgGatingManager::RecordApprovalFromEntry(const ReorgGateEntry& entry)
{
    m_approval.is_valid = true;
    m_approval.fork_point_hash = entry.fork_point_hash;
    m_approval.candidate_tip_hash = entry.candidate_tip_hash;
    m_approval.current_tip_hash = entry.current_tip_hash;
    m_approval.approved_at = GetTime();

    LogPrintf("REORG GATING: Recorded approval for reorg at fork point %s (candidate %s, valid for %d seconds). "
              "Later segments of this reorg will not re-prompt.\n",
              m_approval.fork_point_hash.ToString(),
              m_approval.candidate_tip_hash.ToString(),
              m_config.approval_ttl_secs);
}

void ReorgGatingManager::ConvertToVeto(ReorgGateEntry& entry, const char* origin)
{
    entry.gate_state = ReorgGateState::VETOED;
    entry.decision = ReorgDecision::REJECT;
    entry.vetoed_at = GetTime();
    entry.veto_candidate_height = entry.candidate_height;
    entry.veto_margin_positive = entry.work.candidate_raw_work > entry.work.current_raw_work;
    entry.veto_raw_margin = entry.veto_margin_positive
                                ? entry.work.candidate_raw_work - entry.work.current_raw_work
                                : arith_uint256{};

    LogPrintf("REORG GATING: Gate %d REJECTED (%s): candidate %s vetoed for %d seconds; "
              "escapes early if the branch extends >=%d blocks or its raw-work margin over the tip grows.\n",
              entry.gate_id, origin, entry.candidate_tip_hash.ToString(),
              m_config.veto_ttl_secs, m_config.veto_growth_blocks);
}

void ReorgGatingManager::ArmTimeout(uint64_t gate_id, uint64_t generation)
{
    std::function<void(std::function<void()>, int64_t)> schedule_fn;
    {
        LOCK(m_mutex);
        schedule_fn = m_schedule_fn;
    }
    if (!schedule_fn) return; // unit tests drive HandleTimeout directly
    schedule_fn([this, gate_id, generation] { HandleTimeout(gate_id, generation); },
                m_config.timeout_secs);
}

uint64_t ReorgGatingManager::SetPending(const ReorgAdvisory& advisory,
                                        const uint256& candidate_tip_hash,
                                        int candidate_height,
                                        const uint256& current_tip_hash,
                                        const uint256& fork_point_hash,
                                        const uint256& anchor_hash,
                                        const ReorgGateWorkSnapshot& work)
{
    uint64_t gate_id{0};
    uint64_t generation{0};
    bool arm{false};
    {
        LOCK(m_mutex);
        const GateKey key{fork_point_hash, anchor_hash};
        auto it = m_gates.find(key);
        if (it != m_gates.end()) {
            ReorgGateEntry& entry = it->second;
            if (entry.gate_state == ReorgGateState::PENDING) {
                // Same reorg, longer segment: refresh what the operator sees.
                // The gate keeps its identity, generation and armed timeout.
                entry.advisory = advisory;
                entry.candidate_tip_hash = candidate_tip_hash;
                entry.candidate_height = candidate_height;
                entry.current_tip_hash = current_tip_hash;
                entry.work = work;
                LogDebug(BCLog::VALIDATION, "REORG GATING: Gate %d refreshed (candidate %s, height %d).\n",
                         entry.gate_id, candidate_tip_hash.ToString(), candidate_height);
            }
            // A VETOED entry is authoritative: the operator said no. Do not
            // resurrect the prompt until the veto expires or escapes.
            return entry.gate_id;
        }

        ReorgGateEntry entry;
        entry.gate_id = m_next_gate_id++;
        entry.generation = ++m_next_generation;
        entry.gate_state = ReorgGateState::PENDING;
        entry.advisory = advisory;
        entry.fork_point_hash = fork_point_hash;
        entry.anchor_hash = anchor_hash;
        entry.candidate_tip_hash = candidate_tip_hash;
        entry.candidate_height = candidate_height;
        entry.current_tip_hash = current_tip_hash;
        entry.work = work;
        entry.pending_since = GetTime();
        gate_id = entry.gate_id;
        generation = entry.generation;
        m_gates.emplace(key, std::move(entry));
        arm = m_config.gating_mode == ReorgGatingMode::MASK;

        LogPrintf("REORG GATING: Deep reorg detected (gate %d, depth=%d). Awaiting operator decision.\n",
                  gate_id, advisory.depth_current);
        LogPrintf("REORG GATING: Current tip: %s, Candidate tip: %s, Fork point: %s\n",
                  current_tip_hash.ToString(), candidate_tip_hash.ToString(), fork_point_hash.ToString());
        LogPrintf("REORG GATING: Timeout in %d seconds. Use RPC 'submitreorgdecision' to accept or reject.\n",
                  m_config.timeout_secs);
    }
    // Arm outside m_mutex: the scheduler owns the timeout, and a stale timer
    // is neutralized by the generation check in HandleTimeout.
    if (arm) ArmTimeout(gate_id, generation);
    return gate_id;
}

std::vector<ReorgGateEntry> ReorgGatingManager::GetGates() const
{
    LOCK(m_mutex);
    std::vector<ReorgGateEntry> gates;
    gates.reserve(m_gates.size());
    for (const auto& [key, entry] : m_gates) {
        gates.push_back(entry);
    }
    std::sort(gates.begin(), gates.end(),
              [](const ReorgGateEntry& a, const ReorgGateEntry& b) { return a.gate_id < b.gate_id; });
    return gates;
}

std::optional<ReorgGateEntry> ReorgGatingManager::GetGate(uint64_t gate_id) const
{
    LOCK(m_mutex);
    for (const auto& [key, entry] : m_gates) {
        if (entry.gate_id == gate_id) return entry;
    }
    return std::nullopt;
}

std::vector<std::pair<uint64_t, uint256>> ReorgGatingManager::GetGateAnchors() const
{
    LOCK(m_mutex);
    std::vector<std::pair<uint64_t, uint256>> anchors;
    anchors.reserve(m_gates.size());
    for (const auto& [key, entry] : m_gates) {
        anchors.emplace_back(entry.gate_id, entry.anchor_hash);
    }
    return anchors;
}

size_t ReorgGatingManager::GateCount() const
{
    LOCK(m_mutex);
    return m_gates.size();
}

bool ReorgGatingManager::HasPending() const
{
    LOCK(m_mutex);
    for (const auto& [key, entry] : m_gates) {
        if (entry.gate_state == ReorgGateState::PENDING) return true;
    }
    return false;
}

ReorgGatingManager::SubmitStatus ReorgGatingManager::SubmitDecision(const std::optional<uint64_t>& gate_id,
                                                                    ReorgDecision decision,
                                                                    uint64_t* out_gate_id)
{
    if (decision != ReorgDecision::ACCEPT && decision != ReorgDecision::REJECT) {
        LogPrintf("REORG GATING: Invalid decision. Must be ACCEPT or REJECT.\n");
        return SubmitStatus::BAD_STATE;
    }

    {
        LOCK(m_mutex);
        auto [status, entry] = ResolveGate(gate_id);
        if (status != SubmitStatus::OK) return status;
        if (out_gate_id) *out_gate_id = entry->gate_id;

        // Operator decisions bump the generation so any armed timeout for the
        // previous generation fires as a no-op.
        entry->generation = ++m_next_generation;

        if (m_config.gating_mode == ReorgGatingMode::BLOCK) {
            if (entry->gate_state != ReorgGateState::PENDING) return SubmitStatus::BAD_STATE;
            entry->decision = decision;
            LogPrintf("REORG GATING: Operator decision received for gate %d: %s\n",
                      entry->gate_id, DecisionName(decision));
        } else if (decision == ReorgDecision::ACCEPT) {
            // ACCEPT clears the mask (works on a vetoed gate too: an explicit
            // accept overrides an earlier reject).
            LogPrintf("REORG GATING: Gate %d ACCEPTED by operator; unmasking candidate %s.\n",
                      entry->gate_id, entry->candidate_tip_hash.ToString());
            RecordApprovalFromEntry(*entry);
            m_gates.erase(GateKey{entry->fork_point_hash, entry->anchor_hash});
            // Re-activation runs on the dedicated kick thread, never on the
            // RPC or scheduler thread.
            m_kick_requested = true;
        } else {
            // REJECT converts the mask into (or refreshes) a TTL-bound veto.
            ConvertToVeto(*entry, "operator REJECT");
        }
    }
    m_cv.notify_all();
    return SubmitStatus::OK;
}

ReorgGatingManager::SubmitStatus ReorgGatingManager::ClearVeto(const std::optional<uint64_t>& gate_id,
                                                               uint64_t* out_gate_id)
{
    {
        LOCK(m_mutex);
        auto [status, entry] = ResolveGate(gate_id);
        if (status != SubmitStatus::OK) return status;
        if (entry->gate_state != ReorgGateState::VETOED) return SubmitStatus::BAD_STATE;
        if (out_gate_id) *out_gate_id = entry->gate_id;
        LogPrintf("REORG GATING: Gate %d veto cleared by operator; branch may re-prompt.\n", entry->gate_id);
        m_gates.erase(GateKey{entry->fork_point_hash, entry->anchor_hash});
        // Kick so the branch re-prompts without waiting for a new block.
        m_kick_requested = true;
    }
    m_cv.notify_all();
    return SubmitStatus::OK;
}

bool ReorgGatingManager::RemoveGate(uint64_t gate_id, const std::string& reason)
{
    LOCK(m_mutex);
    for (auto it = m_gates.begin(); it != m_gates.end(); ++it) {
        if (it->second.gate_id == gate_id) {
            LogPrintf("REORG GATING: Gate %d removed (%s).\n", gate_id, reason);
            m_gates.erase(it);
            return true;
        }
    }
    return false;
}

size_t ReorgGatingManager::PruneMootGates(const std::function<ReorgGateAnchorStatus(const uint256&)>& classify)
{
    // Classify against a snapshot of anchors, then remove per gate id: the
    // classifier may take cs_main, which must never be acquired under m_mutex.
    size_t removed{0};
    for (const auto& [gate_id, anchor_hash] : GetGateAnchors()) {
        switch (classify(anchor_hash)) {
        case ReorgGateAnchorStatus::KEEP:
            break;
        case ReorgGateAnchorStatus::INVALIDATED:
            if (RemoveGate(gate_id, "candidate subtree invalidated by operator")) ++removed;
            break;
        case ReorgGateAnchorStatus::ON_ACTIVE_CHAIN:
            if (RemoveGate(gate_id, "anchor is on the active chain")) ++removed;
            break;
        }
    }
    return removed;
}

ReorgDecision ReorgGatingManager::WaitForDecision(const std::function<bool()>& interrupted)
{
    WAIT_LOCK(m_mutex, lock);

    // BLOCK mode parks the single ActivateBestChain caller (serialized by
    // m_chainstate_mutex), so at most one gate is pending; wait on the oldest.
    uint64_t gate_id{0};
    {
        const ReorgGateEntry* found{nullptr};
        for (const auto& [key, entry] : m_gates) {
            if (entry.gate_state != ReorgGateState::PENDING) continue;
            if (!found || entry.gate_id < found->gate_id) found = &entry;
        }
        if (!found) return ReorgDecision::NONE;
        gate_id = found->gate_id;
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(m_config.timeout_secs);

    while (true) {
        // Re-resolve each tick: the gate can be cleared underneath the wait.
        ReorgGateEntry* entry = FindGateById(gate_id);
        if (!entry) return ReorgDecision::NONE;
        if (entry->decision != ReorgDecision::NONE) return entry->decision;
        if (interrupted && interrupted()) {
            // Shutdown must never hang behind the gate: abort WITHOUT deciding.
            LogPrintf("REORG GATING: Interrupt during gate wait; aborting without a decision.\n");
            return ReorgDecision::ABORT;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            entry->decision = ReorgDecision::TIMEOUT;
            LogPrintf("REORG GATING: Decision timeout. Default action: %s\n",
                      m_config.timeout_accept ? "ACCEPT (subject to raw-work guardrail)" : "REJECT");
            return ReorgDecision::TIMEOUT;
        }
        // Slice the wait so the interrupt is observed within a second.
        m_cv.wait_for(lock, std::chrono::seconds(1));
    }
}

bool ReorgGatingManager::EvaluateMask(uint64_t gate_id, const uint256& candidate_hash, int candidate_height,
                                      const arith_uint256& candidate_raw_work,
                                      const arith_uint256& tip_raw_work)
{
    LOCK(m_mutex);
    if (m_config.gating_mode != ReorgGatingMode::MASK) return false;
    ReorgGateEntry* entry = FindGateById(gate_id);
    if (!entry) return false;
    if (entry->gate_state == ReorgGateState::PENDING) {
        // Track the growing branch: the mask keeps ActivateBestChainStep from
        // re-arming this gate, so the best candidate seen at selection time is
        // what keeps the operator view - and any later veto baseline - fresh.
        if (candidate_height >= entry->candidate_height) {
            entry->candidate_tip_hash = candidate_hash;
            entry->candidate_height = candidate_height;
            entry->work.candidate_raw_work = candidate_raw_work;
            entry->work.current_raw_work = tip_raw_work;
        }
        return true;
    }

    // VETOED: drop the veto when it expires or an escape fires, so the branch
    // re-prompts (once) through ActivateBestChainStep. A fresh reject then
    // records a fresh veto with fresh baselines.
    const auto erase_and_unmask = [&](const char* why) EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        LogPrintf("REORG GATING: Gate %d veto %s; branch will re-prompt.\n", entry->gate_id, why);
        m_gates.erase(GateKey{entry->fork_point_hash, entry->anchor_hash});
        return false;
    };
    if (GetTime() - entry->vetoed_at > m_config.veto_ttl_secs) {
        return erase_and_unmask("TTL expired");
    }
    if (candidate_height - entry->veto_candidate_height >= m_config.veto_growth_blocks) {
        return erase_and_unmask("growth escape (branch extended)");
    }
    if (candidate_raw_work > tip_raw_work) {
        const arith_uint256 margin{candidate_raw_work - tip_raw_work};
        if (!entry->veto_margin_positive || margin > entry->veto_raw_margin) {
            return erase_and_unmask("raw-work escape (margin over tip grew)");
        }
    }
    return true;
}

void ReorgGatingManager::HandleTimeout(uint64_t gate_id, uint64_t generation)
{
    // Take a fresh work snapshot first (needs cs_main); never under m_mutex.
    uint256 candidate_hash;
    std::function<std::optional<ReorgGateWorkSnapshot>(const uint256&)> snapshot_fn;
    {
        LOCK(m_mutex);
        ReorgGateEntry* entry = FindGateById(gate_id);
        if (!entry || entry->generation != generation || entry->gate_state != ReorgGateState::PENDING) {
            return; // stale timer: the operator (or another transition) won the race
        }
        candidate_hash = entry->candidate_tip_hash;
        snapshot_fn = m_snapshot_fn;
    }
    std::optional<ReorgGateWorkSnapshot> fresh;
    if (snapshot_fn) fresh = snapshot_fn(candidate_hash);

    {
        LOCK(m_mutex);
        ReorgGateEntry* entry = FindGateById(gate_id);
        if (!entry || entry->generation != generation || entry->gate_state != ReorgGateState::PENDING) {
            return; // decision landed while the snapshot was being taken
        }
        if (fresh) entry->work = *fresh;

        const bool accept = m_config.timeout_accept && TimeoutAcceptAllowed(entry->work);
        if (accept) {
            LogPrintf("REORG GATING: Gate %d decision timeout; auto-accepting raw-work-heavier candidate %s.\n",
                      entry->gate_id, entry->candidate_tip_hash.ToString());
            RecordApprovalFromEntry(*entry);
            m_gates.erase(GateKey{entry->fork_point_hash, entry->anchor_hash});
            m_kick_requested = true;
        } else {
            if (m_config.timeout_accept) {
                LogPrintf("REORG GATING: Gate %d timeout-accept blocked by raw-work guardrail "
                          "(candidate not strictly raw-work-heavier, or penalty/policy-driven); "
                          "treating timeout as REJECT.\n",
                          entry->gate_id);
            }
            entry->generation = ++m_next_generation;
            ConvertToVeto(*entry, "decision timeout");
        }
    }
    m_cv.notify_all();
}

void ReorgGatingManager::RecordApprovalFromPending()
{
    LOCK(m_mutex);
    // BLOCK-mode helper: the sole (oldest) gate carries the decision.
    ReorgGateEntry* found{nullptr};
    for (auto& [key, entry] : m_gates) {
        if (!found || entry.gate_id < found->gate_id) found = &entry;
    }
    if (!found) return;
    RecordApprovalFromEntry(*found);
}

void ReorgGatingManager::ClearPending()
{
    LOCK(m_mutex);
    auto oldest = m_gates.end();
    for (auto it = m_gates.begin(); it != m_gates.end(); ++it) {
        if (oldest == m_gates.end() || it->second.gate_id < oldest->second.gate_id) oldest = it;
    }
    if (oldest == m_gates.end()) return;
    m_gates.erase(oldest);
    LogDebug(BCLog::VALIDATION, "REORG GATING: Pending state cleared.\n");
}

ReorgApprovalState ReorgGatingManager::GetApproval() const
{
    LOCK(m_mutex);
    if (!m_approval.is_valid) {
        return ReorgApprovalState{};
    }
    if (GetTime() - m_approval.approved_at > m_config.approval_ttl_secs) {
        return ReorgApprovalState{};
    }
    return m_approval;
}

void ReorgGatingManager::ClearApproval()
{
    LOCK(m_mutex);
    m_approval = ReorgApprovalState{};
    LogDebug(BCLog::VALIDATION, "REORG GATING: Approval state cleared.\n");
}

int64_t ReorgGatingManager::GetTimeoutRemaining() const
{
    LOCK(m_mutex);
    const ReorgGateEntry* found{nullptr};
    for (const auto& [key, entry] : m_gates) {
        if (entry.gate_state != ReorgGateState::PENDING) continue;
        if (!found || entry.gate_id < found->gate_id) found = &entry;
    }
    if (!found) return 0;

    int64_t elapsed = GetTime() - found->pending_since;
    int64_t remaining = m_config.timeout_secs - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool ReorgGatingManager::TimeoutAcceptAllowed(const ReorgGateWorkSnapshot& work)
{
    // Auto-accept must never follow a penalty/policy-manufactured reorg: only
    // a candidate that is strictly heavier in never-mutated raw consensus
    // work may be followed unattended.
    return work.candidate_raw_work > work.current_raw_work && !work.penalty_or_policy_driven;
}

ReorgGatingManager& GetReorgGatingManager()
{
    static ReorgGatingManager manager;
    return manager;
}

ReorgGateWorkSnapshot ComputeReorgGateWorkSnapshot(const CBlockIndex& current_tip,
                                                   const CBlockIndex& candidate_tip)
{
    ReorgGateWorkSnapshot work;
    work.current_work = current_tip.nChainWork;
    work.candidate_work = candidate_tip.nChainWork;
    work.current_penalty = current_tip.nChainPenalty;
    work.candidate_penalty = candidate_tip.nChainPenalty;
    work.current_raw_work = current_tip.nChainWorkRaw;
    work.candidate_raw_work = candidate_tip.nChainWorkRaw;
    // "Wins on effective work" uses the same comparator fork choice uses, so
    // the flag reflects exactly the ordering that promoted the candidate.
    work.penalty_or_policy_driven =
        node::CBlockIndexPolicyComparator()(&current_tip, &candidate_tip) &&
        !(candidate_tip.nChainWorkRaw > current_tip.nChainWorkRaw);
    return work;
}

std::optional<ReorgGateWorkSnapshot> ComputeReorgGateWorkSnapshot(ChainstateManager& chainman,
                                                                  const uint256& candidate_tip_hash)
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* candidate{chainman.m_blockman.LookupBlockIndex(candidate_tip_hash)};
    const CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (!candidate || !tip) return std::nullopt;
    return ComputeReorgGateWorkSnapshot(*tip, *candidate);
}

void PruneMootReorgGates(ChainstateManager& chainman)
{
    AssertLockHeld(::cs_main);
    ReorgGatingManager& mgr = GetReorgGatingManager();
    if (mgr.GateCount() == 0) return;
    mgr.PruneMootGates([&chainman](const uint256& anchor_hash) {
        AssertLockHeld(::cs_main);
        const CBlockIndex* anchor{chainman.m_blockman.LookupBlockIndex(anchor_hash)};
        if (!anchor) return ReorgGateAnchorStatus::KEEP;
        // BLOCK_FAILED_MASK covers both FAILED_VALID (the anchor itself was
        // invalidated) and FAILED_CHILD (an ancestor was): either way the
        // candidate subtree can never be selected again.
        if (anchor->nStatus & BLOCK_FAILED_MASK) return ReorgGateAnchorStatus::INVALIDATED;
        if (chainman.ActiveChain().Contains(anchor)) return ReorgGateAnchorStatus::ON_ACTIVE_CHAIN;
        return ReorgGateAnchorStatus::KEEP;
    });
}

namespace {
//! Depth of nested ReorgGateOperatorAction scopes on this thread.
thread_local int g_reorg_gate_operator_action_depth{0};
} // namespace

ReorgGateOperatorAction::ReorgGateOperatorAction()
{
    ++g_reorg_gate_operator_action_depth;
}

ReorgGateOperatorAction::~ReorgGateOperatorAction()
{
    --g_reorg_gate_operator_action_depth;
}

bool ReorgGateOperatorActionActive()
{
    return g_reorg_gate_operator_action_depth > 0;
}

bool ShouldGateReorg(int depth_current, int64_t since_last_block, bool disconnect_only,
                     const std::optional<ReorgGatingConfig>& config_opt)
{
    // The gate exists to obtain operator sign-off. An operator-initiated
    // action (invalidateblock/reconsiderblock) already carries that sign-off,
    // so gating it would only block the RPC until the decision timeout.
    if (ReorgGateOperatorActionActive()) {
        LogPrintf("REORG GATING: Skipping gate - chain switch is operator-initiated.\n");
        return false;
    }

    // Local policy corrections can make the best chain an ancestor of the
    // current tip. That disconnect-only retreat is self-correction, not a
    // competing fork that needs operator approval.
    if (disconnect_only) {
        return false;
    }

    ReorgGatingConfig config = config_opt ? *config_opt : GetReorgGatingConfig();

    if (!config.enabled) {
        return false;
    }

    // Don't gate if below depth threshold
    if (depth_current <= config.gating_depth_threshold) {
        return false;
    }

    // Don't gate if node was offline too long (auto-follow per spec)
    ReorgAdvisoryConfig adv_config = GetReorgAdvisoryConfig();
    if (since_last_block > adv_config.offline_threshold_secs) {
        LogDebug(BCLog::VALIDATION,
            "REORG GATING: Skipping gate - node was offline for %lld seconds (threshold: %lld)\n",
            since_last_block, adv_config.offline_threshold_secs);
        return false;
    }

    return true;
}

bool ShouldAutoFollowSanePartitionReorg(const ReorgAdvisory& advisory,
                                        const std::optional<ReorgGatingConfig>& config_opt)
{
    const ReorgGatingConfig config = config_opt ? *config_opt : GetReorgGatingConfig();

    if (!config.autofollow_sane_partitions) {
        return false;
    }

    if (!advisory.is_valid || !advisory.calibration.is_valid) {
        return false;
    }

    if (advisory.depth_current <= config.gating_depth_threshold) {
        return false;
    }

    if (advisory.depth_fork <= 0 || advisory.seg_current.block_count <= 0 || advisory.seg_fork.block_count <= 0) {
        return false;
    }

    if (advisory.seg_fork.work_diff <= advisory.seg_current.work_diff) {
        return false;
    }

    if (advisory.first_block_delay_secs < config.autofollow_min_first_block_delay_secs) {
        return false;
    }

    const double fork_hashrate = advisory.hashrate_fork_pct;
    const double current_hashrate = advisory.hashrate_current_pct;

    if (!std::isfinite(fork_hashrate) || !std::isfinite(current_hashrate)) {
        return false;
    }

    if (fork_hashrate <= 0.0 || current_hashrate <= 0.0) {
        return false;
    }

    if (fork_hashrate < static_cast<double>(config.autofollow_min_fork_hashrate_pct) ||
        fork_hashrate > static_cast<double>(config.autofollow_max_fork_hashrate_pct)) {
        return false;
    }

    if ((fork_hashrate * 100.0) <
        (current_hashrate * static_cast<double>(config.autofollow_min_fork_to_current_ratio_pct))) {
        return false;
    }

    return true;
}
