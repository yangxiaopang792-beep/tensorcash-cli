// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include <consensus/amount.h>
#include <net.h>
#include <protocol.h>
#include <threadsafety.h>
#include <txorphanage.h>
#include <validationinterface.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class AddrMan;
class CTxMemPool;
class ChainstateManager;
class BanMan;
class CBlockIndex;
class CScheduler;
class DataStream;
class uint256;

namespace node {
class Warnings;
} // namespace node

/** Whether transaction reconciliation protocol should be enabled by default. */
static constexpr bool DEFAULT_TXRECONCILIATION_ENABLE{false};
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const uint32_t DEFAULT_MAX_ORPHAN_TRANSACTIONS{100};
/** Default number of non-mempool transactions to keep around for block reconstruction. Includes
    orphan, replaced, and rejected transactions. */
static const uint32_t DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN{100};
static const bool DEFAULT_PEERBLOOMFILTERS = false;
static const bool DEFAULT_PEERBLOCKFILTERS = false;
/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
static const unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/** Default minimum verified cumulative VDF tick per block for header-only candidate fetch.
 *
 *  Temporarily lowered from 40000 to 35000 tick/s during the 2026-07 fast-block
 *  recovery (min-per-block 21.6M -> 18.9M). Unlike the slack (already 21 days,
 *  which only shifts the intercept), the expectation sets the floor's SLOPE, so
 *  lowering it both widens headroom and slows the rate the floor rises per
 *  block, letting default-configured nodes ride out the compressed-spacing
 *  episode. Honest miners run well above this (blended ~48-70k/s in the affected
 *  window), so it stays a real sequential-time gate. Restore to 40000 once block
 *  spacing normalises above the breakeven cadence. */
static constexpr uint64_t DEFAULT_SPV_MIN_CUMULATIVE_TICK_PER_BLOCK{35000 * 9 * 60};
/** Expected block cadence used to convert slack days into block slack. */
static constexpr uint32_t DEFAULT_SPV_MIN_CUMULATIVE_TICK_BLOCK_SECONDS{9 * 60};
/** Default slack before enforcing the cumulative VDF tick floor.
 *
 *  The slack absorbs TRANSIENT accrual deficits without touching the floor's
 *  slope (which is what bounds a fabricated from-genesis chain at height).
 *  During difficulty catch-up, block intervals compress between retargets and
 *  per-block tick accrual (fleet tick rate x interval) drops below the slope,
 *  eating headroom: on tensor mainnet 2026-07 a sustained hashrate ramp cost
 *  ~28B ticks of headroom in one 2016-block window and ~40B across the
 *  episode -- the previous 2-day slack (320 blocks = 6.9B offset) would have
 *  had default-configured nodes refusing the honest chain. 21 days
 *  (3360 blocks = 72.6B offset at the default slope) covers ~1.9x that
 *  episode as a constant, non-height-scaling discount. */
static constexpr uint32_t DEFAULT_SPV_MIN_CUMULATIVE_TICK_SLACK_DAYS{21};

struct CNodeStateStats {
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::chrono::microseconds m_ping_wait;
    std::vector<int> vHeightInFlight;
    bool m_relay_txs;
    CAmount m_fee_filter_received;
    uint64_t m_addr_processed = 0;
    uint64_t m_addr_rate_limited = 0;
    bool m_addr_relay_enabled{false};
    ServiceFlags their_services;
    int64_t presync_height{-1};
    std::chrono::seconds time_offset{0};
};

struct PeerManagerInfo {
    std::chrono::seconds median_outbound_time_offset{0s};
    bool ignores_incoming_txs{false};
};

/** SPV cumulative-tick gate state, for getspvtickinfo. */
struct SpvTickInfo {
    //! Configured floor slope (ticks/block; 0 = gate disabled) and slack days.
    uint64_t min_cumulative_tick_per_block{0};
    uint32_t min_cumulative_tick_slack_days{0};
    //! Floor value at the queried height (saturated to uint64).
    uint64_t floor_at_height{0};
    //! EMA-based expected tick per block used by the hysteresis margin.
    uint64_t expected_tick_per_block{0};
    //! Sidecar cache occupancy: total entries, VALID entries, cum_set anchors.
    uint64_t vdf_header_entries{0};
    uint64_t vdf_header_valid{0};
    uint64_t vdf_header_anchored{0};
    //! Backfill queue depths: sum over per-peer queues + peer-agnostic staging.
    uint64_t backfill_peer_total{0};
    uint64_t backfill_staged_any{0};
};

class PeerManager : public CValidationInterface, public NetEventsInterface
{
public:
    struct Options {
        //! Whether this node is running in -blocksonly mode
        bool ignore_incoming_txs{DEFAULT_BLOCKSONLY};
        //! Whether transaction reconciliation protocol is enabled
        bool reconcile_txs{DEFAULT_TXRECONCILIATION_ENABLE};
        //! Maximum number of orphan transactions kept in memory
        uint32_t max_orphan_txs{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
        //! Number of non-mempool transactions to keep around for block reconstruction. Includes
        //! orphan, replaced, and rejected transactions.
        uint32_t max_extra_txs{DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN};
        //! Whether all P2P messages are captured to disk
        bool capture_messages{false};
        //! Whether or not the internal RNG behaves deterministically (this is
        //! a test-only option).
        bool deterministic_rng{false};
        //! Number of headers sent in one getheaders message result (this is
        //! a test-only option).
        uint32_t max_headers_result{MAX_HEADERS_RESULTS};
        // SPV selection knobs (default enable ASN corroboration, min=2)
        bool spv_asn_corroboration{true};
        uint32_t spv_asn_min{2};
        // Reorg depth above which ASN corroboration is required (default 3).
        // Configurable so low-diversity (e.g. Tor-heavy) nodes can raise it
        // during a hashrate spike without a rebuild.
        int spv_asn_min_reorg_depth{3};
        // SPV hysteresis EMA alpha, in basis points (1/10000). Default 200 = 2%
        uint32_t spv_hysteresis_alpha_bps{200};
        // SPV hysteresis base fraction (of E), in basis points. Default 5000 = 50%
        uint32_t spv_hysteresis_base_bps{5000};
        // SPV hysteresis default expected tick per block (fallback if EMA uninitialized)
        uint64_t spv_hysteresis_default_tick{1000000};
        // Minimum cumulative verified tick floor: max(0, height - slack_blocks) * ticks/block.
        // Set ticks/block to 0 to disable.
        uint64_t spv_min_cumulative_tick_per_block{DEFAULT_SPV_MIN_CUMULATIVE_TICK_PER_BLOCK};
        uint32_t spv_min_cumulative_tick_slack_days{DEFAULT_SPV_MIN_CUMULATIVE_TICK_SLACK_DAYS};
        // SPV deep-reorg sampling threshold D (default 6)
        int spv_reorg_sampling_threshold{6};
        // SPV sampling max N (default 12)
        uint32_t spv_sampling_max_n{12};
        // Onion diversity: vanity prefix, freshness tag length, block window.
        // Empty prefix = derive from the chain (the network-wide vanity
        // convention: "tensorc" on tensor mainnet, "ten" on tensor-test /
        // tensor-reg). The mainnet prefix is long enough that a node cannot
        // grind it itself: nodes install a pre-ground key, so the binary's
        // CHECKED prefix and the fleet's INSTALLED prefix must move together.
        // If they drift, nodes without an explicit -spv-onion-prefix earn zero
        // diversity credit and Tor-only nodes wedge behind the deep-reorg gate.
        // Keying off the chain (not one compiled constant) keeps a single
        // binary aligned across nets, but does not remove the fleet-coordination
        // requirement when the ground convention itself changes.
        std::string spv_onion_prefix{};
        size_t spv_onion_tag_len{3};
        int spv_onion_freshness_window{1400};
    };

    static std::unique_ptr<PeerManager> make(CConnman& connman, AddrMan& addrman,
                                             BanMan* banman, ChainstateManager& chainman,
                                             CTxMemPool& pool, node::Warnings& warnings, Options opts);
    virtual ~PeerManager() = default;

    /**
     * Attempt to manually fetch block from a given peer. We must already have the header.
     *
     * @param[in]  peer_id      The peer id
     * @param[in]  block_index  The blockindex
     * @returns std::nullopt if a request was successfully made, otherwise an error message
     */
    virtual std::optional<std::string> FetchBlock(NodeId peer_id, const CBlockIndex& block_index) = 0;

    /** Begin running background tasks, should only be called once */
    virtual void StartScheduledTasks(CScheduler& scheduler) = 0;

    /** Get statistics from node state */
    virtual bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) const = 0;

    /** Get SPV cumulative-tick gate state; floor evaluated at the given height. */
    virtual SpvTickInfo GetSpvTickInfo(int height) = 0;

    virtual std::vector<TxOrphanage::OrphanTxBase> GetOrphanTransactions() = 0;

    /** Get peer manager info. */
    virtual PeerManagerInfo GetInfo() const = 0;

    /** Relay transaction to all peers. */
    virtual void RelayTransaction(const uint256& txid, const uint256& wtxid) = 0;

    /** Send ping message to all peers */
    virtual void SendPings() = 0;

    /** Set the height of the best block and its time (seconds since epoch). */
    virtual void SetBestBlock(int height, std::chrono::seconds time) = 0;

    /* Public for unit testing. */
    virtual void UnitTestMisbehaving(NodeId peer_id) = 0;

    /**
     * Evict extra outbound peers. If we think our tip may be stale, connect to an extra outbound.
     * Public for unit testing.
     */
    virtual void CheckForStaleTipAndEvictPeers() = 0;

    /** Process a single message from a peer. Public for fuzz testing */
    virtual void ProcessMessage(CNode& pfrom, const std::string& msg_type, DataStream& vRecv,
                                const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /** This function is used for testing the stale tip eviction logic, see denialofservice_tests.cpp */
    virtual void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) = 0;

    /**
     * Gets the set of service flags which are "desirable" for a given peer.
     *
     * These are the flags which are required for a peer to support for them
     * to be "interesting" to us, ie for us to wish to use one of our few
     * outbound connection slots for or for us to wish to prioritize keeping
     * their connection around.
     *
     * Relevant service flags may be peer- and state-specific in that the
     * version of the peer may determine which flags are required (eg in the
     * case of NODE_NETWORK_LIMITED where we seek out NODE_NETWORK peers
     * unless they set NODE_NETWORK_LIMITED and we are out of IBD, in which
     * case NODE_NETWORK_LIMITED suffices).
     *
     * Thus, generally, avoid calling with 'services' == NODE_NONE, unless
     * state-specific flags must absolutely be avoided. When called with
     * 'services' == NODE_NONE, the returned desirable service flags are
     * guaranteed to not change dependent on state - ie they are suitable for
     * use when describing peers which we know to be desirable, but for which
     * we do not have a confirmed set of service flags.
    */
    virtual ServiceFlags GetDesirableServiceFlags(ServiceFlags services) const = 0;
};

namespace net_processing_testing {
struct PeerAccess {
    static size_t VdfHeaderCount(const PeerManager& peerman);
    static bool HasVdfHeader(const PeerManager& peerman, const uint256& hash);
    static void TrackVdfHeader(PeerManager& peerman, const uint256& hash, bool on_active, int64_t ts, uint64_t tick);
    static void RunVdfHeaderPrune(PeerManager& peerman);
    static void ClearVdfHeaders(PeerManager& peerman);
    //! Apply anchor updates staged by BlockConnected/BlockDisconnected (in
    //! production this runs from SendMessages on the message thread).
    static void DrainPendingAnchors(PeerManager& peerman);
    //! Drive ComputeCumFromGenesis for the block index entry with this hash.
    //! Returns {ok, cum_tick low64}.
    static std::pair<bool, uint64_t> ComputeCumFromGenesis(PeerManager& peerman, const uint256& tip_hash);
    //! Drive CollectMissingSidecarPath for the block index entry with this hash.
    static std::vector<std::pair<uint256, uint256>> CollectMissingSidecarPath(PeerManager& peerman, const uint256& tip_hash, size_t max_items);
    //! Queue (header, prev) pairs into a peer's GETHEADERS_EXT backlog.
    static void QueueHeadersExt(PeerManager& peerman, NodeId nodeid, const std::vector<std::pair<uint256, uint256>>& queries);
    static size_t HeadersExtBacklogSize(PeerManager& peerman, NodeId nodeid);
};
}

#endif // BITCOIN_NET_PROCESSING_H
