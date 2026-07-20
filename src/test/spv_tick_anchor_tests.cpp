// Tests for disk-backed cumulative-tick anchors (ComputeCumFromGenesis /
// TryAnchorFromDisk), the missing-sidecar path walk used by the
// min-cumulative-tick gate backfill, and GETHEADERS_EXT backlog dedupe/cap.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <chain.h>
#include <net.h>
#include <net_processing.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <utility>
#include <vector>

using net_processing_testing::PeerAccess;

namespace {

// TestChain100Setup with peerman wired to validation signals the way init.cpp
// does it in production, so BlockConnected/BlockDisconnected anchor
// maintenance fires for blocks mined inside the test body.
struct SpvTickAnchorSetup : public TestChain100Setup {
    SpvTickAnchorSetup()
    {
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    }
    ~SpvTickAnchorSetup()
    {
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
    }

    const CBlockIndex* ActiveTip() const
    {
        return WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    }

    uint64_t DiskCumulativeTick(const CBlockIndex* pindex) const
    {
        CBlock block;
        BOOST_REQUIRE(WITH_LOCK(cs_main, return m_node.chainman->m_blockman.ReadBlock(block, *pindex)));
        return block.cumulative_tick;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(spv_tick_anchor_tests, SpvTickAnchorSetup)

// Restart/TTL-wipe scenario: with an empty sidecar cache, the walk must anchor
// from our own validated block storage instead of failing the whole path.
BOOST_AUTO_TEST_CASE(anchor_from_disk_after_cache_wipe)
{
    PeerManager& peerman = *m_node.peerman;
    const CBlockIndex* tip = ActiveTip();

    PeerAccess::ClearVdfHeaders(peerman);
    BOOST_CHECK_EQUAL(PeerAccess::VdfHeaderCount(peerman), 0U);

    const auto [ok, cum] = PeerAccess::ComputeCumFromGenesis(peerman, tip->GetBlockHash());
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(cum, DiskCumulativeTick(tip));

    // The walk self-anchored: the tip is now a cached entry, so the next
    // evaluation does not touch disk.
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, tip->GetBlockHash()));
}

// BlockConnected must maintain the anchor at the new tip, so the common
// extend-tip walk succeeds without gossip or a disk read.
BOOST_AUTO_TEST_CASE(block_connected_maintains_tip_anchor)
{
    PeerManager& peerman = *m_node.peerman;

    PeerAccess::ClearVdfHeaders(peerman);
    const CScript coinbase_script = m_coinbase_txns.back()->vout[0].scriptPubKey;
    const CBlock new_block = CreateAndProcessBlock({}, coinbase_script);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // The callback must only STAGE the anchor (taking g_msgproc_mutex from a
    // validation callback deadlocks against LimitValidationInterfaceQueue)...
    BOOST_CHECK(!PeerAccess::HasVdfHeader(peerman, new_block.GetHash()));
    // ...and the message-thread drain applies it.
    PeerAccess::DrainPendingAnchors(peerman);

    const CBlockIndex* tip = ActiveTip();
    BOOST_CHECK_EQUAL(tip->nHeight, 101);
    BOOST_CHECK(tip->GetBlockHash() == new_block.GetHash());
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, tip->GetBlockHash()));

    const auto [ok, cum] = PeerAccess::ComputeCumFromGenesis(peerman, tip->GetBlockHash());
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(cum, DiskCumulativeTick(tip));

    // The RPC-facing accessor never touches g_msgproc_mutex; the drain also
    // refreshed its stats snapshot.
    const SpvTickInfo tick_info = m_node.peerman->GetSpvTickInfo(tip->nHeight);
    BOOST_CHECK(tick_info.vdf_header_anchored >= 1U);
    BOOST_CHECK_EQUAL(tick_info.vdf_header_entries, PeerAccess::VdfHeaderCount(peerman));
}

// An invalidated block must not be trusted as a disk anchor (its
// cumulative_tick no longer has consensus standing on this node), while its
// parent -- the new active tip -- must be. The missing-path walk reports
// exactly the untrusted segment and stops at validated storage.
BOOST_AUTO_TEST_CASE(missing_path_walk_stops_at_validated_storage)
{
    PeerManager& peerman = *m_node.peerman;
    const CBlockIndex* old_tip = ActiveTip();
    const uint256 old_tip_hash = old_tip->GetBlockHash();
    const uint256 parent_hash = old_tip->pprev->GetBlockHash();

    BlockValidationState state;
    m_node.chainman->ActiveChainstate().InvalidateBlock(state, const_cast<CBlockIndex*>(old_tip));
    BOOST_REQUIRE(state.IsValid());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    PeerAccess::DrainPendingAnchors(peerman);
    BOOST_REQUIRE(ActiveTip()->GetBlockHash() == parent_hash);

    PeerAccess::ClearVdfHeaders(peerman);

    const auto missing = PeerAccess::CollectMissingSidecarPath(peerman, old_tip_hash, 100);
    BOOST_REQUIRE_EQUAL(missing.size(), 1U);
    BOOST_CHECK(missing[0].first == old_tip_hash);
    BOOST_CHECK(missing[0].second == parent_hash);

    // No verified path through the invalidated block...
    const auto [ok_invalid, cum_invalid] = PeerAccess::ComputeCumFromGenesis(peerman, old_tip_hash);
    BOOST_CHECK(!ok_invalid);
    // ...but the new tip disk-anchors fine.
    const auto [ok_parent, cum_parent] = PeerAccess::ComputeCumFromGenesis(peerman, parent_hash);
    BOOST_CHECK(ok_parent);
    BOOST_CHECK_EQUAL(cum_parent, DiskCumulativeTick(ActiveTip()));
}

// TTL pruning drops stale non-active entries but keeps near-tip anchors.
BOOST_AUTO_TEST_CASE(prune_keeps_active_anchor_drops_stale)
{
    PeerManager& peerman = *m_node.peerman;
    const CBlockIndex* tip = ActiveTip();

    PeerAccess::ClearVdfHeaders(peerman);
    // Recreate the tip anchor via a walk (disk-backed).
    const auto [ok, cum] = PeerAccess::ComputeCumFromGenesis(peerman, tip->GetBlockHash());
    BOOST_REQUIRE(ok);

    // A stale, non-active entry (ts far beyond the 1800s TTL).
    const uint256 stale_hash = ArithToUint256(arith_uint256(0xdeadbeef));
    PeerAccess::TrackVdfHeader(peerman, stale_hash, /*on_active=*/false, GetTime() - 3600, /*tick=*/5);
    BOOST_REQUIRE(PeerAccess::HasVdfHeader(peerman, stale_hash));

    PeerAccess::RunVdfHeaderPrune(peerman);
    BOOST_CHECK(!PeerAccess::HasVdfHeader(peerman, stale_hash));
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, tip->GetBlockHash()));
}

// GETHEADERS_EXT backlog: duplicates are not re-queued, and the per-peer cap
// bounds the backlog under header floods.
BOOST_AUTO_TEST_CASE(headers_ext_backlog_dedupes_and_caps)
{
    PeerManager& peerman = *m_node.peerman;

    const NodeId id{0};
    CNode node{id,
               /*sock=*/nullptr,
               CAddress(),
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               CAddress(),
               /*addrNameIn=*/"",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};
    WITH_LOCK(NetEventsInterface::g_msgproc_mutex, peerman.InitializeNode(node, NODE_NETWORK));

    std::vector<std::pair<uint256, uint256>> queries;
    for (uint64_t i = 1; i <= 3; ++i) {
        queries.emplace_back(ArithToUint256(arith_uint256(i)), uint256());
    }
    PeerAccess::QueueHeadersExt(peerman, id, queries);
    BOOST_CHECK_EQUAL(PeerAccess::HeadersExtBacklogSize(peerman, id), 3U);

    // Re-queueing the same hashes must not grow the backlog.
    PeerAccess::QueueHeadersExt(peerman, id, queries);
    BOOST_CHECK_EQUAL(PeerAccess::HeadersExtBacklogSize(peerman, id), 3U);

    // Flood far past the cap: the backlog stays bounded.
    std::vector<std::pair<uint256, uint256>> flood;
    flood.reserve(9000);
    for (uint64_t i = 1000; i < 10000; ++i) {
        flood.emplace_back(ArithToUint256(arith_uint256(i)), uint256());
    }
    PeerAccess::QueueHeadersExt(peerman, id, flood);
    BOOST_CHECK_EQUAL(PeerAccess::HeadersExtBacklogSize(peerman, id), 8000U);

    WITH_LOCK(NetEventsInterface::g_msgproc_mutex, peerman.FinalizeNode(node));
}

BOOST_AUTO_TEST_SUITE_END()
