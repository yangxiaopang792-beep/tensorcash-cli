// Ensure VDF header eviction preserves active-chain entries while pruning stale ones.

#include <boost/test/unit_test.hpp>

#include <net_processing.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <random.h>

BOOST_FIXTURE_TEST_SUITE(net_processing_vdf_eviction_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(active_chain_headers_survive_eviction_window)
{
    using net_processing_testing::PeerAccess;

    PeerManager& peerman = *m_node.peerman;

    const int64_t base_time = GetTime();
    const uint64_t tick = 10;

    // Insert three headers: two pinned to the active chain, one stale.
    const uint256 active_a = GetRandHash();
    const uint256 active_b = GetRandHash();
    const uint256 stale = GetRandHash();

    PeerAccess::TrackVdfHeader(peerman, active_a, /*on_active=*/true, base_time, tick);
    PeerAccess::TrackVdfHeader(peerman, active_b, /*on_active=*/true, base_time, tick);
    PeerAccess::TrackVdfHeader(peerman, stale,   /*on_active=*/false, base_time, tick);

    BOOST_CHECK_EQUAL(PeerAccess::VdfHeaderCount(peerman), 3U);

    // First prune within TTL keeps everything.
    SetMockTime(base_time + 60);
    PeerAccess::RunVdfHeaderPrune(peerman);
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, active_a));
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, active_b));
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, stale));

    // Advance past TTL; stale entries should disappear while active ones remain pinned.
    SetMockTime(base_time + 7200);
    PeerAccess::RunVdfHeaderPrune(peerman);
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, active_a));
    BOOST_CHECK(PeerAccess::HasVdfHeader(peerman, active_b));
    BOOST_CHECK(!PeerAccess::HasVdfHeader(peerman, stale));

    // Active entries still counted.
    BOOST_CHECK_EQUAL(PeerAccess::VdfHeaderCount(peerman), 2U);

    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
