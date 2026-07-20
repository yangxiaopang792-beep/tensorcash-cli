// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validationadvisory.h>

#include <consensus/consensus.h>
#include <arith_uint256.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <primitives/transaction.h>

#include <chrono>
#include <map>
#include <set>
#include <thread>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validationadvisory_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(should_trigger_advisory_thresholds)
{
    // Test ShouldTriggerAdvisory function with explicit config
    // to avoid depending on gArgs in unit tests

    ReorgAdvisoryConfig config;
    config.enabled = true;
    config.depth_threshold = 3;  // default
    config.offline_threshold_secs = 6 * 60 * 60;  // 6 hours default

    // Depth <= 3 should NOT trigger (regardless of time)
    BOOST_CHECK(!ShouldTriggerAdvisory(0, 0, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(1, 0, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(2, 0, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(3, 0, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(3, 3600, config));  // 1 hour

    // Depth > 3 with reasonable time SHOULD trigger
    BOOST_CHECK(ShouldTriggerAdvisory(4, 0, config));
    BOOST_CHECK(ShouldTriggerAdvisory(4, 3600, config));       // 1 hour
    BOOST_CHECK(ShouldTriggerAdvisory(10, 1800, config));      // 30 minutes
    BOOST_CHECK(ShouldTriggerAdvisory(100, 7200, config));     // 2 hours

    // Depth > 3 but offline > 6 hours should NOT trigger
    const int64_t six_hours = 6 * 60 * 60;
    BOOST_CHECK(!ShouldTriggerAdvisory(4, six_hours + 1, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(10, six_hours + 3600, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(100, 24 * 60 * 60, config));  // 24 hours

    // Boundary at exactly 6 hours
    BOOST_CHECK(ShouldTriggerAdvisory(4, six_hours - 1, config));
    BOOST_CHECK(ShouldTriggerAdvisory(4, six_hours, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(4, six_hours + 1, config));
}

BOOST_AUTO_TEST_CASE(should_trigger_advisory_disabled)
{
    // Test that disabled config prevents advisory
    ReorgAdvisoryConfig config;
    config.enabled = false;
    config.depth_threshold = 3;
    config.offline_threshold_secs = 6 * 60 * 60;

    // Even deep reorgs should NOT trigger when disabled
    BOOST_CHECK(!ShouldTriggerAdvisory(100, 0, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(1000, 0, config));
}

BOOST_AUTO_TEST_CASE(should_trigger_advisory_custom_thresholds)
{
    // Test with custom thresholds
    ReorgAdvisoryConfig config;
    config.enabled = true;
    config.depth_threshold = 10;  // Higher threshold
    config.offline_threshold_secs = 3600;  // Only 1 hour offline threshold

    // Depth 5 should NOT trigger with threshold 10
    BOOST_CHECK(!ShouldTriggerAdvisory(5, 0, config));
    BOOST_CHECK(!ShouldTriggerAdvisory(10, 0, config));

    // Depth 11 SHOULD trigger
    BOOST_CHECK(ShouldTriggerAdvisory(11, 0, config));

    // But offline > 1 hour should NOT trigger
    BOOST_CHECK(!ShouldTriggerAdvisory(11, 3601, config));
}

BOOST_AUTO_TEST_CASE(tx_overlap_calculation)
{
    // Test ComputeTxOverlap with various scenarios

    // Empty sets - degenerate case returns 100%
    {
        SegmentStats seg_a, seg_b;
        BOOST_CHECK_CLOSE(ComputeTxOverlap(seg_a, seg_b), 100.0, 0.01);
    }

    // Identical sets - 100% overlap
    {
        SegmentStats seg_a, seg_b;
        uint256 tx1 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001").value();
        uint256 tx2 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002").value();
        uint256 tx3 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000003").value();

        seg_a.txids = {tx1, tx2, tx3};
        seg_b.txids = {tx1, tx2, tx3};

        BOOST_CHECK_CLOSE(ComputeTxOverlap(seg_a, seg_b), 100.0, 0.01);
    }

    // No overlap - 0%
    {
        SegmentStats seg_a, seg_b;
        uint256 tx1 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001").value();
        uint256 tx2 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002").value();
        uint256 tx3 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000003").value();
        uint256 tx4 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000004").value();

        seg_a.txids = {tx1, tx2};
        seg_b.txids = {tx3, tx4};

        BOOST_CHECK_CLOSE(ComputeTxOverlap(seg_a, seg_b), 0.0, 0.01);
    }

    // Partial overlap - Jaccard index calculation
    // A = {1, 2, 3}, B = {2, 3, 4}
    // Intersection = {2, 3} = 2 elements
    // Union = {1, 2, 3, 4} = 4 elements
    // Jaccard = 2/4 = 50%
    {
        SegmentStats seg_a, seg_b;
        uint256 tx1 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001").value();
        uint256 tx2 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002").value();
        uint256 tx3 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000003").value();
        uint256 tx4 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000004").value();

        seg_a.txids = {tx1, tx2, tx3};
        seg_b.txids = {tx2, tx3, tx4};

        BOOST_CHECK_CLOSE(ComputeTxOverlap(seg_a, seg_b), 50.0, 0.01);
    }

    // One empty, one non-empty - 0%
    {
        SegmentStats seg_a, seg_b;
        uint256 tx1 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001").value();

        seg_a.txids = {tx1};
        // seg_b.txids is empty

        BOOST_CHECK_CLOSE(ComputeTxOverlap(seg_a, seg_b), 0.0, 0.01);
    }
}

BOOST_AUTO_TEST_CASE(advisory_summary_format)
{
    // Test ReorgAdvisory::Summary() output format

    ReorgAdvisory advisory;
    advisory.is_valid = false;

    // Invalid advisory
    std::string summary = advisory.Summary();
    BOOST_CHECK(summary.find("invalid") != std::string::npos);

    // Valid advisory
    advisory.is_valid = true;
    advisory.lca_height = 100000;
    advisory.depth_current = 5;
    advisory.depth_fork = 8;
    advisory.tx_overlap_pct = 85.5;
    advisory.first_block_delay_secs = 3600;  // 1 hour
    advisory.hashrate_current_pct = 95.0;
    advisory.hashrate_fork_pct = 150.0;
    advisory.calibration.sec_per_tick = 0.001;
    advisory.calibration.is_valid = true;

    summary = advisory.Summary();
    BOOST_CHECK(summary.find("LCA=100000") != std::string::npos);
    BOOST_CHECK(summary.find("depth_cur=5") != std::string::npos);
    BOOST_CHECK(summary.find("depth_fork=8") != std::string::npos);
    BOOST_CHECK(summary.find("tx_overlap=85.5%") != std::string::npos);
    BOOST_CHECK(summary.find("first_block_delay=3600s") != std::string::npos);
    BOOST_CHECK(summary.find("calibration_ok=true") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(tick_calibration_edge_cases)
{
    // Test TickTimeCalibration structure

    TickTimeCalibration cal;

    // Default should be invalid
    BOOST_CHECK(!cal.is_valid);
    BOOST_CHECK_EQUAL(cal.sec_per_tick, 0.0);
    BOOST_CHECK_EQUAL(cal.baseline_hashrate, 0.0);

    // Set valid values
    cal.is_valid = true;
    cal.sec_per_tick = 0.0005;  // 0.5ms per tick
    cal.baseline_hashrate = 1e15;  // 1 PH/s
    cal.window_blocks = 2000;

    BOOST_CHECK(cal.is_valid);
    BOOST_CHECK_GT(cal.sec_per_tick, 0.0);
    BOOST_CHECK_GT(cal.baseline_hashrate, 0.0);
}

BOOST_AUTO_TEST_CASE(segment_stats_structure)
{
    // Test SegmentStats structure and methods

    SegmentStats seg;

    // Default values
    BOOST_CHECK_EQUAL(seg.block_count, 0);
    BOOST_CHECK_EQUAL(seg.ticks_diff, 0);
    BOOST_CHECK_EQUAL(seg.clock_time_secs, 0);
    BOOST_CHECK_EQUAL(seg.miner_time_secs, 0);
    BOOST_CHECK(seg.txids.empty());
    BOOST_CHECK(!seg.data_complete);

    // Set some values
    seg.block_count = 10;
    seg.ticks_diff = 100000;
    seg.clock_time_secs = 6000;  // 100 minutes
    seg.miner_time_secs = 5900;  // ~98 minutes
    seg.data_complete = true;

    uint256 tx1 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001").value();
    seg.txids.insert(tx1);

    BOOST_CHECK_EQUAL(seg.block_count, 10);
    BOOST_CHECK_EQUAL(seg.txids.size(), 1u);
    BOOST_CHECK(seg.data_complete);
}

BOOST_AUTO_TEST_CASE(constants_values)
{
    // Verify constants are set to expected values

    BOOST_CHECK_EQUAL(ADVISORY_DEPTH_THRESHOLD, 6);
    BOOST_CHECK_EQUAL(ADVISORY_OFFLINE_THRESHOLD_SECS, 6 * 60 * 60);  // 6 hours
    BOOST_CHECK_EQUAL(ADVISORY_CALIBRATION_WINDOW, 2000);
}

BOOST_AUTO_TEST_CASE(config_struct_defaults)
{
    // Test ReorgAdvisoryConfig default values
    ReorgAdvisoryConfig config;

    BOOST_CHECK(config.enabled);
    BOOST_CHECK_EQUAL(config.depth_threshold, ADVISORY_DEPTH_THRESHOLD);
    BOOST_CHECK_EQUAL(config.offline_threshold_secs, ADVISORY_OFFLINE_THRESHOLD_SECS);

    ReorgGatingConfig gating_config;
    BOOST_CHECK(gating_config.autofollow_sane_partitions);
    BOOST_CHECK_EQUAL(gating_config.autofollow_min_fork_hashrate_pct, DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_HASHRATE_PCT);
    BOOST_CHECK_EQUAL(gating_config.autofollow_max_fork_hashrate_pct, DEFAULT_REORG_AUTOFOLLOW_MAX_FORK_HASHRATE_PCT);
    BOOST_CHECK_EQUAL(gating_config.autofollow_min_fork_to_current_ratio_pct, DEFAULT_REORG_AUTOFOLLOW_MIN_FORK_TO_CURRENT_RATIO_PCT);
    BOOST_CHECK_EQUAL(gating_config.autofollow_min_first_block_delay_secs, DEFAULT_REORG_AUTOFOLLOW_MIN_FIRST_BLOCK_DELAY_SECS);
}

BOOST_AUTO_TEST_CASE(should_gate_reorg_skips_disconnect_only_retreat)
{
    ReorgGatingConfig config;
    config.enabled = true;
    config.gating_depth_threshold = ADVISORY_DEPTH_THRESHOLD;

    BOOST_CHECK(ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/false, config));
    BOOST_CHECK(!ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/true, config));
}

BOOST_AUTO_TEST_CASE(should_gate_reorg_skips_operator_initiated_actions)
{
    ReorgGatingConfig config;
    config.enabled = true;
    config.gating_depth_threshold = ADVISORY_DEPTH_THRESHOLD;

    BOOST_CHECK(!ReorgGateOperatorActionActive());
    BOOST_CHECK(ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/false, config));
    {
        ReorgGateOperatorAction action;
        BOOST_CHECK(ReorgGateOperatorActionActive());
        BOOST_CHECK(!ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/false, config));
        {
            ReorgGateOperatorAction nested;
            BOOST_CHECK(!ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/false, config));
        }
        // Still overridden after the nested scope ends.
        BOOST_CHECK(ReorgGateOperatorActionActive());
        BOOST_CHECK(!ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/false, config));
    }
    BOOST_CHECK(!ReorgGateOperatorActionActive());
    BOOST_CHECK(ShouldGateReorg(ADVISORY_DEPTH_THRESHOLD + 1, 0, /*disconnect_only=*/false, config));
}

namespace {

//! Deterministic gating config for manager tests (never reads gArgs).
ReorgGatingConfig TestGatingConfig(ReorgGatingMode mode)
{
    ReorgGatingConfig config;
    config.enabled = true;
    config.gating_depth_threshold = ADVISORY_DEPTH_THRESHOLD;
    config.timeout_secs = 600;
    config.timeout_accept = false;
    config.approval_ttl_secs = DEFAULT_REORG_APPROVAL_TTL_SECS;
    config.gating_mode = mode;
    config.veto_ttl_secs = 600;
    config.veto_growth_blocks = 3;
    return config;
}

//! Work snapshot from small integers (raw sides drive the guardrails).
ReorgGateWorkSnapshot TestWork(uint64_t current_raw, uint64_t candidate_raw, bool penalty_driven = false)
{
    ReorgGateWorkSnapshot work;
    work.current_raw_work = arith_uint256{current_raw};
    work.candidate_raw_work = arith_uint256{candidate_raw};
    work.current_work = arith_uint256{current_raw};
    work.candidate_work = arith_uint256{candidate_raw};
    work.penalty_or_policy_driven = penalty_driven;
    return work;
}

uint256 TestHash(uint8_t tag)
{
    return uint256::FromHex(strprintf("%062x%02x", 0, tag)).value();
}

//! Arm a gate on mgr with distinct hashes derived from tag.
uint64_t ArmTestGate(ReorgGatingManager& mgr, uint8_t tag, int candidate_height = 100,
                     const ReorgGateWorkSnapshot& work = TestWork(50, 60))
{
    ReorgAdvisory advisory;
    advisory.is_valid = true;
    advisory.depth_current = 7;
    return mgr.SetPending(advisory,
                          /*candidate_tip_hash=*/TestHash(tag),
                          candidate_height,
                          /*current_tip_hash=*/TestHash(0xb0),
                          /*fork_point_hash=*/TestHash(0xc0),
                          /*anchor_hash=*/TestHash(tag + 1),
                          work);
}

} // namespace

BOOST_AUTO_TEST_CASE(reorg_gating_approval_lifecycle)
{
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::BLOCK)};

    const uint256 candidate = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000aa").value();
    const uint256 current = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000bb").value();
    const uint256 fork_point = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000cc").value();
    const uint256 anchor = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000dd").value();

    // No approval before any decision.
    BOOST_CHECK(!mgr.GetApproval().is_valid);

    // Recording without a pending reorg is a no-op.
    mgr.RecordApprovalFromPending();
    BOOST_CHECK(!mgr.GetApproval().is_valid);

    ReorgAdvisory advisory;
    advisory.depth_current = 5;
    advisory.is_valid = true;
    const uint64_t gate_id = mgr.SetPending(advisory, candidate, /*candidate_height=*/105,
                                            current, fork_point, anchor, TestWork(50, 60));
    const auto gate = mgr.GetGate(gate_id);
    BOOST_REQUIRE(gate.has_value());
    BOOST_CHECK(gate->fork_point_hash == fork_point);
    BOOST_CHECK(gate->anchor_hash == anchor);
    BOOST_CHECK(gate->gate_state == ReorgGateState::PENDING);

    mgr.RecordApprovalFromPending();
    mgr.ClearPending();

    // Approval survives ClearPending and matches the accepted reorg,
    // including the old tip it was granted against.
    BOOST_CHECK(!mgr.HasPending());
    BOOST_CHECK_EQUAL(mgr.GateCount(), 0u);
    ReorgApprovalState approval = mgr.GetApproval();
    BOOST_CHECK(approval.is_valid);
    BOOST_CHECK(approval.fork_point_hash == fork_point);
    BOOST_CHECK(approval.candidate_tip_hash == candidate);
    BOOST_CHECK(approval.current_tip_hash == current);

    mgr.ClearApproval();
    BOOST_CHECK(!mgr.GetApproval().is_valid);
}

BOOST_AUTO_TEST_CASE(reorg_gating_approval_ttl)
{
    SetMockTime(1000000);
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::BLOCK)};

    const uint256 candidate = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000aa").value();
    const uint256 current = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000bb").value();
    const uint256 fork_point = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000cc").value();
    const uint256 anchor = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000dd").value();

    ReorgAdvisory advisory;
    advisory.is_valid = true;
    mgr.SetPending(advisory, candidate, /*candidate_height=*/105, current, fork_point, anchor, TestWork(50, 60));
    mgr.RecordApprovalFromPending();
    mgr.ClearPending();

    BOOST_CHECK(mgr.GetApproval().is_valid);

    // Still valid at exactly the TTL boundary.
    SetMockTime(1000000 + DEFAULT_REORG_APPROVAL_TTL_SECS);
    BOOST_CHECK(mgr.GetApproval().is_valid);

    // Expired past the TTL.
    SetMockTime(1000000 + DEFAULT_REORG_APPROVAL_TTL_SECS + 1);
    BOOST_CHECK(!mgr.GetApproval().is_valid);

    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(reorg_gating_keyed_map_lifecycle)
{
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};

    // Two distinct {fork point, anchor} keys coexist with monotonic ids.
    const uint64_t id_a = ArmTestGate(mgr, /*tag=*/0x10, /*candidate_height=*/100);
    const uint64_t id_b = ArmTestGate(mgr, /*tag=*/0x20, /*candidate_height=*/101);
    BOOST_CHECK(id_b > id_a);
    BOOST_CHECK_EQUAL(mgr.GateCount(), 2u);
    BOOST_CHECK(mgr.HasPending());

    // Re-arming an existing key is idempotent: same gate id, refreshed
    // candidate tip/height, no duplicate entry.
    ReorgAdvisory advisory;
    advisory.is_valid = true;
    const uint64_t id_a2 = mgr.SetPending(advisory, TestHash(0x99), /*candidate_height=*/107,
                                          TestHash(0xb0), TestHash(0xc0), TestHash(0x11), TestWork(50, 70));
    BOOST_CHECK_EQUAL(id_a2, id_a);
    BOOST_CHECK_EQUAL(mgr.GateCount(), 2u);
    const auto refreshed = mgr.GetGate(id_a);
    BOOST_REQUIRE(refreshed.has_value());
    BOOST_CHECK(refreshed->candidate_tip_hash == TestHash(0x99));
    BOOST_CHECK_EQUAL(refreshed->candidate_height, 107);

    // GetGates is sorted by gate id.
    const auto gates = mgr.GetGates();
    BOOST_REQUIRE_EQUAL(gates.size(), 2u);
    BOOST_CHECK_EQUAL(gates[0].gate_id, id_a);
    BOOST_CHECK_EQUAL(gates[1].gate_id, id_b);
}

BOOST_AUTO_TEST_CASE(reorg_gating_gate_id_targeting)
{
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};

    // No gate at all.
    BOOST_CHECK(mgr.SubmitDecision(std::nullopt, ReorgDecision::ACCEPT) ==
                ReorgGatingManager::SubmitStatus::NO_GATE);

    const uint64_t id_a = ArmTestGate(mgr, 0x10);
    const uint64_t id_b = ArmTestGate(mgr, 0x20);

    // Bare form is refused while more than one gate exists.
    BOOST_CHECK(mgr.SubmitDecision(std::nullopt, ReorgDecision::ACCEPT) ==
                ReorgGatingManager::SubmitStatus::AMBIGUOUS);

    // Unknown id is refused.
    BOOST_CHECK(mgr.SubmitDecision(id_b + 1000, ReorgDecision::ACCEPT) ==
                ReorgGatingManager::SubmitStatus::UNKNOWN_GATE);

    // Targeted accept hits only its gate; the other stays pending.
    uint64_t resolved{0};
    BOOST_CHECK(mgr.SubmitDecision(id_a, ReorgDecision::ACCEPT, &resolved) ==
                ReorgGatingManager::SubmitStatus::OK);
    BOOST_CHECK_EQUAL(resolved, id_a);
    BOOST_CHECK(!mgr.GetGate(id_a).has_value());
    BOOST_CHECK(mgr.GetGate(id_b).has_value());
    BOOST_CHECK(mgr.GetApproval().is_valid);

    // With exactly one gate left, the bare form works again.
    BOOST_CHECK(mgr.SubmitDecision(std::nullopt, ReorgDecision::REJECT, &resolved) ==
                ReorgGatingManager::SubmitStatus::OK);
    BOOST_CHECK_EQUAL(resolved, id_b);
    const auto vetoed = mgr.GetGate(id_b);
    BOOST_REQUIRE(vetoed.has_value());
    BOOST_CHECK(vetoed->gate_state == ReorgGateState::VETOED);
}

BOOST_AUTO_TEST_CASE(reorg_gating_veto_ttl_and_escapes)
{
    SetMockTime(2000000);
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};

    // --- TTL expiry ---
    {
        const uint64_t id = ArmTestGate(mgr, 0x10, /*candidate_height=*/100, TestWork(50, 40));
        // Pending gates always mask.
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 100, arith_uint256{40}, arith_uint256{50}));

        BOOST_REQUIRE(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        // Vetoed and still masked within the TTL, unchanged branch.
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 100, arith_uint256{40}, arith_uint256{50}));

        // Past the TTL the veto is dropped so the branch re-prompts (once).
        SetMockTime(2000000 + 601);
        BOOST_CHECK(!mgr.EvaluateMask(id, TestHash(0x99), 100, arith_uint256{40}, arith_uint256{50}));
        BOOST_CHECK(!mgr.GetGate(id).has_value());
        SetMockTime(2000000);
    }

    // --- Growth escape: branch extends >= veto_growth_blocks (3) ---
    {
        const uint64_t id = ArmTestGate(mgr, 0x20, /*candidate_height=*/100, TestWork(50, 40));
        BOOST_REQUIRE(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 101, arith_uint256{41}, arith_uint256{50}));
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 102, arith_uint256{42}, arith_uint256{50}));
        // +3 blocks beyond the veto-time height: escape fires, gate dropped.
        BOOST_CHECK(!mgr.EvaluateMask(id, TestHash(0x99), 103, arith_uint256{43}, arith_uint256{50}));
        BOOST_CHECK(!mgr.GetGate(id).has_value());
    }

    // --- Raw-work escape: margin over the tip grows past the veto baseline ---
    {
        // At veto time the candidate leads the tip by 10 raw units.
        const uint64_t id = ArmTestGate(mgr, 0x30, /*candidate_height=*/100, TestWork(50, 60));
        BOOST_REQUIRE(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        // Same margin: still masked.
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 100, arith_uint256{60}, arith_uint256{50}));
        // Margin shrank (our tip out-worked it): still masked.
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 100, arith_uint256{60}, arith_uint256{55}));
        // Margin grew past the baseline: escape fires, gate dropped.
        BOOST_CHECK(!mgr.EvaluateMask(id, TestHash(0x99), 101, arith_uint256{65}, arith_uint256{50}));
        BOOST_CHECK(!mgr.GetGate(id).has_value());
    }

    // --- Raw-work escape from a non-positive baseline ---
    {
        // At veto time the candidate does NOT lead on raw work (policy-driven
        // shape); any positive raw margin later must re-prompt.
        const uint64_t id = ArmTestGate(mgr, 0x40, /*candidate_height=*/100, TestWork(50, 40));
        BOOST_REQUIRE(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.EvaluateMask(id, TestHash(0x99), 100, arith_uint256{50}, arith_uint256{50}));
        BOOST_CHECK(!mgr.EvaluateMask(id, TestHash(0x99), 101, arith_uint256{51}, arith_uint256{50}));
        BOOST_CHECK(!mgr.GetGate(id).has_value());
    }

    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(reorg_gating_timeout_generation_race)
{
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};

    const uint64_t id = ArmTestGate(mgr, 0x10);
    const auto armed = mgr.GetGate(id);
    BOOST_REQUIRE(armed.has_value());
    const uint64_t armed_generation = armed->generation;

    // Operator decision bumps the generation...
    BOOST_REQUIRE(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
    const auto vetoed = mgr.GetGate(id);
    BOOST_REQUIRE(vetoed.has_value());
    BOOST_CHECK(vetoed->generation != armed_generation);
    BOOST_CHECK(vetoed->gate_state == ReorgGateState::VETOED);
    const int64_t vetoed_at = vetoed->vetoed_at;

    // ...so the stale timer armed at SetPending fires as a no-op: the veto is
    // neither cleared nor re-recorded.
    mgr.HandleTimeout(id, armed_generation);
    const auto after = mgr.GetGate(id);
    BOOST_REQUIRE(after.has_value());
    BOOST_CHECK(after->gate_state == ReorgGateState::VETOED);
    BOOST_CHECK_EQUAL(after->vetoed_at, vetoed_at);
    BOOST_CHECK_EQUAL(after->generation, vetoed->generation);

    // A timeout for a gate that no longer exists is also a no-op.
    mgr.HandleTimeout(id + 1000, armed_generation);
    BOOST_CHECK_EQUAL(mgr.GateCount(), 1u);
}

BOOST_AUTO_TEST_CASE(reorg_gating_idempotent_transitions)
{
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};

    // Double accept: the second decision finds no gate and changes nothing.
    {
        const uint64_t id = ArmTestGate(mgr, 0x10);
        BOOST_CHECK(mgr.SubmitDecision(id, ReorgDecision::ACCEPT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.SubmitDecision(id, ReorgDecision::ACCEPT) == ReorgGatingManager::SubmitStatus::UNKNOWN_GATE);
        BOOST_CHECK_EQUAL(mgr.GateCount(), 0u);
        mgr.ClearApproval();
    }

    // Double reject: the second reject refreshes the veto, no state corruption.
    {
        const uint64_t id = ArmTestGate(mgr, 0x20);
        BOOST_CHECK(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        const auto gate = mgr.GetGate(id);
        BOOST_REQUIRE(gate.has_value());
        BOOST_CHECK(gate->gate_state == ReorgGateState::VETOED);

        // Accept overrides an earlier reject (veto-clear + approve in one step).
        BOOST_CHECK(mgr.SubmitDecision(id, ReorgDecision::ACCEPT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(!mgr.GetGate(id).has_value());
        BOOST_CHECK(mgr.GetApproval().is_valid);
        mgr.ClearApproval();
    }

    // ClearVeto: only valid on vetoed gates; double-clear is a no-op error.
    {
        const uint64_t id = ArmTestGate(mgr, 0x30);
        BOOST_CHECK(mgr.ClearVeto(id) == ReorgGatingManager::SubmitStatus::BAD_STATE);
        BOOST_REQUIRE(mgr.SubmitDecision(id, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.ClearVeto(id) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.ClearVeto(id) == ReorgGatingManager::SubmitStatus::UNKNOWN_GATE);
        BOOST_CHECK_EQUAL(mgr.GateCount(), 0u);
    }

    // RemoveGate is safe on a missing id.
    BOOST_CHECK(!mgr.RemoveGate(12345, "test"));
}

BOOST_AUTO_TEST_CASE(reorg_gating_prune_moot_gates)
{
    ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};

    // Anchors: 0x11 (invalidated), 0x21 (forced active), 0x31 (still live).
    const uint64_t id_a = ArmTestGate(mgr, 0x10);
    const uint64_t id_b = ArmTestGate(mgr, 0x20);
    const uint64_t id_c = ArmTestGate(mgr, 0x30);
    // Vetoed gates are swept the same as pending ones.
    BOOST_REQUIRE(mgr.SubmitDecision(id_b, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);

    const auto classify = [](const uint256& anchor) {
        if (anchor == TestHash(0x11)) return ReorgGateAnchorStatus::INVALIDATED;
        if (anchor == TestHash(0x21)) return ReorgGateAnchorStatus::ON_ACTIVE_CHAIN;
        return ReorgGateAnchorStatus::KEEP;
    };

    BOOST_CHECK_EQUAL(mgr.PruneMootGates(classify), 2u);
    BOOST_CHECK(!mgr.GetGate(id_a).has_value());
    BOOST_CHECK(!mgr.GetGate(id_b).has_value());
    BOOST_CHECK(mgr.GetGate(id_c).has_value());
    BOOST_CHECK_EQUAL(mgr.GateCount(), 1u);

    // Idempotent: a second sweep over the same state removes nothing.
    BOOST_CHECK_EQUAL(mgr.PruneMootGates(classify), 0u);
    BOOST_CHECK(mgr.GetGate(id_c).has_value());

    // Sweeping an empty map is a no-op.
    BOOST_CHECK(mgr.SubmitDecision(id_c, ReorgDecision::ACCEPT) == ReorgGatingManager::SubmitStatus::OK);
    BOOST_CHECK_EQUAL(mgr.PruneMootGates(classify), 0u);
}

BOOST_AUTO_TEST_CASE(reorg_gating_timeout_accept_guardrail)
{
    // Predicate: auto-accept only a strictly raw-work-heavier candidate that
    // is not penalty/policy-driven.
    BOOST_CHECK(ReorgGatingManager::TimeoutAcceptAllowed(TestWork(50, 60, /*penalty_driven=*/false)));
    BOOST_CHECK(!ReorgGatingManager::TimeoutAcceptAllowed(TestWork(50, 50, false)));  // equal raw: no
    BOOST_CHECK(!ReorgGatingManager::TimeoutAcceptAllowed(TestWork(60, 50, false)));  // lighter raw: no
    BOOST_CHECK(!ReorgGatingManager::TimeoutAcceptAllowed(TestWork(50, 60, true)));   // policy-driven: no

    // End-to-end (mask mode, timeout_accept=1): guardrail pass auto-accepts.
    {
        ReorgGatingConfig config = TestGatingConfig(ReorgGatingMode::MASK);
        config.timeout_accept = true;
        ReorgGatingManager mgr{config};
        const uint64_t id = ArmTestGate(mgr, 0x10, 100, TestWork(50, 60));
        const auto gate = mgr.GetGate(id);
        BOOST_REQUIRE(gate.has_value());
        mgr.HandleTimeout(id, gate->generation);
        BOOST_CHECK(!mgr.GetGate(id).has_value()); // accepted and cleared
        BOOST_CHECK(mgr.GetApproval().is_valid);
    }

    // Guardrail fail (raw-lighter candidate): timeout acts as veto-REJECT.
    {
        ReorgGatingConfig config = TestGatingConfig(ReorgGatingMode::MASK);
        config.timeout_accept = true;
        ReorgGatingManager mgr{config};
        const uint64_t id = ArmTestGate(mgr, 0x20, 100, TestWork(60, 50));
        const auto gate = mgr.GetGate(id);
        BOOST_REQUIRE(gate.has_value());
        mgr.HandleTimeout(id, gate->generation);
        const auto after = mgr.GetGate(id);
        BOOST_REQUIRE(after.has_value());
        BOOST_CHECK(after->gate_state == ReorgGateState::VETOED);
        BOOST_CHECK(!mgr.GetApproval().is_valid);
    }

    // Guardrail fail (penalty/policy-driven): timeout acts as veto-REJECT.
    {
        ReorgGatingConfig config = TestGatingConfig(ReorgGatingMode::MASK);
        config.timeout_accept = true;
        ReorgGatingManager mgr{config};
        const uint64_t id = ArmTestGate(mgr, 0x30, 100, TestWork(50, 60, /*penalty_driven=*/true));
        const auto gate = mgr.GetGate(id);
        BOOST_REQUIRE(gate.has_value());
        mgr.HandleTimeout(id, gate->generation);
        const auto after = mgr.GetGate(id);
        BOOST_REQUIRE(after.has_value());
        BOOST_CHECK(after->gate_state == ReorgGateState::VETOED);
        BOOST_CHECK(!mgr.GetApproval().is_valid);
    }

    // timeout_accept=0: timeout always vetoes, even a raw-work-heavier candidate.
    {
        ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::MASK)};
        const uint64_t id = ArmTestGate(mgr, 0x40, 100, TestWork(50, 60));
        const auto gate = mgr.GetGate(id);
        BOOST_REQUIRE(gate.has_value());
        mgr.HandleTimeout(id, gate->generation);
        const auto after = mgr.GetGate(id);
        BOOST_REQUIRE(after.has_value());
        BOOST_CHECK(after->gate_state == ReorgGateState::VETOED);
    }
}

BOOST_AUTO_TEST_CASE(reorg_gating_block_mode_wait_interrupt_and_decisions)
{
    // Interrupt aborts the wait without a decision or approval.
    {
        ReorgGatingConfig config = TestGatingConfig(ReorgGatingMode::BLOCK);
        ReorgGatingManager mgr{config};
        const uint64_t id = ArmTestGate(mgr, 0x10);
        BOOST_CHECK(mgr.WaitForDecision([] { return true; }) == ReorgDecision::ABORT);
        // The gate survives the abort (the caller clears it explicitly) and
        // no approval was recorded.
        BOOST_CHECK(mgr.GetGate(id).has_value());
        BOOST_CHECK(!mgr.GetApproval().is_valid);
        mgr.ClearPending();
        BOOST_CHECK_EQUAL(mgr.GateCount(), 0u);
    }

    // A decision submitted before/while waiting is returned as-is.
    {
        ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::BLOCK)};
        ArmTestGate(mgr, 0x20);
        BOOST_REQUIRE(mgr.SubmitDecision(std::nullopt, ReorgDecision::REJECT) == ReorgGatingManager::SubmitStatus::OK);
        BOOST_CHECK(mgr.WaitForDecision([] { return false; }) == ReorgDecision::REJECT);
        mgr.ClearPending();
    }

    // Zero timeout: the wait resolves to TIMEOUT without an operator.
    {
        ReorgGatingConfig config = TestGatingConfig(ReorgGatingMode::BLOCK);
        config.timeout_secs = 0;
        ReorgGatingManager mgr{config};
        ArmTestGate(mgr, 0x30);
        BOOST_CHECK(mgr.WaitForDecision([] { return false; }) == ReorgDecision::TIMEOUT);
        mgr.ClearPending();
    }

    // No pending gate: nothing to wait on.
    {
        ReorgGatingManager mgr{TestGatingConfig(ReorgGatingMode::BLOCK)};
        BOOST_CHECK(mgr.WaitForDecision([] { return false; }) == ReorgDecision::NONE);
    }
}

BOOST_AUTO_TEST_CASE(should_auto_follow_sane_partition_reorg)
{
    ReorgGatingConfig config;
    config.enabled = true;
    config.gating_depth_threshold = ADVISORY_DEPTH_THRESHOLD;

    ReorgAdvisory advisory;
    advisory.is_valid = true;
    advisory.calibration.is_valid = true;
    advisory.depth_current = 8;
    advisory.depth_fork = 12;
    advisory.seg_current.block_count = 8;
    advisory.seg_fork.block_count = 12;
    advisory.seg_current.work_diff = arith_uint256(80);
    advisory.seg_fork.work_diff = arith_uint256(120);
    advisory.hashrate_current_pct = 40.0;
    advisory.hashrate_fork_pct = 100.0;
    advisory.first_block_delay_secs = DEFAULT_REORG_AUTOFOLLOW_MIN_FIRST_BLOCK_DELAY_SECS + 60;

    BOOST_CHECK(ShouldAutoFollowSanePartitionReorg(advisory, config));

    ReorgAdvisory disabled_candidate = advisory;
    config.autofollow_sane_partitions = false;
    BOOST_CHECK(!ShouldAutoFollowSanePartitionReorg(disabled_candidate, config));
    config.autofollow_sane_partitions = true;

    ReorgAdvisory invalid_candidate = advisory;
    invalid_candidate.is_valid = false;
    BOOST_CHECK(!ShouldAutoFollowSanePartitionReorg(invalid_candidate, config));

    ReorgAdvisory weak_candidate = advisory;
    weak_candidate.seg_fork.work_diff = arith_uint256(70);
    BOOST_CHECK(!ShouldAutoFollowSanePartitionReorg(weak_candidate, config));

    ReorgAdvisory anomalous_candidate = advisory;
    anomalous_candidate.hashrate_fork_pct = DEFAULT_REORG_AUTOFOLLOW_MAX_FORK_HASHRATE_PCT + 1.0;
    BOOST_CHECK(!ShouldAutoFollowSanePartitionReorg(anomalous_candidate, config));

    ReorgAdvisory peer_race_candidate = advisory;
    peer_race_candidate.first_block_delay_secs = DEFAULT_REORG_AUTOFOLLOW_MIN_FIRST_BLOCK_DELAY_SECS - 1;
    BOOST_CHECK(!ShouldAutoFollowSanePartitionReorg(peer_race_candidate, config));

    ReorgAdvisory not_materially_stronger = advisory;
    not_materially_stronger.hashrate_current_pct = 90.0;
    not_materially_stronger.hashrate_fork_pct = 100.0;
    BOOST_CHECK(!ShouldAutoFollowSanePartitionReorg(not_materially_stronger, config));
}

BOOST_AUTO_TEST_CASE(advisory_store_operations)
{
    // Test ReorgAdvisoryStore functionality
    ReorgAdvisoryStore store;

    // Initially empty
    BOOST_CHECK_EQUAL(store.Size(), 0u);
    BOOST_CHECK(!store.GetLatest().has_value());
    BOOST_CHECK(store.GetAll().empty());

    // Add an advisory
    ReorgAdvisory adv1;
    adv1.lca_height = 100;
    adv1.depth_current = 5;
    adv1.is_valid = true;
    store.Add(adv1);

    BOOST_CHECK_EQUAL(store.Size(), 1u);
    BOOST_CHECK(store.GetLatest().has_value());
    BOOST_CHECK_EQUAL(store.GetLatest()->lca_height, 100);

    // Add another advisory
    ReorgAdvisory adv2;
    adv2.lca_height = 200;
    adv2.depth_current = 10;
    adv2.is_valid = true;
    store.Add(adv2);

    BOOST_CHECK_EQUAL(store.Size(), 2u);
    // Latest should be the newest one
    BOOST_CHECK_EQUAL(store.GetLatest()->lca_height, 200);

    // GetRecent should return newest first
    auto recent = store.GetRecent(2);
    BOOST_CHECK_EQUAL(recent.size(), 2u);
    BOOST_CHECK_EQUAL(recent[0].lca_height, 200);
    BOOST_CHECK_EQUAL(recent[1].lca_height, 100);

    // Clear
    store.Clear();
    BOOST_CHECK_EQUAL(store.Size(), 0u);
    BOOST_CHECK(!store.GetLatest().has_value());
}

BOOST_AUTO_TEST_CASE(max_blocks_for_txids_default)
{
    // Test that GetMaxBlocksForTxids returns default when no arg is set
    // Note: In unit tests, gArgs may not have the arg set, so we get the default
    int max_blocks = GetMaxBlocksForTxids();
    // Should be the default value (100) when no arg is set
    BOOST_CHECK_EQUAL(max_blocks, DEFAULT_MAX_BLOCKS_FOR_TXIDS);
}

BOOST_AUTO_TEST_CASE(constants_updated)
{
    // Verify the new constant is correct
    BOOST_CHECK_EQUAL(DEFAULT_MAX_BLOCKS_FOR_TXIDS, 100);
}

BOOST_AUTO_TEST_CASE(generate_advisory_metrics_basic)
{
    // Build a small synthetic fork with explicit ticks, times, and first_seen values.
    // Use lambda-backed data source to avoid disk I/O.
    struct BlockNode {
        std::unique_ptr<CBlockIndex> index;
        uint256 hash;
    };

    auto MakeBlock = [](int64_t nTime, uint64_t cumulative_tick, int tx_tag) {
        CBlock blk;
        blk.nTime = nTime;
        blk.cumulative_tick = cumulative_tick;

        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vout.resize(1);
        coinbase.vout[0].nValue = 50 * COIN;
        blk.vtx.push_back(MakeTransactionRef(coinbase));

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.resize(1);
        tx.vout[0].nValue = 1 * COIN;
        tx.vout[0].scriptPubKey.assign(reinterpret_cast<const unsigned char*>(&tx_tag),
                                       reinterpret_cast<const unsigned char*>(&tx_tag) + sizeof(tx_tag));
        blk.vtx.push_back(MakeTransactionRef(tx));
        return blk;
    };

    std::vector<BlockNode> nodes;
    std::map<uint256, CBlock> blocks;
    std::map<uint256, int64_t> first_seen;

    auto add_block = [&](int height, const std::string& hash_hex, uint64_t chainwork,
                         int64_t nTime, uint64_t cumulative_tick, int tx_tag, CBlockIndex* prev) -> CBlockIndex* {
        nodes.push_back({});
        BlockNode& node = nodes.back();
        node.hash = uint256::FromHex(hash_hex).value();
        node.index = std::make_unique<CBlockIndex>();
        node.index->nHeight = height;
        node.index->nTime = nTime;
        uint256 cw = uint256::FromHex(strprintf("%064x", chainwork)).value();
        node.index->nChainWork = UintToArith256(cw);
        node.index->pprev = prev;
        node.index->phashBlock = &node.hash;

        CBlock blk = MakeBlock(nTime, cumulative_tick, tx_tag);
        blocks.emplace(node.hash, blk);
        first_seen[node.hash] = nTime + 5;
        return node.index.get();
    };

    // Base chain: b0 -> b1 -> lca (b2)
    CBlockIndex* b0 = add_block(0, "0000000000000000000000000000000000000000000000000000000000000001", 10, 100, 0, 1, nullptr);
    CBlockIndex* b1 = add_block(1, "0000000000000000000000000000000000000000000000000000000000000002", 20, 160, 10, 2, b0);
    CBlockIndex* lca = add_block(2, "0000000000000000000000000000000000000000000000000000000000000003", 30, 220, 30, 3, b1);

    // Current chain: lca -> c3 -> c4
    CBlockIndex* c3 = add_block(3, "0000000000000000000000000000000000000000000000000000000000000004", 45, 280, 50, 4, lca);
    CBlockIndex* current_tip = add_block(4, "0000000000000000000000000000000000000000000000000000000000000005", 60, 340, 70, 5, c3);

    // Fork chain: lca -> f3 -> f4 -> f5
    CBlockIndex* f3 = add_block(3, "0000000000000000000000000000000000000000000000000000000000000006", 50, 280, 55, 6, lca);
    CBlockIndex* f4 = add_block(4, "0000000000000000000000000000000000000000000000000000000000000007", 70, 340, 80, 7, f3);
    CBlockIndex* fork_tip = add_block(5, "0000000000000000000000000000000000000000000000000000000000000008", 90, 400, 100, 8, f4);

    auto reader = [&](const CBlockIndex& idx, CBlock& out) {
        auto it = blocks.find(idx.GetBlockHash());
        if (it == blocks.end()) return false;
        out = it->second;
        return true;
    };
    auto seen = [&](const uint256& h) {
        auto it = first_seen.find(h);
        return it == first_seen.end() ? int64_t{0} : it->second;
    };

    LambdaBlockDataSource source(reader, seen);

    // Supply a safe calibration window (>= min window) to avoid optional access issues.
    ReorgAdvisory adv = GenerateReorgAdvisory(
        source,
        current_tip,
        fork_tip,
        lca,
        /*calibration_window=*/3,
        /*calibration_min_window=*/1);

    BOOST_CHECK(adv.is_valid);
    BOOST_CHECK_EQUAL(adv.lca_height, 2);
    BOOST_CHECK_EQUAL(adv.depth_current, 2);
    BOOST_CHECK_EQUAL(adv.depth_fork, 3);

    // sec_per_tick: (220 - 100) / (30 - 0) = 120 / 30 = 4, but our window (3) walks back only 2 blocks ->  (220-160)/(30-10)=60/20=3
    BOOST_CHECK(adv.calibration.is_valid);
    BOOST_CHECK_CLOSE(adv.calibration.sec_per_tick, 3.0, 0.1);

    BOOST_CHECK_EQUAL(adv.seg_current.ticks_diff, 40u); // 70 - 30
    BOOST_CHECK_EQUAL(adv.seg_fork.ticks_diff, 70u);    // 100 - 30

    // Fork has more work and higher hashrate than current branch
    BOOST_CHECK_GT(adv.hashrate_fork_pct, adv.hashrate_current_pct);
    BOOST_CHECK_GT(adv.first_block_delay_secs, 0);
    BOOST_CHECK_EQUAL(static_cast<int>(adv.tx_overlap_pct), 0);
}

BOOST_AUTO_TEST_CASE(worker_pool_basic)
{
    // Test AdvisoryWorkerPool basic lifecycle
    AdvisoryWorkerPool pool;

    // Not running initially
    BOOST_CHECK(!pool.IsRunning());

    // Start the pool
    pool.Start();
    BOOST_CHECK(pool.IsRunning());

    // Submit an advisory
    ReorgAdvisory adv;
    adv.lca_height = 12345;
    adv.depth_current = 5;
    adv.is_valid = true;
    pool.Submit(adv);

    // Give the worker a moment to process
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Stop the pool
    pool.Stop();
    BOOST_CHECK(!pool.IsRunning());

    // Start is idempotent
    pool.Start();
    pool.Start();  // Should not crash or create duplicate threads
    pool.Stop();
}

BOOST_AUTO_TEST_CASE(worker_pool_multiple_submits)
{
    AdvisoryWorkerPool pool;
    pool.Start();

    // Submit multiple advisories
    for (int i = 0; i < 10; ++i) {
        ReorgAdvisory adv;
        adv.lca_height = 1000 + i;
        adv.depth_current = 5;
        adv.is_valid = true;
        pool.Submit(adv);
    }

    // Give the worker time to process all
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    pool.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
