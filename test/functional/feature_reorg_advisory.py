#!/usr/bin/env python3
# Copyright (c) 2024-present The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the reorg advisory system.

Tests:
- Deep reorgs (> 3 blocks) trigger advisory logging
- getreorgadvisories RPC returns advisory data with correct structure
- getlatestreorgadvisory RPC returns single latest advisory
- clearreorgadvisories RPC clears stored advisories
- Advisory is NOT triggered when disabled via config
- Advisory is NOT triggered for shallow reorgs (below threshold)
- -reorgadvisorynotify command is executed when advisory triggers
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class ReorgAdvisoryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Force cleanup even on failure to prevent state contamination
        self.force_cleanup_on_failure = True
        # Enable reorg advisory with default thresholds
        # Include spv-asn-corroboration=0 for 2-node topology sync
        self.extra_args = [
            ["-reorgadvisory=1", "-reorgadvisorydepth=3", "-spv-asn-corroboration=0"],
            ["-reorgadvisory=1", "-reorgadvisorydepth=3", "-spv-asn-corroboration=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def no_op(self):
        """No-op sync function for single node operations."""
        pass

    def run_test(self):
        self.test_deep_reorg_creates_advisory()
        self.test_getlatestreorgadvisory()
        self.test_clearreorgadvisories()
        self.test_advisory_disabled()
        self.test_shallow_reorg_no_advisory()
        self.test_notify_command()

    def get_advisory_count(self, node):
        """Helper to get the number of advisories from RPC result."""
        result = node.getreorgadvisories()
        return result["total_stored"]

    def get_advisories(self, node, count=10):
        """Helper to get the advisories list from RPC result."""
        result = node.getreorgadvisories(count)
        return result["advisories"]

    def test_deep_reorg_creates_advisory(self):
        """Test that a deep reorg (> threshold) creates an advisory entry"""
        self.log.info("Testing deep reorg creates advisory...")

        node0, node1 = self.nodes[0], self.nodes[1]

        self.log.info("Generate initial blocks on node0")
        self.generate(node0, 110, sync_fun=lambda: self.sync_all())

        # Record the LCA height (where the fork will occur)
        lca_height = node0.getblockcount()
        self.log.info(f"LCA height (fork point): {lca_height}")

        self.log.info("Verify no advisories exist initially")
        assert_equal(self.get_advisory_count(node0), 0)

        self.log.info("Disconnect nodes to create fork")
        self.disconnect_nodes(0, 1)

        # Mine blocks on each node to create divergent chains
        blocks_on_node0 = 5
        blocks_on_node1 = 8

        self.log.info(f"Mine {blocks_on_node0} blocks on node0 (will be orphaned)")
        self.generate(node0, blocks_on_node0, sync_fun=self.no_op)

        self.log.info(f"Mine {blocks_on_node1} blocks on node1 (longer chain)")
        self.generate(node1, blocks_on_node1, sync_fun=self.no_op)

        height0 = node0.getblockcount()
        height1 = node1.getblockcount()
        self.log.info(f"Heights before reorg: node0={height0}, node1={height1}")

        self.log.info("Reconnect nodes to trigger reorg")
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # node0 should reorg to node1's chain
        new_height0 = node0.getblockcount()
        self.log.info(f"Height after reorg: node0={new_height0}")
        assert_equal(new_height0, height1)

        self.log.info(f"Check for reorg advisory (reorg depth was {blocks_on_node0} blocks)")
        # Give the async advisory a moment to complete
        self.wait_until(lambda: self.get_advisory_count(node0) > 0, timeout=10)

        advisory_count = self.get_advisory_count(node0)
        self.log.info(f"Found {advisory_count} advisories")
        assert_greater_than(advisory_count, 0)

        # Verify advisory content
        advisories = self.get_advisories(node0)
        latest = advisories[0]
        self.log.info(f"Latest advisory: {latest}")

        # Basic structure checks - RPC uses "valid" not "is_valid"
        assert "lca_height" in latest, "Advisory should have lca_height"
        assert "depth_current" in latest, "Advisory should have depth_current"
        assert "depth_fork" in latest, "Advisory should have depth_fork"
        assert "valid" in latest, "Advisory should have valid"

        # Verify the advisory reports a deep reorg
        # depth_current = orphaned blocks from node0's perspective (should be 5)
        assert_greater_than(latest["depth_current"], 3)
        self.log.info(f"Advisory depth_current: {latest['depth_current']}")

        # depth_fork should be > depth_current (that's why we reorged)
        assert_greater_than(latest["depth_fork"], latest["depth_current"])
        self.log.info(f"Advisory depth_fork: {latest['depth_fork']}")

        # LCA should be at or near where we disconnected
        assert_equal(latest["lca_height"], lca_height)

        self.log.info("Deep reorg advisory test passed")

    def test_getlatestreorgadvisory(self):
        """Test that getlatestreorgadvisory returns the most recent advisory"""
        self.log.info("Testing getlatestreorgadvisory RPC...")

        node0 = self.nodes[0]

        # We should have at least 1 advisory from the previous test
        advisory_count = self.get_advisory_count(node0)
        self.log.info(f"Current advisory count: {advisory_count}")
        assert_greater_than(advisory_count, 0)

        # Get the latest advisory
        latest = node0.getlatestreorgadvisory()
        self.log.info(f"Latest advisory: {latest}")

        # Verify it has the expected structure
        assert "lca_height" in latest, "Latest advisory should have lca_height"
        assert "depth_current" in latest, "Latest advisory should have depth_current"
        assert "depth_fork" in latest, "Latest advisory should have depth_fork"
        assert "valid" in latest, "Latest advisory should have valid"

        # Should match what getreorgadvisories returns as first entry
        advisories = self.get_advisories(node0)
        assert_equal(latest["lca_height"], advisories[0]["lca_height"])
        assert_equal(latest["depth_current"], advisories[0]["depth_current"])

        self.log.info("getlatestreorgadvisory test passed")

    def test_clearreorgadvisories(self):
        """Test that clearreorgadvisories clears all stored advisories"""
        self.log.info("Testing clearreorgadvisories RPC...")

        node0 = self.nodes[0]

        # We should have at least 1 advisory from the deep reorg test
        advisory_count_before = self.get_advisory_count(node0)
        self.log.info(f"Advisory count before clear: {advisory_count_before}")
        assert_greater_than(advisory_count_before, 0)

        # Clear the advisories
        result = node0.clearreorgadvisories()
        self.log.info(f"Clear result: {result}")

        # Verify the cleared count matches
        assert_equal(result["cleared"], advisory_count_before)

        # Verify advisories are now empty
        advisory_count_after = self.get_advisory_count(node0)
        self.log.info(f"Advisory count after clear: {advisory_count_after}")
        assert_equal(advisory_count_after, 0)

        # getlatestreorgadvisory should return null
        latest = node0.getlatestreorgadvisory()
        self.log.info(f"Latest after clear: {latest}")
        assert latest is None, "Latest should be null after clearing"

        self.log.info("clearreorgadvisories test passed")

    def test_advisory_disabled(self):
        """Test that advisory is NOT created when disabled via config"""
        self.log.info("Testing advisory disabled via config...")

        # Start fresh - restart both nodes (node0 with advisory disabled)
        self.restart_node(0, extra_args=["-reorgadvisory=0", "-reorgadvisorydepth=3", "-spv-asn-corroboration=0"])
        self.restart_node(1, extra_args=["-reorgadvisory=1", "-reorgadvisorydepth=3", "-spv-asn-corroboration=0"])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]

        # Generate blocks to establish common chain
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()

        # Save current advisory count (should be 0 after restart since store is in-memory)
        advisory_count_before = self.get_advisory_count(node0)
        self.log.info(f"Advisory count before: {advisory_count_before}")

        self.log.info("Disconnect nodes")
        self.disconnect_nodes(0, 1)

        self.log.info("Mine 6 blocks on node0")
        self.generate(node0, 6, sync_fun=self.no_op)

        self.log.info("Mine 10 blocks on node1")
        self.generate(node1, 10, sync_fun=self.no_op)

        height_before = node0.getblockcount()
        target_height = node1.getblockcount()
        self.log.info(f"Heights before reorg: node0={height_before}, node1={target_height}")

        self.log.info("Reconnect to trigger reorg (should NOT create advisory)")
        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info(f"Height after reorg: node0={node0.getblockcount()}")

        # Since advisory is disabled, count should not increase
        time.sleep(1)  # Brief wait for async task if any
        advisory_count_after = self.get_advisory_count(node0)
        self.log.info(f"Advisory count after: {advisory_count_after}")
        assert_equal(advisory_count_before, advisory_count_after)

        self.log.info("Advisory disabled test passed")

    def test_shallow_reorg_no_advisory(self):
        """Test that shallow reorg (< threshold) does NOT create advisory"""
        self.log.info("Testing shallow reorg does not create advisory...")

        # Start fresh - restart both nodes with advisory enabled
        self.restart_node(0, extra_args=["-reorgadvisory=1", "-reorgadvisorydepth=3", "-spv-asn-corroboration=0"])
        self.restart_node(1, extra_args=["-reorgadvisory=1", "-reorgadvisorydepth=3", "-spv-asn-corroboration=0"])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]

        # Generate blocks to establish common chain
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()

        # Save current advisory count (should be 0 after restart)
        advisory_count_before = self.get_advisory_count(node0)
        self.log.info(f"Advisory count before shallow reorg: {advisory_count_before}")

        self.log.info("Disconnect nodes")
        self.disconnect_nodes(0, 1)

        # Create a shallow 2-block reorg (at or below threshold of 3)
        self.log.info("Mine 2 blocks on node0 (shallow)")
        self.generate(node0, 2, sync_fun=self.no_op)

        self.log.info("Mine 3 blocks on node1 (slightly longer)")
        self.generate(node1, 3, sync_fun=self.no_op)

        self.log.info(f"Heights before reorg: node0={node0.getblockcount()}, node1={node1.getblockcount()}")

        self.log.info("Reconnect to trigger shallow reorg")
        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info(f"Height after reorg: node0={node0.getblockcount()}")

        time.sleep(1)  # Brief wait for async task if any
        advisory_count_after = self.get_advisory_count(node0)
        self.log.info(f"Advisory count after shallow reorg: {advisory_count_after}")

        # 2 blocks is <= 3 threshold, so no new advisory
        assert_equal(advisory_count_before, advisory_count_after)

        self.log.info("Shallow reorg test passed")

    def test_notify_command(self):
        """Test that -reorgadvisorynotify command is executed on deep reorg"""
        self.log.info("Testing reorg advisory notify command...")

        # Create a temp file path for the notify output
        notify_file = os.path.join(self.options.tmpdir, "reorg_notify.txt")

        # Restart nodes with notify command configured
        # The command writes depth, lca_height, fork_depth, overlap to the file
        notify_cmd = f'echo "depth=%d lca=%h fork=%f overlap=%o" >> {notify_file}'
        self.restart_node(0, extra_args=[
            "-reorgadvisory=1",
            "-reorgadvisorydepth=3",
            "-spv-asn-corroboration=0",
            f"-reorgadvisorynotify={notify_cmd}"
        ])
        self.restart_node(1, extra_args=[
            "-reorgadvisory=1",
            "-reorgadvisorydepth=3",
            "-spv-asn-corroboration=0"
        ])
        self.connect_nodes(0, 1)

        node0, node1 = self.nodes[0], self.nodes[1]

        # Generate blocks to establish common chain
        self.generate(node0, 101, sync_fun=self.no_op)
        self.sync_all()

        # Ensure notify file doesn't exist yet
        if os.path.exists(notify_file):
            os.remove(notify_file)

        self.log.info("Disconnect nodes to create fork")
        self.disconnect_nodes(0, 1)

        # Create a deep reorg (> 3 blocks)
        self.log.info("Mine 5 blocks on node0 (will be orphaned)")
        self.generate(node0, 5, sync_fun=self.no_op)

        self.log.info("Mine 8 blocks on node1 (longer chain)")
        self.generate(node1, 8, sync_fun=self.no_op)

        self.log.info("Reconnect to trigger reorg and notify")
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Wait for async advisory processing
        self.wait_until(lambda: os.path.exists(notify_file), timeout=10)

        # Read and verify the notify file contents
        with open(notify_file, 'r') as f:
            content = f.read()
        self.log.info(f"Notify file contents: {content}")

        # Verify the placeholders were substituted
        assert "depth=5" in content, f"Expected depth=5 in notify output, got: {content}"
        assert "lca=" in content, f"Expected lca= in notify output, got: {content}"
        assert "fork=" in content, f"Expected fork= in notify output, got: {content}"
        assert "overlap=" in content, f"Expected overlap= in notify output, got: {content}"

        self.log.info("Notify command test passed")


if __name__ == '__main__':
    ReorgAdvisoryTest(__file__).main()
