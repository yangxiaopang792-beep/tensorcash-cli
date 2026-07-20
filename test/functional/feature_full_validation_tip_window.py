#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise external Full validation tip-window behavior during bootstrap."""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class FullValidationTipWindowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            ["-validationapi=mock", "-mockval-force-external=1", "-mockval-default-quick=quick_ok_smell_ok", "-fullvalidationtipwindow=2"],
            [],
            ["-validationapi=mock", "-mockval-force-external=1", "-mockval-default-quick=quick_ok_smell_ok", "-fullvalidationtipwindow=0"],
        ]

    def full_requests(self, node):
        return [req["id"] for req in node.validationmockrequests() if req["type"] == "Full"]

    def wait_for_full_request(self, node, block_hash):
        self.wait_until(lambda: block_hash in self.full_requests(node), timeout=20)

    def clear_mock_history(self, node):
        node.validationmockclear()
        node.validationmockdefault("quick", "quick_ok_smell_ok")

    def submit_block_from(self, target, source, block_hash):
        return target.submitblock(source.getblock(block_hash, 0))

    def run_test(self):
        window_node = self.nodes[0]
        miner = self.nodes[1]
        unlimited_node = self.nodes[2]

        self.log.info("Mine an old chain before the validating nodes connect")
        now = int(time.time())
        old_time = now - 7 * 24 * 60 * 60
        blocks = []
        for i in range(5):
            miner.setmocktime(old_time + i + 1)
            blocks.extend(self.generate(miner, 1, sync_fun=self.no_op))
        miner.setmocktime(0)
        window_node.setmocktime(now)
        unlimited_node.setmocktime(now)

        self.log.info("A non-live node with window=2 connects old blocks without Full results")
        self.connect_nodes(0, 1)
        self.wait_until(lambda: window_node.getblockchaininfo()["headers"] >= 5, timeout=20)
        for block_hash in blocks[:3]:
            self.submit_block_from(window_node, miner, block_hash)
        self.wait_until(lambda: window_node.getblockcount() == 3, timeout=20)

        self.clear_mock_history(window_node)

        self.log.info("The configured tail still requires Full validation before advancing")
        result = self.submit_block_from(window_node, miner, blocks[3])
        assert result in (None, "inconclusive")
        self.wait_for_full_request(window_node, blocks[3])
        assert_equal(window_node.getblockcount(), 3)
        requests = self.full_requests(window_node)
        assert blocks[0] not in requests
        assert blocks[1] not in requests
        assert blocks[2] not in requests
        assert blocks[3] in requests

        window_node.validationmockset(blocks[3], "full", "full_green")
        result = self.submit_block_from(window_node, miner, blocks[3])
        assert result in (None, "duplicate", "inconclusive")
        self.wait_until(lambda: window_node.getblockcount() >= 4, timeout=20)

        if blocks[4] not in self.full_requests(window_node):
            self.submit_block_from(window_node, miner, blocks[4])
        self.wait_for_full_request(window_node, blocks[4])
        window_node.validationmockset(blocks[4], "full", "full_green")
        result = self.submit_block_from(window_node, miner, blocks[4])
        assert result in (None, "duplicate", "inconclusive")
        self.wait_until(lambda: window_node.getblockcount() == 5, timeout=20)

        requests = self.full_requests(window_node)
        assert blocks[0] not in requests
        assert blocks[1] not in requests
        assert blocks[2] not in requests
        assert blocks[3] in requests
        assert blocks[4] in requests

        self.log.info("Window=0 keeps the explicit reverify-from-genesis behavior")
        self.connect_nodes(2, 1)
        self.wait_for_full_request(unlimited_node, blocks[0])
        assert_equal(unlimited_node.getblockcount(), 0)
        assert_equal(self.full_requests(unlimited_node)[0], blocks[0])


if __name__ == "__main__":
    FullValidationTipWindowTest(__file__).main()
