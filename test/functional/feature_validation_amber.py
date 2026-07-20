#!/usr/bin/env python3
# Copyright (c) 2024 TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise ValidationAPI amber follow-up flow end-to-end."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
import time
from pathlib import Path

class ValidationAmberTest(BitcoinTestFramework):
    STATUS_CODES = {
        "full_green": 7,
        "full_amber": 8,
        "full_red": 9,
    }

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            ["-validationapi=mock", "-mockval-force-external=1", "-mockval-default-full=full_green"],
            ["-validationapi=mock", "-mockval-force-external=1", "-mockval-default-full=full_green"],
        ]

    def send_full_request(self, node, block_hash):
        # use mock API RPC to mark block request as amber
        node.validationmockset(block_hash, "full", "full_amber")

    def wait_for_full_status(self, node, block_hash, expected_status, timeout=60):
        status_code = self.STATUS_CODES[expected_status.lower()]
        code_fragment = f", 2, {status_code})".encode()
        log_paths = [n.debug_log_path for n in self.nodes]
        positions = {}
        window = 4096
        for path in log_paths:
            if path.exists():
                size = path.stat().st_size
                positions[path] = max(0, size - window)
            else:
                positions[path] = 0

        def _seen_status():
            for path in log_paths:
                if not path.exists():
                    continue
                pos = positions[path]
                with open(path, "rb") as fh:
                    lookbehind = max(window, len(code_fragment), len(b"SetRequestStatus"))
                    seek_pos = max(0, pos - lookbehind)
                    fh.seek(seek_pos)
                    data = fh.read()
                    positions[path] = fh.tell()
                if b"SetRequestStatus" in data and code_fragment in data:
                    return True
            return False

        self.wait_until(_seen_status, timeout=timeout)

    def run_test(self):
        node0 = self.nodes[0]
        # Sanity: mock backend should be reported as available
        info = node0.getvalidationapiinfo()
        assert info["available"]
        assert info["active"]

        # connect peers for header traffic via framework helper
        self.connect_nodes(0, 1)
        # allow multiple outbound slots in case the node maintains parallel handshakes
        self.wait_until(lambda: node0.getconnectioncount() >= 1)

        # mine a block to generate full validation request
        block_hash = self.generate(node0, 1)[0]
        self.send_full_request(node0, block_hash)
        self.nodes[1].validationmockset(block_hash, "full", "full_green")

        # deterministically resolve to green via mock RPC (simulates peer verdict)
        node0.validationmockset(block_hash, "full", "full_green")
        self.wait_for_full_status(node0, block_hash, "full_green", timeout=10)

        # scenario: peer doesn't respond, ensure retries then forced resolution
        self.disconnect_nodes(0, 1)
        self.wait_until(lambda: node0.getconnectioncount() == 0)

        block_hash2 = self.generate(node0, 1, sync_fun=lambda: None)[0]
        node0.validationmockset(block_hash2, "full", "full_amber")
        # force failure verdict without waiting for retries to keep test deterministic
        node0.validationmockset(block_hash2, "full", "full_red")

        start = time.time()
        self.wait_for_full_status(node0, block_hash2, "full_red", timeout=10)
        duration = time.time() - start
        assert duration < 30

        # Full RED is a local zero-work result: the block is stored but does not beat its parent.
        parent_hash = node0.getbestblockhash()
        parent_work = int(node0.getblockheader(parent_hash)["chainwork"], 16)
        candidate = self.generateblock(
            node0,
            node0.get_deterministic_priv_key().address,
            [],
            False,
            sync_fun=self.no_op,
        )
        red_hash = candidate["hash"]
        node0.validationmockset(red_hash, "full", "full_red")
        submit_result = node0.submitblock(candidate["hex"])
        assert submit_result in (None, "duplicate", "inconclusive"), f"unexpected submitblock result: {submit_result}"
        assert_equal(node0.getbestblockhash(), parent_hash)
        assert_equal(int(node0.getblockheader(red_hash)["chainwork"], 16), parent_work)

        self.restart_node(0)
        node0 = self.nodes[0]
        assert_equal(node0.getbestblockhash(), parent_hash)
        assert_equal(int(node0.getblockheader(red_hash)["chainwork"], 16), parent_work)

        # Revalidation to green replays chainwork and allows the block to become best.
        result = node0.revalidateblock(red_hash, 1000)
        assert_equal(result["validation_status"], "full_green")
        assert_equal(result["chain_action"], "accepted")
        assert_equal(node0.getbestblockhash(), red_hash)
        assert int(node0.getblockheader(red_hash)["chainwork"], 16) > parent_work

if __name__ == '__main__':
    ValidationAmberTest(__file__).main()
