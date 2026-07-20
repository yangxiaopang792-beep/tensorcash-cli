#!/usr/bin/env python3
"""Tick accumulator consensus checks (negative case).

Verifies a block is rejected when cumulative_tick != prev.cumulative_tick + pow.tick.
Uses minimal setup on a single node and does not rely on external APIs.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    initialize_tensor_block_fields,
)
from test_framework.util import assert_equal


class TickAccumulatorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 1)

        prev = int(node.getbestblockhash(), 16)
        prev_info = node.getblock(node.getbestblockhash())
        height = node.getblockcount() + 1

        # Get the previous block's cumulative tick
        prev_cumulative_tick = prev_info.get('cumulative_tick', 0)

        bad = create_block(prev, create_coinbase(height))
        initialize_tensor_block_fields(bad)
        bad.pow.tick = 100  # set a nonzero tick
        bad.cumulative_tick = 1  # incorrect (should be prev_cum + 100)
        bad.nTime += 1  # Make it slightly different time
        bad.hashMerkleRoot = bad.calc_merkle_root()
        from test_framework.blocktools import set_block_tick
        # Set block tick but with wrong cumulative_tick
        set_block_tick(bad, tick=100, prev_cumulative_tick=0)
        bad.cumulative_tick = 1  # override with wrong value
        bad.solve()

        # Submitting should fail (tip unchanged)
        prev_tip = node.getbestblockhash()
        node.submitblock(bad.serialize().hex())
        assert_equal(node.getbestblockhash(), prev_tip)

        # Now construct a valid block with matching cumulative_tick
        good = create_block(prev, create_coinbase(height))
        initialize_tensor_block_fields(good)
        good.nTime += 2  # Different time from bad block
        from test_framework.blocktools import set_block_tick_from_prev
        # Let set_block_tick_from_prev handle all tick setup
        set_block_tick_from_prev(node, good, tick=100)
        good.hashMerkleRoot = good.calc_merkle_root()
        good.solve()
        result = node.submitblock(good.serialize().hex())
        if result is not None:
            self.log.error(f"Block submission failed with: {result}")
            self.log.error(f"Block tick: {good.pow.tick}, cumulative_tick: {good.cumulative_tick}")
            self.log.error(f"Previous cumulative_tick: {prev_cumulative_tick}")
        assert result is None, f"Expected block to be accepted but got: {result}"


if __name__ == '__main__':
    TickAccumulatorTest(__file__).main()

