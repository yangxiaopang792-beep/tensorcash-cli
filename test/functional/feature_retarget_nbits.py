#!/usr/bin/env python3
"""Network retarget should use nBits (not nAdjBits).

This functional test:
 - Mines a valid block
 - Builds a new block with valid PoW (via nAdjBits) but flips nBits
 - Submits the block and asserts it is rejected (tip does not advance)

It is isolated, single-node, and parallel-friendly.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    initialize_tensor_block_fields,
)
from test_framework.util import assert_equal


class RetargetNBitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # No external API needed for regtest header checks
        self.extra_args = [[]]

    def run_test(self):
        node = self.nodes[0]

        # Generate a starting block
        self.generate(node, 1)
        tip_hash = int(node.getbestblockhash(), 16)
        tip_info = node.getblock(node.getbestblockhash())
        height = tip_info['height'] + 1

        # Create a new block extending the tip
        block = create_block(tip_hash, create_coinbase(height))
        initialize_tensor_block_fields(block)
        from test_framework.blocktools import set_block_tick_from_prev
        set_block_tick_from_prev(node, block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()  # mines against nAdjBits

        # Submit a valid block to advance the tip
        assert node.submitblock(block.serialize().hex()) is None
        new_tip = node.getbestblockhash()
        assert_equal(new_tip, block.hash)

        # Build another block and then flip nBits while keeping PoW tied to nAdjBits
        tip_hash2 = int(node.getbestblockhash(), 16)
        height2 = node.getblockcount() + 1
        bad = create_block(tip_hash2, create_coinbase(height2))
        initialize_tensor_block_fields(bad)
        set_block_tick_from_prev(node, bad)
        bad.hashMerkleRoot = bad.calc_merkle_root()
        bad.solve()

        # Flip the network difficulty bits (retarget) only
        bad.nBits = (bad.nBits - 1) & 0xFFFFFFFF

        # Submitting should fail: header retarget uses nBits -> mismatch => rejected
        prev_tip = node.getbestblockhash()
        node.submitblock(bad.serialize().hex())
        # Tip must remain unchanged
        assert_equal(node.getbestblockhash(), prev_tip)


if __name__ == '__main__':
    RetargetNBitsTest(__file__).main()

