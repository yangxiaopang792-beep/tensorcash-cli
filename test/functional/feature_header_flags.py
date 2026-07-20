#!/usr/bin/env python3
"""Header flags malleability tolerance (flags do not affect PoW/acceptance).

Builds a block with nonzero header flags and ensures it is accepted.
Single-node, isolated, and safe for parallel runs.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    initialize_tensor_block_fields,
)
from test_framework.util import assert_equal


class HeaderFlagsMalleabilityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 1)

        tip_hash = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1

        blk = create_block(tip_hash, create_coinbase(height))
        initialize_tensor_block_fields(blk)
        from test_framework.blocktools import set_block_tick_from_prev
        set_block_tick_from_prev(node, blk)
        blk.flags = 0xFF  # set nonzero header flags
        blk.hashMerkleRoot = blk.calc_merkle_root()
        blk.solve()

        # Should be accepted normally
        assert node.submitblock(blk.serialize().hex()) is None
        assert_equal(node.getbestblockhash(), blk.hash)


if __name__ == '__main__':
    HeaderFlagsMalleabilityTest(__file__).main()

