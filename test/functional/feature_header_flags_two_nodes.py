#!/usr/bin/env python3
"""Two-node header flags malleability test.

Each node accepts a block with identical content except for the header `flags`
field. Since the block hash excludes `flags`, both should end up on the same
chain and stay in consensus.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    initialize_tensor_block_fields,
)


class HeaderFlagsTwoNodesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]

    def run_test(self):
        n0, n1 = self.nodes
        self.connect_nodes(0, 1)

        # Start from genesis + 1 block
        self.generate(n0, 1)
        self.sync_blocks([n0, n1])

        tip = int(n0.getbestblockhash(), 16)
        height = n0.getblockcount() + 1

        # Create a block and solve it
        b0 = create_block(tip, create_coinbase(height))
        initialize_tensor_block_fields(b0)
        from test_framework.blocktools import set_block_tick_from_prev
        set_block_tick_from_prev(n0, b0)
        b0.flags = 0x00
        b0.hashMerkleRoot = b0.calc_merkle_root()
        b0.solve()

        # Disconnect nodes before submitting to prevent automatic propagation
        self.disconnect_nodes(0, 1)

        # Submit the block with flags=0x00 to node 0
        result0 = n0.submitblock(b0.serialize().hex())
        assert result0 is None, f"Block submission to n0 failed: {result0}"

        # Create identical block but with different flags for node 1
        # Copy all fields from b0 to ensure same hash
        import copy
        b1 = copy.deepcopy(b0)
        b1.flags = 0x80  # Different flags but should still be accepted

        # Submit the block with flags=0x80 to node 1
        result1 = n1.submitblock(b1.serialize().hex())
        # Both blocks should be accepted since they have the same hash (flags excluded)
        assert result1 is None, f"Block with flags=0x80 failed: {result1}"

        # Reconnect nodes
        self.connect_nodes(0, 1)

        # After sync, both nodes must be at the same best hash
        self.sync_blocks([n0, n1])
        assert_equal(n0.getbestblockhash(), n1.getbestblockhash())


if __name__ == '__main__':
    HeaderFlagsTwoNodesTest(__file__).main()

