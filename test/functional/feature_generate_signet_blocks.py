#!/usr/bin/env python3
"""Generate signet blocks for feature_signet.py test"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
import os

SIGNET_DEFAULT_CHALLENGE = '512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae'

class GenerateSignetBlocks(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Node 0: OP_TRUE for easy block generation
        # Node 1: Default challenge to test block compatibility
        self.extra_args = [
            ["-signetchallenge=51"],  # OP_TRUE
            [f"-signetchallenge={SIGNET_DEFAULT_CHALLENGE}"]  # Default
        ]

    def setup_network(self):
        self.setup_nodes()
        # Don't connect - they're on different signets

    def run_test(self):
        self.log.info("Generating 10 signet blocks with OP_TRUE challenge...")

        # Generate blocks on node 0 (OP_TRUE)
        blocks_to_generate = 10
        block_hashes = self.generate(self.nodes[0], blocks_to_generate, sync_fun=self.no_op)

        # Collect the raw blocks
        signet_blocks_optrue = []
        for block_hash in block_hashes:
            block_hex = self.nodes[0].getblock(block_hash, 0)  # 0 = hex format
            signet_blocks_optrue.append(f"    '{block_hex}',")

        # Write to file for persistence
        output_file = "/tmp/generated_signet_blocks.py"
        with open(output_file, "w") as f:
            f.write("# Generated signet blocks for feature_signet.py:\n")
            f.write("# These blocks use OP_TRUE (51) challenge\n")
            f.write("signet_blocks = [\n")
            for block in signet_blocks_optrue:
                f.write(block + "\n")
            f.write("]\n")

        # Also print to stdout
        print("\n" + "="*80)
        print("# Generated signet blocks for feature_signet.py:")
        print("# NOTE: These blocks use OP_TRUE (51) challenge")
        print("# Update feature_signet.py to use node[0] or node[1] (which use OP_TRUE)")
        print("# instead of node[2] for the pregenerated blocks test")
        print("="*80)
        print("signet_blocks = [")
        for block in signet_blocks_optrue:
            print(block)
        print("]")
        print("="*80)
        print(f"\nBlocks saved to: {output_file}")

        # Verify the blocks
        self.log.info(f"Successfully generated {len(block_hashes)} blocks with OP_TRUE challenge")
        assert_equal(self.nodes[0].getblockcount(), blocks_to_generate)

        # Test that blocks are rejected by incompatible challenge node
        if len(block_hashes) > 0:
            self.log.info("Testing that OP_TRUE blocks are rejected by default challenge node...")
            first_block = self.nodes[0].getblock(block_hashes[0], 0)
            result = self.nodes[1].submitblock(first_block)
            self.log.info(f"Block submission result on default challenge node: {result}")
            assert result == 'bad-signet-blksig' or result == 'prev-blk-not-found'

if __name__ == '__main__':
    GenerateSignetBlocks(__file__).main()