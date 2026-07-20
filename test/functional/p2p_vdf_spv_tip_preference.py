#!/usr/bin/env python3
"""Exercise the SPV hysteresis gate before fetching blocks for a reorg."""

import os
import threading
import time

from test_framework.messages import msg_headers
from test_framework.p2p import P2P_SERVICES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal
from test_framework.vdf_messages import NODE_VDFSPV

from test_framework.vdf_spv_test_util import (
    VdfSyncPeer,
    build_blocks,
    headers_message,
    make_sidecar,
)


class P2PVdfSpvTipPreference(BitcoinTestFramework):
    def setup_chain(self):
        # Set up timeout before chain setup which might hang
        self.setup_test_timeout(60)
        super().setup_chain()

    def set_test_params(self):
        base_args = get_tensorcash_test_params(
            disable_asn_corroboration=True,
            disable_hysteresis=False,
            disable_reorg_sampling=True,
            disable_extapi=True,
            additional_args=[
                "-spv-hysteresis-alpha-bps=0",
                "-spv-hysteresis-default-tick=100",
                "-minimumchainwork=0x1",
                "-peermanmaxheadersresult=10",
            ],
        )
        self.num_nodes = 1
        self.extra_args = [base_args]
        self.setup_clean_chain = True
        self.rpc_timeout = 120
        self.disable_autoconnect = False

    def connect_peer(self, label: str, *, respond_to_getdata=False, auto_sidecars=True) -> VdfSyncPeer:
        self.log.info(f"Creating peer '{label}'")
        peer = VdfSyncPeer(label, respond_to_getdata=respond_to_getdata, auto_sidecars=auto_sidecars)
        self.log.info(f"Adding P2P connection for peer '{label}'")
        self.nodes[0].add_p2p_connection(peer, services=P2P_SERVICES | NODE_VDFSPV)
        self.log.info(f"Waiting for verack from peer '{label}'")
        peer.wait_for_verack()
        self.log.info(f"Syncing with ping for peer '{label}'")
        peer.sync_with_ping()
        self.log.info(f"Successfully connected peer '{label}'")
        return peer

    def setup_test_timeout(self, timeout_seconds=60):
        """Set up a timer to abort the test if it takes too long."""
        def timeout_handler():
            self.log.error(f"TEST TIMEOUT: Test exceeded {timeout_seconds} seconds")
            self.log.error("Forcibly terminating test to prevent hanging")
            os._exit(1)

        timer = threading.Timer(timeout_seconds, timeout_handler)
        timer.daemon = True
        timer.start()
        self._timeout_timer = timer
        self.log.info(f"Test timeout set to {timeout_seconds} seconds")

    def cancel_timeout(self):
        """Cancel the timeout timer if test completes successfully."""
        if hasattr(self, '_timeout_timer'):
            self._timeout_timer.cancel()

    def run_test(self):
        self.log.info("Entering run_test")

        try:
            self.log.info("About to call _run_test_impl")
            self._run_test_impl()
            self.log.info("Completed _run_test_impl successfully")
        except Exception as e:
            self.log.error(f"Exception in _run_test_impl: {e}")
            raise
        finally:
            self.cancel_timeout()
            self.log.info("Canceled timeout")

    def _run_test_impl(self):
        self.log.info("Starting test implementation")
        node = self.nodes[0]

        # Mine a short active chain with deterministic ticks so CanDirectFetch() succeeds
        genesis_hash = node.getblockhash(0)
        active_batch = build_blocks(node, genesis_hash, 6, tick=100)
        for block in active_batch.blocks:
            result = node.submitblock(block.serialize().hex())
            assert_equal(result, None)
        active_tip_hash = format(active_batch.blocks[-1].sha256, '064x')
        assert_equal(node.getbestblockhash(), active_tip_hash)
        active_height = node.getblockcount()

        # Build a competing fork from a deeper point to ensure larger reorg depth
        # Fork from block 2 (depth D=4) so hysteresis = D*E = 4*100 = 400
        lca_block = active_batch.blocks[1]  # Fork from block 2
        lca_hash = format(lca_block.sha256, '064x')
        lca_info = node.getblockheader(lca_hash)
        self.log.info(f"Active chain height {active_height}, LCA height {lca_info['height']}")

        # First stage: build fork that's not quite enough to overcome hysteresis
        # With alpha=0, base=0, so hysteresis = D*E = 4*100 = 400
        # Active chain cumulative tick = 610, LCA has 210, so fork needs > 610 + 400 = 1010 to trigger
        # Fork stage 1: 3 blocks with tick=100 gives cumulative 210+300=510 (not enough)
        fork_stage1 = build_blocks(node, lca_hash, 3, tick=100)
        # Fork stage 2: 3 more blocks with tick=180 gives cumulative 510+540=1050 (enough!)
        fork_stage2 = build_blocks(node, format(fork_stage1.blocks[-1].sha256, '064x'), 3, tick=180)
        fork_blocks = fork_stage1.blocks + fork_stage2.blocks

        fork_peer = self.connect_peer("fork", respond_to_getdata=False)
        for block in fork_blocks:
            fork_peer.track_block(block)
        fork_peer.queue_sidecars(make_sidecar(block) for block in fork_blocks)

        # Announce the first segment: cumulative tick short of the hysteresis margin
        first_msg = msg_headers()
        first_msg.headers = headers_message(fork_stage1.blocks)
        self.log.info(f"Sending {len(first_msg.headers)} headers for fork stage 1")
        fork_peer.send_message(first_msg)
        fork_peer.wait_for_getheadext(1, timeout=5)

        # Give the node time to process headers but verify no block fetch occurs
        time.sleep(2)

        # Log details before assertion for debugging
        self.log.info(f"Fork stage 1 cumulative tick: 510, active chain: 610, margin: 400, needed: >1010")
        self.log.info(f"Number of getdata requests: {len(fork_peer.getdata_requests)}")

        # The hysteresis gate should prevent fetching when margin is insufficient
        assert len(fork_peer.getdata_requests) == 0, f"Expected no fetch with insufficient hysteresis margin, got {len(fork_peer.getdata_requests)} requests"
        assert_equal(node.getbestblockhash(), active_tip_hash)
        self.log.info("No fetch issued with insufficient hysteresis margin")

        # Extend the fork so it clears the margin and should now trigger a block download
        second_msg = msg_headers()
        second_msg.headers = headers_message(fork_stage2.blocks)
        fork_peer.send_message(second_msg)
        fork_peer.wait_for_getheadext(2, timeout=5)

        fork_peer.wait_for_getdata(1, timeout=5)
        self.log.info("Fetch requested once hysteresis gate is satisfied")

        fork_peer.respond_to_getdata = True
        fork_peer.serve_tracked_getdata()

        target_tip = format(fork_blocks[-1].sha256, '064x')
        self.wait_until(lambda: node.getbestblockhash() == target_tip, timeout=10)
        final_height = node.getblockcount()
        assert_equal(final_height, lca_info['height'] + len(fork_blocks))
        self.log.info("Reorg completed after hysteresis-gated fetch")

        fork_peer.peer_disconnect()


if __name__ == "__main__":
    P2PVdfSpvTipPreference(__file__).main()
