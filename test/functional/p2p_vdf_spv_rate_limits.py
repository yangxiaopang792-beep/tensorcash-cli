#!/usr/bin/env python3
"""Exercise HEADERS_EXT rate limit enforcement and request throttling."""

import os
import threading

from test_framework.messages import msg_headers
from test_framework.p2p import P2P_SERVICES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_greater_than
from test_framework.vdf_messages import NODE_VDFSPV, VdfExtSidecar, msg_headers_ext

from test_framework.vdf_spv_test_util import (
    VdfSyncPeer,
    build_blocks,
    headers_message,
    make_sidecar,
)


class P2PVdfSpvRateLimits(BitcoinTestFramework):
    def setup_chain(self):
        # Set up timeout before chain setup which might hang
        self.setup_test_timeout(240)  # Longer timeout for this test (block building with VDF)
        super().setup_chain()

    def set_test_params(self):
        base_args = get_tensorcash_test_params(
            disable_asn_corroboration=True,
            disable_hysteresis=True,
            disable_reorg_sampling=True,
            disable_extapi=True,
        )
        base_args.extend([
            "-minimumchainwork=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "-peermanmaxheadersresult=2000",
        ])
        # Add whitelist back for rate limit testing (we'll test without it separately)
        base_args.append("-whitelist=noban@127.0.0.1")
        self.num_nodes = 1
        self.extra_args = [base_args]
        self.setup_clean_chain = True
        self.rpc_timeout = 240

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

    def send_headers_in_batches(self, peer: VdfSyncPeer, blocks) -> None:
        batch = []
        for block in blocks:
            batch.append(block)
            if len(batch) == 2000:
                msg = msg_headers()
                msg.headers = headers_message(batch)
                peer.send_message(msg, sync=False)
                batch.clear()
        if batch:
            msg = msg_headers()
            msg.headers = headers_message(batch)
            peer.send_message(msg, sync=False)
        peer.sync_with_ping()

    def setup_test_timeout(self, timeout_seconds=120):
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
        try:
            self._run_test_impl()
        finally:
            self.cancel_timeout()

    def _run_test_impl(self):
        self.log.info("Starting rate limits test")
        node = self.nodes[0]
        self.log.info("Got node reference, generating blocks...")
        self.generate(node, 5)
        self.log.info("Generated 5 blocks successfully")

        # --- Scenario 1: peer exceeds inbound HEADERS_EXT limit ---
        spammer = self.connect_peer("spam", auto_sidecars=False)
        payload = msg_headers_ext()
        sidecars = []
        for i in range(2050):
            sc = VdfExtSidecar()
            sc.header_hash = (i.to_bytes(4, "little") + b"\x00" * 28)
            sc.prev_hash = b"\x00" * 32
            sc.tick = 1
            sidecars.append(sc)
        payload.sidecars = sidecars

        with node.assert_debug_log(expected_msgs=["headers_ext-rate-limit"]):
            spammer.send_message(payload, sync=False)
            spammer.sync_with_ping()

        if spammer.is_connected:
            spammer.peer_disconnect()
            spammer.wait_for_disconnect()

        # --- Scenario 2: node throttles its own HEADERS_EXT queries ---
        primary = self.connect_peer("primary")
        secondary = self.connect_peer("secondary")

        base_tip = node.getbestblockhash()
        self.log.info(f"Building 2300 blocks from tip {base_tip[:16]}...")
        chain = build_blocks(node, base_tip, 2300, tick=900)
        self.log.info("Built 2300 blocks")

        for block in chain.blocks:
            primary.track_block(block)
            secondary.track_block(block)

        primary.queue_sidecars(make_sidecar(block) for block in chain.blocks)
        secondary.queue_sidecars(make_sidecar(block) for block in chain.blocks)

        self.send_headers_in_batches(primary, chain.blocks)

        # Messages are processed synchronously with lock fix

        primary.wait_for_getheadext(1)

        def total_queries(peer: VdfSyncPeer) -> int:
            return sum(len(req.queries) for req in peer.getheadext_requests)

        try:
            self.wait_until(lambda: total_queries(primary) > 0, timeout=10)
        except AssertionError as e:
            self.log.error(f"Primary peer received no getheadext queries: {e}")
            raise

        try:
            self.wait_until(lambda: total_queries(primary) >= 1000, timeout=30)
        except AssertionError as e:
            self.log.error(f"Primary peer didn't reach 1000 queries, got {total_queries(primary)}: {e}")
            raise
        assert total_queries(primary) <= 1900

        self.send_headers_in_batches(secondary, chain.blocks)

        # Messages are processed synchronously with lock fix

        try:
            self.wait_until(lambda: total_queries(secondary) > 0, timeout=10)
        except AssertionError as e:
            self.log.error(f"Secondary peer received no getheadext queries: {e}")
            raise

        assert primary.is_connected
        assert secondary.is_connected
        assert_greater_than(total_queries(primary) + total_queries(secondary), 2000)

        primary.peer_disconnect()
        secondary.peer_disconnect()


if __name__ == "__main__":
    P2PVdfSpvRateLimits(__file__).main()
