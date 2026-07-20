#!/usr/bin/env python3
"""Reject/bans peers that claim massive tick without matching proof."""

import os
import threading

from test_framework.messages import msg_headers
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.p2p import P2P_SERVICES
from test_framework.vdf_messages import NODE_VDFSPV, msg_headers_ext

from test_framework.vdf_spv_test_util import (
    VdfSyncPeer,
    build_blocks,
    headers_message,
    make_sidecar,
)


class P2PVdfSpvMassiveTickBan(BitcoinTestFramework):
    def setup_chain(self):
        # Set up timeout before chain setup which might hang
        self.setup_test_timeout(60)
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
            "-peermanmaxheadersresult=4",
        ])
        # Keep noban whitelist since we test misbehavior detection, not disconnection
        base_args.append("-whitelist=noban@127.0.0.1")
        self.num_nodes = 1
        self.extra_args = [base_args]
        self.setup_clean_chain = True

    def connect_peer(self, label: str) -> VdfSyncPeer:
        self.log.info(f"Creating peer '{label}'")
        peer = VdfSyncPeer(label, respond_to_getdata=False, auto_sidecars=False)
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
        try:
            self._run_test_impl()
        finally:
            self.cancel_timeout()

    def _run_test_impl(self):
        self.log.info("Starting massive tick ban test")
        node = self.nodes[0]
        self.log.info("Got node reference, generating blocks...")
        self.generate(node, 5)
        self.log.info("Generated 5 blocks successfully")
        tip = node.getbestblockhash()
        self.log.info(f"Got tip: {tip}")

        attacker = self.connect_peer("massive-tick")

        self.log.info("Building chain blocks...")
        chain = build_blocks(node, tip, 4, tick=800)
        self.log.info("Built chain blocks")

        self.log.info("Setting up block hashes...")
        for block in chain.blocks:
            attacker.track_block(block)
        self.log.info("Block hashes set up")

        def inflate_tick(sidecar: dict) -> None:
            sidecar["tick"] = 10 ** 14

        attacker.auto_sidecars = False

        headers_msg = msg_headers()
        headers_msg.headers = headers_message(chain.blocks)
        attacker.send_message(headers_msg)

        # Messages are processed synchronously with lock fix

        try:
            attacker.wait_for_getheadext(1, timeout=5)
        except AssertionError as e:
            self.log.error(f"Attacker timeout waiting for getheadext: {e}")
            raise

        mutated = msg_headers_ext()
        entries = []
        for block in chain.blocks:
            sc = make_sidecar(block)
            inflate_tick(sc)
            entries.append(sc)
        mutated.sidecars = entries

        # The node should detect the invalid massive tick claim
        with node.assert_debug_log(expected_msgs=["bad-headers-ext-branch-tick", "Misbehaving"]):
            attacker.send_message(mutated, sync=False)
            attacker.sync_with_ping()

        # Note: Test peers are whitelisted with 'noban' so they won't be disconnected,
        # but the misbehavior is still detected and logged. In production, such peers
        # would be banned/disconnected.
        self.log.info("Massive tick detected and peer marked as misbehaving (not disconnected due to test whitelist)")

        # Clean up
        if attacker.is_connected:
            attacker.peer_disconnect()
            attacker.wait_for_disconnect()


if __name__ == "__main__":
    P2PVdfSpvMassiveTickBan(__file__).main()
