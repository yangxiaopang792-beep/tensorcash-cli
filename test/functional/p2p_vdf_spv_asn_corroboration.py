#!/usr/bin/env python3
"""Require multiple ASNs before fetching toward a candidate VDF SPV tip.

IMPORTANT FINDINGS:
1. ASN mapping doesn't work for loopback addresses (127.0.0.x)
   - They are classified as NET_UNROUTABLE, not NET_IPV4
   - GetMappedAS() only works for NET_IPV4 and NET_IPV6
   - This is a test limitation, NOT a production bug

2. Despite this limitation, we can still test ASN corroboration:
   - All test peers get ASN=0 (unmapped)
   - With -spv-asn-min=2, the node should require 2 distinct ASNs
   - Having only ASN=0 (1 unique ASN) should prevent fetch

3. ACTUAL BUG FOUND:
   - The node fetches blocks even with insufficient ASN diversity
   - ASN corroboration security feature is not working
"""

import ipaddress
import os
import sys
import signal
import threading

# Handle ASMap import - try test_framework first, then fall back to contrib
try:
    from test_framework.asmap import ASMap, net_to_prefix
except ImportError:
    # In docker, the path might be different
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'contrib', 'asmap'))
    try:
        from asmap import ASMap, net_to_prefix
    except ImportError:
        # Try /build path for docker environment
        sys.path.insert(0, '/build/bcore/contrib/asmap')
        from asmap import ASMap, net_to_prefix

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


class P2PVdfSpvAsnCorroboration(BitcoinTestFramework):
    def setup_chain(self):
        # Set up timeout before chain setup which might hang
        self.setup_test_timeout(60)
        super().setup_chain()

    def set_test_params(self):
        base_args = get_tensorcash_test_params(
            disable_asn_corroboration=False,  # ENABLE ASN corroboration for testing
            disable_hysteresis=True,
            disable_reorg_sampling=True,
            disable_extapi=True,
        )
        base_args.extend([
            "-spv-asn-corroboration=1",
            "-spv-asn-min=2",  # Require 2 distinct ASNs
            "-minimumchainwork=0x1",  # Low to ensure we can sync
            "-peermanmaxheadersresult=10",
        ])
        self.num_nodes = 1
        self.extra_args = [base_args]
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def connect_peer(self, label: str, addr: str = None) -> VdfSyncPeer:
        self.log.info(f"Creating peer '{label}' with simulated address {addr if addr else 'default'}")
        peer = VdfSyncPeer(label, respond_to_getdata=False, auto_sidecars=True)
        self.log.info(f"Adding P2P connection for peer '{label}'")
        # Note: For testing, we connect normally but the node will see different ASNs based on asmap
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
        self.log.info("Starting ASN corroboration test")
        node = self.nodes[0]

        # NOTE: ASN mapping doesn't work with loopback addresses (127.0.0.x)
        # They are classified as NET_UNROUTABLE, not NET_IPV4
        # This is a test limitation, not a production bug

        # For this test, we'll verify the ASN corroboration logic still works
        # even when all peers have ASN=0 (unmapped)
        # With -spv-asn-min=2, having only ASN=0 should still prevent fetch

        self.log.info("Testing ASN corroboration with unmapped addresses (ASN=0)")
        self.log.info("All peers will have ASN=0, which should still trigger protection")

        # Verify node configuration
        netinfo = node.getnetworkinfo()
        self.log.info(f"Network info - localaddresses: {netinfo.get('localaddresses', [])}")

        # Check ASN settings via getblockchaininfo or other RPCs
        blockchain_info = node.getblockchaininfo()
        self.log.info(f"Blockchain state: height={blockchain_info.get('blocks')}, chain={blockchain_info.get('chain')}")

        # Generate initial blocks
        self.generate(node, 6)
        initial_height = node.getblockcount()
        self.log.info(f"Generated {initial_height} initial blocks")

        # Create a DEEP reorg scenario - fork from 5 blocks back to trigger ASN check (D > 3)
        fork_point = node.getblockhash(initial_height - 5)
        self.log.info(f"Forking from height {initial_height - 5}")

        # Build a better fork (7 blocks vs 5, higher tick) to create reorg depth D = 5 > 3
        branch = build_blocks(node, fork_point, 7, tick=1000)
        self.log.info("Built 7-block fork with tick=1000 each (deep reorg D=5 > 3)")

        # Phase 1: Test with insufficient ASNs (should NOT fetch blocks)
        self.log.info("=== PHASE 1: Testing insufficient ASN diversity ===")

        # Connect 2 peers from same ASN (default 127.0.0.1)
        peer1 = self.connect_peer("peer-same-asn-1")
        peer2 = self.connect_peer("peer-same-asn-2")

        # Set up blocks for both peers
        for peer in [peer1, peer2]:
            for block in branch.blocks:
                peer.track_block(block)
            peer.queue_sidecars(make_sidecar(block) for block in branch.blocks)

        # Send headers from first peer
        headers_msg = msg_headers()
        headers_msg.headers = headers_message(branch.blocks)
        self.log.info("Sending headers from peer 1 (same ASN)")
        self.log.info(f"Headers being sent: {len(headers_msg.headers)} headers")
        # Don't try to log header hashes - CBlockHeader doesn't have GetHash method

        peer1.send_message(headers_msg)

        # Wait and check for requests
        import time
        time.sleep(1)

        # Check peer status after first peer
        peerinfo1 = node.getpeerinfo()
        self.log.info("=== After peer 1 headers ===")
        for i, peer in enumerate(peerinfo1):
            self.log.info(f"Peer {i}: addr={peer.get('addr')}, mapped_as={peer.get('mapped_as', 'N/A')}, synced_headers={peer.get('synced_headers')}")

        # Check if peer1 got any requests
        self.log.info(f"Peer 1 getdata requests so far: {len(peer1.getdata_requests)}")
        self.log.info(f"Peer 1 getheadext requests so far: {len(peer1.getheadext_requests)}")

        # Send from second peer (same ASN)
        self.log.info("Sending headers from peer 2 (same ASN)")
        peer2.send_message(headers_msg)
        time.sleep(2)

        # Check peer status after second peer
        peerinfo2 = node.getpeerinfo()
        self.log.info("=== After peer 2 headers ===")
        for i, peer in enumerate(peerinfo2):
            self.log.info(f"Peer {i}: addr={peer.get('addr')}, mapped_as={peer.get('mapped_as', 'N/A')}, synced_headers={peer.get('synced_headers')}")

        # Check if any blocks were requested (should be 0 with ASN corroboration)
        total_requests = len(peer1.getdata_requests) + len(peer2.getdata_requests)
        self.log.info(f"Total getdata requests from same-ASN peers: {total_requests}")
        self.log.info(f"  Peer 1: {len(peer1.getdata_requests)} requests")
        self.log.info(f"  Peer 2: {len(peer2.getdata_requests)} requests")

        # Get detailed peer info to check ASN assignment
        peerinfo = node.getpeerinfo()
        self.log.info("=== Final peer state ===")
        for i, peer in enumerate(peerinfo):
            self.log.info(f"Peer {i} details:")
            self.log.info(f"  addr: {peer.get('addr')}")
            self.log.info(f"  mapped_as: {peer.get('mapped_as', 'N/A')}")
            self.log.info(f"  connection_type: {peer.get('connection_type')}")
            self.log.info(f"  services: {peer.get('services')}")
            self.log.info(f"  servicesnames: {peer.get('servicesnames')}")
            self.log.info(f"  synced_headers: {peer.get('synced_headers')}")
            self.log.info(f"  synced_blocks: {peer.get('synced_blocks')}")

        # Check the node's debug.log for ASN corroboration messages
        if total_requests == 0:
            self.log.info("SUCCESS: ASN corroboration prevented fetch from insufficient ASN diversity")
        else:
            self.log.error(f"FAILURE: Expected 0 requests, got {total_requests}")

            # Analyze the issue
            self.log.error("=== ASN CORROBORATION ANALYSIS ===")

            # Check if all peers have the same mapped_as
            mapped_asns = set()
            for peer in peerinfo:
                mapped_as = peer.get('mapped_as', 0)
                mapped_asns.add(mapped_as)

            self.log.error(f"Unique ASNs seen: {mapped_asns}")
            self.log.error(f"Number of unique ASNs: {len(mapped_asns)}")

            if mapped_asns == {0}:
                self.log.error("DIAGNOSIS: All peers have ASN=0 (unmapped)")
                self.log.error("This is EXPECTED for loopback addresses (127.0.0.x)")
                self.log.error("Loopback addresses are NET_UNROUTABLE, ASN maps don't apply")
                self.log.error("")
                self.log.error("REAL BUG: Even with all peers at ASN=0 (only 1 unique ASN),")
                self.log.error("the node fetched blocks for deep reorg (D=5 > 3) when -spv-asn-min=2 requires 2 distinct ASNs")
                self.log.error("ASN corroboration check is NOT working correctly!")
            elif len(mapped_asns) == 1:
                self.log.error("DIAGNOSIS: All peers mapped to same non-zero ASN")
                self.log.error("BUG: ASN corroboration should have prevented fetch")
            else:
                self.log.error("DIAGNOSIS: Multiple different ASNs found")
                self.log.error(f"Unique ASNs: {mapped_asns}")
                self.log.error("Unexpected - test peers should all have same ASN")

            # Check which peer got the request
            if len(peer1.getdata_requests) > 0:
                self.log.error(f"Peer 1 received {len(peer1.getdata_requests)} getdata requests")
            if len(peer2.getdata_requests) > 0:
                self.log.error(f"Peer 2 received {len(peer2.getdata_requests)} getdata requests")

            self.log.error("=== END ANALYSIS ===")
            raise AssertionError(f"ASN corroboration failed: got {total_requests} requests with {len(mapped_asns)} unique ASNs")

        # Verify chain hasn't changed
        assert_equal(node.getbestblockhash(), node.getblockhash(initial_height))

        # Clean up
        peer1.peer_disconnect()
        peer2.peer_disconnect()

        self.log.info("=== ASN corroboration test completed successfully ===")
        self.log.info("NOTE: This test verifies ASN corroboration prevents single-ASN attacks")


if __name__ == "__main__":
    P2PVdfSpvAsnCorroboration(__file__).main()
