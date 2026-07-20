#!/usr/bin/env python3
"""Regression test for GETHEADERS_EXT liveness (m_peer_ext_inflight).

Covers the four parts of the deadlock fix:
  0b  partial HEADERS_EXT reply -> requeue only the missing hashes (answered cleared);
  0b  empty  HEADERS_EXT reply  -> requeue the whole batch;
  0d  unanswerable query        -> node still emits an (empty) HEADERS_EXT so the
                                   requester can fail over immediately;
  0c  no reply at all           -> after EXT_REQUEST_TIMEOUT_SEC the in-flight batch
                                   is requeued and re-sent (timeout safety net).
"""

from test_framework.messages import msg_headers
from test_framework.p2p import P2P_SERVICES, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_tensorcash import get_tensorcash_test_params
from test_framework.util import assert_equal
from test_framework.vdf_messages import NODE_VDFSPV, msg_headers_ext
from test_framework.vdf_spv_test_util import (
    VdfSyncPeer,
    build_blocks,
    headers_message,
    make_sidecar,
)

# Mirror of the C++ constant in net_processing.cpp (EXT_REQUEST_TIMEOUT_SEC).
EXT_REQUEST_TIMEOUT_SEC = 30


class P2PVdfSpvExtLiveness(BitcoinTestFramework):
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
            "-whitelist=noban@127.0.0.1",
        ])
        self.num_nodes = 1
        self.extra_args = [base_args]
        self.setup_clean_chain = True
        self.rpc_timeout = 240

    def connect_vdf_peer(self, label):
        peer = VdfSyncPeer(label, auto_sidecars=False)
        self.nodes[0].add_p2p_connection(peer, services=P2P_SERVICES | NODE_VDFSPV)
        peer.wait_for_verack()
        peer.sync_with_ping()
        return peer

    def send_headers(self, peer, blocks):
        msg = msg_headers()
        msg.headers = headers_message(blocks)
        peer.send_message(msg, sync=False)
        peer.sync_with_ping()

    @staticmethod
    def getheadext_count(peer):
        with p2p_lock:
            return len(peer.getheadext_requests)

    @staticmethod
    def headers_ext_count(peer):
        with p2p_lock:
            return len(peer.headers_ext_received)

    @staticmethod
    def requested_hashes_since(peer, start_index):
        with p2p_lock:
            return {
                header_hash
                for request in peer.getheadext_requests[start_index:]
                for header_hash, _prev_hash in request.queries
            }

    def test_partial_reply_requeues_missing_hash(self):
        node = self.nodes[0]
        peer = self.connect_vdf_peer("partial-reply")
        chain = build_blocks(node, node.getbestblockhash(), 2, tick=900)

        self.send_headers(peer, chain.blocks)
        peer.wait_for_getheadext(1)
        first_count = self.getheadext_count(peer)
        first_queries = self.requested_hashes_since(peer, 0)
        expected_hashes = {int(block.sha256) for block in chain.blocks}
        assert_equal(expected_hashes.issubset(first_queries), True)

        partial = msg_headers_ext()
        partial.sidecars = [make_sidecar(chain.blocks[0])]
        peer.send_message(partial, sync=False)
        peer.sync_with_ping()

        missing_hash = int(chain.blocks[1].sha256)
        answered_hash = int(chain.blocks[0].sha256)
        self.wait_until(lambda: self.getheadext_count(peer) >= first_count + 1, timeout=10)
        retried_hashes = self.requested_hashes_since(peer, first_count)
        assert_equal(missing_hash in retried_hashes, True)
        assert_equal(answered_hash in retried_hashes, False)

        peer.peer_disconnect()

    def test_empty_reply_requeues_batch(self):
        node = self.nodes[0]
        peer = self.connect_vdf_peer("empty-reply")
        chain = build_blocks(node, node.getbestblockhash(), 1, tick=900)

        self.send_headers(peer, chain.blocks)
        peer.wait_for_getheadext(1)
        first_count = self.getheadext_count(peer)

        empty = msg_headers_ext()
        empty.sidecars = []
        peer.send_message(empty, sync=False)
        peer.sync_with_ping()

        expected_hash = int(chain.blocks[0].sha256)
        self.wait_until(lambda: self.getheadext_count(peer) >= first_count + 1, timeout=10)
        retried_hashes = self.requested_hashes_since(peer, first_count)
        assert_equal(expected_hash in retried_hashes, True)

        peer.peer_disconnect()

    def test_responder_answers_unanswerable_query(self):
        # 0d: a GETHEADERS_EXT for a header the node cannot serve must still get an
        # (empty) HEADERS_EXT reply, so the requester fails over instead of hanging.
        node = self.nodes[0]
        peer = self.connect_vdf_peer("empty-response")

        unknown_hash = int.from_bytes(b"\xde\xad\xbe\xef" * 8, "big")
        baseline = self.headers_ext_count(peer)
        peer.send_getheaders_ext([(unknown_hash, 0)])
        self.wait_until(lambda: self.headers_ext_count(peer) > baseline, timeout=10)

        with p2p_lock:
            reply = peer.headers_ext_received[-1]
        assert_equal(len(reply.sidecars), 0)

        peer.peer_disconnect()

    def test_no_reply_requeues_after_timeout(self):
        # 0c: if the peer never replies, the in-flight batch must be requeued and
        # re-sent once EXT_REQUEST_TIMEOUT_SEC has elapsed (timeout safety net).
        node = self.nodes[0]
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        base_mock = tip_time + 120
        node.setmocktime(base_mock)

        peer = self.connect_vdf_peer("timeout-no-reply")  # auto_sidecars=False -> never replies
        chain = build_blocks(node, node.getbestblockhash(), 1, tick=900)

        self.send_headers(peer, chain.blocks)
        peer.wait_for_getheadext(1)
        first_count = self.getheadext_count(peer)
        expected_hash = int(chain.blocks[0].sha256)

        # No reply. Advance past the in-flight timeout and let the node's periodic
        # send loop expire + requeue the outstanding hash.
        node.setmocktime(base_mock + EXT_REQUEST_TIMEOUT_SEC + 1)
        peer.sync_with_ping()
        self.wait_until(lambda: self.getheadext_count(peer) >= first_count + 1, timeout=15)
        retried_hashes = self.requested_hashes_since(peer, first_count)
        assert_equal(expected_hash in retried_hashes, True)

        node.setmocktime(0)
        peer.peer_disconnect()

    def run_test(self):
        self.generate(self.nodes[0], 2)
        self.test_partial_reply_requeues_missing_hash()
        self.test_empty_reply_requeues_batch()
        self.test_responder_answers_unanswerable_query()
        self.test_no_reply_requeues_after_timeout()


if __name__ == "__main__":
    P2PVdfSpvExtLiveness(__file__).main()
