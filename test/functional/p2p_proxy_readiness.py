#!/usr/bin/env python3
# Copyright (c) 2025 The TensorCash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test proxy-readiness gating in ThreadDNSAddressSeed.

Covers:
  1. I2P-only proxy does NOT trigger the seed-fetch proxy gate (regression test
     for the IsSeedFetchProxyConfigured fix).
  2. Delayed SOCKS proxy: ThreadDNSAddressSeed waits for the proxy to become
     reachable before trying seed nodes.
  3. Unreachable proxy with empty addrman: early HTTP seed bootstrap path is
     entered.
"""

import socket
import threading

from test_framework.test_framework import BitcoinTestFramework


# A minimal TCP listener that accepts and immediately closes connections,
# used to simulate a SOCKS proxy becoming reachable after a delay.
class DelayedListener:
    """Start listening on *port* after *delay* seconds."""
    def __init__(self, port, delay):
        self.port = port
        self.delay = delay
        self._sock = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        # Wait before binding
        if not self._stop.wait(self.delay):
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(1.0)
            self._sock.bind(('127.0.0.1', self.port))
            self._sock.listen(5)
            while not self._stop.is_set():
                try:
                    conn, _ = self._sock.accept()
                    conn.close()
                except socket.timeout:
                    continue

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        if self._sock:
            self._sock.close()


class P2PProxyReadiness(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.disable_autoconnect = False

    def test_i2p_only_no_proxy_gate(self):
        """An -i2psam-only node must NOT wait for proxy readiness.

        The seed-fetch proxy gate should only activate for proxies that
        seed fetches route through (NET_ONION, NET_IPV4, name proxy).
        With only -i2psam set, the proxy-readiness wait in
        ThreadDNSAddressSeed should not be entered.
        """
        self.log.info("I2P-only: proxy readiness wait is not entered")
        seed_node = "25.0.0.1"
        # -i2psam points at a non-listening port — it should NOT cause the
        # proxy-readiness gate to activate for seednode connections.
        with self.nodes[0].assert_debug_log(
            expected_msgs=[f"Empty addrman, adding seednode ({seed_node}) to addrfetch"],
            unexpected_msgs=["Waiting up to", "Proxy not reachable"],
            timeout=15,
        ):
            self.restart_node(0, extra_args=[
                f"-seednode={seed_node}",
                "-i2psam=127.0.0.1:60000",
                "-dnsseed=1",
            ])

    def test_delayed_proxy_defers_seedwait(self):
        """When -proxy is set but the proxy is not yet listening,
        ThreadDNSAddressSeed should wait for it to become reachable
        before giving seed nodes time to connect.
        """
        self.log.info("Delayed proxy: DNS seed thread waits for proxy readiness")

        # Pick a port that is initially not listening.
        proxy_port = 19150
        seed_node = "faketestnode.onion"

        # Start a delayed listener that starts accepting after 5 seconds.
        listener = DelayedListener(proxy_port, delay=5)
        listener.start()

        try:
            # The node should:
            # 1. Log that it's waiting for the proxy
            # 2. Eventually detect the proxy once the listener starts
            with self.nodes[0].assert_debug_log(
                expected_msgs=[
                    "Waiting up to",
                    "Proxy is reachable after",
                ],
                timeout=25,
            ):
                self.restart_node(0, extra_args=[
                    f"-seednode={seed_node}",
                    f"-proxy=127.0.0.1:{proxy_port}",
                    "-dnsseed=1",
                ])
        finally:
            listener.stop()

    def test_proxy_unreachable_early_bootstrap(self):
        """When the proxy never becomes reachable and addrman is empty,
        ThreadDNSAddressSeed should enter the early HTTP seed bootstrap
        path (even though regtest has no HTTP seed URLs configured, the
        log message is emitted before the URL check).
        """
        self.log.info("Unreachable proxy: early bootstrap path entered")

        # Use a port where nothing will ever listen.
        dead_proxy_port = 19151
        seed_node = "faketestnode.onion"

        with self.nodes[0].assert_debug_log(
            expected_msgs=[
                "Proxy not reachable and addrman empty",
            ],
            timeout=30,
        ):
            self.restart_node(0, extra_args=[
                f"-seednode={seed_node}",
                f"-proxy=127.0.0.1:{dead_proxy_port}",
                "-dnsseed=1",
            ])

    def run_test(self):
        self.test_i2p_only_no_proxy_gate()
        self.test_delayed_proxy_defers_seedwait()
        self.test_proxy_unreachable_early_bootstrap()


if __name__ == '__main__':
    P2PProxyReadiness(__file__).main()
