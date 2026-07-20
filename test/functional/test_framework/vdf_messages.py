#!/usr/bin/env python3
# Copyright (c) 2024 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VDF SPV message serialization for functional tests."""

import struct
from test_framework.messages import (
    ser_compact_size,
    deser_compact_size,
    ser_uint256,
    deser_uint256,
    ser_string,
    deser_string,
)
from test_framework.p2p import P2PInterface
from io import BytesIO

# Service flag for VDF SPV support
NODE_VDFSPV = (1 << 24)

class VdfExtSidecar:
    """VDF Extended sidecar structure matching C++ implementation."""

    def __init__(self):
        self.header_hash = b'\x00' * 32
        self.prev_hash = b'\x00' * 32
        self.tick = 0
        self.vdf = b''
        self.merkle_branch_tick = []
        self.merkle_branch_vdf = []
        self.leaf_scheme_version = 1
        self.n_leaves = 4

    def serialize(self):
        """Serialize to match C++ VdfExtSidecar."""
        r = b""
        # header_hash (uint256)
        r += self.header_hash
        # prev_hash (uint256)
        r += self.prev_hash
        # tick (uint64)
        r += struct.pack("<Q", self.tick)
        # vdf (vector<uint8_t>)
        r += ser_string(self.vdf)
        # merkle_branch_tick (vector<uint256>)
        r += ser_compact_size(len(self.merkle_branch_tick))
        for branch in self.merkle_branch_tick:
            r += branch
        # merkle_branch_vdf (vector<uint256>)
        r += ser_compact_size(len(self.merkle_branch_vdf))
        for branch in self.merkle_branch_vdf:
            r += branch
        # leaf_scheme_version (uint8)
        r += struct.pack("B", self.leaf_scheme_version)
        # n_leaves (uint32)
        r += struct.pack("<I", self.n_leaves)
        return r

    def deserialize(self, f):
        """Deserialize from bytes matching C++ format."""
        # header_hash
        self.header_hash = f.read(32)
        # prev_hash
        self.prev_hash = f.read(32)
        # tick
        self.tick = struct.unpack("<Q", f.read(8))[0]
        # vdf
        self.vdf = deser_string(f)
        # merkle_branch_tick
        n_tick = deser_compact_size(f)
        self.merkle_branch_tick = []
        for _ in range(n_tick):
            self.merkle_branch_tick.append(f.read(32))
        # merkle_branch_vdf
        n_vdf = deser_compact_size(f)
        self.merkle_branch_vdf = []
        for _ in range(n_vdf):
            self.merkle_branch_vdf.append(f.read(32))
        # leaf_scheme_version
        self.leaf_scheme_version = struct.unpack("B", f.read(1))[0]
        # n_leaves
        self.n_leaves = struct.unpack("<I", f.read(4))[0]

from test_framework.p2p import MESSAGEMAP


class msg_getheadext:
    """GETHEADERS_EXT message (wire name: getheadext)."""
    msgtype = b"getheadext"

    def __init__(self):
        # List of (header_hash, prev_hash) uint256 pairs
        self.queries = []

    def serialize(self):
        r = ser_compact_size(len(self.queries))
        for header_hash, prev_hash in self.queries:
            r += ser_uint256(header_hash)
            r += ser_uint256(prev_hash)
        return r

    def deserialize(self, f):
        n = deser_compact_size(f)
        self.queries = []
        for _ in range(n):
            header_hash = deser_uint256(f)
            prev_hash = deser_uint256(f)
            self.queries.append((header_hash, prev_hash))

    def __repr__(self):
        return f"msg_getheadext(queries={len(self.queries)})"

class msg_headers_ext:
    """HEADERS_EXT message with proper serialization."""
    msgtype = b"headers_ext"

    def __init__(self):
        self.sidecars = []

    def serialize(self):
        """Serialize matching C++ vector<VdfExtSidecar>."""
        r = b""
        # Vector size as CompactSize
        r += ser_compact_size(len(self.sidecars))
        # Each sidecar
        for sc in self.sidecars:
            if isinstance(sc, VdfExtSidecar):
                r += sc.serialize()
            else:
                # Handle dict format for convenience
                sidecar = VdfExtSidecar()
                sidecar.header_hash = sc.get('header_hash', b'\x00' * 32)
                sidecar.prev_hash = sc.get('prev_hash', b'\x00' * 32)
                sidecar.tick = sc.get('tick', 0)
                sidecar.vdf = sc.get('vdf', b'')
                sidecar.merkle_branch_tick = sc.get('merkle_branch_tick', [])
                sidecar.merkle_branch_vdf = sc.get('merkle_branch_vdf', [])
                sidecar.leaf_scheme_version = sc.get('leaf_scheme_version', 1)
                sidecar.n_leaves = sc.get('n_leaves', 4)
                r += sidecar.serialize()
        return r

    def deserialize(self, f):
        """Deserialize from bytes."""
        n = deser_compact_size(f)
        self.sidecars = []
        for _ in range(n):
            sc = VdfExtSidecar()
            sc.deserialize(f)
            self.sidecars.append(sc)

    def __repr__(self):
        return f"msg_headers_ext({len(self.sidecars)} sidecars)"

class VdfSpvNode(P2PInterface):
    """P2P node that supports VDF SPV protocol."""

    def __init__(self):
        super().__init__()
        self.headers_ext_received = []
        # Maintain both new and legacy attribute names for convenience
        self.getheadext_received = []
        self.getheaders_ext_received = []

    def on_getheadext(self, message):
        """Handle incoming GETHEADERS_EXT (wire: getheadext)."""
        self.getheadext_received.append(message)
        # Back-compat alias
        self.getheaders_ext_received.append(message)

    # Back-compat handler name, in case a peer still uses old wire name
    def on_getheaders_ext(self, message):
        self.on_getheadext(message)

    def on_headers_ext(self, message):
        """Handle incoming HEADERS_EXT."""
        self.headers_ext_received.append(message)

    def send_getheaders_ext(self, queries):
        """Send GETHEADERS_EXT message (wire: getheadext)."""
        msg = msg_getheadext()
        msg.queries = queries
        self.send_message(msg)

    def send_headers_ext(self, sidecars):
        """Send HEADERS_EXT message."""
        msg = msg_headers_ext()
        msg.sidecars = sidecars
        self.send_message(msg)

    def send_message(self, message, *, sync=True, timeout=60):
        """Send a message to the node, optionally waiting for a ping roundtrip."""
        if sync:
            self.send_and_ping(message, timeout=timeout)
        else:
            self.send_without_ping(message)

# Register custom messages so inbound messages are parsed
MESSAGEMAP[b"headers_ext"] = msg_headers_ext
MESSAGEMAP[b"getheadext"] = msg_getheadext

# Back-compat alias for code that might import the old class name
msg_getheaders_ext = msg_getheadext
