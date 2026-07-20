"""Utilities for VDF SPV functional tests."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable, List, Optional, Callable

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
    set_block_tick_from_prev,
)
from test_framework.messages import (
    MSG_BLOCK,
    MSG_TYPE_MASK,
    CBlockHeader,
    msg_block,
)
from test_framework.p2p import (
    P2P_SERVICES,
    EncryptedP2PState,
    NetworkThread,
    logger,
    p2p_lock,
)
from test_framework.vdf_messages import (
    VdfSpvNode,
    msg_headers_ext,
)
from test_framework.vdf_helper import (
    cache_block_cumulative,
    create_headers_ext_sidecar,
    _lookup_parent_cumulative,
)


@dataclass
class BlockBatch:
    blocks: List
    description: str


class VdfSyncPeer(VdfSpvNode):
    """P2P peer that tracks protocol interactions and can serve queued sidecars."""

    def __init__(self, label: str, *, respond_to_getdata: bool = True, auto_sidecars: bool = True):
        super().__init__()
        self.label = label
        self.respond_to_getdata = respond_to_getdata
        self.auto_sidecars = auto_sidecars
        self.blocks_by_hash = {}
        self._queued_sidecars: "OrderedDict[int, dict]" = OrderedDict()
        self.getdata_requests: List = []
        self.getheadext_requests: List = []
        self.headext_sent = 0
        self.headers_received = 0
        self._sidecar_delay = 0.0
        self._listen_addr: Optional[str] = None
        self._listen_port: Optional[int] = None
        self._service_flags = P2P_SERVICES

    # --- Helpers ---------------------------------------------------------

    def reset(self):
        with p2p_lock:
            self.getdata_requests.clear()
            self.getheadext_requests.clear()
            self.headext_sent = 0

    def set_sidecar_delay(self, delay: float) -> None:
        self._sidecar_delay = delay

    def configure_listener(self, *, addr: Optional[str] = None, port: Optional[int] = None) -> None:
        self._listen_addr = addr
        self._listen_port = port

    def set_service_flags(self, services: int) -> None:
        self._service_flags = services

    # --- P2P callbacks ---------------------------------------------------

    def on_getheadext(self, message):
        super().on_getheadext(message)
        # Note: p2p_lock is already held by on_message when this is called
        self.getheadext_requests.append(message)
        if not self.auto_sidecars:
            return
        if self._sidecar_delay:
            time.sleep(self._sidecar_delay)
        replies = []
        for header_hash, _prev in getattr(message, "queries", []):
            entry = self._lookup_sidecar(header_hash)
            logger.debug("[%s] GETHEADERS_EXT query=%064x hit=%s", self.label, header_hash, entry is not None)
            if entry is not None:
                replies.append(entry)
        if replies:
            payload = msg_headers_ext()
            payload.sidecars = replies
            self.send_without_ping(payload)
            self.headext_sent += len(replies)
            logger.debug("[%s] sent %d sidecars", self.label, len(replies))
        else:
            logger.debug("[%s] no sidecars to send", self.label)

    def on_getheaders_ext(self, message):  # alias for legacy name
        self.on_getheadext(message)

    def on_getdata(self, message):
        if self.respond_to_getdata:
            replies = []
            for inv in getattr(message, "inv", []):
                if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                    blk = self._lookup_block(inv.hash)
                    logger.debug("[%s] GETDATA hash=%064x hit=%s", self.label, inv.hash, blk is not None)
                    if blk is not None:
                        replies.append(blk)
            for blk in replies:
                self.send_without_ping(msg_block(blk))
            if replies:
                logger.debug("[%s] sent %d blocks", self.label, len(replies))
        # Note: p2p_lock is already held by on_message when this is called
        self.getdata_requests.append(message)

    def peer_accept_connection(self, connect_id, connect_cb=lambda: None, *, net, timeout_factor, supports_v2_p2p, reconnect, services=P2P_SERVICES, **kwargs):
        self.peer_connect_helper('0', 0, net, timeout_factor)
        self.reconnect = reconnect
        if supports_v2_p2p:
            self.v2_state = EncryptedP2PState(initiating=False, net=net)

        addr = getattr(self, '_listen_addr', None)
        port = getattr(self, '_listen_port', None)
        self._listen_addr = None
        self._listen_port = None

        def start_listener():
            listen_kwargs = {'idx': connect_id}
            if addr is not None:
                listen_kwargs['addr'] = addr
            if port is not None:
                listen_kwargs['port'] = port
            return NetworkThread.listen(self, connect_cb, **listen_kwargs)

        effective_services = getattr(self, '_service_flags', services)
        self.peer_connect_send_version(effective_services)

        return start_listener

    # --- Public API ------------------------------------------------------


    def wait_for_getdata(self, min_count: int, timeout: float = 10.0) -> None:
        start = time.time()
        while True:
            with p2p_lock:
                count = len(self.getdata_requests)
            if count >= min_count:
                break
            if time.time() - start > timeout:
                raise AssertionError(f"Timeout waiting for {min_count} GETDATA (have {count})")
            time.sleep(0.05)

    def queue_sidecars(self, entries: Iterable[dict]) -> None:
        for entry in entries:
            hdr_bytes = entry.get("header_hash")
            if not isinstance(hdr_bytes, (bytes, bytearray)) or len(hdr_bytes) != 32:
                continue
            mapped = dict(entry)
            little_int = int.from_bytes(hdr_bytes, "little")
            big_int = int.from_bytes(hdr_bytes, "big")
            logger.debug("[%s] queue sidecar hash=%064x", self.label, little_int)
            self._queued_sidecars[hdr_bytes] = mapped
            self._queued_sidecars[little_int] = mapped
            self._queued_sidecars[big_int] = mapped

    def serve_tracked_getdata(self) -> None:
        """Reply to previously observed GETDATA requests by serving tracked blocks."""
        with p2p_lock:
            pending = list(self.getdata_requests)
            self.getdata_requests.clear()

        for message in pending:
            replies = []
            for inv in getattr(message, "inv", []):
                if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                    blk = self._lookup_block(inv.hash)
                    if blk is not None:
                        replies.append(blk)
                        logger.debug("[%s] serving deferred GETDATA hash=%064x", self.label, inv.hash)
            for blk in replies:
                self.send_without_ping(msg_block(blk))

    def send_headers_with_sidecars(self, blocks: Iterable, *, mutate: Optional[Callable[[dict], None]] = None) -> None:
        payload = msg_headers_ext()
        sidecars = []
        for block in blocks:
            sc = make_sidecar(block)
            if mutate is not None:
                mutate(sc)
            sidecars.append(sc)
        payload.sidecars = sidecars
        self.send_and_ping(payload)
        self.headext_sent += len(sidecars)

    def wait_for_getheadext(self, min_count: int, timeout: float = 10.0) -> None:
        start = time.time()
        while True:
            with p2p_lock:
                count = len(self.getheadext_requests)
            if count >= min_count:
                break
            if time.time() - start > timeout:
                raise AssertionError(f"Timeout waiting for {min_count} GETHEADERS_EXT (have {count})")
            time.sleep(0.05)

    def track_block(self, block) -> None:
        little_int = int(block.sha256)
        little_bytes = little_int.to_bytes(32, "little")
        big_int = int.from_bytes(little_bytes, "big")
        logger.debug("[%s] track block hash=%064x", self.label, little_int)
        self.blocks_by_hash[little_int] = block
        self.blocks_by_hash[little_bytes] = block
        self.blocks_by_hash[big_int] = block

    def _lookup_sidecar(self, key) -> Optional[dict]:
        if key in self._queued_sidecars:
            return self._queued_sidecars[key]
        try:
            key_bytes = key.to_bytes(32, "little")
        except Exception:
            return None
        return self._queued_sidecars.get(key_bytes)

    def _lookup_block(self, key):
        if key in self.blocks_by_hash:
            return self.blocks_by_hash[key]
        try:
            key_bytes = key.to_bytes(32, "little")
        except Exception:
            return None
        return self.blocks_by_hash.get(key_bytes)


def build_blocks(node, parent_hex: str, count: int, *, tick: int, spacing: int = 60) -> BlockBatch:
    """Create `count` consecutive solved blocks with deterministic ticks and realistic VDF sidecars."""
    import time as time_module
    from test_framework.messages import CProofBlob
    from test_framework.blocktools import create_coinbase

    logger.debug(f"build_blocks: starting {count} blocks from {parent_hex[:16]}..., tick={tick}")
    blocks: List = []
    prev_hex = parent_hex
    cumulative = 0
    parent_height = 0

    if parent_hex != "0" * 64:
        parent_cum = _lookup_parent_cumulative(parent_hex)
        if parent_cum is not None:
            cumulative = parent_cum
            logger.debug(f"build_blocks: cached parent cumulative {cumulative}")
        else:
            # Get cumulative_tick from the actual block, not just the header
            try:
                from test_framework.messages import CBlock
                from io import BytesIO
                # Get raw block hex (verbosity=0)
                parent_block_hex = node.getblock(parent_hex, 0)
                # Deserialize to get cumulative_tick
                parent_block_bytes = bytes.fromhex(parent_block_hex)
                parent_block = CBlock()
                parent_block.deserialize(BytesIO(parent_block_bytes))
                cumulative = parent_block.cumulative_tick
                cache_block_cumulative(parent_hex, cumulative)
                logger.info(f"build_blocks: got parent cumulative_tick={cumulative} from block {parent_hex[:16]}...")
            except Exception as e:
                logger.debug(f"build_blocks: getblock failed: {e}, starting from 0")
                cumulative = 0

        try:
            parent_info = node.getblockheader(parent_hex)
            parent_height = parent_info.get('height', 0)
            base_time = parent_info.get('time', int(time_module.time()))
        except Exception as e:
            logger.debug(f"build_blocks: getblockheader failed: {e}")
            try:
                parent_height = node.getblockcount()
            except Exception:
                parent_height = 0
            base_time = int(time_module.time())
    else:
        base_time = int(time_module.time())

    for idx in range(count):
        block_height = parent_height + idx + 1
        block_time = base_time + spacing * (idx + 1)

        coinbase = create_coinbase(height=block_height)
        block = create_block(hashprev=int(prev_hex, 16), coinbase=coinbase, ntime=block_time)

        if not hasattr(block, 'pow'):
            block.pow = CProofBlob()

        block.pow.tick = tick
        block.pow.model_identifier = b"testModel@testModelCommit"

        cumulative += tick
        block.cumulative_tick = cumulative

        # Use proper VDF proof generation like working tests
        try:
            from test_framework.vdf_helper import populate_tensor_pow_fields, HAS_CHIAVDF
            # Convert prev hash to correct byte order for VDF challenge
            prev_hash_bytes = bytes.fromhex(prev_hex)[::-1] if prev_hex != "0" * 64 else b'\x00' * 32
            populate_tensor_pow_fields(
                block,
                prev_hash_bytes,  # Correct VDF challenge (previous block hash)
                tick=tick,
                vdf_verify_active=True,
                use_real_vdf=HAS_CHIAVDF  # Use real chiavdf proofs
            )
            logger.debug(f"build_blocks: Generated VDF proof with chiavdf: {len(block.pow.vdf)} bytes")
        except Exception as e:
            logger.debug(f"build_blocks: VDF generation failed: {e}")
            block.pow.vdf = b""

        block.solve()

        block_hash_hex = format(block.sha256, '064x')
        cache_block_cumulative(block_hash_hex, cumulative)
        blocks.append(block)
        prev_hex = block_hash_hex
        logger.info(f"build_blocks: built block {idx+1}/{count} hash={block_hash_hex[:16]}... tick={tick} cumulative_tick={cumulative}")

    return BlockBatch(blocks, f"{count} blocks tick={tick}")


def make_sidecar(block) -> dict:
    header_hash = int(block.sha256).to_bytes(32, "little")
    prev_hash = int(block.hashPrevBlock).to_bytes(32, "little")
    return create_headers_ext_sidecar(header_hash, prev_hash, block.pow)


def headers_message(blocks: Iterable) -> List[CBlockHeader]:
    return [CBlockHeader(block) for block in blocks]
