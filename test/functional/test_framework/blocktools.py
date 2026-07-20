#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for manipulating blocks and transactions."""

import struct
from io import BytesIO
import time
import unittest

from .address import (
    address_to_scriptpubkey,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    script_to_p2sh_p2wsh,
    script_to_p2wsh,
)
from .messages import (
    CBlock,
    COIN,
    COutPoint,
    CProofBlob,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
    hash256,
    ser_uint256,
    tx_from_hex,
    uint256_from_compact,
    WITNESS_SCALE_FACTOR,
    MAX_SEQUENCE_NONFINAL,
)

# Import VDF helper functions if available
try:
    from .vdf_helper import (
        generate_vdf_proof,
        compute_pow_commitment,
        HAS_CHIAVDF,
        cache_block_cumulative,
    )
except ImportError:
    HAS_CHIAVDF = False
    generate_vdf_proof = None
    compute_pow_commitment = None
    cache_block_cumulative = None
from .script import (
    CScript,
    CScriptNum,
    CScriptOp,
    OP_0,
    OP_RETURN,
    OP_TRUE,
)
from .script_util import (
    key_to_p2pk_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    script_to_p2wsh_script,
)
from .util import assert_equal
from .authproxy import JSONRPCException
from typing import Optional, Dict
from .vdf_helper import _lookup_parent_cumulative, refresh_cumulative_tick_cache_from_node

MAX_BLOCK_SIGOPS = 20000
MAX_BLOCK_SIGOPS_WEIGHT = MAX_BLOCK_SIGOPS * WITNESS_SCALE_FACTOR
MAX_STANDARD_TX_WEIGHT = 400000

# Genesis block time (regtest)
TIME_GENESIS_BLOCK = 1296688602

MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

# Coinbase transaction outputs can only be spent after this number of new blocks (network rule)
COINBASE_MATURITY = 100

# Default TensorCash VDF tick to use when constructing synthetic blocks in tests.
# A relatively small value keeps functional tests fast while still exercising
# the tick plumbing end-to-end.
DEFAULT_TEST_POW_TICK = 1000

# From BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"

NORMAL_GBT_REQUEST_PARAMS = {"rules": ["segwit"]}
VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4
MIN_BLOCKS_TO_KEEP = 288

REGTEST_RETARGET_PERIOD = 150

REGTEST_N_BITS = 0x207fffff  # difficulty retargeting is disabled in REGTEST chainparams"
REGTEST_TARGET = 0x7fffff0000000000000000000000000000000000000000000000000000000000
assert_equal(uint256_from_compact(REGTEST_N_BITS), REGTEST_TARGET)

DIFF_1_N_BITS = 0x1d00ffff
DIFF_1_TARGET = 0x00000000ffff0000000000000000000000000000000000000000000000000000
assert_equal(uint256_from_compact(DIFF_1_N_BITS), DIFF_1_TARGET)

DIFF_4_N_BITS = 0x1c3fffc0
DIFF_4_TARGET = int(DIFF_1_TARGET / 4)
assert_equal(uint256_from_compact(DIFF_4_N_BITS), DIFF_4_TARGET)

# Local cumulative tick cache (covers blocks crafted in tests before they're
# accepted by a node). Keys are lowercase hex block hashes.
_LOCAL_BLOCK_CUM_CACHE: Dict[str, int] = {}


def _register_local_block(block) -> None:
    if block is None:
        return
    try:
        block.calc_sha256()
        block_hash_hex = f"{block.sha256:064x}"
        cum_tick = int(getattr(block, 'cumulative_tick', 0))
        _LOCAL_BLOCK_CUM_CACHE[block_hash_hex.lower()] = cum_tick
        if cache_block_cumulative is not None:
            cache_block_cumulative(block_hash_hex, cum_tick)
    except Exception:
        pass


def register_block_tick_cache(block) -> None:
    """Expose local cumulative tick caching for external callers."""
    _register_local_block(block)

def nbits_str(nbits):
    return f"{nbits:08x}"

def target_str(target):
    return f"{target:064x}"

def create_block(hashprev=None, coinbase=None, ntime=None, *, version=None, tmpl=None, txlist=None):
    """Create a block (with regtest difficulty)."""
    block = CBlock()
    if tmpl is None:
        tmpl = {}
    block.nVersion = version or tmpl.get('version') or VERSIONBITS_LAST_OLD_BLOCK_VERSION
    block.nTime = ntime or tmpl.get('curtime') or int(time.time() + 600)
    block.hashPrevBlock = hashprev or int(tmpl['previousblockhash'], 0x10)
    if tmpl and tmpl.get('bits') is not None:
        block.nBits = struct.unpack('>I', bytes.fromhex(tmpl['bits']))[0]
    else:
        block.nBits = REGTEST_N_BITS
    if coinbase is None:
        coinbase = create_coinbase(height=tmpl['height'])
    block.vtx.append(coinbase)
    if txlist:
        for tx in txlist:
            if not hasattr(tx, 'calc_sha256'):
                tx = tx_from_hex(tx)
            block.vtx.append(tx)
    block.hashMerkleRoot = block.calc_merkle_root()
    # Initialize Tensor header extras so PoW uses adjusted bits
    block.nAdjBits = block.nBits
    block.flags = 0
    block.hashPoW = 0
    # Initialize cumulative_tick to 0 (will be set properly by set_block_tick_from_prev if needed)
    block.cumulative_tick = 0
    # Initialize pow field with default tick for Tensor
    block.pow = CProofBlob()
    block.pow.tick = DEFAULT_TEST_POW_TICK  # Default tick keeps tests fast
    # Set default model identifier for TensorCash validation
    # This matches the DefaultModelName@DefaultModelCommit for tensor-reg chain
    block.pow.model_identifier = b"testModel@testModelCommit"
    # VDF proof will be generated when solve() is called
    block.pow.vdf = b""
    block.calc_sha256()
    return block


def set_block_difficulty(block, nbits: int, *, set_adj: bool = True):
    """Set difficulty bits on a block and optionally mirror to nAdjBits.

    - Updates `block.nBits` and, when set_adj, `block.nAdjBits` too.
    - Recomputes header hashes (full and short).
    """
    block.nBits = int(nbits)
    if set_adj:
        block.nAdjBits = block.nBits
    # Recompute header hashes with new bits
    block.calc_sha256()


def set_block_tick(block, tick: int, *, prev_block=None, prev_cumulative_tick: Optional[int] = None):
    """Set PoW tick and keep cumulative_tick consistent.

    Pass either prev_block (with cumulative_tick field) or prev_cumulative_tick explicitly.
    """
    if not hasattr(block, 'pow'):
        return  # Older objects won't support tensor pow; ignore
    block.pow.tick = int(tick)
    if block.pow.tick <= 0 and (prev_block is not None or prev_cumulative_tick is not None):
        raise ValueError("tick must be positive for non-genesis blocks")
    base = 0
    if prev_cumulative_tick is not None:
        base = int(prev_cumulative_tick)
    elif prev_block is not None and hasattr(prev_block, 'cumulative_tick'):
        base = int(prev_block.cumulative_tick)
    block.cumulative_tick = base + int(tick)
    _register_local_block(prev_block)
    _register_local_block(block)

def set_block_vdf_proof(block, prev_block_hash: bytes = None, generate_real: bool = True):
    """Generate and set VDF proof for a block.

    Args:
        block: CBlock object to update
        prev_block_hash: Previous block hash (32 bytes). If None, uses block.hashPrevBlock
        generate_real: If True and chiavdf available, generate real proof. Otherwise use test vector.
    """
    if not hasattr(block, 'pow'):
        block.pow = CProofBlob()

    # Get previous block hash
    if prev_block_hash is None:
        # Convert from block's integer hashPrevBlock to bytes
        prev_hash_hex = format(block.hashPrevBlock, '064x')
        prev_block_hash = bytes.fromhex(prev_hash_hex)[::-1]  # Reverse for internal byte order

    # Get tick value
    tick = getattr(block.pow, 'tick', 100000)  # Default tick if not set

    # Generate VDF proof
    if generate_real and generate_vdf_proof is not None:
        block.pow.vdf = generate_vdf_proof(prev_block_hash, tick, 1024)
    else:
        # Use a test vector or placeholder
        # This matches the known test vector for zero hash with tick=1998848
        if prev_block_hash == b'\x00' * 32 and tick == 1998848:
            block.pow.vdf = bytes.fromhex(
                "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
                "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
                "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
                "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
                "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
                "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
                "dd6aaa12a5083b9454a0100"
            )
        else:
            # Generate a plausible placeholder (won't pass verification)
            import hashlib
            h = hashlib.sha256()
            h.update(prev_block_hash)
            h.update(tick.to_bytes(8, 'little'))
            block.pow.vdf = b'\x03\x00' + h.digest()[:198]

def update_block_pow_commitment(block, use_merkle: bool = True):
    """Update block's hashPoW field with proper commitment.

    Args:
        block: CBlock object to update
        use_merkle: If True, use Merkle root commitment. If False, use legacy hash.
    """
    if not hasattr(block, 'pow'):
        return

    if compute_pow_commitment is not None:
        # Use the VDF helper to compute proper commitment
        commitment = compute_pow_commitment(block.pow, use_merkle)
        block.hashPoW = int.from_bytes(commitment, 'little')
    else:
        # Fallback: simplified commitment
        block.hashPoW = block.sha256 if hasattr(block, 'sha256') else 0

def _decode_block_hex(hex_str: str) -> CBlock:
    """Decode a hex-serialized block (Tensor header/format) into a CBlock."""
    raw = bytes.fromhex(hex_str)
    f = BytesIO(raw)
    blk = CBlock()
    blk.deserialize(f)
    return blk

def set_block_tick_from_prev(node, block: CBlock, prev_hash_hex: Optional[str] = None,
                             *, tick: Optional[int] = None,
                             generate_vdf: bool = True, use_merkle: bool = True,
                             force_refresh_cache: bool = False):
    """Populate Tensor PoW tick fields using the previous block from node.

    - Ensures block.cumulative_tick = prev.cumulative_tick + block.pow.tick.
    - Generates a VDF proof and updates hashPoW commitment by default so the
      returned block mirrors node-side expectations.
    - Safe to call before block.solve(); does not mutate PoW target fields.

    Args:
        node: RPC connection to get previous block
        block: CBlock to update
        prev_hash_hex: Previous block hash in hex (optional)
        tick: If provided, override block.pow.tick before computing cumulative tick
        generate_vdf: If True (default), generate VDF proof for the block
        use_merkle: If True, compute hashPoW as Merkle root
        force_refresh_cache: If True, always refresh cumulative_tick cache from node
    """
    # Determine previous block hash (hex)
    prev_hexhash = prev_hash_hex or node.getbestblockhash()
    expected_prev = int(prev_hexhash, 16)
    if not hasattr(block, 'hashPrevBlock') or block.hashPrevBlock == 0:
        block.hashPrevBlock = expected_prev
    elif block.hashPrevBlock != expected_prev:
        raise ValueError("block.hashPrevBlock does not match provided prev hash")
    prev_block = None
    prev_cumulative = None
    try:
        prev_block_hex = node.getblock(prev_hexhash, 0)
        prev_block = _decode_block_hex(prev_block_hex)
        prev_cumulative = int(getattr(prev_block, 'cumulative_tick', 0))
    except JSONRPCException as exc:
        # Handle both -5 (block not found) and -1 (header-only block)
        if getattr(exc, 'error', {}).get('code') not in (-5, -1):
            raise
        # Attempt to rely on cached cumulative tick for detached blocks
        prev_cumulative = _LOCAL_BLOCK_CUM_CACHE.get(prev_hexhash.lower())
        if prev_cumulative is None:
            prev_cumulative = _lookup_parent_cumulative(prev_hexhash)
        if prev_cumulative is None:
            refresh_cumulative_tick_cache_from_node(node, prev_hexhash, depth=2)
            prev_cumulative = _lookup_parent_cumulative(prev_hexhash)
        if prev_cumulative is None:
            raise
    # Cache cumulative tick when available
    if prev_cumulative is not None:
        _LOCAL_BLOCK_CUM_CACHE[prev_hexhash.lower()] = prev_cumulative
        if cache_block_cumulative is not None:
            cache_block_cumulative(prev_hexhash, prev_cumulative)
        # Also ensure we have the parent's parent cached if needed
        if force_refresh_cache and prev_block is not None and hasattr(prev_block, 'hashPrevBlock'):
            parent_of_prev_hex = format(prev_block.hashPrevBlock, '064x')
            try:
                parent_of_prev_block_hex = node.getblock(parent_of_prev_hex, 0)
                parent_of_prev_block = _decode_block_hex(parent_of_prev_block_hex)
                parent_of_prev_cumulative = int(getattr(parent_of_prev_block, 'cumulative_tick', 0))
                cache_block_cumulative(parent_of_prev_hex, parent_of_prev_cumulative)
            except Exception:
                pass  # Genesis or unavailable block
    if tick is not None:
        if not hasattr(block, 'pow'):
            block.pow = CProofBlob()
        block.pow.tick = int(tick)

    if not hasattr(block, 'pow'):
        block.pow = CProofBlob()

    # Default tick to a sensible positive value for synthetic blocks.
    tick_val = getattr(block.pow, 'tick', 0)
    if tick_val <= 0 and block.hashPrevBlock != 0:
        tick_val = DEFAULT_TEST_POW_TICK
        block.pow.tick = int(tick_val)

    if tick_val <= 0 and block.hashPrevBlock != 0:
        raise ValueError(
            "set_block_tick_from_prev requires block.pow.tick to be a positive value"
        )
    if prev_block is not None:
        set_block_tick(block, tick=int(tick_val), prev_block=prev_block)
    else:
        set_block_tick(block, tick=int(tick_val), prev_cumulative_tick=prev_cumulative)

    _register_local_block(prev_block)
    _register_local_block(block)
    # Ensure model identifier is set
    if not hasattr(block, 'pow'):
        block.pow = CProofBlob()
    if not hasattr(block.pow, 'model_identifier') or not block.pow.model_identifier:
        block.pow.model_identifier = b"testModel@testModelCommit"

    # Generate VDF proof if requested
    if generate_vdf:
        # Convert prev hash to bytes for VDF generation
        prev_hash_bytes = bytes.fromhex(prev_hexhash)[::-1]
        set_block_vdf_proof(block, prev_hash_bytes, generate_real=HAS_CHIAVDF)
        if len(getattr(block.pow, 'vdf', b"")) == 0 and block.hashPrevBlock != 0:
            raise RuntimeError("Failed to generate VDF proof for non-genesis block")

    # Update hashPoW commitment if VDF was generated or requested
    if generate_vdf or use_merkle:
        update_block_pow_commitment(block, use_merkle=use_merkle)

def initialize_tensor_block_fields(block, generate_vdf: bool = False, use_merkle_commitment: bool = True):
    """Helper to ensure Tensor-specific block fields are properly initialized.

    This should be called when manually creating CBlock instances to ensure:
    - nAdjBits is set (defaults to nBits)
    - cumulative_tick is initialized (defaults to 0)
    - hashPoW and flags are set
    - pow field with tick is created
    - Optional: VDF proof is generated

    Args:
        block: CBlock object to initialize
        generate_vdf: If True, generate VDF proof for the block
        use_merkle_commitment: If True, compute hashPoW as Merkle root
    """
    if not hasattr(block, 'nAdjBits') or block.nAdjBits == 0:
        block.nAdjBits = block.nBits
    if not hasattr(block, 'cumulative_tick'):
        block.cumulative_tick = 0
    if not hasattr(block, 'hashPoW'):
        block.hashPoW = 0
    if not hasattr(block, 'flags'):
        block.flags = 0
    if not hasattr(block, 'pow'):
        block.pow = CProofBlob()

    # Ensure a positive tick so helper routines (and the node) accept the block.
    if getattr(block.pow, 'tick', 0) <= 0:
        block.pow.tick = DEFAULT_TEST_POW_TICK

    # Set default model identifier for TensorCash validation
    if not hasattr(block.pow, 'model_identifier') or not block.pow.model_identifier:
        block.pow.model_identifier = b"testModel@testModelCommit"

    # Generate VDF proof if requested
    if generate_vdf:
        set_block_vdf_proof(block, generate_real=HAS_CHIAVDF)

    # Update hashPoW commitment
    update_block_pow_commitment(block, use_merkle=use_merkle_commitment)


def create_block_with_vdf(hashprev=None, coinbase=None, ntime=None, tick=100000,
                          generate_vdf=True, use_merkle=True, **kwargs):
    """Create a block with proper TensorCash VDF fields.

    This is a convenience wrapper around create_block that also:
    - Initializes TensorCash fields
    - Generates VDF proof if requested
    - Computes proper hashPoW commitment

    Args:
        hashprev: Previous block hash
        coinbase: Coinbase transaction
        ntime: Block timestamp
        tick: VDF iterations (default 100000)
        generate_vdf: If True, generate VDF proof
        use_merkle: If True, use Merkle root for hashPoW
        **kwargs: Additional arguments for create_block

    Returns:
        CBlock with TensorCash fields properly set
    """
    # Create basic block
    block = create_block(hashprev, coinbase, ntime, **kwargs)

    # Set tick value
    if not hasattr(block, 'pow'):
        block.pow = CProofBlob()
    block.pow.tick = tick

    # Initialize TensorCash fields and optionally generate VDF
    initialize_tensor_block_fields(block, generate_vdf=generate_vdf, use_merkle_commitment=use_merkle)

    return block

def get_witness_script(witness_root, witness_nonce):
    witness_commitment = hash256(ser_uint256(witness_root) + ser_uint256(witness_nonce))
    output_data = WITNESS_COMMITMENT_HEADER + witness_commitment
    return CScript([OP_RETURN, output_data])

def add_witness_commitment(block, nonce=0):
    """Add a witness commitment to the block's coinbase transaction.

    According to BIP141, blocks with witness rules active must commit to the
    hash of all in-block transactions including witness."""
    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    block.vtx[0].vout.append(CTxOut(0, get_witness_script(witness_root, witness_nonce)))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()


def script_BIP34_coinbase_height(height):
    if height <= 16:
        res = CScriptOp.encode_op_n(height)
        # Append dummy to increase scriptSig size to 2 (see bad-cb-length consensus rule)
        return CScript([res, OP_0])
    return CScript([CScriptNum(height)])


def create_coinbase(height, pubkey=None, *, script_pubkey=None, extra_output_script=None, fees=0, nValue=50, retarget_period=REGTEST_RETARGET_PERIOD):
    """Create a coinbase transaction.

    If pubkey is passed in, the coinbase output will be a P2PK output;
    otherwise an anyone-can-spend output.

    If extra_output_script is given, make a 0-value output to that
    script. This is useful to pad block weight/sigops as needed. """
    coinbase = CTransaction()
    coinbase.nLockTime = height - 1
    coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff), script_BIP34_coinbase_height(height), MAX_SEQUENCE_NONFINAL))
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = nValue * COIN
    if nValue == 50:
        halvings = int(height / retarget_period)
        coinbaseoutput.nValue >>= halvings
        coinbaseoutput.nValue += fees
    if pubkey is not None:
        coinbaseoutput.scriptPubKey = key_to_p2pk_script(pubkey)
    elif script_pubkey is not None:
        coinbaseoutput.scriptPubKey = script_pubkey
    else:
        coinbaseoutput.scriptPubKey = CScript([OP_TRUE])
    coinbase.vout = [coinbaseoutput]
    if extra_output_script is not None:
        coinbaseoutput2 = CTxOut()
        coinbaseoutput2.nValue = 0
        coinbaseoutput2.scriptPubKey = extra_output_script
        coinbase.vout.append(coinbaseoutput2)
    coinbase.calc_sha256()
    return coinbase

def create_tx_with_script(prevtx, n, script_sig=b"", *, amount, output_script=None):
    """Return one-input, one-output transaction object
       spending the prevtx's n-th output with the given amount.

       Can optionally pass scriptPubKey and scriptSig, default is anyone-can-spend output.
    """
    if output_script is None:
        output_script = CScript()
    tx = CTransaction()
    assert n < len(prevtx.vout)
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), script_sig, SEQUENCE_FINAL))
    tx.vout.append(CTxOut(amount, output_script))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, accurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, accurate)
    return count

def get_legacy_sigopcount_tx(tx, accurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(accurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(accurate)
    return count

def witness_script(use_p2wsh, pubkey):
    """Create a scriptPubKey for a pay-to-witness TxOut.

    This is either a P2WPKH output for the given pubkey, or a P2WSH output of a
    1-of-1 multisig for the given pubkey. Returns the hex encoding of the
    scriptPubKey."""
    if not use_p2wsh:
        # P2WPKH instead
        pkscript = key_to_p2wpkh_script(pubkey)
    else:
        # 1-of-1 multisig
        witness_script = keys_to_multisig_script([pubkey])
        pkscript = script_to_p2wsh_script(witness_script)
    return pkscript.hex()

def create_witness_tx(node, use_p2wsh, utxo, pubkey, encode_p2sh, amount):
    """Return a transaction (in hex) that spends the given utxo to a segwit output.

    Optionally wrap the segwit output using P2SH."""
    if use_p2wsh:
        program = keys_to_multisig_script([pubkey])
        addr = script_to_p2sh_p2wsh(program) if encode_p2sh else script_to_p2wsh(program)
    else:
        addr = key_to_p2sh_p2wpkh(pubkey) if encode_p2sh else key_to_p2wpkh(pubkey)
    if not encode_p2sh:
        assert_equal(address_to_scriptpubkey(addr).hex(), witness_script(use_p2wsh, pubkey))
    return node.createrawtransaction([utxo], {addr: amount})

def send_to_witness(use_p2wsh, node, utxo, pubkey, encode_p2sh, amount, sign=True, insert_redeem_script=""):
    """Create a transaction spending a given utxo to a segwit output.

    The output corresponds to the given pubkey: use_p2wsh determines whether to
    use P2WPKH or P2WSH; encode_p2sh determines whether to wrap in P2SH.
    sign=True will have the given node sign the transaction.
    insert_redeem_script will be added to the scriptSig, if given."""
    tx_to_witness = create_witness_tx(node, use_p2wsh, utxo, pubkey, encode_p2sh, amount)
    if (sign):
        signed = node.signrawtransactionwithwallet(tx_to_witness)
        assert "errors" not in signed or len(["errors"]) == 0
        return node.sendrawtransaction(signed["hex"])
    else:
        if (insert_redeem_script):
            tx = tx_from_hex(tx_to_witness)
            tx.vin[0].scriptSig += CScript([bytes.fromhex(insert_redeem_script)])
            tx_to_witness = tx.serialize().hex()

    return node.sendrawtransaction(tx_to_witness)

class TestFrameworkBlockTools(unittest.TestCase):
    def test_create_coinbase(self):
        height = 20
        coinbase_tx = create_coinbase(height=height)
        assert_equal(CScriptNum.decode(coinbase_tx.vin[0].scriptSig), height)
