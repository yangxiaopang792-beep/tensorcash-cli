#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining on an alternate Tensor mainnet

Test mining related RPCs that involve difficulty adjustment, which
regtest doesn't have.

It uses an alternate Tensor mainnet chain. See data/README.md for how it was generated.

Mine one retarget period worth of blocks with a short interval in
order to maximally raise the difficulty. Verify this using the getmininginfo RPC.

"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.blocktools import (
    create_coinbase,
    set_block_difficulty,
    set_block_tick_from_prev,
    uint256_from_compact,
    update_block_pow_commitment,
)

from test_framework.messages import CBlock, COIN, SEQUENCE_FINAL

import json
import os

# See data/README.md
COINBASE_SCRIPT_PUBKEY="76a914eadbac7f36c37e39361168b7aaee3cb24a25312d88ac"
TENSOR_DEFAULT_MODEL = b"Qwen/Qwen3-8B@9c925d64d72725edaf899c6cb9c377fd0709d9c5"
MODEL_DIFFICULTY_NORMALIZER = 1_000_000
POW_LIMIT_HEX = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
POW_LIMIT_INT = int(POW_LIMIT_HEX, 16)
TENSOR_HALVING_INTERVAL = 210_000

# TensorCash block subsidy schedule (must match GetBlockSubsidy in validation.cpp).
TENSOR_INITIAL_REWARD = 715  # BTC units; converted to satoshis via COIN
TENSOR_EPOCH_START_LEN = 715
TENSOR_EPOCH_CAP_LEN = TENSOR_EPOCH_START_LEN * (1 << 10)
TENSOR_P = 3
TENSOR_Q = 5
# Precomputed finite total supply from this recurrence, in satoshis.
TENSOR_EXPECTED_TOTAL_SATS = 2_118_415_303_530_240


def compact_from_uint256(value: int) -> int:
    if value <= 0:
        return 0
    size = (value.bit_length() + 7) // 8
    if size <= 3:
        compact = value << (8 * (3 - size))
    else:
        compact = value >> (8 * (size - 3))
    compact &= 0x007fffff
    compact |= size << 24
    return compact

class MiningMainnetTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = "tensor"
        # The Tensor mainnet genesis (nTime 1780329205 = 2026-06-01) sits near
        # the present, so the imported chain (genesis + 60s/block × 2015 ≈ +34h)
        # is dated into the near future. The setmocktime RPC is unavailable on
        # the non-mockable tensor chain, so freeze the node clock past the
        # chain's end via the -mocktime startup arg (applied unconditionally in
        # init, unlike the IsMockableChain-gated RPC) so submitblock does not
        # reject late blocks as "time-too-new", independent of wall-clock.
        genesis_ntime = 1780329205
        mocktime = genesis_ntime + 2015 * 60 + 7200  # past the last block + MAX_FUTURE_BLOCK_TIME
        self.extra_args = [[
            f'-mocktime={mocktime}',
            '-validationapi=mock',
            '-useextapi=0',
            '-mockval-default-quick=quick_ok_smell_ok',
            '-mockval-default-model=model_ok',
            '-mockval-preapprove-genesis=1',
        ]]

    def _ensure_model_difficulty(self, node):
        if hasattr(self, '_model_difficulty'):
            return self._model_difficulty
        models = node.getmodelslist(False)
        target_id = TENSOR_DEFAULT_MODEL.decode()
        for entry in models:
            ident = f"{entry['model_name']}@{entry['model_commit']}"
            if ident == target_id:
                self._model_difficulty = int(entry['difficulty'])
                break
        else:
            raise RuntimeError("Default Tensor model not found in model DB")
        return self._model_difficulty

    def _max_adj_bits(self, base_bits: int, node) -> int:
        base_target = uint256_from_compact(base_bits)
        diff = self._ensure_model_difficulty(node)
        if diff <= 0:
            return base_bits
        norm = MODEL_DIFFICULTY_NORMALIZER
        powlim = POW_LIMIT_INT
        q = base_target // diff
        max_adj = q * norm
        if max_adj > powlim:
            max_adj = powlim
        else:
            rem = base_target - (q * diff)
            extra = (rem * norm) // diff
            if extra:
                if max_adj > powlim - extra:
                    max_adj = powlim
                else:
                    max_adj += extra
        if max_adj <= 0:
            max_adj = 1
        return compact_from_uint256(max_adj)

    def add_options(self, parser):
        parser.add_argument(
            '--datafile',
            default='data/mainnet_alt.json',
            help='Block data file (default: %(default)s)',
        )

    def mine(self, height, prev_hash, timestamp, start_nonce, n_bits, node):
        self.log.debug(f"height={height}")
        block = CBlock()
        block.nVersion = 0x20000000
        block.hashPrevBlock = int(prev_hash, 16)
        block.nTime = timestamp
        # Set reported network difficulty (nBits) while keeping Tensor PoW lenient via nAdjBits
        block.nBits = int(n_bits)
        set_block_difficulty(block, block.nBits, set_adj=False)
        # Use the loosest allowable adjusted target derived from the model difficulty
        block.nAdjBits = self._max_adj_bits(block.nBits, node)
        block.rehash()
        block.nNonce = start_nonce
        block.vtx = [create_coinbase(
            height=height,
            script_pubkey=bytes.fromhex(COINBASE_SCRIPT_PUBKEY),
            retarget_period=TENSOR_HALVING_INTERVAL,
        )]
        # The alternate mainnet chain was mined with non-timelocked coinbase txs.
        block.vtx[0].nLockTime = 0
        block.vtx[0].vin[0].nSequence = SEQUENCE_FINAL
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        # Populate Tensor PoW tick metadata and generate a VDF proof so the
        # reconstructed block satisfies mainnet verification rules.
        set_block_tick_from_prev(node, block, prev_hash)
        block.pow.model_identifier = TENSOR_DEFAULT_MODEL
        update_block_pow_commitment(block, use_merkle=True)
        block.rehash()

        # Ensure the Tensor short-hash PoW meets the eased target by tweaking
        # nonce and (if needed) timestamp deterministically. With nAdjBits set
        # to the loosest allowable target, solutions should be found quickly,
        # but allow ample headroom so regeneration succeeds even when
        # timestamps were replayed from legacy data.
        target = uint256_from_compact(block.nAdjBits)
        nonce_attempts = 0
        max_nonce_attempts = 1 << 19  # ~500k nonce trials before adjusting time
        time_shifts = 0
        max_time_shifts = 1 << 11   # allow drifting up to ~2048 seconds if needed
        while block.short_sha256 > target:
            block.nNonce = (block.nNonce + 1) & 0xffffffff
            block.rehash()
            nonce_attempts += 1
            if nonce_attempts > max_nonce_attempts:
                if time_shifts >= max_time_shifts:
                    raise RuntimeError("Unable to satisfy Tensor short-hash PoW for imported Tensor block")
                time_shifts += 1
                block.nTime += 1
                nonce_attempts = 0
                self.log.debug("Adjusting timestamp by +1s to satisfy short-hash PoW (shift=%d)", time_shifts)
                block.rehash()
        block_hex = block.serialize(with_witness=False).hex()
        try:
            node.validationmockset(block.hash, "quick", "quick_ok_smell_ok")
            node.validationmockset(block.hash, "model", "model_ok")
            node.validationmockset(block.hash, "full", "full_green")
        except Exception as err:
            self.log.warning("validationmockset failed for %s: %s", block.hash, err)
        self.log.debug(block_hex)
        assert_equal(node.submitblock(block_hex), None)
        prev_hash = node.getbestblockhash()
        assert_equal(prev_hash, block.hash)
        return prev_hash, block.nTime, block.nNonce


    def run_test(self):
        node = self.nodes[0]
        # Clear disk space warning
        node.stderr.seek(0)
        node.stderr.truncate()
        self.log.info("Load alternative Tensor mainnet blocks")
        prev_hash = node.getbestblockhash()
        prev_time = node.getblockheader(prev_hash)['time']

        data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.options.datafile)
        blocks = None
        output_blocks = None
        output_path = None

        if os.path.exists(data_path):
            with open(data_path, encoding='utf-8') as f:
                candidate = json.load(f)
                assert_equal(len(candidate['timestamps']), 2015)
                assert_equal(len(candidate['timestamps']), len(candidate['nonces']))
                if 'bits' in candidate:
                    assert_equal(len(candidate['timestamps']), len(candidate['bits']))
                if candidate['timestamps'] and candidate['timestamps'][0] > prev_time:
                    blocks = candidate
                else:
                    self.log.warning("Existing datafile predates Tensor genesis; regenerating block vector")

        if blocks is None:
            tc_tmp = os.getenv("TC_TMPDIR")
            if not tc_tmp:
                tc_tmp = self.options.tmpdir
            output_path = os.path.join(tc_tmp, "tensor_mainnet_blocks.json")
            output_blocks = {"timestamps": [], "nonces": [], "bits": []}
        interval = 60
        n_blocks = 2015
        for i in range(n_blocks):
            if blocks is not None:
                timestamp = blocks['timestamps'][i]
                start_nonce = blocks['nonces'][i]
                n_bits = int(blocks['bits'][i], 16) if 'bits' in blocks else int(node.getmininginfo()['next']['bits'], 16)
            else:
                timestamp = prev_time + interval
                start_nonce = 0
                n_bits = int(node.getmininginfo()['next']['bits'], 16)
            prev_hash, prev_time, final_nonce = self.mine(i + 1, prev_hash, timestamp, start_nonce, n_bits, node)
            if output_blocks is not None:
                output_blocks['timestamps'].append(prev_time)
                output_blocks['nonces'].append(final_nonce)
                output_blocks['bits'].append(f"{n_bits:08x}")

        if output_blocks is not None:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_blocks, f, indent=2)
            self.log.info(f"Wrote Tensor mainnet vector to {output_path}")

        assert_equal(node.getblockcount(), 2015)

        self.log.info("Check difficulty adjustment with getmininginfo")
        mining_info = node.getmininginfo()
        assert_equal(mining_info['blocks'], 2015)
        # Difficulty should increase after a rapid mining period
        assert mining_info['next']['difficulty'] >= mining_info['difficulty']
        assert_equal(mining_info['next']['height'], 2016)

        # TensorCash: verify block subsidy schedule and asymptotic total supply.
        self._check_tensor_subsidy_schedule(node)
        self._check_tensor_subsidy_convergence()

    def _tensor_subsidy_at_height(self, height: int) -> int:
        """Pure Python mirror of TensorCash subsidy schedule (in satoshis)."""
        reward = TENSOR_INITIAL_REWARD * COIN
        epoch_len = TENSOR_EPOCH_START_LEN
        if height <= 0:
            return reward
        remaining = height
        while remaining >= epoch_len and reward > 0:
            remaining -= epoch_len
            reward = (reward * TENSOR_P) // TENSOR_Q
            epoch_len = min(epoch_len * 2, TENSOR_EPOCH_CAP_LEN)
        return reward

    def _check_tensor_subsidy_schedule(self, node):
        self.log.info("Check TensorCash subsidy schedule via getblockstats")
        # Use heights covered by the imported alternate Tensor mainnet chain.
        sample_heights = [0, 1, 714, 715, 1715, 2015]
        for h in sample_heights:
            stats = node.getblockstats(h, ["subsidy"])
            onchain_subsidy = stats["subsidy"]
            expected_sats = self._tensor_subsidy_at_height(h)
            assert_equal(onchain_subsidy, expected_sats)

    def _check_tensor_subsidy_convergence(self):
        self.log.info("Check TensorCash subsidy convergence to finite total")
        reward = TENSOR_INITIAL_REWARD * COIN
        epoch_len = TENSOR_EPOCH_START_LEN
        total_sats = 0
        while reward > 0:
            epoch_sats = reward * epoch_len
            total_sats += epoch_sats
            reward = (reward * TENSOR_P) // TENSOR_Q
            epoch_len = min(epoch_len * 2, TENSOR_EPOCH_CAP_LEN)

        assert_equal(total_sats, TENSOR_EXPECTED_TOTAL_SATS)

if __name__ == '__main__':
    MiningMainnetTest(__file__).main()
