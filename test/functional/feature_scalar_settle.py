#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial end-to-end OP_SCALAR_CFD_SETTLE settlement test (Slice 3f).

MUTUALLY-DISTRUSTING PARTIES, separate nodes + wallets:
  node0 / w_issuer = oracle issuer (registers the asset, publishes the fixing) + miner + keeper
  node1 / w_owner  = the LONG party (its payout leg pays a node1-owned key)
  node2 / w_cp     = the SHORT counterparty (its payout leg pays a node2-owned key)

A native-TSC CFD vault is opened at an OP_SCALAR_CFD_SETTLE taproot covenant (NUMS internal key,
so it is script-path only) committing to owner/cp keys held by the two distrusting parties. After
the issuer publishes the scalar and it buries, ANY keeper can settle — the covenant enforces the
deterministic split, so the keeper cannot favour either side. Covers (CFD_GENERALISATION.md §2-§4):
  * ACTIVATION BOUNDARY: below ScalarCfdHeight the opcode is an inert NOP, so the leaf leaves its
    operands on the stack and tapscript rejects -> the covenant is unsettleable until activation
    (exercises GetBlockScriptFlags height-gating end to end via generateblock)
  * a PREMATURE settle (above activation, fixing not yet buried) -> rejected (no snapshot entry)
  * honest settlement -> owner and cp each receive exactly their formula payout (verified per wallet)
  * a GREEDY keeper (mispaid outputs) -> the block is rejected by consensus

A live-chain reorg/removal of a SETTLEMENT is intentionally out of scope here (deferred to a
dedicated cache/reorg slice): publication reorg is covered in feature_scalar_publication.py, and
the non-cacheable re-validation enqueue in the C++ scalar_cfd_validation pvChecks test.
"""
import hashlib
import os
import time
from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    uint256_from_str,
)
from test_framework.script import (
    CScript,
    OP_CHECKLOCKTIMEVERIFY,
    OP_DROP,
    OP_NOP10,  # == OP_SCALAR_CFD_SETTLE (0xb9)
    OP_TRUE,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

RAW_U256_LE = 1
BOND = 5.1
UNLOCK_SATS = 510000000
COIN = 100_000_000
MIN_SETTLE_OUTPUT = 546
LAMBDA_SCALE = 1 << 16
MATURITY = 100  # SCALARCFD_MATURITY_DEPTH on regtest
SCALAR_CFD_HEIGHT = 160  # opcode activation height for this test

# BIP341 NUMS point H: an x-only pubkey with no known discrete log -> key-path is unspendable.
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def scalar_hex(n):
    return f"{n:064x}"


def le(n, width):
    return n.to_bytes(width, "little")


def payout_strike_long(K, X, lambda_q, vault_im, min_out=MIN_SETTLE_OUTPUT):
    """Mirror ComputeScalarCfdPayout for STRIKE-mode, long direction (loss when X < K)."""
    if not (X < K):
        return vault_im, 0
    num = K - X
    lhs = num * lambda_q
    denom_scaled = K * LAMBDA_SCALE
    cp = vault_im if lhs >= denom_scaled else (lhs * vault_im) // denom_scaled
    owner = vault_im - cp
    if cp != 0 and cp < min_out:
        cp, owner = 0, vault_im
    elif owner != 0 and owner < min_out:
        owner, cp = 0, vault_im
    return owner, cp


class ScalarSettleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_scalarsettle".encode()).hexdigest()[:16]
        common = ["-assetsheight=0", f"-scalarcfdheight={SCALAR_CFD_HEIGHT}", "-acceptnonstdtxn=1", "-txindex"]
        self.extra_args = [list(common) for _ in range(3)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)

    # ---- leaf / covenant construction ----
    def build_leaf(self, *, contract_id, settle_lock, underlying, feed_id, fixing_ref, deadline,
                   strike, fallback, lambda_q, loss_dir, vault_im, owner_key, cp_key):
        # The full canonical §2.2 leaf (ISSUER_PUBLISHED, native collateral, STRIKE mode).
        return CScript([
            contract_id, OP_DROP,                       # contract_id32
            b"\x01",                                    # template_version
            le(settle_lock, 1), OP_CHECKLOCKTIMEVERIFY, OP_DROP,  # settle_lock (minimal CScriptNum push)
            b"\x00",                                    # source_type = ISSUER_PUBLISHED
            underlying,                                 # underlying_asset_id32
            le(feed_id, 4),
            le(fixing_ref, 8),
            le(deadline, 4),
            b"\x00",                                    # payoff_mode = STRIKE
            le(RAW_U256_LE, 2),                         # scalar_format_id
            strike,                                     # strike_le32
            fallback,                                   # fallback_scalar_le32
            le(lambda_q, 4),
            bytes([loss_dir]),                          # loss_direction
            b"\x00" * 32,                               # collateral = NATIVE_SENTINEL
            le(vault_im, 8),
            owner_key, cp_key,                          # owner_key32, cp_key32
            OP_NOP10,                                   # OP_SCALAR_CFD_SETTLE
        ])

    def covenant(self, leaf):
        tap = taproot_construct(NUMS, [("settle", bytes(leaf))])
        return tap, tap.leaves["settle"]

    def fund_vault(self, covenant_addr, amount_btc):
        """Send `amount_btc` to the covenant address; return (txid, vout, value_sat)."""
        txid = self.w_issuer.sendtoaddress(covenant_addr, amount_btc)
        self.generate(self.nodes[0], 1)
        dec = self.nodes[0].getrawtransaction(txid, True)
        for v in dec["vout"]:
            if v["scriptPubKey"].get("address") == covenant_addr:
                return txid, v["n"], int(round(v["value"] * COIN))
        raise AssertionError("covenant output not found in funding tx")

    def spend_leaf(self, vault, leaf, tap, leaf_info, outs, *, nlocktime=0, nseq=0xffffffff):
        """Build a taproot script-path spend revealing `leaf`, with the given (spk, sat) outputs."""
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = nlocktime
        outpoint = COutPoint(uint256_from_str(bytes.fromhex(vault[0])[::-1]), vault[1])
        tx.vin.append(CTxIn(outpoint, nSequence=nseq))
        for spk, sat in outs:
            tx.vout.append(CTxOut(sat, spk))
        control = bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf), control]
        tx.rehash()
        return tx

    def settle_tx(self, vault_txid, vault_vout, leaf, tap, leaf_info, settle_lock, outs):
        # nSequence=0 (not FINAL) + nLockTime=settle_lock so the leaf CLTV is satisfied.
        return self.spend_leaf((vault_txid, vault_vout), leaf, tap, leaf_info, outs,
                               nlocktime=settle_lock, nseq=0)

    def mine_to(self, target):
        cur = self.nodes[0].getblockcount()
        if target > cur:
            self.generate(self.nodes[0], target - cur)

    def settle_and_reject(self, miner_addr, vault, leaf, tap, leaf_info, settle_lock, outs):
        tx = self.settle_tx(vault[0], vault[1], leaf, tap, leaf_info, settle_lock, outs)
        assert_raises_rpc_error(-25, None, self.generateblock, self.nodes[0], miner_addr,
                                [tx.serialize().hex()], sync_fun=self.no_op)

    def run_test(self):
        for n in self.nodes:
            n.createwallet(wallet_name="")
        self.w_issuer = self.nodes[0].get_wallet_rpc("")  # issuer/oracle + miner + keeper
        self.w_owner = self.nodes[1].get_wallet_rpc("")   # LONG party
        self.w_cp = self.nodes[2].get_wallet_rpc("")      # SHORT counterparty

        miner_addr = self.w_issuer.getnewaddress()
        self.generatetoaddress(self.nodes[0], 130, miner_addr, sync_fun=self.sync_all)

        asset_id = hashlib.sha256(f"oracle_{self.test_run_id}".encode()).hexdigest()
        ticker, feed, epoch = "ORCL", 7, 1
        K, X = 100, 90                        # strike, published scalar (long loses: X < K)
        lambda_q = 1 * LAMBDA_SCALE
        vault_im = 1 * COIN
        settle_lock = 1

        # --- issuer registers the oracle asset (publication waits until activation) ---
        self.log.info("issuer registers oracle asset")
        self.w_issuer.registerasset(self.w_issuer.getnewaddress(), BOND, asset_id, 3, 28, UNLOCK_SATS,
                                    ticker, 8, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(asset_id) is not None)

        # --- the two distrusting parties' payout keys (each on its own node/wallet) + the covenant ---
        owner_addr = self.w_owner.getnewaddress(address_type="bech32m")
        cp_addr = self.w_cp.getnewaddress(address_type="bech32m")
        owner_key = bytes.fromhex(self.w_owner.getaddressinfo(owner_addr)["witness_program"])
        cp_key = bytes.fromhex(self.w_cp.getaddressinfo(cp_addr)["witness_program"])
        owner_spk = bytes(address_to_scriptpubkey(owner_addr))
        cp_spk = bytes(address_to_scriptpubkey(cp_addr))

        # The leaf carries U as raw LE bytes; uint256{bytes} must equal the registry's asset_id,
        # which is FromHex(display-hex) = reversed bytes. So reverse the display hex.
        underlying = bytes.fromhex(asset_id)[::-1]
        leaf = self.build_leaf(contract_id=b"\x11" * 32, settle_lock=settle_lock, underlying=underlying,
                               feed_id=feed, fixing_ref=epoch, deadline=1_000_000,
                               strike=le(K, 32), fallback=le(95, 32), lambda_q=lambda_q,
                               loss_dir=0, vault_im=vault_im, owner_key=owner_key, cp_key=cp_key)
        tap, leaf_info = self.covenant(leaf)
        covenant_addr = self.nodes[0].decodescript(tap.scriptPubKey.hex())["address"]

        owner_pay, cp_pay = payout_strike_long(K, X, lambda_q, vault_im)
        self.log.info("formula payout: owner=%d cp=%d (sum=%d)", owner_pay, cp_pay, owner_pay + cp_pay)
        assert_equal(owner_pay + cp_pay, vault_im)
        assert_greater_than(owner_pay, MIN_SETTLE_OUTPUT)
        assert_greater_than(cp_pay, MIN_SETTLE_OUTPUT)
        correct_outs = [(owner_spk, owner_pay), (cp_spk, cp_pay)]

        # Two identical vaults, both funded BELOW activation (A passes every gate, B for the greedy try).
        self.log.info("funding two native vaults at the covenant address")
        vault_a = self.fund_vault(covenant_addr, Decimal(vault_im) / COIN)
        vault_b = self.fund_vault(covenant_addr, Decimal(vault_im) / COIN)
        assert_equal(vault_a[2], vault_im)

        # A SENTINEL covenant (OP_NOP10 OP_TRUE) isolates the flag transition from any fixing state:
        # it leaves exactly ONE element, so it SPENDS below activation (0xb9 is a NOP) and FAILS above
        # (0xb9 = OP_SCALAR_CFD_SETTLE then demands 16 operands on an empty stack). This proves
        # GetBlockScriptFlags toggles SCRIPT_VERIFY_SCALAR_CFD at the height, independent of publication.
        sentinel_leaf = CScript([OP_NOP10, OP_TRUE])
        tap_s, leaf_s = self.covenant(sentinel_leaf)
        sentinel_addr = self.nodes[0].decodescript(tap_s.scriptPubKey.hex())["address"]
        sentinel_a = self.fund_vault(sentinel_addr, Decimal(vault_im) / COIN)
        sentinel_b = self.fund_vault(sentinel_addr, Decimal(vault_im) / COIN)
        sink = bytes(address_to_scriptpubkey(self.w_issuer.getnewaddress()))

        # === ACTIVATION BOUNDARY (below): the flag is OFF, so 0xb9 is a NOP ===
        self.log.info("below activation: flag OFF — sentinel NOP-spend succeeds, real covenant is inert")
        assert_greater_than(SCALAR_CFD_HEIGHT, self.nodes[0].getblockcount() + 1)
        # Sentinel spends (NOP -> OP_TRUE -> single true element): proves SCRIPT_VERIFY_SCALAR_CFD is off.
        s_below = self.spend_leaf(sentinel_a, sentinel_leaf, tap_s, leaf_s, [(sink, vault_im)])
        blk0 = self.generateblock(self.nodes[0], miner_addr, [s_below.serialize().hex()], sync_fun=self.no_op)
        assert s_below.rehash() in self.nodes[0].getblock(blk0["hash"])["tx"]
        assert self.nodes[0].gettxout(sentinel_a[0], sentinel_a[1]) is None  # spent
        # The real covenant leaf, by contrast, leaves its 16 operands -> tapscript rejects (unsettleable).
        self.settle_and_reject(miner_addr, vault_a, leaf, tap, leaf_info, settle_lock, correct_outs)

        # === activate; the same sentinel leaf now FAILS (0xb9 is the active opcode, empty stack) ===
        self.mine_to(SCALAR_CFD_HEIGHT)
        self.log.info("at/above activation: flag ON — the sentinel NOP-spend now fails")
        s_above = self.spend_leaf(sentinel_b, sentinel_leaf, tap_s, leaf_s, [(sink, vault_im)])
        assert_raises_rpc_error(-25, None, self.generateblock, self.nodes[0], miner_addr,
                                [s_above.serialize().hex()], sync_fun=self.no_op)
        assert self.nodes[0].gettxout(sentinel_b[0], sentinel_b[1]) is not None  # not spent

        self.log.info("at/above activation: issuer publishes scalar X=%d", X)
        pol = self.nodes[0].getassetpolicy(asset_id)
        self.w_issuer.scalarpublish_raw(pol["icu_txid"], pol["icu_vout"], asset_id,
                                        self.w_issuer.getnewaddress(), BOND, feed, epoch, scalar_hex(X),
                                        RAW_U256_LE, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        pub_height = self.nodes[0].getblockcount()
        self.wait_until(lambda: self.nodes[0].scalargetfeed(asset_id, feed)["last_epoch"] == epoch)

        # === PREMATURE: published but not yet buried -> no snapshot entry -> reject (fails closed) ===
        self.log.info("premature settle (fixing not buried) is rejected")
        assert_greater_than(pub_height + MATURITY, self.nodes[0].getblockcount() + 1)
        self.settle_and_reject(miner_addr, vault_a, leaf, tap, leaf_info, settle_lock, correct_outs)

        # === bury the fixing, then HONEST keeper settlement of vault A ===
        self.log.info("burying the fixing (%d blocks), then honest keeper settlement", MATURITY)
        self.generate(self.nodes[0], MATURITY + 1)
        assert_greater_than(self.nodes[0].getblockcount(), pub_height + MATURITY)

        owner_before = self.w_owner.getreceivedbyaddress(owner_addr, 0)
        cp_before = self.w_cp.getreceivedbyaddress(cp_addr, 0)
        honest = self.settle_tx(vault_a[0], vault_a[1], leaf, tap, leaf_info, settle_lock, correct_outs)
        blk = self.generateblock(self.nodes[0], miner_addr, [honest.serialize().hex()], sync_fun=self.sync_all)
        settle_txid = honest.rehash()
        assert settle_txid in self.nodes[0].getblock(blk["hash"])["tx"]

        dec = self.nodes[0].getrawtransaction(settle_txid, True)
        legs = {v["scriptPubKey"]["hex"]: int(round(v["value"] * COIN)) for v in dec["vout"]}
        assert_equal(legs[owner_spk.hex()], owner_pay)
        assert_equal(legs[cp_spk.hex()], cp_pay)

        # Each distrusting party verifiably received exactly its formula leg, in its OWN wallet.
        self.sync_all()
        self.w_owner.syncwithvalidationinterfacequeue()
        self.w_cp.syncwithvalidationinterfacequeue()
        assert_equal(self.w_owner.getreceivedbyaddress(owner_addr, 0) - owner_before, Decimal(owner_pay) / COIN)
        assert_equal(self.w_cp.getreceivedbyaddress(cp_addr, 0) - cp_before, Decimal(cp_pay) / COIN)

        # === GREEDY keeper: pay the whole vault to the owner, starving cp -> consensus rejects ===
        self.log.info("greedy keeper (owner takes all) is rejected by the covenant")
        self.settle_and_reject(miner_addr, vault_b, leaf, tap, leaf_info, settle_lock, [(owner_spk, vault_im)])
        assert self.nodes[0].gettxout(vault_b[0], vault_b[1]) is not None  # vault B never connected


if __name__ == "__main__":
    ScalarSettleTest(__file__).main()
