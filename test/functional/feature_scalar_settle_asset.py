#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""OP_SCALAR_CFD_SETTLE with NON-NATIVE (asset) collateral — end-to-end (Slice 4c/4d).

Proves the validation PRODUCER path (the eval branch itself is unit-tested in scalar_cfd_eval_tests):
  * an asset-collateral vault (an AssetTag(C, vault_im) output at the OP_SCALAR_CFD_SETTLE covenant)
    SETTLES through ConnectBlock, paying each non-zero leg as AssetTag(C, leg) to the owner/cp keys
    (asset conservation delta=0, native dust funded from the vault's own native value, 0-fee);
  * a collateral asset WITHOUT the COLLATERAL_SAFE policy bit is REJECTED at settlement — the
    producer reads the real registry policy_bits, stages the policy single-threaded, and the opcode's
    CollateralPolicyGatePasses gate fails closed (SCALARCFD_COLLATERAL).

Scope note: the collateral GATE field-values (kyc/tfr/WRAP_REQUIRED) and the §5.1 collateral-safe
rotation-immutability rule are covered by UNIT tests (scalar_cfd_snapshot_tests::
collateral_policy_gate_verdict and asset_tests::collateral_safe_rotation_rule). Exercising those
functionally needs manual IssuerReg construction / a quorum+ballot rotation, disproportionate to the
already-proven pure logic; this test covers the producer wiring those units cannot reach.
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
    OP_1,
    OP_CHECKLOCKTIMEVERIFY,
    OP_DROP,
    OP_NOP10,  # == OP_SCALAR_CFD_SETTLE (0xb9)
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from asset_wallet_util import make_asset_tag_tlv

RAW_U256_LE = 1
BOND = 5.1
UNLOCK_SATS = 510000000
COIN = 100_000_000
MIN_SETTLE_OUTPUT = 546
LAMBDA_SCALE = 1 << 16
MATURITY = 100
SCALAR_CFD_HEIGHT = 160

# policy_bits: MINT_ALLOWED|BURN_ALLOWED = 0x03; COLLATERAL_SAFE = 0x40.
MINT_BURN = 0x03
COLLATERAL_SAFE = 0x40

NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def scalar_hex(n):
    return f"{n:064x}"


def le(n, width):
    return n.to_bytes(width, "little")


def asset_tag_bytes(asset_id_hex, units):
    """An ASSET_TAG (0x01) output vExt matching the on-chain encoding: the asset_id is stored in
    uint256-internal byte order (the reverse of the display hex), as BuildAssetTagTlv writes it."""
    internal = bytes.fromhex(asset_id_hex)[::-1]
    return bytes.fromhex(make_asset_tag_tlv(internal.hex(), units))


def parse_asset_tag(outext_hex):
    """Decode a raw outext hex (HexStr(vExt)) ASSET_TAG into (display_asset_id_hex, units) or None."""
    if not outext_hex:
        return None
    b = bytes.fromhex(outext_hex)
    if len(b) < 42 or b[0] != 0x01:
        return None
    display = bytes(reversed(b[2:34])).hex()
    return display, int.from_bytes(b[34:42], "little")


def payout_strike_long(K, X, lambda_q, vault_im, min_out=MIN_SETTLE_OUTPUT):
    """Mirror ComputeScalarCfdPayout for STRIKE-mode, long direction (loss when X < K)."""
    if not (X < K):
        return vault_im, 0
    lhs = (K - X) * lambda_q
    denom_scaled = K * LAMBDA_SCALE
    cp = vault_im if lhs >= denom_scaled else (lhs * vault_im) // denom_scaled
    owner = vault_im - cp
    if cp != 0 and cp < min_out:
        cp, owner = 0, vault_im
    elif owner != 0 and owner < min_out:
        owner, cp = 0, vault_im
    return owner, cp


class ScalarSettleAssetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_scalarasset".encode()).hexdigest()[:16]
        self.extra_args = [["-assetsheight=0", f"-scalarcfdheight={SCALAR_CFD_HEIGHT}",
                            "-acceptnonstdtxn=1", "-txindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- leaf / covenant ----
    def build_leaf(self, *, collateral, settle_lock, underlying, feed_id, fixing_ref, deadline,
                   strike, fallback, lambda_q, loss_dir, vault_im, owner_key, cp_key):
        return CScript([
            b"\x11" * 32, OP_DROP,
            b"\x01",
            le(settle_lock, 1), OP_CHECKLOCKTIMEVERIFY, OP_DROP,
            b"\x00",                                    # source_type = ISSUER_PUBLISHED
            underlying,
            le(feed_id, 4),
            le(fixing_ref, 8),
            le(deadline, 4),
            b"\x00",                                    # payoff_mode = STRIKE
            le(RAW_U256_LE, 2),
            strike,
            fallback,
            le(lambda_q, 4),
            bytes([loss_dir]),
            collateral,                                 # collateral_asset_id32 (C, NOT zero)
            le(vault_im, 8),
            owner_key, cp_key,
            OP_NOP10,
        ])

    def covenant(self, leaf):
        tap = taproot_construct(NUMS, [("settle", bytes(leaf))])
        return tap, tap.leaves["settle"]

    def register_and_mint(self, label, policy_bits, units):
        """Register a collateral asset with the given policy_bits and mint `units` to ourselves.
        Returns (asset_id, mint_outpoint, mint_native_sats, mint_spk)."""
        aid = hashlib.sha256(f"{label}_{self.test_run_id}".encode()).hexdigest()
        self.w.registerasset(self.w.getnewaddress(), BOND, aid, policy_bits, 28, UNLOCK_SATS,
                             None, 0, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(aid) is not None)
        pol = self.nodes[0].getassetpolicy(aid)
        # mint `units` via mintasset (ICU rotation + AssetTag output). policy_bits must match the
        # registered asset (the rotation keeps core_policy_commit). Arg order: icu_txid, icu_vout,
        # icu_address, icu_amount, asset_address, asset_amount_btc, asset_id, asset_units, ...
        asset_addr = self.w.getnewaddress("", "bech32")
        res = self.w.mintasset(pol["icu_txid"], pol["icu_vout"], self.w.getnewaddress(), BOND,
                               asset_addr, Decimal("0.05"), aid, units, policy_bits, 28, UNLOCK_SATS,
                               {"autofund": True, "broadcast": True, "fee_rate": 10})
        mint_txid = res["txid"] if isinstance(res, dict) else res
        self.generate(self.nodes[0], 1)
        dec = self.nodes[0].getrawtransaction(mint_txid, True)
        for v in dec["vout"]:
            tag = parse_asset_tag(v.get("outext"))
            if tag and tag[0] == aid:
                return aid, (mint_txid, v["n"]), int(round(v["value"] * COIN)), bytes.fromhex(v["scriptPubKey"]["hex"])
        raise AssertionError("minted asset output not found")

    def fund_asset_vault(self, aid, mint_op, mint_native, covenant_addr, vault_im, mint_units):
        """Spend the minted C-UTXO into a covenant vault carrying AssetTag(C, vault_im) + change."""
        vault_native = 20000  # plenty for two >=546 native-dust payout legs at 0-fee
        change_native = mint_native - vault_native - 2000  # 2000 sat fee
        change_addr = self.w.getnewaddress("", "bech32")
        raw = self.nodes[0].createrawtransaction(
            [{"txid": mint_op[0], "vout": mint_op[1]}],
            [{covenant_addr: Decimal(vault_native) / COIN}, {change_addr: Decimal(change_native) / COIN}])
        raw = self.nodes[0].rawtxattachassettag(raw, 0, aid, vault_im)
        raw = self.nodes[0].rawtxattachassettag(raw, 1, aid, mint_units - vault_im)
        signed = self.w.signrawtransactionwithwallet(raw)
        txid = self.nodes[0].sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1)
        dec = self.nodes[0].getrawtransaction(txid, True)
        for v in dec["vout"]:
            if v["scriptPubKey"].get("address") == covenant_addr:
                return txid, v["n"], int(round(v["value"] * COIN))
        raise AssertionError("covenant vault output not found")

    def settle_tx(self, vault, leaf, tap, leaf_info, settle_lock, aid, legs):
        """Spend the vault (script-path), emitting AssetTag(C, leg) outputs. legs = [(spk, units), ...]."""
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = settle_lock
        tx.vin.append(CTxIn(COutPoint(uint256_from_str(bytes.fromhex(vault[0])[::-1]), vault[1]), nSequence=0))
        native_each = vault[2] // max(1, len(legs))
        for spk, units in legs:
            o = CTxOut(native_each, spk)
            o.vExt = asset_tag_bytes(aid, units)
            tx.vout.append(o)
        control = bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf), control]
        tx.rehash()
        return tx

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="")
        self.w = self.nodes[0].get_wallet_rpc("")
        miner = self.w.getnewaddress()
        # Mine above activation with headroom for publication + burial.
        self.generatetoaddress(self.nodes[0], SCALAR_CFD_HEIGHT + 5, miner)

        # --- oracle asset U + published scalar ---
        u_aid = hashlib.sha256(f"oracle_{self.test_run_id}".encode()).hexdigest()
        feed, epoch, K, X = 7, 1, 100, 90
        lambda_q = 1 * LAMBDA_SCALE
        self.w.registerasset(self.w.getnewaddress(), BOND, u_aid, MINT_BURN, 28, UNLOCK_SATS,
                             "ORCL", 8, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(u_aid) is not None)
        upol = self.nodes[0].getassetpolicy(u_aid)
        self.w.scalarpublish_raw(upol["icu_txid"], upol["icu_vout"], u_aid, self.w.getnewaddress(),
                                 BOND, feed, epoch, scalar_hex(X), RAW_U256_LE,
                                 {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        pub_height = self.nodes[0].getblockcount()
        self.wait_until(lambda: self.nodes[0].scalargetfeed(u_aid, feed)["last_epoch"] == epoch)

        # --- collateral asset C (COLLATERAL_SAFE) + mint ---
        # vault_im large enough (in C units) that BOTH legs clear the 546-unit dust floor: with
        # f_loss=0.1 (K=100,X=90,lambda=1) cp=0.1*vault_im, owner=0.9*vault_im.
        units = 20000
        vault_im = 10000
        c_aid, c_op, c_native, _ = self.register_and_mint("collat_ok", MINT_BURN | COLLATERAL_SAFE, units)

        owner_addr = self.w.getnewaddress(address_type="bech32m")
        cp_addr = self.w.getnewaddress(address_type="bech32m")
        owner_key = bytes.fromhex(self.w.getaddressinfo(owner_addr)["witness_program"])
        cp_key = bytes.fromhex(self.w.getaddressinfo(cp_addr)["witness_program"])
        owner_spk = CScript([OP_1, owner_key])
        cp_spk = CScript([OP_1, cp_key])

        underlying = bytes.fromhex(u_aid)[::-1]
        collateral = bytes.fromhex(c_aid)[::-1]
        settle_lock = 1
        leaf = self.build_leaf(collateral=collateral, settle_lock=settle_lock, underlying=underlying,
                               feed_id=feed, fixing_ref=epoch, deadline=1_000_000, strike=le(K, 32),
                               fallback=le(95, 32), lambda_q=lambda_q, loss_dir=0, vault_im=vault_im,
                               owner_key=owner_key, cp_key=cp_key)
        tap, leaf_info = self.covenant(leaf)
        covenant_addr = self.nodes[0].decodescript(tap.scriptPubKey.hex())["address"]

        owner_pay, cp_pay = payout_strike_long(K, X, lambda_q, vault_im)
        assert_equal(owner_pay + cp_pay, vault_im)
        self.log.info("asset payout legs: owner=%d cp=%d (units of C)", owner_pay, cp_pay)

        vault = self.fund_asset_vault(c_aid, c_op, c_native, covenant_addr, vault_im, units)

        # bury the fixing
        self.generate(self.nodes[0], MATURITY + 1)
        assert_greater_than(self.nodes[0].getblockcount(), pub_height + MATURITY)

        # === HONEST asset settlement ===
        self.log.info("honest asset-collateral settlement through ConnectBlock")
        legs = [(owner_spk, owner_pay), (cp_spk, cp_pay)]
        legs = [(spk, u) for spk, u in legs if u > 0]
        tx = self.settle_tx(vault, leaf, tap, leaf_info, settle_lock, c_aid, legs)
        blk = self.generateblock(self.nodes[0], miner, [tx.serialize().hex()], sync_fun=self.no_op)
        assert tx.rehash() in self.nodes[0].getblock(blk["hash"])["tx"]
        # each leg landed as AssetTag(C, leg) at the right key
        dec = self.nodes[0].getrawtransaction(tx.rehash(), True)
        seen = {}
        for v in dec["vout"]:
            tag = parse_asset_tag(v.get("outext"))
            if tag and tag[0] == c_aid:
                seen[v["scriptPubKey"]["hex"]] = tag[1]
        # Each non-zero leg lands as AssetTag(C, leg) at its key; a zero (dust-snapped) leg emits none.
        for spk_hex, pay in ((owner_spk.hex(), owner_pay), (cp_spk.hex(), cp_pay)):
            if pay > 0:
                assert_equal(seen.get(spk_hex), pay)
            else:
                assert spk_hex not in seen
        assert_greater_than(owner_pay, 0)
        assert_greater_than(cp_pay, 0)  # this test is configured for a genuine two-leg split
        assert self.nodes[0].gettxout(vault[0], vault[1]) is None  # vault spent

        # === GATE: a collateral asset WITHOUT COLLATERAL_SAFE is rejected ===
        self.log.info("collateral asset without COLLATERAL_SAFE bit is rejected at settlement")
        nb_aid, nb_op, nb_native, _ = self.register_and_mint("collat_nobit", MINT_BURN, units)
        nb_collateral = bytes.fromhex(nb_aid)[::-1]
        nb_leaf = self.build_leaf(collateral=nb_collateral, settle_lock=settle_lock, underlying=underlying,
                                  feed_id=feed, fixing_ref=epoch, deadline=1_000_000, strike=le(K, 32),
                                  fallback=le(95, 32), lambda_q=lambda_q, loss_dir=0, vault_im=vault_im,
                                  owner_key=owner_key, cp_key=cp_key)
        nb_tap, nb_info = self.covenant(nb_leaf)
        nb_addr = self.nodes[0].decodescript(nb_tap.scriptPubKey.hex())["address"]
        nb_vault = self.fund_asset_vault(nb_aid, nb_op, nb_native, nb_addr, vault_im, units)
        nb_tx = self.settle_tx(nb_vault, nb_leaf, nb_tap, nb_info, settle_lock, nb_aid, legs)
        assert_raises_rpc_error(-25, None, self.generateblock, self.nodes[0], miner,
                                [nb_tx.serialize().hex()], sync_fun=self.no_op)
        assert self.nodes[0].gettxout(nb_vault[0], nb_vault[1]) is not None  # vault NOT spent

        self.log.info("asset-collateral settle + no-bit gate rejection: PASS")


if __name__ == "__main__":
    ScalarSettleAssetTest(__file__).main()
