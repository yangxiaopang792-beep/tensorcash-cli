#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end functional test for the scalar note-pair securitisation RPCs (CFD_GENERALISATION.md §6/§7,
Slice 5h). Drives the whole securitisation lifecycle through the new wallet RPCs on a live regtest node:

    scalar.build_register  -> batch-register both L and S coupon children under a root
    scalar.build_issue     -> atomic dual-mint (N L + N S) + fund N asset-C vaults
    scalar.record_issue    -> persist the wallet record
    scalar.list            -> read it back
    scalar.build_settlement-> keeper settles one vault; the long/short pots receive their C legs
    scalar.build_redeem    -> redeem L vs the long pot and S vs the short pot (reclaim collateral)
    scalar.build_unwind    -> permissionless complete-set collapse of an UNSETTLED vault

Each tx is built with broadcast=false and mined via generateblock (full ConnectBlock validation, bypassing
relay-standardness) — a mined block is the end-to-end proof that the RPC built a consensus-valid tx.
"""
import hashlib
import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

RAW_U256_LE = 1
BOND = 5.1
UNLOCK_SATS = 510000000
COIN = 100_000_000
LAMBDA_SCALE = 1 << 16
MATURITY = 100
SCALAR_CFD_HEIGHT = 160
MINT_BURN = 0x03
COLLATERAL_SAFE = 0x40


def scalar_hex(n):
    return f"{n:064x}"


def parse_asset_tag(outext_hex):
    """Decode a raw outext hex ASSET_TAG into (display_asset_id_hex, units) or None."""
    if not outext_hex:
        return None
    b = bytes.fromhex(outext_hex)
    if len(b) < 42 or b[0] != 0x01:
        return None
    return bytes(reversed(b[2:34])).hex(), int.from_bytes(b[34:42], "little")


class ScalarNotePairTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # scalarcfdheight=SCALAR_CFD_HEIGHT activates the opcode; -txindex for getrawtransaction.
        self.extra_args = [["-txindex", f"-scalarcfdheight={SCALAR_CFD_HEIGHT}"]]
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_scalarnotepair".encode()).hexdigest()[:16]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_hex(self, hex_tx):
        """Mine ONE block containing exactly the given raw tx; returns its txid. A rejection (consensus
        invalid) raises, so a successful return proves the tx is valid under full block validation."""
        self.generateblock(self.nodes[0], self.miner, [hex_tx])
        # The txid is the double-SHA of the tx; easier: decode to read it back.
        return self.nodes[0].decoderawtransaction(hex_tx)["txid"]

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="")
        self.w = self.nodes[0].get_wallet_rpc("")
        self.miner = self.w.getnewaddress()
        self.generatetoaddress(self.nodes[0], SCALAR_CFD_HEIGHT + 5, self.miner)

        rid = self.test_run_id
        feed, epoch, K, X = 7, 1, 100, 90
        lambda_q = 1 * LAMBDA_SCALE
        N = 2
        vault_im = 10000

        # --- oracle asset U + published scalar X ---
        u_aid = hashlib.sha256(f"np_oracle_{rid}".encode()).hexdigest()
        self.w.registerasset(self.w.getnewaddress(), BOND, u_aid, MINT_BURN, 28, UNLOCK_SATS,
                             "ORCL", 8, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        upol = self.nodes[0].getassetpolicy(u_aid)
        self.w.scalarpublish_raw(upol["icu_txid"], upol["icu_vout"], u_aid, self.w.getnewaddress(),
                                 BOND, feed, epoch, scalar_hex(X), RAW_U256_LE,
                                 {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        pub_height = self.nodes[0].getblockcount()

        # --- root asset (sponsors the L/S children) ---
        root_aid = hashlib.sha256(f"np_root_{rid}".encode()).hexdigest()
        self.w.registerasset(self.w.getnewaddress(), BOND, root_aid, MINT_BURN, 28, UNLOCK_SATS,
                             "ACME", 0, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)

        # --- collateral asset C (COLLATERAL_SAFE) + mint enough for N vaults ---
        c_aid = hashlib.sha256(f"np_collat_{rid}".encode()).hexdigest()
        self.w.registerasset(self.w.getnewaddress(), BOND, c_aid, MINT_BURN | COLLATERAL_SAFE, 28, UNLOCK_SATS,
                             None, 0, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)
        cpol = self.nodes[0].getassetpolicy(c_aid)
        self.w.mintasset(cpol["icu_txid"], cpol["icu_vout"], self.w.getnewaddress(), BOND,
                         self.w.getnewaddress("", "bech32"), Decimal("0.05"), c_aid, 25000,
                         MINT_BURN | COLLATERAL_SAFE, 28, UNLOCK_SATS,
                         {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(self.nodes[0], 1)

        terms = {
            "source_type": 0, "payoff_mode": 0, "loss_direction": 0,
            "underlying_asset_id": u_aid, "feed_id": feed, "fixing_ref": epoch,
            "publication_deadline_height": 1_000_000, "settle_lock_height": 1,
            "scalar_format_id": RAW_U256_LE, "strike": scalar_hex(K), "fallback_scalar": scalar_hex(95),
            "lambda_q": lambda_q, "collateral_asset_id": c_aid, "vault_im": vault_im,
            "lot_count": N, "series_salt": "ee" * 32,
        }

        # === REGISTER: one batch tx creates both L and S coupon children ===
        self.log.info("scalar.build_register: batch-register L and S children")
        reg = self.w.scalar.build_register(terms, "ACME", "U6L", "U6S", {"broadcast": False, "fee_rate": 10})
        pair_id, l_id, s_id = reg["pair_id"], reg["long_token_id"], reg["short_token_id"]
        register_txid = self.mine_hex(reg["hex"])
        lpol = self.nodes[0].getassetpolicy(l_id)
        spol = self.nodes[0].getassetpolicy(s_id)
        assert lpol is not None and spol is not None, "L/S children not registered"
        assert_equal(self.nodes[0].getassetpolicy(l_id)["issued_total"], 0)
        assert_equal(self.nodes[0].getassetpolicy(s_id)["issued_total"], 0)

        # === ISSUE: atomic dual-mint + N asset-C vaults ===
        self.log.info("scalar.build_issue: mint N L + N S and fund N vaults")
        iss = self.w.scalar.build_issue(terms, {"broadcast": False, "fee_rate": 10, "vault_native_sats": 20000})
        assert_equal(iss["lot_count"], N)
        assert_equal(len(iss["vault_spks"]), N)
        issue_txid = self.mine_hex(iss["hex"])
        assert_equal(self.nodes[0].getassetpolicy(l_id)["issued_total"], N)
        assert_equal(self.nodes[0].getassetpolicy(s_id)["issued_total"], N)

        # === RECORD + LIST ===
        self.log.info("scalar.record_issue + scalar.list")
        rec = self.w.scalar.record_issue(terms, issue_txid, register_txid)
        assert_equal(rec["persisted"], True)
        assert_equal(len(rec["lot_vaults"]), N)
        listed = self.w.scalar.list()
        assert_equal(len(listed), 1)
        assert_equal(listed[0]["pair_id"], pair_id)
        assert_equal(listed[0]["lot_count"], N)
        lot_vaults = rec["lot_vaults"]  # ["txid:vout", ...] in lot order

        # bury the published fixing for settlement
        self.generate(self.nodes[0], MATURITY + 1)
        assert_greater_than(self.nodes[0].getblockcount(), pub_height + MATURITY)

        # === SETTLE lot 0: long/short pots receive their C legs ===
        self.log.info("scalar.build_settlement: settle lot 0")
        st = self.w.scalar.build_settlement(terms, 0, lot_vaults[0], {"broadcast": False, "fee_rate": 10})
        assert_equal(st["is_fallback"], False)
        owner_pay, cp_pay = int(st["payout_owner"]), int(st["payout_cp"])
        assert_equal(owner_pay + cp_pay, vault_im)
        assert_greater_than(owner_pay, cp_pay)  # X<K: long (owner) keeps the larger share
        settle_txid = self.mine_hex(st["hex"])
        # vout 0 = owner (long) pot, vout 1 = cp (short) pot — deterministic build order.
        dec = self.nodes[0].getrawtransaction(settle_txid, True)
        assert_equal(parse_asset_tag(dec["vout"][0].get("outext")), (c_aid, owner_pay))
        assert_equal(parse_asset_tag(dec["vout"][1].get("outext")), (c_aid, cp_pay))

        # === REDEEM: L vs the long pot, S vs the short pot ===
        self.log.info("scalar.build_redeem: redeem L (long) then S (short)")
        rl = self.w.scalar.build_redeem(terms, True, [{"lot_index": 0, "pot": f"{settle_txid}:0"}],
                                        {"broadcast": False, "fee_rate": 10})
        assert_equal(rl["units_retired"], 1)
        self.mine_hex(rl["hex"])
        rs = self.w.scalar.build_redeem(terms, False, [{"lot_index": 0, "pot": f"{settle_txid}:1"}],
                                        {"broadcast": False, "fee_rate": 10})
        assert_equal(rs["units_retired"], 1)
        self.mine_hex(rs["hex"])

        # === UNWIND: permissionless complete-set collapse of the UNSETTLED lot 1 ===
        self.log.info("scalar.build_unwind: complete-set collapse of lot 1")
        uw = self.w.scalar.build_unwind(terms, 1, lot_vaults[1], {"broadcast": False, "fee_rate": 10})
        assert_equal(uw["lot_index"], 1)
        unwind_txid = self.mine_hex(uw["hex"])
        # the unwind reclaims the FULL collateral as a single AssetTag(C, vault_im) output.
        udec = self.nodes[0].getrawtransaction(unwind_txid, True)
        reclaimed = [parse_asset_tag(v.get("outext")) for v in udec["vout"]]
        assert (c_aid, vault_im) in reclaimed, "unwind did not reclaim the full collateral"

        self.log.info("scalar note-pair lifecycle (register -> issue -> record -> settle -> redeem -> unwind) OK")


if __name__ == "__main__":
    ScalarNotePairTest(__file__).main()
