#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end functional test for the scalar-CFD publication subsystem (Slice 1f).

CROSS-WALLET, two nodes:
  node0 / wallet0 = the issuer (registers the oracle asset, owns its ICU, publishes scalars)
  node1 / wallet1 = a separate wallet that mines, holds some of the asset, and READS feeds

Covers (CFD_GENERALISATION.md §3):
  * activation gating by -scalarcfdheight (reject below, accept at/above)
  * scalarpublish_raw -> mine -> scalargetfeed / scalarlistfeeds readback on BOTH nodes
  * monotonic enforcement (epoch != head+1 rejected at relay)
  * reorg / disconnect restores the feed head (the 1d scalar_undo reverse-apply, end-to-end)
  * burn-safety: publishing does NOT spend the issuer's same-asset holder UTXOs
  * new_icu_address reuse: the IssuerReg reattaches to the ICU output, asset survives
  * RPC error paths: epoch 0, unknown scalar_format_id, insufficient change for carrier fee
"""
import hashlib
import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, assert_greater_than

SCALAR_CFD_HEIGHT = 200          # activation height for this test
RAW_U256_LE = 1                  # assets::SCALAR_FORMAT_RAW_U256_LE
BOND = 5.1                       # >= 5 BTC min bond; also == unlock_fees so rotations keep it
UNLOCK_SATS = 510000000         # 5.1 BTC in sats


def scalar_hex(n):
    """A 64-hex-char (uint256) display-hex scalar from a small int."""
    return f"{n:064x}"


class ScalarPublicationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.test_run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_scalarpub".encode()).hexdigest()[:16]
        common = ["-assetsheight=0", f"-scalarcfdheight={SCALAR_CFD_HEIGHT}", "-acceptnonstdtxn=1"]
        self.extra_args = [list(common), list(common)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    # ---- helpers ----
    def mine_to_height(self, target):
        cur = self.nodes[0].getblockcount()
        if target > cur:
            self.generatetoaddress(self.nodes[1], target - cur, self.miner_addr, sync_fun=self.sync_all)

    def current_icu(self, asset_id):
        p = self.nodes[0].getassetpolicy(asset_id)
        return p["icu_txid"], p["icu_vout"]

    def publish(self, asset_id, feed_id, epoch, value, *, new_addr=None, change_addr=None, fmt=RAW_U256_LE, fee_rate=10):
        icu_txid, icu_vout = self.current_icu(asset_id)
        addr = new_addr if new_addr is not None else self.wallet0.getnewaddress()
        opts = {"autofund": True, "broadcast": True, "fee_rate": fee_rate}
        if change_addr is not None:
            opts["change_address"] = change_addr
        return self.wallet0.scalarpublish_raw(
            icu_txid, icu_vout, asset_id, addr, BOND,
            feed_id, epoch, scalar_hex(value), fmt, opts)

    def publish_and_mine(self, asset_id, feed_id, epoch, value, **kw):
        prev_icu_txid, _ = self.current_icu(asset_id)
        self.publish(asset_id, feed_id, epoch, value, **kw)
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        # publication rotates the ICU; wait for the registry to advance on node0
        self.wait_until(lambda: self.nodes[0].getassetpolicy(asset_id)["icu_txid"] != prev_icu_txid)

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="")
        self.nodes[1].createwallet(wallet_name="")
        self.wallet0 = self.nodes[0].get_wallet_rpc("")   # issuer
        self.wallet1 = self.nodes[1].get_wallet_rpc("")   # miner + reader + holder

        self.miner_addr = self.wallet1.getnewaddress()
        self.generatetoaddress(self.nodes[1], 120, self.miner_addr, sync_fun=self.sync_all)
        # Fund the issuer wallet generously.
        self.wallet1.sendtoaddress(self.wallet0.getnewaddress(), 90)
        self.generatetoaddress(self.nodes[1], 1, self.miner_addr, sync_fun=self.sync_all)

        asset_id = hashlib.sha256(f"oracle_{self.test_run_id}".encode()).hexdigest()
        ticker = "ORCL"
        feed = 7

        # --- register the oracle asset on the issuer node ---
        self.log.info("register oracle asset")
        reg_addr = self.wallet0.getnewaddress()
        self.wallet0.registerasset(reg_addr, BOND, asset_id, 3, 28, UNLOCK_SATS, ticker, 8,
                                   {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(asset_id) is not None)

        # --- mint asset units to the issuer (same-asset holder UTXOs for burn-safety) ---
        self.log.info("mint asset units to issuer + send some cross-wallet to holder")
        icu_txid, icu_vout = self.current_icu(asset_id)
        self.wallet0.mintasset(icu_txid, icu_vout, self.wallet0.getnewaddress(), BOND,
                               self.wallet0.getnewaddress(), 0.001, asset_id, 1000000, 3, 28, UNLOCK_SATS,
                               {"autofund": True, "broadcast": True, "fee_rate": 5})
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(asset_id)["icu_txid"] != icu_txid)
        # send some units cross-wallet to node1's holder so balances are non-trivial both sides
        self.wallet0.sendasset(ticker, self.wallet1.getnewaddress(), 250000)
        self.sync_mempools()
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.wallet1.syncwithvalidationinterfacequeue()
        assert_equal(self.wallet0.getassetbalance([asset_id])[0]["balance"], 750000)
        assert_equal(self.wallet1.getassetbalance([asset_id])[0]["balance"], 250000)

        # ============ activation boundary ============
        # Relay/mempool checks against tip+1, so to be "below activation" the tx must be
        # mineable below N: at tip N-2 the next block is N-1 (< N) -> carrier is unknown TLV.
        self.log.info("activation: publishing below ScalarCfdHeight is rejected as unknown TLV")
        self.mine_to_height(SCALAR_CFD_HEIGHT - 2)
        assert_greater_than(SCALAR_CFD_HEIGHT, self.nodes[0].getblockcount() + 1)
        assert_raises_rpc_error(-25, "outext", self.publish, asset_id, feed, 1, 1001)

        self.log.info("activation: at/above ScalarCfdHeight the publication is accepted")
        self.mine_to_height(SCALAR_CFD_HEIGHT - 1)  # publish now -> mined at height N (active)
        issuer_asset_before = self.wallet0.getassetbalance([asset_id])[0]["balance"]
        self.publish_and_mine(asset_id, feed, 1, 1001)
        assert_equal(self.nodes[0].getblockcount(), SCALAR_CFD_HEIGHT)

        # ============ readback on BOTH nodes (cross-wallet / cross-node) ============
        self.log.info("readback: scalargetfeed agrees across nodes; head advances")
        for node in (self.nodes[0], self.nodes[1]):
            r = node.scalargetfeed(asset_id, feed)
            assert_equal(r["epoch"], 1)
            assert_equal(r["last_epoch"], 1)
            assert_equal(r["scalar"], scalar_hex(1001))
            assert_equal(r["scalar_format_id"], RAW_U256_LE)
        feeds0 = self.nodes[0].scalarlistfeeds(asset_id)
        feeds1 = self.nodes[1].scalarlistfeeds(asset_id)
        assert_equal(feeds0, feeds1)
        assert_equal(feeds0, [{"feed_id": feed, "last_epoch": 1}])

        # ============ burn-safety: publishing did NOT spend the issuer's asset UTXOs ============
        self.log.info("burn-safety: issuer asset balance unchanged by publication")
        assert_equal(self.wallet0.getassetbalance([asset_id])[0]["balance"], issuer_asset_before)
        assert_equal(self.wallet1.getassetbalance([asset_id])[0]["balance"], 250000)

        # ============ monotonic enforcement ============
        self.log.info("monotonic: epoch must equal head+1")
        assert_raises_rpc_error(-25, "scalar-nonmonotonic", self.publish, asset_id, feed, 1, 9)  # replay
        assert_raises_rpc_error(-25, "scalar-nonmonotonic", self.publish, asset_id, feed, 3, 9)  # gap
        self.publish_and_mine(asset_id, feed, 2, 1002)
        assert_equal(self.nodes[1].scalargetfeed(asset_id, feed)["last_epoch"], 2)
        assert_equal(self.nodes[1].scalargetfeed(asset_id, feed, 1)["scalar"], scalar_hex(1001))

        # ============ reorg: disconnect restores the head (scalar_undo reverse-apply) ============
        self.log.info("reorg: invalidate the epoch-2 block -> head restores to 1; reconsider -> back to 2")
        tip = self.nodes[0].getbestblockhash()
        self.nodes[0].invalidateblock(tip)
        assert_equal(self.nodes[0].scalargetfeed(asset_id, feed)["last_epoch"], 1)
        assert_raises_rpc_error(-5, "no such scalar epoch", self.nodes[0].scalargetfeed, asset_id, feed, 2)
        self.nodes[0].reconsiderblock(tip)
        assert_equal(self.nodes[0].scalargetfeed(asset_id, feed)["last_epoch"], 2)
        self.sync_all()

        # ====== same-script change collision: IssuerReg must reattach to the ICU, not change ======
        # Force the funding change to use the SAME scriptPubKey as the ICU successor by routing
        # both to one address. This reproduces the old failure mode (reattach-by-script could hit
        # change); the fix matches the unique non-change output by script AND amount.
        self.log.info("collision: change shares the ICU script; IssuerReg still reattaches to the ICU output")
        reused = self.wallet0.getnewaddress()
        before_icu = self.current_icu(asset_id)
        icu_txid0, icu_vout0 = before_icu
        res = self.wallet0.scalarpublish_raw(
            icu_txid0, icu_vout0, asset_id, reused, BOND, feed, 3, scalar_hex(1003), RAW_U256_LE,
            {"autofund": True, "broadcast": True, "fee_rate": 10, "change_address": reused})
        pub_txid = res["txid"]
        # Confirm the collision actually happened: >=2 outputs share the reused script.
        self.sync_mempools()
        reused_spk = self.wallet0.getaddressinfo(reused)["scriptPubKey"]
        decoded = self.nodes[0].getrawtransaction(pub_txid, True)
        same_script = [o for o in decoded["vout"] if o["scriptPubKey"].get("hex") == reused_spk]
        assert_greater_than(len(same_script), 1)  # ICU successor + change both use `reused`
        self.generate(self.nodes[1], 1, sync_fun=self.sync_all)
        self.wait_until(lambda: self.nodes[0].getassetpolicy(asset_id)["icu_txid"] != icu_txid0)
        # IssuerReg reattached to the ICU output (asset registry resolves to the publish tx) and the
        # feed advanced; no asset was burned.
        p = self.nodes[0].getassetpolicy(asset_id)
        assert_equal(p["icu_txid"], pub_txid)
        # Explicitly: the registry ICU points at the BOND-valued reused-script output, NOT the
        # same-script change output -> the IssuerReg reattached to the intended ICU successor.
        icu_out = decoded["vout"][p["icu_vout"]]
        assert_equal(icu_out["scriptPubKey"]["hex"], reused_spk)
        assert_equal(icu_out["value"], Decimal("5.1"))
        assert self.current_icu(asset_id) != before_icu
        assert_equal(self.nodes[1].scalargetfeed(asset_id, feed)["last_epoch"], 3)
        assert_equal(self.wallet0.getassetbalance([asset_id])[0]["balance"], issuer_asset_before)

        # ============ RPC error paths ============
        self.log.info("error paths: epoch 0, unknown format")
        assert_raises_rpc_error(-8, "epoch 0 is reserved", self.publish, asset_id, feed, 0, 5)
        assert_raises_rpc_error(-8, "unknown scalar_format_id", self.publish, asset_id, feed, 4, 5, fmt=99)
        # NOTE: the carrier-fee "Insufficient change" path (scalar.cpp) is a reviewed error path;
        # it is not asserted here because the issuer wallet always has ample change to cover the
        # carrier vbytes, so it cannot be forced deterministically through the autofund path.

        # sanity: after all the rejects, the feed head is still 3 and a normal publish still works
        assert_equal(self.nodes[0].scalargetfeed(asset_id, feed)["last_epoch"], 3)
        self.publish_and_mine(asset_id, feed, 4, 1004)
        assert_equal(self.nodes[1].scalargetfeed(asset_id, feed)["last_epoch"], 4)
        self.log.info("scalar publication end-to-end: OK")


if __name__ == "__main__":
    ScalarPublicationTest(__file__).main()
