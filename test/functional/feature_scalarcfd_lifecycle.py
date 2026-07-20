#!/usr/bin/env python3
# Copyright (c) 2026 The Tensorcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Two-party bilateral lifecycle test for the scalar CFD (CFD_GENERALISATION.md §7, Slice 5f-7).

Two DISTINCT wallets (alice = LONG / proposer + feed issuer, bob = SHORT / acceptor) run the full
scalarcfd.* lifecycle with NO coordinator, the underlying being an issuer-published FX cross rate X:

  propose -> accept -> import_acceptance  (both wallets derive + persist the SAME contract_id)
  -> co-signed ATOMIC open (each funds ONLY its own native IM vault; one tx) -> record_open (both)
  -> scalarcfd.price (mark to market off the chain scalar) -> bury the fixing
  -> unilateral settlement by EITHER party (bob settles long, alice settles short) via
     build_settlement + finalize_settlement (the committed-covenant extract guard)
  -> on a second contract: cooperative 2-of-2 close (build_coop_close + sign_coop x2)
  -> ADVERSARIAL: mutating the coop outputs after the first signature yields a tx the network rejects
     (the first signature no longer validates over the mutated transaction).

X = 90 vs strike K = 100 (long-loss): the long owner loses lambda*(K-X)/K = 10% of its IM to the short.
"""
import hashlib
import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.psbt import PSBT, PSBT_GLOBAL_UNSIGNED_TX

COIN = 100_000_000
RAW_U256_LE = 1
BOND = 5.1
UNLOCK_SATS = 510000000
MINT_BURN = 0x03
MATURITY = 100
SCALAR_CFD_HEIGHT = 160
LAMBDA_SCALE = 1 << 16


def scalar_hex(n):
    return f"{n:064x}"


def sats(amount_btc):
    return int(round(Decimal(str(amount_btc)) * COIN))


class ScalarCfdLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # NO -acceptnonstdtxn: open + settlement must relay under STANDARD policy.
        self.extra_args = [["-txindex", f"-scalarcfdheight={SCALAR_CFD_HEIGHT}"]]
        self.rid = hashlib.sha256(f"{os.getpid()}_{time.time()}_scalarcfd".encode()).hexdigest()[:16]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_terms(self, u_aid, feed, epoch, settle_lock, im_btc):
        return {
            "source_type": 0, "payoff_mode": 0,
            "underlying_asset_id": u_aid, "feed_id": feed, "fixing_ref": epoch,
            "publication_deadline_height": 1_000_000, "settle_lock_height": settle_lock,
            "scalar_format_id": RAW_U256_LE, "strike": scalar_hex(100), "fallback_scalar": scalar_hex(95),
            "long": {"im": str(sats(im_btc)), "lambda_q": LAMBDA_SCALE},   # native collateral (no collateral_asset_id)
            "short": {"im": str(sats(im_btc)), "lambda_q": LAMBDA_SCALE},
        }

    def open_contract(self, terms):
        """propose -> accept -> import -> co-signed open -> record_open in both wallets. Returns contract_id."""
        a, b, node = self.alice, self.bob, self.nodes[0]
        a_owner = a.getnewaddress("", "bech32m"); a_cp = a.getnewaddress("", "bech32m")
        b_owner = b.getnewaddress("", "bech32m"); b_cp = b.getnewaddress("", "bech32m")

        offer = a.scalarcfd.propose(terms, "long", a_owner, a_cp)["offer"]
        review = b.scalarcfd.accept(offer, b_owner, b_cp)
        assert "acceptance" not in review and "action_required" in review
        accepted = b.scalarcfd.accept(offer, b_owner, b_cp, {"confirmed": True})
        cid = accepted["contract_id"]
        imported = a.scalarcfd.import_acceptance(offer, accepted["acceptance"])
        assert_equal(imported["contract_id"], cid)
        assert_equal(imported["state"], "accepted")

        a_open = a.scalarcfd.build_open(cid, "long")
        assert_equal(a_open["leg"], "long")
        b_open = b.scalarcfd.build_open(cid, "short", {"psbt": a_open["psbt"]})
        a_signed = a.walletprocesspsbt(b_open["psbt"], True)
        b_signed = b.walletprocesspsbt(a_signed["psbt"], True)
        final = b.finalizepsbt(b_signed["psbt"])
        assert_equal(final["complete"], True)
        open_txid = node.sendrawtransaction(final["hex"])
        self.generate(node, 1)
        a.scalarcfd.record_open(cid, open_txid)
        b.scalarcfd.record_open(cid, open_txid)
        # record_open is idempotent for the same tx; a different tx is rejected.
        b.scalarcfd.record_open(cid, open_txid)
        return cid, (a_owner, a_cp, b_owner, b_cp)

    def covenant_settle(self, signer, psbt_b64):
        # Sign the keeper fee input, extract via finalize_settlement (the committed-covenant guard), then
        # mine via generateblock: the OP_SCALAR_CFD_SETTLE fixing resolves under the block's context (the
        # mempool-relay path can be a block behind), so settlements are mined directly — full ConnectBlock
        # validation, the same path the other scalar functional tests use.
        processed = signer.walletprocesspsbt(psbt_b64, True)
        hex_tx = signer.scalarcfd.finalize_settlement(processed["psbt"])["hex"]
        self.generateblock(self.nodes[0], signer.getnewaddress(), [hex_tx])
        return hex_tx

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice", descriptors=True)
        node.createwallet("bob", descriptors=True)
        self.alice = node.get_wallet_rpc("alice")
        self.bob = node.get_wallet_rpc("bob")
        a, b = self.alice, self.bob
        self.generatetoaddress(node, 150, a.getnewaddress())
        self.generatetoaddress(node, 150, b.getnewaddress())
        a.rescanblockchain(); b.rescanblockchain()

        # --- oracle feed: alice registers U and publishes X=90 at the fixing epoch ---
        feed, epoch, X = 7, 1, 90
        u_aid = hashlib.sha256(f"cfd_oracle_{self.rid}".encode()).hexdigest()
        a.registerasset(a.getnewaddress(), BOND, u_aid, MINT_BURN, 28, UNLOCK_SATS, "ORCL", 8,
                        {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(node, 1)
        upol = node.getassetpolicy(u_aid)
        a.scalarpublish_raw(upol["icu_txid"], upol["icu_vout"], u_aid, a.getnewaddress(), BOND, feed, epoch,
                            scalar_hex(X), RAW_U256_LE, {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(node, 1)
        pub_height = node.getblockcount()
        settle_lock = pub_height + MATURITY + 5

        im_btc = 2
        im = sats(im_btc)
        terms = self.make_terms(u_aid, feed, epoch, settle_lock, im_btc)

        # === SETTLEMENT CONTRACT: full lifecycle through unilateral settlement ===
        self.log.info("propose -> accept -> import -> co-signed open -> record_open")
        cid, (a_owner, a_cp, b_owner, b_cp) = self.open_contract(terms)

        # --- mark to market BEFORE burial (fixing not resolvable yet) ---
        q = a.scalarcfd.price(cid)
        assert_equal(q["fixing_reached"], False)
        assert abs(float(q["current_ratio"]) - 0.9) < 1e-6, q["current_ratio"]
        assert q["intrinsic_long_mtm"] < 0      # long is under water at X<K
        assert_equal(q["intrinsic_short_mtm"], -q["intrinsic_long_mtm"])

        # --- bury the fixing + reach the settle lock ---
        deficit = settle_lock - node.getblockcount()
        if deficit > 0:
            self.generatetoaddress(node, deficit, a.getnewaddress())

        # Expected payouts (X=90 < K=100, lambda 1x, STRIKE): long loses 10%, short flat.
        l_cp = im // 10            # 0.2 BTC to the short (long's loss)
        l_owner = im - l_cp        # 1.8 BTC back to the long owner

        self.log.info("unilateral settlement: bob settles the long vault, alice the short vault")
        # finalize_settlement is scoped: a plain signed PSBT (no covenant input) is rejected.
        plain = b.walletcreatefundedpsbt([], [{b.getnewaddress(): 1.0}])["psbt"]
        plain_signed = b.walletprocesspsbt(plain, True)["psbt"]
        assert_raises_rpc_error(-8, "no committed OP_SCALAR_CFD_SETTLE input", b.scalarcfd.finalize_settlement, plain_signed)

        ls = b.scalarcfd.build_settlement(cid, "long")
        assert_equal(sats(ls["payout_owner"]), l_owner)
        assert_equal(sats(ls["payout_cp"]), l_cp)
        assert_equal(ls["is_fallback"], False)
        # An unsigned fee input cannot be extracted.
        assert_raises_rpc_error(-8, "not finalized and verified", b.scalarcfd.finalize_settlement, ls["psbt"])
        self.covenant_settle(b, ls["psbt"])
        self.generate(node, 1)

        ss = a.scalarcfd.build_settlement(cid, "short")  # short flat: owner=im, cp=0 (single output)
        assert_equal(sats(ss["payout_owner"]), im)
        assert_equal(sats(ss["payout_cp"]), 0)
        self.covenant_settle(a, ss["psbt"])
        self.generate(node, 1)
        a.rescanblockchain(); b.rescanblockchain()

        # --- cross-wallet payout routing (long lost 0.2 to short) ---
        assert_equal(sats(a.getreceivedbyaddress(a_owner)), l_owner)  # long owner = alice
        assert_equal(sats(b.getreceivedbyaddress(b_cp)), l_cp)        # long cp = bob
        assert_equal(sats(b.getreceivedbyaddress(b_owner)), im)       # short owner = bob (flat)
        assert_equal(sats(a.getreceivedbyaddress(a_cp)), 0)           # short cp = alice (no loss)

        # double-settle: the spent long vault cannot be settled again.
        assert_raises_rpc_error(-8, "missing or already spent", b.scalarcfd.build_settlement, cid, "long")

        # === COOP CONTRACT: a fresh contract closed cooperatively (no maturity wait) ===
        self.log.info("cooperative 2-of-2 close + adversarial output-mutation rejection")
        epoch2 = 2
        a.scalarpublish_raw(node.getassetpolicy(u_aid)["icu_txid"], node.getassetpolicy(u_aid)["icu_vout"],
                            u_aid, a.getnewaddress(), BOND, feed, epoch2, scalar_hex(X), RAW_U256_LE,
                            {"autofund": True, "broadcast": True, "fee_rate": 10})
        self.generate(node, 1)
        terms2 = self.make_terms(u_aid, feed, epoch2, node.getblockcount() + MATURITY + 50, im_btc)
        cid2, _ = self.open_contract(terms2)

        # Honest coop close of the long vault to an agreed split (vault 2 -> 1.5 + 0.49, fee 0.01).
        coop_a = a.getnewaddress("", "bech32m"); coop_b = b.getnewaddress("", "bech32m")
        agreed = [{"address": coop_a, "amount": "1.5"}, {"address": coop_b, "amount": "0.49"}]
        cc = a.scalarcfd.build_coop_close(cid2, "long", agreed)
        assert_equal(cc["fee"], Decimal("0.01"))
        a_sig = a.scalarcfd.sign_coop(cid2, "long", cc["psbt"])
        assert_equal(a_sig["complete"], False)
        bf = b.scalarcfd.sign_coop(cid2, "long", a_sig["psbt"])
        assert_equal(bf["complete"], True)
        node.sendrawtransaction(bf["hex"])
        self.generate(node, 1)
        a.rescanblockchain(); b.rescanblockchain()
        assert_equal(sats(a.getreceivedbyaddress(coop_a)), sats("1.5"))
        assert_equal(sats(b.getreceivedbyaddress(coop_b)), sats("0.49"))

        # ADVERSARIAL: mutate the coop outputs AFTER alice signs the still-unspent short vault. Bob signs the
        # mutated tx (both sigs present), but alice's signature was over the ORIGINAL outputs, so the network
        # rejects the spend — a partner cannot alter the agreed split after the first signature.
        cc2 = a.scalarcfd.build_coop_close(cid2, "short", agreed)
        a_sig2 = a.scalarcfd.sign_coop(cid2, "short", cc2["psbt"])  # alice's sig over the original outputs
        psbt = PSBT.from_base64(a_sig2["psbt"])
        psbt.tx.vout[0].nValue -= sats("0.25")                     # mutate an agreed output amount
        psbt.g.map[PSBT_GLOBAL_UNSIGNED_TX] = psbt.tx.serialize_without_witness()
        mutated = psbt.to_base64()
        bm = b.scalarcfd.sign_coop(cid2, "short", mutated)          # bob signs the mutated tx
        assert_equal(bm["complete"], True)                          # both signatures present...
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, bm["hex"])  # ...but alice's no longer validates

        # The honest unilateral fallback still settles that short vault after burial.
        deficit2 = terms2["settle_lock_height"] - node.getblockcount()
        if deficit2 > 0:
            self.generatetoaddress(node, deficit2, a.getnewaddress())
        ss2 = b.scalarcfd.build_settlement(cid2, "short")
        self.covenant_settle(b, ss2["psbt"])
        self.generate(node, 1)

        # === FALLBACK PRICE: a contract whose fixing epoch is never published resolves to the committed
        # fallback once past deadline + effective grace; scalarcfd.price must mark it is_fallback. ===
        self.log.info("scalarcfd.price on a deadline-fallback fixing")
        deadline_fb = node.getblockcount() + 3
        terms_fb = self.make_terms(u_aid, feed, 99, deadline_fb + 20, im_btc)  # epoch 99 is never published
        terms_fb["publication_deadline_height"] = deadline_fb
        a_o = a.getnewaddress("", "bech32m"); a_c = a.getnewaddress("", "bech32m")
        b_o = b.getnewaddress("", "bech32m"); b_c = b.getnewaddress("", "bech32m")
        offer_fb = a.scalarcfd.propose(terms_fb, "long", a_o, a_c)["offer"]
        acc_fb = b.scalarcfd.accept(offer_fb, b_o, b_c, {"confirmed": True})  # record persists; no open needed to price
        a.scalarcfd.import_acceptance(offer_fb, acc_fb["acceptance"])
        cid_fb = acc_fb["contract_id"]
        # Bury past deadline + effective grace (max(FALLBACK_GRACE, MATURITY) = MATURITY).
        n = deadline_fb + MATURITY + 1 - node.getblockcount()
        if n > 0:
            self.generatetoaddress(node, n, a.getnewaddress())
        qf = a.scalarcfd.price(cid_fb)
        assert_equal(qf["fixing_reached"], True)
        assert_equal(qf["is_fallback"], True)
        assert_equal(qf["forward_provenance"], "fallback")
        assert abs(float(qf["forecast_ratio"]) - 0.95) < 1e-6, qf["forecast_ratio"]  # fallback 95 / strike 100

        self.log.info("scalar CFD bilateral lifecycle (open -> price -> settle -> coop close -> adversarial reject -> fallback price) OK")


if __name__ == "__main__":
    ScalarCfdLifecycleTest(__file__).main()
