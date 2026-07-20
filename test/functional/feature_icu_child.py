#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Consensus + mempool tests for root-sponsored ICU children (ICU_CHILD.md).

A fully-bonded root ticker ROOT may sponsor low-bond children ROOT.SUFFIX by
co-spending its current ICU (which must itself carry at least AssetMinIcuBond) in the
child's registration transaction. Children are otherwise ordinary ICU assets.

Pure ticker-grammar rejection (lowercase, empty/short suffix, second dot, 12-byte
dotless) is enforced by the consensus parser and is covered exhaustively by the C++
unit tests (asset_tests.cpp). Here those grammar cases are checked at the RPC client
gate (rawtxattachissuerreg, which shares the same helper); the semantic cases below
build valid-grammar transactions and assert real consensus / mempool rejection.
"""

import hashlib
import os
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from asset_wallet_util import mint_asset

COIN = Decimal("1.0")
SAT = Decimal("0.00000001")
ASSET_MIN_ICU_BOND = Decimal("5.0")          # Consensus::Params::AssetMinIcuBond (5 TSC)
SPONSORED_CHILD_MIN_BOND_SATS = 10_000        # Consensus::Params::SponsoredChildMinIcuBond
CHILD_BOND = Decimal("0.0001")                # 10,000 sats
DUST = Decimal("0.00005")


def _q(amount: Decimal) -> float:
    return float(amount.quantize(SAT))


class IcuChildTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.force_cleanup_on_failure = True
        self.run_id = hashlib.sha256(f"{os.getpid()}_{time.time()}_icuchild".encode()).hexdigest()[:6].upper()
        self.extra_args = [[
            "-assetsheight=0",
            "-acceptnonstdtxn=1",
            "-persistmempool=0",
            "-dbcache=1000",
        ]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # --- helpers -------------------------------------------------------------

    def _aid(self, label: str) -> str:
        return hashlib.sha256(f"{label}_{self.run_id}".encode()).hexdigest()

    def _root_ticker(self, label: str) -> str:
        # 3..11 chars, first a letter, [A-Z0-9]. "R" + 5 hex of a label hash.
        return "R" + hashlib.sha256(f"{label}_{self.run_id}".encode()).hexdigest()[:5].upper()

    def _largest_funding(self, n, exclude):
        excl = {(t, v) for t, v in exclude}
        for u in sorted(n.listunspent(), key=lambda e: Decimal(str(e["amount"])), reverse=True):
            if (u["txid"], u["vout"]) in excl:
                continue
            return u
        return None

    def register_root(self, n, label, *, bond=ASSET_MIN_ICU_BOND, ticker=None, policy_bits=3,
                      families=28, decimals=None):
        """Register a full-bond root and return (asset_id, ticker, policy, unlock_sats)."""
        aid = self._aid(label)
        ticker = ticker if ticker is not None else self._root_ticker(label)
        unlock = max(int(bond * 100_000_000), 500_000_000)
        raw = n.createrawtransaction([], {n.getnewaddress(): _q(bond)})
        raw = n.rawtxattachissuerreg(raw, 0, aid, policy_bits, families, unlock, ticker, decimals)
        funded = n.fundrawtransaction(raw)
        signed = n.signrawtransactionwithwallet(funded["hex"])
        n.sendrawtransaction(signed["hex"])
        self.generate(n, 1)
        pol = n.getassetpolicy(aid)
        assert pol is not None, f"root {ticker} not registered"
        assert_equal(pol["ticker"], ticker)
        return aid, ticker, pol, unlock

    def build_child_tx(self, n, *, parent_pol, parent_aid, parent_ticker, parent_unlock,
                       children, parent_bond=ASSET_MIN_ICU_BOND, spend_parent=True,
                       parent_policy_bits=3, parent_families=28, parent_decimals=None,
                       fee=Decimal("0.0003"), funding_override=None):
        """Build (and sign) a sponsored-child registration transaction.

        children: list of dicts with keys asset_id, ticker, bond(Decimal), unlock_sats,
        policy_bits, families, cap(optional), decimals(optional).

        Output layout: vout0 = parent successor (when spend_parent), then one ICU output
        per child, then change. Returns the signed tx hex.
        """
        inputs = []
        exclude = []
        total_in = Decimal("0")

        icu_txid = parent_pol["icu_txid"]
        icu_vout = parent_pol["icu_vout"]
        if spend_parent:
            inputs.append({"txid": icu_txid, "vout": icu_vout})
            exclude.append((icu_txid, icu_vout))
            total_in += parent_bond

        fund = funding_override or self._largest_funding(n, exclude)
        if fund is None:
            self.generate(n, 1)
            fund = self._largest_funding(n, exclude)
        inputs.append({"txid": fund["txid"], "vout": fund["vout"]})
        total_in += Decimal(str(fund["amount"]))

        outputs = []
        if spend_parent:
            outputs.append({n.getnewaddress(): _q(parent_bond)})
        for c in children:
            outputs.append({n.getnewaddress(): _q(c["bond"])})

        spent = (parent_bond if spend_parent else Decimal("0")) + sum(c["bond"] for c in children)
        change = total_in - spent - fee
        assert change >= 0, "insufficient funding for child tx"
        change_pos = None
        if change > DUST:
            outputs.append({n.getnewaddress(): _q(change)})
            change_pos = len(outputs) - 1

        raw = n.createrawtransaction(inputs, outputs)

        vout = 0
        if spend_parent:
            # Recreate the parent as a byte-equivalent successor in vout0.
            raw = n.rawtxattachissuerreg(raw, 0, parent_aid, parent_policy_bits, parent_families,
                                         parent_unlock, parent_ticker, parent_decimals)
            vout = 1
        for c in children:
            opts = {}
            if c.get("cap"):
                opts["issuance_cap_units"] = c["cap"]
            raw = n.rawtxattachissuerreg(raw, vout, c["asset_id"], c.get("policy_bits", 3),
                                         c.get("families", 28), c["unlock_sats"], c["ticker"],
                                         c.get("decimals"), opts if opts else None)
            vout += 1
        assert change_pos is None or vout == change_pos

        signed = n.signrawtransactionwithwallet(raw)
        assert signed.get("complete", False), f"child tx incomplete: {signed}"
        return signed["hex"]

    def _child(self, label, ticker, *, bond=CHILD_BOND, unlock=None, policy_bits=3, families=28,
               cap=None, decimals=None):
        return {
            "asset_id": self._aid(label),
            "ticker": ticker,
            "bond": bond,
            "unlock_sats": unlock if unlock is not None else max(int(bond * 100_000_000), 500_000_000),
            "policy_bits": policy_bits,
            "families": families,
            "cap": cap,
            "decimals": decimals,
        }

    def current_icu(self, n, aid):
        pol = n.getassetpolicy(aid)
        return pol["icu_txid"], pol["icu_vout"], pol

    # --- test ----------------------------------------------------------------

    def run_test(self):
        n = self.nodes[0]
        self.generate(n, 101)

        # Case 1: register a full-bond root.
        acme_id, acme, acme_pol, acme_unlock = self.register_root(n, "acme")
        self.log.info(f"registered root {acme}")

        def parent_kwargs(pol):
            return dict(parent_pol=pol, parent_aid=acme_id, parent_ticker=acme,
                        parent_unlock=acme_unlock)

        # Case 2: register child ROOT.C150K with parent co-spend at the 10,000-sat floor.
        child_tk = f"{acme}.C150K"
        hexed = self.build_child_tx(n, children=[self._child("acme.c150k", child_tk)],
                                    **parent_kwargs(acme_pol))
        n.sendrawtransaction(hexed)
        self.generate(n, 1)
        cpol = n.getassetpolicy(self._aid("acme.c150k"))
        assert cpol is not None, "child not registered"
        assert_equal(cpol["ticker"], child_tk)
        cval, _ = self._decode_icu_value(n, cpol)
        assert_equal(int((cval * 100_000_000).quantize(Decimal("1"))), SPONSORED_CHILD_MIN_BOND_SATS)
        self.log.info(f"registered child {child_tk} at child floor")

        # Lookup regression (stale 3..11 ticker validators): the dotted child ticker must
        # resolve by ticker through the node lookup, the by-ticker lookup, and a wallet
        # resolver path — not only by asset_id.
        child_id = self._aid("acme.c150k")
        assert_equal(n.getassetpolicy(child_tk)["asset_id"], child_id)
        assert_equal(n.getassetpolicy(child_tk)["ticker"], child_tk)
        assert_equal(n.getassetbyticker(child_tk)["asset_id"], child_id)
        assert_equal(n.getassetinfo(child_tk)["asset_id"], child_id)
        self.log.info("child ticker resolves via getassetpolicy / getassetbyticker / getassetinfo")

        # Refresh the parent ICU pointer (it rotated when sponsoring the child).
        _, _, acme_pol = self.current_icu(n, acme_id)

        # Case 3: two siblings in one transaction with a single parent co-spend.
        sib_a = f"{acme}.P150K"
        sib_b = f"{acme}.C160K"
        hexed = self.build_child_tx(
            n,
            children=[self._child("acme.p150k", sib_a), self._child("acme.c160k", sib_b)],
            **parent_kwargs(acme_pol))
        n.sendrawtransaction(hexed)
        self.generate(n, 1)
        assert n.getassetpolicy(self._aid("acme.p150k")) is not None
        assert n.getassetpolicy(self._aid("acme.c160k")) is not None
        self.log.info("registered two siblings with one parent co-spend")
        _, _, acme_pol = self.current_icu(n, acme_id)

        # Case 4: reject a child with no parent ICU input.
        hexed = self.build_child_tx(n, children=[self._child("acme.noparent", f"{acme}.NOPAR")],
                                    spend_parent=False, **parent_kwargs(acme_pol))
        assert_raises_rpc_error(-26, "asset-child-parent-not-spent", n.sendrawtransaction, hexed)
        self.log.info("rejected child with no parent ICU input")

        # Case 5: reject a child whose root is not bound.
        unbound = "Z" + self.run_id + "X"
        hexed = self.build_child_tx(n, children=[self._child("unbound.child", f"{unbound}.C150K")],
                                    spend_parent=False, **parent_kwargs(acme_pol))
        assert_raises_rpc_error(-26, "asset-child-no-parent", n.sendrawtransaction, hexed)
        self.log.info("rejected child of an unbound root")

        # Case 9: wrong-root co-spend — child ACME.X while spending BETA's ICU.
        beta_id, beta, beta_pol, beta_unlock = self.register_root(n, "beta")
        hexed = self.build_child_tx(
            n, parent_pol=beta_pol, parent_aid=beta_id, parent_ticker=beta, parent_unlock=beta_unlock,
            children=[self._child("acme.wrongroot", f"{acme}.WRONG")])
        assert_raises_rpc_error(-26, "asset-child-parent-not-spent", n.sendrawtransaction, hexed)
        self.log.info("rejected wrong-root co-spend")

        # Case 10: reject reserved-root sponsorship (TSC.FOO).
        hexed = self.build_child_tx(n, children=[self._child("tsc.foo", "TSC.FOO")],
                                    spend_parent=False, **parent_kwargs(acme_pol))
        assert_raises_rpc_error(-26, "asset-ticker-reserved", n.sendrawtransaction, hexed)
        self.log.info("rejected reserved-root sponsorship TSC.FOO")

        # Cases 8, 11, 12: grammar rejected at the shared RPC client gate. (Lowercase is
        # normalized to uppercase by the RPC, so its rejection is purely a consensus-parser
        # concern and is covered by the C++ unit tests, not here.)
        for bad in [f"{acme}.C150K.X", f"{acme}.", f"{acme}.C1", f"{acme}..C150", "ABCDEFGHIJKL"]:
            assert_raises_rpc_error(-8, "invalid ticker", n.rawtxattachissuerreg,
                                    n.createrawtransaction([], {n.getnewaddress(): 5.1}),
                                    0, self._aid("grammar"), 3, 28, None, bad)
        self.log.info("rejected malformed child tickers at the RPC gate")

        # Case 13: reject a duplicate child ticker.
        hexed = self.build_child_tx(n, children=[self._child("acme.c150k.dup", f"{acme}.C150K")],
                                    **parent_kwargs(acme_pol))
        assert_raises_rpc_error(-26, "asset-ticker-duplicate", n.sendrawtransaction, hexed)
        self.log.info("rejected duplicate child ticker")

        # Case 7: reject sponsorship when the parent's CURRENT ICU is below the full bond.
        # Rotate ACME down to exactly rotation_min_sats (4.75 TSC < AssetMinIcuBond) — a valid
        # locked rotation — then attempt to sponsor with that under-bonded ICU.
        rot_min = (ASSET_MIN_ICU_BOND * 95) / 100
        self.rotate_icu(n, acme_id, acme, acme_unlock, new_bond=rot_min)
        _, _, acme_pol = self.current_icu(n, acme_id)
        hexed = self.build_child_tx(n, children=[self._child("acme.underbond", f"{acme}.UNDER")],
                                    parent_bond=rot_min, **parent_kwargs(acme_pol))
        assert_raises_rpc_error(-26, "asset-child-parent-underbond", n.sendrawtransaction, hexed)
        self.log.info("rejected sponsorship by an under-bonded parent ICU")

        # Slice 2: the sponsorchildasset wallet RPC + registerasset root-only alignment.
        self.test_sponsorchildasset_rpc(n)

        # Case 14 & 15: ordinary child rotation without parent co-spend, down to its own
        # rotation_min_sats (9,500 sats), accepted by the mempool.
        child_id = self._aid("acme.c150k")
        _, _, c_pol = self.current_icu(n, child_id)
        child_rot_min = Decimal(SPONSORED_CHILD_MIN_BOND_SATS) * 95 // 100 * SAT  # 9,500 sats
        self.rotate_icu(n, child_id, child_tk, max(int(CHILD_BOND * 100_000_000), 500_000_000),
                        new_bond=child_rot_min)
        self.log.info("accepted ordinary child rotation to rotation_min_sats (mempool)")

        # Case 19: reorg disconnect erases the child ticker binding; reconnect restores it.
        # ACME is now under-bonded (4.75) from case 7, so a fresh full-bond root sponsors here.
        gamma_id, gamma, gamma_pol, gamma_unlock = self.register_root(n, "gamma")
        reorg_tk = f"{gamma}.REORG"
        reorg_id = self._aid("gamma.reorg")
        hexed = self.build_child_tx(
            n, parent_pol=gamma_pol, parent_aid=gamma_id, parent_ticker=gamma, parent_unlock=gamma_unlock,
            children=[self._child("gamma.reorg", reorg_tk)])
        n.sendrawtransaction(hexed)
        self.generate(n, 1)
        block_hash = n.getbestblockhash()
        assert n.getassetpolicy(reorg_id) is not None
        n.invalidateblock(block_hash)
        assert_equal(n.getassetpolicy(reorg_id), None)
        n.reconsiderblock(block_hash)
        assert n.getassetpolicy(reorg_id) is not None, "child not restored on reconnect"
        assert_equal(n.getassetpolicy(reorg_id)["ticker"], reorg_tk)
        self.log.info("child ticker binding survives disconnect/reconnect")

    # --- icu helpers (defined late to keep run_test readable) ----------------

    def _decode_icu_value(self, n, pol):
        info = n.gettransaction(pol["icu_txid"], True, True)
        entry = info["decoded"]["vout"][pol["icu_vout"]]
        return Decimal(str(entry["value"])), entry.get("outext")

    def rotate_icu(self, n, aid, ticker, unlock, *, new_bond, policy_bits=3, families=28,
                   fee=Decimal("0.0003"), decimals=None):
        """Spend the current ICU and recreate the IssuerReg with a new bond, via the mempool."""
        _, _, pol = self.current_icu(n, aid)
        icu_txid, icu_vout = pol["icu_txid"], pol["icu_vout"]
        cur_val, _ = self._decode_icu_value(n, pol)
        fund = self._largest_funding(n, [(icu_txid, icu_vout)])
        inputs = [{"txid": icu_txid, "vout": icu_vout}, {"txid": fund["txid"], "vout": fund["vout"]}]
        total_in = cur_val + Decimal(str(fund["amount"]))
        change = total_in - new_bond - fee
        outputs = [{n.getnewaddress(): _q(new_bond)}]
        if change > DUST:
            outputs.append({n.getnewaddress(): _q(change)})
        raw = n.createrawtransaction(inputs, outputs)
        raw = n.rawtxattachissuerreg(raw, 0, aid, policy_bits, families, unlock, ticker, decimals)
        signed = n.signrawtransactionwithwallet(raw)
        assert signed.get("complete", False), f"rotation incomplete: {signed}"
        txid = n.sendrawtransaction(signed["hex"])
        self.generate(n, 1)
        return txid


    def test_sponsorchildasset_rpc(self, n):
        """Slice 2: sponsorchildasset builds/signs/broadcasts a child registration; the result
        resolves by ticker; and registerasset rejects dotted tickers (root-only alignment)."""
        # Fresh full-bond root, independent of ACME's now-under-bonded state.
        delta_id, delta, _dpol, _du = self.register_root(n, "delta")

        # broadcast=true: builds, funds, signs, and broadcasts in one call.
        child1 = self._aid("delta.opt1")
        res = n.sponsorchildasset(delta, "OPT1A", child1, n.getnewaddress(),
                                  {"child_bond_sats": SPONSORED_CHILD_MIN_BOND_SATS, "broadcast": True})
        assert_equal(res["child_ticker"], f"{delta}.OPT1A")
        assert_equal(res["child_asset_id"], child1)
        assert_equal(res["child_bond_sats"], SPONSORED_CHILD_MIN_BOND_SATS)
        assert_equal(res["parent_asset_id"], delta_id)
        assert_equal(res["requires_parent_signature"], False)
        assert res["parent_successor_vout"] != res["child_icu_vout"]
        assert "txid" in res
        self.generate(n, 1)
        cpol = n.getassetpolicy(child1)
        assert cpol is not None and cpol["ticker"] == f"{delta}.OPT1A", cpol
        assert_equal(n.getassetbyticker(f"{delta}.OPT1A")["asset_id"], child1)

        # default (broadcast=false): returns funded hex the wallet can sign + send itself.
        child2 = self._aid("delta.opt2")
        res2 = n.sponsorchildasset(delta, "OPT2B", child2, n.getnewaddress())
        assert "txid" not in res2
        signed = n.signrawtransactionwithwallet(res2["hex"])
        assert signed["complete"], signed
        n.sendrawtransaction(signed["hex"])
        self.generate(n, 1)
        assert n.getassetpolicy(child2) is not None

        # child bond below the floor is rejected client-side.
        assert_raises_rpc_error(-8, "SponsoredChildMinIcuBond", n.sponsorchildasset,
                                delta, "OPT3C", self._aid("delta.opt3"), n.getnewaddress(),
                                {"child_bond_sats": SPONSORED_CHILD_MIN_BOND_SATS - 1})

        # registerasset is root-only: a dotted ticker is rejected with a pointer to sponsorchildasset.
        assert_raises_rpc_error(-8, "sponsorchildasset", n.registerasset,
                                n.getnewaddress(), 5.0, self._aid("delta.viareg"), 3, 28, None, f"{delta}.VIAREG")
        self.log.info("sponsorchildasset RPC builds/broadcasts/resolves; registerasset rejects child tickers")

        # Funding must NOT pull parent token UTXOs (native-fee funding). Mint parent units to the
        # wallet, then sponsor another child and confirm it still builds + the node accepts it — a
        # tx that consumed a token input would fail asset conservation and be rejected.
        _, _, dpol = self.current_icu(n, delta_id)
        dval, _ = self._decode_icu_value(n, dpol)
        mint_asset(n, delta_id, dpol, dval, asset_units=1000)
        child4 = self._aid("delta.opt4")
        res4 = n.sponsorchildasset(delta, "OPT4D", child4, n.getnewaddress(), {"broadcast": True})
        assert "txid" in res4
        self.generate(n, 1)
        assert n.getassetpolicy(child4) is not None, "child not registered while wallet held parent tokens"
        self.log.info("sponsorchildasset funds natively even when the wallet holds parent token units")

        # A bogus parent_icu_outpoint override (unknown UTXO) is rejected.
        assert_raises_rpc_error(-5, "", n.sponsorchildasset, delta, "OPT5E", self._aid("delta.opt5"),
                                n.getnewaddress(), {"parent_icu_outpoint": "00" * 32 + ":0"})

        # An override pointing at a DIFFERENT root's current ICU is rejected (wrong-root co-spend).
        _eid, _e, eps_pol, _eu = self.register_root(n, "epsilon")
        eps_op = f"{eps_pol['icu_txid']}:{eps_pol['icu_vout']}"
        assert_raises_rpc_error(-8, "different asset", n.sponsorchildasset,
                                delta, "OPT6F", self._aid("delta.opt6"), n.getnewaddress(),
                                {"parent_icu_outpoint": eps_op})
        self.log.info("sponsorchildasset rejects bogus and wrong-root parent_icu_outpoint overrides")

        # Full parity (ICU_CHILD.md §7.1): a sponsored child can carry an ICU governance payload,
        # exactly like a standalone asset. Build the canonical payload, register the child with it,
        # and confirm the on-chain registry entry records the ICU commitment (not a bare stub).
        witness = {"version": "1.0", "timestamp": 0, "canonical_hash": "placeholder"}
        payload = n.buildcanonicalicupayload("Sponsored child governance document", witness, 0)
        gov_child = self._aid("delta.gov")
        gres = n.sponsorchildasset(delta, "GOVDOC", gov_child, n.getnewaddress(),
                                   {"broadcast": True, "fee_rate": 5.0,
                                    "icu_payload_plain": payload["icu_payload_plain"], "icu_visibility": 0})
        # The IssuerReg/chunk vExt is attached after funding; without the post-attach fee bump the
        # effective rate collapses (~0.3 sat/vB) and a real node drops the tx for min-relay. Verify
        # the produced tx actually lands near the requested 5 sat/vB.
        gtx = n.gettransaction(gres["txid"], True, True)
        feerate = abs(float(gtx["fee"])) * 1e8 / gtx["decoded"]["vsize"]
        assert feerate >= 4.0, f"fee rate too low ({feerate:.2f} sat/vB) — post-attach fee bump missing"
        self.generate(n, 1)
        gpol = n.getassetpolicy(gov_child)
        assert gpol is not None, "governance child not registered"
        assert gpol.get("icu_ctxt_commit", "0" * 64) != "0" * 64, gpol
        self.log.info(f"sponsored child carries ICU governance + clears fee rate ({feerate:.1f} sat/vB)")


if __name__ == '__main__':
    IcuChildTest(__file__).main()
