#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end coverage for the on-chain ICU acceptance RECORD create RPC.

icu.acceptance.record.create builds a 0x40 acceptance vExt bound to the holder's taproot UTXO,
signs it with the holder's taproot output key (raw Schnorr over the TSC-ICU-ACCEPTANCE-RECORD-1
message), funds a fee-only tx with a zero-value OP_RETURN carrying the record, and broadcasts it.

Covers: P2TR-v1 acknowledge, rotation-durable RETURN (relinquish to issuer) + adversarial-return rejection,
verified-only list, Option-A inline-context required-body_refs, P2TR-v2/PQ acknowledge (disabled secp output
key), and P2WPKH + P2PKH SECP_BIP322_HASH commit-reveal acknowledge (commit H(proof); verify only with the
revealed proof). P2WSH/P2SH script (multisig) hash-hidden families are accepted by create but not yet tested.
"""

import hashlib
import json
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

ASSET_OUT_BTC = Decimal("0.001")


class IcuAcceptanceRecordCreateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node[0]: the holder/issuer wallet node. node[1]: a -disablewallet HOSTER, to prove verify/list
        # work with no wallet at all (genuine notarization), not just on the root RPC endpoint.
        # node[1] also runs -icuacceptanceindex so its list RPC is served from the asset index (fast path),
        # not a full block scan -- exercising the index end-to-end.
        self.extra_args = [
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-txindex=1"],
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-txindex=1", "-disablewallet", "-icuacceptanceindex=1"],
        ]

    def init_wallet(self, *, node):
        # node[1] runs with -disablewallet -- skip the framework's auto createwallet/importprivkey for it.
        # (Default setup_network connects node[0]<->node[1]; the hoster is a passive validating observer.)
        if "-disablewallet" in self.extra_args[node]:
            return
        super().init_wallet(node=node)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- ICU payload helper (mirrors feature_icu_acceptance) -------------------
    def build_canonical_payload(self, canonical_text, witness_bundle, *, visibility=0):
        canonical_bytes = canonical_text.encode("utf-8")
        canonical_hash_le = hashlib.sha256(canonical_bytes).digest()[::-1].hex()
        for key, value in list(witness_bundle.items()):
            if key == "canonical_hash" and value == "placeholder":
                witness_bundle[key] = canonical_hash_le
        witness_json = json.dumps(witness_bundle, separators=(",", ":")).encode("utf-8")

        def compact(n):
            out = bytearray()
            if n < 253:
                out.append(n)
            elif n <= 0xFFFF:
                out.append(253); out.extend(n.to_bytes(2, "little"))
            elif n <= 0xFFFFFFFF:
                out.append(254); out.extend(n.to_bytes(4, "little"))
            else:
                out.append(255); out.extend(n.to_bytes(8, "little"))
            return out

        payload = bytearray([1, 0, 1 if visibility == 1 else 0, visibility])
        payload.extend(compact(len(canonical_bytes)))
        payload.extend(canonical_bytes)
        payload.extend(compact(len(witness_json)))
        payload.extend(witness_json)
        payload.append(0)  # empty metadata
        return bytes(payload), canonical_hash_le

    def register_icu_asset(self, ticker, canonical_text):
        w = self.w
        asset_id = hashlib.sha256(f"{ticker}_{self.run_tag}".encode()).hexdigest()
        payload, canonical_hash_le = self.build_canonical_payload(
            canonical_text, {"canonical_hash": "placeholder"})
        opts = {"autofund": True, "broadcast": True,
                "icu_payload_plain": payload.hex(), "icu_visibility": 0}
        w.registerasset(w.getnewaddress(), 5.1, asset_id, 3, 28, 510000000, ticker, 6, opts)
        self.generate(self.node0, 1)
        assert_equal(self.node0.getassetpolicy(asset_id)["icu_plain_commit"], canonical_hash_le)
        return asset_id, canonical_hash_le

    def mint_to_holder(self, asset_id, units, addr_type=None, addr=None):
        w = self.w
        policy = self.node0.getassetpolicy(asset_id)
        holder_addr = addr if addr else w.getnewaddress(address_type=addr_type)
        w.mintasset(policy["icu_txid"], policy["icu_vout"], w.getnewaddress(), 5.1,
                    holder_addr, float(ASSET_OUT_BTC), asset_id, units, 3, 28, 510000000,
                    {"autofund": True, "broadcast": True, "fee_rate": 5})
        self.generate(self.node0, 1)
        for u in w.listassetutxos([asset_id]):
            if int(u["asset_units"]) != units:
                continue
            # When no explicit address was given, disambiguate by the generated address. For an explicit
            # address (e.g. a v2/ML-DSA address that may not round-trip in the listing), trust the unique units.
            if addr is None and u.get("address") != holder_addr:
                continue
            return u["txid"], u["vout"], u.get("address", holder_addr), units
        raise AssertionError("minted holder UTXO not found")

    def spend_holder_asset(self, htxid, hvout, asset_id, units):
        """Transfer the whole holder asset UTXO to a fresh address (so the bound prevout is spent)."""
        w = self.w
        fee_utxo = next(u for u in w.listunspent()
                        if (u["txid"], u["vout"]) != (htxid, hvout) and u["amount"] > Decimal("0.01"))
        dest = w.getnewaddress(address_type="bech32m")
        inputs = [{"txid": htxid, "vout": hvout}, {"txid": fee_utxo["txid"], "vout": fee_utxo["vout"]}]
        change = Decimal(fee_utxo["amount"]) - ASSET_OUT_BTC - Decimal("0.0005")
        outputs = [{dest: float(ASSET_OUT_BTC)}, {w.getnewaddress(): float(change)}]
        raw = w.createrawtransaction(inputs, outputs)
        raw = self.node0.rawtxattachassettag(raw, 0, asset_id, units)
        signed = w.signrawtransactionwithwallet(raw)
        assert signed["complete"], signed
        w.sendrawtransaction(signed["hex"])
        self.generate(self.node0, 1)

    def run_test(self):
        self.node0 = self.nodes[0]
        self.run_tag = self.node0.getblockhash(0)[:16]
        self.node0.createwallet("holder")
        self.w = self.node0.get_wallet_rpc("holder")
        self.generatetoaddress(self.node0, 110, self.w.getnewaddress())

        asset_id, canonical_le = self.register_icu_asset("ICUREC", "ICU acceptance record terms v1")

        # --- P2TR-v1 holder: acknowledge create -> relay -> mine ---
        self.log.info("group: taproot (P2TR-v1) acknowledge record create")
        htxid, hvout, haddr, hunits = self.mint_to_holder(asset_id, 1_000_000, "bech32m")
        res = self.w.icu.acceptance.record.create(
            asset_id, "acknowledge", {"holder_txid": htxid, "holder_vout": hvout})
        assert_equal(res["mode"], "acknowledge")
        assert_equal(res["holder_family"], "p2tr-v1")
        assert_equal(res["holder_txid"], htxid)
        assert_equal(int(res["holder_vout"]), hvout)
        assert_equal(int(res["accepted_units"]), hunits)
        assert_equal(res["body_refs"], [])  # plain doc, whole-document acknowledge
        assert len(res["signature"]) == 128, res["signature"]  # 64-byte Schnorr, hex

        txid = res["txid"]
        assert txid in self.node0.getrawmempool(), "record tx not in mempool (relay rejected the 0x40)"
        blk = self.generate(self.node0, 1)[0]
        assert txid in self.node0.getblock(blk)["tx"], "record tx not mined (consensus rejected the 0x40)"

        # The 0x40 record rode on a zero-value OP_RETURN output at the reported vout.
        decoded = self.node0.getrawtransaction(txid, True, blk)
        anchor = decoded["vout"][int(res["acceptance_vout"])]
        assert_equal(anchor["value"], Decimal("0"))
        assert anchor["scriptPubKey"]["asm"].startswith("OP_RETURN"), anchor["scriptPubKey"]
        # The holder asset UTXO is NOT spent by an acknowledge (it stays live).
        assert htxid in [u["txid"] for u in self.w.listassetutxos([asset_id])], "ACK must not spend the holder UTXO"
        self.log.info("  taproot ACK record relayed + mined; holder UTXO untouched")

        # --- verify the record by fetching the tx FROM the node by txid (proves it is on chain) ---
        avout = int(res["acceptance_vout"])
        ver = self.w.icu.acceptance.record.verify(txid, avout, {"blockhash": blk})
        assert_equal(ver["verified"], True)
        assert_equal(ver["scheme"], "schnorr-raw")
        assert_equal(ver["acceptance_txid"], txid)
        assert_equal(ver["acceptance_mined"], True)
        assert_equal(ver["carrier_shape_ok"], True)
        assert_equal(ver["asset_registered"], True)
        assert_equal(ver["doc_current"], True)
        assert_equal(ver["prevout_source"], "utxo")
        assert_equal(ver["holder_utxo_live"], True)
        assert_equal(ver["holder_spk_matches"], True)
        assert_equal(ver["units_match"], True)
        assert_equal(ver["signature_valid"], True)
        # WALLET-FREE: verify/list are now NODE RPCs. Prove a genuine -disablewallet hoster (node[1], which
        # has NO wallet at all) can notarize the record over its node endpoint.
        self.sync_blocks([self.nodes[0], self.nodes[1]])
        hoster = self.nodes[1]
        # The hoster's list is served from -icuacceptanceindex -- make that explicit so a regression (index
        # not built / not consulted) is obvious: wait until the index reports synced before listing.
        self.wait_until(lambda: hoster.getindexinfo().get("icuacceptanceindex", {}).get("synced", False))
        assert_equal(hoster.getindexinfo()["icuacceptanceindex"]["synced"], True)
        nver = hoster.icu.acceptance.record.verify(txid, avout, {"blockhash": blk})
        assert_equal(nver["verified"], True)
        assert_equal(nver["body_refs_ok"], True)
        nlist = hoster.icu.acceptance.record.list(asset_id)  # served from -icuacceptanceindex (fast path)
        assert txid in {r["acceptance_txid"] for r in nlist}, "index-backed hoster list must find the verified record"
        self.log.info("  wallet-free: a -disablewallet + -icuacceptanceindex hoster verifies + index-lists the record")
        # On-chain proof: an unpublished/unknown txid is not found (cannot verify off-chain bytes).
        assert_raises_rpc_error(-5, "acceptance transaction not found",
                                self.w.icu.acceptance.record.verify, "ab" * 32, 0, {})
        # Provenance: a non-record output of the same tx is rejected.
        nonrec = next(i for i in range(len(decoded["vout"])) if i != avout)
        assert_raises_rpc_error(-8, "does not carry a well-formed",
                                self.w.icu.acceptance.record.verify, txid, nonrec, {"blockhash": blk})
        self.log.info("  record verifies from the node by txid; unpublished/non-record rejected")

        # --- historical: after the holder transfers the asset, the acceptance still verifies (txindex) ---
        self.log.info("group: post-transfer historical verify (prevout_source=txindex)")
        self.spend_holder_asset(htxid, hvout, asset_id, hunits)
        ver2 = self.w.icu.acceptance.record.verify(txid, avout, {"blockhash": blk})
        assert_equal(ver2["prevout_source"], "txindex")
        assert_equal(ver2["holder_utxo_live"], False)
        assert_equal(ver2["holder_spk_matches"], True)
        assert_equal(ver2["units_match"], True)
        assert_equal(ver2["signature_valid"], True)
        assert_equal(ver2["verified"], True)
        self.log.info("  acceptance still verifies after the holder transferred the asset")

        # (Non-taproot ACK is now SUPPORTED via SECP_BIP322_HASH commit-reveal -- exercised in the
        # "P2WPKH commit-reveal acknowledge" group below -- so it is no longer a refusal case.)

        # --- RETURN: relinquish the asset to the issuer; the spend is the attribution (any family) ---
        self.log.info("group: return (relinquish to issuer)")
        rtxid, rvout, _, runits = self.mint_to_holder(asset_id, 250_000, "bech32m")
        rres = self.w.icu.acceptance.record.create(asset_id, "return", {"holder_txid": rtxid, "holder_vout": rvout})
        assert_equal(rres["mode"], "return")
        assert_equal(int(rres["accepted_units"]), runits)
        ret_txid = rres["txid"]
        assert ret_txid in self.node0.getrawmempool(), "return tx not in mempool"
        rblk = self.generate(self.node0, 1)[0]
        assert ret_txid in self.node0.getblock(rblk)["tx"], "return tx not mined"
        rv = self.w.icu.acceptance.record.verify(ret_txid, int(rres["acceptance_vout"]), {"blockhash": rblk})
        assert_equal(rv["scheme"], "none")
        assert_equal(rv["holder_utxo_live"], False)   # the return spent the holder UTXO
        assert_equal(rv["units_match"], True)
        assert_equal(rv["signature_valid"], True)     # spends holder + units sent to issuer
        assert_equal(rv["verified"], True)
        self.log.info("  return relayed + mined; verifies (spend + asset-to-issuer)")

        # rotation-durable: rotate the issuer ICU TWICE (each mint moves icu_outpoint to a new address), so
        # the return target is now two hops back in the rotation chain. The SAME return must still verify --
        # this exercises the multi-hop chain walk, not just the immediate parent.
        self.mint_to_holder(asset_id, 50_000, addr_type="bech32m")   # rotation #1
        self.mint_to_holder(asset_id, 60_000, addr_type="bech32m")   # rotation #2
        rvd = self.w.icu.acceptance.record.verify(ret_txid, int(rres["acceptance_vout"]), {"blockhash": rblk})
        assert_equal(rvd["verified"], True)  # STILL verified after TWO issuer ICU rotations (rotation-durable)
        self.log.info("  return STILL verifies after two issuer ICU rotations (multi-hop rotation-durable)")

        # negative: a NONE record whose tx sends the asset to a THIRD PARTY (not the issuer) must NOT
        # verify -- this regression-tests the issuer-return security property. Reuse a correctly-bound
        # NONE record (created with broadcast=false) in an adversarial tx.
        ntxid, nvout, _, nunits = self.mint_to_holder(asset_id, 100_000, "bech32m")
        legit = self.w.icu.acceptance.record.create(
            asset_id, "return", {"holder_txid": ntxid, "holder_vout": nvout, "broadcast": False})
        none_vext = legit["acceptance_vext"]
        third = self.w.getnewaddress(address_type="bech32m")
        fee_utxo = next(u for u in self.w.listunspent()
                        if (u["txid"], u["vout"]) != (ntxid, nvout) and u["amount"] > Decimal("0.01"))
        change = Decimal(fee_utxo["amount"]) - ASSET_OUT_BTC - Decimal("0.0005")
        inputs = [{"txid": ntxid, "vout": nvout}, {"txid": fee_utxo["txid"], "vout": fee_utxo["vout"]}]
        outputs = [{third: float(ASSET_OUT_BTC)}, {"data": "00"}, {self.w.getnewaddress(): float(change)}]
        raw = self.w.createrawtransaction(inputs, outputs)
        raw = self.node0.rawtxattachassettag(raw, 0, asset_id, nunits)  # asset -> third party (not issuer)
        raw = self.node0.rawtxaddoutext(raw, 1, none_vext)             # NONE record on the OP_RETURN carrier
        signed = self.w.signrawtransactionwithwallet(raw)
        assert signed["complete"], signed
        adv_txid = self.w.sendrawtransaction(signed["hex"])
        ablk = self.generate(self.node0, 1)[0]
        adv = self.w.icu.acceptance.record.verify(adv_txid, 1, {"blockhash": ablk})
        assert_equal(adv["scheme"], "none")
        assert_equal(adv["signature_valid"], False)   # spends the holder, but the asset went elsewhere
        assert_equal(adv["verified"], False)
        self.log.info("  adversarial return (asset to a third party) correctly rejected")

        # --- list: enumerate the on-chain acceptance records for the asset ---
        self.log.info("group: list acceptance records")
        # default: only VERIFIED records -- the adversarial third-party return is excluded.
        by_txid = {r["acceptance_txid"]: r for r in self.w.icu.acceptance.record.list(asset_id)}
        assert txid in by_txid, "ACK record not listed"
        assert_equal(by_txid[txid]["mode"], "acknowledge")
        assert_equal(by_txid[txid]["scheme"], "schnorr-raw")
        assert_equal(by_txid[txid]["verified"], True)
        assert adv_txid not in by_txid, "adversarial (unverified) return must be excluded by default"
        # The legit RETURN is now ROTATION-DURABLE: even though the issuer ICU rotated after the return, it
        # still verifies (the verifier accepts historical issuer ICU addresses), so it is in the default set.
        assert ret_txid in by_txid, "legit RETURN must remain verified across issuer rotation"
        assert_equal(by_txid[ret_txid]["verified"], True)
        # include_invalid surfaces all candidate records found by the scan, each tagged with verified.
        allrecs = {r["acceptance_txid"]: r for r in self.w.icu.acceptance.record.list(asset_id, {"include_invalid": True})}
        assert adv_txid in allrecs, "include_invalid should surface the adversarial record"
        assert_equal(allrecs[adv_txid]["verified"], False)
        assert allrecs[adv_txid]["reason"], "an unverified record must surface a reason"  # not empty
        # mode filter
        acks = self.w.icu.acceptance.record.list(asset_id, {"mode": "acknowledge"})
        assert all(r["mode"] == "acknowledge" for r in acks), acks
        assert txid in [r["acceptance_txid"] for r in acks]
        assert ret_txid not in [r["acceptance_txid"] for r in acks]
        self.log.info("  list returns only verified records; include_invalid + mode filter work")

        # --- Option-A inline context (TSC-ICU-CONTEXT-1 inside canonical_text) required: create auto-affirms all refs ---
        self.log.info("group: inline-context (Option A) required body_refs")
        ITEXT = "Governance preamble for the inline-context acceptance asset."
        ICA, ICB = "Clause A: the holder affirms provision alpha.", "Clause B: the holder affirms provision beta."
        # Pass clauses via icu_clauses (arg 4) so the authoritative context is embedded INSIDE canonical_text
        # (Option A), covered by icu_plain_commit -- NOT the deprecated metadata icu_context (arg 3, left null).
        built = self.w.buildcanonicalicupayload(ITEXT, {"canonical_hash": "placeholder"}, 0, None, [ICA, ICB], "required")
        expected_refs = set(built["body_keys"])  # authoritative inline body keys
        ictx_asset = hashlib.sha256(f"ICTX_{self.run_tag}".encode()).hexdigest()
        self.w.registerasset(self.w.getnewaddress(), 5.1, ictx_asset, 3, 28, 510000000, "ICTX", 6,
                             {"autofund": True, "broadcast": True,
                              "icu_payload_plain": built["icu_payload_plain"], "icu_visibility": 0})
        self.generate(self.node0, 1)
        assert_equal(self.node0.getassetpolicy(ictx_asset)["icu_plain_commit"], built["canonical_hash"])
        assert_equal(self.w.geticupayload(ictx_asset)["context_source"], "inline")  # Option-A inline, not metadata
        ictxid, icvout, _, _ = self.mint_to_holder(ictx_asset, 1_000_000, addr_type="bech32m")
        # create ACK WITHOUT body_refs -> a 'required' inline context auto-affirms ALL designated bodies.
        icres = self.w.icu.acceptance.record.create(
            ictx_asset, "acknowledge", {"holder_txid": ictxid, "holder_vout": icvout})
        assert_equal(icres["context_source"], "inline")
        assert_equal(set(icres["body_refs"]), expected_refs)
        icblk = self.generate(self.node0, 1)[0]
        icv = self.w.icu.acceptance.record.verify(icres["txid"], int(icres["acceptance_vout"]), {"blockhash": icblk})
        assert_equal(icv["verified"], True)
        assert_equal(icv["body_refs_ok"], True)  # affirmed refs == the committed inline designated clauses
        self.log.info("  inline-context (Option A) required: context_source=inline; all body_refs auto-affirmed + verified")

        # --- P2TR-v2 (ML-DSA) acknowledge: signs with the key-path-disabled secp output key ---
        # Stage the v2 holder the proven way (per wallet_pq_mldsa.py): mint to a regular address, then
        # sendasset to the ML-DSA address (sendasset auto-detects ML-DSA and auto-signs).
        self.log.info("group: P2TR-v2 (ML-DSA) acknowledge")
        pq_payload, _ = self.build_canonical_payload("ICU PQ acceptance terms v1", {"canonical_hash": "placeholder"})
        pq_asset = hashlib.sha256(f"ICUPQ_{self.run_tag}".encode()).hexdigest()
        self.w.registerasset(self.w.getnewaddress(), 5.1, pq_asset, 3, 28, 510000000, "ICUPQ", 6,
                             {"autofund": True, "broadcast": True, "icu_payload_plain": pq_payload.hex(),
                              "icu_visibility": 0})
        self.generate(self.node0, 1)
        self.mint_to_holder(pq_asset, 500_000, addr_type="bech32m")  # balance to send from
        v2addr = self.w.generatemldsaaddress(65)["address"]
        send = self.w.sendasset(pq_asset, v2addr, 200_000)
        assert "txid" in send, send
        sblk = self.generate(self.node0, 1)[0]
        stx = self.node0.getrawtransaction(send["txid"], True, sblk)
        v2vout = next(i for i, o in enumerate(stx["vout"])
                      if o.get("scriptPubKey", {}).get("address") == v2addr)
        v2res = self.w.icu.acceptance.record.create(
            pq_asset, "acknowledge", {"holder_txid": send["txid"], "holder_vout": v2vout})
        assert_equal(v2res["holder_family"], "p2tr-v2")
        assert_equal(int(v2res["accepted_units"]), 200_000)
        v2acc = v2res["txid"]
        assert v2acc in self.node0.getrawmempool(), "v2 ACK tx not in mempool"
        v2blk = self.generate(self.node0, 1)[0]
        assert v2acc in self.node0.getblock(v2blk)["tx"], "v2 ACK tx not mined"
        v2v = self.w.icu.acceptance.record.verify(v2acc, int(v2res["acceptance_vout"]), {"blockhash": v2blk})
        assert_equal(v2v["scheme"], "schnorr-raw")
        assert_equal(v2v["signature_valid"], True)
        assert_equal(v2v["verified"], True)
        self.log.info("  P2TR-v2 ACK created with the disabled secp output key + verified")

        # --- P2WPKH commit-reveal acknowledge: commit H(BIP-322 proof); verify only with the revealed proof ---
        self.log.info("group: P2WPKH commit-reveal acknowledge")
        ptxid, pvout, _, _ = self.mint_to_holder(asset_id, 444_000, addr_type="bech32")  # P2WPKH holder
        pres = self.w.icu.acceptance.record.create(asset_id, "acknowledge", {"holder_txid": ptxid, "holder_vout": pvout})
        assert_equal(pres["holder_family"], "bip322-hash")
        proof = pres["revealed_bip322_proof"]
        assert proof, "create must return the BIP-322 proof to retain"
        pacc = pres["txid"]
        assert pacc in self.node0.getrawmempool(), "P2WPKH ACK tx not in mempool"
        pblk = self.generate(self.node0, 1)[0]
        assert pacc in self.node0.getblock(pblk)["tx"], "P2WPKH ACK tx not mined"
        avout = int(pres["acceptance_vout"])
        # without the revealed proof -> not verified (the on-chain commitment alone is insufficient)
        pv0 = self.w.icu.acceptance.record.verify(pacc, avout, {"blockhash": pblk})
        assert_equal(pv0["scheme"], "bip322-hash")
        assert_equal(pv0["signature_valid"], False)
        assert_equal(pv0["verified"], False)
        # with the revealed proof -> verified (H(proof)==commit AND BIP-322 valid over the record message)
        pv1 = self.w.icu.acceptance.record.verify(pacc, avout, {"blockhash": pblk, "revealed_bip322_proof": proof})
        assert_equal(pv1["signature_valid"], True)
        assert_equal(pv1["verified"], True)
        # a tampered proof -> not verified (fails the H(proof) commitment check)
        wrong = ("00" if proof[:2].lower() != "00" else "11") + proof[2:]
        pv2 = self.w.icu.acceptance.record.verify(pacc, avout, {"blockhash": pblk, "revealed_bip322_proof": wrong})
        assert_equal(pv2["signature_valid"], False)
        assert_equal(pv2["verified"], False)
        self.log.info("  P2WPKH commit-reveal: H(proof) committed; verifies only with the correct revealed proof")

        # --- P2PKH (legacy) commit-reveal acknowledge: backs the hash-hidden family claim beyond P2WPKH ---
        self.log.info("group: P2PKH (legacy) commit-reveal acknowledge")
        pkh_payload, _ = self.build_canonical_payload("ICU P2PKH acceptance terms v1", {"canonical_hash": "placeholder"})
        pkh_asset = hashlib.sha256(f"ICUPKH_{self.run_tag}".encode()).hexdigest()
        # allowed_spk_families = 28 (P2WPKH|P2WSH|P2TR) | 1 (SPK_P2PKH) = 29, so a legacy holder is allowed.
        self.w.registerasset(self.w.getnewaddress(), 5.1, pkh_asset, 3, 29, 510000000, "ICUPKH", 6,
                             {"autofund": True, "broadcast": True, "icu_payload_plain": pkh_payload.hex(),
                              "icu_visibility": 0})
        self.generate(self.node0, 1)
        # Stage the legacy holder via sendasset (mint-direct to non-default families is unreliable).
        self.mint_to_holder(pkh_asset, 500_000, addr_type="bech32m")  # balance to send from
        legacy = self.w.getnewaddress(address_type="legacy")          # P2PKH
        lsend = self.w.sendasset(pkh_asset, legacy, 222_000)
        assert "txid" in lsend, lsend
        lsblk = self.generate(self.node0, 1)[0]
        lstx = self.node0.getrawtransaction(lsend["txid"], True, lsblk)
        lpvout = next(i for i, o in enumerate(lstx["vout"]) if o.get("scriptPubKey", {}).get("address") == legacy)
        lptxid = lsend["txid"]
        lpres = self.w.icu.acceptance.record.create(pkh_asset, "acknowledge", {"holder_txid": lptxid, "holder_vout": lpvout})
        assert_equal(lpres["holder_family"], "bip322-hash")
        lproof = lpres["revealed_bip322_proof"]
        assert lproof, "create must return the BIP-322 proof for a P2PKH holder"
        lpacc = lpres["txid"]
        lpblk = self.generate(self.node0, 1)[0]
        lpv0 = self.w.icu.acceptance.record.verify(lpacc, int(lpres["acceptance_vout"]), {"blockhash": lpblk})
        assert_equal(lpv0["scheme"], "bip322-hash")
        assert_equal(lpv0["signature_valid"], False)  # no proof revealed
        lpv1 = self.w.icu.acceptance.record.verify(lpacc, int(lpres["acceptance_vout"]), {"blockhash": lpblk, "revealed_bip322_proof": lproof})
        assert_equal(lpv1["signature_valid"], True)   # H(proof) + BIP-322 valid for the legacy holder address
        assert_equal(lpv1["verified"], True)
        self.log.info("  P2PKH (legacy) commit-reveal verified with the revealed proof")

        # --- NON-CUSTODIAL (keyless) round-trip: prepare -> client signs locally -> assemble -> fund/sign/send ---
        # The node never holds the holder key: it returns the message_to_sign in prepare, the CLIENT BIP-322
        # signs it locally, assemble re-verifies the client sig and emits an UNFUNDED carrier-only rawtx, and
        # the client funds + signs the fee inputs + broadcasts. No icu.acceptance.record.create is used.
        self.log.info("group: NON-CUSTODIAL keyless prepare/assemble round-trip (P2WPKH holder)")
        nctxid, ncvout, ncaddr, ncunits = self.mint_to_holder(asset_id, 333_000, addr_type="bech32")  # P2WPKH holder

        # 1) prepare (keyless node): resolve the record + the message the client must sign.
        prep = self.node0.icu.acceptance.record.prepare(asset_id, "acknowledge", nctxid, ncvout)
        assert_equal(prep["mode"], "acknowledge")
        assert_equal(prep["scheme"], "bip322-hash")           # P2WPKH -> commit-reveal
        assert_equal(int(prep["holder_vout"]), ncvout)
        assert_equal(int(prep["accepted_units"]), ncunits)
        assert prep["message_to_sign"], "prepare must return a message_to_sign"
        nc_holder_addr = prep["holder_address"]
        assert nc_holder_addr, "prepare must decode the holder address"

        # 2) CLIENT signs the message LOCALLY with its OWN holder key (BIP-322).
        proof = self.w.signmessagebip322(nc_holder_addr, prep["message_to_sign"])
        assert proof, "client-side BIP-322 signing failed"

        # assemble must REJECT a tampered/garbage client proof (verify-before-assemble).
        garbage = ("AA" if proof[:2] != "AA" else "BB") + proof[2:]
        assert_raises_rpc_error(-8, None, self.node0.icu.acceptance.record.assemble,
                                asset_id, "acknowledge", prep["icu_plain_commit"], prep["holder_txid"],
                                int(prep["holder_vout"]), prep["holder_spk_hash"], int(prep["accepted_units"]),
                                int(prep["sig_scheme"]), prep["body_refs"],
                                {"revealed_bip322_proof": garbage, "holder_address": nc_holder_addr})
        self.log.info("  assemble rejects a tampered client BIP-322 proof (verify-before-assemble)")

        # 3) assemble (keyless node): re-verify + emit the UNFUNDED carrier-only rawtx.
        asm = self.node0.icu.acceptance.record.assemble(
            asset_id, "acknowledge", prep["icu_plain_commit"], prep["holder_txid"],
            int(prep["holder_vout"]), prep["holder_spk_hash"], int(prep["accepted_units"]),
            int(prep["sig_scheme"]), prep["body_refs"],
            {"revealed_bip322_proof": proof, "holder_address": nc_holder_addr})
        assert_equal(int(asm["acceptance_vout"]), 0)
        nc_vext = asm["acceptance_vext"]
        assert nc_vext, "assemble must return the acceptance vExt"
        retained_proof = asm["revealed_bip322_proof"]      # hex-of-base64, for verify

        # Sanity: the unfunded rawtx carries the 0x40 vExt on the carrier output (vout 0).
        unfunded_dec = self.node0.decoderawtransaction(asm["rawtx"])
        assert_equal(len(unfunded_dec["vin"]), 0)          # UNFUNDED: no inputs
        assert_equal((unfunded_dec["vout"][0].get("outext", "") or "").lower(), nc_vext.lower())

        # 4) CLIENT funds + signs the fee inputs LOCALLY + broadcasts.
        funded = self.w.fundrawtransaction(asm["rawtx"], {"fee_rate": 5})
        # CRITICAL: fundrawtransaction MUST PRESERVE the 0x40 vExt carrier output.
        fdec = self.node0.decoderawtransaction(funded["hex"])
        carrier = None
        for o in fdec["vout"]:
            v = o.get("outext", "") or ""
            if v and v.lower() == nc_vext.lower():
                carrier = o
                break
        assert carrier is not None, (
            "fundrawtransaction DROPPED the 0x40 acceptance vExt carrier output -- "
            "the non-custodial design needs adjustment (cannot fund the carrier-only tx without losing the record). "
            f"funded vouts: {fdec['vout']}")
        assert_equal(carrier["value"], 0)                  # zero-value carrier preserved
        self.log.info("  fundrawtransaction PRESERVES the 0x40 vExt carrier output")

        signed = self.w.signrawtransactionwithwallet(funded["hex"])
        assert signed["complete"], signed
        nc_acc_txid = self.node0.sendrawtransaction(signed["hex"])
        # The carrier vout index after funding (find it again in the final tx).
        nc_final = self.node0.decoderawtransaction(signed["hex"])
        nc_acc_vout = next(i for i, o in enumerate(nc_final["vout"])
                           if (o.get("outext", "") or "").lower() == nc_vext.lower())
        nc_blk = self.generate(self.node0, 1)[0]
        assert nc_acc_txid in self.node0.getblock(nc_blk)["tx"], "non-custodial acceptance tx not mined"

        # 5) verify the keyless-assembled record with the retained proof.
        ncv = self.node0.icu.acceptance.record.verify(
            nc_acc_txid, nc_acc_vout, {"blockhash": nc_blk, "revealed_bip322_proof": retained_proof})
        assert_equal(ncv["scheme"], "bip322-hash")
        assert_equal(ncv["signature_valid"], True)
        assert_equal(ncv["body_refs_ok"], True)
        assert_equal(ncv["verified"], True)
        self.log.info("  NON-CUSTODIAL round-trip verified end-to-end (node never held the holder key)")

        # Negative guards on the keyless path:
        # (a) assemble rejects a sig_scheme that doesn't match the holder prevout family (P2WPKH => bip322-hash);
        #     the caller cannot pick the scheme -- it's derived from the prevout spk.
        assert_raises_rpc_error(-8, "sig_scheme does not match", self.node0.icu.acceptance.record.assemble,
                                asset_id, "acknowledge", prep["icu_plain_commit"], prep["holder_txid"],
                                int(prep["holder_vout"]), prep["holder_spk_hash"], int(prep["accepted_units"]),
                                1, prep["body_refs"], {"record_signature": "00" * 64})  # 1=SCHNORR_RAW (wrong family)
        # (b) LIVE-ONLY: transfer the holder UTXO, then prepare refuses it (no post-transfer/former-holder ACK).
        self.spend_holder_asset(nctxid, ncvout, asset_id, ncunits)
        assert_raises_rpc_error(-8, "live UTXO", self.node0.icu.acceptance.record.prepare,
                                asset_id, "acknowledge", nctxid, ncvout)
        self.log.info("  keyless guards: scheme-family mismatch + spent (former-holder) prevout both rejected")

        # --- NON-CUSTODIAL RETURN (return_psbt): record.create returns an UNSIGNED wallet-annotated PSBT for
        # the relinquishing spend; the CLIENT signs the spend locally (holder key never leaves the client),
        # finalizes + broadcasts; the mined 0x40 NONE return record then verifies. ----------------------------
        self.log.info("group: NON-CUSTODIAL return (return_psbt: client signs the spend locally)")
        nrtxid, nrvout, _, nrunits = self.mint_to_holder(asset_id, 277_000, addr_type="bech32")  # P2WPKH holder

        # return_psbt is REJECTED for acknowledge (only meaningful for the relinquishing spend).
        assert_raises_rpc_error(-8, None, self.w.icu.acceptance.record.create, asset_id, "acknowledge",
                                {"holder_txid": nrtxid, "holder_vout": nrvout, "return_psbt": True})

        # 1) create RETURN with return_psbt: get an unsigned, wallet-annotated PSBT (no txid).
        rret = self.w.icu.acceptance.record.create(
            asset_id, "return", {"holder_txid": nrtxid, "holder_vout": nrvout, "return_psbt": True})
        assert "psbt" in rret, "return_psbt must return a PSBT"
        assert "txid" not in rret, "return_psbt must NOT sign/broadcast (no txid)"
        assert_equal(rret["complete"], False)
        assert rret["acceptance_vext"], "the unsigned PSBT path must still surface the acceptance vExt"
        assert_equal(rret["mode"], "return")
        assert_equal(int(rret["accepted_units"]), nrunits)
        nr_issuer = rret["issuer_address"]

        # 2) Assert the returned PSBT is genuinely UNSIGNED, carries the 0x40 NONE carrier, and sends the
        #    units to the issuer ICU address. No input may already be finalized / carry partial sigs.
        dec = self.w.decodepsbt(rret["psbt"])
        assert len(dec["inputs"]) >= 1, dec
        for i, pin in enumerate(dec["inputs"]):
            assert "final_scriptwitness" not in pin and "final_scriptSig" not in pin, \
                f"PSBT input {i} is already finalized -- it must still need the client's signature"
            assert not pin.get("partial_signatures"), \
                f"PSBT input {i} already carries partial sigs -- it must be unsigned"
        # The holder asset input must be present and signable by an external holder: witnessUtxo +
        # bip32 derivation present (P2WPKH).
        utx = dec["tx"]
        holder_in = next(j for j, vin in enumerate(utx["vin"])
                         if vin["txid"] == nrtxid and int(vin["vout"]) == nrvout)
        hpin = dec["inputs"][holder_in]
        assert "witness_utxo" in hpin, f"holder input missing witnessUtxo (not externally signable): {hpin}"
        assert hpin.get("bip32_derivs"), f"holder input missing bip32Derivation (not externally signable): {hpin}"
        # A vout carries the acceptance vExt (NONE 0x40 carrier); another sends the units to the issuer.
        avout = int(rret["acceptance_vout"])
        carrier = utx["vout"][avout]
        assert_equal(carrier["value"], Decimal("0"))
        assert_equal((carrier.get("outext", "") or "").lower(), rret["acceptance_vext"].lower())
        issuer_out = next(o for k, o in enumerate(utx["vout"])
                          if k != avout and o.get("scriptPubKey", {}).get("address") == nr_issuer)
        assert issuer_out is not None, "PSBT must send the units to the issuer ICU address"
        self.log.info("  return_psbt: PSBT is unsigned, carries the 0x40 NONE carrier + the issuer output")

        # 3) CLIENT signs the spend LOCALLY (the wallet stands in for the holder's local signer), finalizes,
        #    broadcasts. signmessage/sign never happened on create -- the key only signs here, client-side.
        proc = self.w.walletprocesspsbt(rret["psbt"])           # sign=true by default
        assert proc["complete"], proc
        fin = self.w.finalizepsbt(proc["psbt"])
        assert fin["complete"], fin
        nr_txid = self.w.sendrawtransaction(fin["hex"])
        nr_blk = self.generate(self.node0, 1)[0]
        assert nr_txid in self.node0.getblock(nr_blk)["tx"], "non-custodial return tx not mined"

        # 4) verify the mined NONE return record.
        nrv = self.w.icu.acceptance.record.verify(nr_txid, avout, {"blockhash": nr_blk})
        assert_equal(nrv["scheme"], "none")
        assert_equal(nrv["holder_utxo_live"], False)   # the client's spend relinquished the holder UTXO
        assert_equal(nrv["units_match"], True)
        assert_equal(nrv["signature_valid"], True)     # spends the holder + units went to the issuer
        assert_equal(nrv["verified"], True)
        self.log.info("  NON-CUSTODIAL return verified: unsigned PSBT -> client signs -> broadcast -> verified=true")

        # 5) the return_psbt path NEVER signs, so it must work on a LOCKED encrypted wallet (a stray unlock
        #    requirement would block the supposedly-keyless path). Mint a fresh holder UTXO while still
        #    unlocked, then encrypt+lock the wallet and prove return_psbt still builds (no unlock needed).
        lk_txid, lk_vout, _, _ = self.mint_to_holder(asset_id, 80_000, addr_type="bech32")
        self.w.encryptwallet("p@ssphrase")                              # encrypts + leaves the wallet LOCKED
        rpsbt = self.w.icu.acceptance.record.create(
            asset_id, "return", {"holder_txid": lk_txid, "holder_vout": lk_vout, "return_psbt": True})
        assert "psbt" in rpsbt and "txid" not in rpsbt, "return_psbt must build an unsigned PSBT on a LOCKED wallet"
        self.log.info("  return_psbt builds on a LOCKED encrypted wallet (keyless path requires no unlock)")


if __name__ == "__main__":
    IcuAcceptanceRecordCreateTest(__file__).main()
