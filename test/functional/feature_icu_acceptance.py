#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional coverage for the ICU document-acceptance protocol.

The acceptance object is the canonical DOCUMENT hash -- the asset registry's
icu_plain_commit -- carried verbatim in an OP_RETURN. There are no per-clause fields.

Exercises the wallet-free hoster RPCs (icu.acceptance.prepare / .verify) on a node with
NO wallet (-disablewallet -txindex=1), the custodial wallet RPC (icu.acceptance) as a
fixture/smoke generator, and the protocol invariants:

  - acknowledge (non-custodial): prepare -> client builds a native OP_RETURN(doc-hash) tx ->
    holder BIP-322-signs the acceptance message -> verify=true. Attribution is the BIP-322
    signature by the holder address (NOT the tx funding key), so a signature from any other
    wallet key does not count. Plus: wrong/missing OP_RETURN, canonical/holder mismatch.
  - custodial acknowledge smoke + return_psbt rejection.
  - return (plain asset): the spend attributes the holder. valid full return verifies; not
    spending the holder outpoint, wrong units, wrong issuer, missing OP_RETURN all fail.
  - hybrid timing: pre-broadcast (live UTXO) vs post-mine (txindex) verify.
  - KYC branch: prepare returns commitment_onchain=false. The full KYC return verify-branch
    is PENDING a real Groth16 proof fixture (a KYC transfer needs one).
"""

import hashlib
import json
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

ASSET_OUT_BTC = Decimal("0.001")
FEE_BTC = Decimal("0.0005")


class IcuAcceptanceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node0 = holder/client wallet + miner; node1 = wallet-free hoster with txindex.
        self.extra_args = [
            ["-assetsheight=0", "-acceptnonstdtxn=1"],
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-disablewallet", "-txindex=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        # node1 is the wallet-free hoster (-disablewallet); skip per-node wallet init for it.
        if node == 1:
            return
        super().init_wallet(node=node)

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    # ---- ICU payload helper (mirrors feature_assets_basic_highlevel) -----------
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
                out.append(253)
                out.extend(n.to_bytes(2, "little"))
            elif n <= 0xFFFFFFFF:
                out.append(254)
                out.extend(n.to_bytes(4, "little"))
            else:
                out.append(255)
                out.extend(n.to_bytes(8, "little"))
            return out

        payload = bytearray([1, 0, 1 if visibility == 1 else 0, visibility])
        payload.extend(compact(len(canonical_bytes)))
        payload.extend(canonical_bytes)
        payload.extend(compact(len(witness_json)))
        payload.extend(witness_json)
        payload.append(0)  # empty metadata
        return bytes(payload), canonical_hash_le

    # ---- asset fixtures --------------------------------------------------------
    def register_icu_asset(self, ticker, canonical_text, *, extra_opts=None):
        w = self.w
        asset_id = hashlib.sha256(f"{ticker}_{self.run_tag}".encode()).hexdigest()
        payload, canonical_hash_le = self.build_canonical_payload(
            canonical_text, {"canonical_hash": "placeholder"})
        opts = {"autofund": True, "broadcast": True,
                "icu_payload_plain": payload.hex(), "icu_visibility": 0}
        if extra_opts:
            opts.update(extra_opts)
        w.registerasset(w.getnewaddress(), 5.1, asset_id, 3, 28, 510000000, ticker, 6, opts)
        self.generate(self.node0, 1, sync_fun=self.sync_all)
        assert_equal(self.node0.getassetpolicy(asset_id)["icu_plain_commit"], canonical_hash_le)
        return asset_id, canonical_hash_le

    def mint_to_holder(self, asset_id, units):
        w = self.w
        policy = self.node0.getassetpolicy(asset_id)
        holder_addr = w.getnewaddress(address_type="bech32m")
        w.mintasset(policy["icu_txid"], policy["icu_vout"], w.getnewaddress(), 5.1,
                    holder_addr, float(ASSET_OUT_BTC), asset_id, units, 3, 28, 510000000,
                    {"autofund": True, "broadcast": True, "fee_rate": 5})
        self.generate(self.node0, 1, sync_fun=self.sync_all)
        for u in w.listassetutxos([asset_id]):
            if u.get("address") == holder_addr and int(u["asset_units"]) == units:
                return u["txid"], u["vout"], holder_addr, units
        raise AssertionError("minted holder UTXO not found")

    # ---- tx builders -----------------------------------------------------------
    def native_data_tx(self, data_hex_or_none):
        """A native fee-only tx; default coin control avoids asset UTXOs. Carries one
        OP_RETURN if data is given."""
        w = self.w
        outs = [{w.getnewaddress(): 0.0001}]
        if data_hex_or_none is not None:
            outs.append({"data": data_hex_or_none})
        funded = w.fundrawtransaction(w.createrawtransaction([], outs))
        signed = w.signrawtransactionwithwallet(funded["hex"])
        assert signed["complete"]
        return signed["hex"]

    def build_return_tx(self, holder_txid, holder_vout, asset_id, units_to_dest,
                        dest_addr, *, op_return_hex=None, spend_holder=True, holder_units=None):
        w = self.w
        holder_units = holder_units if holder_units is not None else units_to_dest
        fee_utxo = next((u for u in w.listunspent()
                         if (u["txid"], u["vout"]) != (holder_txid, holder_vout)
                         and u["amount"] > FEE_BTC + 2 * ASSET_OUT_BTC), None)
        assert fee_utxo is not None, "no native fee UTXO"

        inputs = []
        if spend_holder:
            inputs.append({"txid": holder_txid, "vout": holder_vout})
        inputs.append({"txid": fee_utxo["txid"], "vout": fee_utxo["vout"]})

        change_btc = Decimal(fee_utxo["amount"]) - ASSET_OUT_BTC - FEE_BTC
        outputs = [{dest_addr: float(ASSET_OUT_BTC)}]
        if units_to_dest < holder_units:
            outputs.append({w.getnewaddress(address_type="bech32m"): float(ASSET_OUT_BTC)})
            change_btc -= ASSET_OUT_BTC
        if op_return_hex is not None:
            outputs.append({"data": op_return_hex})
        if change_btc > Decimal("0.00001"):
            outputs.append({w.getnewaddress(): float(change_btc)})

        raw = w.createrawtransaction(inputs, outputs)
        raw = self.node0.rawtxattachassettag(raw, 0, asset_id, units_to_dest)
        if units_to_dest < holder_units:
            raw = self.node0.rawtxattachassettag(raw, 1, asset_id, holder_units - units_to_dest)
        signed = w.signrawtransactionwithwallet(raw)
        assert signed["complete"], signed
        return signed["hex"]

    # ---- test groups -----------------------------------------------------------
    def test_ack_noncustodial(self, asset_id, canonical_le):
        self.log.info("group: non-custodial acknowledge (doc-hash + BIP-322)")
        htxid, hvout, haddr, _ = self.mint_to_holder(asset_id, 1_000_000)

        prep = self.hoster.icu.acceptance.prepare(asset_id, "acknowledge", htxid, hvout)
        assert_equal(prep["mode"], "acknowledge")
        assert_equal(prep["holder_address"], haddr)
        assert_equal(prep["canonical_hash"], canonical_le)
        assert_equal(prep["commitment_onchain"], True)

        rawtx = self.native_data_tx(prep["op_return_data"])
        sig = self.w.signmessagebip322(haddr, prep["message_to_sign"])
        res = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, rawtx, sig)
        assert_equal(res["verified"], True)
        assert_equal(res["op_return_found"], True)
        assert_equal(res["signature_valid"], True)
        assert_equal(res["holder_utxo_live"], True)
        assert_equal(res["prevout_source"], "utxo")

        # bad signature (wrong message)
        bad = self.w.signmessagebip322(haddr, "not the message")
        r = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, rawtx, bad)
        assert_equal(r["signature_valid"], False)
        assert_equal(r["verified"], False)

        # a signature from a DIFFERENT wallet key does not count -- attribution is the holder
        # address's BIP-322, not the tx funding key.
        other = self.w.getnewaddress(address_type="bech32m")
        other_sig = self.w.signmessagebip322(other, prep["message_to_sign"])
        r = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, rawtx, other_sig)
        assert_equal(r["signature_valid"], False)
        assert_equal(r["verified"], False)

        # wrong OP_RETURN hash
        wrong = self.native_data_tx("de" * 32)
        r = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, wrong, sig)
        assert_equal(r["op_return_found"], False)
        assert_equal(r["verified"], False)

        # missing OP_RETURN entirely
        none_tx = self.native_data_tx(None)
        r = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, none_tx, sig)
        assert_equal(r["op_return_found"], False)
        assert_equal(r["verified"], False)

        # expected_canonical mismatch -> error
        assert_raises_rpc_error(-8, "does not match the registry commitment",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"expected_canonical_hash": "00" * 32})
        # holder_address mismatch -> error
        assert_raises_rpc_error(-8, "does not match the address",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"holder_address": self.w.getnewaddress()})

    def test_ack_custodial_smoke(self, asset_id):
        self.log.info("group: custodial acknowledge smoke + return_psbt rejection")
        htxid, hvout, haddr, _ = self.mint_to_holder(asset_id, 500_000)
        res = self.w.icu.acceptance(asset_id, "acknowledge", {"holder_address": haddr, "broadcast": False})
        assert_equal(res["mode"], "acknowledge")
        assert "holder_signature" in res and "hex" in res and "message_to_sign" in res

        v = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout,
                                              res["hex"], res["holder_signature"])
        assert_equal(v["verified"], True)

        assert_raises_rpc_error(-8, "return_psbt is not supported",
                                self.w.icu.acceptance, asset_id, "acknowledge", {"return_psbt": True})

    def test_return_plain(self, asset_id):
        self.log.info("group: plain-asset return (happy + negatives) + hybrid timing")
        htxid, hvout, haddr, hunits = self.mint_to_holder(asset_id, 1_000_000)
        prep = self.hoster.icu.acceptance.prepare(asset_id, "return", htxid, hvout)
        assert_equal(prep["commitment_onchain"], True)
        issuer = prep["issuer_address"]
        opret = prep["op_return_data"]

        good = self.build_return_tx(htxid, hvout, asset_id, hunits, issuer, op_return_hex=opret, holder_units=hunits)
        r = self.hoster.icu.acceptance.verify(asset_id, "return", htxid, hvout, good, "")
        assert_equal(r["verified"], True)
        assert_equal(r["op_return_found"], True)
        assert_equal(r["spends_holder_op"], True)
        assert_equal(r["asset_to_issuer"], True)
        assert_equal(r["holder_utxo_live"], True)
        assert_equal(r["prevout_source"], "utxo")

        # does not spend the bound holder outpoint (native inputs only; no mint -> no ICU rotation)
        not_spend = self.build_return_tx(htxid, hvout, asset_id, hunits, issuer,
                                         op_return_hex=opret, spend_holder=False, holder_units=hunits)
        r = self.hoster.icu.acceptance.verify(asset_id, "return", htxid, hvout, not_spend, "")
        assert_equal(r["spends_holder_op"], False)
        assert_equal(r["verified"], False)

        # wrong units to issuer (partial return)
        wrong_units = self.build_return_tx(htxid, hvout, asset_id, hunits // 2, issuer,
                                           op_return_hex=opret, holder_units=hunits)
        r = self.hoster.icu.acceptance.verify(asset_id, "return", htxid, hvout, wrong_units, "")
        assert_equal(r["asset_to_issuer"], False)
        assert_equal(r["verified"], False)

        # wrong issuer address
        wrong_dest = self.build_return_tx(htxid, hvout, asset_id, hunits,
                                          self.w.getnewaddress(address_type="bech32m"),
                                          op_return_hex=opret, holder_units=hunits)
        r = self.hoster.icu.acceptance.verify(asset_id, "return", htxid, hvout, wrong_dest, "")
        assert_equal(r["asset_to_issuer"], False)
        assert_equal(r["verified"], False)

        # missing OP_RETURN for a plain asset (commitment_onchain=true requires it)
        no_opret = self.build_return_tx(htxid, hvout, asset_id, hunits, issuer, op_return_hex=None, holder_units=hunits)
        r = self.hoster.icu.acceptance.verify(asset_id, "return", htxid, hvout, no_opret, "")
        assert_equal(r["op_return_found"], False)
        assert_equal(r["verified"], False)

        # hybrid timing: broadcast + mine the good return, then verify post-spend via txindex
        self.w.sendrawtransaction(good)
        self.generate(self.node0, 1, sync_fun=self.sync_all)
        r = self.hoster.icu.acceptance.verify(asset_id, "return", htxid, hvout, good, "")
        assert_equal(r["prevout_source"], "txindex")
        assert_equal(r["holder_utxo_live"], False)
        assert_equal(r["verified"], True)

    def test_issuer_rotation(self, asset_id):
        self.log.info("group: issuer ICU rotation -> ACK stays verifiable (document hash is stable)")
        htxid, hvout, haddr, _ = self.mint_to_holder(asset_id, 1_000_000)
        prep = self.hoster.icu.acceptance.prepare(asset_id, "acknowledge", htxid, hvout)
        issuer_before = prep["issuer_address"]
        rawtx = self.native_data_tx(prep["op_return_data"])
        sig = self.w.signmessagebip322(haddr, prep["message_to_sign"])
        assert_equal(self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, rawtx, sig)["verified"], True)

        # Rotate the issuer ICU: minting moves icu_outpoint to a new address; the canonical
        # document hash (icu_plain_commit) is unchanged. The holder UTXO is untouched.
        self.mint_to_holder(asset_id, 1)
        issuer_after = self.hoster.icu.acceptance.prepare(asset_id, "acknowledge", htxid, hvout)["issuer_address"]
        assert issuer_after != issuer_before, "mint should rotate the issuer ICU address"

        # The OLD acknowledgment still verifies: the message excludes the issuer and the OP_RETURN
        # carries the stable document hash. (A terms amendment would change the hash and correctly
        # invalidate it; an address-only rotation does not.)
        r = self.hoster.icu.acceptance.verify(asset_id, "acknowledge", htxid, hvout, rawtx, sig)
        assert_equal(r["op_return_found"], True)
        assert_equal(r["signature_valid"], True)
        assert_equal(r["verified"], True)

    def test_kyc_branch(self):
        self.log.info("group: KYC return -> commitment_onchain=false (prepare only)")
        vk_data = (b"mock_verification_key_data" * 20).hex()
        asset_id, _ = self.register_icu_asset(
            "ICUKYC", "KYC-gated terms v1",
            extra_opts={"kyc_flags": 1, "vk_data": vk_data, "max_root_age": 86400})
        assert self.node0.getassetpolicy(asset_id)["has_kyc"], "asset should be has_kyc"
        htxid, hvout, _, _ = self.mint_to_holder(asset_id, 1_000_000)
        prep = self.hoster.icu.acceptance.prepare(asset_id, "return", htxid, hvout)
        assert_equal(prep["commitment_onchain"], False)
        self.log.info("  PENDING: full KYC return verify-branch needs a real Groth16 proof fixture; "
                      "only prepare/commitment_onchain=false is covered here.")

    def run_test(self):
        self.node0 = self.nodes[0]
        self.hoster = self.nodes[1]
        self.run_tag = self.nodes[0].getblockhash(0)[:16]

        self.node0.createwallet("holder")
        self.w = self.node0.get_wallet_rpc("holder")
        self.generatetoaddress(self.node0, 110, self.w.getnewaddress(), sync_fun=self.sync_all)

        asset_id, canonical_le = self.register_icu_asset("ICUACC", "ICU acceptance terms v1")
        self.test_ack_noncustodial(asset_id, canonical_le)
        self.test_ack_custodial_smoke(asset_id)
        self.test_return_plain(asset_id)
        self.test_issuer_rotation(asset_id)
        self.test_kyc_branch()


if __name__ == "__main__":
    IcuAcceptanceTest(__file__).main()
