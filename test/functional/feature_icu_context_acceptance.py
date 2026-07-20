#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Holder-only TSC-ICU-DOC-ACCEPT-2 end-to-end (§7.3).

A HOLDER-ONLY (encrypted-ICU) asset carries a `required` TSC-ICU-CONTEXT-1 map. The wallet-free
hoster is GIVEN the asset DEK so it decrypts the committed map itself and enforces membership +
required-set -- nothing is published in cleartext, and the flow goes through:

  register(holder-only, required context) -> mint to holder -> dumpassetdek
    -> hoster prepare(body_refs=all, dek) -> holder BIP-322 sign -> hoster verify(body_refs, dek)

Negatives: required-but-subset, ref-not-in-map, holder-only-without-dek, wrong dek.
"""
import base64
import hashlib
import json
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

ASSET_OUT_BTC = Decimal("0.001")

# Already-normalized canonical text (CRLF, NFC, no trailing ws) with two unique clause substrings.
CANON = ("MASTER AGREEMENT.\r\n"
         "CLAUSE SEVEN: irrevocable power of attorney granted to the Company.\r\n"
         "MIDDLE MATTER.\r\n"
         "CLAUSE ELEVEN: the Company may effect a sanctioned burn.\r\n"
         "END.\r\n")
CL7 = "CLAUSE SEVEN: irrevocable power of attorney granted to the Company."
CL11 = "CLAUSE ELEVEN: the Company may effect a sanctioned burn."


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


def body_key(blob):
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()  # raw-digest hex (NOT reversed)


class IcuContextAcceptanceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node0 = holder/issuer wallet + miner; node1 = wallet-free hoster with txindex.
        self.extra_args = [
            ["-assetsheight=0", "-acceptnonstdtxn=1"],
            ["-assetsheight=0", "-acceptnonstdtxn=1", "-disablewallet", "-txindex=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        if node == 1:
            return
        super().init_wallet(node=node)

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def build_payload(self, metadata_bytes):
        cbytes = CANON.encode("utf-8")
        witness = json.dumps({"canonical_hash": hashlib.sha256(cbytes).digest()[::-1].hex()},
                             separators=(",", ":")).encode("utf-8")
        p = bytearray([1, 0, 0, 0])  # plaintext structure; registerasset re-encrypts per icu_visibility
        p.extend(compact(len(cbytes))); p.extend(cbytes)
        p.extend(compact(len(witness))); p.extend(witness)
        p.extend(compact(len(metadata_bytes))); p.extend(metadata_bytes)
        return bytes(p)

    def register_holder_only(self, ticker, context):
        meta = json.dumps(context, separators=(",", ":")).encode("utf-8")
        asset_id = hashlib.sha256(ticker.encode()).hexdigest()
        opts = {"autofund": True, "broadcast": True,
                "icu_payload_plain": self.build_payload(meta).hex(), "icu_visibility": 1}
        self.w.registerasset(self.w.getnewaddress(), 5.1, asset_id, 3, 28, 510000000, ticker, 6, opts)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        return asset_id

    def mint_to_holder(self, asset_id, units):
        w = self.w
        policy = self.nodes[0].getassetpolicy(asset_id)
        holder = w.getnewaddress(address_type="bech32m")
        w.mintasset(policy["icu_txid"], policy["icu_vout"], w.getnewaddress(), 5.1,
                    holder, float(ASSET_OUT_BTC), asset_id, units, 3, 28, 510000000,
                    {"autofund": True, "broadcast": True, "fee_rate": 5})
        self.generate(self.nodes[0], 1, sync_fun=self.sync_all)
        for u in w.listassetutxos([asset_id]):
            if u.get("address") == holder and int(u["asset_units"]) == units:
                return u["txid"], u["vout"], holder
        raise AssertionError("minted holder UTXO not found")

    def native_data_tx(self, data_hex):
        w = self.w
        outs = [{w.getnewaddress(): 0.0001}, {"data": data_hex}]
        funded = w.fundrawtransaction(w.createrawtransaction([], outs))
        signed = w.signrawtransactionwithwallet(funded["hex"])
        assert signed["complete"]
        return signed["hex"]

    def run_test(self):
        self.w = self.nodes[0]
        self.hoster = self.nodes[1]
        self.generate(self.nodes[0], 101, sync_fun=self.sync_all)

        k7, k11 = body_key(CL7), body_key(CL11)
        context = {
            "spec": "TSC-ICU-CONTEXT-1",
            "parse_version": 1,
            "acceptance": "required",
            "bodies": {k7: CL7, k11: CL11},
        }
        asset_id = self.register_holder_only("SHAREH", context)
        dek_hex = base64.b64decode(self.nodes[0].dumpassetdek(asset_id)).hex()
        htxid, hvout, haddr = self.mint_to_holder(asset_id, 1_000_000)

        # --- positive: hoster decrypts the committed map with the DEK and the acceptance goes through ---
        prep = self.hoster.icu.acceptance.prepare(
            asset_id, "acknowledge", htxid, hvout, {"body_refs": [k7, k11], "dek": dek_hex})
        assert_equal(prep["holder_address"], haddr)
        assert "TSC-ICU-DOC-ACCEPT-2" in prep["message_to_sign"]

        rawtx = self.native_data_tx(prep["op_return_data"])
        sig = self.w.signmessagebip322(haddr, prep["message_to_sign"])
        res = self.hoster.icu.acceptance.verify(
            asset_id, "acknowledge", htxid, hvout, rawtx, sig, {"body_refs": [k7, k11], "dek": dek_hex})
        assert_equal(res["verified"], True)
        assert_equal(res["signature_valid"], True)
        self.log.info("holder-only ACCEPT-2 verified via DEK-supplied hoster (nothing in cleartext)")

        # order independence: refs in the other order produce the same message/signature acceptance
        res2 = self.hoster.icu.acceptance.verify(
            asset_id, "acknowledge", htxid, hvout, rawtx, sig, {"body_refs": [k11, k7], "dek": dek_hex})
        assert_equal(res2["verified"], True)

        # --- negatives -----------------------------------------------------------------------------
        # required, but only a subset affirmed
        assert_raises_rpc_error(-8, "all designated bodies must be affirmed",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"body_refs": [k7], "dek": dek_hex})
        # a ref that is not a designated body
        assert_raises_rpc_error(-8, "not a designated body",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"body_refs": [k7, k11, "ab" * 32], "dek": dek_hex})
        # holder-only asset, body_refs but no DEK -> cannot read the committed map
        assert_raises_rpc_error(-8, "supply the 32-byte asset DEK",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"body_refs": [k7, k11]})
        # wrong DEK -> decryption fails
        assert_raises_rpc_error(-8, "failed to decrypt",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"body_refs": [k7, k11], "dek": "11" * 32})

        # THE BYPASS (the key fix): a `required` asset must NOT fall back to a document-only (ACCEPT-1)
        # acceptance when body_refs are omitted. verify must reject, not silently accept the V1 signature.
        assert_raises_rpc_error(-8, "all designated bodies must be affirmed",
                                self.hoster.icu.acceptance.verify, asset_id, "acknowledge", htxid, hvout, rawtx, sig,
                                {"dek": dek_hex})
        # prepare likewise cannot mint a V1 message for a required asset
        assert_raises_rpc_error(-8, "all designated bodies must be affirmed",
                                self.hoster.icu.acceptance.prepare, asset_id, "acknowledge", htxid, hvout,
                                {"dek": dek_hex})
        # holder-only + no DEK at all: the verifier cannot determine the policy, so it must require the
        # DEK rather than silently certify a document-only acceptance.
        assert_raises_rpc_error(-8, "supply the 32-byte asset DEK",
                                self.hoster.icu.acceptance.verify, asset_id, "acknowledge", htxid, hvout, rawtx, sig, {})
        self.log.info("bypass closed: required + no-refs (and no-dek) rejected, no silent ACCEPT-1 fallback")


if __name__ == "__main__":
    IcuContextAcceptanceTest(__file__).main()
