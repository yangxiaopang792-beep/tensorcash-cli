#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end round-trip + validation for the committed TSC-ICU-CONTEXT-1 map (§7.2).

A public ICU asset is registered whose payload metadata carries a context map. We assert:
  - register-time re-encryption PRESERVES the metadata (no silent drop), and geticupayload
    surfaces the parsed `context` (and `metadata` hex);
  - a payload whose context map has a wrong body key is REJECTED at registerasset
    (total-or-refuse: BuildCanonicalIcuPayload validates the map against the text and fails).

Byte-order note: a body key is raw sha256 hex (hexdigest, NOT byte-reversed), matching the
C++ HexStr(raw_digest); the registry icu_plain_commit is the byte-reversed display form.
"""
import hashlib
import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


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


# Canonical text is already in normalized form (CRLF endings, NFC, no trailing whitespace),
# so NormalizeCanonicalText is idempotent and Python's hashes line up with the node's.
CANON = "PREAMBLE.\r\nCLAUSE SEVEN: power of attorney.\r\nEND OF DOCUMENT.\r\n"
CLAUSE = "CLAUSE SEVEN: power of attorney."


class IcuContextTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def build_payload(self, canonical_text, metadata_bytes):
        cbytes = canonical_text.encode("utf-8")
        plain_commit_display = hashlib.sha256(cbytes).digest()[::-1].hex()
        witness = json.dumps({"canonical_hash": plain_commit_display},
                             separators=(",", ":")).encode("utf-8")
        p = bytearray([1, 0, 0, 0])  # version=1, compression=0, enc=0, visibility=0 (public)
        p.extend(compact(len(cbytes))); p.extend(cbytes)
        p.extend(compact(len(witness))); p.extend(witness)
        p.extend(compact(len(metadata_bytes))); p.extend(metadata_bytes)
        return bytes(p), plain_commit_display

    def register(self, ticker, payload_hex):
        node = self.nodes[0]
        asset_id = hashlib.sha256(ticker.encode()).hexdigest()
        opts = {"autofund": True, "broadcast": True,
                "icu_payload_plain": payload_hex, "icu_visibility": 0}
        node.registerasset(node.getnewaddress(), 5.1, asset_id, 3, 28, 510000000, ticker, 6, opts)
        return asset_id

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)  # mature coinbase to fund the wallet

        # --- positive: valid context survives re-encryption and is surfaced ---------
        body_key = hashlib.sha256(CLAUSE.encode("utf-8")).hexdigest()  # raw-digest hex
        context = {
            "spec": "TSC-ICU-CONTEXT-1",
            "parse_version": 1,
            "acceptance": "required",
            "bodies": {body_key: CLAUSE},
        }
        meta = json.dumps(context, separators=(",", ":")).encode("utf-8")
        payload, plain_commit_display = self.build_payload(CANON, meta)

        asset_id = self.register("CTXOK", payload.hex())
        self.generate(node, 1)
        assert_equal(node.getassetpolicy(asset_id)["icu_plain_commit"], plain_commit_display)

        got = node.geticupayload(asset_id)
        assert_equal(got["decrypted"], True)
        assert_equal(got["metadata"], meta.hex())          # metadata not dropped on re-encrypt
        assert_equal(got["context"], context)              # parsed, round-trips exactly
        self.log.info("context map round-trips through register -> geticupayload")

        # --- negative: a wrong body key is rejected at registration -----------------
        bad_context = dict(context)
        bad_context["bodies"] = {"00" * 32: CLAUSE}        # key != sha256(value)
        bad_meta = json.dumps(bad_context, separators=(",", ":")).encode("utf-8")
        bad_payload, _ = self.build_payload(CANON, bad_meta)
        assert_raises_rpc_error(
            -4, "Failed to build public ICU payload",
            self.register, "CTXBAD", bad_payload.hex())
        self.log.info("invalid context map rejected at registerasset (total-or-refuse)")


if __name__ == "__main__":
    IcuContextTest(__file__).main()
