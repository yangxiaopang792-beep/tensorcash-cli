#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Issuer-side builder for a committed TSC-ICU-CONTEXT-1 map (§7.x gap fix).

`buildcanonicalicupayload` is the GUI entry point. This exercises the two-call issuer flow:
  1. build(canonical_text) -> normalized_canonical_text (the GUI computes body keys over THESE bytes);
  2. build(canonical_text, witness, visibility, context) -> validates the map against the normalized
     text and embeds it in metadata; registerasset then commits it, and geticupayload returns it.

Also covers: an invalid context map is rejected at build; and the normalization guard now rejects
zero-width / bidi-override / Unicode non-character code points (displayed-vs-committed hardening).
"""
import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

TEXT = "PREAMBLE.\nCLAUSE A: alpha provision binding the holder.\nMIDDLE.\nCLAUSE B: beta provision.\nEND.\n"
CA = "CLAUSE A: alpha provision binding the holder."
CB = "CLAUSE B: beta provision."


def key(blob):
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()  # raw-digest hex body key


class IcuContextBuilderTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        witness = {"canonical_hash": "placeholder"}

        # Call 1: get the normalized canonical text the GUI hashes body excerpts over.
        b1 = node.buildcanonicalicupayload(TEXT, witness, 0)
        norm = b1["normalized_canonical_text"]
        assert_equal(norm, TEXT.replace("\n", "\r\n"))   # lone LF -> CRLF
        assert CA in norm and CB in norm

        # Call 2: build WITH a required context map; the builder validates it against the text.
        context = {"spec": "TSC-ICU-CONTEXT-1", "parse_version": 1, "acceptance": "required",
                   "bodies": {key(CA): CA, key(CB): CB}}
        b2 = node.buildcanonicalicupayload(TEXT, witness, 0, context)

        asset_id = hashlib.sha256(b"BUILD1").hexdigest()
        node.registerasset(node.getnewaddress(), 5.1, asset_id, 3, 28, 510000000, "BUILD1", 6,
                            {"autofund": True, "broadcast": True,
                             "icu_payload_plain": b2["icu_payload_plain"], "icu_visibility": 0})
        self.generate(node, 1)
        assert_equal(node.getassetpolicy(asset_id)["icu_plain_commit"], b2["canonical_hash"])

        got = node.geticupayload(asset_id)
        assert_equal(got["decrypted"], True)
        assert_equal(got["context"], context)   # built -> committed -> read back, intact
        self.log.info("builder embeds a validated context map; registerasset commits it; geticupayload returns it")

        # Invalid context (wrong body key) rejected at build time.
        bad = {"spec": "TSC-ICU-CONTEXT-1", "parse_version": 1, "acceptance": "required",
               "bodies": {"00" * 32: CA}}
        assert_raises_rpc_error(-8, "invalid context map",
                                node.buildcanonicalicupayload, TEXT, witness, 0, bad)

        # A body value that isn't a substring of the text is rejected at build time.
        notsub = {"spec": "TSC-ICU-CONTEXT-1", "parse_version": 1, "acceptance": "optional",
                  "bodies": {key("NOT IN THE DOCUMENT"): "NOT IN THE DOCUMENT"}}
        assert_raises_rpc_error(-8, "invalid context map",
                                node.buildcanonicalicupayload, TEXT, witness, 0, notsub)

        # Normalization hardening (must-fix): zero-width / bidi-override / non-character code points
        # must be rejected, or displayed bytes could diverge from the committed (hashed) bytes.
        # U+200B ZWSP, U+202E RLO, U+FEFF BOM, U+FFFE non-char, U+FDD0 non-char, U+2066 LRI.
        for bad_cp in [chr(0x200B), chr(0x202E), chr(0xFEFF), chr(0xFFFE), chr(0xFDD0), chr(0x2066)]:
            assert_raises_rpc_error(-8, "disallowed characters",
                                    node.buildcanonicalicupayload, "CLAUSE" + bad_cp + " X.", witness, 0)
        self.log.info("invalid/non-substring context rejected; zero-width/bidi/non-character text rejected")


if __name__ == "__main__":
    IcuContextBuilderTest(__file__).main()
