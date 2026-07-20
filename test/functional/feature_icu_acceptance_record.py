#!/usr/bin/env python3
# Copyright (c) 2026 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ICU acceptance record (0x40 vExt) carrier: consensus + relay accept a well-formed record and
reject a malformed one.

This proves the consensus RELAXATION end to end -- not just block validation but mempool relay too:
  * validation.cpp (ConnectBlock), consensus/tx_verify.cpp (CheckTxInputs) and policy.cpp (IsStandardTx)
    all now whitelist a well-formed 0x40 record;
  * a structurally/semantically invalid 0x40 (e.g. bad mode) is still rejected as 'outext'.

The signature bytes here are dummy: consensus/relay only check the record is structurally + semantically
well formed (fail-closed parse). The cryptographic raw-Schnorr / BIP-322 validity is a read-layer check,
verified separately by RPC/wallet over the TSC-ICU-ACCEPTANCE-RECORD-1 signing message.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def _record_payload(mode=0x01, sig_scheme=0x01, sig_len=64, units=1):
    """Serialize an IcuAcceptanceRecord payload, byte-for-byte matching SerializePayload() (LE)."""
    p = b""
    p += bytes([0x01])                  # version
    p += bytes([mode])                  # mode (1=acknowledge, 2=return)
    p += (0).to_bytes(2, "little")      # flags (reserved, must be 0)
    p += bytes([0x11]) * 32             # asset_id (non-null)
    p += bytes([0x22]) * 32             # icu_plain_commit (non-null)
    p += bytes([0x33]) * 32             # holder_prevout_txid (non-null)
    p += (0).to_bytes(4, "little")      # holder_prevout_vout
    p += bytes([0x44]) * 32             # holder_spk_hash (non-null)
    p += units.to_bytes(8, "little")    # accepted_units (>0)
    p += bytes([sig_scheme])            # sig_scheme (1=SECP_SCHNORR_RAW)
    p += bytes([0x00])                  # body_refs count = 0 (whole-document)
    p += bytes([sig_len])               # sig length (compactsize, <253)
    p += bytes([0x77]) * sig_len        # sig (dummy; crypto validity is read-layer)
    return p


def _tlv_hex(payload):
    """Wrap payload as a full vExt TLV: 0x40 | CompactSize(len) | payload (len < 253 here)."""
    assert len(payload) < 253
    return (bytes([0x40]) + bytes([len(payload)]) + payload).hex()


class IcuAcceptanceRecordTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # acceptnonstdtxn=0: the well-formed record must pass STANDARD relay policy, not just consensus.
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=0"]]
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _build_tx(self, node, tlv_hex):
        raw = node.createrawtransaction([], {node.getnewaddress(): 5.0})
        raw = node.rawtxaddoutext(raw, 0, tlv_hex)
        funded = node.fundrawtransaction(raw)
        signed = node.signrawtransactionwithwallet(funded["hex"])
        return signed["hex"]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        # 1) A well-formed 0x40 acceptance record passes STANDARD relay and is mined.
        good = self._build_tx(node, _tlv_hex(_record_payload()))
        res = node.testmempoolaccept([good])[0]
        assert res["allowed"], "well-formed 0x40 rejected: %s" % res
        txid = node.sendrawtransaction(good)
        blk = self.generate(node, 1)[0]
        assert txid in node.getblock(blk)["tx"]
        self.log.info("well-formed 0x40 acceptance record relayed + mined")

        # 2) A malformed 0x40 record (mode=7) fails fail-closed parse -> rejected as 'outext'.
        bad_mode = self._build_tx(node, _tlv_hex(_record_payload(mode=0x07)))
        assert_raises_rpc_error(-26, "outext", node.sendrawtransaction, bad_mode)

        # 3) Mode/scheme coupling: an ACK with sig_scheme=NONE (0) is semantically invalid -> 'outext'.
        bad_unsigned = self._build_tx(node, _tlv_hex(_record_payload(sig_scheme=0x00, sig_len=0)))
        assert_raises_rpc_error(-26, "outext", node.sendrawtransaction, bad_unsigned)
        self.log.info("malformed / unsigned-ACK 0x40 records rejected as outext")


if __name__ == "__main__":
    IcuAcceptanceRecordTest(__file__).main()
