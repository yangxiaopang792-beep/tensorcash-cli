#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject transactions with unknown TLV in vExt by consensus.

Covers Phase 5 consensus rule: unknown per-output TLV types are invalid.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class AssetUnknownTLVRejectTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-assetsheight=0", "-acceptnonstdtxn=1"]] * self.num_nodes
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def no_op(self):
        """No-op sync function for single node operations."""
        pass

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101, sync_fun=self.no_op)

        # Build a transaction with an unknown TLV on vout 0
        # Get a UTXO to spend
        try:
            utxos = node.listunspent()
        except Exception:
            # If listunspent fails, create a funded transaction using fundrawtransaction
            outputs = {node.getnewaddress(): 5.0}
            raw = node.createrawtransaction([], outputs)
            funded = node.fundrawtransaction(raw)
            signed = node.signrawtransactionwithwallet(funded['hex'])

            # TLV: type=0x99, len=1, value=0xAA
            tlv_hex = "9901aa"
            raw2 = node.rawtxaddoutext(signed['hex'], 0, tlv_hex)
            # Mempool/consensus must reject with reason 'outext'
            assert_raises_rpc_error(-26, "outext", node.sendrawtransaction, raw2)
            self.log.info("Unknown TLV transactions are rejected as expected")
            return

        if not utxos:
            self.generate(node, 1, sync_fun=self.no_op)
            utxos = node.listunspent()
        spend = utxos[0]
        inputs = [{"txid": spend["txid"], "vout": spend["vout"]}]
        outputs = {node.getnewaddress(): float(spend["amount"]) - 0.001}  # Leave some for fees
        raw = node.createrawtransaction(inputs, outputs)
        # TLV: type=0x99, len=1, value=0xAA
        tlv_hex = "9901aa"
        raw2 = node.rawtxaddoutext(raw, 0, tlv_hex)
        funded = node.fundrawtransaction(raw2)
        signed = node.signrawtransactionwithwallet(funded['hex'])

        # Mempool/consensus must reject with reason 'outext'
        assert_raises_rpc_error(-26, "outext", node.sendrawtransaction, signed['hex'])

        self.log.info("Unknown TLV transactions are rejected as expected")


if __name__ == '__main__':
    AssetUnknownTLVRejectTest(__file__).main()
