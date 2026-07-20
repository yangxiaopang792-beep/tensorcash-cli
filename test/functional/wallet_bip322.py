#!/usr/bin/env python3
# Copyright (c) 2025 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests BIP-322 sign/verify message RPCs."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBIP322Test(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("default")
        wallet = node.get_wallet_rpc("default")

        # Mine a block so wallet has balance/keys initialized
        self.generate(node, 1, sync_fun=self.no_op)

        message = "tensor governance"

        self.log.info('Test signing with P2WPKH address')
        addr_wpkh = wallet.getnewaddress(address_type="bech32")
        sig_wpkh = wallet.signmessagebip322(addr_wpkh, message)
        self.log.info(f'Address: {addr_wpkh}')
        self.log.info(f'Signature: {sig_wpkh}')
        verify_result = wallet.verifymessagebip322(addr_wpkh, sig_wpkh, message)
        self.log.info(f'Verification result: {verify_result}')
        assert verify_result

        self.log.info('Test signing with Taproot address')
        addr_tr = wallet.getnewaddress(address_type="bech32m")
        sig_tr = wallet.signmessagebip322(addr_tr, message)
        self.log.info(f'Taproot Address: {addr_tr}')
        self.log.info(f'Taproot Signature: {sig_tr}')
        verify_tr = wallet.verifymessagebip322(addr_tr, sig_tr, message)
        self.log.info(f'Taproot Verification result: {verify_tr}')
        assert verify_tr

        self.log.info('Test verification fails for mismatched message')
        assert not wallet.verifymessagebip322(addr_tr, sig_tr, message + "!")

        self.log.info('Test that signing fails with locked wallet')
        wallet.encryptwallet("pass")
        self.stop_node(0)
        self.start_node(0)
        node = self.nodes[0]
        node.loadwallet("default")
        wallet = node.get_wallet_rpc("default")
        self.generate(node, 1, sync_fun=self.no_op)

        wallet.walletpassphrase("pass", 60)
        addr_locked = wallet.getnewaddress(address_type="bech32m")
        wallet.walletlock()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", wallet.signmessagebip322, addr_locked, message)

        self.log.info('Test that signing succeeds after unlocking wallet')
        wallet.walletpassphrase("pass", 60)
        sig_locked = wallet.signmessagebip322(addr_locked, message)
        assert wallet.verifymessagebip322(addr_locked, sig_locked, message)


if __name__ == '__main__':
    WalletBIP322Test(__file__).main()
