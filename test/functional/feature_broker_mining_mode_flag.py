#!/usr/bin/env python3
# Copyright (c) 2024-present The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Broker-mode hard guard — the -miningbrokermode flag.

When a node is started with -miningbrokermode=1, the sovereign mining entry
points (startmining, startminingwithrotation) must be refused so that
solutions cannot bypass the compute broker's lease index. The
broker-driven RPCs (create_mining_work_unit, submit_mining_response) and
read-only RPCs (getmininginfo) must continue to work.
"""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"

# RPC error codes (mirror src/rpc/protocol.h).
RPC_MISC_ERROR = -1
RPC_INVALID_ADDRESS_OR_KEY = -5


class BrokerMiningModeFlagTest(BitcoinTestFramework):
    def set_test_params(self):
        # Two nodes: one in compute-broker mode, one in sovereign (default)
        # mode. The pairing makes the assertions symmetrical so that the
        # flag is provably the only thing flipping behaviour. The sovereign
        # node is exercised through the address-validation error path so we
        # never actually start mining threads (which depend on the MINER
        # ZMQ endpoints being reachable from the test environment).
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-spv-asn-corroboration=0", "-miningbrokermode=1"],
            ["-spv-asn-corroboration=0"],
        ]
        self.supports_cli = False

    def run_test(self):
        broker_node = self.nodes[0]
        sovereign_node = self.nodes[1]

        # ------------------------------------------------------------------
        # Broker-mode node: sovereign entry points are refused, and the
        # refusal fires BEFORE address/wallet validation. This ordering
        # matters: if an operator misconfigures a node by setting
        # -miningbrokermode=1 alongside a stale mining systemd unit that
        # passes an address argument, the error message should point them
        # at the actual problem (wrong mining mode), not at the address.
        # ------------------------------------------------------------------
        self.log.info("Broker-mode node: startmining is refused with a clear mode error")
        # Deliberately pass a bogus address: the broker-mode guard must
        # win, so we expect RPC_MISC_ERROR with our mode message, NOT
        # RPC_INVALID_ADDRESS_OR_KEY.
        assert_raises_rpc_error(
            RPC_MISC_ERROR, "compute-broker mining mode",
            broker_node.startmining, "not-a-valid-address",
        )
        # Same with a valid address: still refused for the mode reason.
        assert_raises_rpc_error(
            RPC_MISC_ERROR, "compute-broker mining mode",
            broker_node.startmining, ADDRESS_BCRT1_UNSPENDABLE,
        )

        self.log.info("Broker-mode node: startminingwithrotation is refused with a clear mode error")
        # startminingwithrotation has a wallet precondition; the broker-mode
        # check must fire BEFORE the wallet lookup, otherwise an operator
        # who forgot to load a wallet would get the wrong error message.
        assert_raises_rpc_error(
            RPC_MISC_ERROR, "compute-broker mining mode",
            broker_node.startminingwithrotation,
        )

        # ------------------------------------------------------------------
        # Broker-mode node: broker RPCs and read-only RPCs still work.
        # ------------------------------------------------------------------
        self.log.info("Broker-mode node: getmininginfo still works (read-only RPCs unaffected)")
        info = broker_node.getmininginfo()
        assert "tip_hash" in info, info
        assert_equal(info["tip_hash"], broker_node.getbestblockhash())

        self.log.info("Broker-mode node: create_mining_work_unit still works")
        unit = broker_node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "01")
        assert "req_id" in unit, unit
        assert "header_prefix" in unit, unit
        assert "target" in unit, unit

        self.log.info("Broker-mode node: submit_mining_response dispatches past the mode guard")
        # We don't have valid proof::Proof FlatBuffer helpers in Python yet;
        # send obviously invalid base64 and assert the RPC itself dispatches.
        # The mode check would have thrown an RPC_MISC_ERROR; what we want
        # to see is a structured {"accepted": False, ...} response, which
        # proves we got past dispatch and into the FB validator.
        result = broker_node.submit_mining_response(unit["req_id"], "!!!not-base64!!!")
        assert_equal(result["accepted"], False)

        # ------------------------------------------------------------------
        # Sovereign-mode node: the broker-mode guard does NOT fire. We
        # prove this without actually starting mining threads (which
        # require external MINER endpoints) by passing an invalid address
        # and asserting we hit the address-validation error path instead.
        # ------------------------------------------------------------------
        self.log.info("Sovereign node: broker-mode guard does not fire; address validation runs")
        assert_raises_rpc_error(
            RPC_INVALID_ADDRESS_OR_KEY, "Invalid address",
            sovereign_node.startmining, "not-a-valid-address",
        )


if __name__ == "__main__":
    BrokerMiningModeFlagTest(__file__).main()
