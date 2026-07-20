#!/usr/bin/env python3
"""Functional test for the version-keyed reuse-entropy activation height.

Drives real block submission (create_mining_work_unit -> solve -> submit) on a
regtest node with -reuseentropyheight set to a small height X, asserting the
consensus boundary:

  height < X : v1 (legacy) blocks are accepted (grandfathered).
  height >= X: v1 blocks are rejected (bad-proof-version, min-version);
               v2 blocks with high reuse are rejected (bad-reuse-entropy);
               v2 blocks with low reuse are accepted.

Greedy proofs from mining_response_builder have E_reuse == #steps, so
num_tokens controls whether a v2 proof clears the q32 cap (~57.7 forwards):
num_tokens=8 -> reuse 8 (passes), num_tokens=64 -> reuse 64 (rejected).
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.vdf_helper import HAS_CHIAVDF

REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"
ACTIVATION = 3  # -reuseentropyheight


class ReuseEntropyActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-reuseentropyheight=%d" % ACTIVATION,
            "-spv-asn-corroboration=0",
        ]]

    def skip_test_if_missing_module(self):
        if not HAS_CHIAVDF:
            raise self.skip_test("requires chiavdf for VDF proofs")
        try:
            import flatbuffers  # noqa: F401
            from test_framework.mining_response_builder import (  # noqa: F401
                build_mining_response, solve_work_unit,
            )
        except ImportError as e:
            raise self.skip_test("requires flatbuffers + mining_response_builder: %s" % e)

    def run_test(self):
        from test_framework.mining_response_builder import (
            build_mining_response, solve_work_unit,
        )
        node = self.nodes[0]
        self._nonce = 0

        registered = [m for m in node.getmodelslist()
                      if m["status"] == 2 and m["difficulty"] > 0]
        assert registered, "node has no registered model to mine against"
        model_id = "%s@%s" % (registered[0]["model_name"], registered[0]["model_commit"])

        def mine(version=1, num_tokens=8):
            self._nonce += 1
            unit = node.create_mining_work_unit(
                REGTEST_NETWORK, P2_OP_TRUE_HEX, "%02x" % (self._nonce & 0xff))
            sol = solve_work_unit(unit["header_prefix"], unit["target"],
                                  num_tokens=num_tokens)
            payload = build_mining_response(unit["req_id"], sol,
                                            model_identifier=model_id, version=version)
            return node.submit_mining_response(unit["req_id"], payload)

        # --- below activation: v1 is accepted (grandfathered) ---
        self.log.info("mining v1 blocks up to height %d (below activation)" % (ACTIVATION - 1))
        while node.getblockcount() < ACTIVATION - 1:
            res = mine(version=1)
            assert_equal(res["accepted"], True)
        assert_equal(node.getblockcount(), ACTIVATION - 1)

        # --- at activation: v1 rejected (min-version) ---
        self.log.info("v1 at activation height must be rejected (bad-proof-version)")
        res = mine(version=1)
        assert_equal(res["accepted"], False)
        assert_equal(node.getblockcount(), ACTIVATION - 1)
        self.log.info("  v1 reject reason: %s" % res.get("reject_reason"))

        # --- at activation: v2 high-reuse rejected (reuse gate) ---
        self.log.info("v2 high-reuse (num_tokens=64) must be rejected (bad-reuse-entropy)")
        res = mine(version=2, num_tokens=64)
        assert_equal(res["accepted"], False)
        assert_equal(node.getblockcount(), ACTIVATION - 1)
        self.log.info("  v2 high-reuse reject reason: %s" % res.get("reject_reason"))

        # --- at activation: v2 low-reuse accepted -> advances past X ---
        self.log.info("v2 low-reuse (num_tokens=8) must be accepted at activation")
        res = mine(version=2, num_tokens=8)
        assert_equal(res["accepted"], True)
        assert_equal(node.getblockcount(), ACTIVATION)

        # --- above activation: same rules hold ---
        self.log.info("above activation: v1 still rejected, v2 low-reuse accepted")
        res = mine(version=1)
        assert_equal(res["accepted"], False)
        res = mine(version=2, num_tokens=8)
        assert_equal(res["accepted"], True)
        assert_equal(node.getblockcount(), ACTIVATION + 1)

        self.log.info("reuse-entropy activation boundary verified")


if __name__ == "__main__":
    ReuseEntropyActivationTest(__file__).main()
