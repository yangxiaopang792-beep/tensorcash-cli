#!/usr/bin/env python3
"""Functional test for the mandatory v3 activation height (TIP-0003).

Drives real block submission (create_mining_work_unit -> solve -> submit) on a
regtest node with -v3activationheight set to a small height X, asserting the
consensus boundary that makes v3 MANDATORY (not optional) once active:

  height <  X : pre-v3 proofs are accepted (v2 low-reuse here).
  height >= X : pre-v3 proofs are rejected with `bad-proof-version-v3`
                (validation.cpp ContextualCheckBlock / ConnectBlock), because
                every mining proof must be version >= 3 so the prompt-binding
                admission / anti-grind rules apply network-wide.

This exercises the validation-LAYER gate, which QuickVerifier/vector unit
tests deliberately do not (QuickVerifier stays version-agnostic; mandatory v3
lives above it). The v3 ACCEPTANCE path (a genuine nonce-bound admission-band
proof) needs mining_response_builder v3 support and is a separate follow-up;
this test pins the rejection boundary that guards against pre-v3 mining after
activation.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.vdf_helper import HAS_CHIAVDF

REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"
ACTIVATION = 3  # -v3activationheight
V3_REJECT = "bad-proof-version-v3"


class V3ActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-v3activationheight=%d" % ACTIVATION,
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

        def mine(version=2, num_tokens=8):
            self._nonce += 1
            unit = node.create_mining_work_unit(
                REGTEST_NETWORK, P2_OP_TRUE_HEX, "%02x" % (self._nonce & 0xff))
            sol = solve_work_unit(unit["header_prefix"], unit["target"],
                                  num_tokens=num_tokens)
            payload = build_mining_response(unit["req_id"], sol,
                                            model_identifier=model_id, version=version)
            return node.submit_mining_response(unit["req_id"], payload)

        # --- below activation: pre-v3 (v2 low-reuse) is accepted ---
        self.log.info("mining v2 blocks up to height %d (below v3 activation)" % (ACTIVATION - 1))
        while node.getblockcount() < ACTIVATION - 1:
            res = mine(version=2, num_tokens=8)
            assert_equal(res["accepted"], True)
        assert_equal(node.getblockcount(), ACTIVATION - 1)

        # --- at activation: v2 rejected, v3 is mandatory ---
        self.log.info("v2 at v3 activation height must be rejected (%s)" % V3_REJECT)
        res = mine(version=2, num_tokens=8)
        assert_equal(res["accepted"], False)
        assert_equal(node.getblockcount(), ACTIVATION - 1)
        reason = res.get("reject_reason", "")
        self.log.info("  v2 reject reason: %s" % reason)
        assert V3_REJECT in reason, (
            "expected reject reason to contain %r, got %r" % (V3_REJECT, reason))

        # --- also reject an even-older version (v1) at activation ---
        self.log.info("v1 at v3 activation height must also be rejected")
        res = mine(version=1, num_tokens=8)
        assert_equal(res["accepted"], False)
        assert_equal(node.getblockcount(), ACTIVATION - 1)

        self.log.info("v3 mandatory-activation rejection boundary verified")


if __name__ == "__main__":
    V3ActivationTest(__file__).main()
