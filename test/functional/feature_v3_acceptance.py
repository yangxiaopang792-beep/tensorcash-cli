#!/usr/bin/env python3
"""Functional acceptance test for v3 prompt-binding admission (TIP-0003).

feature_v3_activation.py pins the mandatory-version *rejection* boundary. This
test drives the v3 *acceptance* path end-to-end through real block submission
(create_mining_work_unit -> solve -> submit_mining_response -> ProcessNewBlock),
exercising QuickVerifier's in-consensus v3 tier/admission/profile enforcement
(validation.cpp ContextualCheckBlock/ConnectBlock -> VerifyReuseEntropy ->
VerifyV3TierAndAdmission / VerifyV3SamplerProfile).

The transcripts are GENUINE: mining_response_builder.solve_v3_work_unit builds
per-step top-k evidence whose index-sorted CDF interval has a controlled width
(mass), so the verifier replays a real B_cred that crosses the real B_FLOOR/
B_FREE thresholds (45/70 bits) — no chain-param tier knobs.

Scenarios (height X = -v3activationheight):
  1. below X: a pre-v3 (v2) proof is accepted; and the v3 nonce rules are
     DORMANT (quick_verifier PrepareV3 returns before extracting/folding the
     nonce when height < X, keeping upgraded nodes byte-compatible with old
     nodes — accepting a nonce-BOUND transcript here would be a hard fork):
       1a. a v3 proof whose nonce is INERT carrier data (transcript built
           WITHOUT folding) is accepted.
       1b. a v3 proof whose nonce is FOLDED into u/final hash is rejected
           (u replay fails without the nonce on BOTH upgraded and old nodes).
  2. at   X: a pre-v3 (v2) proof is rejected (bad-proof-version-v3).
  3. at X: v3 free tier (B_cred >= 70, no nonce) is accepted.
  5. at X: v3 admission band (45 <= B_cred < 70) with NO nonce is rejected.
  6. at X: a valid-u transcript with a stripped / swapped nonce is rejected
           (nonce perturbs every u => tamper breaks the final-hash/u replay).
  7. at X: v3 free tier carrying a bad (unrelated) nonce is rejected.
  8. at X: a v3 proof with the wrong sampler profile (top_k != 50) is rejected.
  4. at X: v3 admission band with a VALID admissible nonce is accepted.
     Requires argon2 in the functional image AND a grindable registered model
     difficulty; skipped (logged) when either is unavailable, since it is the
     only scenario that must actually satisfy the Argon2id admission target.
"""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.vdf_helper import HAS_CHIAVDF

REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"
ACTIVATION = 4  # -v3activationheight (>=4: room for two pre-activation v3 cases)
V3_REJECT = "bad-proof-version-v3"

# n_entropic * ~2.0 bits/step (mass=0.25) picks the tier with margin from 45/70.
N_FREE = 40       # ~80 bits  -> Free
N_ADMISSION = 28  # ~56 bits  -> AdmissionRequired
BAD_NONCE_HEX = "ab" * 32


class V3AcceptanceTest(BitcoinTestFramework):
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
                build_mining_response, solve_v3_work_unit, solve_work_unit,
            )
        except ImportError as e:
            raise self.skip_test(
                "requires flatbuffers + mining_response_builder: %s" % e)

    def run_test(self):
        from test_framework import mining_response_builder as mrb
        node = self.nodes[0]
        self._nonce = 0

        registered = [m for m in node.getmodelslist()
                      if m["status"] == 2 and m["difficulty"] > 0]
        assert registered, "node has no registered model to mine against"
        model_id = "%s@%s" % (registered[0]["model_name"],
                              registered[0]["model_commit"])
        self._model_id = model_id
        self._model_difficulty = int(registered[0]["difficulty"])

        def work_unit():
            self._nonce += 1
            return node.create_mining_work_unit(
                REGTEST_NETWORK, P2_OP_TRUE_HEX, "%02x" % (self._nonce & 0xff))

        def submit(unit, sol, version):
            payload = mrb.build_mining_response(
                unit["req_id"], sol, model_identifier=model_id, version=version)
            return node.submit_mining_response(unit["req_id"], payload)

        def mine_v2(num_tokens=8):
            unit = work_unit()
            sol = mrb.solve_work_unit(unit["header_prefix"], unit["target"],
                                      num_tokens=num_tokens)
            return submit(unit, sol, version=2)

        def solve_v3(**kw):
            unit = work_unit()
            sol = mrb.solve_v3_work_unit(
                unit["header_prefix"], unit["target"], **kw)
            return unit, sol

        # ---- 1. below activation: v2 accepted + v3 nonce rules dormant ------
        self.log.info("[1] v2 accepted below activation; v3 nonce rules dormant")
        assert_equal(mine_v2()["accepted"], True)  # one block -> height 1

        # 1a. pre-activation v3 with an INERT nonce (transcript NOT folded):
        #     accepted — the extra_flags nonce is ignored while v3 is dormant.
        assert node.getblockcount() + 1 < ACTIVATION, "need a pre-activation height"
        unit, sol = solve_v3(n_entropic=N_FREE)  # u NOT folded with any nonce
        sol_inert = dict(sol, extra_flags=mrb.v3_extra_flags(BAD_NONCE_HEX))
        self.log.info("[1a] pre-activation v3 with inert nonce carrier accepted")
        assert_equal(submit(unit, sol_inert, version=3)["accepted"], True)

        # 1b. pre-activation v3 with a NONCE-BOUND transcript (u/final hash
        #     folded): rejected — u replays without the nonce here, so an old
        #     node would also reject it (no pre-activation fork).
        assert node.getblockcount() + 1 < ACTIVATION, "need a pre-activation height"
        unit, sol = solve_v3(n_entropic=N_FREE,
                             admission_nonce=bytes.fromhex(BAD_NONCE_HEX))
        self.log.info("[1b] pre-activation v3 with nonce-bound transcript rejected")
        res = submit(unit, sol, version=3)
        assert_equal(res["accepted"], False)
        self.log.info("    reject_reason: %s" % res.get("reject_reason", ""))

        while node.getblockcount() < ACTIVATION - 1:
            assert_equal(mine_v2()["accepted"], True)
        assert_equal(node.getblockcount(), ACTIVATION - 1)

        # ---- 2. at activation: v2 rejected (mandatory v3) -------------------
        self.log.info("[2] v2 at activation must be rejected (%s)" % V3_REJECT)
        res = mine_v2()
        assert_equal(res["accepted"], False)
        assert V3_REJECT in res.get("reject_reason", ""), res
        assert_equal(node.getblockcount(), ACTIVATION - 1)

        # ---- 3. v3 free tier (B_cred >= 70, no nonce) accepted --------------
        self.log.info("[3] v3 free tier (no nonce) accepted")
        unit, sol = solve_v3(n_entropic=N_FREE)
        self.log.info("    expected B_cred ~ %.1f bits" %
                      sol["expected_b_cred_bits"])
        res = submit(unit, sol, version=3)
        assert_equal(res["accepted"], True)
        assert_equal(node.getblockcount(), ACTIVATION)

        # From here every work unit is at height >= ACTIVATION. Each rejected
        # submission below leaves the tip unchanged, so they share this height.
        base_height = node.getblockcount()

        def assert_rejected(res, needle=None):
            assert_equal(res["accepted"], False)
            reason = res.get("reject_reason", "")
            self.log.info("    reject_reason: %s" % reason)
            if needle is not None:
                assert needle in reason, (needle, res)
            assert_equal(node.getblockcount(), base_height)

        # ---- 8. wrong sampler profile (v3 with top_k != 50) rejected --------
        self.log.info("[8] v3 with wrong sampler profile (top_k=8) rejected")
        unit = work_unit()
        bad_profile = mrb.solve_work_unit(  # greedy fixture => top_k=8
            unit["header_prefix"], unit["target"], num_tokens=8)
        assert_rejected(submit(unit, bad_profile, version=3), "sampler profile")

        # ---- 5. admission band, NO nonce rejected ---------------------------
        self.log.info("[5] v3 admission band (no nonce) rejected")
        unit, sol = solve_v3(n_entropic=N_ADMISSION)
        self.log.info("    expected B_cred ~ %.1f bits" %
                      sol["expected_b_cred_bits"])
        assert_rejected(submit(unit, sol, version=3), "admission nonce required")

        # ---- 6. nonce strip / swap on a valid-u transcript rejected ---------
        # Build a transcript whose u values (and final hash) are folded with a
        # real nonce, then tamper the claimed nonce. The verifier re-derives u
        # from the CLAIMED nonce, so both tampers break the final-hash replay.
        nonce_a = bytes.fromhex(BAD_NONCE_HEX)
        nonce_b = bytes.fromhex("cd" * 32)

        self.log.info("[6a] admission-band transcript with STRIPPED nonce rejected")
        unit, sol = solve_v3(n_entropic=N_ADMISSION, admission_nonce=nonce_a)
        sol_stripped = dict(sol, extra_flags=None)
        assert_rejected(submit(unit, sol_stripped, version=3))

        self.log.info("[6b] admission-band transcript with SWAPPED nonce rejected")
        unit, sol = solve_v3(n_entropic=N_ADMISSION, admission_nonce=nonce_a)
        sol_swapped = dict(sol, extra_flags=mrb.v3_extra_flags(nonce_b.hex()))
        assert_rejected(submit(unit, sol_swapped, version=3))

        # ---- 7. free tier carrying a bad (unrelated) nonce rejected ---------
        # u/final-hash built WITHOUT a nonce; claiming one makes the verifier
        # fold it into the replay => mismatch (present nonce is always verified).
        self.log.info("[7] v3 free tier with a bad present nonce rejected")
        unit, sol = solve_v3(n_entropic=N_FREE)  # no nonce in u
        sol_badnonce = dict(sol, extra_flags=mrb.v3_extra_flags(BAD_NONCE_HEX))
        assert_rejected(submit(unit, sol_badnonce, version=3))

        # ---- 4. admission band with a VALID admissible nonce accepted -------
        self._scenario_4(node, work_unit, submit, mrb, base_height)

        self.log.info("v3 acceptance scenarios verified")

    def _skip_or_fail(self, reason):
        """Scenario 4 is the ONLY positive-admission proof, so it is MANDATORY
        in CI: any skip path fails the test unless V3_ACCEPTANCE_ALLOW_SKIP=1 is
        set (local-only escape hatch for a dev box without argon2). This stops
        the positive-admission acceptance proof from silently degrading."""
        if os.environ.get("V3_ACCEPTANCE_ALLOW_SKIP") == "1":
            self.log.info("[4] SKIP (V3_ACCEPTANCE_ALLOW_SKIP=1): %s" % reason)
            return
        raise AssertionError(
            "scenario 4 (positive v3 admission) must run in CI but could not: "
            "%s. Set V3_ACCEPTANCE_ALLOW_SKIP=1 to allow skipping locally." % reason)

    def _scenario_4(self, node, work_unit, submit, mrb, base_height):
        """Positive admission: grind a nonce whose Argon2id digest is below the
        registered model's admission target, fold it into the transcript, submit.

        The admission digest depends ONLY on the nonce (msg_w and the prompt
        commitment are fixed once the work unit + deterministic VDF are), so the
        grind is Argon2id-only — the full transcript is rebuilt just once, with
        the winning nonce. MANDATORY in CI (see _skip_or_fail); the rejection
        scenarios above pin negative admission."""
        import struct
        try:
            import pow_v3  # vendored into the image's python path
        except ImportError:
            return self._skip_or_fail(
                "pow_v3/argon2 unavailable in functional image")
        target = pow_v3.admission_target(self._model_difficulty)
        expected_tries = pow_v3.admission_expected_tries(self._model_difficulty)
        max_grind = int(os.environ.get("V3_ADMISSION_MAX_GRIND", "5000"))
        if expected_tries > max_grind:
            return self._skip_or_fail(
                "expected_tries=%d > %d (difficulty=%d) — not grindable"
                % (expected_tries, max_grind, self._model_difficulty))

        self.log.info("[4] grinding admissible nonce (expected_tries~%d) ..."
                      % expected_tries)
        unit = work_unit()
        header_prefix_bytes = bytes.fromhex(unit["header_prefix"])
        # Deterministic VDF (fixed by prev_hash + tick), so msg_w and the prompt
        # commitment are stable across the whole grind — same values the C++
        # verifier rebuilds via BuildStepMessage(..., include_nonce=false).
        tick = 100000
        vdf = mrb.generate_vdf_proof(header_prefix_bytes[4:36], tick)
        msg_w = pow_v3.build_step_message(
            header_prefix_bytes, vdf, tick, 0, [], "fp16")  # no nonce, empty prompt
        commitment = pow_v3.prompt_commitment([], [])

        found = None
        for i in range(max_grind):
            nonce = struct.pack("<I", i) + b"\x00" * 28
            digest = pow_v3.argon2id_digest(
                pow_v3.admission_message(msg_w, self._model_id, nonce, commitment))
            if pow_v3.admission_valid(digest, target):
                found = nonce
                self.log.info("[4] admissible nonce found after %d tries" % (i + 1))
                break
        if found is None:
            return self._skip_or_fail("no admissible nonce in %d tries" % max_grind)

        sol = mrb.solve_v3_work_unit(
            unit["header_prefix"], unit["target"], tick=tick,
            n_entropic=N_ADMISSION, admission_nonce=found)
        res = submit(unit, sol, version=3)
        assert_equal(res["accepted"], True)
        assert node.getblockcount() == base_height + 1, res
        self.log.info("[4] admission-band block with valid nonce accepted")


if __name__ == "__main__":
    V3AcceptanceTest(__file__).main()
