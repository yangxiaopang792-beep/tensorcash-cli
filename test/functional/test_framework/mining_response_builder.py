#!/usr/bin/env python3
# Copyright (c) 2026-present The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build valid proof::MiningResponse FlatBuffers for broker-mining tests.

This is the Python helper the `submit_mining_response` done-when criterion
was gated on (feature_broker_mining_rpc.py). It produces payloads that pass
the FULL acceptance path on regtest:

    submit_mining_response (rpc/mining.cpp)
      -> fillFromFB (primitives/proofblob.cpp)
      -> QuickVerifier::QuickVerify (verification/quick_verifier.cpp)
      -> ProcessNewBlock -> CheckProofOfWork(GetShortHash(), nAdjBits)

The verification contract this mirrors (file references are the source of
truth — re-derive from them if QuickVerifier changes):

- VerifyVDF: real Wesolowski verify via vdf::VerifyAgainstPrevHash with
  challenge = header_prefix[4:36] (raw bytes), iterations = proof.tick,
  discriminant 1024 bits. There is NO regtest bypass, so a real chiavdf
  proof is required (vdf_helper.generate_vdf_proof).
- ComputeUValue / VerifyFinalHash message layout:
      header_prefix(76) || vdf || tick_u32_le || step_u32_le
      || window_tokens(POW_WINDOW_SIZE x int64_le, right-aligned context)
      || compute_precision_bytes
  hashed with single SHA256. Final hash uses step=0 and the full context
  (prompt + chosen; exactly chosen when len(chosen) == POW_WINDOW_SIZE);
  per-step U values use context = prompt + chosen[:step].
- DigestToU: first 4 digest bytes as a little-endian integer, divided by
  2^32, rounded once to float32. We replicate the float32 rounding exactly
  so the stored sampling_u matches the verifier's recomputation bit-for-bit
  (tolerance is 1e-7; ours is 0).
- VerifyHeaderPoW: nonce = first 4 bytes of the final hash;
  dSHA256(header_prefix || hash[:4]) interpreted little-endian must be
  <= target(nAdjBits at header_prefix[72:76]); proof.target must equal the
  32-byte big-endian serialisation of that target (the work unit's `target`
  hex). Regtest nBits 0x207fffff makes a random hash win ~50% of the time,
  so `solve_work_unit` grinds a salt token in chosen_tokens.
- VerifySampleStep: we give the chosen token logit 50.0 and every other
  candidate 0.0 with temperature=1.0, top_p=1.0, repetition_penalty=1.0,
  so after softmax its CDF interval is essentially (0, 1] and any U passes.
- VerifyEntropy: skipped entirely by omitting chosen_probs.
- Model registration: QuickVerifier::VerifyModelRegistration enforces that
  GetModelHash(model_identifier) exists in g_modeldb with difficulty > 0
  whenever g_modeldb is loaded — and on a live regtest bitcoind it IS
  loaded (the "regtest skips the model check" shortcut only holds for unit
  tests that never construct g_modeldb). The DB ships exactly one
  registered model; its (name, commit) are chain-dependent (TensorReg's is
  the empty model → identifier "@"). So callers must pass the identifier of
  an actually-registered model — query getmodelslist and use
  f'{name}@{commit}'. The MODEL_IDENTIFIER default below is only a fallback.
"""

import base64
import hashlib
import json
import math
import struct

import flatbuffers

from test_framework.proof_fb import (
    FloatArray as FA,
    MiningResponse as MR,
    Proof as PF,
    UIntArray as UA,
)
from test_framework.vdf_helper import generate_vdf_proof

# Must match verification/quick_verifier.h
POW_WINDOW_SIZE = 256

# Fallback model identifier. Real callers should pass the identifier of a
# model the node actually has registered (getmodelslist); on TensorReg that
# is the empty model, identifier "@". GetModelHash requires an '@'.
MODEL_IDENTIFIER = "@"
COMPUTE_PRECISION = "fp16"

# Sampling parameters chosen to make VerifySampleStep trivially satisfiable
# while staying inside VerifyParameters' allowed ranges (quick_verifier.h).
TEMPERATURE = 1.0
TOP_P = 1.0
TOP_K = 8
REPETITION_PENALTY = 1.0

# --- v3 (TIP-0003) sampler profile + B_cred tier constants -------- #
# The v3 sampler profile is FIXED and enforced by QuickVerifier when a proof
# is v3-active (pow_v3::SAMPLER_V3_TOP_K etc.); any deviation is rejected.
V3_PROOF_VERSION = 3
V3_TOP_K = 50
V3_TEMPERATURE = 1.0
V3_TOP_P = 1.0
V3_REPETITION_PENALTY = 1.0

# Mirror verification/pow_v3.h §4/§5 so the builder can target a tier exactly.
# The credit is the REAL consensus computation (R=1024 table via pow_v3), so
# the builder's tier prediction matches the verifier's bit-for-bit. pow_v3 is
# vendored beside the functional tests (cwd on sys.path).
import pow_v3 as _pow_v3

V3_ATOL = _pow_v3.ATOL
V3_B_FLOOR_BITS = _pow_v3.B_FLOOR_BITS
V3_B_FREE_BITS = _pow_v3.B_FREE_BITS
V3_BCRED_R = _pow_v3.BCRED_R
# A tiny filler logit: prob e^-60 ~ 9e-27 > 0 (kept in the CDF) but far below
# the chosen interval and pinned to high, non-colliding ids so it can never
# shift the chosen token's [lower, upper]. 47 fillers perturb the softmax
# normaliser by <5e-25, negligible against the interval margin (>= mass/2).
_V3_FILLER_LOGIT = -60.0
_V3_FILLER_ID_BASE = 0x40000000  # 2^30: above any chosen id, below the 2^31 v1 fillers


def v3_step_credit_units(mass):
    """Consensus credit units for one entropic step of interval width ``mass``
    (R=1024 table via pow_v3; R units == 1 bit). The verifier replays width ==
    mass, so this equals credit_units_for_step(mass_q63_for_step(0, mass))."""
    return _pow_v3.credit_units_for_step(
        _pow_v3.mass_q63_for_step(0.0, float(mass)))


def v3_step_bits(mass, atol=V3_ATOL):
    """Float view of v3_step_credit_units for sizing/logging (units / R)."""
    return v3_step_credit_units(mass) / V3_BCRED_R


def _v3_entropic_row(u, chosen_id, mass, top_k=V3_TOP_K):
    """Top-k evidence for one entropic step.

    Positions the chosen token's index-sorted CDF interval as [L, L+mass] with
    ``u`` centred inside it, so QuickVerifier::ComputeCDF replays width==mass
    (=> credited bits == v3_step_bits(mass)) and VerifySampleStep's in-bounds
    check (u in [lower-ATOL, upper+ATOL]) passes with margin ~mass/2. Returns
    (logits[top_k], indices[top_k]); chosen kept at position 0 by convention
    (ComputeCDF sorts by index, so order is otherwise irrelevant).
    """
    m = float(mass)
    assert 0.0 < m < 1.0, m
    L = min(max(u - m / 2.0, 0.0), 1.0 - m)  # lower CDF edge; u centred
    hi = 1.0 - L - m                          # prob of the id above chosen
    ids = [chosen_id]
    logits = [math.log(m)]
    if L > 0.0:
        ids.append(chosen_id - 1)
        logits.append(math.log(L))
    if hi > 0.0:
        ids.append(chosen_id + 1)
        logits.append(math.log(hi))
    n_filler = top_k - len(ids)
    assert n_filler >= 0, (top_k, len(ids))
    ids += [_V3_FILLER_ID_BASE + j for j in range(n_filler)]
    logits += [_V3_FILLER_LOGIT] * n_filler
    return logits, ids


def _v3_greedy_row(chosen_id, top_k=V3_TOP_K):
    """Top-k evidence for a 0-bit step: chosen dominates, interval ~[0,1]."""
    ids = [chosen_id] + [_V3_FILLER_ID_BASE + j for j in range(top_k - 1)]
    logits = [50.0] + [0.0] * (top_k - 1)
    return logits, ids


def _f32(x):
    """Round a Python float to its float32 value (as a Python float)."""
    return struct.unpack("<f", struct.pack("<f", x))[0]


def _digest_to_u(digest):
    """Mirror QuickVerifier::DigestToU (quick_verifier.cpp).

    C++ sums b0 + b1*2^8 + b2*2^16 + b3*2^24 in float32 and divides by 2^32.
    The partial sums up to b2*2^16 are exact integers below 2^24 (exactly
    representable in float32); the only rounding happens adding b3*2^24,
    i.e. a single round-to-nearest of the exact uint32 value. Dividing by
    2^32 is exact. So float32(uint32_value) / 2^32 == float32(uint32_value
    / 2^32), which is what we compute here.
    """
    val = struct.unpack("<I", digest[:4])[0]
    return _f32(val / 4294967296.0)


def _pow_message(header_prefix, vdf, tick, step, context, admission_nonce=None):
    """The SHA256 preimage shared by ComputeUValue and VerifyFinalHash.

    v3 (TIP-0003): when ``admission_nonce`` (32 raw bytes) is given
    it is appended AFTER the precision string, so it perturbs every u draw and
    the final hash. Mirrors pow_v3.build_step_message(admission_nonce=...).
    """
    msg = bytearray()
    msg += header_prefix
    msg += vdf
    msg += struct.pack("<I", tick & 0xFFFFFFFF)  # C++ truncates tick to u32
    msg += struct.pack("<I", step)
    window = [0] * POW_WINDOW_SIZE
    ctx_len = min(len(context), POW_WINDOW_SIZE)
    if ctx_len:
        window[POW_WINDOW_SIZE - ctx_len:] = context[-ctx_len:]
    for token in window:
        msg += struct.pack("<q", token)
    msg += COMPUTE_PRECISION.encode()
    if admission_nonce is not None:
        assert len(admission_nonce) == 32, len(admission_nonce)
        msg += bytes(admission_nonce)
    return bytes(msg)


def compute_final_hash(header_prefix, vdf, tick, prompt_tokens, chosen_tokens,
                       admission_nonce=None):
    """Mirror QuickVerifier::VerifyFinalHash's recomputation (step=0)."""
    if len(chosen_tokens) == POW_WINDOW_SIZE:
        ctx = list(chosen_tokens)
    else:
        ctx = list(prompt_tokens) + list(chosen_tokens)
    return hashlib.sha256(
        _pow_message(header_prefix, vdf, tick, 0, ctx, admission_nonce)
    ).digest()


def compute_sampling_u(header_prefix, vdf, tick, prompt_tokens, chosen_tokens,
                       admission_nonce=None):
    """Mirror QuickVerifier::GetUValues: context excludes the current step."""
    us = []
    for step in range(len(chosen_tokens)):
        ctx = list(prompt_tokens) + list(chosen_tokens[:step])
        digest = hashlib.sha256(
            _pow_message(header_prefix, vdf, tick, step, ctx, admission_nonce)
        ).digest()
        us.append(_digest_to_u(digest))
    return us


def _dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def solve_work_unit(header_prefix_hex, target_hex, *, tick=100000,
                    num_tokens=8, want_winner=True, max_attempts=4096):
    """Solve (or deliberately lose) a create_mining_work_unit work unit.

    Grinds the last chosen token until dSHA256(header_prefix || hash[:4])
    is <= target (want_winner=True) or > target (want_winner=False — used
    to exercise the quick_verify_failed path with an otherwise well-formed
    proof). Regtest's 0x207fffff target wins ~50% per attempt, so both
    grinds converge in a couple of iterations.

    Returns a dict consumed by build_mining_response().
    """
    header_prefix = bytes.fromhex(header_prefix_hex)
    assert len(header_prefix) == 76, len(header_prefix)
    target_int = int(target_hex, 16)
    target_bytes = bytes.fromhex(target_hex)
    assert len(target_bytes) == 32, len(target_bytes)

    # VerifyVDF's challenge is the raw prev-hash bytes from the prefix.
    prev_hash = header_prefix[4:36]
    vdf = generate_vdf_proof(prev_hash, tick)

    adjusted_bits = struct.unpack("<I", header_prefix[72:76])[0]

    base_tokens = [101 + i for i in range(num_tokens - 1)]
    for salt in range(max_attempts):
        chosen_tokens = base_tokens + [salt]
        final_hash = compute_final_hash(header_prefix, vdf, tick, [], chosen_tokens)
        header_hash = _dsha256(header_prefix + final_hash[:4])
        # uint256 stores little-endian; UintToArith256 compares numerically.
        is_winner = int.from_bytes(header_hash, "little") <= target_int
        if is_winner == want_winner:
            return {
                "header_prefix": header_prefix,
                "target": target_bytes,
                "vdf": vdf,
                "tick": tick,
                "chosen_tokens": chosen_tokens,
                "final_hash": final_hash,
                "sampling_u": compute_sampling_u(
                    header_prefix, vdf, tick, [], chosen_tokens
                ),
                "nonce": struct.unpack("<I", final_hash[:4])[0],
                "adjusted_bits": adjusted_bits,
            }
    raise RuntimeError(
        f"no {'winning' if want_winner else 'losing'} salt in "
        f"{max_attempts} attempts — target {target_hex} is degenerate?"
    )


def v3_extra_flags(admission_nonce_hex):
    """The canonical extra_flags carrier for a claimed nonce (mirrors
    pow_v3.merge_extra_flags_v3 over an empty base)."""
    return json.dumps({"v3": {"admission_nonce": admission_nonce_hex}},
                      separators=(",", ":"))


def solve_v3_work_unit(header_prefix_hex, target_hex, *, tick=100000,
                       n_entropic=40, n_greedy=8, mass=0.25,
                       admission_nonce=None, prompt_tokens=None, pad_mask=None,
                       want_winner=True, max_attempts=8192):
    """Solve a work unit with a genuine v3 transcript of controlled B_cred.

    Builds ``n_entropic`` entropic steps (each interval width == ``mass``) and
    ``n_greedy`` greedy steps, then grinds a final salt token for header PoW.
    The salt is the LAST chosen token, so it perturbs only the final hash (its
    step's u uses context that excludes it); every entropic step's u and CDF
    evidence is fixed independently of the grind.

    B_cred == n_entropic * v3_step_credit_units(mass): with mass=0.25 that is
    ~2.0 bits/step, so n_entropic tunes the tier (>=70 free, [45,70) admission,
    <45 invalid). ``admission_nonce`` (32 bytes), when given, is folded into
    every u and the final hash (§7) and carried in extra_flags.
    """
    header_prefix = bytes.fromhex(header_prefix_hex)
    assert len(header_prefix) == 76, len(header_prefix)
    target_int = int(target_hex, 16)
    target_bytes = bytes.fromhex(target_hex)
    assert len(target_bytes) == 32, len(target_bytes)

    prev_hash = header_prefix[4:36]
    vdf = generate_vdf_proof(prev_hash, tick)
    adjusted_bits = struct.unpack("<I", header_prefix[72:76])[0]
    prompt_tokens = list(prompt_tokens or [])
    n_steps = n_entropic + n_greedy + 1  # + salt

    # Entropic chosen ids (1000..) and greedy chosen ids (5000..) are disjoint
    # from each other, from the salt (small ints), and from the 2^30 fillers.
    fixed = ([1000 + i for i in range(n_entropic)]
             + [5000 + i for i in range(n_greedy)])

    for salt in range(max_attempts):
        chosen = fixed + [salt]
        final_hash = compute_final_hash(
            header_prefix, vdf, tick, prompt_tokens, chosen, admission_nonce)
        header_hash = _dsha256(header_prefix + final_hash[:4])
        is_winner = int.from_bytes(header_hash, "little") <= target_int
        if is_winner == want_winner:
            break
    else:
        raise RuntimeError(
            f"no {'winning' if want_winner else 'losing'} salt in "
            f"{max_attempts} attempts — target {target_hex} degenerate?")

    chosen = fixed + [salt]
    us = compute_sampling_u(
        header_prefix, vdf, tick, prompt_tokens, chosen, admission_nonce)

    logits_rows, indices_rows = [], []
    for step in range(n_steps):
        if step < n_entropic:
            lr, ir = _v3_entropic_row(us[step], chosen[step], mass)
        else:
            lr, ir = _v3_greedy_row(chosen[step])
        logits_rows.append(lr)
        indices_rows.append(ir)

    extra_flags = None
    if admission_nonce is not None:
        extra_flags = v3_extra_flags(bytes(admission_nonce).hex())

    return {
        "header_prefix": header_prefix,
        "target": target_bytes,
        "vdf": vdf,
        "tick": tick,
        "chosen_tokens": chosen,
        "final_hash": final_hash,
        "sampling_u": us,
        "nonce": struct.unpack("<I", final_hash[:4])[0],
        "adjusted_bits": adjusted_bits,
        # v3 carriers consumed by build_mining_response:
        "top_k": V3_TOP_K,
        "temperature": V3_TEMPERATURE,
        "top_p": V3_TOP_P,
        "repetition_penalty": V3_REPETITION_PENALTY,
        "topk_logits_rows": logits_rows,
        "topk_indices_rows": indices_rows,
        "prompt_tokens": prompt_tokens,
        "pad_mask": list(pad_mask) if pad_mask is not None else None,
        "extra_flags": extra_flags,
        "expected_b_cred_units": n_entropic * v3_step_credit_units(mass),
        "expected_b_cred_bits": n_entropic * v3_step_bits(mass),
    }


def build_mining_response(req_id, solution, completion_id=None,
                          model_identifier=MODEL_IDENTIFIER, version=1):
    """Serialise a solved work unit into a base64 proof::MiningResponse.

    model_identifier must name a model registered on the target node
    (getmodelslist) or QuickVerifier::VerifyModelRegistration rejects the
    submission as quick_verify_failed.

    version sets proof.version: < REUSE_GATE_VERSION (2) is legacy/grandfathered,
    >= 2 is gated by the q32 reuse-entropy rule. (greedy proofs from this builder
    have E_reuse == #steps, so num_tokens controls whether a v2 proof passes.)
    """
    builder = flatbuffers.Builder(8192)

    chosen_tokens = solution["chosen_tokens"]
    n = len(chosen_tokens)

    # v3 solutions (solve_v3_work_unit) carry genuine per-step evidence and the
    # fixed v3 sampler profile; v1/v2 solutions fall back to the greedy fixture
    # (chosen logit 50.0, fillers 0.0 -> CDF interval ~(0,1], B_cred ~ 0).
    top_k = solution.get("top_k", TOP_K)
    temperature = solution.get("temperature", TEMPERATURE)
    top_p = solution.get("top_p", TOP_P)
    repetition_penalty = solution.get("repetition_penalty", REPETITION_PENALTY)
    v3_logits_rows = solution.get("topk_logits_rows")
    v3_indices_rows = solution.get("topk_indices_rows")
    greedy_fillers = [0x80000000 + j for j in range(top_k - 1)]
    greedy_logits = [50.0] + [0.0] * (top_k - 1)

    fa_offsets = []
    ua_offsets = []
    for step in range(n):
        if v3_logits_rows is not None:
            logits_row = v3_logits_rows[step]
            indices_row = v3_indices_rows[step]
        else:
            logits_row = greedy_logits
            indices_row = [chosen_tokens[step]] + greedy_fillers
        row_len = len(logits_row)

        FA.StartValuesVector(builder, row_len)
        for v in reversed(logits_row):
            builder.PrependFloat32(v)
        vals = builder.EndVector()
        FA.Start(builder)
        FA.AddValues(builder, vals)
        fa_offsets.append(FA.End(builder))

        UA.StartValuesVector(builder, row_len)
        for v in reversed(indices_row):
            builder.PrependUint32(v)
        vals = builder.EndVector()
        UA.Start(builder)
        UA.AddValues(builder, vals)
        ua_offsets.append(UA.End(builder))

    PF.StartTopkLogitsVector(builder, n)
    for off in reversed(fa_offsets):
        builder.PrependUOffsetTRelative(off)
    topk_logits_off = builder.EndVector()

    PF.StartTopkIndicesVector(builder, n)
    for off in reversed(ua_offsets):
        builder.PrependUOffsetTRelative(off)
    topk_indices_off = builder.EndVector()

    PF.StartChosenTokensVector(builder, n)
    for v in reversed(chosen_tokens):
        builder.PrependUint32(v)
    chosen_tokens_off = builder.EndVector()

    PF.StartSamplingUVector(builder, n)
    for v in reversed(solution["sampling_u"]):
        builder.PrependFloat32(v)
    sampling_u_off = builder.EndVector()

    # v3 prompt-binding carriers (optional). prompt_tokens + pad_mask feed
    # pow_v3.prompt_commitment; extra_flags carries the claimed admission nonce.
    prompt_tokens = solution.get("prompt_tokens")
    prompt_tokens_off = None
    if prompt_tokens:
        PF.StartPromptTokensVector(builder, len(prompt_tokens))
        for v in reversed(prompt_tokens):
            builder.PrependUint32(v)
        prompt_tokens_off = builder.EndVector()

    pad_mask = solution.get("pad_mask")
    pad_mask_off = None
    if pad_mask:
        PF.StartPadMaskVector(builder, len(pad_mask))
        for v in reversed(pad_mask):
            builder.PrependBool(bool(v))
        pad_mask_off = builder.EndVector()

    target_off = builder.CreateByteVector(solution["target"])
    vdf_off = builder.CreateByteVector(solution["vdf"])
    hash_off = builder.CreateByteVector(solution["final_hash"])
    block_hash_off = builder.CreateByteVector(solution["header_prefix"][4:36])
    header_prefix_off = builder.CreateByteVector(solution["header_prefix"])
    model_id_off = builder.CreateString(model_identifier)
    precision_off = builder.CreateString(COMPUTE_PRECISION)
    extra_flags_val = solution.get("extra_flags")
    extra_flags_off = (
        builder.CreateString(extra_flags_val) if extra_flags_val else None
    )

    PF.Start(builder)
    PF.AddVersion(builder, version)
    PF.AddTick(builder, solution["tick"])
    PF.AddTimestamp(builder, 1700000000)
    PF.AddTarget(builder, target_off)
    PF.AddVdf(builder, vdf_off)
    PF.AddHash(builder, hash_off)
    PF.AddBlockHash(builder, block_hash_off)
    PF.AddHeaderPrefix(builder, header_prefix_off)
    PF.AddIsSolution(builder, True)
    PF.AddModelIdentifier(builder, model_id_off)
    PF.AddComputePrecision(builder, precision_off)
    if extra_flags_off is not None:
        PF.AddExtraFlags(builder, extra_flags_off)
    PF.AddTemperature(builder, temperature)
    PF.AddTopP(builder, top_p)
    PF.AddTopK(builder, top_k)
    PF.AddRepetitionPenalty(builder, repetition_penalty)
    PF.AddChosenTokens(builder, chosen_tokens_off)
    PF.AddSamplingU(builder, sampling_u_off)
    if prompt_tokens_off is not None:
        PF.AddPromptTokens(builder, prompt_tokens_off)
    if pad_mask_off is not None:
        PF.AddPadMask(builder, pad_mask_off)
    PF.AddTopkLogits(builder, topk_logits_off)
    PF.AddTopkIndices(builder, topk_indices_off)
    # chosen_probs deliberately omitted: VerifyEntropy skips when empty.
    proof_off = PF.End(builder)

    # Only the 32-byte size is validated (kBrokerExpectedHashSize); derive
    # deterministically from the final hash for log readability.
    pow_blob_hash_off = builder.CreateByteVector(
        hashlib.sha256(solution["final_hash"]).digest()
    )
    completion_off = (
        builder.CreateString(completion_id) if completion_id else None
    )

    MR.Start(builder)
    MR.AddReqId(builder, req_id)
    MR.AddNonce(builder, solution["nonce"])
    MR.AddAdjustedBits(builder, solution["adjusted_bits"])
    MR.AddPowBlobHash(builder, pow_blob_hash_off)
    MR.AddDifficulty(builder, solution["adjusted_bits"])
    MR.AddPowBlob(builder, proof_off)
    if completion_off is not None:
        MR.AddCompletionId(builder, completion_off)
    builder.Finish(MR.End(builder))

    return base64.b64encode(bytes(builder.Output())).decode("ascii")
