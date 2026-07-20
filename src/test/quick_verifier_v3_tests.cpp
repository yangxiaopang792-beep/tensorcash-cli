// Copyright (c) 2026 TensorCash
// QuickVerifier v3 prompt-binding enforcement tests (TIP-0003).
//
// Fixture strategy: g_genesisBlob is a real, fully valid 256-step proof whose
// sampler fields happen to equal the consensus-fixed v3.0 profile
// (temperature=1.0, top_p=1.0, top_k=50, repetition_penalty=1.0), so flipping
// its version to 3 exercises the v3 paths without re-mining. Because the
// proof's true B_cred is a property of its real sampling, tier tests pin the
// outcome by moving the B_FLOOR/B_FREE chain params to impossible extremes
// (max possible B_cred is 256 steps * 32-bit/step cap = 8192 bits) instead of
// assuming a measured value. QuickVerify(proof, /*enforce_reuse_entropy=*/false)
// is used where the (orthogonal, already-tested) v2 reuse gate would obscure
// the v3 verdict; VerifyReuseEntropy is used to reach the v3 tier/admission
// logic without the final-hash/header-PoW checks when the fixture cannot
// satisfy them (a nonce changes the proof hash, and re-satisfying header PoW
// would require re-mining).

#include <boost/test/unit_test.hpp>

#include <consensus/params.h>
#include <kernel/genesis_proof.h>
#include <modeldb.h>
#include <primitives/proofblob.h>
#include <test/util/setup_common.h>
#include <verification/pow_v3.h>
#include <verification/quick_verifier.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr int64_t TEST_MODEL_DIFFICULTY{1000};

// Register the genesis model so VerifyModelRegistration passes (same helper
// as quick_verify_tests, renamed to avoid an ODR clash).
void RegisterV3TestModel()
{
    if (!g_modeldb) return;
    const uint256 model_hash = g_genesisBlob.GetModelHash();
    ModelRecord record;
    record.metadata.model_name = "Qwen/Qwen3-8B";
    record.metadata.model_commit = "9c925d64d72725edaf899c6cb9c377fd0709d9c5";
    record.metadata.difficulty = TEST_MODEL_DIFFICULTY;
    record.metadata.cid = "test_cid";
    record.metadata.extra = "";
    record.status = ModelRegistrationStatus::Registered;
    g_modeldb->WriteModel(model_hash, record);
}

// Chain params with v3 active from genesis and the given tier thresholds (in
// credited bits). Everything else keeps the params.h defaults, which mirror
// the vendored pow_v3 constants.
Consensus::Params V3Params(uint64_t floor_bits, uint64_t free_bits, int activation_height = 0)
{
    Consensus::Params params{};
    params.V3ActivationHeight = activation_height;
    params.V3BFloorBits = floor_bits;
    params.V3BFreeBits = free_bits;
    return params;
}

// Above the per-proof maximum (256 steps * 32-bit per-step cap), so any real
// B_cred is guaranteed below a threshold set to this.
constexpr uint64_t IMPOSSIBLE_BITS{8193};

std::array<uint8_t, 32> TestNonce()
{
    std::array<uint8_t, 32> n{};
    for (size_t i = 0; i < n.size(); ++i) n[i] = static_cast<uint8_t>(0xA0 + i);
    return n;
}

std::string NonceHex(const std::array<uint8_t, 32>& nonce)
{
    static const char* hexmap = "0123456789abcdef";
    std::string out;
    for (uint8_t b : nonce) {
        out.push_back(hexmap[b >> 4]);
        out.push_back(hexmap[b & 0x0F]);
    }
    return out;
}

// Reshape every step so the chosen token dominates (mass ~= 1): any u falls in
// the chosen bucket, so recomputed (nonce-perturbed) u values still verify.
// Side effects: B_cred ~= 0 and the v2 reuse gate rejects — tests account for
// both. Copied from quick_verify_tests' ForceGreedyReuse.
void ForceGreedy(CProofBlob& blob)
{
    const float T = (blob.temperature != 0.0f) ? blob.temperature : 1.0f;
    for (size_t i = 0; i < blob.chosen_tokens.size(); ++i) {
        const uint32_t ch = blob.chosen_tokens[i];
        if (i < blob.topk_indices.size() && i < blob.topk_logits.size()) {
            auto& idx = blob.topk_indices[i];
            auto& lg = blob.topk_logits[i];
            for (size_t j = 0; j < idx.size() && j < lg.size(); ++j) {
                lg[j] = (idx[j] == ch) ? 100.0f : -100.0f;
            }
        }
        if (i < blob.softmax_normalizers.size()) {
            blob.softmax_normalizers[i] = 100.0f / T;
        }
    }
}

// Recompute every sampling_u through the vendored pow_v3 step hashing with the
// nonce appended (§7) — the miner-side counterpart of the verifier's replay.
void RecomputeUsWithNonce(CProofBlob& blob, const std::array<uint8_t, 32>& nonce)
{
    std::vector<int64_t> ctx(blob.prompt_tokens.begin(), blob.prompt_tokens.end());
    for (size_t step = 0; step < blob.chosen_tokens.size(); ++step) {
        const std::vector<uint8_t> msg = pow_v3::build_step_message(
            blob.header_prefix, blob.vdf, static_cast<uint32_t>(blob.tick),
            static_cast<uint32_t>(step), ctx, blob.compute_precision, nonce.data());
        blob.sampling_u[step] =
            static_cast<float>(pow_v3::step_u_from_digest(pow_v3::step_digest(msg)));
        ctx.push_back(static_cast<int64_t>(blob.chosen_tokens[step]));
    }
}

// Recompute the final proof hash with the nonce appended (§7): same message
// as the step hash with step=0 over the final context (at the 256-token
// window boundary the context is exactly the chosen tokens, mirroring
// VerifyFinalHash).
void RecomputeFinalHashWithNonce(CProofBlob& blob, const std::array<uint8_t, 32>& nonce)
{
    std::vector<int64_t> ctx;
    if (blob.chosen_tokens.size() == 256) {
        ctx.assign(blob.chosen_tokens.begin(), blob.chosen_tokens.end());
    } else {
        ctx.assign(blob.prompt_tokens.begin(), blob.prompt_tokens.end());
        for (uint32_t t : blob.chosen_tokens) ctx.push_back(static_cast<int64_t>(t));
    }
    const std::vector<uint8_t> msg = pow_v3::build_step_message(
        blob.header_prefix, blob.vdf, static_cast<uint32_t>(blob.tick), 0, ctx,
        blob.compute_precision, nonce.data());
    const std::array<uint8_t, 32> digest = pow_v3::step_digest(msg);
    blob.hash.assign(digest.begin(), digest.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(quick_verifier_v3_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(final_hash_only_rejects_sampling_hash_mismatch)
{
    CProofBlob proof = g_genesisBlob;
    QuickVerifier verifier;

    BOOST_REQUIRE_MESSAGE(verifier.VerifyFinalHashOnly(proof),
                          "fixture final hash must verify: " + verifier.GetLastError());

    proof.hash[0] ^= 0x01;
    BOOST_CHECK(!verifier.VerifyFinalHashOnly(proof));
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());
}

BOOST_AUTO_TEST_CASE(final_hash_only_uses_active_v3_nonce)
{
    const auto nonce = TestNonce();
    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(nonce));

    const Consensus::Params params = V3Params(0, 0);
    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);

    BOOST_CHECK(!verifier.VerifyFinalHashOnly(v3));
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());

    RecomputeFinalHashWithNonce(v3, nonce);
    BOOST_CHECK_MESSAGE(verifier.VerifyFinalHashOnly(v3),
                        "nonce-inclusive final hash must verify: " + verifier.GetLastError());
}

// §5/§7 — the gap this closes: a proof whose committed final hash is DECOUPLED
// from its sampling (in prod, arbitrary bytes that still meet the header-PoW
// target while the sampling sequence replays) is exactly the "Sampling hash
// inconsistent with recomputation" reject the external validator emits. The
// consensus-path entry VerifyReuseEntropy (ConnectBlock / ContextualCheckBlock)
// now catches it in-node rather than deferring solely to the external
// validator, closing the quick-pass/full-fail gap.
BOOST_AUTO_TEST_CASE(v3_reuse_entropy_rejects_decoupled_final_hash)
{
    RegisterV3TestModel();
    const Consensus::Params params = V3Params(/*floor=*/0, /*free=*/0); // free tier

    // Control: the unmodified v3 proof (no nonce) is NOT rejected at the
    // final-hash stage — its valid committed hash passes. Any later reuse-gate
    // verdict is orthogonal and must never surface as "Final hash mismatch".
    {
        CProofBlob v3 = g_genesisBlob;
        v3.version = 3;
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
        (void)verifier.VerifyReuseEntropy(v3);
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") == std::string::npos,
                            "valid final hash must not be rejected: " + verifier.GetLastError());
    }

    // Decoupled hash: flip one committed-hash byte and change nothing else, so
    // the sampling sequence is untouched and would replay — yet the consensus
    // entry now rejects at the final-hash commitment.
    {
        CProofBlob v3 = g_genesisBlob;
        v3.version = 3;
        v3.hash[0] ^= 0x01;
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") != std::string::npos,
                            "consensus entry must reject a decoupled final hash: " + verifier.GetLastError());
    }

    // Safety: a legacy proof (version < REUSE_GATE_VERSION) is grandfathered —
    // all chain history is v1, so the newly-enforced check can never
    // retroactively reject a historical block, even with a corrupt hash.
    {
        CProofBlob v1 = g_genesisBlob;
        v1.version = 1;
        v1.hash[0] ^= 0x01;
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK_MESSAGE(verifier.VerifyReuseEntropy(v1),
                            "grandfathered legacy proof must not be entropy-gated: " + verifier.GetLastError());
    }
}

// Pre-activation heights and missing context leave version-3 proofs verified
// byte-identically to v2; v2 proofs are untouched at ANY height (§1).
BOOST_AUTO_TEST_CASE(v3_rules_dormant_pre_activation_and_for_v2)
{
    RegisterV3TestModel();
    QuickVerifier verifier;

    // Fixture sanity: the unmodified proof passes without the reuse gate.
    CProofBlob v2 = g_genesisBlob;
    v2.version = 2;
    BOOST_REQUIRE_MESSAGE(verifier.QuickVerify(v2, /*enforce_reuse_entropy=*/false) == VerificationResult::Quick_OK,
                          "fixture: " + verifier.GetLastError());

    // version=3, no chain context provided: dormant.
    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    BOOST_CHECK_MESSAGE(verifier.QuickVerify(v3, false) == VerificationResult::Quick_OK,
                        "no-context v3 must be dormant: " + verifier.GetLastError());

    // version=3, context present but height below activation: dormant, even
    // with tier thresholds that would reject if the rules were live.
    const Consensus::Params not_yet = V3Params(IMPOSSIBLE_BITS, IMPOSSIBLE_BITS, /*activation_height=*/1000);
    verifier.SetV3Context(not_yet, /*height=*/999, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK_MESSAGE(verifier.QuickVerify(v3, false) == VerificationResult::Quick_OK,
                        "pre-activation v3 must be dormant: " + verifier.GetLastError());

    // version=2 proof with the v3 rules ACTIVE: untouched (version-keyed).
    QuickVerifier verifier2;
    const Consensus::Params active = V3Params(IMPOSSIBLE_BITS, IMPOSSIBLE_BITS, 0);
    verifier2.SetV3Context(active, /*height=*/1000, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK_MESSAGE(verifier2.QuickVerify(v2, false) == VerificationResult::Quick_OK,
                        "v2 must stay untouched at any height: " + verifier2.GetLastError());
}

// V3ActivationHeight is a VALIDATION gate only — no deserialization is
// version-gated anywhere (the nonce rides the pre-existing extra_flags
// string). A version=3 proof BELOW the activation height must be judged
// under the v2 rules ONLY — no tier rule, no admission, no sampler-profile
// equality — with a verdict identical to an old (pre-v3) node's.
BOOST_AUTO_TEST_CASE(v3_below_activation_judged_under_v2_rules_only)
{
    RegisterV3TestModel();
    constexpr int ACTIVATION{1000};
    // Thresholds that would reject ANY proof if the tier rule ran, so a pass
    // proves the tier rule stayed dormant.
    const Consensus::Params params = V3Params(IMPOSSIBLE_BITS, IMPOSSIBLE_BITS, ACTIVATION);

    // (a) Clean version=3 proof below activation: accepted exactly like v2
    //     (no tier rule, no admission requirement).
    {
        CProofBlob v3 = g_genesisBlob;
        v3.version = 3;
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/ACTIVATION - 1, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK_MESSAGE(verifier.QuickVerify(v3, false) == VerificationResult::Quick_OK,
                            "pre-activation v3 must pass under v2 rules: " + verifier.GetLastError());
    }
    // (b) Claimed admission nonce below activation: extra_flags stays inert —
    //     no nonce enters any hash, no admission check runs. Old nodes ignore
    //     extra_flags entirely; verdict must match theirs.
    {
        CProofBlob v3 = g_genesisBlob;
        v3.version = 3;
        v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(TestNonce()));
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/ACTIVATION - 1, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK_MESSAGE(verifier.QuickVerify(v3, false) == VerificationResult::Quick_OK,
                            "pre-activation nonce claim must be inert: " + verifier.GetLastError());
    }
    // (c) Sampler-profile divergence below activation: the v3 exact-equality
    //     rule must NOT run. The verdict (result + error) must be identical
    //     to an old node's verdict on the same proof at version 2.
    {
        CProofBlob v3 = g_genesisBlob;
        v3.version = 3;
        v3.temperature = 0.5f; // inside the v2 global bounds, outside the v3 profile
        QuickVerifier upgraded;
        upgraded.SetV3Context(params, /*height=*/ACTIVATION - 1, TEST_MODEL_DIFFICULTY);
        const auto res_upgraded = upgraded.QuickVerify(v3, false);
        const std::string err_upgraded = upgraded.GetLastError();

        CProofBlob v2 = v3;
        v2.version = 2;
        QuickVerifier old_node; // no v3 context at all
        const auto res_old = old_node.QuickVerify(v2, false);

        BOOST_CHECK(res_upgraded == res_old);
        BOOST_CHECK_EQUAL(err_upgraded, old_node.GetLastError());
        BOOST_CHECK_MESSAGE(err_upgraded.find("sampler profile") == std::string::npos,
                            "profile equality must not run pre-activation: " + err_upgraded);
    }
}

// §5: B_cred < B_FLOOR => invalid, in both the full entry and the
// consensus-path entry (no quick-pass/full-fail gap).
BOOST_AUTO_TEST_CASE(v3_below_floor_rejects)
{
    RegisterV3TestModel();
    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;

    const Consensus::Params params = V3Params(IMPOSSIBLE_BITS, IMPOSSIBLE_BITS + 1);

    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK(verifier.QuickVerify(v3, false) == VerificationResult::Quick_Fail);
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("B_cred below B_FLOOR") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());

    BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("B_cred below B_FLOOR") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());
}

// §5: B_FLOOR <= B_cred < B_FREE without a claimed nonce => invalid.
BOOST_AUTO_TEST_CASE(v3_admission_band_without_nonce_rejects)
{
    RegisterV3TestModel();
    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;

    const Consensus::Params params = V3Params(/*floor=*/0, /*free=*/IMPOSSIBLE_BITS);

    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK(verifier.QuickVerify(v3, false) == VerificationResult::Quick_Fail);
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("admission nonce required") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());
}

// §5: B_cred >= B_FREE without a nonce needs no admission.
BOOST_AUTO_TEST_CASE(v3_free_tier_without_nonce_accepts)
{
    RegisterV3TestModel();
    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;

    const Consensus::Params params = V3Params(/*floor=*/0, /*free=*/0);

    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK_MESSAGE(verifier.QuickVerify(v3, false) == VerificationResult::Quick_OK,
                        "free tier without nonce must accept: " + verifier.GetLastError());
}

// §2: the consensus-fixed sampler profile is enforced by exact equality for
// active v3 proofs — and ONLY for them.
BOOST_AUTO_TEST_CASE(v3_sampler_profile_divergence_rejects)
{
    RegisterV3TestModel();
    const Consensus::Params params = V3Params(0, 0);

    const auto expect_profile_reject = [&](void (*mutate)(CProofBlob&)) {
        CProofBlob v3 = g_genesisBlob;
        v3.version = 3;
        mutate(v3);
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK(verifier.QuickVerify(v3, false) == VerificationResult::Quick_Fail);
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("sampler profile") != std::string::npos,
                            "unexpected error: " + verifier.GetLastError());

        // The same divergence on a pre-v3 proof must NOT trip the profile rule
        // (the value stays within the v2 global bounds).
        CProofBlob v2 = g_genesisBlob;
        v2.version = 2;
        mutate(v2);
        QuickVerifier plain;
        (void)plain.QuickVerify(v2, false);
        BOOST_CHECK_MESSAGE(plain.GetLastError().find("sampler profile") == std::string::npos,
                            "v2 must not enforce the v3 profile: " + plain.GetLastError());
    };

    expect_profile_reject([](CProofBlob& b) { b.temperature = 0.5f; });
    expect_profile_reject([](CProofBlob& b) { b.top_p = 0.9f; });
    expect_profile_reject([](CProofBlob& b) { b.top_k = 49; });
    expect_profile_reject([](CProofBlob& b) { b.repetition_penalty = 1.5f; });
}

// §7: a claimed nonce enters EVERY u draw and the final proof hash — a proof
// that claims a nonce but was hashed without one fails u replay and the
// final-hash recomputation; the identical proof is untouched pre-v3.
BOOST_AUTO_TEST_CASE(v3_claimed_nonce_changes_every_u_and_final_hash)
{
    RegisterV3TestModel();
    const auto nonce = TestNonce();

    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(nonce));

    const Consensus::Params params = V3Params(0, 0);

    // Full entry: the final hash is recomputed WITH the nonce (§7), so the
    // stored (nonce-less) hash no longer matches.
    {
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK(verifier.QuickVerify(v3, false) == VerificationResult::Quick_Fail);
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") != std::string::npos,
                            "unexpected error: " + verifier.GetLastError());
    }
    // Consensus-path entry: the final-hash commitment is now enforced here
    // too, so the nonce-less stored hash is rejected at the final-hash stage
    // (before the u-replay, which — being nonce-perturbed — would also fail).
    {
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
        BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") != std::string::npos,
                            "unexpected error: " + verifier.GetLastError());
    }
    // Without a v3 context the same extra_flags are inert (§3: v2 semantics
    // untouched), so the proof still verifies.
    {
        QuickVerifier verifier;
        BOOST_CHECK_MESSAGE(verifier.QuickVerify(v3, false) == VerificationResult::Quick_OK,
                            "extra_flags must be inert pre-v3: " + verifier.GetLastError());
    }
}

// §7: with sampling_u and the proof hash recomputed nonce-inclusive, the
// final-hash check passes again — the remaining failure moves downstream
// (header PoW cannot be satisfied without re-mining).
BOOST_AUTO_TEST_CASE(v3_recomputed_hash_with_nonce_passes_final_hash)
{
    RegisterV3TestModel();
    const auto nonce = TestNonce();

    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    ForceGreedy(v3);
    v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(nonce));
    RecomputeUsWithNonce(v3, nonce);
    RecomputeFinalHashWithNonce(v3, nonce);

    const Consensus::Params params = V3Params(0, 0);
    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK(verifier.QuickVerify(v3, false) != VerificationResult::Quick_OK);
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("Final hash mismatch") == std::string::npos,
                        "final hash must match once recomputed with the nonce: " + verifier.GetLastError());
}

#ifdef POW_V3_HAVE_ARGON2
// §5/§6: a PRESENT nonce is verified regardless of tier; an inadmissible one
// rejects in the free tier AND in the admission band.
BOOST_AUTO_TEST_CASE(v3_inadmissible_nonce_rejects_in_every_tier)
{
    RegisterV3TestModel();
    const auto nonce = TestNonce();

    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    ForceGreedy(v3); // recomputed u values always land in the chosen bucket
    v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(nonce));
    RecomputeUsWithNonce(v3, nonce);
    RecomputeFinalHashWithNonce(v3, nonce); // pass the (now-enforced) final-hash check to reach admission

    // difficulty=1 => expected_tries = 5e7 => a fixed arbitrary nonce is
    // inadmissible (except with probability 2^-25 by construction).
    constexpr int64_t hard_difficulty{1};

    // Free tier (floor=0, free=0): B_cred ~ 0 => Free; nonce still verified.
    {
        const Consensus::Params params = V3Params(0, 0);
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, hard_difficulty);
        BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("inadmissible") != std::string::npos,
                            "unexpected error: " + verifier.GetLastError());
    }
    // Admission band (floor=0, free=impossible): required AND inadmissible.
    {
        const Consensus::Params params = V3Params(0, IMPOSSIBLE_BITS);
        QuickVerifier verifier;
        verifier.SetV3Context(params, /*height=*/0, hard_difficulty);
        BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
        BOOST_CHECK_MESSAGE(verifier.GetLastError().find("inadmissible") != std::string::npos,
                            "unexpected error: " + verifier.GetLastError());
    }
}

// §6: an admissible nonce passes the admission check. With difficulty high
// enough that expected_tries == 1, the target is 2^256-1 and every digest is
// admissible; verification then proceeds past admission (here into the v2
// reuse gate, which this deliberately-greedy fixture fails — proving the
// admission verdict, not the gate, moved).
BOOST_AUTO_TEST_CASE(v3_admissible_nonce_passes_admission)
{
    RegisterV3TestModel();
    const auto nonce = TestNonce();

    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    ForceGreedy(v3);
    v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(nonce));
    RecomputeUsWithNonce(v3, nonce);
    RecomputeFinalHashWithNonce(v3, nonce); // pass the (now-enforced) final-hash check to reach admission

    constexpr int64_t easy_difficulty{1000000000000LL}; // expected_tries == 1

    const Consensus::Params params = V3Params(0, 0);
    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, easy_difficulty);
    BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("reuse score") != std::string::npos,
                        "expected the reuse gate (admission must have passed): " + verifier.GetLastError());
}
#endif // POW_V3_HAVE_ARGON2

// §6: a claimed nonce with no resolvable registered difficulty cannot be
// verified => invalid (never silently accepted). Fails before the Argon2
// evaluation, so it needs no libargon2.
BOOST_AUTO_TEST_CASE(v3_claimed_nonce_without_difficulty_rejects)
{
    // Deliberately NO model registration and difficulty 0 in the context.
    const auto nonce = TestNonce();

    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;
    ForceGreedy(v3);
    v3.extra_flags = pow_v3::merge_extra_flags_v3("", NonceHex(nonce));
    RecomputeUsWithNonce(v3, nonce);
    RecomputeFinalHashWithNonce(v3, nonce); // pass the (now-enforced) final-hash check to reach admission

    const Consensus::Params params = V3Params(0, 0);
    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, /*registered_difficulty=*/0);
    BOOST_CHECK(!verifier.VerifyReuseEntropy(v3));
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("difficulty unavailable") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());
}

// §1 fail-closed: chain params that diverge from the vendored pow_v3 argon
// profile / parser bounds must refuse to verify v3 proofs rather than verify
// them with the wrong profile.
BOOST_AUTO_TEST_CASE(v3_params_vendored_mismatch_fails_closed)
{
    RegisterV3TestModel();
    CProofBlob v3 = g_genesisBlob;
    v3.version = 3;

    Consensus::Params params = V3Params(0, 0);
    params.V3ArgonMemoryKiB = 4096; // diverges from pow_v3::ARGON2_MEMORY_KIB

    QuickVerifier verifier;
    verifier.SetV3Context(params, /*height=*/0, TEST_MODEL_DIFFICULTY);
    BOOST_CHECK(verifier.QuickVerify(v3, false) == VerificationResult::Quick_Fail);
    BOOST_CHECK_MESSAGE(verifier.GetLastError().find("vendored pow_v3") != std::string::npos,
                        "unexpected error: " + verifier.GetLastError());

    // ...but the divergence is irrelevant while v3 is dormant (v2 proofs).
    CProofBlob v2 = g_genesisBlob;
    v2.version = 2;
    BOOST_CHECK_MESSAGE(verifier.QuickVerify(v2, false) == VerificationResult::Quick_OK,
                        "params mismatch must not affect pre-v3 proofs: " + verifier.GetLastError());
}

BOOST_AUTO_TEST_SUITE_END()
