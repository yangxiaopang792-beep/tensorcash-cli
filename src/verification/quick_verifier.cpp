#include <verification/quick_verifier.h>
#include <vdf/VdfVerify.h>
#include <verification/pow_v3.h>
#include <verification/verification_utils.h>
#include <util/strencodings.h>
#include <crypto/sha256.h>
#include <arith_uint256.h>
#include <modeldb.h>

#include <algorithm>
#include <numeric>
#include <cstring>
#include <cmath>
#include <limits>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace verification;

VerificationResult QuickVerifier::QuickVerify(const CProofBlob& proof) {
    // Version-keyed: legacy proofs (version < REUSE_GATE_VERSION) are grandfathered;
    // v2+ proofs are enforced against the q32 reuse-entropy gate. No height needed.
    return QuickVerify(proof, /*enforce_reuse_entropy=*/proof.version >= REUSE_GATE_VERSION);
}

bool QuickVerifier::VerifyFinalHashOnly(const CProofBlob& proof) {
    m_lastError.clear();

    // Same v3 applicability/nonce extraction as the full quick path. Without
    // this, active v3 admission-band proofs would be recomputed without the
    // claimed nonce and could be falsely rejected.
    if (!PrepareV3(proof)) {
        return false;
    }

    return VerifyFinalHash(proof);
}

VerificationResult QuickVerifier::QuickVerify(const CProofBlob& proof, bool enforce_reuse_entropy) {
    // Clear previous error
    m_lastError.clear();

    // Clear intermediate capture if enabled
    if (m_captureIntermediates) {
        m_intermediates = IntermediateValues();
    }

    // V3 setup (TIP-0003): decide applicability and extract the
    // claimed admission nonce BEFORE any hashing — the nonce enters every u
    // and the final hash (§7). No-op (byte-identical v2 behavior) unless a
    // chain context was provided, proof.version >= 3 and the height is at or
    // beyond V3ActivationHeight.
    if (!PrepareV3(proof)) {
        return VerificationResult::Quick_Fail;
    }

    // Step 1: Verify model registration (critical for SPV path security)
    if (!VerifyModelRegistration(proof)) {
        // m_lastError already set by VerifyModelRegistration
        return VerificationResult::Quick_Fail_Model_Unregistered;
    }

    // Step 2: Verify block sanity
    if (!VerifyBlockSanity(proof)) {
        // m_lastError already set by VerifyBlockSanity
        return VerificationResult::Quick_Fail;
    }

    // Step 3: Verify parameters
    if (!VerifyParameters(proof)) {
        // m_lastError already set by VerifyParameters
        return VerificationResult::Quick_Fail;
    }

    // Step 4: Set up window data (needed for sequence verification)
    m_windowSize = proof.chosen_tokens.size();
    m_promptTokens = proof.prompt_tokens;
    m_chosenTokens = proof.chosen_tokens;

    // Step 5: Now verify final hash and PoW (after parameters are validated)
    if (!VerifyFinalHash(proof)) {
        // m_lastError already set by VerifyFinalHash
        return VerificationResult::Quick_Fail;
    }

    if (!VerifyHeaderPoW(proof)) {
        // m_lastError already set by VerifyHeaderPoW
        return VerificationResult::Quick_Fail;
    }

    // Step 6: Verify sequence
    if (!VerifySequenceLightVectorized(proof, enforce_reuse_entropy)) {
        // m_lastError already set by VerifySequenceLightVectorized if not set
        if (m_lastError.empty()) {
            m_lastError = "Sequence verification failed";
        }
        return VerificationResult::Quick_Fail;
    }

    return VerificationResult::Quick_OK;
}

bool QuickVerifier::VerifyReuseEntropy(const CProofBlob& proof) {
    // Version-keyed gate. Legacy proofs (below the reuse-gate version) are
    // grandfathered and never entropy-gated; all chain history is v1, so this
    // makes historical blocks impossible to reject regardless of their reuse score.
    if (proof.version < REUSE_GATE_VERSION) {
        return true;
    }

    m_lastError.clear();
    if (m_captureIntermediates) {
        m_intermediates = IntermediateValues();
    }

    // V3 setup — same applicability rule as QuickVerify, so the consensus
    // paths that only run this entry (ConnectBlock / ContextualCheckBlock)
    // enforce the identical v3 tier/admission/profile rules (§5: no
    // quick-pass/full-fail gap).
    if (!PrepareV3(proof)) {
        return false;
    }

    if (!VerifyBlockSanity(proof)) {
        return false;
    }
    if (!VerifyParameters(proof)) {
        return false;
    }

    // Enforce the sampling/final-hash commitment on the consensus entry too
    // (§5/§7: no quick-pass/full-fail gap). VerifySequenceLightVectorized below
    // recomputes each step digest internally, so it catches a *nonce* that
    // perturbs the u draws — but it never compares the proof's committed
    // `hash` against the recomputation. Without this, a proof whose `hash` is
    // decoupled from the sampling (arbitrary 32 bytes that still meet the
    // header-PoW target, with an otherwise-valid sampling sequence) passes the
    // in-node consensus check and is only caught by the external validator
    // (the "Sampling hash inconsistent with recomputation" reject). Placed
    // before the reuse-gate replay so a decoupled hash fails fast. Nonce-bound
    // and v2-clean via PrepareV3 (m_v3Active / m_v3Nonce); grandfathered v1
    // proofs never reach here (version < REUSE_GATE_VERSION returns early).
    if (!VerifyFinalHash(proof)) {
        // m_lastError already set by VerifyFinalHash ("Final hash mismatch").
        return false;
    }

    if (!VerifySequenceLightVectorized(proof, /*enforce_reuse_entropy=*/true)) {
        if (m_lastError.empty()) {
            m_lastError = "Reuse entropy verification failed";
        }
        return false;
    }

    return true;
}

bool QuickVerifier::VerifyBlockSanity(const CProofBlob& proof) {
    // Basic sanity checks
    if (proof.hash.empty()) {
        m_lastError = "Proof hash is empty";
        return false;
    }

    if (proof.model_identifier.empty()) {
        m_lastError = "Model identifier is empty";
        return false;
    }

    // Verify VDF
    if (!VerifyVDF(proof)) {
        // m_lastError already set by VerifyVDF
        return false;
    }

    // Note: Final hash and PoW verification moved to after parameter validation
    // since they depend on having valid parameters

    if (proof.chosen_tokens.empty()) {
        m_lastError = "No chosen tokens";
        return false;
    }

    if (proof.topk_logits.size() != proof.chosen_tokens.size()) {
        m_lastError = "Logits and chosen tokens size mismatch: " +
                      std::to_string(proof.topk_logits.size()) + " != " +
                      std::to_string(proof.chosen_tokens.size());
        return false;
    }

    if (proof.topk_indices.size() != proof.chosen_tokens.size()) {
        m_lastError = "Indices and chosen tokens size mismatch: " +
                      std::to_string(proof.topk_indices.size()) + " != " +
                      std::to_string(proof.chosen_tokens.size());
        return false;
    }

    return true;
}

bool QuickVerifier::VerifyModelRegistration(const CProofBlob& proof) {
    // Model registration check is only performed if model database is available
    // This allows QuickVerify to work in test environments and lightweight contexts
    if (!g_modeldb) {
        // Skip model check if database unavailable (e.g., in unit tests)
        // In production SPV mode, g_modeldb should always be available
        return true;
    }

    // Compute the model hash from the model_identifier
    uint256 model_hash = proof.GetModelHash();

    // Check if model hash is valid (non-zero)
    if (model_hash.IsNull()) {
        m_lastError = "Invalid model identifier format (missing '@' separator)";
        return false;
    }

    // Check if model exists in the registry
    if (!g_modeldb->Exists(model_hash)) {
        m_lastError = "Model not registered: " + proof.model_identifier +
                     " (hash: " + model_hash.ToString() + ")";
        return false;
    }

    // Optionally verify we can read the model record
    ModelRecord model;
    if (!g_modeldb->ReadModel(model_hash, model)) {
        m_lastError = "Failed to read model record for: " + proof.model_identifier;
        return false;
    }

    // Verify the model has positive difficulty (is active)
    if (model.metadata.difficulty <= 0) {
        m_lastError = "Model has non-positive difficulty: " + proof.model_identifier +
                     " (difficulty: " + std::to_string(model.metadata.difficulty) + ")";
        return false;
    }

    return true;
}

bool QuickVerifier::VerifyParameters(const CProofBlob& proof) {
    // Check for NaN or Inf in temperature
    if (std::isnan(proof.temperature) || std::isinf(proof.temperature)) {
        m_lastError = "Invalid temperature value: NaN or Inf detected";
        return false;
    }

    // Verify temperature is valid (using constants from constants.py)
    if (proof.temperature < TEMP_MIN || proof.temperature > TEMP_MAX) {
        m_lastError = "Invalid temperature value: " + std::to_string(proof.temperature) +
                      " (must be in [" + std::to_string(TEMP_MIN) + ", " + std::to_string(TEMP_MAX) + "])";
        return false;
    }

    // Check for NaN or Inf in top_p
    if (std::isnan(proof.top_p) || std::isinf(proof.top_p)) {
        m_lastError = "Invalid top_p value: NaN or Inf detected";
        return false;
    }

    // Verify top_p is valid (using constants from constants.py)
    if (proof.top_p < TOPP_MIN || proof.top_p > TOPP_MAX) {
        m_lastError = "Invalid top_p value: " + std::to_string(proof.top_p) +
                      " (must be in [" + std::to_string(TOPP_MIN) + ", " + std::to_string(TOPP_MAX) + "])";
        return false;
    }

    // Verify top_k is valid (using constants from constants.py)
    if (proof.top_k < TOPK_MIN || proof.top_k > TOPK_MAX) {
        m_lastError = "Invalid top_k value: " + std::to_string(proof.top_k) +
                      " (must be in [" + std::to_string(TOPK_MIN) + ", " + std::to_string(TOPK_MAX) + "])";
        return false;
    }

    // Verify sampling_u size matches chosen_tokens
    if (proof.sampling_u.size() != proof.chosen_tokens.size()) {
        m_lastError = "sampling_u size mismatch: " + std::to_string(proof.sampling_u.size()) +
                      " != " + std::to_string(proof.chosen_tokens.size());
        return false;
    }

    // Verify all sampling_u values are in valid range [0, 1)
    for (size_t i = 0; i < proof.sampling_u.size(); ++i) {
        if (proof.sampling_u[i] < 0.0f || proof.sampling_u[i] >= 1.0f) {
            m_lastError = "Invalid sampling_u value at position " + std::to_string(i) +
                          ": " + std::to_string(proof.sampling_u[i]) +
                          " (must be in [0, 1))";
            return false;
        }
    }

    // V3 (TIP-0003): the sampler profile is a consensus-fixed
    // constant, enforced by exact equality on top of the global bounds above
    // (which stay enforced as a second line for every version).
    if (m_v3Active && !VerifyV3SamplerProfile(proof)) {
        return false;
    }

    return true;
}

bool QuickVerifier::VerifyV3SamplerProfile(const CProofBlob& proof) {
    // Consensus invariant (TIP-0003): v3.0 accepts EXACTLY
    // temperature=1.0, top_p=1.0, top_k=50, repetition_penalty=1.0 — the
    // profile is consensus-fixed, never miner- or model-chosen, so
    // enforcement is exact equality against the proof's existing sampler
    // fields. Any missing field (FlatBuffer default 0) or divergent value is
    // invalid; model `extra` profiles are ignored for v3.0.
    if (proof.temperature != pow_v3::SAMPLER_V3_TEMPERATURE ||
        proof.top_p != pow_v3::SAMPLER_V3_TOP_P ||
        proof.top_k != pow_v3::SAMPLER_V3_TOP_K ||
        proof.repetition_penalty != pow_v3::SAMPLER_V3_REPETITION_PENALTY) {
        m_lastError = "v3: sampler profile mismatch: temperature=" + std::to_string(proof.temperature) +
                      " top_p=" + std::to_string(proof.top_p) +
                      " top_k=" + std::to_string(proof.top_k) +
                      " repetition_penalty=" + std::to_string(proof.repetition_penalty) +
                      " (v3 requires exactly temperature=1.0, top_p=1.0, top_k=50, repetition_penalty=1.0)";
        return false;
    }
    return true;
}

bool QuickVerifier::VerifySequenceLightVectorized(const CProofBlob& proof, bool enforce_reuse_entropy) {
    // Cache frequently used values
    m_windowSize = proof.chosen_tokens.size();
    m_promptTokens = proof.prompt_tokens;
    m_chosenTokens = proof.chosen_tokens;
    m_padMask = proof.pad_mask;

    // Verify inner array sizes match for each step
    for (size_t i = 0; i < m_windowSize; ++i) {
        if (proof.topk_logits[i].size() != proof.topk_indices[i].size()) {
            m_lastError = "Logits and indices size mismatch at step " + std::to_string(i) +
                         ": " + std::to_string(proof.topk_logits[i].size()) +
                         " != " + std::to_string(proof.topk_indices[i].size());
            return false;
        }

        // Check for NaN or Inf in logits
        for (size_t j = 0; j < proof.topk_logits[i].size(); ++j) {
            if (std::isnan(proof.topk_logits[i][j]) || std::isinf(proof.topk_logits[i][j])) {
                m_lastError = "Invalid logit value (NaN or Inf) at step " + std::to_string(i) +
                             ", index " + std::to_string(j);
                return false;
            }
        }

        // Check for NaN or Inf in chosen_probs if available
        if (i < proof.chosen_probs.size()) {
            if (std::isnan(proof.chosen_probs[i]) || std::isinf(proof.chosen_probs[i])) {
                m_lastError = "Invalid chosen probability (NaN or Inf) at step " + std::to_string(i);
                return false;
            }
            // Also check probability is in valid range [0, 1] with small epsilon for floating point precision
            constexpr float PROB_EPSILON = 1e-6f;  // Allow tiny floating point errors
            if (proof.chosen_probs[i] < -PROB_EPSILON || proof.chosen_probs[i] > 1.0f + PROB_EPSILON) {
                m_lastError = "Invalid probability value at step " + std::to_string(i) +
                             ": " + std::to_string(proof.chosen_probs[i]) + " (must be in [0, 1])";
                return false;
            }
        }

        // Check for NaN or Inf in sampling_u
        if (i < proof.sampling_u.size()) {
            if (std::isnan(proof.sampling_u[i]) || std::isinf(proof.sampling_u[i])) {
                m_lastError = "Invalid sampling_u value (NaN or Inf) at step " + std::to_string(i);
                return false;
            }
        }

        // Check for NaN or Inf in logsumexp_stats
        if (i < proof.logsumexp_stats.size()) {
            for (size_t j = 0; j < proof.logsumexp_stats[i].size(); ++j) {
                if (std::isnan(proof.logsumexp_stats[i][j]) || std::isinf(proof.logsumexp_stats[i][j])) {
                    m_lastError = "Invalid logsumexp_stats (NaN or Inf) at step " + std::to_string(i) +
                                 ", element " + std::to_string(j);
                    return false;
                }
            }
        }
    }

    // Step 1: Compute U values for all steps
    std::vector<float> u_values = GetUValues(proof);

    if (m_captureIntermediates) {
        m_intermediates.u_values = u_values;
    }

    // Step 2: Check U values match expected
    for (size_t i = 0; i < m_windowSize; ++i) {
        float diff = std::abs(u_values[i] - proof.sampling_u[i]);
        if (diff > U_TOLERANCE) {
            m_lastError = "U value mismatch at step " + std::to_string(i) +
                         ": computed=" + std::to_string(u_values[i]) +
                         " expected=" + std::to_string(proof.sampling_u[i]);
            return false;
        }
    }

    std::vector<float> lower_bounds;
    std::vector<float> upper_bounds;
    lower_bounds.reserve(m_windowSize);
    upper_bounds.reserve(m_windowSize);

    // Step 3: Verify each step's sampling
    for (size_t step = 0; step < m_windowSize; ++step) {
        // Build context: prompt_tokens + chosen_tokens[:step]
        std::vector<uint32_t> context = m_promptTokens;
        for (size_t j = 0; j < step; ++j) {
            context.push_back(m_chosenTokens[j]);
        }

        // Deduplicate logits (keep max per token)
        std::vector<float> dedupe_logits;
        std::vector<uint32_t> dedupe_indices;
        DedupeKeepMax(proof.topk_logits[step], proof.topk_indices[step],
                     dedupe_logits, dedupe_indices);

        if (m_captureIntermediates) {
            m_intermediates.dedupe_values.push_back(dedupe_logits);
            m_intermediates.dedupe_indices.push_back(dedupe_indices);
        }

        // Verify sampling for this step
        float lower, upper;
        bool valid = VerifySampleStep(
            step,
            dedupe_logits,
            dedupe_indices,
            context,
            u_values[step],
            m_chosenTokens[step],
            proof,
            lower,
            upper
        );

        if (m_captureIntermediates) {
            m_intermediates.lower_bounds.push_back(lower);
            m_intermediates.upper_bounds.push_back(upper);
        }
        lower_bounds.push_back(lower);
        upper_bounds.push_back(upper);

        if (!valid) {
            m_lastError = "Sampling verification failed at step " + std::to_string(step) +
                         ": u=" + std::to_string(u_values[step]) +
                         " not in [" + std::to_string(lower) + ", " + std::to_string(upper) + "]";
            return false;
        }
    }

    // V3 (TIP-0003): recompute conservative B_cred from the
    // bounds produced above, apply the tier rule and verify a present
    // admission nonce. Runs BEFORE the reuse-entropy gate so v3 failures are
    // attributed precisely; both are enforced.
    if (m_v3Active && !VerifyV3TierAndAdmission(proof, lower_bounds, upper_bounds)) {
        return false;
    }

    if (!enforce_reuse_entropy) {
        return true;
    }

    return VerifyEntropy(lower_bounds, upper_bounds);
}

bool QuickVerifier::PrepareV3(const CProofBlob& proof) {
    m_v3Active = false;
    m_v3Nonce.reset();

    // Consensus invariant (TIP-0003): the v3 rules bind ONLY when
    // proof.version >= 3 AND height >= V3ActivationHeight, read from the chain
    // params active for this block — pre-activation heights and pre-v3 proof
    // versions validate byte-identically to today (v2 untouched).
    if (m_v3ChainParams == nullptr) return true;
    if (proof.version < pow_v3::V3_PROOF_VERSION) return true;
    if (!m_v3ChainParams->IsV3Active(m_v3Height)) return true;

    // The vendored pow_v3 implementation compiles the ARGON2 profile and the
    // §3 extra_flags parser bounds as constants (they are part of the
    // cross-language golden-vector contract). If the chain params ever
    // diverge from them, this binary cannot enforce that chain's v3 rules:
    // fail closed rather than verify with the wrong profile/bounds.
    const Consensus::Params& p = *m_v3ChainParams;
    if (p.V3ArgonTimeCost != pow_v3::ARGON2_TIME_COST ||
        p.V3ArgonMemoryKiB != pow_v3::ARGON2_MEMORY_KIB ||
        p.V3ArgonLanes != pow_v3::ARGON2_LANES ||
        p.V3ExtraFlagsMaxBytes != pow_v3::EXTRA_FLAGS_MAX_BYTES ||
        p.V3ExtraFlagsMaxDepth != pow_v3::EXTRA_FLAGS_MAX_DEPTH) {
        m_lastError = "v3: chain params disagree with the vendored pow_v3 constants "
                      "(argon profile / extra_flags parser bounds); this binary "
                      "cannot verify v3 proofs for this chain";
        return false;
    }
    // The tier thresholds (V3BFloorBits/V3BFreeBits) are deliberately NOT
    // checked here: unit tests steer the genesis blob across tiers by
    // parameterizing them. Production agreement with the compiled pow_v3
    // constants (which the external Python verifier scores with) is enforced
    // fail-closed at STARTUP instead — IsV3TierParamsVendored / init.cpp.

    m_v3Active = true;

    // §3 carrier extraction — never throws. ANY parse failure, size/depth
    // violation, duplicate key or shape mismatch means "no nonce claimed"
    // (free tier OK; below B_FREE rejects in VerifyV3TierAndAdmission). A
    // nonce actually used in sampling but not extracted fails u replay anyway.
    const std::optional<std::string> nonce_hex =
        pow_v3::extract_admission_nonce_hex(proof.extra_flags);
    if (nonce_hex) {
        // Exactly 64 lowercase hex chars by the extractor's shape rule.
        std::array<uint8_t, 32> nonce{};
        const auto nibble = [](char c) -> uint8_t {
            return static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
        };
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<uint8_t>((nibble((*nonce_hex)[2 * i]) << 4) |
                                            nibble((*nonce_hex)[2 * i + 1]));
        }
        m_v3Nonce = nonce;
    }
    return true;
}

bool QuickVerifier::VerifyV3TierAndAdmission(const CProofBlob& proof,
                                             const std::vector<float>& lower_bounds,
                                             const std::vector<float>& upper_bounds) {
    const Consensus::Params& p = *m_v3ChainParams;

    // §4: conservative B_cred over the SAME per-step interval bounds the
    // sampling check just produced (mass_q63 = ceil(hi) - floor(lo) + 2*ATOL,
    // R=1024 table credit per step, exact integer sum — order-independent by
    // construction). Credit is in units: R units == 1 bit.
    uint64_t b_cred_units = 0;
    try {
        const std::vector<double> lo(lower_bounds.begin(), lower_bounds.end());
        const std::vector<double> hi(upper_bounds.begin(), upper_bounds.end());
        b_cred_units = pow_v3::b_cred_units_from_bounds(lo, hi);
    } catch (const std::invalid_argument& e) {
        // §4: an invalid/garbage interval never earns credit — proof invalid.
        m_lastError = std::string("v3: invalid entropy bounds for B_cred: ") + e.what();
        return false;
    }

    // §5 tier rule, thresholds from the chain params active at this height (§1).
    // Chain params carry the tiers as BITS; * R to compare in credit units.
    const uint64_t floor_units = p.V3BFloorBits * pow_v3::BCRED_R;
    const uint64_t free_units = p.V3BFreeBits * pow_v3::BCRED_R;
    const pow_v3::Tier tier = pow_v3::tier_for_b_cred_units(b_cred_units, floor_units, free_units);

    if (tier == pow_v3::Tier::Invalid) {
        m_lastError = "v3: B_cred below B_FLOOR: units=" + std::to_string(b_cred_units) +
                      " < floor_units=" + std::to_string(floor_units);
        return false;
    }
    if (tier == pow_v3::Tier::AdmissionRequired && !m_v3Nonce) {
        m_lastError = "v3: admission nonce required (B_FLOOR <= B_cred < B_FREE): units=" +
                      std::to_string(b_cred_units) + " < free_units=" + std::to_string(free_units) +
                      " and no valid extra_flags.v3.admission_nonce claimed";
        return false;
    }
    if (!m_v3Nonce) {
        // Free tier without an admission claim: nothing further to verify.
        return true;
    }

    // §5: a PRESENT nonce is verified regardless of tier — the nonce perturbs
    // every u in the window (§7), so an unverified one would be a free
    // sampling re-roll lever. Present => valid; this also kills nonce
    // strip/swap malleability (either breaks u replay).

    // §6 target derivation input: the REGISTERED model difficulty (INVERSE
    // compute scalar) from the record active at this block height. Either
    // plumbed by the caller (same record the nAdjBits ratio check reads) or
    // resolved here from modeldb, which is undo/reorg-safe.
    int64_t difficulty = m_v3Difficulty;
    if (difficulty <= 0 && g_modeldb) {
        const uint256 model_hash = proof.GetModelHash();
        ModelRecord rec;
        if (!model_hash.IsNull() && g_modeldb->ReadModel(model_hash, rec)) {
            difficulty = rec.metadata.difficulty;
        }
    }
    if (difficulty <= 0) {
        m_lastError = "v3: registered model difficulty unavailable for " + proof.model_identifier +
                      "; cannot verify claimed admission nonce";
        return false;
    }

    // §6 pad_mask canonical shape: omitted means all-false for the prompt;
    // otherwise it must carry exactly one entry per prompt token. Rederived
    // from proof fields — never carried separately.
    std::vector<uint8_t> pad_mask = proof.pad_mask;
    if (pad_mask.empty()) {
        pad_mask.assign(proof.prompt_tokens.size(), 0);
    } else if (pad_mask.size() != proof.prompt_tokens.size()) {
        m_lastError = "v3: pad_mask size " + std::to_string(pad_mask.size()) +
                      " != prompt_tokens size " + std::to_string(proof.prompt_tokens.size());
        return false;
    }

    try {
        // §6: msg_w is the sampler preimage at the window's FIRST step
        // WITHOUT the nonce (the nonce enters the Argon2id message
        // explicitly). Same builder as u replay => byte-identical layout.
        const std::vector<uint8_t> msg_w =
            BuildStepMessage(m_promptTokens, 0, proof, /*include_nonce=*/false);
        // §6: commitment over the FULL model-visible pre-window prefix
        // (prompt_tokens already includes previously generated tokens for
        // later windows) — closes the vary-the-evicted-prefix amortization.
        const std::vector<int64_t> prompt64(proof.prompt_tokens.begin(), proof.prompt_tokens.end());
        const std::array<uint8_t, 32> commitment = pow_v3::prompt_commitment(prompt64, pad_mask);
        const std::array<uint8_t, 32> digest = pow_v3::argon2id_digest(
            pow_v3::admission_message(msg_w, proof.model_identifier,
                                      m_v3Nonce->data(), commitment));
        const std::array<uint8_t, 32> target_le = pow_v3::admission_target_le(
            difficulty, p.ModelDifficultyNormalizer, p.V3DecodeUsAtNormalizer,
            p.V3EligAlphaNum, p.V3EligAlphaDen, p.V3ArgonRefUs);
        if (!pow_v3::admission_valid(digest, target_le)) {
            m_lastError = "v3: claimed admission nonce is inadmissible: Argon2id digest "
                          "not below the admission target for model difficulty " +
                          std::to_string(difficulty);
            return false;
        }
    } catch (const std::exception& e) {
        // std::invalid_argument (oversized model_identifier/prompt encoding)
        // or std::runtime_error (libargon2 unavailable/failed): the admission
        // claim cannot be verified => invalid.
        m_lastError = std::string("v3: admission verification failed: ") + e.what();
        return false;
    }

    return true;
}

std::vector<float> QuickVerifier::GetUValues(const CProofBlob& proof) {
    std::vector<float> u_values;
    u_values.reserve(m_windowSize);

    for (size_t step = 0; step < m_windowSize; ++step) {
        // Build context for this step
        std::vector<uint32_t> context = m_promptTokens;
        for (size_t j = 0; j < step; ++j) {
            context.push_back(m_chosenTokens[j]);
        }

        float u = ComputeUValue(context, step, proof);
        u_values.push_back(u);
    }

    return u_values;
}

std::vector<uint8_t> QuickVerifier::BuildStepMessage(const std::vector<uint32_t>& context,
                                                     uint32_t step,
                                                     const CProofBlob& proof,
                                                     bool include_nonce) {
    // Build message for SHA256 following Python's _build_msg order:
    // header_data, v, T8, j4, ctx_bytes, precision_bytes [, nonce32]
    std::vector<uint8_t> message;


    // 1. Header prefix (header_data)
    message.insert(message.end(), proof.header_prefix.begin(), proof.header_prefix.end());


    // 2. VDF (v)
    message.insert(message.end(), proof.vdf.begin(), proof.vdf.end());


    // 3. Tick as u32 little-endian (T8)
    auto tick_bytes = Uint32ToLittleEndian(static_cast<uint32_t>(proof.tick));
    message.insert(message.end(), tick_bytes.begin(), tick_bytes.end());

    // 4. Step index as u32 little-endian (j4)
    auto step_bytes = Uint32ToLittleEndian(step);
    message.insert(message.end(), step_bytes.begin(), step_bytes.end());

    // 5. Context tokens (ctx_bytes) - window size is always POW_WINDOW_SIZE
    // regardless of how many steps we're actually verifying
    size_t window_size = POW_WINDOW_SIZE;
    std::vector<int64_t> window_tokens(window_size, 0);

    // Fill window_tokens from the end (like Python's window_tokens[i, -L:] = ctx[-L:])
    // This takes the last min(context_size, window_size) tokens from context
    size_t context_len = std::min(context.size(), window_size);
    if (context_len > 0) {
        size_t start_pos = window_size - context_len;
        // Copy the last context_len tokens to the last context_len positions of window
        for (size_t i = 0; i < context_len; ++i) {
            window_tokens[start_pos + i] = static_cast<int64_t>(context[context.size() - context_len + i]);
        }
    }

    // Convert all window tokens to bytes (8 bytes each, little-endian)
    for (int64_t token : window_tokens) {
        for (int i = 0; i < 8; ++i) {
            message.push_back((token >> (i * 8)) & 0xFF);
        }
    }

    // 6. Compute precision string (precision_bytes)
    auto precision_bytes = StringToBytes(proof.compute_precision);
    message.insert(message.end(), precision_bytes.begin(), precision_bytes.end());

    // 7. V3 (TIP-0003): when an admission nonce is claimed, its 32
    // raw bytes are appended to EVERY step preimage (all 256 u draws and the
    // final target-critical hash) — the layout mirror of
    // pow_v3::build_step_message. Absent nonce (or include_nonce=false, the
    // §6 msg_w case) leaves the message byte-identical to the legacy v2 shape.
    if (include_nonce && m_v3Active && m_v3Nonce) {
        message.insert(message.end(), m_v3Nonce->begin(), m_v3Nonce->end());
    }

    return message;
}

float QuickVerifier::ComputeUValue(const std::vector<uint32_t>& context,
                                   uint32_t step,
                                   const CProofBlob& proof) {
    const std::vector<uint8_t> message =
        BuildStepMessage(context, step, proof, /*include_nonce=*/true);

    // Compute SHA256 (single, not double)
    uint256 hash;
    CSHA256().Write(message.data(), message.size()).Finalize(hash.begin());


    // Convert to float in [0, 1)
    return DigestToU(hash);
}

void QuickVerifier::DedupeKeepMax(
    const std::vector<float>& logits,
    const std::vector<uint32_t>& indices,
    std::vector<float>& dedupe_logits,
    std::vector<uint32_t>& dedupe_indices) {

    std::map<uint32_t, float> tok_to_max;

    for (size_t i = 0; i < indices.size(); ++i) {
        uint32_t tok = indices[i];
        float val = logits[i];

        auto it = tok_to_max.find(tok);
        if (it == tok_to_max.end() || val > it->second) {
            tok_to_max[tok] = val;
        }
    }

    dedupe_indices.clear();
    dedupe_logits.clear();
    dedupe_indices.reserve(tok_to_max.size());
    dedupe_logits.reserve(tok_to_max.size());

    for (const auto& [tok, val] : tok_to_max) {
        dedupe_indices.push_back(tok);
        dedupe_logits.push_back(val);
    }
}

bool QuickVerifier::VerifySampleStep(
    size_t step,
    const std::vector<float>& logits,
    const std::vector<uint32_t>& indices,
    const std::vector<uint32_t>& context,
    float u_value,
    uint32_t expected_token,
    const CProofBlob& proof,
    float& lower_out,
    float& upper_out) {

    // Make a copy for modification
    std::vector<float> temp_logits = logits;

    // 1. Temperature scaling
    ApplyTemperatureScaling(temp_logits, proof.temperature);

    // 2. Repetition penalty
    if (proof.repetition_penalty != 0.0f && proof.repetition_penalty != 1.0f) {
        ApplyRepetitionPenalty(temp_logits, indices, context, proof.repetition_penalty);
    }

    const std::vector<float> pre_trunc_logits = temp_logits;

    // 3. Top-k filtering
    if (proof.top_k > 0) {
        ApplyTopK(temp_logits, proof.top_k);
    }

    if (std::all_of(temp_logits.begin(), temp_logits.end(), [](float logit) {
            return !std::isfinite(logit);
        })) {
        size_t best_pos = 0;
        for (size_t i = 1; i < pre_trunc_logits.size(); ++i) {
            if (pre_trunc_logits[i] > pre_trunc_logits[best_pos] ||
                (pre_trunc_logits[i] == pre_trunc_logits[best_pos] &&
                 indices[i] < indices[best_pos])) {
                best_pos = i;
            }
        }
        std::fill(temp_logits.begin(), temp_logits.end(),
                  -std::numeric_limits<float>::infinity());
        temp_logits[best_pos] = pre_trunc_logits[best_pos];
    }

    // 4. Top-p filtering
    bool borderline = false;
    std::vector<float> mask_p_h_values, mask_p_l_values;
    if (proof.top_p < 1.0f) {
        ApplyTopP(temp_logits, indices, proof.top_p, borderline, mask_p_h_values, mask_p_l_values);
    }

    // 5. Compute probabilities
    std::vector<float> probs = ComputeProbabilities(temp_logits);

    // 6. Build CDF and find bounds
    int position;
    ComputeCDF(probs, indices, expected_token, lower_out, upper_out, position);

    // 7. Check if u is in bounds
    bool in_bounds = (u_value > lower_out - ATOL) && (u_value <= upper_out + ATOL);

    // 8. Handle borderline cases if needed
    if (!in_bounds && borderline) {
        TryBorderlineAdjustment(
            mask_p_h_values, mask_p_l_values, indices,
            expected_token, u_value, lower_out, upper_out);
        in_bounds = (u_value > lower_out - ATOL) && (u_value <= upper_out + ATOL);
    }

    return in_bounds;
}

void QuickVerifier::ApplyTemperatureScaling(std::vector<float>& logits, float temperature) {
    for (auto& logit : logits) {
        if (logit > -std::numeric_limits<float>::infinity()) {
            logit /= temperature;
        }
    }
}

void QuickVerifier::ApplyRepetitionPenalty(
    std::vector<float>& logits,
    const std::vector<uint32_t>& indices,
    const std::vector<uint32_t>& context,
    float repetition_penalty) {

    for (size_t i = 0; i < indices.size(); ++i) {
        if (IsIn(indices[i], context)) {
            if (logits[i] > -std::numeric_limits<float>::infinity()) {
                logits[i] /= repetition_penalty;
            }
        }
    }
}

void QuickVerifier::ApplyTopK(std::vector<float>& logits, uint32_t k) {
    if (k == 0 || k >= logits.size()) {
        return;
    }

    // Get k-th largest value
    std::vector<float> sorted_logits = logits;
    std::sort(sorted_logits.begin(), sorted_logits.end(), std::greater<float>());

    float threshold = sorted_logits[k - 1];

    // Match the miner/Python verifier: ties at the k-th value are masked too.
    for (auto& logit : logits) {
        if (logit <= threshold) {
            logit = -std::numeric_limits<float>::infinity();
        }
    }
}

void QuickVerifier::ApplyTopP(
    std::vector<float>& logits,
    const std::vector<uint32_t>& indices,
    float p,
    bool& borderline,
    std::vector<float>& mask_p_h_values,
    std::vector<float>& mask_p_l_values) {

    std::vector<size_t> sorted_indices;
    sorted_indices.reserve(logits.size());
    for (size_t i = 0; i < logits.size(); ++i) {
        if (std::isfinite(logits[i])) {
            sorted_indices.push_back(i);
        }
    }
    if (sorted_indices.size() <= 1) {
        borderline = false;
        return;
    }

    // Canonical PoW top-p order: logit descending, token id ascending on ties.
    std::stable_sort(sorted_indices.begin(), sorted_indices.end(),
        [&logits, &indices](size_t lhs, size_t rhs) {
            if (logits[lhs] != logits[rhs]) {
                return logits[lhs] > logits[rhs];
            }
            return indices[lhs] < indices[rhs];
        });

    std::vector<float> sorted_logits;
    sorted_logits.reserve(sorted_indices.size());
    for (size_t idx : sorted_indices) {
        sorted_logits.push_back(logits[idx]);
    }

    const double lse = LogSumExp(sorted_logits);
    std::vector<float> probs_sorted;
    probs_sorted.reserve(sorted_logits.size());
    for (auto logit : sorted_logits) {
        probs_sorted.push_back(static_cast<float>(std::exp(static_cast<double>(logit) - lse)));
    }

    std::vector<float> prev_cumsum(probs_sorted.size(), 0.0f);
    double running = 0.0;
    for (size_t i = 0; i < probs_sorted.size(); ++i) {
        prev_cumsum[i] = static_cast<float>(running);
        running += probs_sorted[i];
    }

    borderline = false;
    for (size_t i = 0; i < prev_cumsum.size(); ++i) {
        if (std::abs(prev_cumsum[i] - p) < ATOL) {
            borderline = true;
            break;
        }
    }

    auto keep_at = [&](size_t i, float cutoff) {
        return i == 0 || prev_cumsum[i] < cutoff;
    };

    if (borderline) {
        mask_p_h_values = logits;
        mask_p_l_values = logits;
        for (size_t i = 0; i < sorted_indices.size(); ++i) {
            if (!keep_at(i, p - ATOL)) {
                mask_p_h_values[sorted_indices[i]] =
                    -std::numeric_limits<float>::infinity();
            }
            if (!keep_at(i, p + ATOL)) {
                mask_p_l_values[sorted_indices[i]] =
                    -std::numeric_limits<float>::infinity();
            }
        }
    }

    for (size_t i = 0; i < sorted_indices.size(); ++i) {
        if (!keep_at(i, p)) {
            logits[sorted_indices[i]] = -std::numeric_limits<float>::infinity();
        }
    }
}

void QuickVerifier::ComputeCDF(
    const std::vector<float>& probs,
    const std::vector<uint32_t>& indices,
    uint32_t expected_token,
    float& lower,
    float& upper,
    int& position) {

    // Build (index, prob) pairs and sort by index
    std::vector<std::pair<uint32_t, float>> id_prob_pairs;
    for (size_t i = 0; i < indices.size(); ++i) {
        if (probs[i] > 0) {  // Only include non-zero probabilities
            id_prob_pairs.push_back({indices[i], probs[i]});
        }
    }

    std::sort(id_prob_pairs.begin(), id_prob_pairs.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    // Build CDF
    std::vector<float> cdf(id_prob_pairs.size());
    double cumulative = 0.0;
    for (size_t i = 0; i < id_prob_pairs.size(); ++i) {
        cumulative += id_prob_pairs[i].second;
        cdf[i] = static_cast<float>(cumulative);
    }

    // Find position of expected token
    position = -1;
    for (size_t i = 0; i < id_prob_pairs.size(); ++i) {
        if (id_prob_pairs[i].first == expected_token) {
            position = i;
            break;
        }
    }

    if (position >= 0) {
        lower = position > 0 ? cdf[position - 1] : 0.0f;
        upper = cdf[position];
    } else {
        lower = 0.0f;
        upper = 0.0f;
    }
}

double QuickVerifier::LogSumExp(const std::vector<float>& values) {
    if (values.empty()) {
        return -std::numeric_limits<float>::infinity();
    }

    // Find max for numerical stability
    float max_val = *std::max_element(values.begin(), values.end());

    if (max_val == -std::numeric_limits<float>::infinity()) {
        return -std::numeric_limits<float>::infinity();
    }

    double sum = 0.0;
    for (auto val : values) {
        if (val > -std::numeric_limits<float>::infinity()) {
            sum += std::exp(static_cast<double>(val) - static_cast<double>(max_val));
        }
    }

    return static_cast<double>(max_val) + std::log(sum);
}

std::vector<float> QuickVerifier::ComputeProbabilities(const std::vector<float>& logits) {
    const double lse = LogSumExp(logits);
    std::vector<float> probs;
    probs.reserve(logits.size());

    for (auto logit : logits) {
        if (logit > -std::numeric_limits<float>::infinity()) {
            probs.push_back(static_cast<float>(std::exp(static_cast<double>(logit) - lse)));
        } else {
            probs.push_back(0.0f);
        }
    }

    return probs;
}

std::vector<size_t> QuickVerifier::ArgSort(const std::vector<float>& values, bool descending) {
    std::vector<size_t> indices(values.size());
    std::iota(indices.begin(), indices.end(), 0);

    if (descending) {
        std::stable_sort(indices.begin(), indices.end(),
            [&values](size_t i1, size_t i2) {
                return values[i1] > values[i2];
            });
    } else {
        std::stable_sort(indices.begin(), indices.end(),
            [&values](size_t i1, size_t i2) {
                return values[i1] < values[i2];
            });
    }

    return indices;
}

bool QuickVerifier::VerifyVDF(const CProofBlob& proof) {
    // Wire up actual VDF verification against previous header hash.
    // Basic presence checks first to keep error messages informative.
    if (proof.vdf.empty()) {
        m_lastError = "VDF is empty";
        return false;
    }
    if (proof.header_prefix.size() != 76) {
        m_lastError = "Invalid header_prefix size for VDF: " + std::to_string(proof.header_prefix.size()) + " != 76";
        return false;
    }

    // Extract prev hash from header_prefix: version(4) | prev(32) | merkle(32) | nTime(4) | nAdjBits(4)
    uint256 prev_hash;
    std::memcpy(prev_hash.begin(), proof.header_prefix.data() + 4, 32);

    // Delegate to chiavdf-based verifier (1024-bit discriminant by default, recursion=0).
    // Note: VerifyAgainstPrevHash expects the 32 bytes exactly as serialized in the header.
    const bool ok = vdf::VerifyAgainstPrevHash(prev_hash,
                                               std::span<const uint8_t>(proof.vdf.data(), proof.vdf.size()),
                                               proof.tick,
                                               /*discr_bits=*/1024,
                                               /*recursion=*/0);
    if (!ok) {
        m_lastError = "VDF verification failed";
    }
    return ok;
}

uint32_t QuickVerifier::ConservativeReuseBits(double mass_upper) const {
    if (mass_upper <= 0.0) {
        return REUSE_SCORE_Q32_BITS;
    }
    if (mass_upper >= 1.0) {
        return 0;
    }

    uint32_t bits = 0;
    double threshold = 0.5;
    while (bits < REUSE_SCORE_Q32_BITS && mass_upper <= threshold) {
        ++bits;
        threshold *= 0.5;
    }
    return bits;
}

bool QuickVerifier::VerifyEntropy(const std::vector<float>& lower_bounds,
                                  const std::vector<float>& upper_bounds) {
    if (lower_bounds.size() != upper_bounds.size()) {
        m_lastError = "Entropy bounds size mismatch";
        return false;
    }

    uint32_t prefix_bits = 0;
    uint64_t reuse_score_q32 = 0;

    for (size_t i = 0; i < lower_bounds.size(); ++i) {
        const double lower = static_cast<double>(lower_bounds[i]);
        const double upper = static_cast<double>(upper_bounds[i]);
        if (!std::isfinite(lower) || !std::isfinite(upper) || upper < lower) {
            m_lastError = "Invalid entropy bounds at step " + std::to_string(i);
            return false;
        }

        const double mass_upper = std::min(1.0, std::max(0.0, (upper - lower) + 2.0 * static_cast<double>(ATOL)));
        const uint32_t bits = ConservativeReuseBits(mass_upper);
        prefix_bits = std::min<uint32_t>(REUSE_SCORE_Q32_BITS, prefix_bits + bits);

        const uint64_t term_q32 = (prefix_bits >= REUSE_SCORE_Q32_BITS)
            ? 1ULL
            : (REUSE_SCORE_Q32_ONE >> prefix_bits);
        reuse_score_q32 += term_q32;

        if (reuse_score_q32 > REUSE_SCORE_CAP_Q32) {
            m_lastError = "Expected reuse score too high: q32=" +
                          std::to_string(reuse_score_q32) + " > " +
                          std::to_string(REUSE_SCORE_CAP_Q32) +
                          " (insufficient realized entropy)";
            return false;
        }
    }

    return true;
}

bool QuickVerifier::VerifyFinalHash(const CProofBlob& proof) {
    // Check hash is correct size
    if (proof.hash.size() != 32) {
        m_lastError = "Invalid hash size: " + std::to_string(proof.hash.size()) + " != 32";
        return false;
    }

    // For final hash, build the full context and use ComputeUValue's logic
    // to ensure consistency with sampling verification
    std::vector<uint32_t> full_context;

    if (proof.chosen_tokens.size() == POW_WINDOW_SIZE) {
        // At window boundary: context is exactly the chosen tokens
        // This matches pow_utils.cpp check_solutions() behavior
        full_context = proof.chosen_tokens;
    } else {
        // Before window boundary: use prompt + chosen tokens
        full_context = proof.prompt_tokens;
        full_context.insert(full_context.end(), proof.chosen_tokens.begin(), proof.chosen_tokens.end());
    }

    // Use the SAME message builder as ComputeUValue (step = 0 for the final
    // hash). V3 (TIP-0003): the claimed admission nonce is
    // appended here too, so the proof hash — and therefore the derived header
    // nonce and the short-hash target check — commits to it transitively; no
    // separate post-admission grind field exists, and none may be introduced.
    const std::vector<uint8_t> message =
        BuildStepMessage(full_context, 0, proof, /*include_nonce=*/true);

    // Compute SHA256
    uint256 computed_hash;
    CSHA256().Write(message.data(), message.size()).Finalize(computed_hash.begin());

    // Compare with provided hash
    if (memcmp(computed_hash.begin(), proof.hash.data(), 32) != 0) {
        // Debug output for troubleshooting
        std::stringstream ss;
        ss << "Final hash mismatch: computed=";
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2)
               << (int)computed_hash.begin()[i];
        }
        ss << "... expected=";
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2)
               << (int)proof.hash[i];
        }
        ss << "...";

        // Add more debug info
        ss << " (context_size=" << std::dec << full_context.size()
           << ", precision=" << proof.compute_precision
           << ", tick=" << proof.tick << ")";

        m_lastError = ss.str();
        return false;
    }

    return true;
}

bool QuickVerifier::VerifyHeaderPoW(const CProofBlob& proof) {
    // The nonce is the first 4 bytes of the final hash
    // This verifies that the nonce (derived from sampling) produces a valid PoW
    if (proof.hash.size() < 4) {
        m_lastError = "Hash too short to extract nonce";
        return false;
    }

    // Check target is valid size
    if (proof.target.size() != 32) {
        m_lastError = "Invalid target size: " + std::to_string(proof.target.size()) + " != 32";
        return false;
    }

    // Check header_prefix is 76 bytes (80 - 4 for nonce)
    if (proof.header_prefix.size() != 76) {
        m_lastError = "Invalid header_prefix size: " + std::to_string(proof.header_prefix.size()) + " != 76";
        return false;
    }

    // Extract nAdjBits from header_prefix (bytes 72-75, little-endian)
    // Header structure: version(4) + hashPrevBlock(32) + hashMerkleRoot(32) + nTime(4) + nAdjBits(4) = 76 bytes
    uint32_t nAdjBits = 0;
    nAdjBits |= static_cast<uint32_t>(proof.header_prefix[72]);
    nAdjBits |= static_cast<uint32_t>(proof.header_prefix[73]) << 8;
    nAdjBits |= static_cast<uint32_t>(proof.header_prefix[74]) << 16;
    nAdjBits |= static_cast<uint32_t>(proof.header_prefix[75]) << 24;

    // Convert nAdjBits to target
    arith_uint256 target_from_bits;
    bool negative, overflow;
    target_from_bits.SetCompact(nAdjBits, &negative, &overflow);

    if (negative || overflow) {
        m_lastError = "Invalid nAdjBits: negative or overflow";
        return false;
    }

    // Verify proof.target matches the target derived from nAdjBits
    // ArithToUint256 returns little-endian, but proof.target is big-endian
    uint256 target_u256 = ArithToUint256(target_from_bits);

    // Reverse the target bytes for comparison (little-endian to big-endian)
    std::vector<uint8_t> target_be(32);
    for (int i = 0; i < 32; ++i) {
        target_be[i] = target_u256.begin()[31 - i];
    }

    // Compare the targets - they should match exactly
    if (memcmp(target_be.data(), proof.target.data(), 32) != 0) {
        // Debug output to understand the mismatch
        std::stringstream ss;
        ss << "Target mismatch: nAdjBits=0x" << std::hex << nAdjBits;
        ss << " derived=";
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2)
               << (unsigned int)(unsigned char)target_be[i];
        }
        ss << "... proof.target=";
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2)
               << (unsigned int)(unsigned char)proof.target[i];
        }
        ss << "...";
        m_lastError = ss.str();
        return false;
    }

    // Build complete 80-byte header: header_prefix (76 bytes) + nonce (4 bytes from hash)
    std::vector<uint8_t> header = proof.header_prefix;
    header.insert(header.end(), proof.hash.begin(), proof.hash.begin() + 4);

    // Double SHA256 (Bitcoin-style PoW)
    uint256 first_hash;
    CSHA256().Write(header.data(), header.size()).Finalize(first_hash.begin());

    uint256 header_hash;
    CSHA256().Write(first_hash.begin(), 32).Finalize(header_hash.begin());

    // Convert header hash to arith_uint256 for comparison
    arith_uint256 hash_arith = UintToArith256(header_hash);

    // Check header_hash <= target (Bitcoin-style comparison)
    if (hash_arith > target_from_bits) {
        m_lastError = "Header hash does not meet target difficulty";
        return false;
    }

    return true;
}

std::vector<uint8_t> QuickVerifier::TokensToBytes(const std::vector<uint32_t>& tokens) {
    std::vector<uint8_t> bytes;
    bytes.reserve(tokens.size() * 4);

    for (uint32_t token : tokens) {
        auto token_bytes = Uint32ToLittleEndian(token);
        bytes.insert(bytes.end(), token_bytes.begin(), token_bytes.end());
    }

    return bytes;
}

std::vector<uint8_t> QuickVerifier::Uint32ToLittleEndian(uint32_t value) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
    return bytes;
}

std::vector<uint8_t> QuickVerifier::StringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

float QuickVerifier::DigestToU(const uint256& digest) {
    // Match Python/pow_utils.cpp: uses first 4 bytes
    const unsigned char* data = digest.begin();

    // Match Python's calculation method exactly (from pow_utils.cpp)
    float b0 = static_cast<float>(data[0]);
    float b1 = static_cast<float>(data[1]);
    float b2 = static_cast<float>(data[2]);
    float b3 = static_cast<float>(data[3]);

    float result = (b0 + b1 * 256.0f + b2 * 65536.0f + b3 * 16777216.0f) / 4294967296.0f;
    return result;
}
