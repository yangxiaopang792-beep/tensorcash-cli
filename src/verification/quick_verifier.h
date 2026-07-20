#ifndef BITCOIN_VERIFICATION_QUICK_VERIFIER_H
#define BITCOIN_VERIFICATION_QUICK_VERIFIER_H

#include <consensus/params.h>
#include <primitives/proofblob.h>
#include <crypto/sha256.h>
#include <uint256.h>

#include <array>
#include <optional>
#include <vector>
#include <string>
#include <memory>
#include <cmath>
#include <cstdint>

// Constants from shared-utils/config/constants.py
constexpr size_t POW_WINDOW_SIZE = 256;  // Must match Python's POW_WINDOW_SIZE
constexpr int TOPK_MIN = 5;
constexpr int TOPK_MAX = 50;
constexpr float TOPP_MIN = 0.1f;
constexpr float TOPP_MAX = 1.0f;
constexpr float TEMP_MIN = 0.25f;
constexpr float TEMP_MAX = 2.0f;
constexpr float ATOL = 0.0001f;  // From constants.py
constexpr float U_TOLERANCE = 1e-7f;  // Tighter tolerance for U values
constexpr uint32_t REUSE_SCORE_Q32_BITS = 32;
constexpr uint64_t REUSE_SCORE_Q32_ONE = 1ULL << REUSE_SCORE_Q32_BITS;
constexpr uint64_t REUSE_SCORE_CAP_Q32 = 247891519322ULL;  // ceil(57.716742 * 2^32)
// Proof versions below this are legacy and grandfathered (NOT reuse-entropy gated).
// Versions at/above this carry the q32 reuse-entropy gate. All chain history is v1,
// so legacy blocks can never be rejected by this gate. The activation height only
// governs when v1 is no longer *accepted* (min-version), not which rule applies.
constexpr uint8_t REUSE_GATE_VERSION = 2;

// Verification result enum matching Python ResponseValue
enum class VerificationResult {
    Quick_OK,
    Quick_Fail,
    Quick_OK_Smell_OK,
    Quick_OK_Smell_Fail,
    Quick_Fail_Smell_Fail,
    Quick_Fail_Model_Unregistered  // Model not found in registry
};

class QuickVerifier {
public:
    QuickVerifier() = default;
    ~QuickVerifier() = default;

    // Main verification entry point. Stateless: the reuse-entropy gate is enforced
    // iff proof.version >= REUSE_GATE_VERSION. No chain height needed.
    VerificationResult QuickVerify(const CProofBlob& proof);
    VerificationResult QuickVerify(const CProofBlob& proof, bool enforce_reuse_entropy);

    // Hash-only fast path for ingress sanity checks. This recomputes the
    // target-critical sampling hash using the same byte layout as QuickVerify,
    // including the v3 admission nonce when SetV3Context makes v3 active. It
    // intentionally does not check model registration, header PoW, sequence
    // replay, or smell; callers should use it only as a reject-only preflight.
    bool VerifyFinalHashOnly(const CProofBlob& proof);

    // Version-keyed reuse-entropy gate. Passes (returns true) for legacy proofs
    // below REUSE_GATE_VERSION; runs the q32 reuse-score gate for v2+ proofs.
    bool VerifyReuseEntropy(const CProofBlob& proof);

    // V3 prompt-binding chain context (TIP-0003). The v3 rules —
    // nonce-bound step hashing (§7), consensus-fixed sampler profile (§2),
    // B_cred tiering (§4/§5) and Argon2id admission (§6) — are enforced ONLY
    // when a context has been provided AND proof.version >= 3 AND
    // height >= params.V3ActivationHeight. Callers that never set a context
    // (and all pre-activation heights / pre-v3 proof versions) get behavior
    // byte-identical to today.
    //
    // registered_difficulty is the model record's INVERSE compute difficulty
    // active at the block height (the same record the nAdjBits ratio check in
    // ContextualCheckBlock reads; modeldb is undo/reorg-safe). Pass <= 0 to
    // have the verifier resolve it from g_modeldb at verification time.
    void SetV3Context(const Consensus::Params& params, int height,
                      int64_t registered_difficulty = 0)
    {
        m_v3ChainParams = &params;
        m_v3Height = height;
        m_v3Difficulty = registered_difficulty;
    }

    // Get detailed error message if verification failed
    std::string GetLastError() const { return m_lastError; }

    // Enable intermediate value capture for testing
    void EnableIntermediateCapture(bool enable) { m_captureIntermediates = enable; }

    // Get captured intermediate values for testing
    struct IntermediateValues {
        std::vector<float> u_values;
        std::vector<std::vector<uint32_t>> dedupe_indices;
        std::vector<std::vector<float>> dedupe_values;
        std::vector<float> lower_bounds;
        std::vector<float> upper_bounds;
    };

    const IntermediateValues& GetIntermediates() const { return m_intermediates; }

private:
    // Core verification functions
    bool VerifyBlockSanity(const CProofBlob& proof);
    bool VerifyParameters(const CProofBlob& proof);
    bool VerifySequenceLightVectorized(const CProofBlob& proof, bool enforce_reuse_entropy);
    bool VerifyVDF(const CProofBlob& proof);
    bool VerifyEntropy(const std::vector<float>& lower_bounds,
                       const std::vector<float>& upper_bounds);
    bool VerifyFinalHash(const CProofBlob& proof);
    bool VerifyHeaderPoW(const CProofBlob& proof);
    bool VerifyModelRegistration(const CProofBlob& proof);

    // Helper functions for sequence verification
    std::vector<float> GetUValues(const CProofBlob& proof);
    float ComputeUValue(const std::vector<uint32_t>& context,
                        uint32_t step,
                        const CProofBlob& proof);

    // Single builder for the sampler preimage
    // header_prefix | vdf | u32le(tick) | u32le(step) | ctx_window | precision
    // [| admission_nonce32] shared by ComputeUValue, VerifyFinalHash and the
    // v3 admission msg_w (TIP-0003). With include_nonce=false,
    // or when no v3 nonce is claimed, the output is byte-identical to the
    // legacy v2 message.
    std::vector<uint8_t> BuildStepMessage(const std::vector<uint32_t>& context,
                                          uint32_t step,
                                          const CProofBlob& proof,
                                          bool include_nonce);

    // Per-verification v3 setup: decides whether the v3 rules apply to this
    // proof (version + activation height), cross-checks the chain params
    // against the vendored pow_v3 constants (fail closed on divergence), and
    // extracts/decodes the claimed admission nonce from extra_flags (§3 —
    // extraction violations mean "no nonce claimed", never an error). Returns
    // false (with m_lastError set) only on the params/pow_v3 divergence.
    bool PrepareV3(const CProofBlob& proof);

    // §2: consensus-fixed v3.0 sampler profile, exact equality. Only called
    // when the v3 rules apply.
    bool VerifyV3SamplerProfile(const CProofBlob& proof);

    // §4/§5/§6: recompute conservative B_cred from the per-step bounds, apply
    // the tier rule, and verify the Argon2id admission puzzle whenever a nonce
    // is PRESENT (regardless of tier — an unverified nonce would be a free
    // sampling re-roll lever, §5). Only called when the v3 rules apply.
    bool VerifyV3TierAndAdmission(const CProofBlob& proof,
                                  const std::vector<float>& lower_bounds,
                                  const std::vector<float>& upper_bounds);

    // Deduplication: keep max logit per unique token
    void DedupeKeepMax(
        const std::vector<float>& logits,
        const std::vector<uint32_t>& indices,
        std::vector<float>& dedupe_logits,
        std::vector<uint32_t>& dedupe_indices
    );

    // Sampling verification for a single step
    bool VerifySampleStep(
        size_t step,
        const std::vector<float>& logits,
        const std::vector<uint32_t>& indices,
        const std::vector<uint32_t>& context,
        float u_value,
        uint32_t expected_token,
        const CProofBlob& proof,
        float& lower_out,
        float& upper_out
    );

public:
    // Apply sampling parameters (made public for testing)
    void ApplyTemperatureScaling(std::vector<float>& logits, float temperature);
    void ApplyRepetitionPenalty(std::vector<float>& logits,
                                const std::vector<uint32_t>& indices,
                                const std::vector<uint32_t>& context,
                                float repetition_penalty);
    void ApplyTopK(std::vector<float>& logits, uint32_t k);
    void ApplyTopP(std::vector<float>& logits,
                   const std::vector<uint32_t>& indices,
                   float p,
                   bool& borderline,
                   std::vector<float>& mask_p_h_values,
                   std::vector<float>& mask_p_l_values);

    // CDF computation (made public for verification_utils)
    void ComputeCDF(const std::vector<float>& logits,
                   const std::vector<uint32_t>& indices,
                   uint32_t expected_token,
                   float& lower,
                   float& upper,
                   int& position);

    // Utility functions (made public for verification_utils)
    double LogSumExp(const std::vector<float>& values);
    std::vector<float> ComputeProbabilities(const std::vector<float>& logits);
    std::vector<size_t> ArgSort(const std::vector<float>& values, bool descending = false);
    uint32_t ConservativeReuseBits(double mass_upper) const;

private:

    // SHA256-based U value generation helpers
    std::vector<uint8_t> TokensToBytes(const std::vector<uint32_t>& tokens);
    std::vector<uint8_t> Uint32ToLittleEndian(uint32_t value);
    std::vector<uint8_t> StringToBytes(const std::string& str);
    float DigestToU(const uint256& digest);

    // Member variables
    std::string m_lastError;
    bool m_captureIntermediates = false;
    IntermediateValues m_intermediates;

    // Cached values during verification
    size_t m_windowSize = 0;
    std::vector<uint32_t> m_promptTokens;
    std::vector<uint32_t> m_chosenTokens;
    std::vector<uint8_t> m_padMask;

    // V3 chain context (SetV3Context). Null params = context never provided =
    // v3 rules dormant.
    const Consensus::Params* m_v3ChainParams = nullptr;
    int m_v3Height = -1;
    int64_t m_v3Difficulty = 0;

    // Per-verification v3 state (set by PrepareV3).
    bool m_v3Active = false;
    // Decoded 32-byte admission nonce when one is claimed via
    // extra_flags.v3.admission_nonce (§3). nullopt = no admission claimed.
    std::optional<std::array<uint8_t, 32>> m_v3Nonce;
};

#endif // BITCOIN_VERIFICATION_QUICK_VERIFIER_H
