#include <crypto/groth16.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

#include <blst.h>

#include <crypto/common.h>

namespace groth16 {

// Public Input Schema for KYC Asset Compliance Proofs
// =====================================================
//
// ZK proofs for KYC-gated assets must bind to on-chain transaction context to prevent
// replay attacks and ensure the proof attests to the specific asset transfer being validated.
//
// Two public input layouts are supported:
//
// LEGACY (4 inputs, 128 bytes):
//   [0] Chain/Domain Separator — prevents cross-chain replay
//   [1] Asset ID Commitment   — binds proof to the specific asset
//   [2] Compliance Root + Height — upper 28 bytes: Merkle root, lower 4 bytes: height (BE)
//   [3] Transfer Reporting Anchor — tfr_commit hash or zero
//
// HDv1 (6 inputs, 192 bytes):
//   [0] Chain/Domain Separator — same as legacy
//   [1] Asset ID Commitment   — same as legacy
//   [2] Compliance Root       — pure 32-byte MiMC root (freshness checked on-chain, not in proof)
//   [3] Transfer Reporting Anchor — same as legacy
//   [4] OutputKeyHigh         — upper 128 bits of child x-only key, left-padded to 32 bytes BE
//   [5] OutputKeyLow          — lower 128 bits of child x-only key, left-padded to 32 bytes BE
//
// Circuit family is detected from VK gamma_abc count (== public input count).
//
// Security Notes:
// - Consensus re-derives public inputs[0] (chain separator), [1] (asset id) and [3] (TFR anchor)
//   before invoking the verifier. Mismatches are rejected prior to pairing checks.
// - For HDv1 (6-input) proofs, consensus also validates output key binding against the prevout.
// - Witness commitments still bind the proof/public_inputs blob to the spending transaction, but
//   consensus now enforces explicit asset/chain context independent of the witness commitment.
// - Circuits MUST validate all public inputs match their internal computations
// - Off-chain provers must construct public inputs matching this schema exactly
//
// Reference: See ZK_IMPLEMENTATION_CODEX.md for full specification

namespace {

struct ParsedVerifyingKey {
    blst_p1_affine alpha_g1;
    blst_p2_affine beta_g2;
    blst_p2_affine gamma_g2;
    blst_p2_affine delta_g2;
    blst_p1_affine gamma_abc0;
    std::vector<blst_p1_affine> gamma_abc;
};

inline uint16_t ReadLE16(const unsigned char* ptr)
{
    return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
}

VerifyError ParseVerifyingKey(std::span<const unsigned char> bytes, ParsedVerifyingKey& out)
{
    if (bytes.size() < 2 + GROTH16_G1_COMPRESSED_SIZE + 3 * GROTH16_G2_COMPRESSED_SIZE + GROTH16_G1_COMPRESSED_SIZE) {
        return VerifyError::InvalidVerifyingKey;
    }

    uint16_t gamma_count = ReadLE16(bytes.data());
    size_t offset = 2;

    const unsigned char* ptr = bytes.data() + offset;
    if (blst_p1_uncompress(&out.alpha_g1, ptr) != BLST_SUCCESS || !blst_p1_affine_in_g1(&out.alpha_g1)) {
        return VerifyError::InvalidVerifyingKey;
    }
    offset += GROTH16_G1_COMPRESSED_SIZE;
    ptr = bytes.data() + offset;
    if (blst_p2_uncompress(&out.beta_g2, ptr) != BLST_SUCCESS || !blst_p2_affine_in_g2(&out.beta_g2)) {
        return VerifyError::InvalidVerifyingKey;
    }
    offset += GROTH16_G2_COMPRESSED_SIZE;
    ptr = bytes.data() + offset;
    if (blst_p2_uncompress(&out.gamma_g2, ptr) != BLST_SUCCESS || !blst_p2_affine_in_g2(&out.gamma_g2)) {
        return VerifyError::InvalidVerifyingKey;
    }
    offset += GROTH16_G2_COMPRESSED_SIZE;
    ptr = bytes.data() + offset;
    if (blst_p2_uncompress(&out.delta_g2, ptr) != BLST_SUCCESS || !blst_p2_affine_in_g2(&out.delta_g2)) {
        return VerifyError::InvalidVerifyingKey;
    }
    offset += GROTH16_G2_COMPRESSED_SIZE;
    ptr = bytes.data() + offset;
    if (blst_p1_uncompress(&out.gamma_abc0, ptr) != BLST_SUCCESS || !blst_p1_affine_in_g1(&out.gamma_abc0)) {
        return VerifyError::InvalidVerifyingKey;
    }
    offset += GROTH16_G1_COMPRESSED_SIZE;

    const size_t expected = offset + static_cast<size_t>(gamma_count) * GROTH16_G1_COMPRESSED_SIZE;
    if (bytes.size() != expected) {
        return VerifyError::InvalidVerifyingKey;
    }

    out.gamma_abc.resize(gamma_count);
    for (size_t i = 0; i < gamma_count; ++i) {
        ptr = bytes.data() + offset + i * GROTH16_G1_COMPRESSED_SIZE;
        if (blst_p1_uncompress(&out.gamma_abc[i], ptr) != BLST_SUCCESS || !blst_p1_affine_in_g1(&out.gamma_abc[i])) {
            return VerifyError::InvalidVerifyingKey;
        }
    }

    if (out.gamma_abc.size() > GROTH16_MAX_PUBLIC_INPUTS) {
        return VerifyError::InvalidVerifyingKey;
    }

    return VerifyError::OK;
}

// Public inputs are consensus-bound 32-byte values. Some of those bindings
// (for example the current chain separator and raw asset ids) are not
// guaranteed to be canonical Fr encodings, even though gnark ultimately uses
// them as BLS12-381 scalar field elements inside the proof system.
//
// Consensus already prevalidates the exact raw bytes for chain/asset/root/
// anchor/output-key before we reach the pairing equation, so at this layer we
// load the bytes into Fr rather than rejecting non-canonical encodings.
inline void LoadFrElement(const unsigned char* bytes, blst_scalar& out)
{
    blst_scalar_from_be_bytes(&out, bytes, GROTH16_FR_SIZE);
}

std::optional<uint32_t> ExtractRootHeight(std::span<const unsigned char> public_inputs, size_t element_index)
{
    if ((element_index + 1) * GROTH16_FR_SIZE > public_inputs.size()) {
        return std::nullopt;
    }
    const unsigned char* field = public_inputs.data() + element_index * GROTH16_FR_SIZE;
    const unsigned char* height_ptr = field + GROTH16_FR_SIZE - 4;
    uint32_t height = (static_cast<uint32_t>(height_ptr[0]) << 24) |
                      (static_cast<uint32_t>(height_ptr[1]) << 16) |
                      (static_cast<uint32_t>(height_ptr[2]) << 8) |
                      static_cast<uint32_t>(height_ptr[3]);
    return height;
}

bool AnchorMatches(std::span<const unsigned char> public_inputs, size_t element_index, std::span<const unsigned char> anchor)
{
    if (anchor.size() != GROTH16_FR_SIZE) {
        return false;
    }
    if ((element_index + 1) * GROTH16_FR_SIZE > public_inputs.size()) {
        return false;
    }
    const unsigned char* field = public_inputs.data() + element_index * GROTH16_FR_SIZE;
    return std::equal(anchor.begin(), anchor.end(), field);
}

} // namespace

VerifyError VerifyGroth16WithPolicy(std::span<const unsigned char> proof,
                                    std::span<const unsigned char> public_inputs,
                                    std::span<const unsigned char> vk_bytes,
                                    const VerificationContext& ctx)
{
    // Step 1: Parse and validate the verifying key
    ParsedVerifyingKey vk;
    VerifyError vk_status = ParseVerifyingKey(vk_bytes, vk);
    if (vk_status != VerifyError::OK) {
        return vk_status;
    }

    // Step 2: Validate proof and public input format
    if (proof.size() != GROTH16_PROOF_SIZE) {
        return VerifyError::InvalidProofFormat;
    }
    if (public_inputs.empty() || (public_inputs.size() % GROTH16_FR_SIZE) != 0) {
        return VerifyError::InvalidPublicInputs;
    }

    const size_t public_input_count = public_inputs.size() / GROTH16_FR_SIZE;
    if (public_input_count != vk.gamma_abc.size()) {
        return VerifyError::InvalidPublicInputs;
    }

    // Step 3: Policy-layer checks on public inputs (context binding)
    //
    // These checks enforce that the proof is bound to the current transaction context
    // and satisfies asset-specific policies without needing to understand the circuit internals.

    // Check compliance root freshness (legacy 4-input proofs only).
    // For 4-input proofs: public_inputs[2] = root || height (packed).
    // For 6-input (HDv1) proofs: public_inputs[2] is a pure MiMC root;
    //   freshness is checked on-chain via compliance_root_history.activation_height.
    if (ctx.max_root_age > 0 && public_input_count == 4) {
        auto root_height = ExtractRootHeight(public_inputs, 2);
        if (!root_height.has_value()) {
            return VerifyError::InvalidPublicInputs;
        }
        // Reject if root claims to be from the future
        if (ctx.current_height < static_cast<int>(*root_height)) {
            return VerifyError::RootTooOld;
        }
        // Reject if root is too old (staleness check)
        const uint32_t delta = static_cast<uint32_t>(ctx.current_height - static_cast<int>(*root_height));
        if (delta > ctx.max_root_age) {
            return VerifyError::RootTooOld;
        }
    }

    // Check transfer reporting anchor binding (public_inputs[3] = tfr_commit)
    if (ctx.anchor_commitment.has_value()) {
        if (!AnchorMatches(public_inputs, 3, ctx.anchor_commitment.value())) {
            return VerifyError::AnchorMismatch;
        }
    }

    // Step 4: Cryptographic verification of the Groth16 proof

    blst_p1_affine proof_A_affine, proof_C_affine;
    blst_p2_affine proof_B_affine;

    if (blst_p1_uncompress(&proof_A_affine, proof.data() + 0) != BLST_SUCCESS ||
        !blst_p1_affine_in_g1(&proof_A_affine)) {
        return VerifyError::InvalidProofFormat;
    }
    if (blst_p2_uncompress(&proof_B_affine, proof.data() + GROTH16_G1_COMPRESSED_SIZE) != BLST_SUCCESS ||
        !blst_p2_affine_in_g2(&proof_B_affine)) {
        return VerifyError::InvalidProofFormat;
    }
    if (blst_p1_uncompress(&proof_C_affine, proof.data() + GROTH16_G1_COMPRESSED_SIZE + GROTH16_G2_COMPRESSED_SIZE) != BLST_SUCCESS ||
        !blst_p1_affine_in_g1(&proof_C_affine)) {
        return VerifyError::InvalidProofFormat;
    }

    blst_p1 vk_x;
    blst_p1_from_affine(&vk_x, &vk.gamma_abc0);

    for (size_t i = 0; i < public_input_count; ++i) {
        const unsigned char* field = public_inputs.data() + i * GROTH16_FR_SIZE;
        blst_scalar scalar;
        LoadFrElement(field, scalar);

        // Convert scalar to little-endian bytes for multiplication
        std::array<unsigned char, GROTH16_FR_SIZE> scalar_le{};
        blst_lendian_from_scalar(scalar_le.data(), &scalar);

        blst_p1 gamma_projective;
        blst_p1_from_affine(&gamma_projective, &vk.gamma_abc[i]);
        blst_p1 tmp;
        blst_p1_mult(&tmp, &gamma_projective, scalar_le.data(), GROTH16_FR_SIZE * 8);
        blst_p1_add_or_double(&vk_x, &vk_x, &tmp);
    }

    blst_p1_affine vk_x_aff;
    blst_p1_to_affine(&vk_x_aff, &vk_x);

    // Allocate pairing context buffer (opaque type)
    size_t ctx_size = blst_pairing_sizeof();
    std::vector<uint8_t> ctx_buffer(ctx_size);
    blst_pairing* ctx_pairing = reinterpret_cast<blst_pairing*>(ctx_buffer.data());
    blst_pairing_init(ctx_pairing, true, nullptr, 0);

    // e(A, B) - note: blst_pairing_raw_aggregate takes (ctx, G2, G1)
    blst_pairing_raw_aggregate(ctx_pairing, &proof_B_affine, &proof_A_affine);

    // -e(vk_x, gamma)
    blst_p1 neg_vkx;
    blst_p1_from_affine(&neg_vkx, &vk_x_aff);
    blst_p1_cneg(&neg_vkx, true);
    blst_p1_affine neg_vkx_aff;
    blst_p1_to_affine(&neg_vkx_aff, &neg_vkx);
    blst_pairing_raw_aggregate(ctx_pairing, &vk.gamma_g2, &neg_vkx_aff);

    // -e(C, delta)
    blst_p1 neg_C;
    blst_p1_from_affine(&neg_C, &proof_C_affine);
    blst_p1_cneg(&neg_C, true);
    blst_p1_affine neg_C_aff;
    blst_p1_to_affine(&neg_C_aff, &neg_C);
    blst_pairing_raw_aggregate(ctx_pairing, &vk.delta_g2, &neg_C_aff);

    // -e(alpha, beta)
    blst_p1 neg_alpha;
    blst_p1_from_affine(&neg_alpha, &vk.alpha_g1);
    blst_p1_cneg(&neg_alpha, true);
    blst_p1_affine neg_alpha_aff;
    blst_p1_to_affine(&neg_alpha_aff, &neg_alpha);
    blst_pairing_raw_aggregate(ctx_pairing, &vk.beta_g2, &neg_alpha_aff);

    // Commit and verify
    blst_pairing_commit(ctx_pairing);
    if (!blst_pairing_finalverify(ctx_pairing, nullptr)) {
        return VerifyError::PairingFailed;
    }

    return VerifyError::OK;
}

} // namespace groth16
