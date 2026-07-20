#ifndef BITCOIN_CRYPTO_GROTH16_H
#define BITCOIN_CRYPTO_GROTH16_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <span.h>

namespace groth16 {

static constexpr size_t GROTH16_PROOF_SIZE = 192;           // 48 + 96 + 48 compressed
static constexpr size_t GROTH16_G1_COMPRESSED_SIZE = 48;
static constexpr size_t GROTH16_G2_COMPRESSED_SIZE = 96;
static constexpr size_t GROTH16_FR_SIZE = 32;
static constexpr size_t GROTH16_MAX_PUBLIC_INPUTS = 8;

struct VerificationContext {
    uint32_t max_root_age{0};
    int current_height{0};
    std::optional<std::span<const unsigned char>> anchor_commitment; // optional 32-byte commitment
};

enum class VerifyError {
    OK = 0,
    InvalidProofFormat,
    InvalidVerifyingKey,
    InvalidPublicInputs,
    RootTooOld,
    AnchorMismatch,
    OutputKeyMismatch,
    PairingFailed,
};

VerifyError VerifyGroth16WithPolicy(std::span<const unsigned char> proof,
                                    std::span<const unsigned char> public_inputs,
                                    std::span<const unsigned char> vk_bytes,
                                    const VerificationContext& ctx);

} // namespace groth16

#endif // BITCOIN_CRYPTO_GROTH16_H
