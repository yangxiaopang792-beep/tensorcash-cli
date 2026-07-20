// Copyright (c) 2025 TensorCash
// VDF proof generation for testing

#ifndef BITCOIN_VDF_VDFGENERATE_H
#define BITCOIN_VDF_VDFGENERATE_H

#include <uint256.h>
#include <span>
#include <vector>
#include <cstdint>

namespace vdf {

// Generate a VALID VDF proof for testing purposes
// This uses chiavdf's ProveSlow to generate real, verifiable proofs
// - prev_hash: 32-byte previous block hash (as challenge)
// - iterations: VDF tick count (should be small for testing, e.g., 100-1000)
// - discr_bits: discriminant size in bits (default 1024)
// Returns the serialized VDF proof that will pass verification
std::vector<uint8_t> GenerateProofForTesting(const uint256& prev_hash,
                                             uint64_t iterations,
                                             uint32_t discr_bits = 1024);

// Cleanup function (no-op for ProveSlow, kept for API compatibility)
void CleanupTestProver();

} // namespace vdf

#endif // BITCOIN_VDF_VDFGENERATE_H