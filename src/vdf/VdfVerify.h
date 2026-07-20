// Minimal VDF verification interface for headers-presync (SPV) use.
#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <uint256.h>

namespace vdf {

// Verify Wesolowski VDF proof for a block given the previous block hash as challenge.
// - prev_hash: 32-byte previous block hash (as serialized in header)
// - vdf_proof: serialized proof bytes (~200B)
// - iterations: VDF tick count
// - discr_bits: discriminant size in bits (default 1024 to match miner/verifier)
// - recursion: proof depth (default 0)
// Returns true on successful verification.
bool VerifyAgainstPrevHash(const uint256& prev_hash,
                           std::span<const uint8_t> vdf_proof,
                           uint64_t iterations,
                           uint32_t discr_bits = 1024,
                           uint32_t recursion = 0);

} // namespace vdf

