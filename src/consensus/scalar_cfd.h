// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SCALAR_CFD_H
#define BITCOIN_CONSENSUS_SCALAR_CFD_H

#include <assets/registry.h>      // ScalarRecord
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT (CAmount)
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <optional>

class arith_uint256;

//! Per-leg native-dust floor for an ASSET-collateral settlement output (§2.3 step 6): the keeper
//! funds this native dust alongside the asset-tagged value, so the asset output binds nValue >= this
//! (NOT exact). Intentionally identical (546) to the native MIN_SETTLE_OUTPUT settle floor and the
//! wallet's kMinAssetOutputDust; named separately so the asset path documents its own dust meaning.
static constexpr CAmount SCALARCFD_ASSET_OUTPUT_DUST = MIN_SETTLE_OUTPUT;

//! Scalar-CFD fixing resolution (CFD_GENERALISATION.md §3.4). This is the pure,
//! mode-INDEPENDENT core of the publication->settlement bridge: given a leaf's
//! committed fixing reference + deadline/fallback and a way to read published
//! scalars, it produces the single effective scalar the settlement opcode folds.
//! It performs NO chain/cache access itself (a reader callback is injected), so it
//! is unit-testable in isolation and identical in block validation and mempool.

//! Burial before a published scalar becomes settlement-usable (reorg-stable),
//! mirroring DiffCfdFixingResolvable: 0 <= pub_height < context_height AND
//! pub_height <= context_height - maturity_depth.
bool ScalarCfdFixingBuried(int publication_height, int context_height, int maturity_depth);

//! The effective scalar a settlement leaf resolves to.
struct ResolvedScalar {
    uint256  scalar;
    uint16_t scalar_format_id{0};
    bool     is_fallback{false}; // true => the committed fallback fired (no in-time real fixing)
};

//! Resolve a leaf's fixing via the deterministic three-way deadline/fallback rule
//! (CFD_GENERALISATION.md §3.4). `reader(asset_id, feed_id, epoch)` returns the
//! published record or nullopt. Returns nullopt = "pending" (the opcode must fail).
//!
//!   real = reader(underlying_asset_id, feed_id, fixing_ref)
//!   usable_real = real exists
//!              && real.scalar_format_id == leaf_scalar_format_id   // wrong encoding -> unusable
//!              && real.publication_height <= publication_deadline_height  // LATE pubs -> unusable
//!              && buried(real.publication_height)
//!   if usable_real:
//!       -> real.scalar            (is_fallback=false)   // the real fixing
//!   elif context_height >= publication_deadline_height + max(fallback_grace, maturity_depth):
//!       -> fallback_scalar        (is_fallback=true)    // committed default
//!   else:
//!       -> nullopt                                      // still pending
//!
//! A real fixing whose scalar_format_id differs from the leaf's committed encoding is treated
//! as UNUSABLE (same as a missing/late fixing), so the contract falls through to the committed
//! fallback rather than trapping funds or interpreting bytes under the wrong encoding. The
//! returned scalar is therefore ALWAYS in `leaf_scalar_format_id`.
//!
//! `publication_deadline_height` is the leaf's committed value and is typed `uint32_t` (exactly
//! the leaf encoding), so it is BOUNDED BY ITS TYPE: `deadline + grace` and `ctx - deadline`
//! evaluated in int64_t can never signed-overflow regardless of the input. The effective grace is
//! clamped to >= maturity_depth so the race-freedom invariant (an in-time fixing always buries
//! before the fallback branch can fire) holds even if a chainparam sets grace < maturity.
std::optional<ResolvedScalar> ResolveScalarFixing(
    const uint256& underlying_asset_id,
    uint32_t feed_id,
    uint64_t fixing_ref,
    uint32_t publication_deadline_height,
    const uint256& fallback_scalar,
    uint16_t leaf_scalar_format_id,
    int context_height,
    int maturity_depth,
    int fallback_grace,
    const std::function<std::optional<ScalarRecord>(const uint256&, uint32_t, uint64_t)>& reader);

//! Fixed-point scale for the leverage parameter lambda (Q16), matching the difficulty
//! leaf's encoding (DIFFCFD_LAMBDA_SCALE): lambda = lambda_q / 2^16.
static constexpr uint64_t SCALARCFD_LAMBDA_SCALE{1ULL << 16};

//! Which value denominates the loss fraction (CFD_GENERALISATION.md §4.2). The opcode
//! maps the leaf's payoff_mode byte here: mode 0 -> STRIKE, mode 1 -> REALIZED. Mode 2
//! (FIXED-REF) is deferred (it needs a committed operand the v1 leaf lacks) and is not
//! representable.
enum class ScalarLossDenominator : uint8_t {
    STRIKE   = 0, //!< denominator = committed strike K -> f_loss = clamp(lambda*|X-K|/K, 0, 1)
    REALIZED = 1, //!< denominator = resolved scalar X  -> f_loss = clamp(lambda*|X-K|/X, 0, 1)
};

//! The two outputs a single scalar-CFD vault settles into.
struct ScalarCfdPayout {
    uint64_t payout_owner{0};
    uint64_t payout_cp{0};
};

//! Compute the deterministic, capped per-vault payout for OP_SCALAR_CFD_SETTLE
//! (CFD_GENERALISATION.md §4). Generalises ComputeDiffCfdPayout: identical clamp/floor/
//! dust-snap and 512-bit envelope, but
//!   - the loss is taken in SCALAR (price) space, NOT difficulty's inverted target space:
//!       long  (short_leg=false): loses as X falls below K -> loss iff X < K, num = K - X
//!       short (short_leg=true):  loses as X rises above K  -> loss iff X > K, num = X - K
//!     (flat / in-the-money -> owner keeps the full margin); and
//!   - the denominator is selected by `denominator` (STRIKE=K vs REALIZED=X).
//!
//!   f_loss       = clamp(lambda_q/2^16 * num / denom, 0, 1)
//!   payout_cp    = floor(f_loss * vault_im)   (truncated; remainder accrues to owner)
//!   payout_owner = vault_im - payout_cp
//! then a sub-`min_settle_output` non-zero leg is snapped to 0 (its value to the surviving
//! leg). All intermediate products accumulate in 512 bits without truncation.
//!
//! A ZERO denominator in the loss branch (mode STRIKE with K=0, or mode REALIZED with a
//! resolved X=0) is the clamp limit num/0 -> infinity -> full liquidation (payout_cp =
//! vault_im), handled by the SAME `lhs >= denom_scaled` boundary as fraction>=1 — never a
//! divide-by-zero, never a fund-trapping failure. (This is the deliberate divergence from
//! difficulty, whose realized_target is consensus-read and can never be zero.)
//!
//! `min_settle_output` is the dust floor for the collateral settled: MIN_SETTLE_OUTPUT for
//! NATIVE_SENTINEL collateral, kMinAssetOutputDust for an asset (§5). Returns false
//! (settlement invalid) only when lambda_q == 0 or vault_im < min_settle_output.
bool ComputeScalarCfdPayout(const arith_uint256& strike,
                            const arith_uint256& realized,
                            ScalarLossDenominator denominator,
                            uint32_t lambda_q,
                            uint64_t vault_im,
                            bool short_leg,
                            uint64_t min_settle_output,
                            ScalarCfdPayout& out);

//! Decode a 32-byte scalar blob under `scalar_format_id` into the integer the payout math uses
//! (CFD_GENERALISATION.md §4.2/§6, Slice 6). The catalogue covers byte order (RAW_U256_LE/BE) and
//! canonical fixed-width unsigned ints (U64/U128 LE/BE) whose unused high bytes MUST be zero. It
//! carries NO economic scale: the payoff ratio λ·|X−K|/denom is scale-invariant (X and K share the
//! format), so a Q-scale would cancel — it lives in the wallet display layer, not here. Returns false
//! for an unknown format OR a value that overflows a fixed-width format's range (non-canonical), so
//! the opcode fails CLOSED rather than settle on an ambiguous encoding. Applied to BOTH the committed
//! strike and the resolved scalar, which share the leaf's format by construction.
bool DecodeScalarValue(uint16_t scalar_format_id, const uint256& raw, arith_uint256& out);

//! Inverse of DecodeScalarValue (Slice 6): encode a plain numeric value (e.g. uint256::FromHex of the
//! user's display hex) into the format's canonical WIRE bytes — identity for LE, byte-reversed for BE.
//! Returns false if the value exceeds the format's width. RPC/Qt ingress uses this so users keep ONE
//! numeric "display hex" convention across LE/BE while the on-chain bytes (leaf strike/fallback, the
//! published carrier) honour the format; settlement reads them back with DecodeScalarValue.
bool EncodeScalarToWire(uint16_t scalar_format_id, const uint256& numeric_value, uint256& wire_out);

#endif // BITCOIN_CONSENSUS_SCALAR_CFD_H
