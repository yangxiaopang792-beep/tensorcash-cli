// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DIFFICULTY_CFD_H
#define BITCOIN_CONSENSUS_DIFFICULTY_CFD_H

#include <consensus/amount.h>

#include <cstdint>

class arith_uint256;

//! Minimum non-zero settlement output emitted by OP_DIFFCFD_SETTLE.
//! Fixed consensus constant (NOT the policy dust relay fee, which can change): every
//! non-zero covenant payout is snapped to be >= this so a unilateral settlement always
//! relays. 546 sat is the classic dust floor, comfortably above the ~330 sat P2TR dust
//! at the default 3000 sat/kvB relay rate.
static constexpr CAmount MIN_SETTLE_OUTPUT{546};

//! Fixed-point scale for the leverage parameter lambda. lambda = lambda_q / DIFFCFD_LAMBDA_SCALE,
//! i.e. lambda_q is Q16 (L = 2^16).
static constexpr uint64_t DIFFCFD_LAMBDA_SCALE{1ULL << 16};

//! Burial required before a fixing height becomes resolvable. Applied by CONSENSUS in BOTH block
//! validation and mempool relay (>= the chain's worst-case reorg assumption): a settlement that
//! reads nBits @ H is only valid when H <= context_height - DIFFCFD_MATURITY_DEPTH, so the fixing
//! ancestor is always deeply buried and reorg-stable. See DIFFICULTY_DERIVATIVE.md §3.5.
static constexpr int DIFFCFD_MATURITY_DEPTH{100};

//! Whether a fixing height H is resolvable against an anchor at `context_height` requiring
//! `maturity_depth` burial: 0 <= H < context_height AND H <= context_height - maturity_depth.
//! Pure (testable in isolation); used by the chain fixing resolver in validation.cpp.
bool DiffCfdFixingResolvable(int height, int context_height, int maturity_depth);

//! The two outputs a single vault settles into.
struct DiffCfdPayout {
    uint64_t payout_owner{0};
    uint64_t payout_cp{0};
};

//! Compute the deterministic, capped per-vault payout for OP_DIFFCFD_SETTLE.
//!
//! Pure function of the committed terms and the realized target (see DIFFICULTY_DERIVATIVE.md
//! §1.1 / §3.2 steps 2-3). Denominates the loss as a fraction of the vault's own margin:
//!
//!   long  (DOWN, short_leg=false): loses as difficulty falls  => realized_target > strike_target
//!   short (UP,   short_leg=true):  loses as difficulty rises   => realized_target < strike_target
//!
//!   f_loss   = clamp(lambda_q/L * |move|, 0, 1)         move = (target diff) / realized_target
//!   payout_cp    = floor(f_loss * vault_im)             (truncated; remainder accrues to owner)
//!   payout_owner = vault_im - payout_cp
//!
//! then a sub-dust nonzero leg is snapped to 0 (its value going to the surviving leg) so no
//! non-zero output is ever below MIN_SETTLE_OUTPUT. The clamp boundary (fraction == 1) resolves
//! to full liquidation. All intermediate products accumulate in 512 bits without truncation.
//!
//! Returns false (settlement invalid) when lambda_q == 0, vault_im < MIN_SETTLE_OUTPUT, or the
//! realized target is zero.
bool ComputeDiffCfdPayout(const arith_uint256& strike_target,
                          const arith_uint256& realized_target,
                          uint32_t lambda_q,
                          uint64_t vault_im,
                          bool short_leg,
                          DiffCfdPayout& out);

#endif // BITCOIN_CONSENSUS_DIFFICULTY_CFD_H
