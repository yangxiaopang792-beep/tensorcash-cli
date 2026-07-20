// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/difficulty_cfd.h>

#include <arith_uint256.h>

bool DiffCfdFixingResolvable(int height, int context_height, int maturity_depth)
{
    if (height < 0) return false;
    if (height >= context_height) return false;            // strictly a buried ancestor, never the anchor
    if (height > context_height - maturity_depth) return false; // matured / reorg-stable
    return true;
}

namespace {
//! Widen a 256-bit value into a 512-bit accumulator without truncation, using only the
//! public interface of base_uint (GetLow64 / shift / or).
base_uint<512> Widen(const arith_uint256& x)
{
    base_uint<512> result;
    arith_uint256 tmp = x;
    for (int word = 0; word < 4; ++word) {
        base_uint<512> piece(tmp.GetLow64());
        piece <<= (64 * word);
        result |= piece;
        tmp >>= 64;
    }
    return result;
}
} // namespace

bool ComputeDiffCfdPayout(const arith_uint256& strike_target,
                          const arith_uint256& realized_target,
                          uint32_t lambda_q,
                          uint64_t vault_im,
                          bool short_leg,
                          DiffCfdPayout& out)
{
    if (lambda_q == 0) return false;
    if (vault_im < static_cast<uint64_t>(MIN_SETTLE_OUTPUT)) return false;
    if (realized_target == 0) return false; // denom; DeriveTarget already rejects a zero target

    // Loss numerator by direction; denominator = realized_target (S_target).
    arith_uint256 num;
    if (short_leg) {
        // short (UP): loses as difficulty rises => target falls => realized < strike
        if (!(realized_target < strike_target)) {
            out.payout_owner = vault_im;
            out.payout_cp = 0;
            return true; // in-the-money or flat: owner keeps full margin
        }
        num = strike_target - realized_target;
    } else {
        // long (DOWN): loses as difficulty falls => target rises => realized > strike
        if (!(realized_target > strike_target)) {
            out.payout_owner = vault_im;
            out.payout_cp = 0;
            return true;
        }
        num = realized_target - strike_target;
    }

    // Clamped exact floor in 512 bits.
    //   raw fraction = lambda_q * num / (L * denom),  L = DIFFCFD_LAMBDA_SCALE = 2^16
    //   payout_cp    = floor(fraction * vault_im), clamped to vault_im once fraction >= 1.
    // Widths: num,denom <= 2^256; lambda_q <= 2^32; vault_im <= 2^64. lhs <= 2^288,
    // denom_scaled <= 2^272, numer <= 2^352 — all comfortably inside 512 bits.
    const base_uint<512> lhs = Widen(num) * base_uint<512>(static_cast<uint64_t>(lambda_q));
    const base_uint<512> denom_scaled = Widen(realized_target) << 16; // L * denom

    uint64_t payout_cp;
    if (lhs >= denom_scaled) {
        payout_cp = vault_im; // raw fraction >= 1.0 -> full liquidation (boundary -> full)
    } else {
        const base_uint<512> numer = lhs * base_uint<512>(vault_im);
        const base_uint<512> quotient = numer / denom_scaled;
        // In this branch lhs < denom_scaled, so quotient < vault_im <= 2^64 and fits in 64 bits.
        payout_cp = quotient.GetLow64();
    }
    uint64_t payout_owner = vault_im - payout_cp;

    // Dust floor: snap a sub-dust non-zero leg to 0, its value going to the surviving leg.
    // vault_im >= MIN_SETTLE_OUTPUT guarantees at most one leg can be sub-dust at a time.
    const uint64_t min_out = static_cast<uint64_t>(MIN_SETTLE_OUTPUT);
    if (payout_cp != 0 && payout_cp < min_out) {
        payout_cp = 0;
        payout_owner = vault_im;
    } else if (payout_owner != 0 && payout_owner < min_out) {
        payout_owner = 0;
        payout_cp = vault_im;
    }

    out.payout_owner = payout_owner;
    out.payout_cp = payout_cp;
    return true;
}
