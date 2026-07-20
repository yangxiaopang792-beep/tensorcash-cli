// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/scalar_cfd_leaf.h>

#include <crypto/common.h> // ReadLE16 / ReadLE32 / ReadLE64

#include <cstddef>

namespace {
using valtype = std::vector<unsigned char>;

//! Read the next token and require it to be a direct data push of EXACTLY `len`
//! bytes (`OP_PUSHBYTES_len`). For a minimal direct push the opcode byte equals the
//! pushed length (1..75), so `op == len` rejects `OP_PUSHDATA1/2/4` (0x4c..0x4e) and
//! every `OP_n` numeric opcode (whose data is empty). `len` is only ever 1/2/4/8/32.
bool ReadExactPush(const CScript& s, CScript::const_iterator& pc, std::size_t len, valtype& out)
{
    opcodetype op;
    valtype vch;
    if (!s.GetOp(pc, op, vch)) return false;
    if (static_cast<std::size_t>(op) != len) return false; // direct push only (op byte == length)
    if (vch.size() != len) return false;                    // implied by the above for 1..75; defensive
    out = std::move(vch);
    return true;
}

//! Require the next token to be exactly the bare opcode `expect` carrying no data.
bool ReadBareOpcode(const CScript& s, CScript::const_iterator& pc, opcodetype expect)
{
    opcodetype op;
    valtype vch;
    if (!s.GetOp(pc, op, vch)) return false;
    return op == expect && vch.empty();
}

//! Read the canonical CLTV operand: a direct push of a minimal, non-negative
//! `CScriptNum` of 1..5 bytes. Rejects `OP_PUSHDATA*`/`OP_n`, non-minimal encodings,
//! oversize, and negative locktimes.
bool ReadCltvPush(const CScript& s, CScript::const_iterator& pc, int64_t& out)
{
    opcodetype op;
    valtype vch;
    if (!s.GetOp(pc, op, vch)) return false;
    const std::size_t len = vch.size();
    if (len < 1 || len > 5) return false;
    if (static_cast<std::size_t>(op) != len) return false; // direct push only
    try {
        const CScriptNum n(vch, /*fRequireMinimal=*/true, /*nMaxNumSize=*/5);
        const int64_t v = n.GetInt64();
        if (v < 0) return false; // locktimes are non-negative
        out = v;
    } catch (const scriptnum_error&) {
        return false; // non-minimal / oversize
    }
    return true;
}

//! A direct 32-byte push decoded as a uint256 (LE for the scalar blobs; opaque for ids/keys).
bool ReadUint256Push(const CScript& s, CScript::const_iterator& pc, uint256& out)
{
    valtype vch;
    if (!ReadExactPush(s, pc, 32, vch)) return false;
    out = uint256{vch};
    return true;
}
} // namespace

bool ParseScalarCfdLeaf(const CScript& leaf, ScalarCfdLeaf& out)
{
    CScript::const_iterator pc = leaf.begin();
    valtype vch;

    // <contract_id32> OP_DROP
    if (!ReadUint256Push(leaf, pc, out.contract_id)) return false;
    if (!ReadBareOpcode(leaf, pc, OP_DROP)) return false;

    // <template_version=0x01>
    if (!ReadExactPush(leaf, pc, 1, vch)) return false;
    out.template_version = vch[0];
    if (out.template_version != SCALAR_CFD_TEMPLATE_VERSION_V1) return false; // unknown template -> fail-closed

    // <settle_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
    if (!ReadCltvPush(leaf, pc, out.settle_lock_height)) return false;
    if (!ReadBareOpcode(leaf, pc, OP_CHECKLOCKTIMEVERIFY)) return false;
    if (!ReadBareOpcode(leaf, pc, OP_DROP)) return false;

    // <source_type> — only the two template-valid values.
    if (!ReadExactPush(leaf, pc, 1, vch)) return false;
    out.source_type = vch[0];
    if (out.source_type != static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED) &&
        out.source_type != static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC)) {
        return false;
    }

    // <underlying_asset_id32> — U. CHAIN_INTRINSIC settles from an objective chain metric,
    // not an issuer feed, so it has no underlying: the canonical template pins U to zero.
    // (A non-zero U there would be pure malleability — a different tapleaf hash for an
    // identical settlement — so it is rejected, not merely ignored.)
    if (!ReadUint256Push(leaf, pc, out.underlying_asset_id)) return false;
    if (out.source_type == static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC) &&
        !out.underlying_asset_id.IsNull()) {
        return false;
    }

    // <feed_id_le4>
    if (!ReadExactPush(leaf, pc, 4, vch)) return false;
    out.feed_id = ReadLE32(vch.data());

    // <fixing_ref_le8>
    if (!ReadExactPush(leaf, pc, 8, vch)) return false;
    out.fixing_ref = ReadLE64(vch.data());

    // <publication_deadline_height_le4>
    if (!ReadExactPush(leaf, pc, 4, vch)) return false;
    out.publication_deadline_height = ReadLE32(vch.data());

    // <payoff_mode> — v1 ships {0, 1}; mode 2 is deferred behind a template bump.
    if (!ReadExactPush(leaf, pc, 1, vch)) return false;
    out.payoff_mode = vch[0];
    if (out.payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE) &&
        out.payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)) {
        return false;
    }

    // <scalar_format_id_le2> — extracted but not range-checked (catalogue is an eval concern).
    if (!ReadExactPush(leaf, pc, 2, vch)) return false;
    out.scalar_format_id = ReadLE16(vch.data());

    // <strike_le32> <fallback_scalar_le32>
    if (!ReadUint256Push(leaf, pc, out.strike)) return false;
    if (!ReadUint256Push(leaf, pc, out.fallback_scalar)) return false;

    // <lambda_q_le4>
    if (!ReadExactPush(leaf, pc, 4, vch)) return false;
    out.lambda_q = ReadLE32(vch.data());

    // <loss_direction> — a raw 1-byte push of 0x00/0x01 (NOT OP_1, which is a bare opcode).
    if (!ReadExactPush(leaf, pc, 1, vch)) return false;
    out.loss_direction = vch[0];
    if (out.loss_direction != 0x00 && out.loss_direction != 0x01) return false;

    // <collateral_asset_id32> (32 zero bytes = NATIVE_SENTINEL)
    if (!ReadUint256Push(leaf, pc, out.collateral_asset_id)) return false;

    // <vault_im_le8>
    if (!ReadExactPush(leaf, pc, 8, vch)) return false;
    out.vault_im = ReadLE64(vch.data());

    // <owner_key32> <cp_key32>
    if (!ReadExactPush(leaf, pc, 32, out.owner_key)) return false;
    if (!ReadExactPush(leaf, pc, 32, out.cp_key)) return false;

    // OP_SCALAR_CFD_SETTLE, then nothing trailing.
    if (!ReadBareOpcode(leaf, pc, OP_SCALAR_CFD_SETTLE)) return false;
    if (pc != leaf.end()) return false;

    return true;
}
