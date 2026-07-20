// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SCALAR_CFD_LEAF_H
#define BITCOIN_CONSENSUS_SCALAR_CFD_LEAF_H

#include <script/script.h> // CScript, opcodetype
#include <uint256.h>

#include <cstdint>
#include <vector>

//! Canonical scalar-CFD settlement leaf (CFD_GENERALISATION.md §2.2). This is the
//! PURE, fail-closed parser shared by the single-threaded consensus pre-scan (§3.4,
//! which extracts the committed fixing reference to build the immutable snapshot) and
//! by any caller needing the leaf's committed economic terms. It parses the RAW leaf
//! script bytes, not the post-execution stack, and requires every operand to use its
//! one canonical push form — so a malformed-but-detected leaf can never yield a
//! snapshot entry and therefore can never settle (detection over-approximates;
//! extraction under-approximates; both fail safe).

//! The terminal opcode of the canonical leaf is `OP_SCALAR_CFD_SETTLE` (script.h), the
//! repurposed `OP_NOP10` slot. Parser and interpreter share that one symbol so they cannot
//! drift on the value.

//! The only leaf-template version this parser recognises. A different byte means a
//! different (future) template → no canonical v1 parse → fail-closed (§2.2).
static constexpr uint8_t SCALAR_CFD_TEMPLATE_VERSION_V1{0x01};

//! Native-collateral sentinel: a `collateral_asset_id` of 32 zero bytes selects the
//! native-TSC binding branch (§2.3); any other value is an asset id.
//! (`uint256{}` is all-zero.)

//! `source_type` byte values (§2.2 / §12). Only these two are template-valid.
enum class ScalarCfdSourceType : uint8_t {
    ISSUER_PUBLISHED = 0x00, //!< trusted-issuer feed: `(U, feed_id, fixing_ref=scalar_epoch)`
    CHAIN_INTRINSIC  = 0x01, //!< objective chain metric: `feed_id=metric_id||window_code`, `fixing_ref=height`
};

//! `payoff_mode` byte values (§4, decision 2026-06-22: v1 ships {0, 1}; mode 2 is
//! deferred behind a `template_version` bump, so it is NOT template-valid under v1).
enum class ScalarCfdPayoffMode : uint8_t {
    STRIKE   = 0x00, //!< loss denominated by |X-K|/K
    REALIZED = 0x01, //!< loss denominated by |X-K|/X (reproduces the difficulty semantics)
};

//! Every committed literal of the canonical v1 leaf, decoded. Numeric blobs are
//! little-endian fixed-width; 32-byte ids are stored as uint256; the two settlement
//! keys are kept as raw 32-byte x-only pushes (they are spliced into `OP_1 <key>`
//! output scripts at settlement). Populated only when ParseScalarCfdLeaf returns true.
struct ScalarCfdLeaf {
    uint256  contract_id;                  //!< per-instance uniqueness (NUMS-shared vaults)
    uint8_t  template_version{0};          //!< always SCALAR_CFD_TEMPLATE_VERSION_V1 on success
    int64_t  settle_lock_height{0};        //!< CLTV operand (canonical minimal CScriptNum, >= 0)
    uint8_t  source_type{0};               //!< a ScalarCfdSourceType value
    uint256  underlying_asset_id;          //!< U; MUST be zero for CHAIN_INTRINSIC (parser-enforced)
    uint32_t feed_id{0};                   //!< ISSUER: which feed of U; CHAIN: metric_id||window_code
    uint64_t fixing_ref{0};                //!< ISSUER: scalar_epoch; CHAIN: window-end height
    uint32_t publication_deadline_height{0}; //!< last height a real fixing counts (§3.4)
    uint8_t  payoff_mode{0};               //!< a ScalarCfdPayoffMode value
    uint16_t scalar_format_id{0};          //!< scalar ENCODING the strike/fallback/fixing use
    uint256  strike;                       //!< K, in scalar_format_id's encoding
    uint256  fallback_scalar;              //!< used iff no in-time real fixing (§3.4)
    uint32_t lambda_q{0};                  //!< Q16 leverage (reused from difficulty)
    uint8_t  loss_direction{0};            //!< 0x00 long / 0x01 short
    uint256  collateral_asset_id;          //!< C; 32 zero bytes = NATIVE_SENTINEL (TSC)
    uint64_t vault_im{0};                  //!< IM in C's units
    std::vector<unsigned char> owner_key;  //!< 32-byte x-only
    std::vector<unsigned char> cp_key;     //!< 32-byte x-only
};

//! Parse a revealed tapleaf as the canonical scalar-CFD settlement leaf (§2.2).
//!
//! Returns true (and fills `out`) ONLY when `leaf` is EXACTLY the canonical v1 token
//! sequence with every operand in its one legal push form:
//!   - 1/2/4/8/32-byte blobs are direct data pushes of exactly that length
//!     (`OP_PUSHBYTES_n`) — never `OP_PUSHDATA*`, never an `OP_n`/`CScriptNum` shortcut;
//!   - `settle_lock_height` is a direct push of a minimal, non-negative `CScriptNum`
//!     (1..5 bytes), the canonical CLTV operand;
//!   - `template_version` == 0x01, `source_type` in {0,1}, `payoff_mode` in {0,1},
//!     `loss_direction` in {0,1} (a raw 1-byte push, NOT `OP_1`);
//!   - the structural opcodes (`OP_DROP`, `OP_CHECKLOCKTIMEVERIFY`, the terminal
//!     `OP_SCALAR_CFD_SETTLE`) appear bare and in order, with nothing trailing.
//!
//! Any deviation returns false; `out` is then unspecified. `scalar_format_id` is
//! extracted but NOT range-checked here (the known-format catalogue is an eval/resolution
//! concern that can grow without touching this parser).
bool ParseScalarCfdLeaf(const CScript& leaf, ScalarCfdLeaf& out);

#endif // BITCOIN_CONSENSUS_SCALAR_CFD_LEAF_H
