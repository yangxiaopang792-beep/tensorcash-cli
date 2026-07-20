// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSETS_ICU_ACCEPTANCE_RECORD_H
#define BITCOIN_ASSETS_ICU_ACCEPTANCE_RECORD_H

#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>
#include <uint256.h>

#include <array>
#include <set>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace assets {

// On-chain ICU acceptance record: persists a holder's affirmation of an ICU document (and specific
// clauses) on chain, instead of an off-chain BIP-322 sidecar. ACKNOWLEDGE records are durable +
// self-verifiable from chain data (the signature binds the record, independent of later state). RETURN
// records are also rotation-durable: verification confirms the asset was returned to a current-OR-historical
// issuer ICU address by walking the icu_outpoint rotation chain (needs -txindex to resolve spent
// ancestors), so a legitimate return stays verified across issuer ICU rotations.
//
// CARRIER / CONSENSUS NOTE: the record rides in an output's vExt as TLV type 0x40, like TFR_ANCHOR
// (0x21) -- a freestanding acceptance output, NOT a sub-TLV on the asset output (vExt is single-TLV per
// output). The three vExt whitelists that previously rejected an unknown type now accept a well-formed
// 0x40: ConnectBlock (validation.cpp), CheckTxInputs (consensus/tx_verify.cpp) and IsStandardTx relay
// (policy.cpp). This is a consensus RELAXATION -- a hard fork (old nodes reject 0x40), deployed fleet-
// wide rather than gated by a separate activation height; it rides the existing assets-activation gate.
// Consensus/relay accept iff the record parses (fail-closed structural + semantic validation below);
// signature CRYPTO validity (raw Schnorr / BIP-322 over the TSC-ICU-ACCEPTANCE-RECORD-1 signing message,
// IcuAcceptanceRecordSigningMessage) is a read-layer check.
inline constexpr uint8_t ICU_ACCEPTANCE_TLV_TYPE = 0x40;
inline constexpr uint8_t ICU_ACCEPTANCE_RECORD_VERSION = 1;

// Relay-policy upper bound on a 0x40 record's total vExt size (consensus only caps at the 16 KiB
// per-output vExt hard limit). Comfortably fits the fixed fields + many body_refs + a compact secp
// signature, and stays well under the per-output hard cap.
inline constexpr size_t MAX_ICU_ACCEPTANCE_VEXT_BYTES = 8192;

// Which signature the record carries. The holder's scriptPubKey family decides. EVERY signature is over
// the TSC-ICU-ACCEPTANCE-RECORD-1 message (IcuAcceptanceRecordSigningMessage), which binds ALL record
// fields except the signature -- so a signature cannot be lifted onto a different prevout / units / doc.
//  - SECP_SCHNORR_RAW: a raw BIP-340 Schnorr signature (64 bytes) over a domain-separated hash of the
//    record message, verified directly against the taproot output key extracted from the holder's spk.
//    The path for BOTH taproot families: P2TR-v1 (output key already on chain -> no extra exposure) and
//    P2TR-v2 / PQ (key-path is consensus-disabled, so revealing/using the secp output key is quantum-safe
//    -- breaking it cannot spend). Compact and immediately verifiable.
//  - SECP_BIP322_HASH: only SHA256(bip322_proof), where bip322_proof is a BIP-322 signature over the
//    record message. A commit-reveal for hash-hidden spendable families (P2PKH/P2WPKH/P2WSH): the pubkey
//    is NOT on chain and the key IS spendable, so the proof must not be revealed while the asset is held
//    (that would expose a live key to a quantum attacker). The proof is revealed + matched at spend.
//  - NONE: no signature -- RETURN only (attributed by the asset-input spend, not a message signature).
//
// NOTE: deliberately NO full on-chain BIP-322 scheme and NO ML-DSA scheme. Taproot uses the compact
// SECP_SCHNORR_RAW (a full serialized BIP-322 proof is variable-length and, for hash-hidden families,
// would expose a live key); hash-hidden families use SECP_BIP322_HASH; and even the PQ family signs with
// its quantum-safe secp output key, never a multi-KB ML-DSA blob. ML-DSA stays the SPEND authority.
enum class IcuAcceptSigScheme : uint8_t {
    NONE = 0,
    SECP_SCHNORR_RAW = 1,
    SECP_BIP322_HASH = 2,
};

struct IcuAcceptanceRecord {
    uint8_t version{ICU_ACCEPTANCE_RECORD_VERSION};
    uint8_t mode{1};                  // assets::IcuAcceptanceMode (1=acknowledge, 2=return)
    uint16_t flags{0};                // reserved (0)
    uint256 asset_id;
    uint256 icu_plain_commit;         // the accepted canonical document hash
    uint256 holder_prevout_txid;      // the asset UTXO the holder controls (binds the acceptor)
    uint32_t holder_prevout_vout{0};
    uint256 holder_spk_hash;          // SHA256(prevout scriptPubKey): binds to the exact holder output
    uint64_t accepted_units{0};       // cross-checked against the prevout's asset amount
    uint8_t sig_scheme{static_cast<uint8_t>(IcuAcceptSigScheme::NONE)};
    std::vector<std::array<unsigned char, 32>> body_refs;  // affirmed body keys (raw digests), sorted; empty = whole-doc
    std::vector<unsigned char> sig;   // SECP_SCHNORR_RAW: 64-byte Schnorr; SECP_BIP322_HASH: 32-byte H(proof); NONE: empty

    // Serialize the record payload (the bytes carried INSIDE the 0x40 TLV). Deterministic, little-endian.
    std::vector<unsigned char> SerializePayload() const;
    // Parse a record payload. Returns nullopt on any malformed/trailing-byte input (fail-closed).
    static std::optional<IcuAcceptanceRecord> ParsePayload(const std::vector<unsigned char>& payload);
};

// Semantic validity (beyond structural parse): mode in {acknowledge,return}; reserved flags zero;
// known sig_scheme with a scheme-appropriate signature length; body_refs strictly ascending (sorted +
// unique); RETURN carries no body_refs; required hashes non-null; accepted_units > 0. ParsePayload /
// ParseIcuAcceptanceTLV call this and return nullopt on failure, so consensus (which accepts a 0x40
// vExt iff it parses) only ever accepts well-formed records. `reason` is set on failure.
bool ValidateIcuAcceptanceRecord(const IcuAcceptanceRecord& rec, std::string& reason);

// Wrap a record as a full vExt TLV: 0x40 | CompactSize(payload_len) | payload.
std::vector<unsigned char> BuildIcuAcceptanceTLV(const IcuAcceptanceRecord& rec);
// Parse a full vExt TLV; nullopt unless it is a well-formed type-0x40 record (exact length, no trailer).
std::optional<IcuAcceptanceRecord> ParseIcuAcceptanceTLV(const std::vector<unsigned char>& vext);

// The TSC-ICU-ACCEPTANCE-RECORD-1 signing message: a deterministic, domain-separated string binding
// EVERY record field except the signature (version, mode, flags, asset_id, icu_plain_commit, holder
// prevout + spk hash, accepted_units, sig_scheme, body_refs). The holder signs THIS, so the signature
// commits to the exact prevout / units / scheme / document / clause set -- it cannot be lifted onto a
// different record. Read-layer per scheme: SECP_SCHNORR_RAW -> BIP-340 verify over a TaggedHash of this
// message against the taproot output key in the prevout spk; SECP_BIP322_HASH -> the revealed BIP-322
// proof must verify over this message AND hash to rec.sig.
std::string IcuAcceptanceRecordSigningMessage(const IcuAcceptanceRecord& rec);

// The 32-byte hash a SECP_SCHNORR_RAW signature is made over:
// TaggedHash("TSC-ICU-ACCEPTANCE-RECORD-1", IcuAcceptanceRecordSigningMessage(rec)). Both the wallet
// create-path signer and the read-layer verifier use this exact value.
uint256 IcuAcceptanceRecordSigningHash(const IcuAcceptanceRecord& rec);

// Read-layer verify for SECP_SCHNORR_RAW: BIP-340 verify rec.sig against `output_key` over
// IcuAcceptanceRecordSigningHash(rec). `output_key` is the x-only taproot output key the caller extracts
// from the holder prevout's scriptPubKey (after checking SHA256(spk) == rec.holder_spk_hash). Returns
// false unless sig_scheme == SECP_SCHNORR_RAW with a 64-byte signature.
bool VerifyIcuAcceptanceRecordSchnorr(const IcuAcceptanceRecord& rec, const XOnlyPubKey& output_key);

// Check body_refs against the committed ICU context's designated-clause set (raw-digest hex keys).
// has_context=false => the asset has no clause context, so body_refs must be empty. required=true =>
// EVERY designated clause must be affirmed; otherwise a subset (incl. empty) is allowed. Returns false
// with `reason` on violation. NOTE: readability is the caller's concern -- a context-bearing asset whose
// payload cannot be read must be failed by the caller; this validates only against a KNOWN designated set.
bool CheckIcuBodyRefsAgainstContext(const std::vector<std::array<unsigned char, 32>>& body_refs,
                                    bool has_context, const std::set<std::string>& designated_hex,
                                    bool required, std::string& reason);

// SECP_BIP322_HASH commit-reveal check: SHA256(revealed_proof) == rec.sig (the on-chain commitment).
// The BIP-322 validity of revealed_proof against the now-revealed holder key is checked separately by
// the caller (RPC) via the BIP-322 verifier over IcuAcceptanceRecordSigningMessage().
bool VerifyIcuAcceptanceCommit(const IcuAcceptanceRecord& rec, const std::vector<unsigned char>& revealed_proof);

// SHA256(scriptPubKey bytes): the holder_spk_hash binding. Both the wallet create-path and the
// read-layer verifier hash the prevout scriptPubKey exactly this way to bind a record to the precise
// holder output.
uint256 IcuHolderSpkHash(const CScript& script);

// Extract the x-only taproot output key from a holder scriptPubKey, or nullopt if `spk` is not a
// (v1 or v2) taproot output. `type` is set to the solved TxoutType. Used by the read-layer verifier
// to recover the key a SECP_SCHNORR_RAW record is verified against.
std::optional<XOnlyPubKey> ExtractTaprootOutputKeyFromSpk(const CScript& spk, TxoutType& type);

} // namespace assets

#endif // BITCOIN_ASSETS_ICU_ACCEPTANCE_RECORD_H
