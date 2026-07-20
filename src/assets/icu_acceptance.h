// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSETS_ICU_ACCEPTANCE_H
#define BITCOIN_ASSETS_ICU_ACCEPTANCE_H

#include <uint256.h>

#include <algorithm>
#include <string>
#include <vector>

namespace assets {

// ICU acceptance binds to the canonical TERMS DOCUMENT, not to per-clause selections.
// The on-chain anchor is the document hash itself -- the asset registry's
// icu_plain_commit (= SHA256(canonical_text)) -- carried verbatim in an OP_RETURN.
// There is no bespoke commitment serializer: accepting the document hash is accepting
// the whole document. Onerous-term notice is a UX/legal-evidence matter, not a field.

// Domain tag for the holder's acceptance signature (the BIP-322 message). Bumping this
// changes how the message is reconstructed and so invalidates prior signatures.
inline constexpr const char* ICU_ACCEPTANCE_MSG_TAG = "TSC-ICU-DOC-ACCEPT-1";

enum class IcuAcceptanceMode : uint8_t {
    ACKNOWLEDGE = 1,  // holder keeps the asset; attribution via BIP-322 over the message
    RETURN = 2,       // holder relinquishes the asset to the issuer; attribution via the spend
};

inline const char* IcuAcceptanceModeName(IcuAcceptanceMode m)
{
    return m == IcuAcceptanceMode::ACKNOWLEDGE ? "acknowledge" : "return";
}

// The message the holder signs (BIP-322) to attribute an acknowledgment to their share
// address. The on-chain anchor is the document hash; this message binds that hash to the
// specific asset, holder and mode so a signature cannot be replayed in another context.
// The issuer is deliberately NOT included: asset_id already pins the issuer, and leaving
// it out keeps an acknowledgment verifiable across an issuer ICU *address* rotation (the
// document hash is unchanged). A *terms amendment* changes the document hash and so
// correctly invalidates the old acceptance. Plain pipe-delimited: every field is
// fixed-shape (hex hashes, a mode word, a bech32 address) and contains no '|', so it is
// unambiguous without a length-prefixed codec. RETURN does not use this -- the asset-input
// spend attributes the holder there.
//
// SCOPE: this signature is an off-chain sidecar. It is not in consensus and is NOT bound
// to the acknowledgment tx's txid, so the on-chain confirmation timestamps only when a
// document-hash anchor was mined, not when the holder signed. That suffices for "the
// document hash was anchored on-chain; the signature proves the holder accepted it." If
// signing-time must be cryptographically bound, add the txid here or use an asset self-spend.
inline std::string BuildAcceptanceMessage(
    IcuAcceptanceMode mode,
    const uint256& asset_id,
    const uint256& canonical_hash,
    const std::string& holder_address)
{
    return std::string(ICU_ACCEPTANCE_MSG_TAG) + "|" +
           asset_id.ToString() + "|" +
           IcuAcceptanceModeName(mode) + "|" +
           canonical_hash.ToString() + "|" +
           holder_address;
}

// --- Context-aware acceptance: TSC-ICU-DOC-ACCEPT-2 (acknowledge only) -------------------
// See legal/company/TSC_ICU_CONTEXT_ACCEPTANCE.md §4.2. Used only for assets that carry a
// committed TSC-ICU-CONTEXT-1 map. The holder BIP-322-signs this message to affirm a set of
// subdocuments (body keys). context_hash (SHA256 of the committed context metadata) is bound in
// because the map lives OUTSIDE canonical_hash; it is STABLE across benign re-encryption/re-key
// (the metadata bytes are preserved) and changes only if the committed map changes -- unlike the
// ciphertext commitment, which also moves on any re-encryption. There is no RETURN variant --
// subdoc affirmation is an acknowledge act; RETURN stays on ACCEPT-1.
inline constexpr const char* ICU_ACCEPTANCE_MSG_TAG_V2 = "TSC-ICU-DOC-ACCEPT-2";

// body_hashes are body keys in raw-digest hex (HexStr(SHA256(blob)) per the context spec --
// NOT uint256/display order). They are sorted here so prepare and verify are order-independent
// and produce byte-identical messages from the same affirmed set.
inline std::string BuildAcceptanceMessageV2(
    const uint256& asset_id,
    const uint256& canonical_hash,
    const uint256& context_hash,
    const std::string& holder_address,
    std::vector<std::string> body_hashes)
{
    std::sort(body_hashes.begin(), body_hashes.end());
    std::string msg = std::string(ICU_ACCEPTANCE_MSG_TAG_V2) + "|" +
                      asset_id.ToString() + "|" +
                      "acknowledge" + "|" +
                      canonical_hash.ToString() + "|" +
                      context_hash.ToString() + "|" +
                      holder_address;
    for (const std::string& h : body_hashes) {
        msg += "|" + h;
    }
    return msg;
}

// --- Unified acceptance: TSC-ICU-DOC-ACCEPT-3 (Option A / inline-context assets) ----------------
// For assets whose context map lives INSIDE canonical_text (committed under icu_plain_commit), the
// document hash already moves whenever any clause changes, so a separate context_hash is redundant
// -- it is dropped. One message covers both whole-document acknowledge/return and sub-body
// affirmation: sorted body_refs carry which clauses the holder affirms (empty => whole document;
// always empty for RETURN, where the asset-input spend attributes the holder).
//
// This is a NEW domain tag, not a re-layout of ACCEPT-1/ACCEPT-2: reusing a tag with a different
// field count would be a parser-bifurcation surface. body_refs are body keys in raw-digest hex
// (HexStr(SHA256(normalized clause)) per the context spec), sorted so prepare and verify produce
// byte-identical messages from the same affirmed set. ACCEPT-1/ACCEPT-2 remain ONLY for legacy v1
// (metadata-context / text-only) assets; an inline-context asset MUST NOT be accepted through them.
inline constexpr const char* ICU_ACCEPTANCE_MSG_TAG_V3 = "TSC-ICU-DOC-ACCEPT-3";

inline std::string BuildAcceptanceMessageV3(
    IcuAcceptanceMode mode,
    const uint256& asset_id,
    const uint256& icu_plain_commit,
    const std::string& holder_address,
    std::vector<std::string> body_refs)
{
    std::sort(body_refs.begin(), body_refs.end());
    std::string msg = std::string(ICU_ACCEPTANCE_MSG_TAG_V3) + "|" +
                      asset_id.ToString() + "|" +
                      IcuAcceptanceModeName(mode) + "|" +
                      icu_plain_commit.ToString() + "|" +
                      holder_address;
    for (const std::string& h : body_refs) {
        msg += "|" + h;
    }
    return msg;
}

} // namespace assets

#endif // BITCOIN_ASSETS_ICU_ACCEPTANCE_H
