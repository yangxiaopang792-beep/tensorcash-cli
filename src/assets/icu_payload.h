// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSETS_ICU_PAYLOAD_H
#define BITCOIN_ASSETS_ICU_PAYLOAD_H

#include <hash.h>
#include <logging.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace assets {

struct IcuChunkMetadata;

/**
 * ICU Storage Entry (LevelDB Metadata)
 *
 * This structure stores ICU payload metadata in LevelDB alongside the raw/encrypted bytes.
 * Allows RPCs to distinguish encrypted from plaintext payloads without guessing parameters.
 *
 * Specification: CONTRACTS_EXTENSION_V2_UNIFIED.md §3.1
 */
struct IcuStorageEntry {
    std::vector<unsigned char> icu_cipher;  // Raw or encrypted/compressed blob
    uint8_t compression{0};                  // 0 = none, 1 = zstd
    uint8_t encryption_mode{0};              // 0 = plaintext, 1 = ChaCha20-Poly1305, 2 = XChaCha20-Poly1305
    uint8_t visibility{0};                   // 0 = public, 1 = holder_only
    uint256 canonical_hash;                  // SHA256(canonical_text) - pre-computed for efficiency
    uint256 witness_hash;                    // SHA256(witness_bundle) - pre-computed for efficiency

    SERIALIZE_METHODS(IcuStorageEntry, obj) {
        READWRITE(obj.icu_cipher);
        READWRITE(obj.compression, obj.encryption_mode, obj.visibility);
        READWRITE(obj.canonical_hash, obj.witness_hash);
    }
};

/**
 * Canonical ICU Payload Structure (RPC Layer Only)
 *
 * This structure is NOT consensus-critical. Consensus only validates raw bytes via
 * icu_ctxt_commit. This structure is used by RPC helpers to build and parse
 * canonical ICU payloads for interoperability (e.g., DocuSign evidence packages).
 *
 * Specification: CONTRACTS_EXTENSION_V2_UNIFIED.md §2.2
 */
struct CanonicalIcuPayload {
    uint8_t version{1};            // Always 1
    uint8_t compression{0};        // 0 = none, 1 = zstd
    uint8_t encryption_mode{0};    // 0 = plaintext, 1 = AES-256-GCM, 2 = XChaCha20-Poly1305
    uint8_t visibility{0};         // 0 = public, 1 = holder_only

    std::vector<unsigned char> canonical_text;   // UTF-8, control-free text with canonical CRLF endings
    std::vector<unsigned char> witness_bundle;   // Arbitrary evidence (DocuSign, PGP, Schnorr, etc.)
    std::vector<unsigned char> metadata;         // Optional future use

    SERIALIZE_METHODS(CanonicalIcuPayload, obj) {
        READWRITE(obj.version, obj.compression, obj.encryption_mode, obj.visibility);
        READWRITE(obj.canonical_text);
        READWRITE(obj.witness_bundle);
        READWRITE(obj.metadata);
    }

    /**
     * Compute canonical_hash = SHA256(canonical_text)
     * This hash must appear in the witness_bundle for RPC validation.
     */
    uint256 GetCanonicalHash() const {
        CSHA256 hasher;
        hasher.Write(canonical_text.data(), canonical_text.size());
        uint256 hash;
        hasher.Finalize(hash.begin());
        return hash;
    }

    /**
     * Compute witness_hash = SHA256(witness_bundle)
     */
    uint256 GetWitnessHash() const {
        CSHA256 hasher;
        hasher.Write(witness_bundle.data(), witness_bundle.size());
        uint256 hash;
        hasher.Finalize(hash.begin());
        return hash;
    }

    /**
     * Serialize to raw bytes (before encryption/compression)
     */
    std::vector<unsigned char> Serialize() const {
        DataStream ss{};
        ss << *this;
        // Convert from std::byte to unsigned char
        std::vector<unsigned char> result;
        result.reserve(ss.size());
        for (size_t i = 0; i < ss.size(); ++i) {
            result.push_back(static_cast<unsigned char>(ss[i]));
        }
        return result;
    }

    /**
     * Deserialize from raw bytes
     */
    static std::optional<CanonicalIcuPayload> Deserialize(const std::vector<unsigned char>& bytes) {
        try {
            // Convert from unsigned char to std::byte for DataStream
            std::vector<std::byte> byte_vec;
            byte_vec.reserve(bytes.size());
            for (unsigned char b : bytes) {
                byte_vec.push_back(static_cast<std::byte>(b));
            }
            DataStream ss{byte_vec};
            CanonicalIcuPayload payload;
            ss >> payload;
            return payload;
        } catch (const std::exception& e) {
            LogPrintf("ERROR: CanonicalIcuPayload::Deserialize failed for %d bytes: %s\n", bytes.size(), e.what());
            return std::nullopt;
        }
    }
};

/**
 * Build canonical ICU payload from RPC inputs (returns IcuStorageEntry)
 *
 * @param canonical_text_str UTF-8 text string (will be normalized)
 * @param witness_obj        UniValue object containing witness bundle (DocuSign, PGP, etc.)
 * @param visibility         0 = public, 1 = holder_only
 * @param dek                32-byte Data Encryption Key (required if visibility=1, ignored if visibility=0)
 * @param use_compression    Enable zstd compression (deterministic, optional)
 * @param[out] icu_plain_commit  SHA256(canonical_text)
 * @param[out] icu_ctxt_commit   SHA256(icu_cipher after encryption/compression)
 * @param[out] kdf_salt          16-byte nonce for encryption (derived from DEK+plaintext or zero for public)
 * @param[out] storage_entry     Complete IcuStorageEntry with metadata for LevelDB
 *
 * @return true if successful, false on error
 */
bool BuildCanonicalIcuPayload(
    const std::string& canonical_text_str,
    const UniValue& witness_obj,
    uint8_t visibility,
    const std::array<unsigned char, 32>& dek,
    bool use_compression,
    uint256& icu_plain_commit,
    uint256& icu_ctxt_commit,
    std::array<unsigned char, 16>& kdf_salt,
    IcuStorageEntry& storage_entry,
    const std::vector<unsigned char>& metadata = {}  // committed in payload, sealed by icu_ctxt_commit; if it carries a TSC-ICU-CONTEXT-1 map it is validated against the text
);

/**
 * Build canonical ICU payload from RPC inputs (legacy interface)
 *
 * @param canonical_text_str UTF-8 text string (will be normalized)
 * @param witness_obj        UniValue object containing witness bundle (DocuSign, PGP, etc.)
 * @param visibility         0 = public, 1 = holder_only
 * @param dek                32-byte Data Encryption Key (required if visibility=1, ignored if visibility=0)
 * @param use_compression    Enable zstd compression (deterministic, optional)
 * @param[out] icu_plain_commit  SHA256(canonical_text)
 * @param[out] icu_ctxt_commit   SHA256(icu_cipher after encryption/compression)
 * @param[out] kdf_salt          16-byte nonce for encryption (derived from DEK+plaintext or zero for public)
 * @param[out] icu_cipher        Final encrypted/compressed blob for storage
 *
 * @return true if successful, false on error
 */
bool BuildCanonicalIcuPayload(
    const std::string& canonical_text_str,
    const UniValue& witness_obj,
    uint8_t visibility,
    const std::array<unsigned char, 32>& dek,
    bool use_compression,
    uint256& icu_plain_commit,
    uint256& icu_ctxt_commit,
    std::array<unsigned char, 16>& kdf_salt,
    std::vector<unsigned char>& icu_cipher,
    const std::vector<unsigned char>& metadata = {}
);

/**
 * Parse canonical ICU payload from raw bytes (decryption/decompression NOT done here)
 *
 * This function assumes the payload is already decrypted and decompressed.
 * For encrypted payloads, caller must decrypt first.
 *
 * @param raw_bytes  Plaintext canonical structure bytes
 * @return Parsed payload or nullopt on error
 */
std::optional<CanonicalIcuPayload> ParseCanonicalIcuPayload(const std::vector<unsigned char>& raw_bytes);

/**
 * Normalize canonical text per spec (§2.2):
 * - Validate UTF-8 and reject control, Unicode non-character, zero-width, and bidirectional
 *   embedding/override/isolate code points (anything that can make displayed bytes diverge
 *   from the committed/hashed bytes)
 * - Canonicalise lone LF to CRLF
 * - Trim trailing ASCII space/tab characters
 *
 * Returns std::nullopt when the input contains disallowed code points.
 */
std::optional<std::string> NormalizeCanonicalText(const std::string& input);

/**
 * Verify witness bundle contains canonical_hash
 *
 * Parses witness_bundle as JSON and checks for "canonical_hash" field.
 *
 * @param witness_bundle  Raw witness bundle bytes
 * @param expected_hash   Expected canonical hash
 * @return true if hash found and matches, false otherwise
 */
bool VerifyWitnessLinkage(const std::vector<unsigned char>& witness_bundle, const uint256& expected_hash);

// --- TSC-ICU-CONTEXT-1 (committed clause/context map) -----------------------------------
// See legal/company/TSC_ICU_CONTEXT_ACCEPTANCE.md. The context map is a JSON object carried
// in the committed CanonicalIcuPayload.metadata (sealed by icu_ctxt_commit); it never alters
// canonical_hash. Each body key is the lowercase hex of SHA256 over the exact normalized
// substring bytes -- HexStr of the raw 32-byte digest, NOT uint256 display/byte-reversed
// order; the wallet/RPC side MUST hash identically.
inline constexpr const char* ICU_CONTEXT_SPEC_V1 = "TSC-ICU-CONTEXT-1";
inline constexpr int ICU_CONTEXT_PARSE_VERSION_MAX = 1;

// Binding mode for ValidateIcuContext:
//  - SubstringV1: legacy. Each body value must be a UNIQUE substring of the canonical text (the
//    v1 model, where the map lived in metadata, OUTSIDE the text hash, so it had to be tied back
//    to the prose somehow).
//  - InlineV2 (Option A): the context block is embedded INSIDE canonical_text and is therefore
//    already covered by icu_plain_commit = SHA256(normalized_canonical_text). The substring/
//    uniqueness binding is neither needed nor correct here (the value also appears verbatim inside
//    the embedded block, so it could never be unique), so it is skipped.
enum class IcuContextBinding { SubstringV1, InlineV2 };

// Inline context block (Option A). The AUTHORITATIVE TSC-ICU-CONTEXT-1 map is serialized as a
// single canonical JSON line wrapped by these delimiters and appended to canonical_text, so the
// existing icu_plain_commit covers every clause and any clause change moves the witnessed document
// hash. CanonicalIcuPayload.metadata is reduced to a non-authoritative marker; readers locate the
// block by scanning canonical_text for these delimiters, never by trusting the marker.
inline constexpr const char* ICU_CONTEXT_BLOCK_BEGIN = "-----BEGIN TSC-ICU-CONTEXT-1-----";
inline constexpr const char* ICU_CONTEXT_BLOCK_END   = "-----END TSC-ICU-CONTEXT-1-----";
inline constexpr const char* ICU_CONTEXT_INLINE_MARKER_JSON = "{\"icu_ctx\":\"inline\"}";

/**
 * Validate a TSC-ICU-CONTEXT-1 context map, fail-closed (spec §3.3):
 *  - meta is an object; spec == ICU_CONTEXT_SPEC_V1; 1 <= parse_version <= max;
 *  - acceptance is "required" or "optional";
 *  - bodies is a non-empty object and, for every (key, value):
 *      key == lowercase_hex(SHA256(value)) and value is a UNIQUE substring of
 *      normalized_canonical (or equals the whole normalized_canonical).
 *
 * @param meta                  Parsed metadata JSON (UniValue).
 * @param normalized_canonical  NormalizeCanonicalText output of the asset's canonical text.
 * @param[out] error            Human-readable reason on failure.
 * @return true iff the map is well-formed and fully bound to the text.
 */
bool ValidateIcuContext(const UniValue& meta, const std::string& normalized_canonical, std::string& error,
                        IcuContextBinding binding = IcuContextBinding::SubstringV1);

/**
 * Serialize a (validated) TSC-ICU-CONTEXT-1 object to canonical single-line JSON bytes:
 * lexicographically sorted keys (top-level and within "bodies"), compact (no insignificant
 * whitespace), RFC 8785-style string escaping, raw NFC UTF-8 for non-ASCII. This is the exact
 * byte form embedded inside canonical_text, so the commitment is reproducible across builders.
 */
std::optional<std::string> SerializeCanonicalIcuContext(const UniValue& meta, std::string& error);

/**
 * General canonical-JSON encoder for ICU metadata bands (TSC-ICU-META-1 and its sub-bands, e.g.
 * TSC-ICU-OPTSERIES-1 / TSC-ICU-TERMSHEET-1 — OPTION_SERIES_FREEZE.md §6.1). Generalizes
 * SerializeCanonicalIcuContext to arbitrary object/array/string/integer/bool/null trees so the
 * committed band bytes are reproducible across implementations (writer AND every verifier):
 *  - object keys sorted lexicographically by byte (recursively), compact separators (no whitespace),
 *  - RFC 8785-style string escaping (raw UTF-8 passthrough; caller supplies NFC-normalized text),
 *  - numbers MUST be canonical decimal integers (^-?(0|[1-9][0-9]*)$, no "-0"): floats / exponents /
 *    NaN / Inf / leading zeros are rejected (fail-closed),
 *  - arrays in source order.
 * Not consensus — a wallet/RPC helper. Returns std::nullopt and sets `error` on any non-canonical
 * number or unsupported value type.
 */
std::optional<std::vector<unsigned char>> CanonicalizeIcuBandJson(const UniValue& v, std::string& error);

/**
 * Compose canonical_text (pre-normalization) for Option A inline context: the human terms body,
 * a blank line, then a delimited TSC-ICU-CONTEXT-1 block built from the ordered clause texts.
 * Each clause is normalized (NormalizeCanonicalText) and keyed by lowercase hex SHA256 of the
 * normalized bytes. Empty/duplicate clauses, a bad acceptance value, or any text containing the
 * delimiters are rejected (fail-closed). BuildCanonicalIcuPayload then normalizes+hashes the
 * returned text, so the embedded block is committed under icu_plain_commit.
 *
 * @param[out] out_context   the canonical context object that was embedded (for echoing to clients)
 * @param[out] out_body_keys ordered body keys (raw-digest hex) for acceptance body_refs
 */
std::optional<std::string> ComposeCanonicalTextWithInlineContext(
    const std::string& human_body,
    const std::vector<std::string>& clause_texts,
    const std::string& acceptance,
    UniValue& out_context,
    std::vector<std::string>& out_body_keys,
    std::string& error);

/**
 * Locate, parse and validate (InlineV2) an embedded TSC-ICU-CONTEXT-1 block inside normalized
 * canonical text. Sets present=false and returns nullopt when no block exists. Sets present=true
 * and returns nullopt with `error` set when a block exists but is malformed/ambiguous (multiple
 * delimiters, bad JSON, failed validation) -- callers MUST fail-closed in that case.
 */
std::optional<UniValue> ExtractInlineIcuContext(const std::string& normalized_canonical_text,
                                                bool& present, std::string& error);

/** True iff metadata is the inline-context marker object {"icu_ctx":"inline"}. Advisory only --
 *  the authoritative signal is the presence of the delimited block in canonical_text. */
bool HasInlineIcuContextMarker(const std::vector<unsigned char>& metadata);

/**
 * Recompute icu_plain_commit = SHA256(NormalizeCanonicalText(payload.canonical_text)) and compare
 * to the declared registry value. This is the recompute-or-refuse gate every reader/holder/witness
 * path MUST apply before treating a decrypted document (and its inline clauses) as authentic:
 * consensus stores the declared icu_plain_commit WITHOUT verifying it, so a non-compliant issuer
 * can declare a hash that does not match its canonical_text.
 */
bool VerifyIcuPlainCommit(const CanonicalIcuPayload& payload, const uint256& declared_plain_commit);

/**
 * Compress data using zstd compression
 *
 * @param input  Plaintext data to compress
 * @param level  Compression level (1-22, default 3)
 * @return Compressed data or nullopt on error
 */
std::optional<std::vector<unsigned char>> CompressZstd(const std::vector<unsigned char>& input, int level = 3);

/**
 * Decompress data using zstd decompression
 *
 * @param input  Compressed data
 * @return Decompressed data or nullopt on error
 */
std::optional<std::vector<unsigned char>> DecompressZstd(const std::vector<unsigned char>& input);

/**
 * Encrypt data using ChaCha20-Poly1305 AEAD
 *
 * @param plaintext  Data to encrypt
 * @param key        32-byte encryption key
 * @param nonce      12-byte nonce (96-bit)
 * @param aad        Additional authenticated data (can be empty)
 * @return Encrypted data (ciphertext + 16-byte Poly1305 tag) or nullopt on error
 */
std::optional<std::vector<unsigned char>> EncryptChaCha20Poly1305(
    const std::vector<unsigned char>& plaintext,
    const std::array<unsigned char, 32>& key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad = {}
);

/**
 * Decrypt data using ChaCha20-Poly1305 AEAD
 *
 * @param ciphertext  Encrypted data (ciphertext + 16-byte Poly1305 tag)
 * @param key         32-byte encryption key
 * @param nonce       12-byte nonce (96-bit)
 * @param aad         Additional authenticated data (must match encryption)
 * @return Decrypted plaintext or nullopt on authentication failure
 */
std::optional<std::vector<unsigned char>> DecryptChaCha20Poly1305(
    const std::vector<unsigned char>& ciphertext,
    const std::array<unsigned char, 32>& key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad = {}
);

/**
 * Decrypt canonical ICU payload from raw encrypted/compressed bytes
 *
 * @param icu_cipher  Encrypted/compressed ICU payload
 * @param dek         32-byte Data Encryption Key (unwrapped from ICU_KEYWRAP by wallet)
 * @param kdf_salt    16-byte nonce used during encryption
 * @param encryption_mode  0=plaintext, 1=ChaCha20-Poly1305, 2=XChaCha20-Poly1305
 * @param compression  0=none, 1=zstd
 * @return Decrypted canonical payload or nullopt on error
 */
std::optional<CanonicalIcuPayload> DecryptCanonicalIcuPayload(
    const std::vector<unsigned char>& icu_cipher,
    const std::array<unsigned char, 32>& dek,
    const std::array<unsigned char, 16>& kdf_salt,
    uint8_t encryption_mode,
    uint8_t compression
);

/**
 * Append metadata trailer to an ICU payload for inclusion in ICU_TEXT_CHUNK.
 *
 * @param payload   Raw canonical/plaintext or encrypted ICU payload bytes
 * @param metadata  Compression/encryption parameters and optional witness hash
 * @return Payload with metadata trailer appended
 */
std::vector<unsigned char> AppendIcuChunkMetadata(
    const std::vector<unsigned char>& payload,
    const IcuChunkMetadata& metadata
);

/**
 * Attempt to strip metadata trailer from an ICU payload.
 *
 * @param payload   In/out payload bytes. On success, resized to remove trailer.
 * @param[out] metadata Filled with parsed metadata on success
 * @return true if metadata trailer was found and stripped, false otherwise
 */
bool StripIcuChunkMetadata(
    std::vector<unsigned char>& payload,
    IcuChunkMetadata& metadata
);

} // namespace assets

#endif // BITCOIN_ASSETS_ICU_PAYLOAD_H
