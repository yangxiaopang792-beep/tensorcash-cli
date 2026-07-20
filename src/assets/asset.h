// Minimal asset TLV parsing and helpers for per-output extensions

#ifndef BITCOIN_ASSETS_ASSET_H
#define BITCOIN_ASSETS_ASSET_H

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <uint256.h>

namespace assets {

enum class OutExtType : uint8_t {
    ASSET_TAG        = 0x01,
    ISSUER_REG       = 0x10,
    ISSUER_SCALAR    = 0x11,  // dedicated scalar-feed publication carrier (CFD_GENERALISATION.md §3.1)
    ZK_PARAMS_CHUNK  = 0x20,
    TFR_ANCHOR       = 0x21,
    ZK_PROOF_PAYLOAD = 0x22,  // Groth16 proof + public inputs transported via output TLV
    ICU_TEXT_CHUNK   = 0x30,
    ICU_KEYWRAP      = 0x31,
};

struct AssetTag {
    uint256 id;       // asset_id (raw 32 bytes)
    uint64_t amount;  // units
    uint32_t flags{0};
    bool has_epoch{false};
    uint8_t epoch{0};

    // Optional proposal_hash for governance rotation ballot binding
    bool has_proposal_hash{false};
    uint256 proposal_hash;

    // Optional ICU_KEYWRAP sub-TLV (type 0x03)
    bool has_keywrap{false};
    uint256 keywrap_asset_id;
    uint256 keywrap_ctxt_hash;
    uint256 keywrap_spk_hash32;
    std::string keywrap_wrapped_key;
    uint8_t keywrap_suite_id{0};
    uint8_t keywrap_extras_mask{0};
    bool keywrap_has_wrap_commit{false};
    uint256 keywrap_wrap_commit;
    bool keywrap_has_kc_tag{false};
    std::array<unsigned char, 16> keywrap_kc_tag{};
};

struct IcuChunkMetadata {
    uint8_t version{1};
    uint8_t compression{0};
    uint8_t encryption_mode{0};
    bool has_witness_hash{false};
    uint256 witness_hash;

    IcuChunkMetadata() { witness_hash.SetNull(); }
};

struct IssuerReg {
    uint256 asset_id;
    uint32_t policy_bits{0};
    uint16_t allowed_spk_families{0};
    uint8_t format_version{1}; // 0x01 = v1 (ZK+ICU unified format)

    // Optional ticker (variable length)
    std::string ticker; // uppercase ASCII [A-Z0-9], 3..11, first char A-Z (empty = not set)

    // Optional decimals (0xFF = not set)
    uint8_t decimals{0xFF};

    // Optional unlock fees (0xFFFFFFFFFFFFFFFF = not set)
    uint64_t unlock_fees_sats{std::numeric_limits<uint64_t>::max()};

    // ZK section (always present in v1, zeroed if unused)
    uint32_t kyc_flags{0};
    uint256 zk_vk_commitment; // all zeros = not set
    uint32_t max_root_age{0};
    uint32_t tfr_flags{0};

    // Compliance root commitment (ZK Whitelist Hardening - added 2025-10-20)
    // Legacy (4-input circuits): 28 bytes Merkle root || 4 bytes big-endian capture height
    // HDv1 (6-input circuits):   pure 32-byte MiMC Merkle root (freshness via compliance_root_history)
    // Zero = not set (issuer has not committed a compliance root)
    uint256 compliance_root_commit;

    // ICU section (always present in v1)
    uint32_t icu_flags{0};
    uint64_t issuance_cap_units{0};
    uint256 icu_ctxt_commit;
    uint256 icu_plain_commit;
    std::array<unsigned char, 16> kdf_salt{};
    uint8_t icu_version{0};
    uint8_t icu_visibility{0};
    uint256 core_policy_commit;
    uint8_t policy_epoch{0};
    uint16_t policy_quorum_bps{0};

    // v2 only: delegation pointer (null = self / v1). Reusable/delegated KYC.
    uint256 compliance_delegate_asset_id;
};

// Parse a single-TLV container from vExt; returns std::nullopt on parse error or unknown type
std::optional<AssetTag> ParseAssetTag(const std::vector<unsigned char>& vext);
std::optional<IssuerReg> ParseIssuerReg(const std::vector<unsigned char>& vext);

struct IcuTextChunk {
    std::vector<unsigned char> payload;      // Raw ICU bytes (opaque to consensus)
    std::optional<IcuChunkMetadata> metadata; // Optional metadata trailer (compression/encryption/witness hash)
};

struct IcuKeywrap {
    uint256 asset_id;
    uint256 ctxt_hash;
    uint256 spk_hash32;
    std::string wrapped_key;                 // UTF-8 armored payload
    uint8_t suite_id{0};
    uint8_t extras_mask{0};
    bool has_wrap_commit{false};
    uint256 wrap_commit;
    bool has_kc_tag{false};
    std::array<unsigned char, 16> kc_tag{};
};

struct ZkParamsChunk {
    uint256 asset_id;
    uint256 vk_hash;
    uint16_t chunk_index{0};
    uint16_t chunk_count{0};
    std::vector<unsigned char> data;
};

struct TfrAnchor {
    uint256 asset_id;
    uint256 tfr_commit;
    uint32_t keyset_id{0};
    std::vector<unsigned char> locator;
};

// ZK_PROOF_PAYLOAD (type 0x22): Transports Groth16 proof + public inputs via output TLV.
//
// Proof transport model:
// - One ZK_PROOF_PAYLOAD per asset spend (matched by asset_id)
// - Witness stack contains only standard spend elements (signature + pubkey)
// - Sighash enforcement ensures outputs cannot be rebound after signature
//
// Security: asset_id binding prevents proof reuse across different assets
//
// Public input layouts:
//   Legacy (4 inputs, 128 bytes):
//     [0] = chain separator
//     [1] = asset_id (BE)
//     [2] = compliance_root || height (28 + 4 bytes packed)
//     [3] = tfr_commit (or zero)
//
//   HDv1 (6 inputs, 192 bytes):
//     [0] = chain separator
//     [1] = asset_id (BE)
//     [2] = compliance_root (pure 32-byte MiMC root; freshness via on-chain history)
//     [3] = tfr_commit (or zero)
//     [4] = output_key_high (upper 128 bits of child x-only key, left-padded to 32 bytes)
//     [5] = output_key_low  (lower 128 bits of child x-only key, left-padded to 32 bytes)
struct ZkProofPayload {
    uint256 asset_id;                    // Guard against misbinding (must match AssetTag)
    std::vector<unsigned char> proof;    // Groth16 proof: 192 bytes (compressed A||B||C)
    std::vector<unsigned char> public_inputs; // Public inputs: N × 32 bytes (see layouts above)
};

std::optional<ZkParamsChunk> ParseZkParamsChunk(const std::vector<unsigned char>& vext);
std::optional<TfrAnchor> ParseTfrAnchor(const std::vector<unsigned char>& vext);
std::optional<ZkProofPayload> ParseZkProofPayload(const std::vector<unsigned char>& vext);
std::optional<IcuTextChunk> ParseIcuTextChunk(const std::vector<unsigned char>& vext);
std::optional<IcuKeywrap> ParseIcuKeywrap(const std::vector<unsigned char>& vext);

// ZK chunk assembly and DoS mitigation limits
static constexpr size_t MAX_ZK_CHUNKS          = 8;
static constexpr size_t MAX_ZK_CHUNK_SIZE      = 512;
static constexpr size_t MAX_VK_PAYLOAD_SIZE    = MAX_ZK_CHUNKS * MAX_ZK_CHUNK_SIZE;
static constexpr size_t MAX_TFR_LOCATOR_SIZE   = 128;
static constexpr size_t MAX_ZK_PROOFS_PER_TX   = 2;
static constexpr size_t MAX_ZK_PROOFS_PER_BLOCK = 400;

// ZK_PROOF_PAYLOAD size limits (Groth16 BLS12-381 compressed format)
static constexpr size_t GROTH16_PROOF_SIZE       = 192;  // 48 (A) + 96 (B) + 48 (C)
static constexpr size_t GROTH16_FR_SIZE          = 32;   // Field element size
static constexpr size_t GROTH16_MIN_PUBLIC_INPUTS = 4;   // chain, asset, root, anchor (legacy minimum)
static constexpr size_t GROTH16_MAX_PUBLIC_INPUTS_SIZE = 256; // Maximum public inputs bytes (8 × 32)
static constexpr size_t GROTH16_HDV1_PUBLIC_INPUTS = 6;  // chain, asset, root, anchor, key_high, key_low

// ICU payload limits (raw bytes stored in a single TLV)
static constexpr size_t MAX_ICU_PAYLOAD_BYTES  = 100 * 1024;

// ICU keywrap limits
static constexpr size_t MAX_ICU_KEYWRAP_WRAPPED_KEY_BYTES = 512;
static constexpr size_t MAX_ICU_KEYWRAP_VEXT_BYTES = 700;
static constexpr uint8_t ICU_KEYWRAP_EXTRA_WRAP_COMMIT = 0x01;
static constexpr uint8_t ICU_KEYWRAP_EXTRA_KC_TAG     = 0x02;
static constexpr size_t ICU_KEYWRAP_KC_TAG_SIZE       = 16;

// ICU defaults
static constexpr uint8_t ICU_VERSION_V1 = 1;

// IssuerReg format versions
static constexpr uint8_t ISSUER_REG_FORMAT_V1 = 1;
// v2 == v1 wire layout plus a trailing 32-byte compliance_delegate_asset_id
// (reusable/delegated KYC). A v2 reg MUST carry a non-null delegate; a delegate
// equal to the asset's OWN id is the opt-out sentinel (clear delegation). A v1
// reg leaves delegation unchanged (preserves the prior delegate). See REUSABLE_KYC.md.
static constexpr uint8_t ISSUER_REG_FORMAT_V2 = 2;
static constexpr uint64_t UNLOCK_BUMP_MIN_DEFAULT = 50'000'000ULL;

// --- Ticker grammar (ICU_CHILD.md §3.1, §5.1) ---
// These are the single source of truth for ticker acceptance, shared by the consensus
// parser (ParseIssuerRegV1) and the client-side RPC checks. Do not re-implement ticker
// grammar ad hoc elsewhere.
//
// Root ticker: [A-Z][A-Z0-9]{2,10} — 3..11 bytes, uppercase, first char a letter, no dot.
bool IsRootTicker(std::string_view t);

// One-hop child ticker ROOT.SUFFIX: exactly one '.', both sides valid root tickers.
// Suffix intentionally uses the same 3..11 root grammar (so ACME.C1 is invalid).
struct ChildTicker { std::string root; std::string suffix; };
std::optional<ChildTicker> ParseChildTicker(std::string_view t);

// The single grammar gate for a non-empty IssuerReg ticker: a bare root OR a one-hop
// child. Empty is rejected here — callers treat "no ticker" separately. Carries no
// block-height context; any activation-aware accept/reject lives in validation.cpp
// (ICU_CHILD.md §5.1).
bool IsTickerValidForIssuerReg(std::string_view t);

// Script families mask bits
enum SpkFamily : uint16_t {
    SPK_P2PKH   = 1 << 0,
    SPK_P2SH    = 1 << 1,
    SPK_P2WPKH  = 1 << 2,
    SPK_P2WSH   = 1 << 3,
    SPK_P2TR    = 1 << 4, // witness v1 Taproot (secp key/script path)
    SPK_P2TR_V2 = 1 << 5, // witness v2 Taproot (PQ / ML-DSA tapscript-only)
};

static constexpr uint16_t SPK_HOLDER_ONLY = SPK_P2PKH | SPK_P2WPKH;
// Default excludes P2SH and PQ(v2). PQ is opt-in per asset: the wallet wrap/decrypt
// path must support v2, and for KYC assets a PQ/KYC address binding must exist first.
// Issuers enable PQ by adding SPK_P2TR_V2 to allowed_spk_families.
static constexpr uint16_t SPK_DEFAULT_ALLOWED = SPK_P2WPKH | SPK_P2WSH | SPK_P2TR;

// True iff a registration illegally mixes KYC with PQ (witness-v2) families.
//
// KYC is signalled by reg.kyc_flags != 0 — NOT the KYC_REQUIRED policy bit (see
// validation.cpp's kyc_enabled). Taking the whole IssuerReg (rather than a bare
// uint32_t) prevents a caller from accidentally passing policy_bits: both fields are
// uint32_t, so an integer parameter would not catch that mistake. `resolved_families`
// is the post-default mask (allowed_spk_families or the joint/default fallback).
// KYC holders are v1-Taproot-only (HDv1 binding), so PQ families would freeze them.
inline bool KycPqFamilyConflict(const IssuerReg& reg, uint16_t resolved_families)
{
    return reg.kyc_flags != 0 && (resolved_families & SPK_P2TR_V2) != 0;
}

// Policy bit constants for clarity
static constexpr uint32_t MINT_ALLOWED        = 0x0001u;
static constexpr uint32_t BURN_ALLOWED        = 0x0002u;
static constexpr uint32_t BURN_REQUIRE_ICU    = 0x0004u;
static constexpr uint32_t BURN_JOINT_REQUIRED = 0x0008u;
static constexpr uint32_t KYC_REQUIRED        = 0x0010u;
static constexpr uint32_t TFR_ANCHOR_REQUIRED = 0x0020u;
// Opt-in "collateral-safe" bit (CFD_GENERALISATION.md §5.1). An asset carrying it promises its
// settlement-relevant policy is frozen so a long-dated OP_SCALAR_CFD_SETTLE note collateralised in
// it can always settle (no drift into KYC/TFR/WRAP_REQUIRED after a vault is created).
//
// IMPORTANTLY this bit is DELIBERATELY NOT in POLICY_BITS_IMMUTABLE_MASK / core_policy_commit. The
// core-policy commit is computed unconditionally at every registration; folding the bit in there
// would retroactively change registry state the instant the binary ships — BEFORE the claimed
// ScalarCfdHeight — so a pre-activation registration carrying 0x40 would diverge upgraded vs
// un-upgraded nodes. Instead its immutability is enforced by a HEIGHT-GATED ConnectBlock rule
// (IsCollateralSafeRotationRejected, validation.cpp): below ScalarCfdHeight 0x40 is an ordinary
// ignored policy bit (identical state on every binary); at/above it the bit itself AND the asset's
// icu_flags are frozen. Vaults exist only post-activation, so the liveness guarantee still holds.
static constexpr uint32_t COLLATERAL_SAFE     = 0x0040u;

// Immutable policy bits mask (all bits affecting spend semantics). COLLATERAL_SAFE is intentionally
// EXCLUDED (see above) — its immutability is a separate height-gated rule, not a commit fold.
static constexpr uint32_t POLICY_BITS_IMMUTABLE_MASK =
    MINT_ALLOWED | BURN_ALLOWED | BURN_REQUIRE_ICU | BURN_JOINT_REQUIRED |
    KYC_REQUIRED | TFR_ANCHOR_REQUIRED;

// ICU flags
static constexpr uint32_t WRAP_REQUIRED  = 0x0001u;
static constexpr uint32_t ICU_COMPRESSED = 0x0002u;  // ICU payload uses zstd compression

// Compute core policy commit for immutability enforcement
uint256 ComputeCorePolicyCommit(
    uint16_t allowed_spk_families,
    uint32_t policy_bits,
    uint32_t kyc_flags,
    uint32_t tfr_flags);

// Pure consensus rule (CFD_GENERALISATION.md §5.1): the COLLATERAL_SAFE immutability guard, applied
// on an IssuerReg rotation. Height-gated — INERT below scalar_cfd_height (so 0x40 stays an ordinary
// ignored policy bit pre-activation and the core-policy commit is unchanged on every binary). At/
// above activation it rejects a rotation that either (a) toggles the COLLATERAL_SAFE bit itself
// (added or removed), or (b) changes icu_flags on an asset that carries the bit (WRAP_REQUIRED is
// the drift that would otherwise trap a long-dated note's collateral; icu_flags is the one
// settlement-relevant field not already covered by core_policy_commit). Returns true iff the
// rotation MUST be rejected. Pure helper so ConnectBlock and unit tests share byte-identical logic
// (mirrors CheckScalarPublication). Pass prev/new policy_bits and icu_flags + the activation gate.
bool IsCollateralSafeRotationRejected(uint32_t prev_policy_bits, uint32_t new_policy_bits,
                                      uint32_t prev_icu_flags, uint32_t new_icu_flags,
                                      int height, int scalar_cfd_height);

// Plaintext 2-arg AssetTag TLV: [ASSET_TAG][len][asset_id(32) || amount LE64]. The canonical
// minimal asset tag used by covenant/derivation builders; lives here (bitcoin_common) so non-wallet
// code (the option-series derivation, core verifier) can build it without the wallet library.
// wallet::BuildAssetTagTlv forwards to this.
std::vector<unsigned char> BuildAssetTagTlv(const uint256& asset_id, uint64_t units);

// Governance rotation helpers: build AssetTag with proposal_hash binding
std::vector<unsigned char> BuildAssetTagWithProposal(
    const uint256& asset_id,
    uint64_t amount,
    const uint256& proposal_hash,
    uint32_t flags = 0,
    bool has_epoch = false,
    uint8_t epoch = 0);

inline bool ValidateChunkParams(const ZkParamsChunk& chunk)
{
    if (chunk.chunk_count == 0 || chunk.chunk_count > MAX_ZK_CHUNKS) return false;
    if (chunk.chunk_index >= chunk.chunk_count) return false;
    if (chunk.data.size() > MAX_ZK_CHUNK_SIZE) return false;
    return true;
}

// --- Scalar publication feed (CFD generalisation, CFD_GENERALISATION.md §3) ---
//
// An asset issuer publishes a settlement scalar by spending the asset's current
// ICU and emitting an ISSUER_SCALAR TLV on a SEPARATE carrier output (the ICU
// successor output already carries ISSUER_REG, and vExt holds exactly one TLV).
// ConnectBlock parses this once into the dedicated DB_ASSET_SCALAR index; the
// carrier output is consumed there and its state lives in the index, not the UTXO.
//
// Fixed-width body, no nesting, no JSON:
//   underlying_asset_id : 32   EXPLICIT — must equal an ICU asset spent by this tx
//   feed_id             : u32  which feed of the underlying (LE)
//   scalar_epoch        : u64  monotonic per (asset_id, feed_id); independent of
//                              policy_epoch (which is uint8) (LE)
//   scalar_format_id    : u16  scalar ENCODING only (LE). NOT the payoff mode: a
//                              publication is mode-agnostic. The §4 payoff-mode
//                              selector lives in the settlement contract leaf, which
//                              also commits the expected scalar_format_id and
//                              requires it to equal this published record's value.
//   scalar              : 32   raw 256-bit value, interpreted per scalar_format_id
//                              (reuses the 512-bit settlement math envelope)
struct IssuerScalar {
    uint256  underlying_asset_id;
    uint32_t feed_id{0};
    uint64_t scalar_epoch{0};
    uint16_t scalar_format_id{0};
    uint256  scalar;
};

// Wire size of the fixed-width ISSUER_SCALAR TLV body.
static constexpr size_t ISSUER_SCALAR_BODY_SIZE = 32 + 4 + 8 + 2 + 32; // = 78

// Known scalar formats (ENCODINGS, not payoff modes). The catalogue (CFD_GENERALISATION.md §4/§6,
// Slice 6) blesses byte-order + canonical fixed-width unsigned integers. It deliberately carries NO
// economic scale: the payoff is a ratio λ·|X−K|/denom in which X and K share the SAME format, so any
// implied Q-scale cancels — display scale is a wallet concern (format_id → render), never consensus.
// A publication whose scalar_format_id is not known here is rejected at ConnectBlock; a stored value
// that does not DECODE canonically (see DecodeScalarValue) fails the opcode CLOSED at settlement.
//   *_LE / *_BE  : the stored 32 bytes are read little-endian / big-endian.
//   RAW_U256_*   : full-width 256-bit unsigned; every 32-byte value is canonical (no padding).
//   U64_* / U128_*: fixed-width unsigned, zero-extended to 32 bytes; the unused (high) bytes MUST be
//                   zero (DecodeScalarValue rejects a non-canonical width), bounding the value range.
static constexpr uint16_t SCALAR_FORMAT_RAW_U256_LE = 0x0001;
static constexpr uint16_t SCALAR_FORMAT_RAW_U256_BE = 0x0002;
static constexpr uint16_t SCALAR_FORMAT_U64_LE      = 0x0010;
static constexpr uint16_t SCALAR_FORMAT_U64_BE      = 0x0011;
static constexpr uint16_t SCALAR_FORMAT_U128_LE     = 0x0012;
static constexpr uint16_t SCALAR_FORMAT_U128_BE     = 0x0013;
inline bool IsKnownScalarFormat(uint16_t scalar_format_id)
{
    switch (scalar_format_id) {
    case SCALAR_FORMAT_RAW_U256_LE:
    case SCALAR_FORMAT_RAW_U256_BE:
    case SCALAR_FORMAT_U64_LE:
    case SCALAR_FORMAT_U64_BE:
    case SCALAR_FORMAT_U128_LE:
    case SCALAR_FORMAT_U128_BE:
        return true;
    default:
        return false;
    }
}

// Parse / build the single-TLV ISSUER_SCALAR container. The parser is purely
// STRUCTURAL: it returns the fields iff the bytes are a well-framed, exactly
// 78-byte ISSUER_SCALAR TLV, and performs no semantic checks (non-null asset id,
// known scalar_format_id, monotonic epoch, matching ICU input) — those live in
// ConnectBlock publication validation (§3.3).
std::optional<IssuerScalar> ParseIssuerScalar(const std::vector<unsigned char>& vext);
std::vector<unsigned char> BuildIssuerScalarTlv(const IssuerScalar& s);

// Result of the scalar-publication consensus rule check (CFD_GENERALISATION.md §3.3).
enum class ScalarPubStatus {
    Ok,
    BadFormat,        // unknown scalar_format_id
    NonCanonical,     // value not canonical for the format (e.g. a fixed-width format with non-zero padding)
    CarrierSpendable, // carrier output scriptPubKey is not provably unspendable (would bloat UTXO set)
    UnknownAsset,     // underlying_asset_id is not a registered asset
    NoIcuAuth,        // tx did not spend the underlying's CURRENT ICU (issuer auth)
    ZeroEpoch,        // epoch 0 is reserved/invalid (first real epoch is 1)
    EpochOverflow,    // head_last_epoch == UINT64_MAX, so last+1 would wrap
    NonMonotonic,     // epoch != head_last_epoch+1 (or != 1 when no head exists)
    DuplicateEpoch,   // (asset, feed, epoch) already published — publications are immutable
};

// Pure publication rule check. All chain/tx context is reduced to scalars/booleans
// by the caller, so this is unit-testable in isolation and byte-identical between
// ConnectBlock and the mempool. Checks run in a fixed, deterministic order; the
// FIRST failure wins. `carrier_unspendable` is scriptPubKey.IsUnspendable() of the
// carrier output; `icu_authenticated` is "this tx spent the underlying's current
// ICU" computed against PRE-tx state (the spent ICU, not a staged successor).
// `scalar` is rejected (NonCanonical) if it does not DECODE canonically under
// `scalar_format_id` — i.e. exactly the bytes the settlement opcode can later read.
// Publishing a non-canonical value would otherwise stage a "real" fixing that the
// opcode rejects at settlement, bricking the contract (fallback never fires because
// an in-time real fixing pre-empts it).
ScalarPubStatus CheckScalarPublication(
    uint16_t scalar_format_id,
    const uint256& scalar,
    uint64_t scalar_epoch,
    bool carrier_unspendable,
    bool underlying_registered,
    bool icu_authenticated,
    bool head_exists,
    uint64_t head_last_epoch,
    bool epoch_exists);

// Stable reject-reason token for a non-Ok status (used as the BlockValidationState
// / TxValidationState reject reason, e.g. "scalar-nonmonotonic").
const char* ScalarPubStatusString(ScalarPubStatus status);

} // namespace assets

#endif // BITCOIN_ASSETS_ASSET_H
