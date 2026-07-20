// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCALAR_NOTE_PAIR_H
#define BITCOIN_WALLET_SCALAR_NOTE_PAIR_H

// Scalar note-pair securitisation — pure derivation core (CFD_GENERALISATION.md §6, Slice 5a).
//
// Generalises the single-sided, native-only option-series tokenizer (wallet/option_series.{h,cpp})
// into a TWO-sided, asset-C-collateralised "scalar note pair": one OP_SCALAR_CFD_SETTLE vault per lot
// whose two settlement keys are BOTH pots (§6.1 — #vaults = #ramps; a capped spread is ONE vault with
// a long pot and a short pot, not two vaults). The long pot redeems token L, the short pot redeems
// token S. This file owns:
//   - the canonical §2.2 settle-leaf builder `BuildScalarCfdLeaf` (the exact inverse of the consensus
//     parser `ParseScalarCfdLeaf`; round-tripped in the unit tests so wallet and consensus cannot drift);
//   - the immutable note-pair descriptor (the committed §2.2 leaf economics shared across all lots, plus
//     the two token ids L/S and the lot count N), its tagged-hash id, and the per-lot derivations
//     (salt / two sinks / two pots / settle leaf).
// Everything here is PURE (no wallet/UTXO state) and deterministic from the descriptor, so it doubles
// as the reference generator. The unwind leaf and the final {settle, unwind} vault taptree are added in
// Slice 5d; issuance/redemption builders in 5b/5c; the RPC param layer in 5e.

#include <consensus/scalar_cfd_leaf.h> // ScalarCfdLeaf, SCALAR_CFD_TEMPLATE_VERSION_V1, enums
#include <primitives/transaction.h>   // COutPoint
#include <pubkey.h>
#include <script/script.h>
#include <script/signingprovider.h> // TaprootBuilder
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace wallet {

//! BIP340 tagged-hash domains (mirrors the option-series tag scheme). The id tag names a FIXED v1
//! scheme; the descriptor's first byte IS descriptor_version, so future versions differ in length and
//! the hashed preimages can never collide — the id tag is not bumped per descriptor_version.
inline constexpr char SCALAR_NOTE_PAIR_ID_TAG[]       = "TSC-ScalarNotePair/v1";
inline constexpr char SCALAR_NOTE_PAIR_LOT_TAG[]      = "TSC-ScalarNotePair/lot";
inline constexpr char SCALAR_NOTE_PAIR_SINK_TAG[]     = "TSC-ScalarNotePair/sink";
inline constexpr char SCALAR_NOTE_PAIR_CONTRACT_TAG[] = "TSC-ScalarNotePair/contract";
//! Token-id derivation (§6.2). `base_id` hashes the descriptor economics EXCLUDING the two token ids
//! (non-circular); the long/short token ids are then tagged hashes of that base. So L/S are a
//! deterministic, independently re-derivable function of the contract terms — the descriptor still
//! stores them, but ValidateScalarNotePairTerms requires the stored ids to equal this derivation, and
//! every builder treats the committed ids as authoritative (it verifies, never recomputes-and-fixes).
inline constexpr char SCALAR_NOTE_PAIR_BASE_TAG[]        = "TSC-ScalarNotePair/base";
inline constexpr char SCALAR_NOTE_PAIR_TOKEN_LONG_TAG[]  = "TSC-ScalarNotePair/token-long";
inline constexpr char SCALAR_NOTE_PAIR_TOKEN_SHORT_TAG[] = "TSC-ScalarNotePair/token-short";

inline constexpr uint8_t kScalarNotePairDescriptorVersion = 1; //!< v1 descriptor (frozen length)

//! Side selector for the two pot/sink families of a lot. The long pot redeems token L; the short pot
//! redeems token S. Encoded as a domain-separating byte in the sink derivation so the two families
//! never collide.
inline constexpr uint8_t SCALAR_NOTE_SIDE_LONG  = 0x00;
inline constexpr uint8_t SCALAR_NOTE_SIDE_SHORT = 0x01;

//! Build the canonical §2.2 scalar-CFD settlement leaf — the EXACT inverse of the consensus parser
//! `ParseScalarCfdLeaf`. Every operand is emitted in its one legal push form (fixed-width LE blobs as
//! direct `OP_PUSHBYTES_n`; `settle_lock_height` as a minimal non-negative `CScriptNum` push; the
//! 1-byte version/source/mode/direction fields as raw 1-byte data pushes — never `OP_n`). The two
//! settlement keys come from `leaf.owner_key`/`leaf.cp_key`, which MUST be exactly 32 bytes. The
//! template_version field is always emitted as v1 (the caller's `leaf.template_version`, which must be
//! v1). Round-tripping `ParseScalarCfdLeaf(BuildScalarCfdLeaf(L)) == L` is asserted in the unit tests.
CScript BuildScalarCfdLeaf(const ScalarCfdLeaf& leaf);

//! §6.2 pot leaf (generalises BuildOptionPotLeaf, parameterised by the TOKEN id): a token holder
//! redeems by retiring exactly 1 unit of `token_id` to `sink_spk`. The pot itself holds the collateral
//! asset C — that value flows to the redeemer; the leaf only binds the token retirement.
//!   <tapmatch(sink_spk)> <token_id> <0x01..8> OP_OUTPUTMATCH_ASSET
CScript BuildScalarPotLeaf(const uint256& token_id, const CScript& sink_spk);

//! NUMS_H-internal taproot builder for a pot (single depth-0 leaf).
TaprootBuilder CreateScalarPotBuilder(const CScript& pot_leaf);

//! §6.3 permissionless complete-set unwind leaf: anyone holding 1 L + 1 S can retire BOTH tokens to
//! their burn sinks and reclaim the full vault collateral, with no signature and no fixing. Two chained
//! OP_OUTPUTMATCH_ASSET covenants (long token → long sink, short token → short sink) joined by OP_VERIFY
//! so exactly one truthy element remains at the end (the tapscript clean-stack rule — OP_OUTPUTMATCH_ASSET
//! PUSHES a bool, it does not verify). Generalises the single-token option buy-back leaf to require the
//! complete set:
//!   <tapmatch(long_sink)> <L> <1> OP_OUTPUTMATCH_ASSET OP_VERIFY
//!   <tapmatch(short_sink)> <S> <1> OP_OUTPUTMATCH_ASSET
CScript BuildScalarUnwindLeaf(const uint256& long_token_id, const CScript& long_sink_spk,
                              const uint256& short_token_id, const CScript& short_sink_spk);

//! NUMS_H-internal vault taptree: {settle_leaf, unwind_leaf}, both at depth 1 (§6.1/§6.3). The settle
//! leaf is the keeper covenant (OP_SCALAR_CFD_SETTLE); the unwind leaf is the permissionless complete-set
//! collapse. Order does not affect the BIP341 root.
TaprootBuilder CreateScalarVaultBuilder(const CScript& settle_leaf, const CScript& unwind_leaf);

//! Immutable note-pair parameters — the canonical serialization (SerializeScalarNotePairDescriptor) IS
//! the descriptor; its tagged hash IS the pair_id. Holds the §2.2 leaf economics that are SHARED across
//! all N lots (contract_id and the two pot keys are per-lot, so they are NOT in the descriptor), plus
//! the two token ids and the lot count. Field order/width here mirrors the binary descriptor exactly.
struct ScalarNotePairTerms {
    uint8_t  descriptor_version{kScalarNotePairDescriptorVersion};
    uint8_t  source_type{static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED)};
    uint8_t  payoff_mode{static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE)};
    uint8_t  loss_direction{0};        //!< owner-leg direction: 0x00 long / 0x01 short. The opcode
                                       //!< treats the owner as the long leg iff this is 0x00; the
                                       //!< pots are assigned accordingly (see DeriveScalarNoteLot).
    uint256  underlying_asset_id{};    //!< U — whose feed settles (zero iff CHAIN_INTRINSIC)
    uint32_t feed_id{0};
    uint64_t fixing_ref{0};            //!< ISSUER: scalar_epoch; CHAIN: window-end height
    uint32_t publication_deadline_height{0};
    uint32_t settle_lock_height{0};    //!< CLTV operand (belt-and-suspenders, §2.1)
    uint16_t scalar_format_id{0};
    uint256  strike{};                 //!< K, in scalar_format_id's encoding
    uint256  fallback_scalar{};        //!< used iff no in-time real fixing (§3.4)
    uint32_t lambda_q{0};              //!< Q16 leverage
    uint256  collateral_asset_id{};    //!< C — IM/payout asset; 32 zero bytes = NATIVE_SENTINEL
    uint64_t vault_im{0};              //!< per-lot IM in C's units
    uint256  long_token_id{};          //!< L — the long-exposure token (redeems the long pot)
    uint256  short_token_id{};         //!< S — the short-exposure token (redeems the short pot)
    uint32_t lot_count{0};             //!< N
    uint256  series_salt{};            //!< issuer-chosen salt → distinct vault addresses per series

    SERIALIZE_METHODS(ScalarNotePairTerms, obj) {
        READWRITE(obj.descriptor_version, obj.source_type, obj.payoff_mode, obj.loss_direction,
                  obj.underlying_asset_id, obj.feed_id, obj.fixing_ref, obj.publication_deadline_height,
                  obj.settle_lock_height, obj.scalar_format_id, obj.strike, obj.fallback_scalar,
                  obj.lambda_q, obj.collateral_asset_id, obj.vault_im, obj.long_token_id,
                  obj.short_token_id, obj.lot_count, obj.series_salt);
    }
};

//! Everything derivable for one lot `i`: the per-lot uniqueness commitment, the two sink/pot families
//! (long pot → token L, short pot → token S), and the settle leaf. Per §6.1 the settle leaf binds
//! owner_key/cp_key to the two pot keys BY DIRECTION so token L always tracks the long leg: when
//! loss_direction == 0 the owner is long → owner_key = long pot, cp_key = short pot; when
//! loss_direction == 1 the owner is short → owner_key = short pot, cp_key = long pot. The vault is the
//! NUMS_H taptree {settle_leaf, unwind_leaf}; vault_key/vault_spk are its output key/scriptPubKey.
struct ScalarNoteLot {
    uint32_t index{0};
    uint256  salt{};
    uint256  contract_id{};
    // Long side (token L) — the owner pot.
    XOnlyPubKey long_sink_key{};  uint32_t long_sink_ctr{0};  CScript long_sink_spk;
    XOnlyPubKey long_pot_key{};                               CScript long_pot_spk;   CScript long_pot_leaf;
    // Short side (token S) — the cp pot.
    XOnlyPubKey short_sink_key{}; uint32_t short_sink_ctr{0}; CScript short_sink_spk;
    XOnlyPubKey short_pot_key{};                              CScript short_pot_spk;  CScript short_pot_leaf;
    // Vault — taptree {settle_leaf, unwind_leaf}, NUMS_H-internal.
    CScript settle_leaf;          //!< keeper covenant (OP_SCALAR_CFD_SETTLE)
    CScript unwind_leaf;          //!< permissionless complete-set collapse (§6.3)
    XOnlyPubKey vault_key{};      CScript vault_spk;
};

//! The canonical little-endian descriptor — the exact bytes fed to the id tagged-hash.
std::vector<unsigned char> SerializeScalarNotePairDescriptor(const ScalarNotePairTerms& terms);

//! §6.2 — the "base" descriptor: every committed field EXCEPT the two token ids (long/short), in the
//! same order/width. base_id = TaggedHash(SCALAR_NOTE_PAIR_BASE_TAG, base) drives the token-id
//! derivation, so the derivation cannot depend on the very ids it produces (non-circular).
std::vector<unsigned char> SerializeScalarNotePairBaseDescriptor(const ScalarNotePairTerms& terms);

//! §6.2 — the canonical L/S token ids: L = TaggedHash(token-long, base_id), S = TaggedHash(token-short,
//! base_id). Returns {long_token_id, short_token_id}. `terms.long_token_id`/`short_token_id` are NOT
//! read (they are the very thing this derives), so a caller populates the descriptor by calling this and
//! ValidateScalarNotePairTerms later re-checks the stored ids equal it. Pure + reproducible by any
//! verifier holding the terms.
std::pair<uint256, uint256> DeriveScalarNotePairTokenIds(const ScalarNotePairTerms& terms);

//! Inverse of SerializeScalarNotePairDescriptor. Returns nullopt on a wrong length or a descriptor that
//! fails the in-range enum checks; the caller then recomputes ComputeScalarNotePairId and asserts it
//! equals the id being purchased before re-deriving the backing vaults.
std::optional<ScalarNotePairTerms> ParseScalarNotePairDescriptor(std::span<const unsigned char> descriptor);

//! pair_id = TaggedHash(SCALAR_NOTE_PAIR_ID_TAG, descriptor).
uint256 ComputeScalarNotePairId(const ScalarNotePairTerms& terms);

//! The asset-registry display/lookup hex for an id (== uint256::GetHex, reverse byte order).
std::string ScalarNotePairRegistryIdHex(const uint256& pair_id);

//! Per-lot derivations (mirror the option-series scheme).
uint256 DeriveScalarNoteLotSalt(const uint256& pair_id, uint32_t i);
//! Counter-loop to the first x-only-valid TaggedHash for the given side. Returns {sink output key, ctr}.
std::pair<XOnlyPubKey, uint32_t> DeriveScalarNoteSink(const uint256& pair_id, uint32_t i, uint8_t side);
//! Per-instance uniqueness commitment pushed (and dropped) into the settle leaf.
uint256 DeriveScalarNoteContractId(const uint256& pair_id, uint32_t i);

//! Validate note-pair terms before any builder/RPC serializes them: known descriptor_version; in-range
//! source_type/payoff_mode/loss_direction; source-consistent U (zero iff CHAIN_INTRINSIC, non-zero iff
//! ISSUER); a known scalar_format_id; lot_count > 0; non-zero lambda_q; vault_im >= MIN_SETTLE_OUTPUT;
//! distinct, non-null token ids L/S that also differ from the collateral C; a block-height settle_lock
//! in [1, LOCKTIME_THRESHOLD); and (for native collateral) a MoneyRange total collateral N*vault_im.
//! ALSO requires the stored token ids to equal DeriveScalarNotePairTokenIds(terms) — the canonical
//! derivation — so a descriptor can never carry forged/inconsistent L/S ids (§6.2). Sets `err`.
bool ValidateScalarNotePairTerms(const ScalarNotePairTerms& terms, std::string& err);

//! §6.1/§6.2 — the canonical TSC-ICU-META-1 container bytes carried in BOTH the L and S child ICU
//! payloads: a machine descriptor band (TSC-ICU-SCALARNOTEPAIR-1, the EXACT descriptor hex) plus an
//! auto-derived display termsheet. So either token's ICU lets a cold verifier recover the descriptor,
//! recompute pair_id, and confirm its own asset id is the descriptor's long/short token id.
std::vector<unsigned char> BuildScalarNotePairIcuMetadata(const ScalarNotePairTerms& terms);

//! Derive everything for lot `i` from the terms + pair_id: salt, contract_id, both sink/pot families,
//! the settle leaf, the unwind leaf, and the {settle, unwind} vault. Also the reference vector source.
//! Requires ValidateScalarNotePairTerms to have passed (it Assume()s invariants like i < lot_count).
ScalarNoteLot DeriveScalarNoteLot(const ScalarNotePairTerms& terms, const uint256& pair_id, uint32_t i);

//! Persisted note-pair record (mirrors OptionSeriesRecord), keyed by pair_id. The two token children
//! are registered (each its own sponsorchildasset tx, co-spending the parent root ICU) and then the
//! whole pair is issued in ONE tx (mint N L + N S + fund N collateral vaults). Pots/sinks/vaults are
//! recomputed on demand from `terms` + pair_id, so only the funded outpoints, the two child ICUs, and
//! the txids are stored.
struct ScalarNotePairRecord {
    uint256 pair_id{};                  //!< == ComputeScalarNotePairId(terms)
    ScalarNotePairTerms terms;
    COutPoint long_icu_outpoint{};      //!< token L's current ICU successor (after the issuance tx)
    COutPoint short_icu_outpoint{};     //!< token S's current ICU successor (after the issuance tx)
    uint256 register_long_txid{};       //!< sponsorchildasset tx that registered L
    uint256 register_short_txid{};      //!< sponsorchildasset tx that registered S
    uint256 issue_txid{};               //!< the single atomic dual-mint + vault-funding tx
    std::vector<COutPoint> lot_vaults;  //!< N funded lot-vault outpoints (from the issuance tx)

    SERIALIZE_METHODS(ScalarNotePairRecord, obj) {
        READWRITE(obj.pair_id, obj.terms, obj.long_icu_outpoint, obj.short_icu_outpoint,
                  obj.register_long_txid, obj.register_short_txid, obj.issue_txid, obj.lot_vaults);
    }
};

//! Persistence integrity gate (mirrors ValidateOptionSeriesRecord). A record is valid iff its `terms`
//! pass ValidateScalarNotePairTerms (which includes the canonical token-id check), `pair_id ==
//! ComputeScalarNotePairId(terms)` (and `== *expected_key` when given), both register txids and the
//! issue txid are non-null, both child ICU outpoints reference `issue_txid` (the issuance tx rotated
//! them), and `lot_vaults` is exactly `lot_count` outpoints — none null, none duplicated, each an
//! output of `issue_txid`. Sets `err` on failure. (The tx-level "exactly N L + N S minted and N vaults
//! funded" coupling is checked by ValidateScalarNotePairIssuanceTx in Slice 5b-2.)
bool ValidateScalarNotePairRecord(const ScalarNotePairRecord& record, const uint256* expected_key, std::string& err);

//! A funded input: its outpoint + the ACTUAL on-chain output it spends (value, scriptPubKey, vExt). The
//! issuance builder verifies everything it can from this — the ICUs' IssuerReg ids/policy, the collateral
//! asset, native-vs-asset — so a caller cannot misstate any of it.
struct ScalarFundedInput {
    COutPoint outpoint;
    CTxOut    txout;
};

//! Selected inputs for one atomic issuance tx. The two child ICUs are the mint authorities (consensus
//! requires both be spent, §6.4). collateral_inputs carry asset C (empty iff NATIVE collateral).
struct ScalarNotePairIssuanceInputs {
    ScalarFundedInput long_icu;                        //!< L's current ICU (IssuerReg.asset_id == L)
    ScalarFundedInput short_icu;                       //!< S's current ICU (IssuerReg.asset_id == S)
    std::vector<ScalarFundedInput> collateral_inputs;  //!< AssetTag(C) UTXOs; empty for native collateral
    std::vector<ScalarFundedInput> native_inputs;      //!< native-only funding / fees
};

//! §6.4 — build the ONE atomic issuance tx: spend both child ICUs (mint authority), mint N units of L
//! and N of S to the issuer, and fund all N derived lot vaults with the committed collateral. Verifies
//! the spent ICUs' IssuerReg against the committed token ids AND the §2.5-style invariants observable
//! from the IssuerReg (asset_id == L/S, MINT_ALLOWED, not BURN_ALLOWED, issuance_cap_units == N,
//! decimals == 0, policy_quorum_bps == 0), reuses each ICU's vExt byte-identically for its successor
//! (rotate pattern — no governance mutation), and conserves asset C (Σ C inputs == Σ vault collateral +
//! C change). NATIVE collateral (C == 0): vaults carry nValue == vault_im and no AssetTag, no
//! collateral_inputs. ASSET collateral: vaults carry AssetTag(C, vault_im) and nValue == vault_native_sats.
//!
//! The builder is PURE (no chain access). The caller (RPC, Slice 5e) MUST first read the CONFIRMED
//! registry for L and S and reject anything not yet confirmed / already issued (issued_total != 0) — the
//! "confirmed before minting, no mempool chaining" rule the IssuerReg alone cannot prove. Writes `out`
//! only on success; sets `err` otherwise.
bool BuildScalarNotePairIssuance(const ScalarNotePairTerms& terms, const uint256& pair_id,
                                 const ScalarNotePairIssuanceInputs& inputs,
                                 const CScript& long_icu_successor_spk, const CScript& short_icu_successor_spk,
                                 const CScript& issuer_token_spk, const CScript& change_spk,
                                 CAmount vault_native_sats, CAmount fee, CAmount dust,
                                 CMutableTransaction& out, std::string& err);

//! The atomicity invariant (§6.4), checkable from the issuance tx ALONE (no input data needed): EXACTLY
//! one IssuerReg successor for L and one for S; the AssetTag(L) outputs sum to exactly N and AssetTag(S)
//! to exactly N (mint); and EXACTLY the N derived lot vaults are funded, each once, with the committed
//! collateral encoding (asset: AssetTag(C, vault_im) & nValue >= dust; native: nValue == vault_im & no
//! AssetTag). Used by the builder as a self-check and by record_issue on the confirmed tx, so "mint
//! exactly N L + N S AND fund exactly the N vaults" is a validated invariant, not an RPC convention.
//! (Mint authorisation — both ICUs spent — and C conservation are consensus-enforced.) Sets `err`.
bool ValidateScalarNotePairIssuanceTx(const ScalarNotePairTerms& terms, const uint256& pair_id,
                                      const CTransaction& tx, std::string& err);

//! One pot to redeem: its lot index + the funded pot UTXO. The builder derives the lot and requires the
//! UTXO to BE the derived pot for the chosen side (scriptPubKey == long/short pot spk; asset collateral
//! → AssetTag(C, leg) with leg > 0; native collateral → native-only).
struct ScalarRedemptionPot {
    uint32_t lot_index{0};
    ScalarFundedInput pot;
};

//! §6.2 per-side redemption — the two-sided generalisation of BuildOptionRedemption. `redeem_long`
//! selects the side: true redeems token L against the lots' LONG pots, false redeems token S against the
//! SHORT pots. Every input is verified from its txout: pots (derived spk + collateral encoding),
//! token_inputs (carry the side's token id; units summed from the actual vExt), native_inputs
//! (native-only). Retires exactly 1 token unit to each lot's unique sink, returns token change (m − k)
//! to `holder_spk`, and pays the reclaimed collateral to `holder_spk` — as an AssetTag(C, Σ pot legs)
//! output for asset collateral, or folded into the native sweep for native collateral. All amounts
//! MoneyRange-checked; `dust` is MoneyRange and >= 546; the 64-asset and 128-output policy caps are
//! enforced; duplicate input outpoints / lot indices are rejected. Token + native inputs are appended
//! unsigned. Writes `out` only on success.
bool BuildScalarNoteRedemption(const ScalarNotePairTerms& terms, const uint256& pair_id, bool redeem_long,
                               const std::vector<ScalarRedemptionPot>& pots,
                               const std::vector<ScalarFundedInput>& token_inputs,
                               const std::vector<ScalarFundedInput>& native_inputs,
                               const CScript& holder_spk, CAmount fee, CAmount dust,
                               CMutableTransaction& out, std::string& err);

//! §6.3 permissionless complete-set unwind — spend ONE lot vault via its unwind leaf by presenting
//! 1 L AND 1 S, retiring both to their sinks, and reclaiming the FULL vault collateral. No signature,
//! no fixing, any time. Generalises BuildOptionBuyback to require BOTH tokens. Verifies the vault is the
//! derived lot vault (spk + collateral: asset AssetTag(C, vault_im) / native nValue == vault_im), that
//! the long/short token inputs carry L/S (>= 1 each), and native inputs are native-only. Retires 1 L →
//! long sink + 1 S → short sink, returns token change (m−1 each) to `holder_spk`, and pays the reclaimed
//! collateral to `holder_spk` — AssetTag(C, vault_im) for asset, folded into the native sweep for native.
//! The vault is spent signatureless (witness [unwind_leaf, control]). Caps + MoneyRange as elsewhere.
//! Writes `out` only on success.
bool BuildScalarUnwind(const ScalarNotePairTerms& terms, const uint256& pair_id, uint32_t lot_index,
                       const ScalarFundedInput& vault,
                       const std::vector<ScalarFundedInput>& long_token_inputs,
                       const std::vector<ScalarFundedInput>& short_token_inputs,
                       const std::vector<ScalarFundedInput>& native_inputs,
                       const CScript& holder_spk, CAmount fee, CAmount dust,
                       CMutableTransaction& out, std::string& err);

} // namespace wallet

#endif // BITCOIN_WALLET_SCALAR_NOTE_PAIR_H
