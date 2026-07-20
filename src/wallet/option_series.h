// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_OPTION_SERIES_H
#define BITCOIN_WALLET_OPTION_SERIES_H

// Option-series tokenization — pure derivation core (Slice 1).
//
// Implements the FROZEN derivations of OPTION_SERIES_FREEZE.md (D1-b + D2-a): the binary descriptor (§2),
// asset_id (§3), and the per-lot salt / sink / pot / vault derivations (§4). The descriptor is 103 bytes
// for descriptor_version 1 (call-only) and 104 bytes for v2 (the directional extension, with a trailing
// call/put `direction` byte); v1 stays byte-identical and the asset-id tag is shared across versions.
// Everything here is pure (no wallet/UTXO state) and deterministic from the descriptor, so it doubles as
// the reference generator for the §7.3 conformance vectors. The lot vault reuses the existing
// BuildDifficultyLeafScript / ComputeDifficultyContractId verbatim (writer = short leg for a call, long
// leg for a put) and composes the option-specific buy-back leaf around it; no consensus code is added.

#include <consensus/amount.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/signingprovider.h> // TaprootBuilder
#include <uint256.h>
#include <wallet/difficulty_contract.h>

#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

class UniValue; // RPC parameter layer (declared at the bottom)

namespace wallet {

//! BIP340 tagged-hash domains (OPTION_SERIES_FREEZE.md §3/§4). The asset-id tag is a FIXED domain across
//! all descriptor versions: the descriptor's first byte IS descriptor_version and v1/v2 differ in length
//! (103 vs 104), so the hashed preimages can never collide and a shared tag is sound. (The "/v1" suffix
//! names the tag scheme, which is frozen — it is NOT bumped per descriptor_version.)
inline constexpr char OPTION_SERIES_ID_TAG[]   = "TSC-OptionSeries/v1";
inline constexpr char OPTION_SERIES_LOT_TAG[]  = "TSC-OptionSeries/lot";
inline constexpr char OPTION_SERIES_SINK_TAG[] = "TSC-OptionSeries/sink";

inline constexpr uint8_t kOptionDescriptorVersion = 1;             //!< v1: call-only, 103-byte descriptor (frozen)
inline constexpr uint8_t kOptionDescriptorVersionDirectional = 2; //!< v2: appends a call/put direction byte (104)
inline constexpr uint8_t OPTION_ISSUANCE_SELF      = 0; //!< self-issuance (primary)
inline constexpr uint8_t OPTION_ISSUANCE_BILATERAL = 1; //!< bilateral cosign (advanced)
inline constexpr uint8_t OPTION_LEAFSET_SETTLE_ONLY    = 0; //!< D1-a
inline constexpr uint8_t OPTION_LEAFSET_SETTLE_BUYBACK = 1; //!< D1-b (frozen default)
//! Option direction = which leg the writer funds, i.e. what the tokenized (long) holder gets:
//!   CALL — writer SHORT; holder is long a call → pays out as realized difficulty rises ABOVE the strike.
//!   PUT  — writer LONG;  holder is long a put  → pays out as realized difficulty falls BELOW the strike.
//! Encoded in the descriptor only for descriptor_version >= 2; v1 is implicitly CALL.
inline constexpr uint8_t OPTION_DIRECTION_CALL = 0;
inline constexpr uint8_t OPTION_DIRECTION_PUT  = 1;

//! Immutable series parameters — the canonical serialization (SerializeOptionDescriptor) IS the
//! §2 descriptor; its tagged hash IS asset_id. Field order/width here mirrors §2 exactly. Per-lot
//! salts, pot/sink/vault keys are all DERIVED (never stored) — see OPTION_TOKENIZATION.md §2.1.
struct OptionSeriesTerms {
    uint8_t  descriptor_version{kOptionDescriptorVersion};
    uint8_t  issuance_mode{OPTION_ISSUANCE_SELF};
    uint8_t  leaf_set{OPTION_LEAFSET_SETTLE_BUYBACK};
    XOnlyPubKey writer_key{};          //!< issuer/writer RAW SIGNABLE key (payout output key AND buy-back signer)
    uint32_t strike_nbits{0};
    uint32_t fixing_height{0};
    uint32_t settle_lock_height{0};
    uint32_t lambda_q{0};              //!< Q16
    CAmount  lot_im_sats{0};           //!< per-lot IM = K/N
    uint32_t lot_count{0};             //!< N
    CAmount  reference_premium_sats{0};//!< display/listing only under self-issuance (freeze §4 patch 2)
    uint256  series_salt{};
    uint8_t  direction{OPTION_DIRECTION_CALL}; //!< call (writer short) | put (writer long); descriptor byte only when v >= 2

    //! Wallet-persistence serialization (NOT the §2 consensus descriptor — that is the fixed binary
    //! SerializeOptionDescriptor). `direction` is serialized ONLY for descriptor_version >= 2, so a v1
    //! record stays byte-identical to one written before the field existed: an old (pre-direction) record
    //! deserializes cleanly and defaults to CALL, and a v1 record never grows the trailing byte.
    SERIALIZE_METHODS(OptionSeriesTerms, obj) {
        READWRITE(obj.descriptor_version, obj.issuance_mode, obj.leaf_set, obj.writer_key,
                  obj.strike_nbits, obj.fixing_height, obj.settle_lock_height, obj.lambda_q,
                  obj.lot_im_sats, obj.lot_count, obj.reference_premium_sats, obj.series_salt);
        if (obj.descriptor_version >= kOptionDescriptorVersionDirectional) {
            READWRITE(obj.direction);
        } else {
            SER_READ(obj, obj.direction = OPTION_DIRECTION_CALL);
        }
    }
};

//! Persisted series record (DBKeys::OPTION_SERIES{"optseries"}, keyed by series_id), mirroring
//! DifficultyContractRecord. Pots/sinks are recomputed on demand from `terms` + series_id (no storage
//! drift); only the funded outpoints, the current ICU, and the two txids are stored.
struct OptionSeriesRecord {
    uint256 series_id{};                   //!< == asset_id == ComputeOptionSeriesId(terms)
    OptionSeriesTerms terms;
    COutPoint icu_outpoint{};              //!< current ICU successor (after the issuance tx)
    uint256 register_txid{};
    uint256 issue_txid{};
    std::vector<COutPoint> lot_vaults;     //!< N funded lot-vault outpoints (from the issuance tx)

    SERIALIZE_METHODS(OptionSeriesRecord, obj) {
        READWRITE(obj.series_id, obj.terms, obj.icu_outpoint, obj.register_txid, obj.issue_txid, obj.lot_vaults);
    }
};

//! Persistence integrity gate. A record is valid iff its `terms` pass ValidateOptionSeriesTerms,
//! `series_id == ComputeOptionSeriesId(terms)` (and `== *expected_key` when given — the DB key on
//! load), and `lot_vaults` is exactly `lot_count` outpoints with none null and none duplicated.
//! Called by CWallet::RegisterOptionSeries and the wallet-load path so a mismatched/forged id or a
//! malformed vault set can never enter the wallet's series map. Sets `err` on failure.
bool ValidateOptionSeriesRecord(const OptionSeriesRecord& record, const uint256* expected_key, std::string& err);

//! Everything derivable for one lot `i`. The vault/pot/sink keys are NUMS_H-tweaked taproot output
//! keys; contract_id / settle_leaf come straight from the existing difficulty-contract helpers.
struct OptionLot {
    uint32_t index{0};
    uint256  salt{};
    uint256  contract_id{};
    XOnlyPubKey sink_key{};   uint32_t sink_ctr{0};   CScript sink_spk;
    XOnlyPubKey pot_key{};                            CScript pot_spk;   CScript pot_leaf;
    XOnlyPubKey vault_key{};                          CScript vault_spk;
    CScript settle_leaf;
    CScript buyback_leaf;     //!< empty when leaf_set == SETTLE_ONLY
    DifficultyContractRecord record; //!< funded outpoint set later at issuance; null here
};

//! §2 — the canonical 103-byte (v1, D1-b) little-endian descriptor. The exact bytes fed to §3.
std::vector<unsigned char> SerializeOptionDescriptor(const OptionSeriesTerms& terms);

//! Inverse of SerializeOptionDescriptor: parse on-chain descriptor bytes back into terms (the
//! verifier side of §3 "import and prove"). Returns nullopt if the length is wrong; the caller then
//! recomputes ComputeOptionSeriesId and asserts it equals the asset_id being purchased (authenticity),
//! and runs ValidateOptionSeriesTerms before re-deriving the N backing vaults.
std::optional<OptionSeriesTerms> ParseOptionSeriesDescriptor(std::span<const unsigned char> descriptor);

//! §3 — series_id = asset_id = TaggedHash(OPTION_SERIES_ID_TAG, descriptor).
uint256 ComputeOptionSeriesId(const OptionSeriesTerms& terms);

//! The asset registry's display/lookup hex for a series_id (== uint256::GetHex, reverse byte order).
//! The option-series canonical id is HexStr(series_id) (forward, §7.2), but registerasset / mintasset
//! and getassetinfo / getassetpolicy / geticupayload all speak this reverse-hex form for the SAME 32
//! bytes. ONE documented boundary so the core (derive/verify) and wallet (build_register/build_issue)
//! RPCs agree and a buyer can pass either form to optionseries.verify.
std::string OptionSeriesRegistryIdHex(const uint256& series_id);

//! §6.1 — the canonical-JSON `TSC-ICU-META-1` container bytes for this series: the machine descriptor
//! band (`TSC-ICU-OPTSERIES-1`, the EXACT §2 descriptor hex — §6.2) plus the auto-derived display
//! termsheet (`TSC-ICU-TERMSHEET-1` — §6.3, never a second binding doc). These bytes go in the ICU
//! payload `metadata` slot (sealed by icu_ctxt_commit), so a cold verifier recovers the descriptor on
//! chain and recomputes asset_id. Encoded via assets::CanonicalizeIcuBandJson (reproducible bytes).
std::vector<unsigned char> BuildOptionSeriesIcuMetadata(const OptionSeriesTerms& terms);

//! §4.1 — salt_i = TaggedHash(OPTION_SERIES_LOT_TAG, series_id || le32(i)).
uint256 DeriveOptionLotSalt(const uint256& series_id, uint32_t i);

//! §4.2 — counter-loop to the first x-only-valid TaggedHash(OPTION_SERIES_SINK_TAG, ...). Returns
//! {sink output key, winning ctr}. The key is used untweaked as a provably-unspendable P2TR.
std::pair<XOnlyPubKey, uint32_t> DeriveOptionSink(const uint256& series_id, uint32_t i);

//! §2.3 — pot leaf: <tapmatch(sink_spk)> <asset_id> <0x01..> OP_OUTPUTMATCH_ASSET.
CScript BuildOptionPotLeaf(const uint256& asset_id, const CScript& sink_spk);

//! §4 (D1-b) — buy-back leaf: <writer_key> OP_CHECKSIGVERIFY <tapmatch(sink_spk)> <asset_id> <0x01..> OP_OUTPUTMATCH_ASSET.
CScript BuildOptionBuybackLeaf(const XOnlyPubKey& writer_key, const uint256& asset_id, const CScript& sink_spk);

//! NUMS_H-internal taproot builders. Pot = single depth-0 leaf; vault = settle(+buyback) at depth 1
//! (OPTION_SERIES_FREEZE.md §4 patch 3, leaf version 0xc0). buyback_leaf empty => settle-only (D1-a).
TaprootBuilder CreateOptionPotBuilder(const CScript& pot_leaf);
TaprootBuilder CreateOptionVaultBuilder(const CScript& settle_leaf, const CScript& buyback_leaf);

//! #4 — validate series terms before any builder/RPC serializes them: known descriptor_version,
//! issuance_mode and leaf_set in range, `writer_key.IsFullyValid()`, `lot_count > 0`, non-negative
//! CAmounts, `lot_im_sats >= MIN_SETTLE_OUTPUT`, and (delegated to DifficultyContractTerms::Validate
//! on a representative lot template) a canonical strike, non-zero leverage, and a burial-aligned CLTV.
//! Pass the chain powLimit to also reject an above-powLimit strike. Sets `err` on failure.
bool ValidateOptionSeriesTerms(const OptionSeriesTerms& terms, const uint256* pow_limit, std::string& err);

//! §4 — derive everything for lot `i` from the series terms + series_id. Also the §7.3 vector source.
OptionLot DeriveOptionLot(const OptionSeriesTerms& terms, const uint256& series_id, uint32_t i);

//! A funded input: its outpoint + the ACTUAL on-chain output it spends (value, scriptPubKey, and the
//! vExt AssetTag). The builders verify everything they can from this — the derived covenant
//! scriptPubKey, the exact collateral value, native-vs-asset, and token unit counts — so a caller
//! cannot misstate any of it (review findings #2/#3/#6). `series_id` is computed internally from
//! `terms` (finding #1), never trusted from the caller.
struct FundedOutput {
    COutPoint outpoint;
    CTxOut    txout;
};

//! Settlement skeleton for ONE tokenized lot. Computes series_id internally from `terms`, DERIVES the
//! lot, and requires `vault.txout` to BE the derived lot vault: scriptPubKey == derived, nValue ==
//! per-lot IM, native-only (no AssetTag). Otherwise the option-local analogue of
//! BuildDifficultySettlementSkeleton (payout via DeriveTarget + ComputeDiffCfdPayout, keeper witness
//! [settle_leaf, control], nLockTime == settle_lock_height).
//!
//! SECURITY CONTRACT (as BuildDifficultySettlementSkeleton): `realized_nbits` MUST be the value read
//! from the active chain at `terms.fixing_height`, after enforcing burial — a UX footgun, not a
//! fund-safety hole (a wrong value yields outputs the covenant rejects).
bool BuildOptionSettlementSkeleton(const OptionSeriesTerms& terms, uint32_t lot_index,
                                   const FundedOutput& vault, uint32_t realized_nbits, const uint256& pow_limit,
                                   DifficultySettlementSkeleton& out, std::string& err);

//! One pot to redeem: its lot index + funded pot UTXO. The builder derives the sink/pot leaf and
//! requires `pot.txout` to be the derived pot (scriptPubKey == derived, native-only).
struct OptionRedemptionPot {
    uint32_t     lot_index{0};
    FundedOutput pot;
};

//! §2.8 — assemble a k-lot redemption tx. series_id is derived from `terms`; asset_id == series_id.
//! EVERY input is verified from its `txout`: pots (derived spk, native-only), token inputs (carry
//! AssetTag(series_id); units summed from the actual vExt — finding #2), native fee inputs
//! (native-only — finding #3). Retires exactly 1 unit to each unique sink, returns token change
//! (m − k) + native sweep to `holder_spk`. All amounts MoneyRange-checked; `dust` is MoneyRange and
//! >= 546; the 128 covenant-output AND 64 asset-output policy caps are enforced; duplicate input
//! outpoints rejected. Token + native inputs are appended unsigned. Writes `out` only on success.
bool BuildOptionRedemption(const OptionSeriesTerms& terms,
                           const std::vector<OptionRedemptionPot>& pots,
                           const std::vector<FundedOutput>& token_inputs,
                           const std::vector<FundedOutput>& native_inputs,
                           const CScript& holder_spk, CAmount fee, CAmount dust,
                           CMutableTransaction& out, std::string& err);

//! #3 (D1-b only) — the writer's early-unwind. As redemption, but for one vault: derives the lot,
//! requires `vault.txout` to be the derived vault (spk + nValue == IM + native-only — finding #6),
//! verifies token inputs carry AssetTag(series_id) and native inputs are native-only, then spends the
//! vault via its buy-back leaf (witness `[<placeholder sig>, buyback_leaf, control]`; the wallet signs
//! `OP_CHECKSIGVERIFY` with an OUTPUT-BINDING sighash), retires 1 unit to the lot sink, token change
//! (m − 1) + reclaimed collateral to `writer_spk`. Fails on a settle-only lot or `m < 1`.
bool BuildOptionBuyback(const OptionSeriesTerms& terms, uint32_t lot_index,
                        const FundedOutput& vault,
                        const std::vector<FundedOutput>& token_inputs,
                        const std::vector<FundedOutput>& native_inputs,
                        const CScript& writer_spk, CAmount fee, CAmount dust,
                        CMutableTransaction& out, std::string& err);

// --- RPC parameter layer (lives in bitcoin_common so BOTH the core optionseries.derive/verify RPCs
// and the wallet optionseries.build_register RPC share one parser; no duplication). These take/return
// UniValue and throw JSONRPCError on malformed input. ---

//! Parse a terms object (the optionseries.derive/build_register `terms` arg) into OptionSeriesTerms.
//! writer_key accepts 32-byte x-only hex OR a P2TR (bech32m) address.
OptionSeriesTerms ParseOptionSeriesTermsFromJson(const UniValue& terms);

//! Render terms back to JSON (the decoded `terms` block returned by optionseries.verify).
UniValue OptionSeriesTermsToJson(const OptionSeriesTerms& terms);

//! Extract the §2 descriptor bytes from a verify `source` object — exactly one of `descriptor` (hex),
//! `icu_metadata` (canonical TSC-ICU-META-1 bytes, fail-closed band+canonical check), or `terms`.
std::vector<unsigned char> ExtractOptionSeriesDescriptorFromSource(const UniValue& source);

} // namespace wallet

#endif // BITCOIN_WALLET_OPTION_SERIES_H
