// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scalar_note_pair.h>

#include <addresstype.h>          // WitnessV1Taproot, GetScriptForDestination
#include <arith_uint256.h>        // DecodeScalarValue out-param
#include <assets/asset.h>         // IsKnownScalarFormat
#include <consensus/scalar_cfd.h> // DecodeScalarValue (literal canonicality)
#include <assets/icu_payload.h>   // CanonicalizeIcuBandJson (TSC-ICU-META-1 container)
#include <consensus/amount.h>     // MoneyRange, MAX_MONEY
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT
#include <crypto/common.h>        // ReadLE16/32/64, WriteLE16/32/64
#include <hash.h>                 // HashWriter, TaggedHash
#include <policy/policy.h>        // MAX_COVENANT_TX_OUTPUTS
#include <primitives/transaction.h> // CTransaction, CMutableTransaction, CTxOut
#include <script/interpreter.h>   // ComputeTapMatch, TAPROOT_LEAF_TAPSCRIPT
#include <script/solver.h>        // Solver, TxoutType (mint-output family preflight)
#include <span.h>                 // MakeByteSpan
#include <tinyformat.h>           // strprintf
#include <util/check.h>           // Assume
#include <util/strencodings.h>    // HexStr
#include <util/transaction_identifier.h> // Txid

#include <univalue.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

namespace wallet {

namespace {
std::vector<unsigned char> LE16(uint16_t v) { std::vector<unsigned char> b(2); WriteLE16(b.data(), v); return b; }
std::vector<unsigned char> LE32(uint32_t v) { std::vector<unsigned char> b(4); WriteLE32(b.data(), v); return b; }
std::vector<unsigned char> LE64(uint64_t v) { std::vector<unsigned char> b(8); WriteLE64(b.data(), v); return b; }

void AppendLE16(std::vector<unsigned char>& d, uint16_t v) { const auto b = LE16(v); d.insert(d.end(), b.begin(), b.end()); }
void AppendLE32(std::vector<unsigned char>& d, uint32_t v) { const auto b = LE32(v); d.insert(d.end(), b.begin(), b.end()); }
void AppendLE64(std::vector<unsigned char>& d, uint64_t v) { const auto b = LE64(v); d.insert(d.end(), b.begin(), b.end()); }

//! The OUTPUTMATCH_ASSET operand: exactly 1 raw unit, 8-byte little-endian (decimals == 0).
std::vector<unsigned char> OneUnitLE() { return LE64(1); }

std::vector<unsigned char> LeafBytes(const CScript& s) { return std::vector<unsigned char>(s.begin(), s.end()); }
CScript P2TR(const XOnlyPubKey& key) { return GetScriptForDestination(WitnessV1Taproot{key}); }

//! The canonical descriptor is exactly this many bytes for v1.
constexpr size_t kScalarNotePairDescriptorBytesV1 = 266;

//! Conservative asset/sweep dust floor + the default per-tx AssetTag-output cap (mirror option_series).
constexpr CAmount kMinAssetOutputDust = 546;
constexpr size_t kDefaultMaxAssetsPerTx = 64;
} // namespace

CScript BuildScalarCfdLeaf(const ScalarCfdLeaf& leaf)
{
    // The exact inverse of ParseScalarCfdLeaf (consensus/scalar_cfd_leaf.cpp). Every operand uses its
    // one legal push form; any deviation makes the parser reject the leaf, so a round-trip is the test.
    Assume(leaf.template_version == SCALAR_CFD_TEMPLATE_VERSION_V1);
    Assume(leaf.owner_key.size() == 32);
    Assume(leaf.cp_key.size() == 32);

    CScript s;
    // <contract_id32> OP_DROP
    s << ToByteVector(leaf.contract_id) << OP_DROP;
    // <template_version=0x01> — raw 1-byte data push (op byte == length 1).
    s << std::vector<unsigned char>{leaf.template_version};
    // <settle_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP — minimal non-negative CScriptNum push.
    s << CScriptNum(leaf.settle_lock_height).getvch() << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    // <source_type> (1) <underlying_asset_id32> <feed_id_le4> <fixing_ref_le8> <deadline_le4>
    s << std::vector<unsigned char>{leaf.source_type};
    s << ToByteVector(leaf.underlying_asset_id);
    s << LE32(leaf.feed_id);
    s << LE64(leaf.fixing_ref);
    s << LE32(leaf.publication_deadline_height);
    // <payoff_mode> (1) <scalar_format_id_le2>
    s << std::vector<unsigned char>{leaf.payoff_mode};
    s << LE16(leaf.scalar_format_id);
    // <strike_le32> <fallback_scalar_le32> <lambda_q_le4>
    s << ToByteVector(leaf.strike);
    s << ToByteVector(leaf.fallback_scalar);
    s << LE32(leaf.lambda_q);
    // <loss_direction> — raw 1-byte push of 0x00/0x01 (NOT OP_1; that would be a different leaf byte).
    s << std::vector<unsigned char>{leaf.loss_direction};
    // <collateral_asset_id32> <vault_im_le8>
    s << ToByteVector(leaf.collateral_asset_id);
    s << LE64(leaf.vault_im);
    // <owner_key32> <cp_key32>
    s << leaf.owner_key;
    s << leaf.cp_key;
    // OP_SCALAR_CFD_SETTLE
    s << OP_SCALAR_CFD_SETTLE;
    return s;
}

CScript BuildScalarPotLeaf(const uint256& token_id, const CScript& sink_spk)
{
    const uint256 tap_match = ComputeTapMatch(sink_spk);
    CScript s;
    s << std::vector<unsigned char>(tap_match.begin(), tap_match.end())
      << std::vector<unsigned char>(token_id.begin(), token_id.end())
      << OneUnitLE()
      << OP_OUTPUTMATCH_ASSET;
    return s;
}

TaprootBuilder CreateScalarPotBuilder(const CScript& pot_leaf)
{
    TaprootBuilder b;
    b.Add(0, LeafBytes(pot_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    b.Finalize(XOnlyPubKey::NUMS_H);
    return b;
}

CScript BuildScalarUnwindLeaf(const uint256& long_token_id, const CScript& long_sink_spk,
                              const uint256& short_token_id, const CScript& short_sink_spk)
{
    const uint256 long_match = ComputeTapMatch(long_sink_spk);
    const uint256 short_match = ComputeTapMatch(short_sink_spk);
    CScript s;
    // Long token → long sink. OP_OUTPUTMATCH_ASSET pushes a bool, so OP_VERIFY collapses it (and
    // fail-fasts) before the second match, leaving exactly the short match's bool at the end.
    s << ToByteVector(long_match) << ToByteVector(long_token_id) << OneUnitLE()
      << OP_OUTPUTMATCH_ASSET << OP_VERIFY;
    // Short token → short sink (terminal: its bool is the single clean-stack result).
    s << ToByteVector(short_match) << ToByteVector(short_token_id) << OneUnitLE()
      << OP_OUTPUTMATCH_ASSET;
    return s;
}

TaprootBuilder CreateScalarVaultBuilder(const CScript& settle_leaf, const CScript& unwind_leaf)
{
    TaprootBuilder b;
    // Both leaves at depth 1 (order does not affect the BIP341 root).
    b.Add(1, LeafBytes(settle_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    b.Add(1, LeafBytes(unwind_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    b.Finalize(XOnlyPubKey::NUMS_H);
    return b;
}

std::vector<unsigned char> SerializeScalarNotePairDescriptor(const ScalarNotePairTerms& t)
{
    std::vector<unsigned char> d;
    d.reserve(kScalarNotePairDescriptorBytesV1);
    d.push_back(t.descriptor_version);
    d.push_back(t.source_type);
    d.push_back(t.payoff_mode);
    d.push_back(t.loss_direction);
    d.insert(d.end(), t.underlying_asset_id.begin(), t.underlying_asset_id.end()); // 32
    AppendLE32(d, t.feed_id);
    AppendLE64(d, t.fixing_ref);
    AppendLE32(d, t.publication_deadline_height);
    AppendLE32(d, t.settle_lock_height);
    AppendLE16(d, t.scalar_format_id);
    d.insert(d.end(), t.strike.begin(), t.strike.end());                   // 32
    d.insert(d.end(), t.fallback_scalar.begin(), t.fallback_scalar.end()); // 32
    AppendLE32(d, t.lambda_q);
    d.insert(d.end(), t.collateral_asset_id.begin(), t.collateral_asset_id.end()); // 32
    AppendLE64(d, t.vault_im);
    d.insert(d.end(), t.long_token_id.begin(), t.long_token_id.end());   // 32
    d.insert(d.end(), t.short_token_id.begin(), t.short_token_id.end()); // 32
    AppendLE32(d, t.lot_count);
    d.insert(d.end(), t.series_salt.begin(), t.series_salt.end());       // 32
    Assume(d.size() == kScalarNotePairDescriptorBytesV1);
    return d;
}

std::vector<unsigned char> SerializeScalarNotePairBaseDescriptor(const ScalarNotePairTerms& t)
{
    // The full descriptor MINUS the two token-id fields, same order/width (266 - 64 = 202 bytes). The
    // token ids are derived FROM this, so they cannot be an input to their own derivation.
    std::vector<unsigned char> d;
    d.reserve(kScalarNotePairDescriptorBytesV1 - 64);
    d.push_back(t.descriptor_version);
    d.push_back(t.source_type);
    d.push_back(t.payoff_mode);
    d.push_back(t.loss_direction);
    d.insert(d.end(), t.underlying_asset_id.begin(), t.underlying_asset_id.end());
    AppendLE32(d, t.feed_id);
    AppendLE64(d, t.fixing_ref);
    AppendLE32(d, t.publication_deadline_height);
    AppendLE32(d, t.settle_lock_height);
    AppendLE16(d, t.scalar_format_id);
    d.insert(d.end(), t.strike.begin(), t.strike.end());
    d.insert(d.end(), t.fallback_scalar.begin(), t.fallback_scalar.end());
    AppendLE32(d, t.lambda_q);
    d.insert(d.end(), t.collateral_asset_id.begin(), t.collateral_asset_id.end());
    AppendLE64(d, t.vault_im);
    AppendLE32(d, t.lot_count);
    d.insert(d.end(), t.series_salt.begin(), t.series_salt.end());
    Assume(d.size() == kScalarNotePairDescriptorBytesV1 - 64);
    return d;
}

std::pair<uint256, uint256> DeriveScalarNotePairTokenIds(const ScalarNotePairTerms& t)
{
    const std::vector<unsigned char> base = SerializeScalarNotePairBaseDescriptor(t);
    HashWriter hb{TaggedHash(SCALAR_NOTE_PAIR_BASE_TAG)};
    hb.write(MakeByteSpan(base));
    const uint256 base_id = hb.GetSHA256();

    HashWriter hl{TaggedHash(SCALAR_NOTE_PAIR_TOKEN_LONG_TAG)};
    hl.write(MakeByteSpan(base_id));
    HashWriter hs{TaggedHash(SCALAR_NOTE_PAIR_TOKEN_SHORT_TAG)};
    hs.write(MakeByteSpan(base_id));
    return {hl.GetSHA256(), hs.GetSHA256()};
}

std::optional<ScalarNotePairTerms> ParseScalarNotePairDescriptor(std::span<const unsigned char> d)
{
    if (d.size() != kScalarNotePairDescriptorBytesV1) return std::nullopt;
    ScalarNotePairTerms t;
    size_t o = 0;
    t.descriptor_version = d[o++];
    if (t.descriptor_version != kScalarNotePairDescriptorVersion) return std::nullopt;
    t.source_type = d[o++];
    t.payoff_mode = d[o++];
    t.loss_direction = d[o++];
    std::copy(d.data() + o, d.data() + o + 32, t.underlying_asset_id.begin()); o += 32;
    t.feed_id = ReadLE32(d.data() + o); o += 4;
    t.fixing_ref = ReadLE64(d.data() + o); o += 8;
    t.publication_deadline_height = ReadLE32(d.data() + o); o += 4;
    t.settle_lock_height = ReadLE32(d.data() + o); o += 4;
    t.scalar_format_id = ReadLE16(d.data() + o); o += 2;
    std::copy(d.data() + o, d.data() + o + 32, t.strike.begin()); o += 32;
    std::copy(d.data() + o, d.data() + o + 32, t.fallback_scalar.begin()); o += 32;
    t.lambda_q = ReadLE32(d.data() + o); o += 4;
    std::copy(d.data() + o, d.data() + o + 32, t.collateral_asset_id.begin()); o += 32;
    t.vault_im = ReadLE64(d.data() + o); o += 8;
    std::copy(d.data() + o, d.data() + o + 32, t.long_token_id.begin()); o += 32;
    std::copy(d.data() + o, d.data() + o + 32, t.short_token_id.begin()); o += 32;
    t.lot_count = ReadLE32(d.data() + o); o += 4;
    std::copy(d.data() + o, d.data() + o + 32, t.series_salt.begin()); o += 32;
    Assume(o == kScalarNotePairDescriptorBytesV1);

    // In-range enum checks so a parsed descriptor that survives is always template-coherent (the
    // caller still recomputes the id for authenticity and runs ValidateScalarNotePairTerms).
    if (t.source_type != static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED) &&
        t.source_type != static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC)) return std::nullopt;
    if (t.payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE) &&
        t.payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)) return std::nullopt;
    if (t.loss_direction != 0x00 && t.loss_direction != 0x01) return std::nullopt;
    return t;
}

uint256 ComputeScalarNotePairId(const ScalarNotePairTerms& t)
{
    const std::vector<unsigned char> d = SerializeScalarNotePairDescriptor(t);
    HashWriter h{TaggedHash(SCALAR_NOTE_PAIR_ID_TAG)};
    h.write(MakeByteSpan(d));
    return h.GetSHA256();
}

std::string ScalarNotePairRegistryIdHex(const uint256& pair_id) { return pair_id.GetHex(); }

uint256 DeriveScalarNoteLotSalt(const uint256& pair_id, uint32_t i)
{
    std::vector<unsigned char> buf(pair_id.begin(), pair_id.end());
    AppendLE32(buf, i);
    HashWriter h{TaggedHash(SCALAR_NOTE_PAIR_LOT_TAG)};
    h.write(MakeByteSpan(buf));
    return h.GetSHA256();
}

uint256 DeriveScalarNoteContractId(const uint256& pair_id, uint32_t i)
{
    std::vector<unsigned char> buf(pair_id.begin(), pair_id.end());
    AppendLE32(buf, i);
    HashWriter h{TaggedHash(SCALAR_NOTE_PAIR_CONTRACT_TAG)};
    h.write(MakeByteSpan(buf));
    return h.GetSHA256();
}

std::pair<XOnlyPubKey, uint32_t> DeriveScalarNoteSink(const uint256& pair_id, uint32_t i, uint8_t side)
{
    for (uint32_t ctr = 0;; ++ctr) {
        std::vector<unsigned char> buf(pair_id.begin(), pair_id.end());
        AppendLE32(buf, i);
        buf.push_back(side);
        AppendLE32(buf, ctr);
        HashWriter h{TaggedHash(SCALAR_NOTE_PAIR_SINK_TAG)};
        h.write(MakeByteSpan(buf));
        const uint256 x = h.GetSHA256();
        XOnlyPubKey candidate{std::span<const unsigned char>{x.begin(), x.size()}};
        if (candidate.IsFullyValid()) return {candidate, ctr};
        // ctr wraps only after 2^32 misses (P(valid)~1/2 per try) — unreachable in practice.
    }
}

bool ValidateScalarNotePairTerms(const ScalarNotePairTerms& t, std::string& err)
{
    if (t.descriptor_version != kScalarNotePairDescriptorVersion) { err = "unsupported descriptor_version"; return false; }

    const bool is_chain = (t.source_type == static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC));
    const bool is_issuer = (t.source_type == static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED));
    if (!is_chain && !is_issuer) { err = "invalid source_type"; return false; }
    if (is_chain && !t.underlying_asset_id.IsNull()) { err = "CHAIN_INTRINSIC requires a zero underlying_asset_id"; return false; }
    if (is_issuer && t.underlying_asset_id.IsNull()) { err = "ISSUER_PUBLISHED requires a non-zero underlying_asset_id"; return false; }

    if (t.payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE) &&
        t.payoff_mode != static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)) { err = "invalid payoff_mode"; return false; }
    if (t.loss_direction != 0x00 && t.loss_direction != 0x01) { err = "invalid loss_direction"; return false; }
    if (!assets::IsKnownScalarFormat(t.scalar_format_id)) { err = "unknown scalar_format_id"; return false; }
    // Both committed literals must decode canonically under the format (as the opcode reads them at
    // settlement) — a non-canonical strike/fallback would brick the lot, so reject it at the integrity gate.
    { arith_uint256 tmp; if (!DecodeScalarValue(t.scalar_format_id, t.strike, tmp)) { err = "strike not canonical for scalar_format_id"; return false; } }
    { arith_uint256 tmp; if (!DecodeScalarValue(t.scalar_format_id, t.fallback_scalar, tmp)) { err = "fallback_scalar not canonical for scalar_format_id"; return false; } }

    if (t.lot_count == 0) { err = "lot_count must be > 0"; return false; }
    if (t.lambda_q == 0) { err = "lambda_q must be non-zero"; return false; }
    if (t.vault_im < static_cast<uint64_t>(MIN_SETTLE_OUTPUT)) { err = "vault_im below MIN_SETTLE_OUTPUT"; return false; }

    if (t.long_token_id.IsNull() || t.short_token_id.IsNull()) { err = "token ids L/S must be non-zero"; return false; }
    if (t.long_token_id == t.short_token_id) { err = "token ids L and S must differ"; return false; }
    if (t.long_token_id == t.collateral_asset_id || t.short_token_id == t.collateral_asset_id) {
        err = "token ids must differ from the collateral asset id"; return false;
    }
    // §6.2: the stored token ids MUST equal the canonical derivation. This makes them a verifiable
    // function of the terms and stops any builder/caller silently substituting forged ids.
    {
        const auto [dL, dS] = DeriveScalarNotePairTokenIds(t);
        if (t.long_token_id != dL || t.short_token_id != dS) {
            err = "token ids L/S do not match the canonical derivation"; return false;
        }
    }

    if (t.settle_lock_height < 1) { err = "settle_lock_height must be >= 1"; return false; }
    if (t.settle_lock_height >= LOCKTIME_THRESHOLD) { err = "settle_lock_height must be a block height (< LOCKTIME_THRESHOLD)"; return false; }

    // Total collateral N * vault_im must not overflow (uint64), and for NATIVE collateral it must fit
    // MoneyRange. (vault_im > 0 here from the MIN_SETTLE_OUTPUT check, so the divide is safe.)
    if (static_cast<uint64_t>(t.lot_count) > std::numeric_limits<uint64_t>::max() / t.vault_im) {
        err = "total collateral (lot_count * vault_im) overflows uint64"; return false;
    }
    const uint64_t total = static_cast<uint64_t>(t.lot_count) * t.vault_im;
    if (t.collateral_asset_id.IsNull()) {
        // Compare in uint64 BEFORE any cast: a vault_im/total above INT64_MAX would be
        // implementation-defined as a CAmount. MAX_MONEY is positive so the widening is safe.
        const uint64_t kMaxMoneyU = static_cast<uint64_t>(MAX_MONEY);
        if (t.vault_im > kMaxMoneyU || total > kMaxMoneyU) {
            err = "native total collateral out of MoneyRange"; return false;
        }
    }
    return true;
}

ScalarNoteLot DeriveScalarNoteLot(const ScalarNotePairTerms& t, const uint256& pair_id, uint32_t i)
{
    Assume(i < t.lot_count);
    ScalarNoteLot lot;
    lot.index = i;
    lot.salt = DeriveScalarNoteLotSalt(pair_id, i);
    lot.contract_id = DeriveScalarNoteContractId(pair_id, i);

    // Long side → token L → owner pot.
    std::tie(lot.long_sink_key, lot.long_sink_ctr) = DeriveScalarNoteSink(pair_id, i, SCALAR_NOTE_SIDE_LONG);
    lot.long_sink_spk = P2TR(lot.long_sink_key);
    lot.long_pot_leaf = BuildScalarPotLeaf(t.long_token_id, lot.long_sink_spk);
    TaprootBuilder long_pot_builder = CreateScalarPotBuilder(lot.long_pot_leaf);
    Assume(long_pot_builder.IsComplete());
    lot.long_pot_key = long_pot_builder.GetOutput();
    lot.long_pot_spk = P2TR(lot.long_pot_key);

    // Short side → token S → cp pot.
    std::tie(lot.short_sink_key, lot.short_sink_ctr) = DeriveScalarNoteSink(pair_id, i, SCALAR_NOTE_SIDE_SHORT);
    lot.short_sink_spk = P2TR(lot.short_sink_key);
    lot.short_pot_leaf = BuildScalarPotLeaf(t.short_token_id, lot.short_sink_spk);
    TaprootBuilder short_pot_builder = CreateScalarPotBuilder(lot.short_pot_leaf);
    Assume(short_pot_builder.IsComplete());
    lot.short_pot_key = short_pot_builder.GetOutput();
    lot.short_pot_spk = P2TR(lot.short_pot_key);

    // §6.1 capped-spread topology: ONE vault, two pots. The opcode's payout_owner + payout_cp ==
    // vault_im invariant IS the L/S split. The opcode treats the OWNER leg as long iff
    // loss_direction == 0 (interpreter.cpp: short_leg = loss_dir == 0x01), so to keep token L tracking
    // the LONG leg and token S the SHORT leg for either ramp, the owner/cp keys are assigned by
    // direction: owner = long pot when loss_direction == 0, else owner = short pot.
    const bool owner_is_long = (t.loss_direction == 0x00);
    const XOnlyPubKey& owner_pot_key = owner_is_long ? lot.long_pot_key : lot.short_pot_key;
    const XOnlyPubKey& cp_pot_key    = owner_is_long ? lot.short_pot_key : lot.long_pot_key;
    ScalarCfdLeaf settle;
    settle.contract_id = lot.contract_id;
    settle.template_version = SCALAR_CFD_TEMPLATE_VERSION_V1;
    settle.settle_lock_height = static_cast<int64_t>(t.settle_lock_height);
    settle.source_type = t.source_type;
    settle.underlying_asset_id = t.underlying_asset_id;
    settle.feed_id = t.feed_id;
    settle.fixing_ref = t.fixing_ref;
    settle.publication_deadline_height = t.publication_deadline_height;
    settle.payoff_mode = t.payoff_mode;
    settle.scalar_format_id = t.scalar_format_id;
    settle.strike = t.strike;
    settle.fallback_scalar = t.fallback_scalar;
    settle.lambda_q = t.lambda_q;
    settle.loss_direction = t.loss_direction;
    settle.collateral_asset_id = t.collateral_asset_id;
    settle.vault_im = t.vault_im;
    settle.owner_key = ToByteVector(owner_pot_key);
    settle.cp_key = ToByteVector(cp_pot_key);
    lot.settle_leaf = BuildScalarCfdLeaf(settle);

    // §6.3 permissionless complete-set unwind: retire 1 L → long sink AND 1 S → short sink (same sinks
    // the pots redeem to — burning is burning). The vault taptree is {settle, unwind}.
    lot.unwind_leaf = BuildScalarUnwindLeaf(t.long_token_id, lot.long_sink_spk,
                                            t.short_token_id, lot.short_sink_spk);
    TaprootBuilder vault_builder = CreateScalarVaultBuilder(lot.settle_leaf, lot.unwind_leaf);
    Assume(vault_builder.IsComplete());
    lot.vault_key = vault_builder.GetOutput();
    lot.vault_spk = P2TR(lot.vault_key);
    return lot;
}

std::vector<unsigned char> BuildScalarNotePairIcuMetadata(const ScalarNotePairTerms& t)
{
    const std::vector<unsigned char> descriptor = SerializeScalarNotePairDescriptor(t);

    // Machine descriptor band — the EXACT descriptor bytes (hex), the same string fed to the id hash.
    UniValue notepair(UniValue::VOBJ);
    notepair.pushKV("spec", "TSC-ICU-SCALARNOTEPAIR-1");
    notepair.pushKV("parse_version", static_cast<int64_t>(1));
    notepair.pushKV("descriptor", HexStr(descriptor));

    // Display termsheet — auto-derived from the descriptor fields so it cannot drift; NOT a binding doc.
    const bool is_chain = (t.source_type == static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC));
    const bool owner_long = (t.loss_direction == 0x00);
    UniValue termsheet(UniValue::VOBJ);
    termsheet.pushKV("spec", "TSC-ICU-TERMSHEET-1");
    termsheet.pushKV("parse_version", static_cast<int64_t>(1));
    termsheet.pushKV("instrument", "scalar-note-pair");
    termsheet.pushKV("source_type", is_chain ? "chain-intrinsic" : "issuer-published");
    termsheet.pushKV("payoff_mode", t.payoff_mode == static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED) ? "realized" : "strike");
    termsheet.pushKV("owner_leg", owner_long ? "long" : "short");
    termsheet.pushKV("underlying_asset_id", HexStr(t.underlying_asset_id));
    // Pass each field in its natural (unsigned) width — UniValue has a uint64_t setInt overload, so
    // fixing_ref / vault_im (valid up to UINT64_MAX; asset vault_im may exceed INT64_MAX) are encoded
    // losslessly, never via an implementation-defined uint64->int64 cast.
    termsheet.pushKV("feed_id", t.feed_id);
    termsheet.pushKV("fixing_ref", t.fixing_ref);
    termsheet.pushKV("scalar_format_id", t.scalar_format_id);
    termsheet.pushKV("lambda_q", t.lambda_q);
    termsheet.pushKV("collateral_asset_id", HexStr(t.collateral_asset_id));
    termsheet.pushKV("vault_im", t.vault_im);
    termsheet.pushKV("lot_count", t.lot_count);
    termsheet.pushKV("long_token_id", HexStr(t.long_token_id));
    termsheet.pushKV("short_token_id", HexStr(t.short_token_id));

    UniValue meta(UniValue::VOBJ);
    meta.pushKV("spec", "TSC-ICU-META-1");
    meta.pushKV("scalarnotepair", notepair);
    meta.pushKV("termsheet", termsheet);

    std::string err;
    auto bytes = assets::CanonicalizeIcuBandJson(meta, err);
    // Inputs are all ASCII + canonical integers, so this cannot fail; treat any failure as a bug.
    if (!bytes) throw std::runtime_error("BuildScalarNotePairIcuMetadata: " + err);
    return *bytes;
}

bool ValidateScalarNotePairRecord(const ScalarNotePairRecord& record, const uint256* expected_key, std::string& err)
{
    // Terms must be valid in their own right (includes the canonical token-id consistency check).
    if (!ValidateScalarNotePairTerms(record.terms, err)) return false;

    // The identity invariant: pair_id IS the descriptor hash, and (on load) the DB key is too.
    const uint256 derived = ComputeScalarNotePairId(record.terms);
    if (record.pair_id != derived) { err = "pair_id does not match ComputeScalarNotePairId(terms)"; return false; }
    if (expected_key != nullptr && *expected_key != derived) { err = "DB key does not match the derived pair_id"; return false; }

    // Both children must have been registered (each its own sponsorchildasset tx) and the pair issued.
    if (record.register_long_txid.IsNull()) { err = "register_long_txid is null"; return false; }
    if (record.register_short_txid.IsNull()) { err = "register_short_txid is null"; return false; }
    if (record.issue_txid.IsNull()) { err = "issue_txid is null"; return false; }

    // A persisted record is a FULLY-ISSUED snapshot: the issuance tx mints both tokens (rotating each
    // child ICU) and funds every vault, so both ICU successors and all N vaults are outputs of it. A
    // valid output reference has hash == issue_txid AND a real index (n != NULL_INDEX) — IsNull() only
    // catches the all-null outpoint, so a hash==issue_txid with n==UINT32_MAX would otherwise slip past.
    const Txid issue_txid = Txid::FromUint256(record.issue_txid);
    auto from_issue_tx = [&](const COutPoint& op) {
        return op.hash == issue_txid && op.n != COutPoint::NULL_INDEX;
    };
    if (!from_issue_tx(record.long_icu_outpoint)) { err = "long_icu_outpoint is not a valid output of issue_txid"; return false; }
    if (!from_issue_tx(record.short_icu_outpoint)) { err = "short_icu_outpoint is not a valid output of issue_txid"; return false; }
    if (record.long_icu_outpoint == record.short_icu_outpoint) { err = "long and short ICU outpoints are identical"; return false; }

    // Exactly N funded lot vaults, each a real output of the issuance tx, none duplicated (incl. vs ICUs).
    if (record.lot_vaults.size() != record.terms.lot_count) {
        err = strprintf("lot_vaults count (%u) != lot_count (%u)",
                        static_cast<unsigned>(record.lot_vaults.size()), record.terms.lot_count);
        return false;
    }
    std::set<COutPoint> seen{record.long_icu_outpoint, record.short_icu_outpoint};
    for (const auto& op : record.lot_vaults) {
        if (!from_issue_tx(op)) { err = "lot vault outpoint is not a valid output of issue_txid"; return false; }
        if (!seen.insert(op).second) { err = "duplicate lot vault / ICU outpoint"; return false; }
    }
    return true;
}

namespace {
//! MoneyRange-checked accumulation (rejects out-of-range addends AND running total).
bool AddMoney(CAmount& acc, CAmount v, std::string& err)
{
    if (!MoneyRange(v)) { err = "amount out of MoneyRange"; return false; }
    acc += v;
    if (!MoneyRange(acc)) { err = "summed amount out of MoneyRange"; return false; }
    return true;
}

//! Verify + tally token inputs (all carrying `token_id`); their native dust accrues to native_in.
bool AccumulateScalarTokenInputs(const std::vector<ScalarFundedInput>& token_inputs, const uint256& token_id,
                                 uint64_t& units, CAmount& native_in, std::set<COutPoint>& seen, std::string& err)
{
    units = 0;
    for (const auto& ti : token_inputs) {
        if (!seen.insert(ti.outpoint).second) { err = "duplicate input outpoint"; return false; }
        if (!ti.txout.HasAssetTLV()) { err = "token input is not asset-tagged"; return false; }
        const auto aid = ti.txout.AssetID();
        const auto amt = ti.txout.AssetAmount();
        if (!aid || *aid != token_id) { err = "token input carries a different asset"; return false; }
        if (!amt || *amt == 0) { err = "token input carries zero units"; return false; }
        if (*amt > std::numeric_limits<uint64_t>::max() - units) { err = "token unit sum overflow"; return false; }
        units += *amt;
        if (!AddMoney(native_in, ti.txout.nValue, err)) return false;
    }
    return true;
}

//! Verify native fee inputs (each native-only); value accrues to native_in.
bool AccumulateScalarNativeInputs(const std::vector<ScalarFundedInput>& native_inputs, CAmount& native_in,
                                  std::set<COutPoint>& seen, std::string& err)
{
    for (const auto& n : native_inputs) {
        if (!seen.insert(n.outpoint).second) { err = "duplicate input outpoint"; return false; }
        if (n.txout.HasAssetTLV()) { err = "native fee input is asset-tagged"; return false; }
        if (!AddMoney(native_in, n.txout.nValue, err)) return false;
    }
    return true;
}

//! Verify a spent child ICU carries an IssuerReg matching the committed token id + the §2.5 invariants
//! observable from the IssuerReg. (issued_total == 0 / confirmed-on-chain is the RPC's gate.)
bool VerifyIssuerIcu(const ScalarFundedInput& icu, const uint256& expected_asset_id, uint32_t N,
                     const char* side, std::string& err)
{
    const auto reg = assets::ParseIssuerReg(icu.txout.vExt);
    if (!reg) { err = strprintf("%s ICU input does not carry an IssuerReg", side); return false; }
    if (reg->asset_id != expected_asset_id) { err = strprintf("%s ICU asset_id != committed token id", side); return false; }
    // PLAIN BEARER-COUPON PROFILE. L/S must move freely through redemption/unwind, which retire them to
    // KEYLESS P2TR sinks via d==0 transfers. The family check is skipped for d==0 (tx_verify.cpp:599),
    // but the KYC and TFR-anchor passes run regardless of d — and WRAP_REQUIRED gates transfers — so a
    // sink (no key, no ZK proof, no anchor) could never satisfy them. Therefore require exactly the
    // coupon profile (same spirit as the §5.1 collateral gate, applied to the token assets):
    if (reg->policy_bits != assets::MINT_ALLOWED) {
        err = strprintf("%s token policy_bits must be exactly MINT_ALLOWED (no burn/KYC/TFR/collateral-safe bits)", side); return false;
    }
    if (reg->kyc_flags != 0) { err = strprintf("%s token must have kyc_flags == 0", side); return false; }
    if (reg->tfr_flags != 0) { err = strprintf("%s token must have tfr_flags == 0", side); return false; }
    if (reg->icu_flags != 0) { err = strprintf("%s token must have icu_flags == 0 (no WRAP_REQUIRED)", side); return false; }
    // The effective families (0 == unset → the default) must be exactly the P2TR-safe coupon default, so
    // the mint (d>0, family-checked) lands and P2TR sinks/pots/holders can receive the token.
    const uint16_t eff_families = reg->allowed_spk_families ? reg->allowed_spk_families : assets::SPK_DEFAULT_ALLOWED;
    if (eff_families != assets::SPK_DEFAULT_ALLOWED) {
        err = strprintf("%s token allowed_spk_families must be the default coupon set (P2WPKH|P2WSH|P2TR)", side); return false;
    }
    if (reg->issuance_cap_units != N) { err = strprintf("%s issuance_cap_units != lot_count", side); return false; }
    if (reg->decimals != 0) { err = strprintf("%s asset must have decimals 0", side); return false; }
    if (reg->policy_quorum_bps != 0) { err = strprintf("%s governance quorum must be 0 (immutable)", side); return false; }
    return true;
}

std::vector<unsigned char> SpkKey(const CScript& spk) { return std::vector<unsigned char>(spk.begin(), spk.end()); }

//! True iff `spk` classifies to a family within SPK_DEFAULT_ALLOWED (the coupon family set). The mint
//! outputs (d>0) are family-checked by consensus (tx_verify.cpp), so the builder preflights the mint
//! destination to never emit a tx that would later fail with "asset-spk-not-allowed".
bool MintSpkInDefaultFamily(const CScript& spk)
{
    std::vector<std::vector<unsigned char>> sols;
    uint16_t fam = 0;
    switch (Solver(spk, sols)) {
    case TxoutType::PUBKEYHASH:            fam = assets::SPK_P2PKH; break;
    case TxoutType::SCRIPTHASH:            fam = assets::SPK_P2SH; break;
    case TxoutType::WITNESS_V0_KEYHASH:    fam = assets::SPK_P2WPKH; break;
    case TxoutType::WITNESS_V0_SCRIPTHASH: fam = assets::SPK_P2WSH; break;
    case TxoutType::WITNESS_V1_TAPROOT:    fam = assets::SPK_P2TR; break;
    case TxoutType::WITNESS_V2_TAPROOT:    fam = assets::SPK_P2TR_V2; break;
    default:                               fam = 0; break;
    }
    return fam != 0 && (fam & assets::SPK_DEFAULT_ALLOWED) == fam;
}
} // namespace

bool BuildScalarNotePairIssuance(const ScalarNotePairTerms& terms, const uint256& pair_id,
                                 const ScalarNotePairIssuanceInputs& in,
                                 const CScript& long_icu_successor_spk, const CScript& short_icu_successor_spk,
                                 const CScript& issuer_token_spk, const CScript& change_spk,
                                 CAmount vault_native_sats, CAmount fee, CAmount dust,
                                 CMutableTransaction& out, std::string& err)
{
    if (!ValidateScalarNotePairTerms(terms, err)) return false;
    if (pair_id != ComputeScalarNotePairId(terms)) { err = "pair_id does not match terms"; return false; }
    if (!MoneyRange(fee)) { err = "fee out of MoneyRange"; return false; }
    if (dust < kMinAssetOutputDust || !MoneyRange(dust)) { err = "dust below floor or out of MoneyRange"; return false; }

    const uint32_t N = terms.lot_count;
    const bool native_collateral = terms.collateral_asset_id.IsNull();
    if (!native_collateral && (vault_native_sats < kMinAssetOutputDust || !MoneyRange(vault_native_sats))) {
        err = "vault_native_sats below dust or out of MoneyRange"; return false;
    }

    // Both child ICUs must carry the committed ids + §2.5 invariants (consistency check, never "fixed").
    if (!VerifyIssuerIcu(in.long_icu, terms.long_token_id, N, "long", err)) return false;
    if (!VerifyIssuerIcu(in.short_icu, terms.short_token_id, N, "short", err)) return false;
    if (in.long_icu.outpoint == in.short_icu.outpoint) { err = "long and short ICU are the same outpoint"; return false; }

    // The L and S mints (d>0) both pay issuer_token_spk; consensus family-checks them against the
    // coupon family set, so the mint destination must be in SPK_DEFAULT_ALLOWED.
    if (!MintSpkInDefaultFamily(issuer_token_spk)) {
        err = "issuer_token_spk is not in the coupon family set (mint would be rejected as asset-spk-not-allowed)"; return false;
    }

    std::set<COutPoint> seen{in.long_icu.outpoint, in.short_icu.outpoint};
    CAmount native_in = 0;
    if (!AddMoney(native_in, in.long_icu.txout.nValue, err)) return false;
    if (!AddMoney(native_in, in.short_icu.txout.nValue, err)) return false;

    // Collateral C accounting (asset collateral only). vault_im > 0 and N*vault_im fits per Validate.
    const uint64_t collateral_needed = static_cast<uint64_t>(N) * terms.vault_im;
    uint64_t collateral_in = 0;
    if (native_collateral) {
        if (!in.collateral_inputs.empty()) { err = "native collateral takes no collateral_inputs"; return false; }
    } else {
        for (const auto& ci : in.collateral_inputs) {
            if (!seen.insert(ci.outpoint).second) { err = "duplicate input outpoint"; return false; }
            if (!ci.txout.HasAssetTLV()) { err = "collateral input is not asset-tagged"; return false; }
            const auto aid = ci.txout.AssetID();
            const auto amt = ci.txout.AssetAmount();
            if (!aid || *aid != terms.collateral_asset_id) { err = "collateral input carries a different asset"; return false; }
            if (!amt || *amt == 0) { err = "collateral input carries zero units"; return false; }
            if (*amt > std::numeric_limits<uint64_t>::max() - collateral_in) { err = "collateral unit sum overflow"; return false; }
            collateral_in += *amt;
            if (!AddMoney(native_in, ci.txout.nValue, err)) return false;
        }
        if (collateral_in < collateral_needed) { err = "insufficient collateral C for N vaults"; return false; }
    }
    const uint64_t collateral_change = native_collateral ? 0 : (collateral_in - collateral_needed);
    const bool has_c_change = collateral_change > 0;

    for (const auto& ni : in.native_inputs) {
        if (!seen.insert(ni.outpoint).second) { err = "duplicate input outpoint"; return false; }
        if (ni.txout.HasAssetTLV()) { err = "native fee input is asset-tagged"; return false; }
        if (!AddMoney(native_in, ni.txout.nValue, err)) return false;
    }

    // Output-count + asset-output preflight (mirror option-series N+const cap).
    const size_t asset_outputs = 2u /*L,S mint*/ + (native_collateral ? 0u : static_cast<size_t>(N)) + (has_c_change ? 1u : 0u);
    if (asset_outputs > kDefaultMaxAssetsPerTx) { err = "too many asset outputs for one issuance tx (64 cap)"; return false; }
    const size_t base_outputs = 2u /*ICU succ*/ + 2u /*mint*/ + static_cast<size_t>(N) /*vaults*/ + (has_c_change ? 1u : 0u);
    if (base_outputs + 1u > MAX_COVENANT_TX_OUTPUTS) { err = "too many outputs for one issuance tx"; return false; }

    // Native balance: bonds (self-funded by the ICU inputs) + 2 mint dust + N vault carriers + C-change dust.
    const CAmount l_bond = in.long_icu.txout.nValue;
    const CAmount s_bond = in.short_icu.txout.nValue;
    const CAmount vault_native_each = native_collateral ? static_cast<CAmount>(terms.vault_im) : vault_native_sats;
    CAmount native_out_fixed = 0;
    if (!AddMoney(native_out_fixed, l_bond, err)) return false;
    if (!AddMoney(native_out_fixed, s_bond, err)) return false;
    if (!AddMoney(native_out_fixed, dust, err)) return false; // L mint dust
    if (!AddMoney(native_out_fixed, dust, err)) return false; // S mint dust (added separately: 2*dust could overflow)
    if (vault_native_each != 0 &&
        static_cast<uint64_t>(N) > static_cast<uint64_t>(MAX_MONEY) / static_cast<uint64_t>(vault_native_each)) {
        err = "vault native funding overflow"; return false;
    }
    if (!AddMoney(native_out_fixed, static_cast<CAmount>(N) * vault_native_each, err)) return false;
    if (has_c_change && !AddMoney(native_out_fixed, dust, err)) return false;

    const CAmount native_change = native_in - native_out_fixed - fee;
    if (native_change < 0) { err = "native inputs do not cover bonds + vault funding + dust + fee"; return false; }
    if (native_change > 0 && native_change < kMinAssetOutputDust) {
        err = "native change would be dust; add native input or raise fee"; return false;
    }

    // Assemble: ICU successors (vExt reused byte-identical), L/S mints, N vaults, C/native change.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(in.long_icu.outpoint);
    mtx.vin.emplace_back(in.short_icu.outpoint);
    for (const auto& ci : in.collateral_inputs) mtx.vin.emplace_back(ci.outpoint);
    for (const auto& ni : in.native_inputs) mtx.vin.emplace_back(ni.outpoint);

    { CTxOut o(l_bond, long_icu_successor_spk);  o.vExt = in.long_icu.txout.vExt;  mtx.vout.push_back(std::move(o)); }
    { CTxOut o(s_bond, short_icu_successor_spk); o.vExt = in.short_icu.txout.vExt; mtx.vout.push_back(std::move(o)); }
    { CTxOut o(dust, issuer_token_spk); o.vExt = assets::BuildAssetTagTlv(terms.long_token_id, N);  mtx.vout.push_back(std::move(o)); }
    { CTxOut o(dust, issuer_token_spk); o.vExt = assets::BuildAssetTagTlv(terms.short_token_id, N); mtx.vout.push_back(std::move(o)); }
    for (uint32_t i = 0; i < N; ++i) {
        const ScalarNoteLot lot = DeriveScalarNoteLot(terms, pair_id, i);
        CTxOut o(vault_native_each, lot.vault_spk);
        if (!native_collateral) o.vExt = assets::BuildAssetTagTlv(terms.collateral_asset_id, terms.vault_im);
        mtx.vout.push_back(std::move(o));
    }
    if (has_c_change) { CTxOut o(dust, change_spk); o.vExt = assets::BuildAssetTagTlv(terms.collateral_asset_id, collateral_change); mtx.vout.push_back(std::move(o)); }
    if (native_change > 0) mtx.vout.emplace_back(native_change, change_spk);

    // Self-check: the assembled tx MUST satisfy the output-side atomicity invariant, so future builder
    // drift can never emit an issuance the record layer would reject.
    if (!ValidateScalarNotePairIssuanceTx(terms, pair_id, CTransaction{mtx}, err)) {
        err = "internal: built issuance tx fails ValidateScalarNotePairIssuanceTx: " + err;
        return false;
    }

    out = std::move(mtx);
    return true;
}

bool ValidateScalarNotePairIssuanceTx(const ScalarNotePairTerms& terms, const uint256& pair_id,
                                      const CTransaction& tx, std::string& err)
{
    if (!ValidateScalarNotePairTerms(terms, err)) return false;
    if (pair_id != ComputeScalarNotePairId(terms)) { err = "pair_id does not match terms"; return false; }
    const uint32_t N = terms.lot_count;
    const bool native_collateral = terms.collateral_asset_id.IsNull();

    // The N derived vault scriptPubKeys, each to be funded exactly once.
    std::map<std::vector<unsigned char>, bool> vault_matched;
    for (uint32_t i = 0; i < N; ++i) vault_matched.emplace(SpkKey(DeriveScalarNoteLot(terms, pair_id, i).vault_spk), false);
    if (vault_matched.size() != N) { err = "internal: derived vault scriptPubKey collision"; return false; }

    size_t l_succ = 0, s_succ = 0, vaults = 0;
    uint64_t l_minted = 0, s_minted = 0;
    for (const auto& o : tx.vout) {
        if (const auto reg = assets::ParseIssuerReg(o.vExt)) {
            if (reg->asset_id == terms.long_token_id) ++l_succ;
            else if (reg->asset_id == terms.short_token_id) ++s_succ;
            continue;
        }
        if (o.HasAssetTLV()) {
            const auto aid = o.AssetID();
            const auto amt = o.AssetAmount();
            if (!aid || !amt) continue;
            if (*aid == terms.long_token_id) {
                if (*amt > std::numeric_limits<uint64_t>::max() - l_minted) { err = "AssetTag(L) output sum overflow"; return false; }
                l_minted += *amt; continue;
            }
            if (*aid == terms.short_token_id) {
                if (*amt > std::numeric_limits<uint64_t>::max() - s_minted) { err = "AssetTag(S) output sum overflow"; return false; }
                s_minted += *amt; continue;
            }
            if (!native_collateral && *aid == terms.collateral_asset_id) {
                auto it = vault_matched.find(SpkKey(o.scriptPubKey));
                if (it != vault_matched.end() && *amt == terms.vault_im && o.nValue >= kMinAssetOutputDust) {
                    if (it->second) { err = "duplicate vault output"; return false; }
                    it->second = true; ++vaults;
                }
            }
            continue;
        }
        // Native output: a NATIVE-collateral vault has nValue == vault_im and no AssetTag.
        if (native_collateral && o.nValue >= 0 && static_cast<uint64_t>(o.nValue) == terms.vault_im) {
            auto it = vault_matched.find(SpkKey(o.scriptPubKey));
            if (it != vault_matched.end()) {
                if (it->second) { err = "duplicate vault output"; return false; }
                it->second = true; ++vaults;
            }
        }
    }

    if (l_succ != 1) { err = "expected exactly one L IssuerReg successor"; return false; }
    if (s_succ != 1) { err = "expected exactly one S IssuerReg successor"; return false; }
    if (l_minted != N) { err = strprintf("minted L units (%llu) != lot_count (%u)", (unsigned long long)l_minted, N); return false; }
    if (s_minted != N) { err = strprintf("minted S units (%llu) != lot_count (%u)", (unsigned long long)s_minted, N); return false; }
    if (vaults != N) { err = strprintf("funded vaults (%u) != lot_count (%u)", (unsigned)vaults, N); return false; }
    return true;
}

bool BuildScalarNoteRedemption(const ScalarNotePairTerms& terms, const uint256& pair_id, bool redeem_long,
                               const std::vector<ScalarRedemptionPot>& pots,
                               const std::vector<ScalarFundedInput>& token_inputs,
                               const std::vector<ScalarFundedInput>& native_inputs,
                               const CScript& holder_spk, CAmount fee, CAmount dust,
                               CMutableTransaction& out, std::string& err)
{
    if (!ValidateScalarNotePairTerms(terms, err)) return false;
    if (pair_id != ComputeScalarNotePairId(terms)) { err = "pair_id does not match terms"; return false; }
    const uint64_t k = pots.size();
    if (k == 0) { err = "no pots to redeem"; return false; }
    if (token_inputs.empty()) { err = "no token inputs"; return false; }
    if (!MoneyRange(fee)) { err = "fee out of MoneyRange"; return false; }
    if (dust < kMinAssetOutputDust || !MoneyRange(dust)) { err = "dust below floor or out of MoneyRange"; return false; }

    const bool native_collateral = terms.collateral_asset_id.IsNull();
    const uint256 token_id = redeem_long ? terms.long_token_id : terms.short_token_id;

    // Verify + spend each pot up front (derived spk, collateral encoding, dup-outpoint, dup-lot).
    std::set<COutPoint> seen;
    std::set<uint32_t> seen_lots;
    std::vector<ScalarNoteLot> lots;
    lots.reserve(k);
    CAmount native_in = 0;
    uint64_t collateral_in = 0;
    CMutableTransaction mtx;
    for (const auto& rp : pots) {
        if (rp.lot_index >= terms.lot_count) { err = "pot lot_index out of range"; return false; }
        if (!seen_lots.insert(rp.lot_index).second) { err = "duplicate lot_index in redemption"; return false; }
        if (!seen.insert(rp.pot.outpoint).second) { err = "duplicate input outpoint"; return false; }
        ScalarNoteLot lot = DeriveScalarNoteLot(terms, pair_id, rp.lot_index);
        const CScript& pot_spk = redeem_long ? lot.long_pot_spk : lot.short_pot_spk;
        const CScript& pot_leaf = redeem_long ? lot.long_pot_leaf : lot.short_pot_leaf;
        if (rp.pot.txout.scriptPubKey != pot_spk) { err = "pot UTXO does not match the derived lot pot"; return false; }
        if (native_collateral) {
            if (rp.pot.txout.HasAssetTLV()) { err = "native pot is asset-tagged"; return false; }
        } else {
            const auto aid = rp.pot.txout.AssetID();
            const auto amt = rp.pot.txout.AssetAmount();
            if (!aid || *aid != terms.collateral_asset_id) { err = "pot carries the wrong collateral asset"; return false; }
            if (!amt || *amt == 0) { err = "pot carries zero collateral"; return false; }
            if (*amt > std::numeric_limits<uint64_t>::max() - collateral_in) { err = "collateral sum overflow"; return false; }
            collateral_in += *amt;
        }
        if (!AddMoney(native_in, rp.pot.txout.nValue, err)) return false;

        TaprootBuilder pb = CreateScalarPotBuilder(pot_leaf);
        if (!pb.IsComplete()) { err = "pot builder incomplete"; return false; }
        const std::vector<unsigned char> leafvec(pot_leaf.begin(), pot_leaf.end());
        const TaprootSpendData spend = pb.GetSpendData();
        const auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
        if (it == spend.scripts.end() || it->second.empty()) { err = "could not reconstruct pot control block"; return false; }
        CTxIn vin(rp.pot.outpoint);
        vin.scriptWitness.stack = {leafvec, *it->second.begin()}; // signatureless covenant spend
        mtx.vin.push_back(std::move(vin));
        lots.push_back(std::move(lot));
    }

    uint64_t m = 0;
    if (!AccumulateScalarTokenInputs(token_inputs, token_id, m, native_in, seen, err)) return false;
    if (m < k) { err = "insufficient token units for the requested pots"; return false; }
    const bool token_change = m > k;
    if (!AccumulateScalarNativeInputs(native_inputs, native_in, seen, err)) return false;

    for (const auto& ti : token_inputs) mtx.vin.emplace_back(ti.outpoint);
    for (const auto& n : native_inputs) mtx.vin.emplace_back(n.outpoint);

    // Asset outputs: k sink retirements + token change + (asset collateral → 1 C payout).
    const size_t asset_outputs = static_cast<size_t>(k) + (token_change ? 1u : 0u) + (native_collateral ? 0u : 1u);
    if (asset_outputs > kDefaultMaxAssetsPerTx) { err = "too many asset outputs for one tx (64 cap)"; return false; }
    if (asset_outputs + 1u > MAX_COVENANT_TX_OUTPUTS) { err = "too many outputs for one redemption tx"; return false; }

    // Aggregate per-output dust via AddMoney (MoneyRange-checked each step) — never `asset_outputs * dust`,
    // which could overflow CAmount before a range check since dust is only bounded by MoneyRange.
    CAmount asset_out_dust = 0;
    for (size_t i = 0; i < asset_outputs; ++i) {
        if (!AddMoney(asset_out_dust, dust, err)) return false;
    }
    const CAmount native_sweep = native_in - fee - asset_out_dust; // native collateral folds into this sweep
    if (native_sweep < 0) { err = "inputs do not cover fee + per-output dust"; return false; }
    if (native_sweep > 0 && native_sweep < kMinAssetOutputDust) {
        err = "native sweep would be dust; add native input or raise fee"; return false;
    }

    // Retire exactly 1 token unit to each pot's unique sink.
    for (const auto& lot : lots) {
        const CScript& sink_spk = redeem_long ? lot.long_sink_spk : lot.short_sink_spk;
        CTxOut o(dust, sink_spk);
        o.vExt = assets::BuildAssetTagTlv(token_id, 1);
        mtx.vout.push_back(std::move(o));
    }
    if (token_change) {
        CTxOut o(dust, holder_spk);
        o.vExt = assets::BuildAssetTagTlv(token_id, m - k);
        mtx.vout.push_back(std::move(o));
    }
    if (!native_collateral) {
        // Reclaimed collateral C (Σ pot legs) to the holder; native value flows via the sweep.
        CTxOut o(dust, holder_spk);
        o.vExt = assets::BuildAssetTagTlv(terms.collateral_asset_id, collateral_in);
        mtx.vout.push_back(std::move(o));
    }
    if (native_sweep > 0) mtx.vout.emplace_back(native_sweep, holder_spk);

    out = std::move(mtx);
    return true;
}

bool BuildScalarUnwind(const ScalarNotePairTerms& terms, const uint256& pair_id, uint32_t lot_index,
                       const ScalarFundedInput& vault,
                       const std::vector<ScalarFundedInput>& long_token_inputs,
                       const std::vector<ScalarFundedInput>& short_token_inputs,
                       const std::vector<ScalarFundedInput>& native_inputs,
                       const CScript& holder_spk, CAmount fee, CAmount dust,
                       CMutableTransaction& out, std::string& err)
{
    if (!ValidateScalarNotePairTerms(terms, err)) return false;
    if (pair_id != ComputeScalarNotePairId(terms)) { err = "pair_id does not match terms"; return false; }
    if (lot_index >= terms.lot_count) { err = "lot_index out of range"; return false; }
    if (!MoneyRange(fee)) { err = "fee out of MoneyRange"; return false; }
    if (dust < kMinAssetOutputDust || !MoneyRange(dust)) { err = "dust below floor or out of MoneyRange"; return false; }
    if (long_token_inputs.empty() || short_token_inputs.empty()) { err = "unwind needs both L and S token inputs"; return false; }

    const bool native_collateral = terms.collateral_asset_id.IsNull();
    const ScalarNoteLot lot = DeriveScalarNoteLot(terms, pair_id, lot_index);
    if (vault.txout.scriptPubKey != lot.vault_spk) { err = "vault UTXO does not match the derived lot vault"; return false; }
    if (native_collateral) {
        if (vault.txout.HasAssetTLV()) { err = "native vault is asset-tagged"; return false; }
        if (vault.txout.nValue < 0 || static_cast<uint64_t>(vault.txout.nValue) != terms.vault_im) {
            err = "native vault value != vault_im"; return false;
        }
    } else {
        const auto aid = vault.txout.AssetID();
        const auto amt = vault.txout.AssetAmount();
        if (!aid || *aid != terms.collateral_asset_id) { err = "vault carries the wrong collateral asset"; return false; }
        if (!amt || *amt != terms.vault_im) { err = "vault collateral != vault_im"; return false; }
    }

    std::set<COutPoint> seen{vault.outpoint};
    CAmount native_in = 0;
    if (!AddMoney(native_in, vault.txout.nValue, err)) return false;

    uint64_t m_long = 0, m_short = 0;
    if (!AccumulateScalarTokenInputs(long_token_inputs, terms.long_token_id, m_long, native_in, seen, err)) return false;
    if (m_long < 1) { err = "unwind needs at least 1 L unit"; return false; }
    if (!AccumulateScalarTokenInputs(short_token_inputs, terms.short_token_id, m_short, native_in, seen, err)) return false;
    if (m_short < 1) { err = "unwind needs at least 1 S unit"; return false; }
    if (!AccumulateScalarNativeInputs(native_inputs, native_in, seen, err)) return false;

    // Control block for the UNWIND leaf within the {settle, unwind} taptree (no signature).
    TaprootBuilder vb = CreateScalarVaultBuilder(lot.settle_leaf, lot.unwind_leaf);
    if (!vb.IsComplete()) { err = "vault builder incomplete"; return false; }
    const std::vector<unsigned char> leafvec(lot.unwind_leaf.begin(), lot.unwind_leaf.end());
    const TaprootSpendData spend = vb.GetSpendData();
    const auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    if (it == spend.scripts.end() || it->second.empty()) { err = "could not reconstruct unwind control block"; return false; }
    const std::vector<unsigned char> control = *it->second.begin();

    const bool long_change = m_long > 1, short_change = m_short > 1;
    const size_t asset_outputs = 2u /*L,S sinks*/ + (long_change ? 1u : 0u) + (short_change ? 1u : 0u) + (native_collateral ? 0u : 1u);
    if (asset_outputs > kDefaultMaxAssetsPerTx) { err = "too many asset outputs for one tx (64 cap)"; return false; }
    if (asset_outputs + 1u > MAX_COVENANT_TX_OUTPUTS) { err = "too many outputs for one unwind tx"; return false; }

    CAmount asset_out_dust = 0;
    for (size_t i = 0; i < asset_outputs; ++i) {
        if (!AddMoney(asset_out_dust, dust, err)) return false;
    }
    const CAmount native_sweep = native_in - fee - asset_out_dust; // native collateral folds into this sweep
    if (native_sweep < 0) { err = "inputs do not cover fee + per-output dust"; return false; }
    if (native_sweep > 0 && native_sweep < kMinAssetOutputDust) {
        err = "native sweep would be dust; add native input or raise fee"; return false;
    }

    CMutableTransaction mtx;
    CTxIn vin(vault.outpoint);
    vin.scriptWitness.stack = {leafvec, control}; // permissionless: no signature
    mtx.vin.push_back(std::move(vin));
    for (const auto& ti : long_token_inputs) mtx.vin.emplace_back(ti.outpoint);
    for (const auto& ti : short_token_inputs) mtx.vin.emplace_back(ti.outpoint);
    for (const auto& n : native_inputs) mtx.vin.emplace_back(n.outpoint);

    // Retire the complete set: 1 L → long sink, 1 S → short sink.
    { CTxOut o(dust, lot.long_sink_spk);  o.vExt = assets::BuildAssetTagTlv(terms.long_token_id, 1);  mtx.vout.push_back(std::move(o)); }
    { CTxOut o(dust, lot.short_sink_spk); o.vExt = assets::BuildAssetTagTlv(terms.short_token_id, 1); mtx.vout.push_back(std::move(o)); }
    if (long_change)  { CTxOut o(dust, holder_spk); o.vExt = assets::BuildAssetTagTlv(terms.long_token_id, m_long - 1);  mtx.vout.push_back(std::move(o)); }
    if (short_change) { CTxOut o(dust, holder_spk); o.vExt = assets::BuildAssetTagTlv(terms.short_token_id, m_short - 1); mtx.vout.push_back(std::move(o)); }
    if (!native_collateral) {
        CTxOut o(dust, holder_spk); o.vExt = assets::BuildAssetTagTlv(terms.collateral_asset_id, terms.vault_im); mtx.vout.push_back(std::move(o));
    }
    if (native_sweep > 0) mtx.vout.emplace_back(native_sweep, holder_spk);

    out = std::move(mtx);
    return true;
}

} // namespace wallet
