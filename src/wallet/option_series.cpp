// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/option_series.h>

#include <addresstype.h>          // WitnessV1Taproot, GetScriptForDestination
#include <assets/icu_payload.h>   // CanonicalizeIcuBandJson (TSC-ICU-META-1 container)
#include <consensus/amount.h>     // MoneyRange, MAX_MONEY
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT
#include <crypto/common.h>        // WriteLE32 / WriteLE64
#include <hash.h>                 // HashWriter, TaggedHash
#include <policy/policy.h>        // MAX_COVENANT_TX_OUTPUTS
#include <pow.h>                  // DeriveTarget
#include <script/interpreter.h>   // TAPROOT_LEAF_TAPSCRIPT, ComputeTapMatch
#include <span.h>                 // MakeByteSpan
#include <tinyformat.h>           // strprintf
#include <util/check.h>           // Assume
#include <util/strencodings.h>    // HexStr
#include <util/transaction_identifier.h> // Txid (issue_txid coherence)
#include <assets/asset.h>         // assets::BuildAssetTagTlv (2-arg, plaintext)
#include <key_io.h>               // DecodeDestination (RPC param layer)
#include <rpc/request.h>          // JSONRPCError (RPC param layer)
#include <rpc/util.h>             // AmountFromValue (RPC param layer)

#include <univalue.h>

#include <variant>                // std::get_if (RPC param layer)

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <set>                    // std::set (duplicate-outpoint guard)
#include <span>                   // std::span
#include <tuple>                  // std::tie

namespace wallet {

namespace {
void AppendLE32(std::vector<unsigned char>& v, uint32_t x)
{
    unsigned char b[4];
    WriteLE32(b, x);
    v.insert(v.end(), b, b + 4);
}
void AppendLE64(std::vector<unsigned char>& v, uint64_t x)
{
    unsigned char b[8];
    WriteLE64(b, x);
    v.insert(v.end(), b, b + 8);
}
//! The OUTPUTMATCH_ASSET operand: exactly 1 raw unit, 8-byte little-endian (decimals == 0).
std::vector<unsigned char> OneUnitLE()
{
    std::vector<unsigned char> v;
    AppendLE64(v, 1);
    return v;
}
std::vector<unsigned char> LeafBytes(const CScript& s) { return std::vector<unsigned char>(s.begin(), s.end()); }

//! Conservative standardness floor for an asset / sweep output. The RPC may pass a higher
//! policy-computed dust; the builder refuses anything below this and emits no dust output.
constexpr CAmount kMinAssetOutputDust = 546;
//! Mirrors the `-policymaxassetspertx` default (policy.cpp): a tx is non-standard above this many
//! AssetTag outputs (review finding #5). This is the conservative DEFAULT; an RPC on a node with a
//! configured `-policymaxassetspertx` should pass that runtime value instead of relying on this.
constexpr size_t kDefaultMaxAssetsPerTx = 64;

//! MoneyRange-checked accumulation (review finding #1): rejects out-of-range addends AND an
//! out-of-range running total, so no negative or overflowing native input slips through.
bool AddMoney(CAmount& acc, CAmount v, std::string& err)
{
    if (!MoneyRange(v)) { err = "input amount out of MoneyRange"; return false; }
    acc += v;
    if (!MoneyRange(acc)) { err = "summed input amount out of MoneyRange"; return false; }
    return true;
}

//! Verify + tally token inputs: each must be unique, carry AssetTag(series_id) with non-zero units,
//! and its native dust value accrues to `native_in`. Sums units with overflow guard (findings #2/#1).
bool AccumulateTokenInputs(const std::vector<FundedOutput>& token_inputs, const uint256& series_id,
                           uint64_t& units, CAmount& native_in, std::set<COutPoint>& seen, std::string& err)
{
    units = 0;
    for (const auto& ti : token_inputs) {
        if (!seen.insert(ti.outpoint).second) { err = "duplicate input outpoint"; return false; }
        if (!ti.txout.HasAssetTLV()) { err = "token input is not asset-tagged"; return false; }
        const auto aid = ti.txout.AssetID();
        const auto amt = ti.txout.AssetAmount();
        if (!aid || *aid != series_id) { err = "token input carries a different asset"; return false; }
        if (!amt || *amt == 0) { err = "token input carries zero units"; return false; }
        if (*amt > std::numeric_limits<uint64_t>::max() - units) { err = "token unit sum overflow"; return false; }
        units += *amt;
        if (!AddMoney(native_in, ti.txout.nValue, err)) return false;
    }
    return true;
}

//! Verify native fee inputs: each must be unique and native-only (no AssetTag — finding #3); its
//! value accrues to `native_in`.
bool AccumulateNativeInputs(const std::vector<FundedOutput>& native_inputs, CAmount& native_in,
                            std::set<COutPoint>& seen, std::string& err)
{
    for (const auto& n : native_inputs) {
        if (!seen.insert(n.outpoint).second) { err = "duplicate input outpoint"; return false; }
        if (n.txout.HasAssetTLV()) { err = "native fee input is asset-tagged"; return false; }
        if (!AddMoney(native_in, n.txout.nValue, err)) return false;
    }
    return true;
}
} // namespace

std::vector<unsigned char> SerializeOptionDescriptor(const OptionSeriesTerms& t)
{
    std::vector<unsigned char> d;
    d.reserve(103);
    d.push_back(t.descriptor_version);
    d.push_back(t.issuance_mode);
    d.push_back(t.leaf_set);
    d.insert(d.end(), t.writer_key.begin(), t.writer_key.end());   // 32
    AppendLE32(d, t.strike_nbits);
    AppendLE32(d, t.fixing_height);
    AppendLE32(d, t.settle_lock_height);
    AppendLE32(d, t.lambda_q);
    AppendLE64(d, static_cast<uint64_t>(t.lot_im_sats));
    AppendLE32(d, t.lot_count);
    AppendLE64(d, static_cast<uint64_t>(t.reference_premium_sats));
    d.insert(d.end(), t.series_salt.begin(), t.series_salt.end()); // 32  -> 103 bytes
    // v2 appends the call/put direction byte; v1 stays the frozen 103-byte (implicitly CALL) descriptor.
    if (t.descriptor_version >= kOptionDescriptorVersionDirectional) {
        d.push_back(t.direction);
    }
    Assume(d.size() == (t.descriptor_version >= kOptionDescriptorVersionDirectional ? 104u : 103u));
    return d;
}

std::optional<OptionSeriesTerms> ParseOptionSeriesDescriptor(std::span<const unsigned char> d)
{
    if (d.size() != 103 && d.size() != 104) return std::nullopt;
    const bool has_direction = (d.size() == 104);
    // The version byte and the length must agree: a directional (104-byte) descriptor is v2+, and a
    // 103-byte one must be v1 (no trailing direction).
    if (has_direction && d[0] < kOptionDescriptorVersionDirectional) return std::nullopt;
    if (!has_direction && d[0] >= kOptionDescriptorVersionDirectional) return std::nullopt;

    OptionSeriesTerms t;
    size_t o = 0;
    t.descriptor_version = d[o++];
    t.issuance_mode = d[o++];
    t.leaf_set = d[o++];
    t.writer_key = XOnlyPubKey(std::span<const unsigned char>(d.data() + o, 32)); o += 32;
    t.strike_nbits = ReadLE32(d.data() + o); o += 4;
    t.fixing_height = ReadLE32(d.data() + o); o += 4;
    t.settle_lock_height = ReadLE32(d.data() + o); o += 4;
    t.lambda_q = ReadLE32(d.data() + o); o += 4;
    t.lot_im_sats = static_cast<CAmount>(ReadLE64(d.data() + o)); o += 8;
    t.lot_count = ReadLE32(d.data() + o); o += 4;
    t.reference_premium_sats = static_cast<CAmount>(ReadLE64(d.data() + o)); o += 8;
    std::copy(d.data() + o, d.data() + o + 32, t.series_salt.begin()); o += 32;
    Assume(o == 103);
    if (has_direction) {
        t.direction = d[o++];
        if (t.direction != OPTION_DIRECTION_CALL && t.direction != OPTION_DIRECTION_PUT) return std::nullopt;
    } else {
        t.direction = OPTION_DIRECTION_CALL;
    }
    return t;
}

uint256 ComputeOptionSeriesId(const OptionSeriesTerms& t)
{
    const std::vector<unsigned char> d = SerializeOptionDescriptor(t);
    HashWriter h{TaggedHash(OPTION_SERIES_ID_TAG)};
    h.write(MakeByteSpan(d));
    return h.GetSHA256();
}

std::string OptionSeriesRegistryIdHex(const uint256& series_id)
{
    return series_id.GetHex();
}

std::vector<unsigned char> BuildOptionSeriesIcuMetadata(const OptionSeriesTerms& t)
{
    const std::vector<unsigned char> descriptor = SerializeOptionDescriptor(t);

    // §6.2 machine descriptor band — the EXACT §2 bytes (hex), the same string fed to §3's TaggedHash.
    UniValue optseries(UniValue::VOBJ);
    optseries.pushKV("spec", "TSC-ICU-OPTSERIES-1");
    optseries.pushKV("parse_version", static_cast<int64_t>(1));
    optseries.pushKV("descriptor", HexStr(descriptor));

    // §6.3 display termsheet — auto-derived from §2 fields so it cannot drift; NOT a binding doc.
    const bool is_put = (t.direction == OPTION_DIRECTION_PUT);
    UniValue disclosures(UniValue::VARR);
    disclosures.push_back(is_put ? "covered-put-not-future" : "covered-call-not-future");
    disclosures.push_back("zero-writer-default-risk");
    disclosures.push_back("decimals-0");
    UniValue termsheet(UniValue::VOBJ);
    termsheet.pushKV("spec", "TSC-ICU-TERMSHEET-1");
    termsheet.pushKV("parse_version", static_cast<int64_t>(1));
    termsheet.pushKV("option_kind", is_put ? "put" : "call");
    termsheet.pushKV("strike_nbits", static_cast<int64_t>(t.strike_nbits));
    termsheet.pushKV("fixing_height", static_cast<int64_t>(t.fixing_height));
    termsheet.pushKV("settle_lock_height", static_cast<int64_t>(t.settle_lock_height));
    termsheet.pushKV("lambda_q", static_cast<int64_t>(t.lambda_q));
    termsheet.pushKV("lot_count", static_cast<int64_t>(t.lot_count));
    termsheet.pushKV("lot_im_sats", static_cast<int64_t>(t.lot_im_sats));
    termsheet.pushKV("reference_premium_sats", static_cast<int64_t>(t.reference_premium_sats));
    termsheet.pushKV("payout_cap_per_lot_sats", static_cast<int64_t>(t.lot_im_sats)); // covered option: payout ∈ [0, im]
    termsheet.pushKV("disclosures", disclosures);

    UniValue meta(UniValue::VOBJ);
    meta.pushKV("spec", "TSC-ICU-META-1");
    meta.pushKV("optseries", optseries);
    meta.pushKV("termsheet", termsheet);

    std::string err;
    auto bytes = assets::CanonicalizeIcuBandJson(meta, err);
    // Inputs are all ASCII + canonical integers, so this cannot fail; treat any failure as a bug.
    if (!bytes) throw std::runtime_error("BuildOptionSeriesIcuMetadata: " + err);
    return *bytes;
}

uint256 DeriveOptionLotSalt(const uint256& series_id, uint32_t i)
{
    std::vector<unsigned char> buf(series_id.begin(), series_id.end());
    AppendLE32(buf, i);
    HashWriter h{TaggedHash(OPTION_SERIES_LOT_TAG)};
    h.write(MakeByteSpan(buf));
    return h.GetSHA256();
}

std::pair<XOnlyPubKey, uint32_t> DeriveOptionSink(const uint256& series_id, uint32_t i)
{
    for (uint32_t ctr = 0;; ++ctr) {
        std::vector<unsigned char> buf(series_id.begin(), series_id.end());
        AppendLE32(buf, i);
        AppendLE32(buf, ctr);
        HashWriter h{TaggedHash(OPTION_SERIES_SINK_TAG)};
        h.write(MakeByteSpan(buf));
        const uint256 x = h.GetSHA256();
        XOnlyPubKey candidate{std::span<const unsigned char>{x.begin(), x.size()}};
        if (candidate.IsFullyValid()) return {candidate, ctr};
        // ctr wraps only after 2^32 misses (P(valid)~1/2 per try) — unreachable in practice.
    }
}

CScript BuildOptionPotLeaf(const uint256& asset_id, const CScript& sink_spk)
{
    const uint256 tap_match = ComputeTapMatch(sink_spk);
    CScript s;
    s << std::vector<unsigned char>(tap_match.begin(), tap_match.end())
      << std::vector<unsigned char>(asset_id.begin(), asset_id.end())
      << OneUnitLE()
      << OP_OUTPUTMATCH_ASSET;
    return s;
}

CScript BuildOptionBuybackLeaf(const XOnlyPubKey& writer_key, const uint256& asset_id, const CScript& sink_spk)
{
    const uint256 tap_match = ComputeTapMatch(sink_spk);
    CScript s;
    s << std::vector<unsigned char>(writer_key.begin(), writer_key.end())
      << OP_CHECKSIGVERIFY
      << std::vector<unsigned char>(tap_match.begin(), tap_match.end())
      << std::vector<unsigned char>(asset_id.begin(), asset_id.end())
      << OneUnitLE()
      << OP_OUTPUTMATCH_ASSET;
    return s;
}

TaprootBuilder CreateOptionPotBuilder(const CScript& pot_leaf)
{
    TaprootBuilder b;
    b.Add(0, LeafBytes(pot_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    b.Finalize(XOnlyPubKey::NUMS_H);
    return b;
}

TaprootBuilder CreateOptionVaultBuilder(const CScript& settle_leaf, const CScript& buyback_leaf)
{
    TaprootBuilder b;
    if (buyback_leaf.empty()) {
        // D1-a: settle-only, single depth-0 leaf.
        b.Add(0, LeafBytes(settle_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    } else {
        // D1-b: settle + buy-back, both at depth 1 (order does not affect the BIP341 root).
        b.Add(1, LeafBytes(settle_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        b.Add(1, LeafBytes(buyback_leaf), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    }
    b.Finalize(XOnlyPubKey::NUMS_H);
    return b;
}

bool ValidateOptionSeriesTerms(const OptionSeriesTerms& t, const uint256* pow_limit, std::string& err)
{
    if (t.descriptor_version != kOptionDescriptorVersion && t.descriptor_version != kOptionDescriptorVersionDirectional) {
        err = "unsupported descriptor_version"; return false;
    }
    if (t.direction != OPTION_DIRECTION_CALL && t.direction != OPTION_DIRECTION_PUT) { err = "invalid direction"; return false; }
    // The direction byte only exists in the v2 descriptor, so a put cannot be expressed in v1.
    if (t.direction != OPTION_DIRECTION_CALL && t.descriptor_version < kOptionDescriptorVersionDirectional) {
        err = "put direction requires descriptor_version 2"; return false;
    }
    if (t.issuance_mode != OPTION_ISSUANCE_SELF && t.issuance_mode != OPTION_ISSUANCE_BILATERAL) {
        err = "invalid issuance_mode"; return false;
    }
    if (t.leaf_set != OPTION_LEAFSET_SETTLE_ONLY && t.leaf_set != OPTION_LEAFSET_SETTLE_BUYBACK) {
        err = "invalid leaf_set"; return false;
    }
    if (!t.writer_key.IsFullyValid()) { err = "writer_key is not a valid x-only point"; return false; }
    if (t.lot_count == 0) { err = "lot_count must be > 0"; return false; }
    if (t.lot_im_sats < MIN_SETTLE_OUTPUT) { err = "lot_im_sats below MIN_SETTLE_OUTPUT"; return false; }
    if (!MoneyRange(t.lot_im_sats)) { err = "lot_im_sats out of MoneyRange"; return false; }
    if (t.reference_premium_sats < 0 || !MoneyRange(t.reference_premium_sats)) {
        err = "reference_premium_sats out of MoneyRange"; return false;
    }
    // Total collateral lot_count * lot_im_sats must fit MoneyRange (overflow-safe; lot_im_sats > 0 here).
    if (static_cast<uint64_t>(t.lot_count) > static_cast<uint64_t>(MAX_MONEY) / static_cast<uint64_t>(t.lot_im_sats)) {
        err = "total collateral (lot_count * lot_im_sats) exceeds MAX_MONEY"; return false;
    }

    // Delegate the strike / leverage / CLTV / premium economic checks to the consensus-aligned
    // validator via a representative lot template (the real per-lot cp_key is the pot key, equally a
    // valid point; NUMS_H stands in here purely to pass the key-validity check).
    DifficultyContractTerms lot;
    lot.kind = DIFFICULTY_KIND_OPTION;
    lot.strike_nbits = t.strike_nbits;
    lot.fixing_height = t.fixing_height;
    lot.settle_lock_height = t.settle_lock_height;
    lot.premium = MIN_SETTLE_OUTPUT;
    // The writer funds the SHORT leg for a call and the LONG leg for a put; the other leg stays empty.
    DifficultyLegTerms& writer_leg = (t.direction == OPTION_DIRECTION_CALL) ? lot.short_leg : lot.long_leg;
    writer_leg.im = t.lot_im_sats;
    writer_leg.lambda_q = t.lambda_q;
    writer_leg.owner_key = t.writer_key;
    writer_leg.cp_key = XOnlyPubKey::NUMS_H;
    return lot.Validate(err, pow_limit);
}

bool ValidateOptionSeriesRecord(const OptionSeriesRecord& record, const uint256* expected_key, std::string& err)
{
    // Terms must be valid in their own right (descriptor metadata + economics; pow_limit unavailable
    // here, so the strike-vs-powLimit decode is skipped — the registering RPC checks that with chain).
    if (!ValidateOptionSeriesTerms(record.terms, /*pow_limit=*/nullptr, err)) return false;

    // The identity invariant: series_id IS the descriptor hash, and (on load) the DB key is too.
    const uint256 derived = ComputeOptionSeriesId(record.terms);
    if (record.series_id != derived) {
        err = "series_id does not match ComputeOptionSeriesId(terms)";
        return false;
    }
    if (expected_key != nullptr && *expected_key != derived) {
        err = "DB key does not match the derived series_id";
        return false;
    }

    // A persisted record is a FULLY-ISSUED series snapshot: the ICU successor and every lot vault are
    // outputs of the issuance tx, so their txids MUST equal issue_txid. (Pre-rotation invariant: a
    // future ICU rotation would move icu_outpoint and must relax that single check.)
    if (record.issue_txid.IsNull()) { err = "issue_txid is null"; return false; }
    const Txid issue_txid = Txid::FromUint256(record.issue_txid);
    if (record.icu_outpoint.hash != issue_txid) {
        err = "icu_outpoint does not reference issue_txid"; return false;
    }

    // Exactly N funded lot vaults, none null, none duplicated, each an output of the issuance tx.
    if (record.lot_vaults.size() != record.terms.lot_count) {
        err = strprintf("lot_vaults count (%u) != lot_count (%u)",
                        static_cast<unsigned>(record.lot_vaults.size()), record.terms.lot_count);
        return false;
    }
    std::set<COutPoint> seen;
    for (const auto& op : record.lot_vaults) {
        if (op.IsNull()) { err = "null lot vault outpoint"; return false; }
        if (op.hash != issue_txid) { err = "lot vault outpoint does not reference issue_txid"; return false; }
        if (!seen.insert(op).second) { err = "duplicate lot vault outpoint"; return false; }
    }
    return true;
}

OptionLot DeriveOptionLot(const OptionSeriesTerms& t, const uint256& series_id, uint32_t i)
{
    OptionLot lot;
    lot.index = i;
    lot.salt = DeriveOptionLotSalt(series_id, i);

    std::tie(lot.sink_key, lot.sink_ctr) = DeriveOptionSink(series_id, i);
    lot.sink_spk = GetScriptForDestination(WitnessV1Taproot{lot.sink_key});

    lot.pot_leaf = BuildOptionPotLeaf(series_id, lot.sink_spk);
    TaprootBuilder pot_builder = CreateOptionPotBuilder(lot.pot_leaf);
    Assume(pot_builder.IsComplete());
    lot.pot_key = pot_builder.GetOutput();
    lot.pot_spk = GetScriptForDestination(WitnessV1Taproot{lot.pot_key});

    // Lot terms: an OPTION funds ONLY the writer's leg — SHORT for a call, LONG for a put; the other leg
    // stays empty (DifficultyContractTerms::Validate requires exactly one). cp_key is the pot output key
    // (pay-to-covenant). premium is pinned to MIN_SETTLE_OUTPUT and is vestigial — the lot is minted,
    // never opened, but Validate requires premium >= dust (freeze §4 patch 2). It is decoupled from
    // reference_premium_sats so display economics never move a vault address.
    const bool writer_short = (t.direction == OPTION_DIRECTION_CALL);
    DifficultyContractRecord& rec = lot.record;
    rec.terms.kind = DIFFICULTY_KIND_OPTION;
    rec.terms.strike_nbits = t.strike_nbits;
    rec.terms.fixing_height = t.fixing_height;
    rec.terms.settle_lock_height = t.settle_lock_height;
    rec.terms.premium = MIN_SETTLE_OUTPUT;
    DifficultyLegTerms& wl = writer_short ? rec.terms.short_leg : rec.terms.long_leg;
    wl.im = t.lot_im_sats;
    wl.lambda_q = t.lambda_q;
    wl.owner_key = t.writer_key;   // raw signable writer key (freeze §4 patch 1)
    wl.cp_key = lot.pot_key;        // covenant key, no discrete log
    rec.salt = lot.salt;
    rec.contract_id = ComputeDifficultyContractId(rec.terms, rec.salt);
    (writer_short ? rec.short_internal_key : rec.long_internal_key) = XOnlyPubKey::NUMS_H;
    lot.contract_id = rec.contract_id;

    lot.settle_leaf = BuildDifficultyLeafScript(rec, /*is_short=*/writer_short);
    if (t.leaf_set == OPTION_LEAFSET_SETTLE_BUYBACK) {
        lot.buyback_leaf = BuildOptionBuybackLeaf(t.writer_key, series_id, lot.sink_spk);
    }
    TaprootBuilder vault_builder = CreateOptionVaultBuilder(lot.settle_leaf, lot.buyback_leaf);
    Assume(vault_builder.IsComplete());
    lot.vault_key = vault_builder.GetOutput();
    lot.vault_spk = GetScriptForDestination(WitnessV1Taproot{lot.vault_key});

    return lot;
}

bool BuildOptionSettlementSkeleton(const OptionSeriesTerms& terms, uint32_t lot_index,
                                   const FundedOutput& vault, uint32_t realized_nbits, const uint256& pow_limit,
                                   DifficultySettlementSkeleton& out, std::string& err)
{
    if (!ValidateOptionSeriesTerms(terms, &pow_limit, err)) return false; // series-level metadata + economics
    if (lot_index >= terms.lot_count) { err = "lot_index out of range"; return false; }

    // Compute series_id from terms (finding #1) and DERIVE the lot; require the funded UTXO to BE it.
    const uint256 series_id = ComputeOptionSeriesId(terms);
    const OptionLot lot = DeriveOptionLot(terms, series_id, lot_index);
    const bool writer_short = (terms.direction == OPTION_DIRECTION_CALL);
    if (vault.txout.scriptPubKey != lot.vault_spk) { err = "vault UTXO does not match the derived lot vault"; return false; }
    if (vault.txout.HasAssetTLV()) { err = "vault UTXO is asset-tagged (vaults are native-only)"; return false; }
    const DifficultyLegTerms& wleg = writer_short ? lot.record.terms.short_leg : lot.record.terms.long_leg;
    if (vault.txout.nValue != wleg.im) { err = "vault value does not match the per-lot IM"; return false; }

    const DifficultyContractTerms& tterms = lot.record.terms;
    if (!tterms.Validate(err, &pow_limit)) return false;
    const DifficultyLegTerms& leg = writer_short ? tterms.short_leg : tterms.long_leg; // the writer's funded leg

    const auto strike_target = DeriveTarget(tterms.strike_nbits, pow_limit);
    const auto realized_target = DeriveTarget(realized_nbits, pow_limit);
    if (!strike_target || !realized_target) {
        err = "strike or realized nBits is out of range for the chain powLimit"; return false;
    }
    DiffCfdPayout payout;
    if (!ComputeDiffCfdPayout(*strike_target, *realized_target, leg.lambda_q,
                              static_cast<uint64_t>(leg.im), /*short_leg=*/writer_short, payout)) {
        err = "ComputeDiffCfdPayout rejected the leg terms"; return false;
    }

    // Reconstruct the control block from the OPTION vault tree (settle + buy-back).
    TaprootBuilder builder = CreateOptionVaultBuilder(lot.settle_leaf, lot.buyback_leaf);
    if (!builder.IsComplete()) { err = "option vault builder incomplete"; return false; }
    const std::vector<unsigned char> leafvec(lot.settle_leaf.begin(), lot.settle_leaf.end());
    const TaprootSpendData spend = builder.GetSpendData();
    const auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    if (it == spend.scripts.end() || it->second.empty()) {
        err = "could not reconstruct the option vault control block"; return false;
    }
    const std::vector<unsigned char> control = *it->second.begin();

    DifficultySettlementSkeleton result;
    CTxIn vin(vault.outpoint);
    vin.scriptWitness.stack = {leafvec, control};
    vin.nSequence = CTxIn::SEQUENCE_FINAL - 1; // 0xfffffffe: locktime-enabled, not RBF-final
    result.vault_input = std::move(vin);

    // Exact covenant outputs — a zero leg emits NO output, exactly as OP_DIFFCFD_SETTLE requires.
    if (payout.payout_owner > 0) {
        result.payouts.emplace_back(static_cast<CAmount>(payout.payout_owner),
                                    GetScriptForDestination(WitnessV1Taproot{leg.owner_key}));
    }
    if (payout.payout_cp > 0) {
        result.payouts.emplace_back(static_cast<CAmount>(payout.payout_cp),
                                    GetScriptForDestination(WitnessV1Taproot{leg.cp_key}));
    }
    result.nlocktime = tterms.settle_lock_height;
    result.payout = payout;
    out = std::move(result);
    return true;
}

bool BuildOptionRedemption(const OptionSeriesTerms& terms,
                           const std::vector<OptionRedemptionPot>& pots,
                           const std::vector<FundedOutput>& token_inputs,
                           const std::vector<FundedOutput>& native_inputs,
                           const CScript& holder_spk, CAmount fee, CAmount dust,
                           CMutableTransaction& out, std::string& err)
{
    const uint64_t k = pots.size();
    if (k == 0) { err = "no pots to redeem"; return false; }
    if (token_inputs.empty()) { err = "no token inputs"; return false; }
    if (!MoneyRange(fee)) { err = "fee out of MoneyRange"; return false; }
    if (dust < kMinAssetOutputDust || !MoneyRange(dust)) { err = "dust below floor or out of MoneyRange"; return false; }
    if (!ValidateOptionSeriesTerms(terms, nullptr, err)) return false; // series-level metadata + economics

    const uint256 series_id = ComputeOptionSeriesId(terms); // finding #1: never trust a passed series_id

    // Derive + verify every pot up front (spk, native-only, dup-outpoint, dup-lot); reuse the lots.
    std::set<COutPoint> seen;
    std::set<uint32_t> seen_lots;
    std::vector<OptionLot> lots;
    lots.reserve(k);
    CAmount native_in = 0;
    CMutableTransaction mtx;
    for (const auto& rp : pots) {
        if (rp.lot_index >= terms.lot_count) { err = "pot lot_index out of range"; return false; }
        // One sink/unit per lot: redeeming two UTXOs of the same lot here would burn two units for one
        // lot (the existential sweep-many-UTXOs-with-one-sink case is a separate path). Reject for now.
        if (!seen_lots.insert(rp.lot_index).second) { err = "duplicate lot_index in redemption"; return false; }
        if (!seen.insert(rp.pot.outpoint).second) { err = "duplicate input outpoint"; return false; }
        OptionLot lot = DeriveOptionLot(terms, series_id, rp.lot_index);
        if (rp.pot.txout.scriptPubKey != lot.pot_spk) { err = "pot UTXO does not match the derived lot pot"; return false; }
        if (rp.pot.txout.HasAssetTLV()) { err = "pot UTXO is asset-tagged (pots are native-only)"; return false; }
        if (!AddMoney(native_in, rp.pot.txout.nValue, err)) return false;
        TaprootBuilder pb = CreateOptionPotBuilder(lot.pot_leaf);
        if (!pb.IsComplete()) { err = "pot builder incomplete"; return false; }
        const std::vector<unsigned char> leafvec(lot.pot_leaf.begin(), lot.pot_leaf.end());
        const TaprootSpendData spend = pb.GetSpendData();
        const auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
        if (it == spend.scripts.end() || it->second.empty()) { err = "could not reconstruct pot control block"; return false; }
        CTxIn vin(rp.pot.outpoint);
        vin.scriptWitness.stack = {leafvec, *it->second.begin()}; // signatureless; no CLTV -> final seq
        mtx.vin.push_back(std::move(vin));
        lots.push_back(std::move(lot));
    }

    uint64_t m = 0;
    if (!AccumulateTokenInputs(token_inputs, series_id, m, native_in, seen, err)) return false;
    if (m < k) { err = "insufficient token units for the requested pots"; return false; }
    const bool has_token_change = m > k;
    if (!AccumulateNativeInputs(native_inputs, native_in, seen, err)) return false;

    for (const auto& ti : token_inputs) mtx.vin.emplace_back(ti.outpoint);
    for (const auto& n : native_inputs) mtx.vin.emplace_back(n.outpoint);

    // Policy caps: AssetTag outputs (k sinks + change) <= 64; total outputs (+ native sweep) <= 128.
    const size_t asset_outputs = static_cast<size_t>(k) + (has_token_change ? 1u : 0u);
    if (asset_outputs > kDefaultMaxAssetsPerTx) { err = "too many asset outputs for one tx (64 assets-per-tx cap)"; return false; }
    if (asset_outputs + 1u > MAX_COVENANT_TX_OUTPUTS) { err = "too many outputs for one redemption tx (128-output cap)"; return false; }

    // Output dust (MoneyRange-checked) and native sweep.
    const CAmount asset_out_dust = static_cast<CAmount>(asset_outputs) * dust; // asset_outputs<=64, dust MoneyRange -> no overflow
    if (!MoneyRange(asset_out_dust)) { err = "aggregate output dust out of MoneyRange"; return false; }
    const CAmount native_sweep = native_in - fee - asset_out_dust;
    if (native_sweep < 0) { err = "native inputs do not cover fee + per-output dust"; return false; }
    if (native_sweep > 0 && native_sweep < kMinAssetOutputDust) {
        err = "native sweep would be dust; add native input or raise fee"; return false;
    }

    // Outputs: retire exactly 1 unit to each pot's unique sink.
    for (const auto& lot : lots) {
        CTxOut sink_out;
        sink_out.nValue = dust;
        sink_out.scriptPubKey = lot.sink_spk;
        sink_out.vExt = assets::BuildAssetTagTlv(series_id, 1);
        mtx.vout.push_back(std::move(sink_out));
    }
    if (has_token_change) {
        CTxOut change;
        change.nValue = dust;
        change.scriptPubKey = holder_spk;
        change.vExt = assets::BuildAssetTagTlv(series_id, m - k);
        mtx.vout.push_back(std::move(change));
    }
    if (native_sweep > 0) mtx.vout.emplace_back(native_sweep, holder_spk);

    out = std::move(mtx);
    return true;
}

bool BuildOptionBuyback(const OptionSeriesTerms& terms, uint32_t lot_index,
                        const FundedOutput& vault,
                        const std::vector<FundedOutput>& token_inputs,
                        const std::vector<FundedOutput>& native_inputs,
                        const CScript& writer_spk, CAmount fee, CAmount dust,
                        CMutableTransaction& out, std::string& err)
{
    if (!ValidateOptionSeriesTerms(terms, nullptr, err)) return false; // series-level metadata + economics
    if (lot_index >= terms.lot_count) { err = "lot_index out of range"; return false; }
    if (!MoneyRange(fee)) { err = "fee out of MoneyRange"; return false; }
    if (dust < kMinAssetOutputDust || !MoneyRange(dust)) { err = "dust below floor or out of MoneyRange"; return false; }

    const uint256 series_id = ComputeOptionSeriesId(terms);
    const OptionLot lot = DeriveOptionLot(terms, series_id, lot_index);
    if (lot.buyback_leaf.empty()) { err = "lot has no buy-back leaf (settle-only series)"; return false; }
    if (vault.txout.scriptPubKey != lot.vault_spk) { err = "vault UTXO does not match the derived lot vault"; return false; }
    if (vault.txout.HasAssetTLV()) { err = "vault UTXO is asset-tagged (vaults are native-only)"; return false; }
    const DifficultyLegTerms& wleg = (terms.direction == OPTION_DIRECTION_CALL)
        ? lot.record.terms.short_leg : lot.record.terms.long_leg;
    if (vault.txout.nValue != wleg.im) { err = "vault value does not match the per-lot IM"; return false; }

    std::set<COutPoint> seen;
    seen.insert(vault.outpoint);
    CAmount native_in = 0;
    if (!AddMoney(native_in, vault.txout.nValue, err)) return false;

    uint64_t m = 0;
    if (!AccumulateTokenInputs(token_inputs, series_id, m, native_in, seen, err)) return false;
    if (m < 1) { err = "buy-back needs at least 1 repurchased unit"; return false; }
    const bool has_token_change = m > 1;
    if (!AccumulateNativeInputs(native_inputs, native_in, seen, err)) return false;

    // Control block for the BUY-BACK leaf within the settle+buyback tree.
    TaprootBuilder builder = CreateOptionVaultBuilder(lot.settle_leaf, lot.buyback_leaf);
    if (!builder.IsComplete()) { err = "option vault builder incomplete"; return false; }
    const std::vector<unsigned char> leafvec(lot.buyback_leaf.begin(), lot.buyback_leaf.end());
    const TaprootSpendData spend = builder.GetSpendData();
    const auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    if (it == spend.scripts.end() || it->second.empty()) { err = "could not reconstruct buy-back control block"; return false; }
    const std::vector<unsigned char> control = *it->second.begin();

    const CAmount asset_out_dust = static_cast<CAmount>(1 + (has_token_change ? 1 : 0)) * dust;
    if (!MoneyRange(asset_out_dust)) { err = "aggregate output dust out of MoneyRange"; return false; }
    const CAmount native_sweep = native_in - fee - asset_out_dust;
    if (native_sweep < 0) { err = "native inputs do not cover fee + per-output dust"; return false; }
    if (native_sweep > 0 && native_sweep < kMinAssetOutputDust) {
        err = "native sweep would be dust; add native input or raise fee"; return false;
    }

    CMutableTransaction mtx;
    CTxIn vin(vault.outpoint);
    vin.scriptWitness.stack = {std::vector<unsigned char>{}, leafvec, control}; // [<placeholder sig>, leaf, control]
    mtx.vin.push_back(std::move(vin));
    for (const auto& ti : token_inputs) mtx.vin.emplace_back(ti.outpoint);
    for (const auto& n : native_inputs) mtx.vin.emplace_back(n.outpoint);

    CTxOut sink_out;
    sink_out.nValue = dust;
    sink_out.scriptPubKey = lot.sink_spk;
    sink_out.vExt = assets::BuildAssetTagTlv(series_id, 1);
    mtx.vout.push_back(std::move(sink_out));
    if (has_token_change) {
        CTxOut change;
        change.nValue = dust;
        change.scriptPubKey = writer_spk;
        change.vExt = assets::BuildAssetTagTlv(series_id, m - 1);
        mtx.vout.push_back(std::move(change));
    }
    if (native_sweep > 0) mtx.vout.emplace_back(native_sweep, writer_spk);

    out = std::move(mtx);
    return true;
}

// ---------------------------------------------------------------------------
// RPC parameter layer (shared by the core optionseries.derive/verify RPCs and the wallet
// optionseries.build_register RPC). UniValue in, OptionSeriesTerms / descriptor bytes out.
// ---------------------------------------------------------------------------
namespace {

uint32_t ParseU32Field(const UniValue& o, const std::string& name, std::optional<uint32_t> dflt = std::nullopt)
{
    const UniValue& v = o.find_value(name);
    if (v.isNull()) {
        if (dflt) return *dflt;
        throw JSONRPCError(RPC_INVALID_PARAMETER, name + " is required");
    }
    if (!v.isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a number");
    const int64_t n = v.getInt<int64_t>();
    if (n < 0 || n > static_cast<int64_t>(0xFFFFFFFFLL)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, name + " out of uint32 range");
    }
    return static_cast<uint32_t>(n);
}

const std::string& RequireStr(const UniValue& v, const std::string& name)
{
    if (!v.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a string");
    return v.get_str();
}

uint8_t ParseU8Field(const UniValue& o, const std::string& name, std::optional<uint8_t> dflt = std::nullopt)
{
    const UniValue& v = o.find_value(name);
    if (v.isNull()) {
        if (dflt) return *dflt;
        throw JSONRPCError(RPC_INVALID_PARAMETER, name + " is required");
    }
    if (!v.isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a number");
    const int64_t n = v.getInt<int64_t>();
    if (n < 0 || n > 0xFF) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " out of uint8 range");
    return static_cast<uint8_t>(n);
}

uint256 ParseHash256(const std::string& hex, const std::string& name)
{
    if (!IsHex(hex)) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be hex");
    const std::vector<unsigned char> bytes = ParseHex(hex);
    if (bytes.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be 32 bytes");
    uint256 h;
    std::copy(bytes.begin(), bytes.end(), h.begin());
    return h;
}

// Strict descriptor-hex parse: hex + a structurally valid §2 descriptor (v1 = 103 bytes; v2 = 104 with
// the trailing call/put direction byte), so malformed input is a clear parameter error rather than a later
// authentic:false. ParseOptionSeriesDescriptor enforces the version/length/direction agreement.
std::vector<unsigned char> ParseDescriptorHex(const std::string& hex, const std::string& name)
{
    if (!IsHex(hex)) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be hex");
    std::vector<unsigned char> bytes = ParseHex(hex);
    if (!ParseOptionSeriesDescriptor(bytes).has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            name + " is not a valid option-series descriptor (v1 = 103 bytes, v2 = 104 bytes)");
    }
    return bytes;
}

// Validate that `raw` is the CANONICAL TSC-ICU-META-1 container committed on chain (fail closed), then
// return its TSC-ICU-OPTSERIES-1 descriptor bytes. Checks: parses as a JSON object; re-canonicalizes
// byte-identically (so it IS the committed bytes, not merely some JSON carrying a descriptor); the
// top-level + optseries band identity (spec / parse_version); and a structurally valid descriptor (v1/v2).
std::vector<unsigned char> ExtractDescriptorFromIcuMetadata(const std::vector<unsigned char>& raw)
{
    UniValue meta;
    if (!meta.read(std::string(raw.begin(), raw.end())) || !meta.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_metadata is not a JSON object");
    }
    std::string canon_err;
    const auto canon = assets::CanonicalizeIcuBandJson(meta, canon_err);
    if (!canon) throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_metadata is not canonical JSON: " + canon_err);
    if (*canon != raw) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_metadata is not in canonical form (not the committed on-chain bytes)");
    }
    const UniValue& spec = meta.find_value("spec");
    if (!spec.isStr() || spec.get_str() != "TSC-ICU-META-1") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_metadata spec is not TSC-ICU-META-1");
    }
    const UniValue& opt = meta.find_value("optseries");
    if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_metadata has no optseries band");
    const UniValue& ospec = opt.find_value("spec");
    if (!ospec.isStr() || ospec.get_str() != "TSC-ICU-OPTSERIES-1") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "optseries.spec is not TSC-ICU-OPTSERIES-1");
    }
    const UniValue& opv = opt.find_value("parse_version");
    if (!opv.isNum() || opv.getValStr() != "1") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "optseries.parse_version must be 1");
    }
    const UniValue& desc = opt.find_value("descriptor");
    if (!desc.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "optseries.descriptor is missing");
    return ParseDescriptorHex(desc.get_str(), "optseries.descriptor");
}

//! writer_key: a 32-byte x-only hex (matches the descriptor exactly) or a P2TR (bech32m) address.
XOnlyPubKey ParseWriterKey(const std::string& s)
{
    if (IsHex(s) && s.size() == 64) {
        const std::vector<unsigned char> bytes = ParseHex(s);
        const XOnlyPubKey k{bytes};
        if (!k.IsFullyValid()) throw JSONRPCError(RPC_INVALID_PARAMETER, "writer_key is not a valid x-only point");
        return k;
    }
    const CTxDestination dest = DecodeDestination(s);
    if (const auto* tr = std::get_if<WitnessV1Taproot>(&dest)) {
        return XOnlyPubKey(*tr);
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "writer_key must be 32-byte x-only hex or a P2TR (bech32m) address");
}

} // namespace

OptionSeriesTerms ParseOptionSeriesTermsFromJson(const UniValue& t)
{
    if (!t.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms must be an object");
    OptionSeriesTerms terms;
    terms.descriptor_version = ParseU8Field(t, "descriptor_version", kOptionDescriptorVersion);
    terms.issuance_mode = ParseU8Field(t, "issuance_mode", OPTION_ISSUANCE_SELF);
    terms.leaf_set = ParseU8Field(t, "leaf_set", OPTION_LEAFSET_SETTLE_BUYBACK);

    const UniValue& wk = t.find_value("writer_key");
    if (wk.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "writer_key is required");
    terms.writer_key = ParseWriterKey(RequireStr(wk, "writer_key"));

    terms.strike_nbits = ParseU32Field(t, "strike_nbits");
    terms.fixing_height = ParseU32Field(t, "fixing_height");
    terms.settle_lock_height = ParseU32Field(t, "settle_lock_height");
    terms.lambda_q = ParseU32Field(t, "lambda_q");
    terms.lot_im_sats = AmountFromValue(t.find_value("lot_im"));
    terms.lot_count = ParseU32Field(t, "lot_count");
    const UniValue& rp = t.find_value("reference_premium");
    terms.reference_premium_sats = rp.isNull() ? 0 : AmountFromValue(rp);

    const UniValue& salt = t.find_value("series_salt");
    if (salt.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "series_salt is required");
    terms.series_salt = ParseHash256(RequireStr(salt, "series_salt"), "series_salt");
    terms.direction = ParseU8Field(t, "direction", OPTION_DIRECTION_CALL); // call (0) | put (1); requires v2 for put
    return terms;
}

UniValue OptionSeriesTermsToJson(const OptionSeriesTerms& t)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("descriptor_version", static_cast<int64_t>(t.descriptor_version));
    o.pushKV("issuance_mode", static_cast<int64_t>(t.issuance_mode));
    o.pushKV("leaf_set", static_cast<int64_t>(t.leaf_set));
    o.pushKV("writer_key", HexStr(t.writer_key));
    o.pushKV("strike_nbits", static_cast<int64_t>(t.strike_nbits));
    o.pushKV("fixing_height", static_cast<int64_t>(t.fixing_height));
    o.pushKV("settle_lock_height", static_cast<int64_t>(t.settle_lock_height));
    o.pushKV("lambda_q", static_cast<int64_t>(t.lambda_q));
    o.pushKV("lot_im_sats", static_cast<int64_t>(t.lot_im_sats));
    o.pushKV("lot_count", static_cast<int64_t>(t.lot_count));
    o.pushKV("reference_premium_sats", static_cast<int64_t>(t.reference_premium_sats));
    o.pushKV("series_salt", HexStr(t.series_salt));
    o.pushKV("direction", static_cast<int64_t>(t.direction));
    o.pushKV("option_kind", t.direction == OPTION_DIRECTION_PUT ? "put" : "call");
    return o;
}

std::vector<unsigned char> ExtractOptionSeriesDescriptorFromSource(const UniValue& src)
{
    if (!src.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "source must be an object");
    int provided = 0;
    std::vector<unsigned char> descriptor;
    if (!src.find_value("descriptor").isNull()) {
        provided++;
        descriptor = ParseDescriptorHex(RequireStr(src.find_value("descriptor"), "descriptor"), "descriptor");
    }
    if (!src.find_value("icu_metadata").isNull()) {
        provided++;
        const std::string md_hex = RequireStr(src.find_value("icu_metadata"), "icu_metadata");
        if (!IsHex(md_hex)) throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_metadata must be hex");
        descriptor = ExtractDescriptorFromIcuMetadata(ParseHex(md_hex));
    }
    if (!src.find_value("terms").isNull()) {
        provided++;
        descriptor = SerializeOptionDescriptor(ParseOptionSeriesTermsFromJson(src.find_value("terms")));
    }
    if (provided != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "source must contain exactly one of: descriptor, icu_metadata, terms");
    }
    return descriptor;
}

} // namespace wallet
