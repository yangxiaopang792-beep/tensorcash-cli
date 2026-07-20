// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scalar_cfd_contract.h>

#include <arith_uint256.h>
#include <assets/asset.h>             // BuildAssetTagTlv
#include <consensus/amount.h>         // MAX_MONEY, MoneyRange
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT
#include <consensus/scalar_cfd.h>     // ComputeScalarCfdPayout, DecodeScalarValue, ScalarLossDenominator
#include <consensus/scalar_cfd_leaf.h>// SCALAR_CFD_TEMPLATE_VERSION_V1, ScalarCfdSourceType/PayoffMode
#include <hash.h>                     // HashWriter, TaggedHash
#include <key.h>
#include <script/interpreter.h>       // TAPROOT_LEAF_TAPSCRIPT
#include <script/script.h>            // LOCKTIME_THRESHOLD, OP_*
#include <script/signingprovider.h>   // TaprootBuilder, TaprootSpendData
#include <span.h>                     // MakeByteSpan
#include <tinyformat.h>
#include <util/check.h>
#include <util/transaction_identifier.h> // Txid (opened-state outpoint check)
#include <wallet/scalar_note_pair.h>  // BuildScalarCfdLeaf

#include <cstring>
#include <limits>
#include <stdexcept>

namespace wallet {

namespace {
//! Canonical key-path-disabled P2TR scriptPubKey for an x-only output key.
CScript P2TR(const XOnlyPubKey& key) { CScript s; s << OP_1 << ToByteVector(key); return s; }
std::vector<unsigned char> LeafBytes(const CScript& s) { return std::vector<unsigned char>(s.begin(), s.end()); }
} // namespace

bool ScalarCfdContractTerms::Validate(std::string& err) const
{
    if (source_type > static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC)) { err = "source_type out of range"; return false; }
    if (payoff_mode > static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)) { err = "payoff_mode out of range"; return false; }

    // U must be consistent with the source: CHAIN_INTRINSIC commits zero U; ISSUER_PUBLISHED a real asset.
    const bool chain = source_type == static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC);
    if (chain && !underlying_asset_id.IsNull()) { err = "CHAIN_INTRINSIC requires a zero underlying_asset_id"; return false; }
    if (!chain && underlying_asset_id.IsNull()) { err = "ISSUER_PUBLISHED requires a non-zero underlying_asset_id"; return false; }

    // scalar_format must be a known encoding AND BOTH committed literals must decode canonically under it —
    // exactly as the opcode reads them at settlement (interpreter.cpp). A non-canonical strike/fallback in a
    // persisted record or a metadata-derived descriptor would fail SCALARCFD_ENCODING and brick the contract,
    // so the integrity gate rejects it here rather than at spend time.
    if (!assets::IsKnownScalarFormat(scalar_format_id)) { err = "unknown scalar_format_id"; return false; }
    { arith_uint256 tmp; if (!DecodeScalarValue(scalar_format_id, strike, tmp)) { err = "strike not canonical for scalar_format_id"; return false; } }
    { arith_uint256 tmp; if (!DecodeScalarValue(scalar_format_id, fallback_scalar, tmp)) { err = "fallback_scalar not canonical for scalar_format_id"; return false; } }

    const bool native = collateral_asset_id.IsNull();
    auto check_leg = [&](const ScalarCfdLegTerms& leg, const char* name) -> bool {
        if (leg.lambda_q == 0) { err = strprintf("%s: lambda_q must be non-zero", name); return false; }
        if (leg.im < static_cast<uint64_t>(MIN_SETTLE_OUTPUT)) { err = strprintf("%s: im (%llu) below MIN_SETTLE_OUTPUT (%d)", name, (unsigned long long)leg.im, MIN_SETTLE_OUTPUT); return false; }
        if (native && leg.im > static_cast<uint64_t>(MAX_MONEY)) { err = strprintf("%s: native im exceeds MAX_MONEY", name); return false; }
        if (!leg.owner_key.IsFullyValid()) { err = strprintf("%s: owner_key is not a valid x-only key", name); return false; }
        if (!leg.cp_key.IsFullyValid()) { err = strprintf("%s: cp_key is not a valid x-only key", name); return false; }
        if (leg.owner_key == leg.cp_key) { err = strprintf("%s: owner_key and cp_key must differ", name); return false; }
        return true;
    };
    if (!check_leg(long_leg, "long_leg")) return false;
    if (!check_leg(short_leg, "short_leg")) return false;

    // Block-height CLTV semantics: a height-based lock must be >= 1 and below the time threshold.
    if (settle_lock_height == 0) { err = "settle_lock_height must be >= 1"; return false; }
    if (settle_lock_height >= LOCKTIME_THRESHOLD) { err = "settle_lock_height must be a block height (< LOCKTIME_THRESHOLD)"; return false; }
    return true;
}

uint256 ComputeScalarCfdContractId(const ScalarCfdContractTerms& terms, const uint256& salt)
{
    HashWriter hw{};
    hw << terms << salt;
    return hw.GetHash();
}

bool ValidateScalarCfdContractRecord(const ScalarCfdContractRecord& record, const uint256* expected_key, std::string& err)
{
    if (record.contract_id != ComputeScalarCfdContractId(record.terms, record.salt)) {
        err = "contract_id does not match terms+salt";
        return false;
    }
    if (expected_key && record.contract_id != *expected_key) {
        err = "contract_id does not match the database key";
        return false;
    }
    if (!record.terms.Validate(err)) return false;

    // v1: BOTH vault internal keys MUST be the BIP341 NUMS point (key path provably disabled). A non-NUMS
    // internal would make a vault output key the build/settlement path cannot reconstruct or could be
    // key-path spent — neither is allowed in v1.
    if (record.long_internal_key != XOnlyPubKey::NUMS_H || record.short_internal_key != XOnlyPubKey::NUMS_H) {
        err = "vault internal keys must be the NUMS point in v1";
        return false;
    }
    // Cooperative-close 2-of-2 internals must all be valid x-only keys (the coop leaf commits them).
    for (const XOnlyPubKey& k : {record.long_owner_internal, record.long_cp_internal,
                                 record.short_owner_internal, record.short_cp_internal}) {
        if (!k.IsFullyValid()) { err = "a cooperative-close internal key is not a valid x-only key"; return false; }
    }
    // Fair-Sign atomic-open state must be complete: both adaptor points valid + a binding context. Every
    // scalar bilateral record originates from accept/import, which always set these.
    if (!record.fs_tx_adaptor_point.IsFullyValid()) { err = "proposer Fair-Sign adaptor point is invalid"; return false; }
    if (!record.counterparty_adaptor_point.has_value() || !record.counterparty_adaptor_point->IsFullyValid()) {
        err = "acceptor Fair-Sign adaptor point is missing or invalid";
        return false;
    }
    if (record.fs_context.IsNull()) { err = "fs_context is null"; return false; }

    // Opened-state: once the record claims to be opened (open_txid or any vault set), require the FULL
    // opened invariant — open_txid present, BOTH vault outpoints non-null and referencing the open tx.
    const bool any_open = !record.open_txid.IsNull() || !record.long_vault.IsNull() || !record.short_vault.IsNull();
    if (any_open) {
        if (record.open_txid.IsNull()) { err = "opened record is missing open_txid"; return false; }
        const Txid open = Txid::FromUint256(record.open_txid);
        auto from_open = [&](const COutPoint& op, const char* name) -> bool {
            if (op.hash != open || op.n == COutPoint::NULL_INDEX) { err = strprintf("%s does not reference the open tx", name); return false; }
            return true;
        };
        if (!from_open(record.long_vault, "long_vault")) return false;
        if (!from_open(record.short_vault, "short_vault")) return false;
        if (record.long_vault == record.short_vault) { err = "long_vault and short_vault must be distinct outpoints"; return false; }
    }
    return true;
}

uint256 ComputeScalarCfdContractMeta(const ScalarCfdContractRecord& record)
{
    HashWriter hw = TaggedHash("tensorcash/scalarcfd/fs-meta");
    hw << record.contract_id << record.fs_tx_adaptor_point;
    const bool has_cp = record.counterparty_adaptor_point.has_value();
    hw << has_cp;
    if (has_cp) hw << *record.counterparty_adaptor_point;
    return hw.GetSHA256();
}

uint256 ComputeScalarCfdOfferCommitment(uint8_t proposer_is_short, const ScalarCfdContractTerms& terms,
                                        const XOnlyPubKey& proposer_owner_key,
                                        const XOnlyPubKey& proposer_cp_key, const uint256& salt)
{
    // Hash ONLY fields fixed at propose time: the shared fixing terms, both legs' econ scalars (NOT the
    // payout keys — those carry the acceptor's keys, unset at propose), the proposer's own payout keys
    // (passed explicitly), its side, and the salt. Identical at propose / accept / import.
    HashWriter hw = TaggedHash("tensorcash/scalarcfd/fs-offer-commitment");
    hw << proposer_is_short
       << terms.source_type << terms.payoff_mode << terms.underlying_asset_id
       << terms.feed_id << terms.fixing_ref << terms.publication_deadline_height
       << terms.settle_lock_height << terms.scalar_format_id << terms.strike << terms.fallback_scalar
       << terms.collateral_asset_id
       << terms.long_leg.im << terms.long_leg.lambda_q
       << terms.short_leg.im << terms.short_leg.lambda_q
       << proposer_owner_key << proposer_cp_key << salt;
    return hw.GetSHA256();
}

std::pair<uint256, XOnlyPubKey> DeriveScalarCfdFsAdaptor(const CKey& owner_key, const uint256& salt,
                                                         const uint256& context, uint8_t role)
{
    if (!owner_key.IsValid()) throw std::runtime_error("DeriveScalarCfdFsAdaptor: owner key not available/invalid");
    // scalar = H_tag(owner_priv || salt || context || role || counter); context + role bind the secret to
    // one contract and one side. Retry on the ~2^-128 chance of an invalid scalar.
    for (uint8_t counter = 0; counter < 16; ++counter) {
        HashWriter hw = TaggedHash("tensorcash/scalarcfd/fs-adaptor");
        hw.write(MakeByteSpan(owner_key));
        hw << salt << context << role << counter;
        const uint256 scalar = hw.GetSHA256();
        CKey k;
        k.Set(scalar.begin(), scalar.end(), /*fCompressed=*/true);
        if (k.IsValid()) {
            const XOnlyPubKey xonly(k.GetPubKey());
            uint256 out;
            std::memcpy(out.data(), k.data(), 32);
            return {out, xonly};
        }
    }
    throw std::runtime_error("DeriveScalarCfdFsAdaptor: no valid scalar derived");
}

CScript BuildScalarCfdLegLeaf(const ScalarCfdContractRecord& record, bool is_short)
{
    const auto& t = record.terms;
    const ScalarCfdLegTerms& leg = is_short ? t.short_leg : t.long_leg;
    ScalarCfdLeaf leaf;
    leaf.contract_id = record.contract_id;
    leaf.template_version = SCALAR_CFD_TEMPLATE_VERSION_V1;
    leaf.settle_lock_height = static_cast<int64_t>(t.settle_lock_height);
    leaf.source_type = t.source_type;
    leaf.underlying_asset_id = t.underlying_asset_id;
    leaf.feed_id = t.feed_id;
    leaf.fixing_ref = t.fixing_ref;
    leaf.publication_deadline_height = t.publication_deadline_height;
    leaf.payoff_mode = t.payoff_mode;
    leaf.scalar_format_id = t.scalar_format_id;
    leaf.strike = t.strike;
    leaf.fallback_scalar = t.fallback_scalar;
    leaf.lambda_q = leg.lambda_q;
    leaf.loss_direction = is_short ? 0x01 : 0x00;
    leaf.collateral_asset_id = t.collateral_asset_id;
    leaf.vault_im = leg.im;
    leaf.owner_key = ToByteVector(leg.owner_key);
    leaf.cp_key = ToByteVector(leg.cp_key);
    return BuildScalarCfdLeaf(leaf);
}

CScript BuildScalarCfdCoopLeaf(const ScalarCfdContractRecord& record, bool is_short)
{
    // Plain 2-of-2 cosign of the two parties' INTERNAL (untweaked descriptor) keys behind their payout
    // addresses: <owner_internal> OP_CHECKSIGVERIFY <cp_internal> OP_CHECKSIG. Uniqueness across contracts
    // comes from the sibling settlement leaf (which commits contract_id) via the shared taptweak.
    CScript s;
    s << ToByteVector(record.CoopOwnerInternal(is_short)) << OP_CHECKSIGVERIFY;
    s << ToByteVector(record.CoopCpInternal(is_short)) << OP_CHECKSIG;
    return s;
}

TaprootBuilder CreateScalarCfdVaultBuilder(const ScalarCfdContractRecord& record, bool is_short,
                                           const XOnlyPubKey& internal_key)
{
    TaprootBuilder b;
    b.Add(1, LeafBytes(BuildScalarCfdLegLeaf(record, is_short)), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    b.Add(1, LeafBytes(BuildScalarCfdCoopLeaf(record, is_short)), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    b.Finalize(internal_key);
    return b;
}

bool BuildScalarCfdSettlementSkeleton(const ScalarCfdContractRecord& record, bool is_short,
                                      const arith_uint256& realized,
                                      ScalarCfdSettlementSkeleton& out, std::string& err)
{
    const ScalarCfdContractTerms& t = record.terms;
    if (!t.Validate(err)) return false;
    const ScalarCfdLegTerms& leg = is_short ? t.short_leg : t.long_leg;

    const XOnlyPubKey& internal = record.VaultInternalKey(is_short);
    const COutPoint& vault = record.VaultOutpoint(is_short);
    if (internal.IsNull() || vault.IsNull()) { err = "leg vault not opened (null internal key / outpoint)"; return false; }

    arith_uint256 K;
    if (!DecodeScalarValue(t.scalar_format_id, t.strike, K)) { err = "strike decode failed"; return false; }
    const ScalarLossDenominator denom = t.payoff_mode == static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED)
                                            ? ScalarLossDenominator::REALIZED : ScalarLossDenominator::STRIKE;
    ScalarCfdPayout payout;
    // The payout-snap floor is the consensus constant the opcode passes (interpreter.cpp:1473), NOT a
    // caller choice — any other value would snap differently from OP_SCALAR_CFD_SETTLE.
    if (!ComputeScalarCfdPayout(K, realized, denom, leg.lambda_q, leg.im, /*short_leg=*/is_short,
                                static_cast<uint64_t>(MIN_SETTLE_OUTPUT), payout)) {
        err = "payout computation rejected the leg terms";
        return false;
    }

    // Reconstruct the control block for the settle leaf from the (settle, coop) vault taptree.
    TaprootBuilder vb = CreateScalarCfdVaultBuilder(record, is_short, internal);
    if (!vb.IsComplete()) { err = "vault builder incomplete"; return false; }
    const CScript settle_leaf = BuildScalarCfdLegLeaf(record, is_short);
    const std::vector<unsigned char> settle_bytes = LeafBytes(settle_leaf);
    const TaprootSpendData sd = vb.GetSpendData();
    const auto cit = sd.scripts.find({settle_bytes, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    if (cit == sd.scripts.end() || cit->second.empty()) { err = "could not reconstruct settle control block"; return false; }
    const std::vector<unsigned char> control = *cit->second.begin();

    out.payout = payout;
    out.nlocktime = t.settle_lock_height;
    out.vault_input = CTxIn(vault);
    out.vault_input.nSequence = CTxIn::SEQUENCE_FINAL - 1; // locktime-enabled, non-final (satisfies the CLTV)
    out.vault_input.scriptWitness.stack = {settle_bytes, control};

    // Asset legs carry the consensus carrier-dust nValue alongside their AssetTag (interpreter.cpp:1513);
    // native legs carry the payout itself. Neither is caller-tunable.
    const bool native = t.collateral_asset_id.IsNull();
    out.payouts.clear();
    if (payout.payout_owner > 0) {
        CTxOut o(native ? static_cast<CAmount>(payout.payout_owner) : SCALARCFD_ASSET_OUTPUT_DUST, P2TR(leg.owner_key));
        if (!native) o.vExt = assets::BuildAssetTagTlv(t.collateral_asset_id, payout.payout_owner);
        out.payouts.push_back(std::move(o));
    }
    if (payout.payout_cp > 0) {
        CTxOut o(native ? static_cast<CAmount>(payout.payout_cp) : SCALARCFD_ASSET_OUTPUT_DUST, P2TR(leg.cp_key));
        if (!native) o.vExt = assets::BuildAssetTagTlv(t.collateral_asset_id, payout.payout_cp);
        out.payouts.push_back(std::move(o));
    }
    return true;
}

} // namespace wallet
