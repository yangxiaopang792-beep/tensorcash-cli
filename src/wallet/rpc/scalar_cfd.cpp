// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bilateral (two-party) scalar CFD RPC lifecycle — the offer handshake (CFD_GENERALISATION.md §7, Slice
// 5f-2): scalarcfd.propose / scalarcfd.accept / scalarcfd.import_acceptance. The scalar analogue of the
// difficulty.* bilateral lifecycle (wallet/rpc/difficulty.cpp), built on wallet/scalar_cfd_contract.{h,cpp}.
// The offer/acceptance are plain JSON objects exchanged out-of-band; both carry the Fair-Sign adaptor
// points for atomic risk transfer at open. CHAIN_INTRINSIC is rejected here (no chain resolver yet) — the
// settlement skeleton is source-agnostic, but resolution is ISSUER_PUBLISHED only.

#include <assets/asset.h>             // ParseAssetTag (record_open collateral matching)
#include <assets/registry.h>          // ScalarRecord (fixing reader)
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>         // MoneyRange (guarded merge-fee accumulation)
#include <consensus/consensus.h>      // WITNESS_SCALE_FACTOR
#include <consensus/scalar_cfd.h>     // ResolveScalarFixing, DecodeScalarValue, ComputeScalarCfdPayout
#include <consensus/scalar_cfd_leaf.h> // ScalarCfdSourceType / PayoffMode
#include <core_io.h>
#include <key_io.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <psbt.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>          // EnsureChainman
#include <rpc/util.h>
#include <script/interpreter.h>       // ComputeTapleafHash / ComputeTaprootMerkleRoot / TAPROOT_* / ANNEX_TAG
#include <script/script.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>
#include <validation.h>              // cs_main, ChainstateManager
#include <wallet/coincontrol.h>
#include <wallet/pricing/discount_curve.h>
#include <wallet/pricing/fx_matrix.h>            // PriceSource
#include <wallet/pricing/pricing_context.h>
#include <wallet/pricing/scalar_cfd_pricer.h>
#include <wallet/pricing/scalar_forward_curve.h>
#include <wallet/context.h>
#include <wallet/fairsign.h>
#include <wallet/rpc/util.h>
#include <wallet/scalar_cfd_contract.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <array>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {
namespace {

// ----- small field parsers (local; mirror the scalar.cpp / difficulty.cpp conventions) -----

uint8_t ReqU8(const UniValue& o, const std::string& k)
{
    const int64_t n = o[k].getInt<int64_t>();
    if (n < 0 || n > 0xFF) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " out of uint8 range");
    return static_cast<uint8_t>(n);
}
uint8_t OptU8(const UniValue& o, const std::string& k, uint8_t dflt) { return o.exists(k) ? ReqU8(o, k) : dflt; }
uint16_t ReqU16(const UniValue& o, const std::string& k)
{
    const int64_t n = o[k].getInt<int64_t>();
    if (n < 0 || n > 0xFFFF) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " out of uint16 range");
    return static_cast<uint16_t>(n);
}
uint32_t ReqU32(const UniValue& o, const std::string& k)
{
    const int64_t n = o[k].getInt<int64_t>();
    if (n < 0 || n > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " out of uint32 range");
    return static_cast<uint32_t>(n);
}
uint64_t ReqU64(const UniValue& o, const std::string& k) { return o[k].getInt<uint64_t>(); }

//! OPTIONAL hash/value field: 32-byte hex via uint256::FromHex (same byte convention as the note-pair RPC,
//! so the bilateral and securitisation wire formats agree). Empty / absent -> zero. ONLY for fields whose
//! zero is a deliberate sentinel (e.g. collateral_asset_id zero == native).
uint256 OptHash(const UniValue& o, const std::string& k)
{
    if (!o.exists(k) || o[k].get_str().empty()) return uint256{};
    auto h = uint256::FromHex(o[k].get_str());
    if (!h) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " is not 32-byte hex");
    return *h;
}

//! REQUIRED hash/value field: throws on a missing/empty/malformed value so an omitted required 32-byte
//! field (strike, fallback, salt, contract_id, underlying) can never silently become zero.
uint256 ReqHash(const UniValue& o, const std::string& k)
{
    if (!o.exists(k)) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " is required");
    const std::string s = o[k].get_str();
    if (s.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " must not be empty");
    auto h = uint256::FromHex(s);
    if (!h) throw JSONRPCError(RPC_INVALID_PARAMETER, k + " is not 32-byte hex");
    return *h;
}

//! A collateral-units amount (uint64): accepts a decimal STRING (lossless for asset units that may exceed
//! 2^53) or a JSON number. Used for each leg's IM.
uint64_t ParseUnits(const UniValue& v, const std::string& field)
{
    if (v.isStr()) {
        const std::string& s = v.get_str();
        if (s.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be a decimal integer");
        uint64_t out = 0;
        for (char c : s) {
            if (c < '0' || c > '9') throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be a decimal integer");
            const uint64_t d = static_cast<uint64_t>(c - '0');
            if (out > (std::numeric_limits<uint64_t>::max() - d) / 10) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " overflows uint64");
            out = out * 10 + d;
        }
        return out;
    }
    return v.getInt<uint64_t>();
}

XOnlyPubKey ParseP2TRXOnly(const std::string& addr, const std::string& field)
{
    const CTxDestination dest = DecodeDestination(addr);
    if (const auto* tr = std::get_if<WitnessV1Taproot>(&dest)) return XOnlyPubKey(*tr);
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a P2TR (bech32m) address", field));
}

XOnlyPubKey ParseXOnlyHex(const UniValue& v, const std::string& field)
{
    const std::vector<unsigned char> b = ParseHex(v.get_str());
    if (b.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be a 32-byte x-only pubkey (hex)");
    return XOnlyPubKey(b);
}

// ----- wallet coop-key resolution (mirror difficulty.cpp) -----

std::optional<XOnlyPubKey> DeriveTaprootInternalKey(const CWallet& wallet, const XOnlyPubKey& output_key)
{
    const WitnessV1Taproot tr{output_key};
    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(CTxDestination{tr}));
    if (!provider) return std::nullopt;
    TaprootSpendData spenddata;
    if (!provider->GetTaprootSpendData(tr, spenddata) || spenddata.internal_key.IsNull()) return std::nullopt;
    return spenddata.internal_key;
}

XOnlyPubKey ExtractCoopInternalKey(const CWallet& wallet, const XOnlyPubKey& output_key, const std::string& field)
{
    const auto internal = DeriveTaprootInternalKey(wallet, output_key);
    if (!internal) throw JSONRPCError(RPC_WALLET_ERROR, field + ": this wallet does not control that payout address (needed to derive its cooperative-close key)");
    return *internal;
}

//! The private key behind a payout address's INTERNAL (untweaked descriptor) key, for the coop cosign /
//! the Fair-Sign adaptor derivation. Obtained from the address's own expanded signing provider.
bool GetCoopSignerKey(CWallet& wallet, const XOnlyPubKey& payout_key, const XOnlyPubKey& internal_key, CKey& out_key)
{
    const CScript spk = GetScriptForDestination(WitnessV1Taproot{payout_key});
    LOCK(wallet.cs_wallet);
    for (ScriptPubKeyMan* spkm : wallet.GetScriptPubKeyMans(spk)) {
        auto* desc = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc) continue;
        std::unique_ptr<FlatSigningProvider> prov = desc->GetSolvingProviderForScript(spk, /*include_private=*/true);
        if (prov && prov->GetKeyByXOnly(internal_key, out_key) && out_key.IsValid()
            && XOnlyPubKey(out_key.GetPubKey()) == internal_key) {
            return true;
        }
    }
    return false;
}

// ----- scalar CFD economics + offer/acceptance JSON -----

//! Parse the ECONOMICS-only terms (no payout keys): the shared scalar fixing + each leg's IM + leverage.
//! REJECTS CHAIN_INTRINSIC — settlement resolution is ISSUER_PUBLISHED only until a chain resolver exists
//! (the contract would otherwise be structurally valid yet unsettleable).
ScalarCfdContractTerms ParseScalarCfdEconomics(const UniValue& o)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms must be an object");
    ScalarCfdContractTerms t;
    t.source_type   = OptU8(o, "source_type", static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED));
    if (t.source_type != static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "only ISSUER_PUBLISHED bilateral CFDs are supported (CHAIN_INTRINSIC has no resolver yet)");
    }
    t.payoff_mode   = OptU8(o, "payoff_mode", static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE));
    t.underlying_asset_id = ReqHash(o, "underlying_asset_id"); // ISSUER source => U is required + non-zero
    t.feed_id       = ReqU32(o, "feed_id");
    t.fixing_ref    = ReqU64(o, "fixing_ref");
    t.publication_deadline_height = ReqU32(o, "publication_deadline_height");
    t.settle_lock_height = ReqU32(o, "settle_lock_height");
    t.scalar_format_id = ReqU16(o, "scalar_format_id");
    t.strike        = ReqHash(o, "strike");
    t.fallback_scalar = ReqHash(o, "fallback_scalar");
    t.collateral_asset_id = OptHash(o, "collateral_asset_id"); // zero == native (deliberate sentinel)
    const UniValue& l = o.find_value("long");
    const UniValue& s = o.find_value("short");
    if (!l.isObject() || !s.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.long and terms.short must be objects");
    t.long_leg.im  = ParseUnits(l.find_value("im"), "long.im");
    t.long_leg.lambda_q = ReqU32(l, "lambda_q");
    t.short_leg.im = ParseUnits(s.find_value("im"), "short.im");
    t.short_leg.lambda_q = ReqU32(s, "lambda_q");
    return t; // payout keys left null — filled by AssembleScalarCfdTerms once both parties' keys are known
}

//! Fill the four payout keys from each party's (owner, cp) pair, per side.
//!   proposer long  -> long.owner = prop_owner, short.cp = prop_cp; short.owner = acc_owner, long.cp = acc_cp
//!   proposer short -> short.owner = prop_owner, long.cp = prop_cp; long.owner = acc_owner, short.cp = acc_cp
ScalarCfdContractTerms AssembleScalarCfdTerms(const ScalarCfdContractTerms& econ, bool proposer_is_short,
                                              const XOnlyPubKey& prop_owner, const XOnlyPubKey& prop_cp,
                                              const XOnlyPubKey& acc_owner, const XOnlyPubKey& acc_cp)
{
    ScalarCfdContractTerms t = econ;
    if (proposer_is_short) {
        t.short_leg.owner_key = prop_owner; t.long_leg.cp_key = prop_cp;
        t.long_leg.owner_key = acc_owner;   t.short_leg.cp_key = acc_cp;
    } else {
        t.long_leg.owner_key = prop_owner;  t.short_leg.cp_key = prop_cp;
        t.short_leg.owner_key = acc_owner;  t.long_leg.cp_key = acc_cp;
    }
    return t;
}

//! Slot the coop INTERNAL keys onto the record per side (each leg's owner=the leg party, cp=counterparty).
void SlotCoopInternals(ScalarCfdContractRecord& record, bool proposer_is_short,
                       const XOnlyPubKey& prop_owner_int, const XOnlyPubKey& prop_cp_int,
                       const XOnlyPubKey& acc_owner_int, const XOnlyPubKey& acc_cp_int)
{
    if (proposer_is_short) {
        record.short_owner_internal = prop_owner_int; record.long_cp_internal = prop_cp_int;
        record.long_owner_internal = acc_owner_int;   record.short_cp_internal = acc_cp_int;
    } else {
        record.long_owner_internal = prop_owner_int;  record.short_cp_internal = prop_cp_int;
        record.short_owner_internal = acc_owner_int;  record.long_cp_internal = acc_cp_int;
    }
}

struct ParsedScalarOffer {
    bool proposer_is_short{false};
    uint256 salt{};
    ScalarCfdContractTerms econ; //!< keys null
    XOnlyPubKey prop_owner{}, prop_cp{};
    XOnlyPubKey prop_owner_internal{}, prop_cp_internal{};
    XOnlyPubKey proposer_adaptor_point{};
};

ParsedScalarOffer ParseScalarOffer(const UniValue& o)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer must be an object");
    if (const UniValue& ver = o.find_value("version"); ver.isNull() || ver.getInt<int64_t>() != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.version must be 1");
    }
    if (o.find_value("contract_type").get_str() != "scalar-cfd") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.contract_type must be \"scalar-cfd\"");
    }
    ParsedScalarOffer po;
    const std::string role = o.find_value("proposer_role").get_str();
    if (role == "short") po.proposer_is_short = true;
    else if (role == "long") po.proposer_is_short = false;
    else throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.proposer_role must be 'long' or 'short'");
    po.salt = ReqHash(o, "salt");
    po.econ = ParseScalarCfdEconomics(o.find_value("terms"));
    po.prop_owner = ParseXOnlyHex(o.find_value("proposer_owner_key"), "offer.proposer_owner_key");
    po.prop_cp = ParseXOnlyHex(o.find_value("proposer_cp_key"), "offer.proposer_cp_key");
    po.prop_owner_internal = ParseXOnlyHex(o.find_value("proposer_owner_internal"), "offer.proposer_owner_internal");
    po.prop_cp_internal = ParseXOnlyHex(o.find_value("proposer_cp_internal"), "offer.proposer_cp_internal");
    if (const UniValue& ap = o.find_value("proposer_adaptor_point"); !ap.isNull()) {
        po.proposer_adaptor_point = ParseXOnlyHex(ap, "offer.proposer_adaptor_point");
    }
    return po;
}

UniValue EconomicsToJSON(const ScalarCfdContractTerms& e)
{
    UniValue t(UniValue::VOBJ);
    t.pushKV("source_type", static_cast<uint64_t>(e.source_type));
    t.pushKV("payoff_mode", static_cast<uint64_t>(e.payoff_mode));
    t.pushKV("underlying_asset_id", e.underlying_asset_id.GetHex());
    t.pushKV("feed_id", static_cast<uint64_t>(e.feed_id));
    t.pushKV("fixing_ref", e.fixing_ref);
    t.pushKV("publication_deadline_height", static_cast<uint64_t>(e.publication_deadline_height));
    t.pushKV("settle_lock_height", static_cast<uint64_t>(e.settle_lock_height));
    t.pushKV("scalar_format_id", static_cast<uint64_t>(e.scalar_format_id));
    t.pushKV("strike", e.strike.GetHex());
    t.pushKV("fallback_scalar", e.fallback_scalar.GetHex());
    t.pushKV("collateral_asset_id", e.collateral_asset_id.GetHex());
    UniValue lj(UniValue::VOBJ), sj(UniValue::VOBJ);
    lj.pushKV("im", strprintf("%llu", (unsigned long long)e.long_leg.im));
    lj.pushKV("lambda_q", static_cast<uint64_t>(e.long_leg.lambda_q));
    sj.pushKV("im", strprintf("%llu", (unsigned long long)e.short_leg.im));
    sj.pushKV("lambda_q", static_cast<uint64_t>(e.short_leg.lambda_q));
    t.pushKV("long", lj);
    t.pushKV("short", sj);
    return t;
}

UniValue OfferToJSON(bool proposer_is_short, const uint256& salt, const ScalarCfdContractTerms& econ,
                     const XOnlyPubKey& prop_owner, const XOnlyPubKey& prop_cp,
                     const XOnlyPubKey& prop_owner_internal, const XOnlyPubKey& prop_cp_internal,
                     const XOnlyPubKey& proposer_adaptor_point)
{
    UniValue offer(UniValue::VOBJ);
    offer.pushKV("version", 1);
    offer.pushKV("contract_type", "scalar-cfd");
    offer.pushKV("proposer_role", proposer_is_short ? "short" : "long");
    offer.pushKV("salt", salt.GetHex());
    offer.pushKV("terms", EconomicsToJSON(econ));
    offer.pushKV("proposer_owner_key", HexStr(prop_owner));
    offer.pushKV("proposer_cp_key", HexStr(prop_cp));
    offer.pushKV("proposer_owner_internal", HexStr(prop_owner_internal));
    offer.pushKV("proposer_cp_internal", HexStr(prop_cp_internal));
    offer.pushKV("proposer_adaptor_point", HexStr(proposer_adaptor_point));
    return offer;
}


// ----- open / record_open helpers -----

//! The committed vault scriptPubKey for one leg: P2TR of the {settle, coop} taptree under NUMS_H.
CScript ScalarCfdVaultSpk(const ScalarCfdContractRecord& record, bool is_short)
{
    TaprootBuilder b = CreateScalarCfdVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
    if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build scalar CFD vault");
    return GetScriptForDestination(WitnessV1Taproot{b.GetOutput()});
}

//! Count outputs that fund a given leg vault with the committed collateral encoding. Native collateral
//! (collateral_id zero): exact native nValue == im and NO AssetTLV. Asset collateral: AssetTag(C, im) at
//! the spk (the native carrier nValue is keeper-funded, not committed, so it is not matched).
int CountScalarVaultOutputs(const std::vector<CTxOut>& vout, const CScript& spk,
                            const uint256& collateral_id, uint64_t im)
{
    const bool native = collateral_id.IsNull();
    int n = 0;
    for (const CTxOut& o : vout) {
        if (o.scriptPubKey != spk) continue;
        if (native) {
            if (!o.HasAssetTLV() && o.nValue >= 0 && static_cast<uint64_t>(o.nValue) == im) ++n;
        } else if (auto tag = assets::ParseAssetTag(o.vExt); tag && tag->id == collateral_id && tag->amount == im) {
            ++n;
        }
    }
    return n;
}

//! True iff this PSBT input is an OP_SCALAR_CFD_SETTLE covenant spend safe to extract without local script
//! verification: its finalized witness must reveal a tapscript leaf that (a) contains OP_SCALAR_CFD_SETTLE
//! AND (b) is genuinely COMMITTED by the spent v1-Taproot output (BIP341 tweak check). (b) is essential —
//! without it a forged final_script_witness carrying an OP_SCALAR_CFD_SETTLE leaf could bypass verification
//! and let finalize emit an invalid transaction. Mirrors difficulty's IsCommittedDiffCfdCovenantInput.
bool IsCommittedScalarCfdCovenantInput(const PSBTInput& in, const CTxIn& txin)
{
    CTxOut utxo;
    if (!in.witness_utxo.IsNull()) {
        utxo = in.witness_utxo;
    } else if (in.non_witness_utxo) {
        if (txin.prevout.n >= in.non_witness_utxo->vout.size()) return false;
        utxo = in.non_witness_utxo->vout[txin.prevout.n];
    } else {
        return false;
    }
    int witver;
    std::vector<unsigned char> program;
    if (!utxo.scriptPubKey.IsWitnessProgram(witver, program)) return false;
    if (witver != 1 || program.size() != 32) return false; // v1 P2TR only

    const std::vector<std::vector<unsigned char>>& full = in.final_script_witness.stack;
    if (full.size() < 2) return false;
    size_t end = full.size();
    if (!full[end - 1].empty() && full[end - 1][0] == ANNEX_TAG) --end; // drop optional annex
    if (end < 2) return false;
    const std::vector<unsigned char>& control = full[end - 1];
    const std::vector<unsigned char>& leaf = full[end - 2];

    if (control.size() < TAPROOT_CONTROL_BASE_SIZE ||
        (control.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0 ||
        control.size() > TAPROOT_CONTROL_MAX_SIZE) {
        return false;
    }

    // The revealed leaf must actually contain OP_SCALAR_CFD_SETTLE (scanned as opcodes, not raw bytes).
    CScript leaf_script(leaf.begin(), leaf.end());
    bool has_settle = false;
    opcodetype op;
    for (CScript::const_iterator pc = leaf_script.begin(); leaf_script.GetOp(pc, op); ) {
        if (op == OP_SCALAR_CFD_SETTLE) { has_settle = true; break; }
    }
    if (!has_settle) return false;

    // Prove the leaf is committed by the spent Taproot output key (tweak check, as VerifyTaprootCommitment).
    const uint256 tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, leaf);
    const uint256 merkle_root = ComputeTaprootMerkleRoot(control, tapleaf_hash);
    const XOnlyPubKey p{std::span{control}.subspan(1, TAPROOT_CONTROL_BASE_SIZE - 1)};
    const XOnlyPubKey q{program};
    return q.CheckTapTweak(p, merkle_root, control[0] & 1);
}

//! Witness weight of a Taproot script-path input revealing `script` + `control_block` with
//! `signature_elements` 64-byte Schnorr sigs (0 for the keyless covenant). Lets FundTransaction size the
//! fee for the pre-selected covenant input the wallet cannot otherwise estimate.
int64_t EstimateTaprootScriptPathInputWeight(size_t script_size, size_t control_block_size, size_t signature_elements)
{
    constexpr int64_t BASE_NONWITNESS_WEIGHT = (32 + 4 + 1 + 4) * WITNESS_SCALE_FACTOR;
    int64_t weight = BASE_NONWITNESS_WEIGHT;
    const size_t stack_elems = signature_elements + 2; // sigs + script + control
    weight += GetSizeOfCompactSize(stack_elems);
    constexpr size_t TAPROOT_SIG_SIZE = 65;
    for (size_t i = 0; i < signature_elements; ++i) weight += GetSizeOfCompactSize(TAPROOT_SIG_SIZE) + TAPROOT_SIG_SIZE;
    weight += GetSizeOfCompactSize(script_size) + script_size;
    weight += GetSizeOfCompactSize(control_block_size) + control_block_size;
    return weight;
}

//! MoneyRange-guarded addition for the agreed coop-output sum (the amounts are user-supplied).
CAmount CheckedAddCoop(CAmount total, CAmount add)
{
    if (!MoneyRange(add) || !MoneyRange(total) || total > MAX_MONEY - add) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "coop output amounts out of range / overflow");
    }
    return total + add;
}

//! Annotate a PSBT input for a 2-of-2 script-path spend of the coop leaf (witness_utxo + tap internal key
//! + merkle root + the leaf's control block set), so each party can sign its half.
void AnnotateCoopLeaf(PSBTInput& in, const CTxOut& vault_txout, const XOnlyPubKey& internal_key,
                      const uint256& merkle_root,
                      const std::pair<std::vector<unsigned char>, int>& leaf_key,
                      const std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>& control_blocks)
{
    in.witness_utxo = vault_txout;
    in.m_tap_internal_key = internal_key;
    in.m_tap_merkle_root = merkle_root;
    in.m_tap_scripts[leaf_key] = control_blocks;
}

//! Embed the fs/contract_meta proprietary global so the atomic-risk-transfer adaptor ceremony can locate
//! this contract from the open PSBT (mirrors difficulty's EmbedFsContractMeta).
void EmbedFsContractMeta(PartiallySignedTransaction& psbt, const uint256& meta)
{
    const std::vector<unsigned char>& ident = wallet::fairsign::Identifier();
    DataStream ss_key{};
    WriteCompactSize(ss_key, PSBT_GLOBAL_PROPRIETARY);
    ss_key << ident;
    WriteCompactSize(ss_key, /*subtype=*/uint64_t{0});
    for (char c : std::string_view("contract_meta")) ss_key << static_cast<uint8_t>(c);

    PSBTProprietary entry;
    entry.identifier = ident;
    entry.subtype = 0;
    entry.key = std::vector<unsigned char>(UCharCast(ss_key.data()), UCharCast(ss_key.data() + ss_key.size()));
    entry.value = std::vector<unsigned char>(meta.begin(), meta.end());
    psbt.m_proprietary.insert(entry);
}

} // namespace

RPCHelpMan scalarcfd_propose()
{
    return RPCHelpMan{
        "scalarcfd.propose",
        "Propose a bilateral scalar-CFD contract. The proposer defines the full economics (the shared "
        "issuer-published scalar fixing + both legs' IM and leverage), picks their side, and supplies their "
        "two P2TR payout addresses (owner = the leg they post / IM return; cp = their claim on the "
        "counterparty's leg). Returns an offer to hand to the counterparty out-of-band. Nothing is persisted "
        "— the record is created by scalarcfd.accept (acceptor) and scalarcfd.import_acceptance (proposer).",
        {
            {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO,
                "Contract economics (no payout keys). Fields: source_type (0=ISSUER_PUBLISHED), payoff_mode "
                "(0=STRIKE,1=REALIZED), underlying_asset_id (hex), feed_id, fixing_ref, publication_deadline_height, "
                "settle_lock_height, scalar_format_id, strike (hex), fallback_scalar (hex), collateral_asset_id "
                "(hex; omit=native), and long/short each an object {im (decimal collateral units), lambda_q (Q16)}",
                {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A terms field"}}},
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's side: \"long\" or \"short\""},
            {"owner", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's P2TR payout address for the leg they post"},
            {"cp", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's P2TR payout address for their claim on the counterparty's leg"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::OBJ_DYN, "offer", "The offer to hand to the counterparty (consumed by scalarcfd.accept)",
                {{RPCResult::Type::ELISION, "", ""}}}}},
        RPCExamples{HelpExampleCli("scalarcfd.propose", "'{...terms...}' \"long\" \"bcrt1p...\" \"bcrt1p...\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            ScalarCfdContractTerms econ = ParseScalarCfdEconomics(request.params[0]);
            // The proposer supplies strike/fallback as a NUMERIC display-hex value; store the format's wire
            // bytes (identity for LE, byte-reversed for BE) so settlement reads back the intended number.
            // This is the sole human-numeric ingress — the offer then carries wire, which accept/import
            // round-trip verbatim (no re-encode), so the two parties commit byte-identical terms.
            {
                uint256 w;
                if (!EncodeScalarToWire(econ.scalar_format_id, econ.strike, w))
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "strike exceeds the scalar_format_id width");
                econ.strike = w;
                if (!EncodeScalarToWire(econ.scalar_format_id, econ.fallback_scalar, w))
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "fallback_scalar exceeds the scalar_format_id width");
                econ.fallback_scalar = w;
            }
            const std::string role = request.params[1].get_str();
            bool proposer_is_short;
            if (role == "short") proposer_is_short = true;
            else if (role == "long") proposer_is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "role must be \"long\" or \"short\"");
            const XOnlyPubKey owner = ParseP2TRXOnly(request.params[2].get_str(), "owner");
            const XOnlyPubKey cp = ParseP2TRXOnly(request.params[3].get_str(), "cp");
            const XOnlyPubKey owner_int = ExtractCoopInternalKey(*pwallet, owner, "owner");
            const XOnlyPubKey cp_int = ExtractCoopInternalKey(*pwallet, cp, "cp");

            const uint256 salt = GetRandHash();

            // Fair-Sign adaptor: derive the proposer's point from the internal key behind its owner payout,
            // bound to the offer commitment (== fs_context). Stateless — re-derived + verified at
            // import_acceptance and at ceremony; only the point is published, the secret is discarded.
            CKey owner_internal_priv;
            if (!GetCoopSignerKey(*pwallet, owner, owner_int, owner_internal_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the private key behind the owner payout address");
            }
            const uint256 fs_context = ComputeScalarCfdOfferCommitment(proposer_is_short, econ, owner, cp, salt);
            const XOnlyPubKey prop_adaptor_point =
                DeriveScalarCfdFsAdaptor(owner_internal_priv, salt, fs_context, SCALAR_CFD_FS_ROLE_PROPOSER).second;

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer", OfferToJSON(proposer_is_short, salt, econ, owner, cp, owner_int, cp_int, prop_adaptor_point));
            return result;
        }};
}

RPCHelpMan scalarcfd_accept()
{
    return RPCHelpMan{
        "scalarcfd.accept",
        "Accept a scalar-CFD offer. Supply your two P2TR payout addresses (owner = the leg you post; cp = "
        "your claim on the proposer's leg). Without options.confirmed this returns the assembled contract_id "
        "for review; with options.confirmed=true it validates the full terms, persists the contract record in "
        "this wallet, and returns an acceptance to hand back to the proposer.",
        {
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The offer object from scalarcfd.propose", std::vector<RPCArg>{}},
            {"owner", RPCArg::Type::STR, RPCArg::Optional::NO, "Acceptor's P2TR payout address for the leg they post"},
            {"cp", RPCArg::Type::STR, RPCArg::Optional::NO, "Acceptor's P2TR payout address for their claim on the proposer's leg"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Acceptance options",
                {{"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Set true (after reviewing terms) to persist + commit"}}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "contract_id", "The assembled contract id"},
                {RPCResult::Type::OBJ_DYN, "acceptance", /*optional=*/true, "Acceptance for the proposer (only when confirmed)",
                    {{RPCResult::Type::ELISION, "", ""}}},
                {RPCResult::Type::STR, "action_required", /*optional=*/true, "Present when not yet confirmed"},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.accept", "'{...offer...}' \"bcrt1p...\" \"bcrt1p...\" '{\"confirmed\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const ParsedScalarOffer po = ParseScalarOffer(request.params[0]);
            const XOnlyPubKey acc_owner = ParseP2TRXOnly(request.params[1].get_str(), "owner");
            const XOnlyPubKey acc_cp = ParseP2TRXOnly(request.params[2].get_str(), "cp");
            const XOnlyPubKey acc_owner_int = ExtractCoopInternalKey(*pwallet, acc_owner, "owner");
            const XOnlyPubKey acc_cp_int = ExtractCoopInternalKey(*pwallet, acc_cp, "cp");
            const ScalarCfdContractTerms terms =
                AssembleScalarCfdTerms(po.econ, po.proposer_is_short, po.prop_owner, po.prop_cp, acc_owner, acc_cp);

            std::string verr;
            if (!terms.Validate(verr)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid terms: " + verr);
            const uint256 contract_id = ComputeScalarCfdContractId(terms, po.salt);

            const UniValue options = request.params[3].isNull() ? UniValue(UniValue::VOBJ) : request.params[3].get_obj();
            const UniValue& confirmed = options.find_value("confirmed");
            UniValue result(UniValue::VOBJ);
            result.pushKV("contract_id", contract_id.GetHex());
            if (confirmed.isNull() || !confirmed.get_bool()) {
                result.pushKV("action_required", "review terms, then call again with options={\"confirmed\":true} to accept");
                return result;
            }

            if (!po.proposer_adaptor_point.IsFullyValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer is missing a valid proposer_adaptor_point");
            }
            CKey acc_owner_priv;
            if (!GetCoopSignerKey(*pwallet, acc_owner, acc_owner_int, acc_owner_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the private key behind the owner payout address");
            }
            const uint256 fs_context = ComputeScalarCfdOfferCommitment(po.proposer_is_short, terms, po.prop_owner, po.prop_cp, po.salt);
            const XOnlyPubKey acc_adaptor_point =
                DeriveScalarCfdFsAdaptor(acc_owner_priv, po.salt, fs_context, SCALAR_CFD_FS_ROLE_ACCEPTOR).second;

            ScalarCfdContractRecord record;
            record.terms = terms;
            record.salt = po.salt;
            record.contract_id = contract_id;
            record.long_internal_key = XOnlyPubKey::NUMS_H;
            record.short_internal_key = XOnlyPubKey::NUMS_H;
            SlotCoopInternals(record, po.proposer_is_short, po.prop_owner_internal, po.prop_cp_internal, acc_owner_int, acc_cp_int);
            record.fs_tx_adaptor_point = po.proposer_adaptor_point;
            record.counterparty_adaptor_point = acc_adaptor_point;
            record.fs_context = fs_context;
            try {
                pwallet->RegisterScalarCfdContract(record);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, e.what());
            }

            UniValue acceptance(UniValue::VOBJ);
            acceptance.pushKV("contract_id", contract_id.GetHex());
            acceptance.pushKV("salt", po.salt.GetHex());
            acceptance.pushKV("acceptor_owner_key", HexStr(acc_owner));
            acceptance.pushKV("acceptor_cp_key", HexStr(acc_cp));
            acceptance.pushKV("acceptor_owner_internal", HexStr(acc_owner_int));
            acceptance.pushKV("acceptor_cp_internal", HexStr(acc_cp_int));
            acceptance.pushKV("acceptor_adaptor_point", HexStr(acc_adaptor_point));
            result.pushKV("acceptance", acceptance);
            return result;
        }};
}

RPCHelpMan scalarcfd_import_acceptance()
{
    return RPCHelpMan{
        "scalarcfd.import_acceptance",
        "Proposer: import the acceptance for an offer you proposed. Reconstructs the full terms from your "
        "original offer plus the acceptor's payout keys, recomputes + VERIFIES the contract_id, re-derives "
        "and verifies the proposer adaptor point, and persists the identical contract record in this wallet. "
        "After this both wallets hold the same record and either party can fund (scalarcfd.build_open) and settle it.",
        {
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Your original offer object from scalarcfd.propose", std::vector<RPCArg>{}},
            {"acceptance", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The acceptance object from the counterparty's scalarcfd.accept", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "contract_id", "The agreed contract id"},
                {RPCResult::Type::STR, "state", "\"accepted\""},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.import_acceptance", "'{...offer...}' '{...acceptance...}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const UniValue& offer = request.params[0];
            const UniValue& acc = request.params[1];
            if (!offer.isObject() || !acc.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer and acceptance must be objects");

            const ParsedScalarOffer po = ParseScalarOffer(offer);
            const XOnlyPubKey acc_owner = ParseXOnlyHex(acc.find_value("acceptor_owner_key"), "acceptance.acceptor_owner_key");
            const XOnlyPubKey acc_cp = ParseXOnlyHex(acc.find_value("acceptor_cp_key"), "acceptance.acceptor_cp_key");
            const XOnlyPubKey acc_owner_int = ParseXOnlyHex(acc.find_value("acceptor_owner_internal"), "acceptance.acceptor_owner_internal");
            const XOnlyPubKey acc_cp_int = ParseXOnlyHex(acc.find_value("acceptor_cp_internal"), "acceptance.acceptor_cp_internal");
            const ScalarCfdContractTerms terms =
                AssembleScalarCfdTerms(po.econ, po.proposer_is_short, po.prop_owner, po.prop_cp, acc_owner, acc_cp);

            // The acceptance echoes the salt; it MUST match the offer's (defends against pairing an
            // acceptance with the wrong offer).
            if (ReqHash(acc, "salt") != po.salt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance salt does not match the offer");
            }

            std::string verr;
            if (!terms.Validate(verr)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid terms: " + verr);
            const uint256 contract_id = ComputeScalarCfdContractId(terms, po.salt);
            const uint256 claimed = ReqHash(acc, "contract_id");
            if (contract_id != claimed) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance contract_id does not match the reconstructed terms");
            }

            // Re-derive the proposer's adaptor (same inputs as at propose) and VERIFY it reproduces the
            // point published in the offer — a strong consistency check before this record can be signed with it.
            if (!po.proposer_adaptor_point.IsFullyValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer is missing a valid proposer_adaptor_point");
            }
            CKey prop_owner_priv;
            if (!GetCoopSignerKey(*pwallet, po.prop_owner, po.prop_owner_internal, prop_owner_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the proposer's owner internal key for adaptor derivation");
            }
            const uint256 fs_context = ComputeScalarCfdOfferCommitment(po.proposer_is_short, terms, po.prop_owner, po.prop_cp, po.salt);
            const XOnlyPubKey rederived =
                DeriveScalarCfdFsAdaptor(prop_owner_priv, po.salt, fs_context, SCALAR_CFD_FS_ROLE_PROPOSER).second;
            if (rederived != po.proposer_adaptor_point) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Re-derived proposer adaptor point does not match the offer");
            }
            const XOnlyPubKey acc_adaptor_point = ParseXOnlyHex(acc.find_value("acceptor_adaptor_point"), "acceptance.acceptor_adaptor_point");
            if (!acc_adaptor_point.IsFullyValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.acceptor_adaptor_point is not a valid x-only point");
            }

            ScalarCfdContractRecord record;
            record.terms = terms;
            record.salt = po.salt;
            record.contract_id = contract_id;
            record.long_internal_key = XOnlyPubKey::NUMS_H;
            record.short_internal_key = XOnlyPubKey::NUMS_H;
            SlotCoopInternals(record, po.proposer_is_short, po.prop_owner_internal, po.prop_cp_internal, acc_owner_int, acc_cp_int);
            record.fs_tx_adaptor_point = po.proposer_adaptor_point;
            record.counterparty_adaptor_point = acc_adaptor_point;
            record.fs_context = fs_context;
            try {
                pwallet->RegisterScalarCfdContract(record);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, e.what());
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("contract_id", contract_id.GetHex());
            result.pushKV("state", "accepted");
            return result;
        }};
}

RPCHelpMan scalarcfd_build_open()
{
    return RPCHelpMan{
        "scalarcfd.build_open",
        "Fund THIS party's IM vault for an already-agreed scalar CFD (created via "
        "scalarcfd.propose/accept/import_acceptance) and return a co-signing PSBT. Two-party ATOMIC open: the "
        "first party calls this for its leg to get a partial PSBT; the counterparty calls it for the other "
        "leg passing options.psbt to augment it, so a single transaction funds BOTH vaults and neither party "
        "fronts the other's margin. Each party then signs its own inputs (walletprocesspsbt); once finalized "
        "+ broadcast, BOTH parties call scalarcfd.record_open. v1 funds NATIVE-collateral vaults only "
        "(asset-collateral open is a later slice).",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scalar CFD contract id (must already exist in this wallet)"},
            {"leg", RPCArg::Type::STR, RPCArg::Optional::NO, "Which leg's IM vault THIS wallet funds: \"long\" or \"short\""},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding options",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Counterparty's partial open PSBT to augment (the second party supplies this)"},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in " + CURRENCY_ATOM + "/vB for this party's inputs"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded open PSBT (this party's leg funded; combined when augmenting)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " (this party's contribution, or the combined fee when augmenting)"},
                {RPCResult::Type::STR, "leg", "The leg this wallet funded"},
                {RPCResult::Type::NUM, "vault_index", "vout index of this leg's IM vault in the returned PSBT"},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.build_open", "\"<contract_id>\" \"long\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const std::string leg_str = request.params[1].get_str();
            bool is_short;
            if (leg_str == "short") is_short = true;
            else if (leg_str == "long") is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "leg must be \"long\" or \"short\"");

            const auto rec_opt = pwallet->FindScalarCfdContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scalar CFD contract (propose/accept it first)");
            const ScalarCfdContractRecord record = *rec_opt;

            // Integrity gate at the build boundary, BEFORE deriving/funding any vault — a record that fails
            // the accepted-state invariants (non-NUMS internals, incomplete coop/FS state) must never be
            // turned into an on-chain vault.
            std::string verr;
            if (!ValidateScalarCfdContractRecord(record, /*expected_key=*/nullptr, verr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Refusing to open an invalid contract record: " + verr);
            }
            // Refuse to fund an already-opened contract — re-funding would create a SECOND pair of vaults
            // and leave one exposure untracked (record_open only records one open tx).
            if (!record.open_txid.IsNull() || !record.long_vault.IsNull() || !record.short_vault.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract is already opened; cannot fund it again");
            }
            if (!record.terms.collateral_asset_id.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-collateral bilateral open is not supported yet (native collateral only)");
            }

            // Both vault scripts (this wallet builds both regardless of which leg it funds).
            TaprootBuilder myb = CreateScalarCfdVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
            if (!myb.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build scalar CFD vault");
            const WitnessV1Taproot my_out{myb.GetOutput()};
            const CScript my_spk = GetScriptForDestination(my_out);
            const CScript other_spk = ScalarCfdVaultSpk(record, !is_short);
            const CScript long_spk = ScalarCfdVaultSpk(record, /*is_short=*/false);
            const CScript short_spk = ScalarCfdVaultSpk(record, /*is_short=*/true);
            const uint64_t my_im_u = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
            const uint64_t other_im_u = (is_short ? record.terms.long_leg : record.terms.short_leg).im;
            const CAmount my_im = static_cast<CAmount>(my_im_u); // native + MoneyRange (terms.Validate)

            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            coin_control.m_change_type = OutputType::BECH32M;
            const UniValue options = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
            if (const UniValue& fr = options.find_value("fee_rate"); !fr.isNull()) {
                const CAmount fee_rate = AmountFromValue(fr, /*decimals=*/3);
                if (fee_rate <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be greater than 0");
                coin_control.m_feerate = CFeeRate{fee_rate};
                coin_control.fOverrideFeeRate = true;
            }
            std::vector<CRecipient> recipients{CRecipient{my_out, my_im, /*fSubtractFeeFromAmount=*/false}};
            CMutableTransaction mytx;
            mytx.version = 2;
            auto myfund = FundTransaction(*pwallet, mytx, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
            if (!myfund) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(myfund).original);
            const CMutableTransaction my_funded{*myfund->tx};

            PartiallySignedTransaction my_psbt{my_funded};
            {
                bool complete = false;
                if (const auto e = pwallet->FillPSBT(my_psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                    throw JSONRPCPSBTError(*e);
                }
            }

            const UniValue& psbt_opt = options.find_value("psbt");
            PartiallySignedTransaction result;
            CAmount fee = myfund->fee;

            if (psbt_opt.isNull()) {
                result = std::move(my_psbt); // FIRST party: just our funded leg
            } else {
                // SECOND party: merge our funded leg into the counterparty's partial PSBT (one atomic tx).
                PartiallySignedTransaction in_psbt;
                std::string derr;
                if (!DecodeBase64PSBT(in_psbt, psbt_opt.get_str(), derr)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", derr));
                }
                if (CountScalarVaultOutputs(in_psbt.tx->vout, other_spk, uint256{}, other_im_u) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Counterparty PSBT must fund exactly one of the other leg's IM vault");
                }
                if (CountScalarVaultOutputs(in_psbt.tx->vout, my_spk, uint256{}, my_im_u) != 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Counterparty PSBT must not already contain this leg's IM vault");
                }

                CMutableTransaction combined{*in_psbt.tx};
                const size_t in_in = combined.vin.size();
                const size_t in_out = combined.vout.size();
                std::set<COutPoint> seen;
                for (const CTxIn& vin : combined.vin) seen.insert(vin.prevout);
                for (const CTxIn& vin : my_funded.vin) {
                    if (!seen.insert(vin.prevout).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Counterparty PSBT shares an input with this wallet");
                    }
                    combined.vin.push_back(vin);
                }
                for (const CTxOut& vout : my_funded.vout) combined.vout.push_back(vout);

                result = PartiallySignedTransaction{combined};
                for (size_t i = 0; i < in_in && i < in_psbt.inputs.size(); ++i) result.inputs[i] = in_psbt.inputs[i];
                for (size_t i = 0; i < in_out && i < in_psbt.outputs.size(); ++i) result.outputs[i] = in_psbt.outputs[i];
                for (size_t j = 0; j < my_psbt.inputs.size(); ++j) result.inputs[in_in + j] = my_psbt.inputs[j];
                for (size_t j = 0; j < my_psbt.outputs.size(); ++j) result.outputs[in_out + j] = my_psbt.outputs[j];

                // Combined fee = sum(input UTXO values) - sum(output values), but only over UNTRUSTED PSBT
                // values guarded by MoneyRange (per addend AND running total). A malformed counterparty PSBT
                // with a missing/out-of-range/overflowing value falls back to this party's own funding fee.
                CAmount tin = 0, tout = 0;
                bool have_all = true;
                for (const PSBTInput& pin : result.inputs) {
                    if (pin.witness_utxo.IsNull() || !MoneyRange(pin.witness_utxo.nValue)) { have_all = false; break; }
                    tin += pin.witness_utxo.nValue;
                    if (!MoneyRange(tin)) { have_all = false; break; }
                }
                if (have_all) {
                    for (const CTxOut& o : result.tx->vout) {
                        if (!MoneyRange(o.nValue)) { have_all = false; break; }
                        tout += o.nValue;
                        if (!MoneyRange(tout)) { have_all = false; break; }
                    }
                }
                if (have_all && tin >= tout) fee = tin - tout;

                if (CountScalarVaultOutputs(result.tx->vout, long_spk, uint256{}, record.terms.long_leg.im) != 1 ||
                    CountScalarVaultOutputs(result.tx->vout, short_spk, uint256{}, record.terms.short_leg.im) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Merged open must fund exactly one long and one short IM vault");
                }
            }

            if (CountScalarVaultOutputs(result.tx->vout, my_spk, uint256{}, my_im_u) != 1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx must contain exactly one of this leg's IM vault");
            }
            int my_idx = -1;
            for (size_t i = 0; i < result.tx->vout.size(); ++i) {
                const CTxOut& o = result.tx->vout[i];
                if (o.scriptPubKey == my_spk && !o.HasAssetTLV() && o.nValue >= 0 && static_cast<uint64_t>(o.nValue) == my_im_u) {
                    my_idx = static_cast<int>(i);
                    break;
                }
            }
            if (my_idx < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx is missing this leg's vault output");

            // Embed fs/contract_meta for the atomic-risk-transfer ceremony (the record validator already
            // guaranteed both adaptor points + a non-null context).
            EmbedFsContractMeta(result, ComputeScalarCfdContractMeta(record));

            DataStream ss{};
            ss << result;
            UniValue out(UniValue::VOBJ);
            out.pushKV("psbt", EncodeBase64(ss.str()));
            out.pushKV("fee", ValueFromAmount(fee));
            out.pushKV("leg", leg_str);
            out.pushKV("vault_index", my_idx);
            return out;
        }};
}

RPCHelpMan scalarcfd_record_open()
{
    return RPCHelpMan{
        "scalarcfd.record_open",
        "Record the funded vault outpoints for an opened scalar CFD. Call this in BOTH wallets after the "
        "co-signed open transaction is broadcast: it locates both IM vault outputs in that transaction (by "
        "their committed scriptPubKeys + collateral encoding), persists their outpoints + the open txid into "
        "the contract record, and re-validates the full opened-state invariant, so either party can settle.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scalar CFD contract id"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The broadcast open transaction id (must be a wallet transaction)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "long_vault", "outpoint of the long IM vault (txid:n)"},
                {RPCResult::Type::STR, "short_vault", "outpoint of the short IM vault (txid:n)"},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.record_open", "\"<contract_id>\" \"<open_txid>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const uint256 txid_u = ParseHashV(request.params[1], "txid");
            const Txid txid = Txid::FromUint256(txid_u);

            const auto rec_opt = pwallet->FindScalarCfdContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scalar CFD contract");
            ScalarCfdContractRecord record = *rec_opt;

            CTransactionRef tx;
            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(txid);
                if (wtx) tx = wtx->tx;
            }
            if (!tx) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid is not a transaction in this wallet");

            // Resolve each leg's funded vault by {rebuilt spk, committed IM/collateral encoding}, requiring
            // EXACTLY ONE match (reject duplicate/ambiguous/wrong-value).
            const auto find_unique_vault = [&](bool is_short) -> int {
                const CScript spk = ScalarCfdVaultSpk(record, is_short);
                const uint64_t im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
                const uint256& c = record.terms.collateral_asset_id;
                if (CountScalarVaultOutputs(tx->vout, spk, c, im) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction does not contain exactly one of the contract vault(s)");
                }
                const bool native = c.IsNull();
                for (size_t i = 0; i < tx->vout.size(); ++i) {
                    const CTxOut& o = tx->vout[i];
                    if (o.scriptPubKey != spk) continue;
                    if (native) {
                        if (!o.HasAssetTLV() && o.nValue >= 0 && static_cast<uint64_t>(o.nValue) == im) return static_cast<int>(i);
                    } else if (auto tag = assets::ParseAssetTag(o.vExt); tag && tag->id == c && tag->amount == im) {
                        return static_cast<int>(i);
                    }
                }
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction does not contain the contract vault");
            };

            const COutPoint new_long(txid, static_cast<uint32_t>(find_unique_vault(/*is_short=*/false)));
            const COutPoint new_short(txid, static_cast<uint32_t>(find_unique_vault(/*is_short=*/true)));

            // Idempotency / double-open guard: if this contract was already opened, only accept a re-record
            // of the EXACT same open (same tx + same outpoints); a different open tx is rejected so the
            // recorded exposure can never be silently overwritten.
            const bool already_opened = !record.open_txid.IsNull() || !record.long_vault.IsNull() || !record.short_vault.IsNull();
            if (already_opened) {
                if (record.open_txid != txid_u || record.long_vault != new_long || record.short_vault != new_short) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract is already opened with a different transaction");
                }
                // Same open already recorded — idempotent no-op.
            } else {
                record.open_txid = txid_u;
                record.long_vault = new_long;
                record.short_vault = new_short;
                // RegisterScalarCfdContract runs the STATE-AWARE validator: with the vaults now set it
                // enforces the full opened-state invariant (open_txid + both outpoints non-null/distinct +
                // referencing the open tx).
                try {
                    pwallet->RegisterScalarCfdContract(record);
                } catch (const std::exception& e) {
                    throw JSONRPCError(RPC_WALLET_ERROR, e.what());
                }
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("long_vault", new_long.ToString());
            out.pushKV("short_vault", new_short.ToString());
            return out;
        }};
}

RPCHelpMan scalarcfd_build_settlement()
{
    return RPCHelpMan{
        "scalarcfd.build_settlement",
        "Build the keeper settlement PSBT for one leg of a scalar CFD: spend that leg's IM vault through its "
        "unilateral OP_SCALAR_CFD_SETTLE covenant leaf (signatureless) and pay the exact computed payout "
        "outputs, with the broadcaster's external native input covering the fee (the covenant outputs are "
        "never shaved). The scalar fixing is resolved from the active chain at the committed feed/epoch "
        "(buried by SCALARCFD_MATURITY_DEPTH, or the committed fallback past deadline+grace). v1 settles "
        "NATIVE-collateral vaults only. The returned PSBT has the vault input ALREADY FINALIZED "
        "([leaf, control]); keeper flow: sign the fee input with walletprocesspsbt, extract with "
        "scalarcfd.finalize_settlement, then sendrawtransaction (NOT finalizepsbt — it re-verifies the covenant "
        "leaf, which needs a chain fixing context).",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scalar CFD contract id"},
            {"leg", RPCArg::Type::STR, RPCArg::Optional::NO, "Which leg to settle: \"long\" or \"short\""},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding overrides",
                {{"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in " + CURRENCY_ATOM + "/vB"}}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded settlement PSBT (vault input finalized; fee input to be signed)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "The keeper fee in " + CURRENCY_UNIT},
                {RPCResult::Type::STR_AMOUNT, "payout_owner", "Native amount returned to this leg's owner"},
                {RPCResult::Type::STR_AMOUNT, "payout_cp", "Native amount paid to the counterparty"},
                {RPCResult::Type::BOOL, "is_fallback", "true if the committed fallback scalar fired"},
                {RPCResult::Type::NUM, "vault_input_index", "vin index of the spent vault"},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.build_settlement", "\"<contract_id>\" \"short\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const std::string leg_str = request.params[1].get_str();
            bool is_short;
            if (leg_str == "short") is_short = true;
            else if (leg_str == "long") is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "leg must be \"long\" or \"short\"");

            const auto rec_opt = pwallet->FindScalarCfdContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scalar CFD contract");
            const ScalarCfdContractRecord record = *rec_opt;
            const ScalarCfdContractTerms& t = record.terms;

            // Front-load integrity: the record must pass the full (opened-state) invariant before we build.
            std::string verr;
            if (!ValidateScalarCfdContractRecord(record, /*expected_key=*/nullptr, verr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Refusing to settle an invalid contract record: " + verr);
            }
            if (!t.collateral_asset_id.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-collateral settlement is not supported yet (native collateral only)");
            }
            const COutPoint vault_op = record.VaultOutpoint(is_short);
            if (vault_op.IsNull()) throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no funded vault for this leg (not opened?)");

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            const Consensus::Params& consensus = Params().GetConsensus();

            // Read the unspent vault UTXO + resolve the fixing under cs_main, released BEFORE FundTransaction.
            CTxOut vault_txout;
            std::optional<ResolvedScalar> resolved;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                const auto coin = coins.GetCoin(vault_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint is missing or already spent");
                vault_txout = coin->out;
                const int ctx_height = chainman.ActiveChain().Height();
                if (ctx_height < 0) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                auto reader = [&](const uint256& aid, uint32_t feed, uint64_t epoch) -> std::optional<ScalarRecord> {
                    ScalarRecord r;
                    if (coins.ReadAssetScalar(aid, feed, epoch, r)) return r;
                    return std::nullopt;
                };
                resolved = ResolveScalarFixing(t.underlying_asset_id, t.feed_id, t.fixing_ref, t.publication_deadline_height,
                                               t.fallback_scalar, t.scalar_format_id, ctx_height,
                                               consensus.SCALARCFD_MATURITY_DEPTH, consensus.SCALARCFD_FALLBACK_GRACE, reader);
            }
            if (!resolved) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fixing not resolvable yet (no buried in-time publication and deadline+grace not elapsed)");
            }

            // Front-load vault match (user-requested guard): the recorded UTXO must STILL be exactly the
            // vault this record describes — rebuilt covenant spk + committed native collateral — else the
            // PSBT would fund + serialize yet be consensus-invalid.
            const ScalarCfdLegTerms& leg = is_short ? t.short_leg : t.long_leg;
            {
                const CScript expected_spk = ScalarCfdVaultSpk(record, is_short);
                if (vault_txout.scriptPubKey != expected_spk || vault_txout.HasAssetTLV() ||
                    vault_txout.nValue < 0 || static_cast<uint64_t>(vault_txout.nValue) != leg.im) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Recorded vault UTXO does not match the contract (stale/corrupt record?)");
                }
            }

            arith_uint256 realized;
            if (!DecodeScalarValue(resolved->scalar_format_id, resolved->scalar, realized)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Resolved scalar decode failed");
            }

            ScalarCfdSettlementSkeleton skel;
            std::string serr;
            if (!BuildScalarCfdSettlementSkeleton(record, is_short, realized, skel, serr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Settlement build failed: " + serr);
            }
            // Defensive: ComputeScalarCfdPayout snaps a sub-dust leg to the surviving leg (= vault_im >=
            // MIN_SETTLE_OUTPUT), so >=1 payout is always present — but refuse a zero-output settlement
            // outright rather than fund a tx that would spend the vault into only change.
            if (skel.payouts.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No non-dust settlement outputs for this leg");
            }
            const std::vector<unsigned char>& leaf_bytes = skel.vault_input.scriptWitness.stack.at(0);
            const std::vector<unsigned char>& control = skel.vault_input.scriptWitness.stack.at(1);

            // Funding paradigm (mirrors difficulty / repo-repay): pre-select the covenant vault as a fixed
            // input with its UTXO + explicit script-path weight (the wallet can't size a keyless covenant),
            // pass the payouts as recipients, FundTransaction adds the external native fee input + change.
            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            coin_control.m_change_type = OutputType::BECH32M;
            const UniValue options = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
            if (const UniValue& fr = options.find_value("fee_rate"); !fr.isNull()) {
                const CAmount fee_rate = AmountFromValue(fr, /*decimals=*/3);
                if (fee_rate <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_rate must be greater than 0");
                coin_control.m_feerate = CFeeRate{fee_rate};
                coin_control.fOverrideFeeRate = true;
            }
            PreselectedInput& preset = coin_control.Select(vault_op);
            preset.SetTxOut(vault_txout);
            preset.SetSequence(skel.vault_input.nSequence);
            preset.SetScriptWitness(skel.vault_input.scriptWitness);
            coin_control.SetInputWeight(vault_op,
                EstimateTaprootScriptPathInputWeight(leaf_bytes.size(), control.size(), /*signature_elements=*/0));

            CMutableTransaction tx;
            tx.version = 2;
            tx.nLockTime = skel.nlocktime;
            tx.vin.push_back(skel.vault_input);

            std::vector<CRecipient> recipients;
            if (skel.payout.payout_owner > 0) recipients.push_back({WitnessV1Taproot{leg.owner_key}, static_cast<CAmount>(skel.payout.payout_owner), false});
            if (skel.payout.payout_cp > 0) recipients.push_back({WitnessV1Taproot{leg.cp_key}, static_cast<CAmount>(skel.payout.payout_cp), false});

            auto fund_res = FundTransaction(*pwallet, tx, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
            if (!fund_res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original);
            CMutableTransaction funded{*fund_res->tx};
            const CAmount fee = fund_res->fee;

            int vault_in_idx = -1;
            for (size_t i = 0; i < funded.vin.size(); ++i) {
                if (funded.vin[i].prevout == vault_op) { vault_in_idx = static_cast<int>(i); break; }
            }
            if (vault_in_idx < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx lost the vault input");

            // A PSBT's unsigned tx carries empty scriptSigs/witnesses; the covenant witness lives in the
            // PSBT input's final_script_witness (set last so FillPSBT's SignPSBTInput doesn't drop it).
            for (auto& vin : funded.vin) { vin.scriptSig.clear(); vin.scriptWitness.SetNull(); }

            PartiallySignedTransaction psbtx{funded};
            bool complete = false;
            if (const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                throw JSONRPCPSBTError(*fill_err);
            }
            {
                PSBTInput& vin_psbt = psbtx.inputs[vault_in_idx];
                vin_psbt.witness_utxo = vault_txout;
                vin_psbt.final_script_witness.stack = {leaf_bytes, control};
            }

            DataStream ss{};
            ss << psbtx;
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ss.str()));
            result.pushKV("fee", ValueFromAmount(fee));
            result.pushKV("payout_owner", ValueFromAmount(static_cast<CAmount>(skel.payout.payout_owner)));
            result.pushKV("payout_cp", ValueFromAmount(static_cast<CAmount>(skel.payout.payout_cp)));
            result.pushKV("is_fallback", resolved->is_fallback);
            result.pushKV("vault_input_index", vault_in_idx);
            return result;
        }};
}

RPCHelpMan scalarcfd_finalize_settlement()
{
    return RPCHelpMan{
        "scalarcfd.finalize_settlement",
        "Extract the final raw transaction from a fully-prepared scalar settlement PSBT (the keyless "
        "OP_SCALAR_CFD_SETTLE covenant vault input finalized by scalarcfd.build_settlement, plus the fee input "
        "signed via walletprocesspsbt). Unlike finalizepsbt, this does NOT re-verify the covenant input — "
        "OP_SCALAR_CFD_SETTLE cannot be verified without a chain fixing context the PSBT layer lacks, and the "
        "node fully validates on submission. Verification is skipped ONLY for inputs whose finalized leaf "
        "contains OP_SCALAR_CFD_SETTLE AND is committed by the spent Taproot output; ALL other inputs are "
        "verified normally, and at least one committed covenant input is required.",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO,
             "A settlement PSBT in which every input is finalized (vault witness from build_settlement; fee "
             "input signed + finalized via walletprocesspsbt)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "hex", "The extracted network-serialized transaction, ready for sendrawtransaction"}}},
        RPCExamples{HelpExampleCli("scalarcfd.finalize_settlement", "\"<psbt>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            PartiallySignedTransaction psbtx;
            std::string err;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", err));
            }

            // Assemble final witnesses for any signed inputs (e.g. the fee input). The covenant input is
            // already final; FinalizePSBT preserves it. The overall "complete" flag is ignored (always false
            // since the covenant input can't be script-verified here).
            FinalizePSBT(psbtx);

            // Bypass verification ONLY for genuine OP_SCALAR_CFD_SETTLE covenant input(s) — leaf contains the
            // opcode AND is committed by the spent Taproot output (the node validates them with the real
            // fixing context on submission). EVERY other input must finalize AND verify, and at least one
            // committed covenant input must be present — so this cannot extract an arbitrary unverified tx.
            const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
            CMutableTransaction mtx{*psbtx.tx};
            bool found_covenant = false;
            for (size_t i = 0; i < mtx.vin.size(); ++i) {
                const PSBTInput& in = psbtx.inputs[i];
                if (IsCommittedScalarCfdCovenantInput(in, mtx.vin[i])) {
                    found_covenant = true;
                } else if (!PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Input %u is not finalized and verified (sign every non-covenant input first)", i));
                }
                mtx.vin[i].scriptSig = in.final_script_sig;
                mtx.vin[i].scriptWitness = in.final_script_witness;
            }
            if (!found_covenant) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "PSBT has no committed OP_SCALAR_CFD_SETTLE input — this RPC only extracts scalar settlements");
            }

            DataStream ssTx;
            ssTx << TX_WITH_WITNESS(CTransaction(mtx));
            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", HexStr(ssTx));
            return result;
        }};
}

RPCHelpMan scalarcfd_price()
{
    return RPCHelpMan{
        "scalarcfd.price",
        "Mark a bilateral scalar CFD to market. The underlying is the FX cross rate X = base/quote published "
        "by the contract's feed; the current/realized cross rate is read live from the chain, the forward F "
        "from the per-(underlying, feed, collateral) forward curve (or an inline override, else flat), the "
        "discount factor from the COLLATERAL asset's discount curve, and vol from an inline override. Returns "
        "the long/short MTM (collateral numeraire) + greeks, sharing the consensus payout convention exactly.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scalar CFD contract id"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Pricing overrides",
                {
                    {"source", RPCArg::Type::STR, RPCArg::Default{"market"}, "Curve tier: \"mark\" or \"market\""},
                    {"forward_cross_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override the forward F (same units as the scalar)"},
                    {"sigma", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override the annualized vol of log X"},
                    {"discount_factor", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override the collateral-asset PV discount factor"},
                    {"greeks", RPCArg::Type::BOOL, RPCArg::Default{true}, "Compute delta/vega/theta"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "contract_id", "The contract id"},
            {RPCResult::Type::NUM, "current_ratio", "X_now / K"},
            {RPCResult::Type::NUM, "forecast_ratio", "F / K"},
            {RPCResult::Type::NUM, "sigma", ""}, {RPCResult::Type::NUM, "tau_years", ""},
            {RPCResult::Type::NUM, "discount_factor", ""}, {RPCResult::Type::STR, "forward_provenance", ""},
            {RPCResult::Type::BOOL, "fixing_reached", ""}, {RPCResult::Type::BOOL, "is_fallback", "the known fixing is the committed fallback"},
            {RPCResult::Type::BOOL, "collateral_is_native", ""},
            {RPCResult::Type::NUM, "intrinsic_long_mtm", ""}, {RPCResult::Type::NUM, "intrinsic_short_mtm", ""},
            {RPCResult::Type::NUM, "expected_long_mtm", ""}, {RPCResult::Type::NUM, "expected_short_mtm", ""},
            {RPCResult::Type::NUM, "long_delta_to_cross_rate", ""}, {RPCResult::Type::NUM, "short_delta_to_cross_rate", ""},
            {RPCResult::Type::NUM, "long_vega", ""}, {RPCResult::Type::NUM, "short_vega", ""},
            {RPCResult::Type::NUM, "long_theta", ""}, {RPCResult::Type::NUM, "short_theta", ""},
            {RPCResult::Type::BOOL, "model_unreliable", ""},
            {RPCResult::Type::ARR, "warnings", "", {{RPCResult::Type::STR, "", ""}}},
        }},
        RPCExamples{HelpExampleCli("scalarcfd.price", "\"<contract_id>\" '{\"sigma\":0.4}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const auto rec_opt = pwallet->FindScalarCfdContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scalar CFD contract");
            const ScalarCfdContractTerms& t = rec_opt->terms;

            const UniValue options = request.params[1].isNull() ? UniValue(UniValue::VOBJ) : request.params[1].get_obj();
            pricing::PriceSource source = pricing::PriceSource::MARKET;
            if (const UniValue& s = options.find_value("source"); !s.isNull()) {
                const std::string sv = s.get_str();
                if (sv == "mark") source = pricing::PriceSource::MARK;
                else if (sv == "market") source = pricing::PriceSource::MARKET;
                else throw JSONRPCError(RPC_INVALID_PARAMETER, "source must be \"mark\" or \"market\"");
            }
            const bool greeks = options.find_value("greeks").isNull() || options.find_value("greeks").get_bool();

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            const Consensus::Params& consensus = Params().GetConsensus();

            pricing::ScalarCfdMarketInputs mkt;
            mkt.collateral_is_native = t.collateral_asset_id.IsNull();
            std::vector<pricing::Warning> warnings;
            int current_height = 0;
            {
                LOCK(cs_main);
                auto& coins = chainman.ActiveChainstate().CoinsTip();
                current_height = chainman.ActiveChain().Height();
                if (current_height < 0) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");

                // Current cross rate = the latest published scalar for the feed, ONLY if its encoding matches
                // the contract's scalar_format_id (else decoding foreign bytes under our format would
                // misprice — flat at the strike + warn). Flat at strike when no feed yet.
                uint64_t last_epoch = 0;
                ScalarRecord head_rec;
                if (coins.ReadAssetScalarHead(t.underlying_asset_id, t.feed_id, last_epoch) &&
                    coins.ReadAssetScalar(t.underlying_asset_id, t.feed_id, last_epoch, head_rec) &&
                    head_rec.scalar_format_id == t.scalar_format_id) {
                    mkt.current_scalar = head_rec.scalar;
                } else {
                    mkt.current_scalar = t.strike; // no matching feed -> R=1 (no intrinsic move)
                    warnings.push_back(pricing::Warning::Info(pricing::WarningCategory::COVERAGE,
                        "No published scalar in the contract's format for the feed; intrinsic marks flat at the strike"));
                }
                // Realized fixing (buried real publication or committed fallback past deadline+grace).
                auto reader = [&](const uint256& aid, uint32_t feed, uint64_t epoch) -> std::optional<ScalarRecord> {
                    ScalarRecord r;
                    if (coins.ReadAssetScalar(aid, feed, epoch, r)) return r;
                    return std::nullopt;
                };
                if (auto resolved = ResolveScalarFixing(t.underlying_asset_id, t.feed_id, t.fixing_ref,
                        t.publication_deadline_height, t.fallback_scalar, t.scalar_format_id, current_height,
                        consensus.SCALARCFD_MATURITY_DEPTH, consensus.SCALARCFD_FALLBACK_GRACE, reader)) {
                    mkt.realized_scalar = resolved->scalar;
                    mkt.realized_is_fallback = resolved->is_fallback; // distinguish a fallback from a real fixing
                }
            }

            mkt.current_height = current_height;
            const int64_t spacing = consensus.nPowTargetSpacing > 0 ? consensus.nPowTargetSpacing : 600;
            const int blocks_to_deadline = std::max<int64_t>(0, static_cast<int64_t>(t.publication_deadline_height) - current_height);
            mkt.blocks_to_fixing = blocks_to_deadline;
            mkt.tau_years = static_cast<double>(blocks_to_deadline) * static_cast<double>(spacing) / 31'536'000.0;

            pricing::PricingContext& ctx = pwallet->GetPricingContext();

            // Forward F: explicit override -> per-feed forward curve -> flat (current).
            if (const UniValue& fo = options.find_value("forward_cross_rate"); !fo.isNull()) {
                mkt.forward_cross_rate = fo.get_real();
                mkt.forward_provenance = pricing::ScalarCurveProvenance::MARK;
            } else if (auto curve = ctx.GetScalarForwardCurve(
                           pricing::ScalarFeedKey{t.underlying_asset_id, t.feed_id, t.collateral_asset_id}, source)) {
                std::vector<pricing::Warning> cw;
                if (auto f = curve->ForwardCrossRate(static_cast<uint32_t>(blocks_to_deadline), cw)) {
                    mkt.forward_cross_rate = *f;
                    mkt.forward_provenance = curve->provenance;
                }
                warnings.insert(warnings.end(), cw.begin(), cw.end());
            } else {
                mkt.forward_cross_rate = 0.0; // flat (pricer falls back to current)
                mkt.forward_provenance = pricing::ScalarCurveProvenance::FLAT;
                warnings.push_back(pricing::Warning::Info(pricing::WarningCategory::COVERAGE,
                    "No scalar forward curve for this feed; using the current cross rate as a flat forecast"));
            }

            // Vol: explicit override -> 0 (deterministic point forecast; per-feed vol surface is a follow-up).
            if (const UniValue& so = options.find_value("sigma"); !so.isNull()) mkt.sigma = so.get_real();

            // Discount factor: explicit override -> the COLLATERAL asset's discount curve -> 1.
            if (const UniValue& d = options.find_value("discount_factor"); !d.isNull()) {
                mkt.discount_factor = d.get_real();
            } else if (auto dc = ctx.GetCurve(t.collateral_asset_id, mkt.collateral_is_native, source)) {
                // The cashflow cannot settle before BOTH the CLTV and the fixing being resolvable — worst
                // case the deadline + effective grace (grace clamped >= maturity, mirroring the resolver).
                // Settle_lock can legally precede the deadline, so discount to the LATER of the two.
                const int64_t eff_grace = std::max<int64_t>(consensus.SCALARCFD_FALLBACK_GRACE, consensus.SCALARCFD_MATURITY_DEPTH);
                const int64_t resolvable_h = static_cast<int64_t>(t.publication_deadline_height) + eff_grace;
                const int64_t settle_h = mkt.realized_scalar.has_value()
                    ? static_cast<int64_t>(t.settle_lock_height) // fixing already resolved -> the CLTV governs
                    : std::max<int64_t>(static_cast<int64_t>(t.settle_lock_height), resolvable_h);
                const int64_t settle_blocks = std::max<int64_t>(0, settle_h - current_height);
                const double days = static_cast<double>(settle_blocks) * static_cast<double>(spacing) / 86400.0;
                std::vector<pricing::Warning> dw;
                mkt.discount_factor = dc->GetDiscountFactor(static_cast<uint32_t>(std::lround(days)), dw);
                warnings.insert(warnings.end(), dw.begin(), dw.end());
            } else {
                mkt.discount_factor = 1.0;
                warnings.push_back(pricing::Warning::Info(pricing::WarningCategory::COVERAGE,
                    "No collateral discount curve; scalar MTM is undiscounted (DF=1)"));
            }

            pricing::ScalarCfdValuation v = pricing::ScalarCfdPricer::Price(t, mkt, greeks);
            // Prepend the RPC-resolution warnings (curve/feed coverage) to the pricer's own.
            v.warnings.insert(v.warnings.begin(), warnings.begin(), warnings.end());

            UniValue out(UniValue::VOBJ);
            out.pushKV("contract_id", contract_id.GetHex());
            out.pushKV("current_ratio", v.current_ratio);
            out.pushKV("forecast_ratio", v.forecast_ratio);
            out.pushKV("sigma", v.sigma);
            out.pushKV("tau_years", v.tau_years);
            out.pushKV("discount_factor", v.discount_factor);
            out.pushKV("forward_provenance", v.forward_provenance);
            out.pushKV("fixing_reached", v.fixing_reached);
            out.pushKV("is_fallback", v.is_fallback);
            out.pushKV("collateral_is_native", v.collateral_is_native);
            out.pushKV("intrinsic_long_mtm", v.intrinsic_long_mtm);
            out.pushKV("intrinsic_short_mtm", v.intrinsic_short_mtm);
            out.pushKV("expected_long_mtm", v.expected_long_mtm);
            out.pushKV("expected_short_mtm", v.expected_short_mtm);
            out.pushKV("long_delta_to_cross_rate", v.long_delta_to_cross_rate);
            out.pushKV("short_delta_to_cross_rate", v.short_delta_to_cross_rate);
            out.pushKV("long_vega", v.long_vega);
            out.pushKV("short_vega", v.short_vega);
            out.pushKV("long_theta", v.long_theta);
            out.pushKV("short_theta", v.short_theta);
            out.pushKV("model_unreliable", v.model_unreliable);
            UniValue warr(UniValue::VARR);
            for (const pricing::Warning& w : v.warnings) warr.push_back(w.message);
            out.pushKV("warnings", warr);
            return out;
        }};
}

RPCHelpMan scalarcfd_build_coop_close()
{
    return RPCHelpMan{
        "scalarcfd.build_coop_close",
        "Build a cooperative-close PSBT that spends one leg's vault via its 2-of-2 cosign leaf to a "
        "mutually-agreed set of outputs — an early/negotiated settlement that bypasses the deterministic "
        "covenant (no maturity/burial wait). The vault funds the fee, so the agreed outputs must sum to <= the "
        "vault value (the remainder is the fee). Both parties must sign: each calls scalarcfd.sign_coop on the "
        "returned PSBT in turn (NOT walletprocesspsbt); the second sign_coop returns the broadcastable hex. "
        "The unilateral OP_SCALAR_CFD_SETTLE leaf remains the trustless fallback. v1: native-collateral only.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scalar CFD contract id"},
            {"leg", RPCArg::Type::STR, RPCArg::Optional::NO, "Which vault to close: \"long\" or \"short\""},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Agreed outputs (sum <= vault value; the remainder is the fee)",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount"},
                        }},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded cooperative-close PSBT (spends the 2-of-2 coop leaf; both parties sign)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "The fee (vault value minus the agreed outputs) in " + CURRENCY_UNIT},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.build_coop_close",
            "\"<contract_id>\" \"long\" '[{\"address\":\"bcrt1p...\",\"amount\":\"5\"}]'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const std::string leg_str = request.params[1].get_str();
            bool is_short;
            if (leg_str == "short") is_short = true;
            else if (leg_str == "long") is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "leg must be \"long\" or \"short\"");

            const auto rec_opt = pwallet->FindScalarCfdContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scalar CFD contract");
            const ScalarCfdContractRecord record = *rec_opt;

            std::string verr;
            if (!ValidateScalarCfdContractRecord(record, /*expected_key=*/nullptr, verr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Refusing to coop-close an invalid contract record: " + verr);
            }
            if (!record.terms.collateral_asset_id.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-collateral cooperative close is not supported yet (native collateral only)");
            }
            const COutPoint vault_op = record.VaultOutpoint(is_short);
            if (vault_op.IsNull()) throw JSONRPCError(RPC_WALLET_ERROR, "Vault not opened/recorded for this leg");

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);
            CTxOut vault_txout;
            {
                LOCK(cs_main);
                const auto coin = chainman.ActiveChainstate().CoinsTip().GetCoin(vault_op);
                if (!coin || coin->IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint is missing or already spent");
                vault_txout = coin->out;
            }

            // Reconstruct the vault + coop leaf control block; verify the UTXO is EXACTLY this vault (rebuilt
            // covenant spk + native + recorded IM), so a stale record cannot coop-close a wrong UTXO.
            TaprootBuilder b = CreateScalarCfdVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
            if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Vault internal key is not set/valid");
            const uint64_t leg_im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
            if (vault_txout.scriptPubKey != GetScriptForDestination(WitnessV1Taproot{b.GetOutput()})
                || vault_txout.HasAssetTLV() || vault_txout.nValue < 0 || static_cast<uint64_t>(vault_txout.nValue) != leg_im) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Recorded vault UTXO does not match the contract (stale/corrupt record?)");
            }
            const CScript coop_leaf = BuildScalarCfdCoopLeaf(record, is_short);
            const std::vector<unsigned char> coop_leaf_vec(coop_leaf.begin(), coop_leaf.end());
            const TaprootSpendData spend = b.GetSpendData();
            const auto sit = spend.scripts.find({coop_leaf_vec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
            if (sit == spend.scripts.end() || sit->second.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not reconstruct the cooperative leaf control block");
            }

            // Build the agreed close tx (vault input -> agreed outputs; the vault funds the fee).
            CMutableTransaction tx;
            tx.version = 2;
            CTxIn vin(vault_op);
            vin.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(vin);
            const UniValue& outs = request.params[2].get_array();
            if (outs.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs must not be empty");
            CAmount out_sum = 0;
            for (size_t i = 0; i < outs.size(); ++i) {
                const UniValue& o = outs[i];
                const CTxDestination dest = DecodeDestination(o.find_value("address").get_str());
                if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output address");
                const CAmount amt = AmountFromValue(o.find_value("amount"));
                if (amt < MIN_SETTLE_OUTPUT) throw JSONRPCError(RPC_INVALID_PARAMETER, "Output amount below dust");
                out_sum = CheckedAddCoop(out_sum, amt);
                tx.vout.push_back(CTxOut(amt, GetScriptForDestination(dest)));
            }
            if (out_sum > vault_txout.nValue) throw JSONRPCError(RPC_INVALID_PARAMETER, "Agreed outputs exceed the vault value");
            const CAmount fee = vault_txout.nValue - out_sum;

            PartiallySignedTransaction psbtx{tx};
            AnnotateCoopLeaf(psbtx.inputs[0], vault_txout, record.VaultInternalKey(is_short),
                             spend.merkle_root, sit->first, sit->second);

            DataStream ss{};
            ss << psbtx;
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ss.str()));
            result.pushKV("fee", ValueFromAmount(fee));
            return result;
        }};
}

RPCHelpMan scalarcfd_sign_coop()
{
    return RPCHelpMan{
        "scalarcfd.sign_coop",
        "Add THIS wallet's half of the 2-of-2 cooperative-close signature to a PSBT from "
        "scalarcfd.build_coop_close, and — once BOTH parties have signed — assemble the final witness and "
        "return the broadcastable transaction. Each party signs the coop leaf "
        "(<owner_internal> CHECKSIGVERIFY <cp_internal> CHECKSIG) with a raw Schnorr tapscript signature over "
        "its own internal key. This does NOT use walletprocesspsbt (the standard signer refuses covenant "
        "inputs it does not own). Flow: party A builds + sign_coop, sends to B, who sign_coops to get "
        "{complete:true, hex}, then sendrawtransaction.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scalar CFD contract id"},
            {"leg", RPCArg::Type::STR, RPCArg::Optional::NO, "Which leg's vault is being closed: \"long\" or \"short\""},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64 cooperative-close PSBT (from build_coop_close, or a partner-signed PSBT)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "complete", "True when both parties have signed (then `hex` is present)"},
                {RPCResult::Type::STR, "psbt", "The PSBT with this wallet's partial signature added"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The extracted transaction, present only when complete"},
            }},
        RPCExamples{HelpExampleCli("scalarcfd.sign_coop", "\"<contract_id>\" \"long\" \"<psbt>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const std::string leg_str = request.params[1].get_str();
            bool is_short;
            if (leg_str == "short") is_short = true;
            else if (leg_str == "long") is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "leg must be \"long\" or \"short\"");

            const auto rec_opt = pwallet->FindScalarCfdContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scalar CFD contract");
            const ScalarCfdContractRecord record = *rec_opt;
            const COutPoint vault_op = record.VaultOutpoint(is_short);
            if (vault_op.IsNull()) throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no funded vault for this leg");
            if (record.CoopOwnerInternal(is_short).IsNull() || record.CoopCpInternal(is_short).IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no cooperative-close keys");
            }

            PartiallySignedTransaction psbtx;
            std::string err;
            if (!DecodeBase64PSBT(psbtx, request.params[2].get_str(), err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("PSBT decode failed: %s", err));
            }
            if (!psbtx.tx) throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");

            int vidx = -1;
            for (size_t i = 0; i < psbtx.tx->vin.size(); ++i) {
                if (psbtx.tx->vin[i].prevout == vault_op) { vidx = static_cast<int>(i); break; }
            }
            if (vidx < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT does not spend this leg's vault outpoint");
            PSBTInput& in = psbtx.inputs[vidx];
            if (in.witness_utxo.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Coop PSBT input is missing its witness_utxo");

            // Reconstruct the coop leaf/control/tapleaf hash and verify the spent UTXO is exactly this vault
            // (covenant spk + native + recorded IM) — never sign against a substituted output/leaf.
            TaprootBuilder b = CreateScalarCfdVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
            if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Vault internal key is not set/valid");
            const uint64_t leg_im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
            if (in.witness_utxo.scriptPubKey != GetScriptForDestination(WitnessV1Taproot{b.GetOutput()})
                || in.witness_utxo.HasAssetTLV() || in.witness_utxo.nValue < 0 || static_cast<uint64_t>(in.witness_utxo.nValue) != leg_im) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT vault input does not match the contract");
            }
            const CScript coop_leaf = BuildScalarCfdCoopLeaf(record, is_short);
            const std::vector<unsigned char> coop_leaf_vec(coop_leaf.begin(), coop_leaf.end());
            const std::pair<std::vector<unsigned char>, int> leaf_key{coop_leaf_vec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)};
            const TaprootSpendData spend = b.GetSpendData();
            const auto sit = spend.scripts.find(leaf_key);
            if (sit == spend.scripts.end() || sit->second.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not reconstruct the cooperative leaf control block");
            }
            const uint256 leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, coop_leaf_vec);

            in.m_tap_internal_key = record.VaultInternalKey(is_short);
            in.m_tap_merkle_root = spend.merkle_root;
            in.m_tap_scripts[leaf_key] = sit->second;

            const XOnlyPubKey owner_int = record.CoopOwnerInternal(is_short);
            const XOnlyPubKey cp_int = record.CoopCpInternal(is_short);
            const std::array<std::pair<XOnlyPubKey, XOnlyPubKey>, 2> signers{{
                {owner_int, record.CoopOwnerKey(is_short)},
                {cp_int, record.CoopCpKey(is_short)},
            }};

            bool signed_any = false;
            for (const auto& [signer, payout] : signers) {
                CKey key;
                if (!GetCoopSignerKey(*pwallet, payout, signer, key)) continue;

                const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
                ScriptExecutionData execdata;
                execdata.m_annex_init = true;
                execdata.m_annex_present = false;
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = 0xFFFFFFFF;
                execdata.m_tapleaf_hash_init = true;
                execdata.m_tapleaf_hash = leaf_hash;

                uint256 sighash;
                if (!SignatureHashSchnorr(sighash, execdata, *psbtx.tx, static_cast<uint32_t>(vidx),
                                          SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute the cooperative tapscript sighash");
                }
                std::array<unsigned char, 64> sig_array;
                if (!key.SignSchnorr(sighash, sig_array, /*merkle_root=*/nullptr, GetRandHash())) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create the cooperative Schnorr signature");
                }
                in.m_tap_script_sigs[{signer, leaf_hash}] = std::vector<unsigned char>(sig_array.begin(), sig_array.end());
                signed_any = true;
            }
            if (!signed_any) {
                throw JSONRPCError(RPC_WALLET_ERROR, "This wallet controls neither cooperative-close key for this leg");
            }

            UniValue result(UniValue::VOBJ);
            // Script is <owner> CHECKSIGVERIFY <cp> CHECKSIG, so the witness stack (bottom->top) is
            // [sig_cp, sig_owner], then [leaf, control].
            const auto owner_sig = in.m_tap_script_sigs.find({owner_int, leaf_hash});
            const auto cp_sig = in.m_tap_script_sigs.find({cp_int, leaf_hash});
            const bool complete = owner_sig != in.m_tap_script_sigs.end() && cp_sig != in.m_tap_script_sigs.end();
            if (complete) {
                in.final_script_witness.stack = {cp_sig->second, owner_sig->second, coop_leaf_vec, *sit->second.begin()};
                CMutableTransaction mtx{*psbtx.tx};
                if (!FinalizeAndExtractPSBT(psbtx, mtx)) {
                    for (size_t i = 0; i < mtx.vin.size(); ++i) {
                        if (!psbtx.inputs[i].final_script_witness.IsNull()) {
                            mtx.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
                        }
                    }
                }
                result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            }
            DataStream ss{};
            ss << psbtx;
            result.pushKV("complete", complete);
            result.pushKV("psbt", EncodeBase64(ss.str()));
            return result;
        }};
}

} // namespace wallet
