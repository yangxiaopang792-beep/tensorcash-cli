// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h> // WITNESS_SCALE_FACTOR
#include <core_io.h>
#include <key_io.h>
#include <node/context.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>  // EnsureChainman
#include <rpc/util.h>
#include <script/interpreter.h> // ComputeTapleafHash / ComputeTaprootMerkleRoot / TAPROOT_* constants
#include <script/script.h>
#include <script/signingprovider.h>
#include <serialize.h>        // GetSizeOfCompactSize
#include <streams.h>
#include <univalue.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>       // cs_main, ChainstateManager
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/difficulty_contract.h>
#include <wallet/fairsign.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/vaultregistry.h>
#include <wallet/wallet.h>

#include <array>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace wallet {

namespace {

//! Parse a P2TR (witness v1) bech32m address into its x-only output key. The difficulty covenant
//! pays to OP_1 <xonly> exactly, so payout destinations MUST be v1 Taproot.
XOnlyPubKey ParseP2TRXOnly(const std::string& addr, const std::string& field)
{
    const CTxDestination dest = DecodeDestination(addr);
    if (const auto* tr = std::get_if<WitnessV1Taproot>(&dest)) {
        return XOnlyPubKey(*tr);
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a P2TR (bech32m) address", field));
}

//! True iff this PSBT input is a difficulty settlement covenant spend that we can safely extract without
//! local script verification: its finalized witness must reveal a tapscript leaf that (a) contains
//! OP_DIFFCFD_SETTLE and (b) is genuinely COMMITTED by the spent v1-Taproot output (BIP341 tweak check).
//! Requirement (b) is essential — without it a forged final_script_witness carrying an OP_DIFFCFD_SETTLE
//! leaf could bypass verification and let this RPC emit an invalid transaction. Tapscript script-path
//! layout is [..inputs, leaf_script, control_block] with an optional trailing annex (first byte ANNEX_TAG).
bool IsCommittedDiffCfdCovenantInput(const PSBTInput& in, const CTxIn& txin)
{
    // The spent output is needed to prove commitment; take it from the PSBT's UTXO data.
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

    // BIP341 control-block shape: 33-byte base + N*32-byte path, N in [0, 128].
    if (control.size() < TAPROOT_CONTROL_BASE_SIZE ||
        (control.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0 ||
        control.size() > TAPROOT_CONTROL_MAX_SIZE) {
        return false;
    }

    // The revealed leaf must actually contain OP_DIFFCFD_SETTLE (scanned as opcodes, not raw bytes).
    CScript leaf_script(leaf.begin(), leaf.end());
    bool has_settle = false;
    opcodetype op;
    for (CScript::const_iterator pc = leaf_script.begin(); leaf_script.GetOp(pc, op); ) {
        if (op == OP_DIFFCFD_SETTLE) { has_settle = true; break; }
    }
    if (!has_settle) return false;

    // Prove the leaf is committed by the spent Taproot output key (tweak check, as VerifyTaprootCommitment).
    const uint256 tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, leaf);
    const uint256 merkle_root = ComputeTaprootMerkleRoot(control, tapleaf_hash);
    const XOnlyPubKey p{std::span{control}.subspan(1, TAPROOT_CONTROL_BASE_SIZE - 1)};
    const XOnlyPubKey q{program};
    return q.CheckTapTweak(p, merkle_root, control[0] & 1);
}

uint32_t ParseUint32(const UniValue& v, const std::string& field)
{
    const int64_t n = v.getInt<int64_t>();
    if (n < 0 || n > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s out of uint32 range", field));
    }
    return static_cast<uint32_t>(n);
}

DifficultyLegTerms ParseLeg(const UniValue& o, const std::string& name)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be an object");
    DifficultyLegTerms leg;
    leg.im = AmountFromValue(o.find_value("im"));
    leg.lambda_q = ParseUint32(o.find_value("lambda_q"), name + ".lambda_q");
    leg.owner_key = ParseP2TRXOnly(o.find_value("owner").get_str(), name + ".owner");
    leg.cp_key = ParseP2TRXOnly(o.find_value("cp").get_str(), name + ".cp");
    // im_asset stays null (native-only in v1).
    return leg;
}

DifficultyContractTerms ParseTerms(const UniValue& o)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms must be an object");
    DifficultyContractTerms terms;
    terms.strike_nbits = ParseUint32(o.find_value("strike_nbits"), "strike_nbits");
    terms.fixing_height = ParseUint32(o.find_value("fixing_height"), "fixing_height");
    terms.settle_lock_height = ParseUint32(o.find_value("settle_lock_height"), "settle_lock_height");
    terms.long_leg = ParseLeg(o.find_value("long"), "long");
    terms.short_leg = ParseLeg(o.find_value("short"), "short");
    return terms;
}

// ----- Bilateral lifecycle (propose / accept / import_acceptance) helpers -----

//! Parse the ECONOMICS-only terms (no payout keys): strike, fixing, settle-lock, and each leg's IM +
//! leverage. The payout keys are filled later by AssembleTerms once both parties' keys are known.
DifficultyContractTerms ParseEconomics(const UniValue& o)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms must be an object");
    DifficultyContractTerms t;
    t.strike_nbits = ParseUint32(o.find_value("strike_nbits"), "strike_nbits");
    t.fixing_height = ParseUint32(o.find_value("fixing_height"), "fixing_height");
    t.settle_lock_height = ParseUint32(o.find_value("settle_lock_height"), "settle_lock_height");
    const UniValue& l = o.find_value("long");
    const UniValue& s = o.find_value("short");
    if (!l.isObject() || !s.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.long and terms.short must be objects");
    t.long_leg.im = AmountFromValue(l.find_value("im"));
    t.long_leg.lambda_q = ParseUint32(l.find_value("lambda_q"), "long.lambda_q");
    t.short_leg.im = AmountFromValue(s.find_value("im"));
    t.short_leg.lambda_q = ParseUint32(s.find_value("lambda_q"), "short.lambda_q");
    return t; // payout keys left null
}

XOnlyPubKey ParseXOnlyHex(const UniValue& v, const std::string& field)
{
    const std::vector<unsigned char> b = ParseHex(v.get_str());
    if (b.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be a 32-byte x-only pubkey (hex)");
    return XOnlyPubKey(b);
}

//! Slot each party's two payout keys into the four leg slots according to the proposer's side. Each
//! party supplies (owner = the leg they post / their IM return, cp = their claim on the other leg).
//!   long leg : owner = LONG party,  cp = SHORT party
//!   short leg: owner = SHORT party, cp = LONG party
DifficultyContractTerms AssembleTerms(const DifficultyContractTerms& econ, bool proposer_is_short,
                                      const XOnlyPubKey& prop_owner, const XOnlyPubKey& prop_cp,
                                      const XOnlyPubKey& acc_owner, const XOnlyPubKey& acc_cp)
{
    DifficultyContractTerms t = econ; // strike/fixing/settle + per-leg im/lambda; keys still null
    if (proposer_is_short) {
        t.short_leg.owner_key = prop_owner; t.long_leg.cp_key = prop_cp;
        t.long_leg.owner_key = acc_owner;   t.short_leg.cp_key = acc_cp;
    } else {
        t.long_leg.owner_key = prop_owner;  t.short_leg.cp_key = prop_cp;
        t.short_leg.owner_key = acc_owner;  t.long_leg.cp_key = acc_cp;
    }
    return t;
}

struct ParsedOffer {
    bool proposer_is_short{false};
    uint256 salt{};
    DifficultyContractTerms econ;   //!< keys null
    XOnlyPubKey prop_owner{};
    XOnlyPubKey prop_cp{};
    XOnlyPubKey prop_owner_internal{}; //!< coop cosign internal key behind prop_owner
    XOnlyPubKey prop_cp_internal{};    //!< coop cosign internal key behind prop_cp
    XOnlyPubKey proposer_adaptor_point{}; //!< Fair-Sign adaptor point for atomic risk transfer (null if absent)
};

//! Read an offer's kind ("cfd" if the field is absent), rejecting anything else with a clean error so a
//! missing/unknown kind fails consistently rather than taking a parser-dependent path.
std::string ParseOfferKind(const UniValue& offer)
{
    if (!offer.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer must be an object");
    const UniValue& k = offer.find_value("kind");
    if (k.isNull()) return "cfd";
    const std::string s = k.get_str();
    if (s != "cfd" && s != "option") throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.kind must be \"cfd\" or \"option\"");
    return s;
}

ParsedOffer ParseOffer(const UniValue& o)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer must be an object");
    // Enforce the envelope so an unrelated/forward-version blob is rejected up front.
    const UniValue& ver = o.find_value("version");
    if (ver.isNull() || ver.getInt<int64_t>() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.version must be 1");
    if (o.find_value("contract_type").get_str() != "difficulty") throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.contract_type must be \"difficulty\"");
    if (const UniValue& k = o.find_value("kind"); !k.isNull() && k.get_str() != "cfd") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.kind must be \"cfd\" (use difficulty.accept_option for an option offer)");
    }
    ParsedOffer po;
    const std::string role = o.find_value("proposer_role").get_str();
    if (role == "short") po.proposer_is_short = true;
    else if (role == "long") po.proposer_is_short = false;
    else throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.proposer_role must be 'long' or 'short'");
    po.salt = ParseHashV(o.find_value("salt"), "offer.salt");
    po.econ = ParseEconomics(o.find_value("terms"));
    po.prop_owner = ParseXOnlyHex(o.find_value("proposer_owner_key"), "offer.proposer_owner_key");
    po.prop_cp = ParseXOnlyHex(o.find_value("proposer_cp_key"), "offer.proposer_cp_key");
    po.prop_owner_internal = ParseXOnlyHex(o.find_value("proposer_owner_internal"), "offer.proposer_owner_internal");
    po.prop_cp_internal = ParseXOnlyHex(o.find_value("proposer_cp_internal"), "offer.proposer_cp_internal");
    // Atomic-risk-transfer adaptor point (optional — absent on pre-atomic-open offers).
    if (const UniValue& ap = o.find_value("proposer_adaptor_point"); !ap.isNull()) {
        po.proposer_adaptor_point = ParseXOnlyHex(ap, "offer.proposer_adaptor_point");
    }
    return po;
}

UniValue OfferToJSON(bool proposer_is_short, const uint256& salt, const DifficultyContractTerms& econ,
                     const XOnlyPubKey& prop_owner, const XOnlyPubKey& prop_cp,
                     const XOnlyPubKey& prop_owner_internal, const XOnlyPubKey& prop_cp_internal,
                     const XOnlyPubKey& proposer_adaptor_point)
{
    UniValue terms(UniValue::VOBJ);
    terms.pushKV("strike_nbits", static_cast<uint64_t>(econ.strike_nbits));
    terms.pushKV("fixing_height", static_cast<uint64_t>(econ.fixing_height));
    terms.pushKV("settle_lock_height", static_cast<uint64_t>(econ.settle_lock_height));
    UniValue lj(UniValue::VOBJ);
    lj.pushKV("im", ValueFromAmount(econ.long_leg.im));
    lj.pushKV("lambda_q", static_cast<uint64_t>(econ.long_leg.lambda_q));
    UniValue sj(UniValue::VOBJ);
    sj.pushKV("im", ValueFromAmount(econ.short_leg.im));
    sj.pushKV("lambda_q", static_cast<uint64_t>(econ.short_leg.lambda_q));
    terms.pushKV("long", lj);
    terms.pushKV("short", sj);

    UniValue offer(UniValue::VOBJ);
    offer.pushKV("version", 1);
    offer.pushKV("contract_type", "difficulty");
    offer.pushKV("kind", "cfd");
    offer.pushKV("proposer_role", proposer_is_short ? "short" : "long");
    offer.pushKV("salt", salt.GetHex());
    offer.pushKV("terms", terms);
    offer.pushKV("proposer_owner_key", HexStr(prop_owner));
    offer.pushKV("proposer_cp_key", HexStr(prop_cp));
    offer.pushKV("proposer_owner_internal", HexStr(prop_owner_internal));
    offer.pushKV("proposer_cp_internal", HexStr(prop_cp_internal));
    offer.pushKV("proposer_adaptor_point", HexStr(proposer_adaptor_point));
    return offer;
}

// ----- OPTION handshake helpers (kind = OPTION: one margined writer leg + a buyer→writer premium) -----

//! Assemble OPTION terms: the writer's single margined leg (long or short per `writer_is_short`) carries
//! the IM + leverage + owner(=writer)/cp(=buyer) keys; the other leg stays empty; kind=OPTION; premium set.
DifficultyContractTerms AssembleOptionTerms(uint32_t strike_nbits, uint32_t fixing_height, uint32_t settle_lock_height,
                                            CAmount im, uint32_t lambda_q, CAmount premium, bool writer_is_short,
                                            const XOnlyPubKey& writer_key, const XOnlyPubKey& buyer_key)
{
    DifficultyContractTerms t;
    t.strike_nbits = strike_nbits;
    t.fixing_height = fixing_height;
    t.settle_lock_height = settle_lock_height;
    t.kind = DIFFICULTY_KIND_OPTION;
    t.premium = premium;
    DifficultyLegTerms& w = writer_is_short ? t.short_leg : t.long_leg;
    w.im = im;
    w.lambda_q = lambda_q;
    w.owner_key = writer_key; // writer: IM-return at settle + premium receipt at open
    w.cp_key = buyer_key;     // buyer: option payout if in-the-money
    return t;
}

struct ParsedOptionOffer {
    bool writer_is_short{false};
    bool proposer_is_writer{false};
    uint256 salt{};
    uint32_t strike_nbits{0}, fixing_height{0}, settle_lock_height{0}, lambda_q{0};
    CAmount im{0}, premium{0};
    XOnlyPubKey proposer_key{};
    XOnlyPubKey proposer_internal{};       //!< coop/adaptor internal key behind proposer_key
    XOnlyPubKey proposer_adaptor_point{};  //!< Fair-Sign adaptor point (null if absent)
};

ParsedOptionOffer ParseOptionOffer(const UniValue& o)
{
    if (!o.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer must be an object");
    const UniValue& ver = o.find_value("version");
    if (ver.isNull() || ver.getInt<int64_t>() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.version must be 1");
    if (o.find_value("contract_type").get_str() != "difficulty") throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.contract_type must be \"difficulty\"");
    if (o.find_value("kind").get_str() != "option") throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.kind must be \"option\"");
    ParsedOptionOffer po;
    const std::string ws = o.find_value("writer_side").get_str();
    if (ws == "short") po.writer_is_short = true;
    else if (ws == "long") po.writer_is_short = false;
    else throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.writer_side must be 'long' or 'short'");
    const std::string role = o.find_value("proposer_role").get_str();
    if (role == "writer") po.proposer_is_writer = true;
    else if (role == "buyer") po.proposer_is_writer = false;
    else throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.proposer_role must be 'writer' or 'buyer'");
    po.salt = ParseHashV(o.find_value("salt"), "offer.salt");
    const UniValue& terms = o.find_value("terms");
    if (!terms.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.terms must be an object");
    po.strike_nbits = ParseUint32(terms.find_value("strike_nbits"), "strike_nbits");
    po.fixing_height = ParseUint32(terms.find_value("fixing_height"), "fixing_height");
    po.settle_lock_height = ParseUint32(terms.find_value("settle_lock_height"), "settle_lock_height");
    po.im = AmountFromValue(terms.find_value("im"));
    po.lambda_q = ParseUint32(terms.find_value("lambda_q"), "lambda_q");
    po.premium = AmountFromValue(terms.find_value("premium"));
    po.proposer_key = ParseXOnlyHex(o.find_value("proposer_key"), "offer.proposer_key");
    if (const UniValue& pi = o.find_value("proposer_internal"); !pi.isNull()) {
        po.proposer_internal = ParseXOnlyHex(pi, "offer.proposer_internal");
    }
    if (const UniValue& ap = o.find_value("proposer_adaptor_point"); !ap.isNull()) {
        po.proposer_adaptor_point = ParseXOnlyHex(ap, "offer.proposer_adaptor_point");
    }
    return po;
}

//! Reconstruct option terms from a parsed offer plus the acceptor's payout key (the proposer's key fills
//! whichever role the proposer took; the acceptor's the other).
DifficultyContractTerms AssembleOptionTermsFromOffer(const ParsedOptionOffer& po, const XOnlyPubKey& acceptor_key)
{
    const XOnlyPubKey writer_key = po.proposer_is_writer ? po.proposer_key : acceptor_key;
    const XOnlyPubKey buyer_key = po.proposer_is_writer ? acceptor_key : po.proposer_key;
    return AssembleOptionTerms(po.strike_nbits, po.fixing_height, po.settle_lock_height, po.im, po.lambda_q,
                               po.premium, po.writer_is_short, writer_key, buyer_key);
}

//! Count outputs that are an EXACT native (no asset TLV) deposit of `amount` to `spk`. Vault binding is
//! by {scriptPubKey, amount, native} — a script match at the wrong value or asset-tagged is NOT a vault.
int CountNativeVaultOutputs(const std::vector<CTxOut>& vout, const CScript& spk, CAmount amount)
{
    int n = 0;
    for (const CTxOut& o : vout) {
        if (o.scriptPubKey == spk && o.nValue == amount && !o.HasAssetTLV()) ++n;
    }
    return n;
}

//! Witness weight of a Taproot script-path input revealing `script` + `control_block` with
//! `signature_elements` 64-byte Schnorr sigs (0 for a keyless covenant). Mirrors the repo/forward
//! covenant-spend fee estimation so FundTransaction sizes the fee correctly for a non-wallet input.
int64_t EstimateTaprootScriptPathInputWeight(size_t script_size, size_t control_block_size, size_t signature_elements)
{
    constexpr int64_t BASE_NONWITNESS_WEIGHT = (32 + 4 + 1 + 4) * WITNESS_SCALE_FACTOR;
    int64_t weight = BASE_NONWITNESS_WEIGHT;
    const size_t stack_elems = signature_elements + 2; // sigs + script + control
    weight += GetSizeOfCompactSize(stack_elems);
    constexpr size_t TAPROOT_SIG_SIZE = 65; // 64-byte schnorr + sighash byte
    for (size_t i = 0; i < signature_elements; ++i) {
        weight += GetSizeOfCompactSize(TAPROOT_SIG_SIZE) + TAPROOT_SIG_SIZE;
    }
    weight += GetSizeOfCompactSize(script_size) + script_size;
    weight += GetSizeOfCompactSize(control_block_size) + control_block_size;
    return weight;
}

//! Build a VaultMetadata for one leg's difficulty vault. Both registry leaves carry a null signing_key:
//! the settlement leaf is signatureless covenant, and the cooperative leaf is a 2-of-2 signed externally
//! by difficulty.sign_coop (each party with the tweaked key for its own payout address), NOT through the
//! registry signing provider — so the registry only needs to track the vault UTXO.
std::optional<VaultMetadata> BuildLegVaultMetadata(const DifficultyContractRecord& record, bool is_short,
                                                   const TaprootBuilder& builder)
{
    // Two leaves (order matches CreateDifficultyVaultBuilder): the signatureless settlement covenant, and
    // the 2-of-2 cooperative-close leaf.
    const CScript settle_leaf = BuildDifficultyLeafScript(record, is_short);
    const CScript coop_leaf = BuildDifficultyCoopLeafScript(record, is_short);
    const std::vector<VaultLeafDescriptor> leaves{
        VaultBuilder::CreateLeaf(settle_leaf, /*signing_key=*/XOnlyPubKey(), "difficulty-settle",
                                 record.terms.settle_lock_height),
        VaultBuilder::CreateLeaf(coop_leaf, /*signing_key=*/XOnlyPubKey(), "cooperative", std::nullopt)};
    return VaultBuilder::Build(builder, record.contract_id,
                               is_short ? VaultRole::DIFFICULTY_SHORT : VaultRole::DIFFICULTY_LONG, leaves);
}

//! Build ONE leg's vault from the record, validate, and register it in `wallet` (in >=1 descriptor SPKM)
//! so the wallet tracks the vault UTXO. Returns the Taproot output. Idempotent: an already-registered
//! vault (same contract + role) is success; a fresh registration must fully succeed including the
//! WriteVaultMetadata persist (a post-failure GetVaultMetadata is NOT treated as success). Throws on failure.
WitnessV1Taproot RegisterVaultLeg(CWallet& wallet, const DifficultyContractRecord& record, bool is_short)
{
    TaprootBuilder b = CreateDifficultyVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
    if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build difficulty vault");
    const WitnessV1Taproot out{b.GetOutput()};
    const CScript spk = GetScriptForDestination(out);

    LOCK(wallet.cs_wallet);
    const auto meta = BuildLegVaultMetadata(record, is_short, b);
    if (!meta || !meta->Validate()) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build/validate difficulty vault metadata");

    bool reg = false;
    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        auto* desc = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc) continue;
        bool r;
        if (const auto existing = desc->GetVaultMetadata(spk)) {
            r = existing->contract_id == meta->contract_id && existing->role == meta->role; // same vault already registered
        } else {
            r = desc->RegisterCovenantVault(spk, *meta); // fresh registration must fully succeed (incl. persist)
        }
        if (r) {
            reg = true;
            std::set<CScript> registered{spk};
            wallet.CacheNewScriptPubKeys(registered, spkm);
        }
    }
    if (!reg) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to register difficulty vault in the wallet");
    return out;
}

//! Build + register BOTH leg vaults (CFD open) so the wallet tracks both UTXOs regardless of which leg
//! it funds.
void BuildRegisterBothVaults(CWallet& wallet, const DifficultyContractRecord& record,
                             WitnessV1Taproot& long_out, WitnessV1Taproot& short_out)
{
    long_out = RegisterVaultLeg(wallet, record, /*is_short=*/false);
    short_out = RegisterVaultLeg(wallet, record, /*is_short=*/true);
}

} // namespace

//! Derive the INTERNAL (untweaked) x-only key behind a P2TR output key this wallet controls — i.e. the
//! descriptor key for the payout address P2TR(output_key). (Mirrors the forward's LookupTaprootInternalKey.)
static std::optional<XOnlyPubKey> DeriveTaprootInternalKey(const CWallet& wallet, const XOnlyPubKey& output_key)
{
    const WitnessV1Taproot tr{output_key};
    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(CTxDestination{tr}));
    if (!provider) return std::nullopt;
    TaprootSpendData spenddata;
    if (!provider->GetTaprootSpendData(tr, spenddata) || spenddata.internal_key.IsNull()) return std::nullopt;
    return spenddata.internal_key;
}

//! Extract the internal key behind a payout key THIS wallet must control (for the cooperative cosign).
static XOnlyPubKey ExtractCoopInternalKey(const CWallet& wallet, const XOnlyPubKey& output_key, const std::string& field)
{
    const auto internal = DeriveTaprootInternalKey(wallet, output_key);
    if (!internal) {
        throw JSONRPCError(RPC_WALLET_ERROR, field + ": this wallet does not control that payout address (needed to derive its cooperative-close key)");
    }
    return *internal;
}

//! Slot the four cooperative internal keys into the record by the proposer's side (mirrors AssembleTerms).
static void SlotCoopInternals(DifficultyContractRecord& record, bool proposer_is_short,
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

//! Minimal annotation of the coop vault input so the close PSBT carries what difficulty.sign_coop needs:
//! the spent UTXO, the (NUMS) internal key + merkle root, and the coop leaf + its control block.
static void AnnotateCoopLeaf(PSBTInput& in, const CTxOut& vault_txout,
                             const XOnlyPubKey& internal_key, const uint256& merkle_root,
                             const std::pair<std::vector<unsigned char>, int>& leaf_key,
                             const std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>& control_blocks)
{
    in.witness_utxo = vault_txout;
    in.m_tap_internal_key = internal_key;
    in.m_tap_merkle_root = merkle_root;
    in.m_tap_scripts[leaf_key] = control_blocks;
}

//! Resolve the INTERNAL private key THIS wallet holds behind a coop signer. `payout_key` is the wallet's
//! own payout output address that anchors the descriptor; `internal_key` is the untweaked key that appears
//! in the coop leaf. A wallet-global GetKeyByXOnly cannot reverse a raw keyid to a descriptor index, so we
//! expand the payout address's own provider (which has already derived the index) and look the key up there.
static bool GetCoopSignerKey(CWallet& wallet, const XOnlyPubKey& payout_key,
                             const XOnlyPubKey& internal_key, CKey& out_key)
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

//! Embed the Fair-Sign `contract_meta` global-proprietary entry so adaptor.prepare can locate this
//! contract for the atomic-risk-transfer ceremony. Mirrors AddProprietaryEntry()'s key construction
//! (in contracts.cpp) exactly so ExtractFsContractMeta() reads it back. Called only when the record is
//! ceremony-ready (both adaptor points + a non-null fs_context present).
static void EmbedFsContractMeta(PartiallySignedTransaction& psbt, const uint256& meta)
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

RPCHelpMan difficulty_build_open()
{
    return RPCHelpMan{
        "difficulty.build_open",
        "Fund THIS party's IM vault for an already-agreed difficulty contract (created via "
        "difficulty.propose/accept/import_acceptance) and return a co-signing PSBT. Two-party ATOMIC open: "
        "the first party calls this for its leg to get a partial PSBT; the counterparty calls it for the "
        "other leg passing options.psbt to augment it, so a single transaction funds BOTH vaults and "
        "neither party fronts the other's margin. Each party then signs its own inputs (walletprocesspsbt); "
        "once finalized + broadcast, BOTH parties call difficulty.record_open. Both vaults are registered "
        "in this wallet. IM is native-only in v1.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The difficulty contract id (must already exist in this wallet)"},
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
        RPCExamples{HelpExampleCli("difficulty.build_open", "\"<contract_id>\" \"long\"")},
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

            const auto rec_opt = pwallet->FindDifficultyContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown difficulty contract (propose/accept it first)");
            const DifficultyContractRecord record = *rec_opt;
            if (record.terms.IsOption()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "This is an option contract — use difficulty.build_open_option");
            }

            // Build + register BOTH vaults (this wallet tracks both, regardless of which leg it funds).
            WitnessV1Taproot long_out, short_out;
            BuildRegisterBothVaults(*pwallet, record, long_out, short_out);
            const WitnessV1Taproot my_out = is_short ? short_out : long_out;
            const CScript my_spk = GetScriptForDestination(my_out);
            const CScript other_spk = GetScriptForDestination(is_short ? long_out : short_out);
            const CAmount my_im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
            const CAmount other_im = (is_short ? record.terms.long_leg : record.terms.short_leg).im;

            // Fund THIS party's vault from this wallet (empty-vout tx + the vault as the sole recipient).
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
            auto myfund = FundTransaction(*pwallet, mytx, recipients, /*change_pos=*/std::nullopt,
                                          /*lockUnspents=*/false, coin_control);
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
                // FIRST party: the PSBT is just our own funded leg.
                result = std::move(my_psbt);
            } else {
                // SECOND party: merge our funded leg into the counterparty's partial PSBT (one atomic tx).
                PartiallySignedTransaction in_psbt;
                std::string derr;
                if (!DecodeBase64PSBT(in_psbt, psbt_opt.get_str(), derr)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", derr));
                }
                // The counterparty PSBT must fund EXACTLY ONE of the other leg's IM vault and NONE of this
                // leg's — reject duplicate/ambiguous vault outputs before merging (so the final tx cannot
                // end up funding more than one matching vault).
                if (CountNativeVaultOutputs(in_psbt.tx->vout, other_spk, other_im) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Counterparty PSBT must fund exactly one of the other leg's IM vault");
                }
                if (CountNativeVaultOutputs(in_psbt.tx->vout, my_spk, my_im) != 0) {
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
                // Splice each side's PSBT metadata into its slots: counterparty's first, ours appended.
                for (size_t i = 0; i < in_in && i < in_psbt.inputs.size(); ++i) result.inputs[i] = in_psbt.inputs[i];
                for (size_t i = 0; i < in_out && i < in_psbt.outputs.size(); ++i) result.outputs[i] = in_psbt.outputs[i];
                for (size_t j = 0; j < my_psbt.inputs.size(); ++j) result.inputs[in_in + j] = my_psbt.inputs[j];
                for (size_t j = 0; j < my_psbt.outputs.size(); ++j) result.outputs[in_out + j] = my_psbt.outputs[j];

                // Combined fee = sum(input UTXO values) - sum(output values), when every input has its UTXO.
                CAmount tin = 0, tout = 0;
                bool have_all = true;
                for (const PSBTInput& pin : result.inputs) {
                    if (!pin.witness_utxo.IsNull()) tin += pin.witness_utxo.nValue;
                    else have_all = false;
                }
                for (const CTxOut& o : result.tx->vout) tout += o.nValue;
                if (have_all) fee = tin - tout;

                // The merged tx must fund EXACTLY ONE long and ONE short vault — no more, no less.
                const CScript long_spk = GetScriptForDestination(long_out);
                const CScript short_spk = GetScriptForDestination(short_out);
                if (CountNativeVaultOutputs(result.tx->vout, long_spk, record.terms.long_leg.im) != 1 ||
                    CountNativeVaultOutputs(result.tx->vout, short_spk, record.terms.short_leg.im) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Merged open must fund exactly one long and one short IM vault");
                }
            }

            // This leg's vault must appear exactly once in the result.
            if (CountNativeVaultOutputs(result.tx->vout, my_spk, my_im) != 1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx must contain exactly one of this leg's IM vault");
            }
            int my_idx = -1;
            for (size_t i = 0; i < result.tx->vout.size(); ++i) {
                if (result.tx->vout[i].scriptPubKey == my_spk && result.tx->vout[i].nValue == my_im && !result.tx->vout[i].HasAssetTLV()) {
                    my_idx = static_cast<int>(i);
                    break;
                }
            }
            if (my_idx < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx is missing this leg's vault output");

            // Embed fs/contract_meta for the atomic-risk-transfer ceremony, but only once the contract
            // is ceremony-ready (both adaptor points + context set by accept/import). A CFD open whose
            // record predates the adaptor wiring simply carries no meta (and can't run the ceremony).
            if (record.fs_tx_adaptor_point.IsFullyValid() && record.counterparty_adaptor_point
                && record.counterparty_adaptor_point->IsFullyValid() && !record.fs_context.IsNull()) {
                EmbedFsContractMeta(result, ComputeDifficultyContractMeta(record));
            }

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

RPCHelpMan difficulty_propose()
{
    return RPCHelpMan{
        "difficulty.propose",
        "Propose a bilateral difficulty-derivative contract. The proposer defines the full economics "
        "(strike, fixing height, settle-lock, both IMs, both leverages), picks their side, and supplies "
        "their two P2TR payout addresses (owner = the leg they will post / their IM return; cp = their "
        "claim on the counterparty's leg). Returns an offer to hand to the counterparty out-of-band. "
        "Nothing is persisted — the record is created by difficulty.accept (acceptor) and "
        "difficulty.import_acceptance (proposer).",
        {
            {"terms", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Contract economics (no payout keys)",
                {
                    {"strike_nbits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Committed compact difficulty target (canonical)"},
                    {"fixing_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Buried ancestor height H whose nBits is the underlying"},
                    {"settle_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leaf CLTV; must be >= fixing_height + maturity"},
                    {"long", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Long leg economics",
                        {
                            {"im", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Initial margin"},
                            {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leverage in Q16 (lambda * 65536)"},
                        }},
                    {"short", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Short leg economics",
                        {
                            {"im", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Initial margin"},
                            {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leverage in Q16"},
                        }},
                }},
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's side: \"long\" or \"short\""},
            {"owner", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's P2TR payout address for the leg they post (IM return)"},
            {"cp", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's P2TR payout address for their claim on the counterparty's leg"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ANY, "offer", "The offer to hand to the counterparty (consumed by difficulty.accept)"},
            }},
        RPCExamples{HelpExampleCli("difficulty.propose",
            "'{\"strike_nbits\":545259519,\"fixing_height\":150,\"settle_lock_height\":250,"
            "\"long\":{\"im\":\"10\",\"lambda_q\":655360},\"short\":{\"im\":\"10\",\"lambda_q\":655360}}' "
            "\"long\" \"bcrt1p...\" \"bcrt1p...\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            const DifficultyContractTerms econ = ParseEconomics(request.params[0]);
            const std::string role = request.params[1].get_str();
            bool proposer_is_short;
            if (role == "short") proposer_is_short = true;
            else if (role == "long") proposer_is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "role must be \"long\" or \"short\"");
            const XOnlyPubKey owner = ParseP2TRXOnly(request.params[2].get_str(), "owner");
            const XOnlyPubKey cp = ParseP2TRXOnly(request.params[3].get_str(), "cp");
            // Extract the internal keys behind the proposer's payout addresses for the cooperative cosign.
            const XOnlyPubKey owner_int = ExtractCoopInternalKey(*pwallet, owner, "owner");
            const XOnlyPubKey cp_int = ExtractCoopInternalKey(*pwallet, cp, "cp");

            const uint256 salt = GetRandHash();

            // Atomic-risk-transfer adaptor: derive the proposer's Fair-Sign point from the internal key
            // behind its owner payout, bound to the offer commitment. Stateless — the same point is
            // re-derived (and verified) at difficulty.import_acceptance and at ceremony time, so nothing
            // is persisted here. The secret is discarded; only the point is published in the offer.
            CKey owner_internal_priv;
            if (!GetCoopSignerKey(*pwallet, owner, owner_int, owner_internal_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the private key behind the owner payout address");
            }
            const uint256 fs_context = ComputeDifficultyOfferCommitment(proposer_is_short, econ, owner, cp, salt);
            const XOnlyPubKey prop_adaptor_point =
                DeriveDifficultyFsAdaptor(owner_internal_priv, salt, fs_context, DIFFICULTY_FS_ROLE_PROPOSER).second;

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer", OfferToJSON(proposer_is_short, salt, econ, owner, cp, owner_int, cp_int, prop_adaptor_point));
            return result;
        }};
}

RPCHelpMan difficulty_accept()
{
    return RPCHelpMan{
        "difficulty.accept",
        "Accept a difficulty-derivative offer. Supply your two P2TR payout addresses (owner = the leg you "
        "post; cp = your claim on the proposer's leg). Without options.confirmed this returns the assembled "
        "contract_id for review; with options.confirmed=true it validates the full terms, persists the "
        "contract record in this wallet, and returns an acceptance to hand back to the proposer.",
        {
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The offer object from difficulty.propose", std::vector<RPCArg>{}},
            {"owner", RPCArg::Type::STR, RPCArg::Optional::NO, "Acceptor's P2TR payout address for the leg they post (IM return)"},
            {"cp", RPCArg::Type::STR, RPCArg::Optional::NO, "Acceptor's P2TR payout address for their claim on the proposer's leg"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Acceptance options",
                {
                    {"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Set true (after reviewing terms) to persist + commit"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "contract_id", "The assembled contract id"},
                {RPCResult::Type::ANY, "acceptance", /*optional=*/true, "Acceptance for the proposer (only when confirmed)"},
                {RPCResult::Type::STR, "action_required", /*optional=*/true, "Present when not yet confirmed"},
            }},
        RPCExamples{HelpExampleCli("difficulty.accept", "'{...offer...}' \"bcrt1p...\" \"bcrt1p...\" '{\"confirmed\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const ParsedOffer po = ParseOffer(request.params[0]);
            const XOnlyPubKey acc_owner = ParseP2TRXOnly(request.params[1].get_str(), "owner");
            const XOnlyPubKey acc_cp = ParseP2TRXOnly(request.params[2].get_str(), "cp");
            const XOnlyPubKey acc_owner_int = ExtractCoopInternalKey(*pwallet, acc_owner, "owner");
            const XOnlyPubKey acc_cp_int = ExtractCoopInternalKey(*pwallet, acc_cp, "cp");
            const DifficultyContractTerms terms =
                AssembleTerms(po.econ, po.proposer_is_short, po.prop_owner, po.prop_cp, acc_owner, acc_cp);

            const uint256 pow_limit = Params().GetConsensus().powLimit;
            std::string verr;
            if (!terms.Validate(verr, &pow_limit)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid terms: " + verr);
            }
            const uint256 contract_id = ComputeDifficultyContractId(terms, po.salt);

            const UniValue options = request.params[3].isNull() ? UniValue(UniValue::VOBJ) : request.params[3].get_obj();
            const UniValue& confirmed = options.find_value("confirmed");
            UniValue result(UniValue::VOBJ);
            result.pushKV("contract_id", contract_id.GetHex());
            if (confirmed.isNull() || !confirmed.get_bool()) {
                result.pushKV("action_required", "review terms, then call again with options={\"confirmed\":true} to accept");
                return result;
            }

            // Atomic-risk-transfer adaptor: derive the acceptor's Fair-Sign point from the internal key
            // behind its own owner payout, bound to the SAME offer commitment the proposer used, and
            // stage both points + context onto the record so the open ceremony can re-derive locally.
            if (!po.proposer_adaptor_point.IsFullyValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer is missing a valid proposer_adaptor_point");
            }
            CKey acc_owner_priv;
            if (!GetCoopSignerKey(*pwallet, acc_owner, acc_owner_int, acc_owner_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the private key behind the owner payout address");
            }
            const uint256 fs_context = ComputeDifficultyOfferCommitment(po.proposer_is_short, terms, po.prop_owner, po.prop_cp, po.salt);
            const XOnlyPubKey acc_adaptor_point =
                DeriveDifficultyFsAdaptor(acc_owner_priv, po.salt, fs_context, DIFFICULTY_FS_ROLE_ACCEPTOR).second;

            DifficultyContractRecord record;
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
                pwallet->RegisterDifficultyContract(record);
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

RPCHelpMan difficulty_import_acceptance()
{
    return RPCHelpMan{
        "difficulty.import_acceptance",
        "Proposer: import the acceptance for an offer you proposed. Reconstructs the full terms from your "
        "original offer plus the acceptor's payout keys, recomputes + VERIFIES the contract_id, and "
        "persists the identical contract record in this wallet. After this both wallets hold the same "
        "record and either party can fund (difficulty.build_open) and settle it.",
        {
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Your original offer object from difficulty.propose", std::vector<RPCArg>{}},
            {"acceptance", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The acceptance object from the counterparty's difficulty.accept", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "contract_id", "The agreed contract id"},
                {RPCResult::Type::STR, "state", "\"accepted\""},
            }},
        RPCExamples{HelpExampleCli("difficulty.import_acceptance", "'{...offer...}' '{...acceptance...}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const UniValue& offer = request.params[0];
            const UniValue& acc = request.params[1];
            if (!offer.isObject() || !acc.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "offer and acceptance must be objects");
            const bool is_option = ParseOfferKind(offer) == "option";

            // Reconstruct the full terms (CFD: four keys; OPTION: writer leg + premium) and the salt.
            DifficultyContractTerms terms;
            uint256 salt;
            bool have_coop = false, coop_proposer_is_short = false;
            XOnlyPubKey coop_prop_owner, coop_prop_cp, coop_acc_owner, coop_acc_cp;
            // Atomic-risk-transfer adaptor staging: computed inside the branch where the parsed offer is in
            // scope, applied to the record below. (CFD + option.)
            bool have_adaptor = false;
            XOnlyPubKey adaptor_prop_point, adaptor_acc_point;
            uint256 adaptor_fs_context;
            // Option-only: the writer-leg coop internals (owner = writer, cp = buyer) the ceremony resolves.
            bool have_opt_internals = false, opt_writer_is_short = false;
            XOnlyPubKey opt_writer_int, opt_buyer_int;
            if (is_option) {
                const ParsedOptionOffer po = ParseOptionOffer(offer);
                salt = po.salt;
                const XOnlyPubKey acc_key = ParseXOnlyHex(acc.find_value("acceptor_key"), "acceptance.acceptor_key");
                terms = AssembleOptionTermsFromOffer(po, acc_key);

                // Re-derive the proposer's option adaptor and verify it matches the offer's point; stage
                // both points + the writer-leg coop internals (owner = writer, cp = buyer).
                if (po.proposer_adaptor_point.IsFullyValid() && po.proposer_internal.IsFullyValid()) {
                    const XOnlyPubKey acc_int = ParseXOnlyHex(acc.find_value("acceptor_internal"), "acceptance.acceptor_internal");
                    CKey prop_priv;
                    if (!GetCoopSignerKey(*pwallet, po.proposer_key, po.proposer_internal, prop_priv)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the proposer's payout internal key for adaptor derivation");
                    }
                    adaptor_fs_context = ComputeDifficultyOptionOfferCommitment(
                        po.writer_is_short, po.proposer_is_writer, po.strike_nbits, po.fixing_height,
                        po.settle_lock_height, po.im, po.lambda_q, po.premium, po.proposer_key, po.salt);
                    adaptor_prop_point = DeriveDifficultyFsAdaptor(prop_priv, salt, adaptor_fs_context, DIFFICULTY_FS_ROLE_PROPOSER).second;
                    if (adaptor_prop_point != po.proposer_adaptor_point) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Re-derived proposer adaptor point does not match the offer");
                    }
                    adaptor_acc_point = ParseXOnlyHex(acc.find_value("acceptor_adaptor_point"), "acceptance.acceptor_adaptor_point");
                    if (!adaptor_acc_point.IsFullyValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.acceptor_adaptor_point is not a valid x-only point");
                    }
                    have_adaptor = true;
                    opt_writer_is_short = po.writer_is_short;
                    opt_writer_int = po.proposer_is_writer ? po.proposer_internal : acc_int;
                    opt_buyer_int  = po.proposer_is_writer ? acc_int : po.proposer_internal;
                    have_opt_internals = true;
                }
            } else {
                const ParsedOffer po = ParseOffer(offer);
                salt = po.salt;
                const XOnlyPubKey acc_owner = ParseXOnlyHex(acc.find_value("acceptor_owner_key"), "acceptance.acceptor_owner_key");
                const XOnlyPubKey acc_cp = ParseXOnlyHex(acc.find_value("acceptor_cp_key"), "acceptance.acceptor_cp_key");
                terms = AssembleTerms(po.econ, po.proposer_is_short, po.prop_owner, po.prop_cp, acc_owner, acc_cp);
                have_coop = true;
                coop_proposer_is_short = po.proposer_is_short;
                coop_prop_owner = po.prop_owner_internal;
                coop_prop_cp = po.prop_cp_internal;
                coop_acc_owner = ParseXOnlyHex(acc.find_value("acceptor_owner_internal"), "acceptance.acceptor_owner_internal");
                coop_acc_cp = ParseXOnlyHex(acc.find_value("acceptor_cp_internal"), "acceptance.acceptor_cp_internal");

                // Re-derive the proposer's adaptor (same inputs as at propose) and VERIFY it reproduces
                // the point published in the offer — a strong consistency check before we sign with it.
                if (po.proposer_adaptor_point.IsFullyValid()) {
                    CKey prop_owner_priv;
                    if (!GetCoopSignerKey(*pwallet, po.prop_owner, po.prop_owner_internal, prop_owner_priv)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the proposer's owner internal key for adaptor derivation");
                    }
                    adaptor_fs_context = ComputeDifficultyOfferCommitment(po.proposer_is_short, terms, po.prop_owner, po.prop_cp, salt);
                    adaptor_prop_point = DeriveDifficultyFsAdaptor(prop_owner_priv, salt, adaptor_fs_context, DIFFICULTY_FS_ROLE_PROPOSER).second;
                    if (adaptor_prop_point != po.proposer_adaptor_point) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Re-derived proposer adaptor point does not match the offer");
                    }
                    adaptor_acc_point = ParseXOnlyHex(acc.find_value("acceptor_adaptor_point"), "acceptance.acceptor_adaptor_point");
                    if (!adaptor_acc_point.IsFullyValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.acceptor_adaptor_point is not a valid x-only point");
                    }
                    have_adaptor = true;
                }
            }
            // The acceptance echoes the salt; it MUST match the offer's (defends against pairing an
            // acceptance with the wrong offer).
            if (ParseHashV(acc.find_value("salt"), "acceptance.salt") != salt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance salt does not match the offer");
            }

            const uint256 pow_limit = Params().GetConsensus().powLimit;
            std::string verr;
            if (!terms.Validate(verr, &pow_limit)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid terms: " + verr);
            }
            const uint256 contract_id = ComputeDifficultyContractId(terms, salt);
            const uint256 claimed = ParseHashV(acc.find_value("contract_id"), "acceptance.contract_id");
            if (contract_id != claimed) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance contract_id does not match the reconstructed terms");
            }

            DifficultyContractRecord record;
            record.terms = terms;
            record.salt = salt;
            record.contract_id = contract_id;
            record.long_internal_key = XOnlyPubKey::NUMS_H;
            record.short_internal_key = XOnlyPubKey::NUMS_H;
            if (have_coop) {
                SlotCoopInternals(record, coop_proposer_is_short, coop_prop_owner, coop_prop_cp, coop_acc_owner, coop_acc_cp);
            }
            if (have_adaptor) {
                record.fs_tx_adaptor_point = adaptor_prop_point;
                record.counterparty_adaptor_point = adaptor_acc_point;
                record.fs_context = adaptor_fs_context;
            }
            if (have_opt_internals) {
                if (opt_writer_is_short) { record.short_owner_internal = opt_writer_int; record.short_cp_internal = opt_buyer_int; }
                else { record.long_owner_internal = opt_writer_int; record.long_cp_internal = opt_buyer_int; }
            }
            try {
                pwallet->RegisterDifficultyContract(record);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, e.what());
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("contract_id", contract_id.GetHex());
            result.pushKV("state", "accepted");
            return result;
        }};
}

RPCHelpMan difficulty_record_open()
{
    return RPCHelpMan{
        "difficulty.record_open",
        "Record the funded vault outpoints for an opened difficulty contract. Call this in BOTH wallets "
        "after the co-signed open transaction is broadcast: it locates both IM vault outputs in that "
        "transaction (by their committed scriptPubKeys) and persists their outpoints + the open txid into "
        "the contract record, so either party can subsequently settle either leg.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The difficulty contract id"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The broadcast open transaction id (must be a wallet transaction)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "long_vault", /*optional=*/true, "outpoint of the long IM vault (txid:n); absent for a short-writer option"},
                {RPCResult::Type::STR, "short_vault", /*optional=*/true, "outpoint of the short IM vault (txid:n); absent for a long-writer option"},
            }},
        RPCExamples{HelpExampleCli("difficulty.record_open", "\"<contract_id>\" \"<open_txid>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const uint256 txid_u = ParseHashV(request.params[1], "txid");
            const Txid txid = Txid::FromUint256(txid_u);

            const auto rec_opt = pwallet->FindDifficultyContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown difficulty contract");
            DifficultyContractRecord record = *rec_opt;

            CTransactionRef tx;
            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* wtx = pwallet->GetWalletTx(txid);
                if (wtx) tx = wtx->tx;
            }
            if (!tx) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid is not a transaction in this wallet");

            // Resolve the funded vault output(s) by {scriptPubKey, native value == IM}, requiring EXACTLY
            // ONE of each expected vault (reject duplicate/ambiguous/wrong-value/asset-tagged matches).
            const auto find_unique_vault = [&](bool is_short) -> int {
                TaprootBuilder b = CreateDifficultyVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
                if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build difficulty vault");
                const CScript spk = GetScriptForDestination(WitnessV1Taproot{b.GetOutput()});
                const CAmount im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
                if (CountNativeVaultOutputs(tx->vout, spk, im) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction does not contain exactly one of the contract vault(s)");
                }
                for (size_t i = 0; i < tx->vout.size(); ++i) {
                    const CTxOut& o = tx->vout[i];
                    if (!o.HasAssetTLV() && o.scriptPubKey == spk && o.nValue == im) return static_cast<int>(i);
                }
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction does not contain the contract vault");
            };

            record.open_txid = txid_u;
            UniValue out(UniValue::VOBJ);
            if (record.terms.IsOption()) {
                // Only the writer's leg is margined. Still require the buyer's premium output to be present
                // (exactly one native premium to the writer's payout key) so a vault-only tx — an open
                // missing the premium — is NOT recorded as a valid option open.
                const bool ws = record.terms.OptionWriterIsShort();
                const CScript premium_spk = GetScriptForDestination(WitnessV1Taproot{record.terms.OptionWriterLeg().owner_key});
                if (CountNativeVaultOutputs(tx->vout, premium_spk, record.terms.premium) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Option open tx must contain exactly one premium output to the writer");
                }
                const COutPoint vault(txid, static_cast<uint32_t>(find_unique_vault(ws)));
                (ws ? record.short_vault : record.long_vault) = vault;
                out.pushKV(ws ? "short_vault" : "long_vault", vault.ToString());
            } else {
                record.long_vault = COutPoint(txid, static_cast<uint32_t>(find_unique_vault(/*is_short=*/false)));
                record.short_vault = COutPoint(txid, static_cast<uint32_t>(find_unique_vault(/*is_short=*/true)));
                out.pushKV("long_vault", record.long_vault.ToString());
                out.pushKV("short_vault", record.short_vault.ToString());
            }
            try {
                pwallet->RegisterDifficultyContract(record);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, e.what());
            }
            return out;
        }};
}

RPCHelpMan difficulty_propose_option()
{
    return RPCHelpMan{
        "difficulty.propose_option",
        "Propose a difficulty OPTION: one party (the WRITER) posts a single IM vault; the other (the BUYER) "
        "pays an upfront premium and receives the in-the-money payout (capped at the writer's IM). The "
        "proposer sets the economics (strike, fixing height, settle-lock, the writer's IM + leverage, the "
        "premium) and the side the WRITER holds, declares whether they are the writer or buyer, and gives "
        "their one P2TR payout address. Returns an offer for the counterparty; nothing is persisted yet.",
        {
            {"terms", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Option economics",
                {
                    {"strike_nbits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Committed compact difficulty target (canonical)"},
                    {"fixing_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Buried ancestor height H whose nBits is the underlying"},
                    {"settle_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leaf CLTV; must be >= fixing_height + maturity"},
                    {"im", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Writer's initial margin (the max payout to the buyer)"},
                    {"lambda_q", RPCArg::Type::NUM, RPCArg::Optional::NO, "Leverage in Q16 (lambda * 65536)"},
                    {"premium", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Upfront premium the buyer pays the writer"},
                }},
            {"writer_side", RPCArg::Type::STR, RPCArg::Optional::NO, "Side the WRITER holds: \"long\" (writer loses as difficulty falls) or \"short\""},
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's role: \"writer\" or \"buyer\""},
            {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's P2TR payout address (writer: IM-return + premium receipt; buyer: option payout)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ANY, "offer", "The option offer to hand to the counterparty (consumed by difficulty.accept_option)"},
            }},
        RPCExamples{HelpExampleCli("difficulty.propose_option",
            "'{\"strike_nbits\":545259519,\"fixing_height\":150,\"settle_lock_height\":250,\"im\":\"10\",\"lambda_q\":655360,\"premium\":\"1\"}' "
            "\"long\" \"writer\" \"bcrt1p...\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            const UniValue& t = request.params[0];
            if (!t.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "terms must be an object");
            const uint32_t strike = ParseUint32(t.find_value("strike_nbits"), "strike_nbits");
            const uint32_t fixing = ParseUint32(t.find_value("fixing_height"), "fixing_height");
            const uint32_t settle = ParseUint32(t.find_value("settle_lock_height"), "settle_lock_height");
            const CAmount im = AmountFromValue(t.find_value("im"));
            const uint32_t lambda = ParseUint32(t.find_value("lambda_q"), "lambda_q");
            const CAmount premium = AmountFromValue(t.find_value("premium"));

            const std::string ws = request.params[1].get_str();
            bool writer_is_short;
            if (ws == "short") writer_is_short = true;
            else if (ws == "long") writer_is_short = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "writer_side must be \"long\" or \"short\"");
            const std::string role = request.params[2].get_str();
            bool proposer_is_writer;
            if (role == "writer") proposer_is_writer = true;
            else if (role == "buyer") proposer_is_writer = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "role must be \"writer\" or \"buyer\"");
            const XOnlyPubKey key = ParseP2TRXOnly(request.params[3].get_str(), "key");
            const XOnlyPubKey key_int = ExtractCoopInternalKey(*pwallet, key, "key");

            const uint256 salt = GetRandHash();

            // Atomic-risk-transfer adaptor: derive the proposer's Fair-Sign point from the internal key
            // behind its payout, bound to the option offer commitment (re-derived + verified later).
            CKey key_priv;
            if (!GetCoopSignerKey(*pwallet, key, key_int, key_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the private key behind the payout address");
            }
            const uint256 fs_context = ComputeDifficultyOptionOfferCommitment(
                writer_is_short, proposer_is_writer, strike, fixing, settle, im, lambda, premium, key, salt);
            const XOnlyPubKey prop_adaptor_point =
                DeriveDifficultyFsAdaptor(key_priv, salt, fs_context, DIFFICULTY_FS_ROLE_PROPOSER).second;

            UniValue terms(UniValue::VOBJ);
            terms.pushKV("strike_nbits", static_cast<uint64_t>(strike));
            terms.pushKV("fixing_height", static_cast<uint64_t>(fixing));
            terms.pushKV("settle_lock_height", static_cast<uint64_t>(settle));
            terms.pushKV("im", ValueFromAmount(im));
            terms.pushKV("lambda_q", static_cast<uint64_t>(lambda));
            terms.pushKV("premium", ValueFromAmount(premium));
            UniValue offer(UniValue::VOBJ);
            offer.pushKV("version", 1);
            offer.pushKV("contract_type", "difficulty");
            offer.pushKV("kind", "option");
            offer.pushKV("writer_side", writer_is_short ? "short" : "long");
            offer.pushKV("proposer_role", proposer_is_writer ? "writer" : "buyer");
            offer.pushKV("salt", salt.GetHex());
            offer.pushKV("terms", terms);
            offer.pushKV("proposer_key", HexStr(key));
            offer.pushKV("proposer_internal", HexStr(key_int));
            offer.pushKV("proposer_adaptor_point", HexStr(prop_adaptor_point));
            UniValue result(UniValue::VOBJ);
            result.pushKV("offer", offer);
            return result;
        }};
}

RPCHelpMan difficulty_accept_option()
{
    return RPCHelpMan{
        "difficulty.accept_option",
        "Accept a difficulty OPTION offer. Supply your one P2TR payout address. Without options.confirmed "
        "this returns the assembled contract_id for review; with options.confirmed=true it validates the "
        "terms, persists the contract record in this wallet, and returns an acceptance for the proposer.",
        {
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The option offer from difficulty.propose_option", std::vector<RPCArg>{}},
            {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "Acceptor's P2TR payout address"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Acceptance options",
                {
                    {"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Set true (after reviewing terms) to persist + commit"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "contract_id", "The assembled contract id"},
                {RPCResult::Type::ANY, "acceptance", /*optional=*/true, "Acceptance for the proposer (only when confirmed)"},
                {RPCResult::Type::STR, "action_required", /*optional=*/true, "Present when not yet confirmed"},
            }},
        RPCExamples{HelpExampleCli("difficulty.accept_option", "'{...offer...}' \"bcrt1p...\" '{\"confirmed\":true}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const ParsedOptionOffer po = ParseOptionOffer(request.params[0]);
            const XOnlyPubKey my_key = ParseP2TRXOnly(request.params[1].get_str(), "key");
            const DifficultyContractTerms terms = AssembleOptionTermsFromOffer(po, my_key);

            const uint256 pow_limit = Params().GetConsensus().powLimit;
            std::string verr;
            if (!terms.Validate(verr, &pow_limit)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid terms: " + verr);
            }
            const uint256 contract_id = ComputeDifficultyContractId(terms, po.salt);

            const UniValue options = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
            const UniValue& confirmed = options.find_value("confirmed");
            UniValue result(UniValue::VOBJ);
            result.pushKV("contract_id", contract_id.GetHex());
            if (confirmed.isNull() || !confirmed.get_bool()) {
                result.pushKV("action_required", "review terms, then call again with options={\"confirmed\":true} to accept");
                return result;
            }

            // Atomic-risk-transfer adaptor: derive the acceptor's Fair-Sign point bound to the SAME option
            // offer commitment, and stage both points + the writer-leg coop internals on the record. The
            // writer leg's owner = the WRITER's payout, cp = the BUYER's payout; each is resolvable by its
            // owning wallet at ceremony time (the buyer owns the cp side, not an owner side).
            if (!po.proposer_adaptor_point.IsFullyValid() || !po.proposer_internal.IsFullyValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Option offer is missing proposer_adaptor_point / proposer_internal");
            }
            const XOnlyPubKey my_int = ExtractCoopInternalKey(*pwallet, my_key, "key");
            CKey my_priv;
            if (!GetCoopSignerKey(*pwallet, my_key, my_int, my_priv)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot resolve the private key behind the payout address");
            }
            const uint256 fs_context = ComputeDifficultyOptionOfferCommitment(
                po.writer_is_short, po.proposer_is_writer, po.strike_nbits, po.fixing_height,
                po.settle_lock_height, po.im, po.lambda_q, po.premium, po.proposer_key, po.salt);
            const XOnlyPubKey acc_adaptor_point =
                DeriveDifficultyFsAdaptor(my_priv, po.salt, fs_context, DIFFICULTY_FS_ROLE_ACCEPTOR).second;
            // writer/buyer internals (independent of who proposed).
            const XOnlyPubKey writer_int = po.proposer_is_writer ? po.proposer_internal : my_int;
            const XOnlyPubKey buyer_int  = po.proposer_is_writer ? my_int : po.proposer_internal;

            DifficultyContractRecord record;
            record.terms = terms;
            record.salt = po.salt;
            record.contract_id = contract_id;
            record.long_internal_key = XOnlyPubKey::NUMS_H;
            record.short_internal_key = XOnlyPubKey::NUMS_H;
            if (po.writer_is_short) {
                record.short_owner_internal = writer_int;
                record.short_cp_internal = buyer_int;
            } else {
                record.long_owner_internal = writer_int;
                record.long_cp_internal = buyer_int;
            }
            record.fs_tx_adaptor_point = po.proposer_adaptor_point;
            record.counterparty_adaptor_point = acc_adaptor_point;
            record.fs_context = fs_context;
            try {
                pwallet->RegisterDifficultyContract(record);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, e.what());
            }

            UniValue acceptance(UniValue::VOBJ);
            acceptance.pushKV("contract_id", contract_id.GetHex());
            acceptance.pushKV("salt", po.salt.GetHex());
            acceptance.pushKV("acceptor_key", HexStr(my_key));
            acceptance.pushKV("acceptor_internal", HexStr(my_int));
            acceptance.pushKV("acceptor_adaptor_point", HexStr(acc_adaptor_point));
            result.pushKV("acceptance", acceptance);
            return result;
        }};
}

RPCHelpMan difficulty_build_open_option()
{
    return RPCHelpMan{
        "difficulty.build_open_option",
        "Fund THIS party's side of an already-agreed difficulty OPTION and return a co-signing PSBT. Two-"
        "party ATOMIC open: the WRITER funds the single IM vault; the BUYER funds the upfront premium (to "
        "the writer's payout address). One party calls this to get a partial PSBT; the counterparty calls "
        "it with options.psbt to augment, so one transaction funds the vault + premium atomically. Each "
        "party signs its own inputs; after broadcast both call difficulty.record_open. The writer vault is "
        "registered in this wallet.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The option contract id (must exist in this wallet)"},
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO, "This wallet's role: \"writer\" (funds the IM vault) or \"buyer\" (funds the premium)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding options",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Counterparty's partial open PSBT to augment"},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in " + CURRENCY_ATOM + "/vB for this party's inputs"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded open PSBT (this party's side funded; combined when augmenting)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " (this party's contribution, or combined when augmenting)"},
                {RPCResult::Type::STR, "role", "The role this wallet funded"},
            }},
        RPCExamples{HelpExampleCli("difficulty.build_open_option", "\"<contract_id>\" \"writer\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
            const std::string role = request.params[1].get_str();
            bool is_writer;
            if (role == "writer") is_writer = true;
            else if (role == "buyer") is_writer = false;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "role must be \"writer\" or \"buyer\"");

            const auto rec_opt = pwallet->FindDifficultyContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown difficulty contract (propose/accept it first)");
            const DifficultyContractRecord record = *rec_opt;
            if (!record.terms.IsOption()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Not an option contract (use difficulty.build_open for a CFD)");

            const bool writer_is_short = record.terms.OptionWriterIsShort();
            const DifficultyLegTerms& wleg = record.terms.OptionWriterLeg();
            // Both parties register + track the single writer vault.
            const WitnessV1Taproot vault_out = RegisterVaultLeg(*pwallet, record, writer_is_short);
            const CScript vault_spk = GetScriptForDestination(vault_out);
            const CAmount vault_im = wleg.im;
            const WitnessV1Taproot premium_out{wleg.owner_key}; // premium → the writer's payout key
            const CScript premium_spk = GetScriptForDestination(premium_out);
            const CAmount premium_amt = record.terms.premium;

            const WitnessV1Taproot my_out = is_writer ? vault_out : premium_out;
            const CScript my_spk = is_writer ? vault_spk : premium_spk;
            const CAmount my_amt = is_writer ? vault_im : premium_amt;
            const CScript other_spk = is_writer ? premium_spk : vault_spk;
            const CAmount other_amt = is_writer ? premium_amt : vault_im;

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
            std::vector<CRecipient> recipients{CRecipient{my_out, my_amt, /*fSubtractFeeFromAmount=*/false}};
            CMutableTransaction mytx;
            mytx.version = 2;
            auto myfund = FundTransaction(*pwallet, mytx, recipients, /*change_pos=*/std::nullopt,
                                          /*lockUnspents=*/false, coin_control);
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
                result = std::move(my_psbt);
            } else {
                PartiallySignedTransaction in_psbt;
                std::string derr;
                if (!DecodeBase64PSBT(in_psbt, psbt_opt.get_str(), derr)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", derr));
                }
                if (CountNativeVaultOutputs(in_psbt.tx->vout, other_spk, other_amt) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Counterparty PSBT must fund exactly one of the other side's output");
                }
                if (CountNativeVaultOutputs(in_psbt.tx->vout, my_spk, my_amt) != 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Counterparty PSBT must not already contain this side's output");
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

                CAmount tin = 0, tout = 0;
                bool have_all = true;
                for (const PSBTInput& pin : result.inputs) {
                    if (!pin.witness_utxo.IsNull()) tin += pin.witness_utxo.nValue;
                    else have_all = false;
                }
                for (const CTxOut& o : result.tx->vout) tout += o.nValue;
                if (have_all) fee = tin - tout;

                // The merged open must fund EXACTLY one writer vault and one premium output.
                if (CountNativeVaultOutputs(result.tx->vout, vault_spk, vault_im) != 1 ||
                    CountNativeVaultOutputs(result.tx->vout, premium_spk, premium_amt) != 1) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Merged option open must fund exactly one IM vault and one premium output");
                }
            }

            if (CountNativeVaultOutputs(result.tx->vout, my_spk, my_amt) != 1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx must contain exactly one of this side's output");
            }

            // Embed fs/contract_meta for the atomic-risk-transfer ceremony when the record is ceremony-ready.
            if (record.fs_tx_adaptor_point.IsFullyValid() && record.counterparty_adaptor_point
                && record.counterparty_adaptor_point->IsFullyValid() && !record.fs_context.IsNull()) {
                EmbedFsContractMeta(result, ComputeDifficultyContractMeta(record));
            }

            DataStream ss{};
            ss << result;
            UniValue out(UniValue::VOBJ);
            out.pushKV("psbt", EncodeBase64(ss.str()));
            out.pushKV("fee", ValueFromAmount(fee));
            out.pushKV("role", role);
            return out;
        }};
}

RPCHelpMan difficulty_build_coop_close()
{
    return RPCHelpMan{
        "difficulty.build_coop_close",
        "Build a cooperative-close PSBT that spends one vault via its 2-of-2 cosign leaf to a mutually-agreed "
        "set of outputs — an early/negotiated settlement that bypasses the deterministic covenant (no "
        "maturity/burial wait). The vault funds the fee, so the agreed outputs must sum to <= the vault value "
        "(the remainder is the fee). Both parties must sign: each calls difficulty.sign_coop on the returned "
        "PSBT in turn (NOT walletprocesspsbt — the standard signer will not sign a covenant input it does not "
        "own); the second sign_coop returns the broadcastable hex. The unilateral covenant leaf remains the "
        "trustless fallback.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The difficulty contract id"},
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
        RPCExamples{HelpExampleCli("difficulty.build_coop_close",
            "\"<contract_id>\" \"long\" '[{\"address\":\"bcrt1p...\",\"amount\":\"5\"},{\"address\":\"bcrt1p...\",\"amount\":\"4.999\"}]'")},
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

            const auto rec_opt = pwallet->FindDifficultyContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown difficulty contract");
            const DifficultyContractRecord record = *rec_opt;
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

            // Reconstruct the vault + coop leaf control block, and verify the UTXO is EXACTLY this vault —
            // same covenant output key, native (no asset TLV), AND the recorded IM value (mirrors
            // build_settlement) so a stale/corrupt record cannot build a coop PSBT against a wrong UTXO.
            TaprootBuilder b = CreateDifficultyVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
            if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Vault internal key is not set/valid");
            const CAmount leg_im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
            if (vault_txout.scriptPubKey != GetScriptForDestination(WitnessV1Taproot{b.GetOutput()})
                || vault_txout.HasAssetTLV() || vault_txout.nValue != leg_im) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Recorded vault UTXO does not match the contract (stale/corrupt record?)");
            }
            const CScript coop_leaf = BuildDifficultyCoopLeafScript(record, is_short);
            const std::vector<unsigned char> coop_leaf_vec(coop_leaf.begin(), coop_leaf.end());
            const TaprootSpendData spend = b.GetSpendData();
            const auto sit = spend.scripts.find({coop_leaf_vec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
            if (sit == spend.scripts.end() || sit->second.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not reconstruct the cooperative leaf control block");
            }
            if (record.CoopOwnerInternal(is_short).IsNull() || record.CoopCpInternal(is_short).IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no cooperative-close keys (record predates coop support)");
            }

            // Build the agreed close tx (vault input → agreed outputs; the vault funds the fee).
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
                tx.vout.push_back(CTxOut(amt, GetScriptForDestination(dest)));
                out_sum += amt;
            }
            if (out_sum > vault_txout.nValue) throw JSONRPCError(RPC_INVALID_PARAMETER, "Agreed outputs exceed the vault value");
            const CAmount fee = vault_txout.nValue - out_sum;

            // Annotate the vault input for a 2-of-2 SCRIPT-PATH spend of the coop leaf, then each party adds
            // its half via difficulty.sign_coop (NOT walletprocesspsbt — the standard wallet signer will not
            // sign a covenant input it does not own; the counterparty's wallet skips it entirely).
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

RPCHelpMan difficulty_sign_coop()
{
    return RPCHelpMan{
        "difficulty.sign_coop",
        "Add THIS wallet's half of the 2-of-2 cooperative-close signature to a PSBT from "
        "difficulty.build_coop_close, and — once BOTH parties have signed — assemble the final witness and "
        "return the broadcastable transaction. Each party signs the coop leaf "
        "(<owner_internal> CHECKSIGVERIFY <cp_internal> CHECKSIG) with a raw Schnorr tapscript signature over "
        "its own internal key (mirrors the forward's direct vault-leaf signing primitive). This does NOT use "
        "walletprocesspsbt: the standard wallet signer refuses covenant inputs it does not own, so the "
        "counterparty's wallet would silently skip the input. Flow: party A builds + sign_coop, sends the PSBT "
        "to party B, who sign_coops to get {complete:true, hex}, then sendrawtransaction.",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The difficulty contract id"},
            {"leg", RPCArg::Type::STR, RPCArg::Optional::NO, "Which leg's vault is being closed: \"long\" or \"short\""},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64 cooperative-close PSBT (from build_coop_close, or a partner-signed PSBT)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "complete", "True when both parties have signed (then `hex` is present)"},
                {RPCResult::Type::STR, "psbt", "The PSBT with this wallet's partial signature added"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The extracted transaction, present only when complete"},
            }},
        RPCExamples{HelpExampleCli("difficulty.sign_coop", "\"<contract_id>\" \"long\" \"<psbt>\"")},
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

            const auto rec_opt = pwallet->FindDifficultyContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown difficulty contract");
            const DifficultyContractRecord record = *rec_opt;
            const COutPoint vault_op = record.VaultOutpoint(is_short);
            if (vault_op.IsNull()) throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no funded vault for this leg");
            if (record.CoopOwnerInternal(is_short).IsNull() || record.CoopCpInternal(is_short).IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no cooperative-close keys (record predates coop support)");
            }

            PartiallySignedTransaction psbtx;
            std::string err;
            if (!DecodeBase64PSBT(psbtx, request.params[2].get_str(), err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("PSBT decode failed: %s", err));
            }
            if (!psbtx.tx) throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");

            // Locate the coop vault input.
            int vidx = -1;
            for (size_t i = 0; i < psbtx.tx->vin.size(); ++i) {
                if (psbtx.tx->vin[i].prevout == vault_op) { vidx = static_cast<int>(i); break; }
            }
            if (vidx < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT does not spend this leg's vault outpoint");
            PSBTInput& in = psbtx.inputs[vidx];
            if (in.witness_utxo.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Coop PSBT input is missing its witness_utxo");

            // Reconstruct the coop leaf, its control block and tapleaf hash, and verify the spent UTXO is
            // exactly this vault — covenant output key, native, AND recorded IM value — so we never sign
            // against a substituted output/leaf or a wrong-valued UTXO.
            TaprootBuilder b = CreateDifficultyVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
            if (!b.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Vault internal key is not set/valid");
            const CAmount leg_im = (is_short ? record.terms.short_leg : record.terms.long_leg).im;
            if (in.witness_utxo.scriptPubKey != GetScriptForDestination(WitnessV1Taproot{b.GetOutput()})
                || in.witness_utxo.HasAssetTLV() || in.witness_utxo.nValue != leg_im) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT vault input does not match the contract");
            }
            const CScript coop_leaf = BuildDifficultyCoopLeafScript(record, is_short);
            const std::vector<unsigned char> coop_leaf_vec(coop_leaf.begin(), coop_leaf.end());
            const std::pair<std::vector<unsigned char>, int> leaf_key{coop_leaf_vec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)};
            const TaprootSpendData spend = b.GetSpendData();
            const auto sit = spend.scripts.find(leaf_key);
            if (sit == spend.scripts.end() || sit->second.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not reconstruct the cooperative leaf control block");
            }
            const uint256 leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, coop_leaf_vec);

            // Make sure the annotations are present (idempotent for a partner-built PSBT).
            in.m_tap_internal_key = record.VaultInternalKey(is_short);
            in.m_tap_merkle_root = spend.merkle_root;
            in.m_tap_scripts[leaf_key] = sit->second;

            // The coop leaf is <owner_internal> CHECKSIGVERIFY <cp_internal> CHECKSIG. Each party signs the
            // internal key behind its own payout address; we look that key up via the payout address's own
            // expanded provider.
            const XOnlyPubKey owner_int = record.CoopOwnerInternal(is_short);
            const XOnlyPubKey cp_int = record.CoopCpInternal(is_short);
            const std::array<std::pair<XOnlyPubKey, XOnlyPubKey>, 2> signers{{
                {owner_int, record.CoopOwnerKey(is_short)},   // (internal key in leaf, payout address)
                {cp_int, record.CoopCpKey(is_short)},
            }};

            // Sign whichever of the two cosign keys THIS wallet controls (one side per party). Idempotent:
            // re-signing simply overwrites this party's own partial sig.
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
            // If both halves are present, assemble the witness and extract. Script is
            // <owner> CHECKSIGVERIFY <cp> CHECKSIG, so the witness stack (bottom→top) is [sig_cp, sig_owner].
            const auto owner_sig = in.m_tap_script_sigs.find({owner_int, leaf_hash});
            const auto cp_sig = in.m_tap_script_sigs.find({cp_int, leaf_hash});
            bool complete = owner_sig != in.m_tap_script_sigs.end() && cp_sig != in.m_tap_script_sigs.end();
            if (complete) {
                in.final_script_witness.stack = {cp_sig->second, owner_sig->second, coop_leaf_vec, *sit->second.begin()};
                CMutableTransaction mtx{*psbtx.tx};
                if (!FinalizeAndExtractPSBT(psbtx, mtx)) {
                    // Fall back to assembling the final tx directly from the finalized witnesses.
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

RPCHelpMan difficulty_build_settlement()
{
    return RPCHelpMan{
        "difficulty.build_settlement",
        "Build the keeper settlement PSBT for one leg of a difficulty contract: spend that leg's IM vault "
        "through its unilateral covenant leaf (signatureless) and pay the exact computed payout outputs, "
        "with the broadcaster's external native input covering the fee (the covenant outputs are never "
        "shaved). nBits is read from the active chain at the committed fixing height, which must be buried "
        "by DIFFCFD_MATURITY_DEPTH. Funding mirrors the repo-repay / forward-delivery covenant-spend paradigm.\n"
        "The returned PSBT has the vault input ALREADY FINALIZED ([leaf, control]). Keeper flow: sign the fee "
        "input with walletprocesspsbt, then extract with difficulty.finalize_settlement, then "
        "sendrawtransaction. NOTE: do NOT use finalizepsbt — it re-verifies the OP_DIFFCFD_SETTLE leaf, which "
        "is unverifiable without a chain fixing context, so it reports the vault input non-final and refuses "
        "to extract. difficulty.finalize_settlement skips that re-verification (the node validates the spend "
        "with the real context on submission).",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The difficulty contract id"},
            {"leg", RPCArg::Type::STR, RPCArg::Optional::NO, "Which leg to settle: \"long\" or \"short\""},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding overrides",
                {
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in " + CURRENCY_ATOM + "/vB"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded settlement PSBT (vault input finalized; fee input to be signed)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "The keeper fee in " + CURRENCY_UNIT},
                {RPCResult::Type::STR_AMOUNT, "payout_owner", "Amount returned to this leg's owner"},
                {RPCResult::Type::STR_AMOUNT, "payout_cp", "Amount paid to the counterparty"},
                {RPCResult::Type::NUM, "vault_input_index", "vin index of the spent vault"},
            }},
        RPCExamples{HelpExampleCli("difficulty.build_settlement", "\"<contract_id>\" \"short\"")},
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

            const auto rec_opt = pwallet->FindDifficultyContract(contract_id);
            if (!rec_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown difficulty contract");
            const DifficultyContractRecord record = *rec_opt;
            const COutPoint vault_op = record.VaultOutpoint(is_short);
            if (vault_op.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Contract has no funded vault for this leg (not opened?)");
            }

            const WalletContext& wctx = EnsureWalletContext(request.context);
            if (!wctx.node_context) throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
            ChainstateManager& chainman = EnsureChainman(*wctx.node_context);

            // Resolve nBits @ fixing_height + enforce burial + verify the vault UTXO is unspent — all
            // chain reads under cs_main, released BEFORE FundTransaction (which takes cs_wallet).
            uint32_t realized_nbits = 0;
            CTxOut vault_txout;
            {
                LOCK(cs_main);
                const CChain& chain = chainman.ActiveChain();
                const int tip_height = chain.Height();
                const int H = static_cast<int>(record.terms.fixing_height);
                if (tip_height < 0) throw JSONRPCError(RPC_WALLET_ERROR, "No active chain tip");
                if (H > tip_height - DIFFCFD_MATURITY_DEPTH) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Fixing height %d is not yet buried by %d (tip %d)", H, DIFFCFD_MATURITY_DEPTH, tip_height));
                }
                const CBlockIndex* pindexH = chain[H];
                if (!pindexH) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("No active-chain block at fixing height %d", H));
                realized_nbits = pindexH->nBits;

                const auto coin = chainman.ActiveChainstate().CoinsTip().GetCoin(vault_op);
                if (!coin || coin->IsSpent()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint is missing or already spent");
                }
                vault_txout = coin->out;
            }

            // Defend against a stale/corrupt record: the spent UTXO MUST be exactly the vault this record
            // describes — same value, native (no asset TLV), and the reconstructed covenant output key —
            // else the PSBT would fund + serialize but be consensus-invalid.
            const DifficultyLegTerms& leg = is_short ? record.terms.short_leg : record.terms.long_leg;
            {
                TaprootBuilder vb = CreateDifficultyVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
                if (!vb.IsComplete()) throw JSONRPCError(RPC_WALLET_ERROR, "Vault internal key is not set/valid");
                const CScript expected_spk = GetScriptForDestination(WitnessV1Taproot{vb.GetOutput()});
                if (vault_txout.scriptPubKey != expected_spk || vault_txout.HasAssetTLV() || vault_txout.nValue != leg.im) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Recorded vault UTXO does not match the contract (stale/corrupt record?)");
                }
            }

            // Build the settlement skeleton (vault input witness = [leaf, control]; exact payout outputs).
            const uint256 pow_limit = Params().GetConsensus().powLimit;
            DifficultySettlementSkeleton skel;
            std::string serr;
            if (!BuildDifficultySettlementSkeleton(record, is_short, realized_nbits, pow_limit, skel, serr)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Settlement build failed: " + serr);
            }
            const std::vector<unsigned char>& leaf_bytes = skel.vault_input.scriptWitness.stack.at(0);
            const std::vector<unsigned char>& control = skel.vault_input.scriptWitness.stack.at(1);

            // Funding paradigm (repo-repay / forward-delivery): pre-select the covenant vault as a fixed
            // input with its UTXO + an explicit script-path WEIGHT (the wallet cannot size a keyless
            // covenant input), pass the payouts as recipients, and let FundTransaction add the external
            // native fee input + change.
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
            if (skel.payout.payout_owner > 0) {
                recipients.push_back({WitnessV1Taproot{leg.owner_key}, static_cast<CAmount>(skel.payout.payout_owner), false});
            }
            if (skel.payout.payout_cp > 0) {
                recipients.push_back({WitnessV1Taproot{leg.cp_key}, static_cast<CAmount>(skel.payout.payout_cp), false});
            }

            auto fund_res = FundTransaction(*pwallet, tx, recipients, /*change_pos=*/std::nullopt,
                                            /*lockUnspents=*/false, coin_control);
            if (!fund_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original);
            }
            CMutableTransaction funded{*fund_res->tx};
            const CAmount fee = fund_res->fee;

            int vault_in_idx = -1;
            for (size_t i = 0; i < funded.vin.size(); ++i) {
                if (funded.vin[i].prevout == vault_op) { vault_in_idx = static_cast<int>(i); break; }
            }
            if (vault_in_idx < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Funded tx lost the vault input");

            // A PSBT's unsigned tx MUST carry empty scriptSigs/witnesses; the covenant witness we pre-set
            // for funding lives in the PSBT input's final_script_witness below, not on the unsigned tx.
            for (auto& vin : funded.vin) {
                vin.scriptSig.clear();
                vin.scriptWitness.SetNull();
            }

            // PSBT: first fill the wallet metadata for the fee input (UTXOs + bip32 derivs, no signing),
            // THEN finalize the KEYLESS covenant input. The order matters: FillPSBT runs SignPSBTInput on
            // every input and, lacking a difficulty fixing context, cannot mark the covenant input complete,
            // so it would drop a pre-set final witness. Setting it last keeps [leaf, control] intact.
            PartiallySignedTransaction psbtx{funded};
            bool complete = false;
            if (const auto fill_err = pwallet->FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                throw JSONRPCPSBTError(*fill_err);
            }
            {
                PSBTInput& vin_psbt = psbtx.inputs[vault_in_idx];
                vin_psbt.witness_utxo = vault_txout;            // for the fee input's taproot sighash
                vin_psbt.final_script_witness.stack = {leaf_bytes, control};  // signatureless covenant spend
            }

            DataStream ss{};
            ss << psbtx;
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ss.str()));
            result.pushKV("fee", ValueFromAmount(fee));
            result.pushKV("payout_owner", ValueFromAmount(static_cast<CAmount>(skel.payout.payout_owner)));
            result.pushKV("payout_cp", ValueFromAmount(static_cast<CAmount>(skel.payout.payout_cp)));
            result.pushKV("vault_input_index", vault_in_idx);
            return result;
        }};
}

RPCHelpMan difficulty_finalize_settlement()
{
    return RPCHelpMan{
        "difficulty.finalize_settlement",
        "Extract the final raw transaction from a fully-prepared difficulty settlement PSBT (the keyless "
        "covenant vault input finalized by difficulty.build_settlement, plus the fee input signed via "
        "walletprocesspsbt). Unlike finalizepsbt, this does NOT re-verify the difficulty covenant input "
        "scripts — OP_DIFFCFD_SETTLE cannot be verified without a chain fixing context the PSBT layer lacks, "
        "and the node fully validates the spend on submission. Verification is skipped ONLY for inputs whose "
        "finalized leaf contains OP_DIFFCFD_SETTLE AND is committed by the spent Taproot output; ALL other "
        "inputs are verified normally, and at least one committed covenant input is required.",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO,
             "A settlement PSBT in which every input is finalized (vault witness from build_settlement; "
             "fee input signed + finalized via walletprocesspsbt)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The extracted network-serialized transaction, ready for sendrawtransaction"},
            }},
        RPCExamples{HelpExampleCli("difficulty.finalize_settlement", "\"<psbt>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            PartiallySignedTransaction psbtx;
            std::string err;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", err));
            }

            // Assemble final witnesses for any inputs the keeper has signed (e.g. the fee input). The
            // covenant input is already final; FinalizePSBT preserves it. The overall "complete" flag is
            // ignored — it is always false because the covenant input cannot be script-verified here.
            FinalizePSBT(psbtx);

            // This is NOT a generic verification-skipping extractor. We bypass verification ONLY for the
            // difficulty covenant input(s) — those whose finalized leaf reveals OP_DIFFCFD_SETTLE (the node
            // validates them with the real fixing context on submission). EVERY other input must be
            // finalized AND verify normally, and at least one covenant input must be present, so this RPC
            // cannot be misused to extract an arbitrary unverified transaction.
            const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
            CMutableTransaction mtx{*psbtx.tx};
            bool found_covenant = false;
            for (size_t i = 0; i < mtx.vin.size(); ++i) {
                const PSBTInput& in = psbtx.inputs[i];
                // Skip local verification ONLY for a genuine difficulty covenant input — one whose finalized
                // leaf both contains OP_DIFFCFD_SETTLE AND is committed by the spent Taproot output. Every
                // other input (and any forged/uncommitted "covenant" witness) must verify normally.
                if (IsCommittedDiffCfdCovenantInput(in, mtx.vin[i])) {
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
                    "PSBT has no committed OP_DIFFCFD_SETTLE input — this RPC only extracts difficulty settlements");
            }

            DataStream ssTx;
            ssTx << TX_WITH_WITNESS(CTransaction(mtx));
            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", HexStr(ssTx));
            return result;
        }};
}

} // namespace wallet
