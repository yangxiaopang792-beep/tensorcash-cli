// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/fairsign.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/contract.h>
#include <wallet/difficulty_contract.h>
#include <wallet/types.h>
#include <wallet/vaultregistry.h>
#include <wallet/vault_signing.h>
#include <assets/asset.h> // ParseAssetTag for asset collateral/principal checks

#include <util/check.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <boost/container/small_vector.hpp>

#include <map>
#include <cstring>
#include <algorithm>
#include <optional>
#include <array>

#include <sync.h>
#include <set>
#include <vector>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>



#ifndef TC_FS_DEBUG
#define TC_FS_DEBUG 0
#endif

#ifndef TC_FS_DEBUG_SECRETS
#define TC_FS_DEBUG_SECRETS 0
#endif

using wallet::CWallet;
using wallet::ScriptPubKeyMan;
using wallet::DescriptorScriptPubKeyMan;

#include <core_io.h>
#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <psbt.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <span>
#include <span.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>


// MuSig2 support for parties using aggregated keys internally (cooperative multi-sig)
// This allows organizations with 2-of-2 or n-of-n MuSig2 setups to participate in adaptor ceremonies
// Note: MuSig2 is for INTRA-party aggregation (cooperative), adaptors are for INTER-party atomicity (adversarial)
// MuSig2 adaptor RPCs are always compiled (using secp256k1-zkp native adaptor support)

#if TC_FS_DEBUG
  #define FSDBG(fmt, ...) LogPrintf("[FS] " fmt "\n", ##__VA_ARGS__)
#else
  #define FSDBG(fmt, ...) do {} while(0)
#endif

static inline std::string Hex32(const unsigned char* p) {
    std::vector<unsigned char> v(p, p + 32);
    return HexStr(v);
}

static inline std::string HexXOnly(const XOnlyPubKey& x) {
    return HexStr(MakeByteSpan(x));
}

static inline std::string HexU256(const uint256& u) {
    return HexStr(MakeByteSpan(u));
}

static bool WalletTryGetKeyByXOnly(CWallet& wallet,
                                   const XOnlyPubKey& xonly,
                                   CKey& out_key)
{
    LOCK(wallet.cs_wallet);
    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc_spkm) continue;
        if (desc_spkm->GetKeyByXOnly(xonly, out_key) && out_key.IsValid()) {
            return true;
        }
    }
    return false;
}
namespace {

const secp256k1_context* GetSigningContext()
{
    static secp256k1_context* ctx = [] {
        secp256k1_context* new_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        std::array<unsigned char, 32> seed{};
        GetStrongRandBytes(std::span<unsigned char>(seed));
        const int ret = secp256k1_context_randomize(new_ctx, seed.data());
        Assert(ret == 1);
        memory_cleanse(seed.data(), seed.size());
        return new_ctx;
    }();
    return ctx;
}

using SmallVectorU8 = boost::container::small_vector<unsigned char, 64>;

constexpr std::string_view FS_COMMITMENT_TAG{"fs/adaptor"};

struct ProprietaryKeyInfo
{
    std::vector<unsigned char> identifier;
    uint64_t subtype{0};
    std::string suffix;
};

std::optional<ProprietaryKeyInfo> DecodeProprietaryKey(const PSBTProprietary& entry)
{
    SpanReader skey{std::span<const unsigned char>(entry.key)};
    ProprietaryKeyInfo info;
    try {
        // Skip type byte
        uint64_t type = ReadCompactSize(skey);
        if (type != PSBT_GLOBAL_PROPRIETARY) {
            return std::nullopt;
        }
        skey >> info.identifier;
        info.subtype = ReadCompactSize(skey);
        // Suffix is raw bytes, not length-prefixed
        std::vector<unsigned char> suffix_bytes(skey.size());
        for (size_t i = 0; i < suffix_bytes.size(); ++i) {
            skey >> suffix_bytes[i];
        }
        info.suffix.assign(reinterpret_cast<const char*>(suffix_bytes.data()), suffix_bytes.size());
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return info;
}

std::vector<XOnlyPubKey> ExtractTaprootScriptSigners(const std::vector<unsigned char>& script_bytes)
{
    std::vector<XOnlyPubKey> signers;
    if (script_bytes.empty()) return signers;

    CScript script(script_bytes.begin(), script_bytes.end());
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> pushdata;
    std::vector<unsigned char> pending_push;
    bool have_pending_push = false;

    while (script.GetOp(pc, opcode, pushdata)) {
        if (opcode <= OP_PUSHDATA4) {
            pending_push = pushdata;
            have_pending_push = true;
            continue;
        }
        if ((opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY) &&
            have_pending_push && pending_push.size() == XOnlyPubKey::size()) {
            signers.emplace_back(std::span<const unsigned char>(pending_push.data(), pending_push.size()));
        }
        have_pending_push = false;
    }

    return signers;
}

struct CandidateTapLeaf {
    std::vector<unsigned char> script;
    std::vector<unsigned char> control;
    uint256 hash;
    int leaf_version{0};
    std::vector<XOnlyPubKey> signers;
};

bool MatchesFsKey(const PSBTProprietary& entry,
                  const std::vector<unsigned char>& identifier,
                  uint64_t subtype,
                  std::string_view suffix)
{
    if (entry.identifier != identifier || entry.subtype != subtype) return false;
    const auto decoded = DecodeProprietaryKey(entry);
    if (!decoded) return false;
    if (decoded->suffix != suffix) return false;
    return true;
}

std::optional<std::vector<unsigned char>> GetFsEntry(const std::set<PSBTProprietary>& container,
                                                     const std::vector<unsigned char>& identifier,
                                                     uint64_t subtype,
                                                     std::string_view suffix)
{
    for (const auto& entry : container) {
        if (MatchesFsKey(entry, identifier, subtype, suffix)) {
            return entry.value;
        }
    }
    return std::nullopt;
}

void AddProprietaryEntry(std::set<PSBTProprietary>& container,
                         const std::vector<unsigned char>& identifier,
                         uint64_t subtype,
                         std::string_view suffix,
                         std::span<const unsigned char> value)
{
    DataStream ss_key{};
    WriteCompactSize(ss_key, PSBT_GLOBAL_PROPRIETARY);
    ss_key << identifier;
    WriteCompactSize(ss_key, subtype);
    // Suffix is NOT length-prefixed, write raw bytes
    for (auto byte : suffix) {
        ss_key << static_cast<uint8_t>(byte);
    }

    PSBTProprietary entry;
    entry.identifier = identifier;
    entry.subtype = subtype;
    entry.key = std::vector<unsigned char>(UCharCast(ss_key.data()), UCharCast(ss_key.data() + ss_key.size()));
    entry.value = std::vector<unsigned char>(value.begin(), value.end());
    container.insert(entry);
}

void ReplaceFsEntry(std::set<PSBTProprietary>& container,
                    const std::vector<unsigned char>& identifier,
                    uint64_t subtype,
                    std::string_view suffix,
                    std::span<const unsigned char> value)
{
    for (auto it = container.begin(); it != container.end();) {
        if (MatchesFsKey(*it, identifier, subtype, suffix)) {
            it = container.erase(it);
        } else {
            ++it;
        }
    }
    AddProprietaryEntry(container, identifier, subtype, suffix, value);
}

void RemoveFsEntry(std::set<PSBTProprietary>& container,
                   const std::vector<unsigned char>& identifier,
                   uint64_t subtype,
                   std::string_view suffix)
{
    for (auto it = container.begin(); it != container.end();) {
        if (MatchesFsKey(*it, identifier, subtype, suffix)) {
            it = container.erase(it);
        } else {
            ++it;
        }
    }
}

UniValue CollectPrepareNonceMetadata(const PartiallySignedTransaction& psbt)
{
    UniValue out(UniValue::VARR);

    for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
        const PSBTInput& input = psbt.inputs[idx];

        const auto single_nonce = GetFsEntry(input.m_proprietary,
                                             wallet::fairsign::Identifier(),
                                             0,
                                             wallet::fairsign::kInputNonceKey);
        if (single_nonce) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("index", static_cast<int>(idx));
            obj.pushKV("mode", "single");
            obj.pushKV("signer", 0);
            obj.pushKV("nonce", HexStr(*single_nonce));
            out.push_back(obj);
        }

        for (const auto& prop : input.m_proprietary) {
            auto info = DecodeProprietaryKey(prop);
            if (!info) continue;
            if (info->identifier != wallet::fairsign::Identifier() || info->subtype != 0) continue;

            if (info->suffix == wallet::fairsign::kInputMuSigAggNonceKey) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("index", static_cast<int>(idx));
                obj.pushKV("mode", "musig_aggnonce");
                obj.pushKV("signer", -1);
                obj.pushKV("nonce", HexStr(prop.value));
                out.push_back(obj);
                continue;
            }

            if (info->suffix.size() > wallet::fairsign::kInputMuSigPubNoncePrefix.size() &&
                info->suffix.rfind(wallet::fairsign::kInputMuSigPubNoncePrefix, 0) == 0) {
                const std::string index_part = info->suffix.substr(wallet::fairsign::kInputMuSigPubNoncePrefix.size());
                int signer_index = -1;
                if (ParseInt32(index_part, &signer_index) && signer_index >= 0) {
                    UniValue obj(UniValue::VOBJ);
                    obj.pushKV("index", static_cast<int>(idx));
                    obj.pushKV("mode", "musig_pubnonce");
                    obj.pushKV("signer", signer_index);
                    obj.pushKV("nonce", HexStr(prop.value));
                    out.push_back(obj);
                }
            }
        }
    }

    return out;
}

std::optional<uint256> ExtractFsContractMeta(const PartiallySignedTransaction& psbt)
{
    const auto value = GetFsEntry(psbt.m_proprietary, wallet::fairsign::Identifier(), 0, "contract_meta");
    if (!value || value->size() != 32) return std::nullopt;
    uint256 meta;
    std::copy(value->begin(), value->end(), meta.begin());
    return meta;
}

uint256 ComputeAdaptorCommitment(const XOnlyPubKey& nonce,
                                const XOnlyPubKey& adaptor,
                                const XOnlyPubKey& signing,
                                const std::array<unsigned char, 32>& msg_digest)
{
    HashWriter hasher = TaggedHash(std::string(FS_COMMITMENT_TAG));
    hasher.write(MakeByteSpan(nonce));
    hasher.write(MakeByteSpan(adaptor));
    hasher.write(MakeByteSpan(signing));
    hasher.write(MakeByteSpan(msg_digest));
    return hasher.GetSHA256();
}

// Compute BIP-340 challenge: e = H_tagged("BIP0340/challenge", R' || Q || m)
// Returns raw 32-byte hash in the byte order that libsecp256k1 expects (big-endian scalar)
static inline std::array<unsigned char, 32>
ComputeBIP340ChallengeBytes(const XOnlyPubKey& r_prime,
                            const XOnlyPubKey& pubkey,
                            const std::array<unsigned char, 32>& msg_digest)
{
    HashWriter hasher = TaggedHash(std::string("BIP0340/challenge"));
    hasher.write(MakeByteSpan(r_prime));
    hasher.write(MakeByteSpan(pubkey));
    hasher.write(MakeByteSpan(msg_digest));

    std::array<unsigned char, 32> out{};
    const uint256 h = hasher.GetSHA256();

    // GetSHA256() returns SHA256 bytes in their natural (big-endian) order
    // libsecp256k1 expects 32-byte big-endian scalars
    // NO REVERSAL NEEDED - just copy the bytes directly
    std::memcpy(out.data(), h.begin(), 32);
    return out;
}

uint256 TapTweak32(const XOnlyPubKey& internal_key,
                   const std::optional<uint256>& merkle_root)
{
    HashWriter hw = TaggedHash(std::string("TapTweak"));
    hw.write(MakeByteSpan(internal_key));
    if (merkle_root) hw.write(MakeByteSpan(*merkle_root));
    return hw.GetSHA256();
}

/* ========================================================================
 * MuSig2 ADAPTOR SIGNATURE ARCHITECTURE
 * ========================================================================
 *
 * Problem: Allows organizations with cooperative multi-sig (2-of-2, n-of-n)
 * to participate in adversarial adaptor-based atomic swaps/settlements.
 *
 * Example: Alice Corp has 2-of-2 treasury (Alice1, Alice2). They want to
 * do a repo contract settlement with Bob (who might be single-key or also MuSig2).
 *
 * Key Insight: MuSig2 and Adaptors are ORTHOGONAL primitives:
 *   - MuSig2 = INTRA-party aggregation (cooperative, within Alice Corp)
 *   - Adaptors = INTER-party atomicity (adversarial, between Alice & Bob)
 *
 * Protocol Layers:
 * ┌────────────────────────────────────────────────────────────────┐
 * │ ADAPTOR LAYER (Adversarial: Alice Corp ↔ Bob)                 │
 * │  - Exchange R'_alice = R_alice + T   and   R'_bob = R_bob + T │
 * │  - Exchange s'_alice, s'_bob (pre-signatures)                 │
 * │  - Atomic completion: s_alice = s'_alice + t                  │
 * └────────────────────────────────────────────────────────────────┘
 *                              ↕
 * ┌────────────────────────────────────────────────────────────────┐
 * │ MUSIG2 LAYER (Cooperative: Alice1 ↔ Alice2)                   │
 * │  - Aggregate nonces: R_alice = MuSig2(R1, R2)                 │
 * │  - Compute partial sigs: partial1, partial2                   │
 * │  - Aggregate: s_alice = partial1 + partial2                   │
 * └────────────────────────────────────────────────────────────────┘
 *
 * CRITICAL: Challenge computation uses R' (adaptor nonce), not R (base nonce)
 *   Standard MuSig2:  e = H("BIP0340/challenge", R    || Q || m)
 *   Adaptor MuSig2:   e'= H("BIP0340/challenge", R'   || Q || m)  ← R' = R + T
 *
 * This ensures final signature (R' || s) verifies correctly after adaptor completion.
 *
 * Math for Alice (2-of-2 MuSig2 with adaptor):
 *   1. Alice1 generates k1, R1 = k1·G
 *      Alice2 generates k2, R2 = k2·G
 *   2. MuSig2 nonce agg: R_alice = MuSig2.NonceAgg(R1, R2)
 *   3. Adaptor layer: R'_alice = R_alice + T
 *   4. Challenge: e' = H(R'_alice || Q || m)  ← Uses R', not R!
 *   5. MuSig2 partial sigs:
 *        partial1 = k1 + e'·(c1·x1')  where c1 is MuSig2 coefficient
 *        partial2 = k2 + e'·(c2·x2')  where c2 is MuSig2 coefficient
 *   6. Aggregate: s'_alice = partial1 + partial2 = (k1+k2) + e'·(c1·x1'+c2·x2')
 *                                                 = k_alice + e'·x'_alice
 *   7. Adaptor completion: s_alice = s'_alice + t
 *
 * Final signature (R'_alice || s_alice) verifies against Q using standard BIP-340.
 *
 * Implementation Notes:
 *   - FairSignInputState.musig_state != nullptr indicates MuSig2 mode
 *   - FairSignInputState.has_keyagg_cache = true when MuSig2 is active
 *   - Single-key mode uses nonce_secret/tweaked_secret (existing fields)
 *   - MuSig2 mode uses musig_state->{secnonce, pubnonce, session}
 *
 * ======================================================================== */

// Deterministic nonce generation for adaptor signatures
// Uses secp256k1 audited primitives for scalar arithmetic (FINANCING_PRIMITIVES.md §9.4)
// Based on BIP-340 nonce derivation with adaptor-specific domain separation
static void GenerateDeterministicNonce(unsigned char nonce_out[32],
                                       const unsigned char secret[32],
                                       const uint256& msg_digest,
                                       const XOnlyPubKey& adaptor_point,
                                       const unsigned char aux[32],
                                       uint32_t counter)
{
    // H_tagged("fs/nonce", secret || msg || adaptor_point || aux || counter)
    HashWriter hw = TaggedHash(std::string("fs/nonce"));
    hw << std::span<const unsigned char>{secret, 32};
    hw << msg_digest;
    hw << adaptor_point;
    hw << std::span<const unsigned char>{aux, 32};
    hw << counter;

    uint256 nonce_hash = hw.GetSHA256();
    std::memcpy(nonce_out, nonce_hash.begin(), 32);
}

// MuSig2 adaptor support via secp256k1-zkp native APIs
// The adaptor point T is passed to secp256k1_musig_nonce_process, which computes
// the correct challenge e' = H(R' || Q || m) internally where R' = R + T.
// This leverages Blockstream's secp256k1-zkp fork (upstream bitcoin-core/secp256k1 removed adaptor support).

bool NormalizeAdaptorSecretToAdaptorX(std::array<unsigned char, 32>& sec,
                                      const XOnlyPubKey& adaptor_x)
{
    // Compute T_from_sec = sec * G
    secp256k1_pubkey T_from_sec;
    if (!secp256k1_ec_pubkey_create(GetSigningContext(), &T_from_sec, sec.data())) {
        return false; // invalid secret
    }

    // Derive xonly and its parity
    secp256k1_xonly_pubkey xonly_from_sec;
    int y_parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &xonly_from_sec, &y_parity, &T_from_sec)) {
        return false;
    }

    // Check x-coordinate matches the advertised adaptor point
    unsigned char xbytes[32];
    secp256k1_xonly_pubkey_serialize(GetSigningContext(), xbytes, &xonly_from_sec);
    if (std::memcmp(xbytes, adaptor_x.data(), 32) != 0) {
        memory_cleanse(xbytes, sizeof(xbytes));
        return false; // does not correspond to this T_x
    }

    // We bound the MuSig session to the EVEN-Y lift (0x02||x).
    // If sec*G had odd Y, negate the secret so (-sec)*G = even-Y lift.
    if (y_parity == 1) {
        if (!secp256k1_ec_seckey_negate(GetSigningContext(), sec.data())) {
            memory_cleanse(xbytes, sizeof(xbytes));
            return false;
        }
    }

    memory_cleanse(xbytes, sizeof(xbytes));
    return true;
}

// Generic contract metadata for Fair-Sign ceremony
struct ContractFairSignMetadata
{
    wallet::CovenantContractKind kind;
    std::vector<XOnlyPubKey> adaptor_points;  // Offer point, acceptance point, etc.
    std::vector<std::optional<uint256>> adaptor_secrets;  // Local secrets if available
};

std::optional<wallet::RepoOfferRecord> FindRepoByMeta(const wallet::CWallet& wallet, const uint256& meta)
{
    std::vector<wallet::RepoOfferRecord> records = wallet.ListRepoOffers();
    for (const auto& record : records) {
        const CTxDestination repay = record.lender_dest_override ? *record.lender_dest_override : record.lender_dest;
        const uint256 computed = wallet::ComputeRepoContractMeta(record, repay);
        if (computed == meta) {
            return record;
        }
    }
    return std::nullopt;
}

std::optional<wallet::ForwardContractRecord> FindForwardByMeta(const wallet::CWallet& wallet, const uint256& meta)
{
    std::vector<wallet::ForwardContractRecord> records = wallet.ListForwardContracts();
    for (const auto& record : records) {
        // Forward contract_meta is computed from commitments (offer + acceptance)
        const uint256 computed_meta = wallet::ComputeForwardContractMeta(record);
        if (computed_meta == meta) {
            return record;
        }
    }
    return std::nullopt;
}

std::optional<wallet::SpotOfferRecord> FindSpotByMeta(const wallet::CWallet& wallet, const uint256& meta)
{
    std::vector<wallet::SpotOfferRecord> records = wallet.ListSpotOffers();
    for (const auto& record : records) {
        if (!record.acceptance) continue;
        const uint256 computed = wallet::ComputeSpotContractMeta(record, &*record.acceptance);
        if (computed == meta) {
            return record;
        }
    }
    return std::nullopt;
}

std::optional<wallet::DifficultyContractRecord> FindDifficultyByMeta(const wallet::CWallet& wallet, const uint256& meta)
{
    for (const auto& rec : wallet.ListDifficultyContracts()) {
        if (wallet::ComputeDifficultyContractMeta(rec) == meta) return rec;
    }
    return std::nullopt;
}

//! Resolve the INTERNAL private key this wallet holds behind a difficulty payout (mirrors
//! GetCoopSignerKey in difficulty.cpp): expand the payout address's own provider and look up the key.
static bool ResolveDifficultyInternalKey(const wallet::CWallet& wallet, const XOnlyPubKey& payout_key,
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

// Generic contract lookup for Fair-Sign ceremony
std::optional<ContractFairSignMetadata> FindContractFairSignMetaByMeta(const wallet::CWallet& wallet, const uint256& meta)
{
    // Try repo first
    if (auto repo_opt = FindRepoByMeta(wallet, meta)) {
        if (!repo_opt->acceptance) {
            return std::nullopt;  // Repo requires acceptance to proceed
        }

        ContractFairSignMetadata result;
        result.kind = wallet::CovenantContractKind::REPO;
        result.adaptor_points.push_back(repo_opt->fs_tx_adaptor_point);
        result.adaptor_points.push_back(repo_opt->acceptance->fs_tx_adaptor_point);
        result.adaptor_secrets.push_back(repo_opt->local_fs_tx_adaptor_secret);
        result.adaptor_secrets.push_back(repo_opt->acceptance->local_fs_tx_adaptor_secret);
        return result;
    }

    // Try forward
    if (auto forward_opt = FindForwardByMeta(wallet, meta)) {
        if (!forward_opt->counterparty_adaptor_point) {
            return std::nullopt;  // Forward requires acceptance to proceed
        }

        ContractFairSignMetadata result;
        result.kind = wallet::CovenantContractKind::FORWARD;
        result.adaptor_points.push_back(forward_opt->fs_tx_adaptor_point);
        result.adaptor_points.push_back(*forward_opt->counterparty_adaptor_point);
        result.adaptor_secrets.push_back(forward_opt->local_fs_tx_adaptor_secret);
        result.adaptor_secrets.push_back(forward_opt->counterparty_adaptor_secret);
        return result;
    }

    // Try spot
    if (auto spot_opt = FindSpotByMeta(wallet, meta)) {
        if (!spot_opt->acceptance) {
            return std::nullopt;
        }

        ContractFairSignMetadata result;
        result.kind = wallet::CovenantContractKind::SPOT;
        result.adaptor_points.push_back(spot_opt->fs_tx_adaptor_point);
        result.adaptor_secrets.push_back(spot_opt->local_fs_tx_adaptor_secret);
        result.adaptor_points.push_back(spot_opt->acceptance->fs_tx_adaptor_point);
        result.adaptor_secrets.push_back(spot_opt->acceptance->local_fs_tx_adaptor_secret);
        return result;
    }

    // Try difficulty (atomic risk transfer). Unlike repo/forward/spot, the adaptor secret is NOT
    // stored — it is re-derived deterministically here from the internal key behind this wallet's own
    // owner payout, then VERIFIED against the stored point before being returned (a bad secret would
    // otherwise yield a bad adaptor signature). Stale/half-built records are rejected.
    if (auto diff_opt = FindDifficultyByMeta(wallet, meta)) {
        if (!diff_opt->counterparty_adaptor_point.has_value() || diff_opt->fs_context.IsNull()
            || !diff_opt->fs_tx_adaptor_point.IsFullyValid()
            || !diff_opt->counterparty_adaptor_point->IsFullyValid()) {
            return std::nullopt;  // not ceremony-ready (needs both VALID points + a context)
        }
        const XOnlyPubKey prop_point = diff_opt->fs_tx_adaptor_point;
        const XOnlyPubKey acc_point = *diff_opt->counterparty_adaptor_point;

        ContractFairSignMetadata result;
        result.kind = wallet::CovenantContractKind::DIFFICULTY;
        result.adaptor_points = {prop_point, acc_point};
        result.adaptor_secrets = {std::nullopt, std::nullopt};

        // Discover our role by MATCHING, not a stored side byte: try every payout this wallet could hold
        // (CFD: each party's leg owner; OPTION: the writer's leg owner + the buyer's leg cp), derive
        // PROPOSER then ACCEPTOR, and keep the secret whose point equals the stored one. The derivation
        // key is specific, so at most one (payout, role) matches — a non-owned/wrong key never collides.
        const std::array<std::pair<XOnlyPubKey, XOnlyPubKey>, 4> candidates = {{
            {diff_opt->terms.long_leg.owner_key,  diff_opt->long_owner_internal},
            {diff_opt->terms.long_leg.cp_key,     diff_opt->long_cp_internal},
            {diff_opt->terms.short_leg.owner_key, diff_opt->short_owner_internal},
            {diff_opt->terms.short_leg.cp_key,    diff_opt->short_cp_internal},
        }};
        bool matched = false;
        for (const auto& [payout_key, internal_key] : candidates) {
            if (matched) break;
            if (!internal_key.IsFullyValid()) continue;
            CKey internal_priv;
            if (!ResolveDifficultyInternalKey(wallet, payout_key, internal_key, internal_priv)) continue;

            auto [s_prop, p_prop] = wallet::DeriveDifficultyFsAdaptor(internal_priv, diff_opt->salt, diff_opt->fs_context, wallet::DIFFICULTY_FS_ROLE_PROPOSER);
            if (p_prop == prop_point) { result.adaptor_secrets[0] = s_prop; matched = true; break; }
            auto [s_acc, p_acc] = wallet::DeriveDifficultyFsAdaptor(internal_priv, diff_opt->salt, diff_opt->fs_context, wallet::DIFFICULTY_FS_ROLE_ACCEPTOR);
            if (p_acc == acc_point) { result.adaptor_secrets[1] = s_acc; matched = true; break; }
        }
        if (!result.adaptor_secrets[0].has_value() && !result.adaptor_secrets[1].has_value()) {
            return std::nullopt;  // we hold neither leg's key, or the record is stale/corrupt
        }
        return result;
    }

    // No matching contract found
    return std::nullopt;
}

bool ExtractWitnessTaprootKey(const CScript& script, XOnlyPubKey& out)
{
    CTxDestination dest;
    if (!ExtractDestination(script, dest)) return false;
    const auto* tap = std::get_if<WitnessV1Taproot>(&dest);
    if (!tap) return false;
    out = static_cast<const XOnlyPubKey&>(*tap);
    return true;
}

std::array<unsigned char, 32> HexToArray(const std::string& hex)
{
    const std::vector<unsigned char> bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Adaptor secret must be 32-byte hex");
    }
    std::array<unsigned char, 32> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

std::string ArrayToHex(const std::array<unsigned char, 32>& data)
{
    return HexStr(data);
}

} // namespace

namespace wallet {

// Helper: Prepare MuSig2 adaptor nonces for a single input (uses secp256k1-zkp only)
static bool PrepareMuSig2AdaptorInput(
    CWallet& wallet,
    PartiallySignedTransaction& psbt,
    size_t input_idx,
    const std::vector<CPubKey>& compressed_pubkeys,
    const std::vector<XOnlyPubKey>& xonly_pubkeys,
    const XOnlyPubKey& adaptor_point,
    const uint256& txid,
    const PrecomputedTransactionData& txdata)
{
    PSBTInput& input = psbt.inputs[input_idx];
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, input_idx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing UTXO for input %u", input_idx));
    }

    if (input.m_tap_internal_key.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT missing tap_internal_key for MuSig2");
    }

    // Convert xonly pubkeys to compressed using GetKeyByXOnly
    std::vector<CPubKey> converted_xonly;
    if (!xonly_pubkeys.empty()) {
        std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(utxo.scriptPubKey);
        if (!provider) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot get solving provider for UTXO");
        }

        for (const XOnlyPubKey& xonly : xonly_pubkeys) {
            CKey key;
            if (provider->GetKeyByXOnly(xonly, key)) {
                // Wallet controls this xonly key - use correct parity
                converted_xonly.push_back(key.GetPubKey());
            } else {
                // Wallet doesn't control - assume even parity for aggregation
                // This is acceptable for MuSig2 with external cosigners
                std::vector<unsigned char> bytes;
                bytes.reserve(33);
                bytes.push_back(0x02);
                bytes.insert(bytes.end(), xonly.begin(), xonly.end());
                CPubKey temp;
                temp.Set(bytes.begin(), bytes.end());
                converted_xonly.push_back(temp);
            }
        }
    }

    // Merge compressed and converted xonly pubkeys
    std::vector<CPubKey> cosigner_pubkeys;
    cosigner_pubkeys.reserve(compressed_pubkeys.size() + converted_xonly.size());
    cosigner_pubkeys.insert(cosigner_pubkeys.end(), compressed_pubkeys.begin(), compressed_pubkeys.end());
    cosigner_pubkeys.insert(cosigner_pubkeys.end(), converted_xonly.begin(), converted_xonly.end());

    if (cosigner_pubkeys.size() < 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "musig2_config.pubkeys must include at least two participants");
    }

    // Determine spend parameters (key-path vs script-path) and compute message digest
    const uint8_t sighash_type = input.sighash_type.has_value() ? static_cast<uint8_t>(*input.sighash_type)
                                                                : static_cast<uint8_t>(SIGHASH_DEFAULT);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;  // No OP_CODESEPARATOR

    bool is_keypath_spend = input.m_tap_scripts.empty();
    std::optional<uint256> tapleaf_hash;

    if (!is_keypath_spend) {
        const auto& [control_block, script] = *input.m_tap_scripts.begin();
        const uint8_t leaf_ver = script.empty() ? TAPROOT_LEAF_MASK : TAPROOT_LEAF_TAPSCRIPT;
        tapleaf_hash = (HashWriter{} << uint8_t(leaf_ver) << script).GetSHA256();

        execdata.m_tapleaf_hash = *tapleaf_hash;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_validation_weight_left_init = true;
        execdata.m_validation_weight_left = MAX_STANDARD_P2WSH_SCRIPT_SIZE;
    }

    // BIP341/342: Use TAPROOT for keypath spends, TAPSCRIPT for script-path spends
    const SigVersion sig_version = is_keypath_spend ? SigVersion::TAPROOT : SigVersion::TAPSCRIPT;
    uint256 msg_digest;
    if (!SignatureHashSchnorr(msg_digest, execdata, *psbt.tx, input_idx, sighash_type,
                              sig_version, txdata, MissingDataBehavior::FAIL)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute Schnorr signature hash for MuSig2 input");
    }

    // Identify the local MuSig participant controlled by this wallet
    // Try multiple lookup methods to handle both legacy and descriptor wallets
    int local_index = -1;
    CKey local_privkey;

    // Method 1: Direct pubkey hash lookup (works for legacy wallets)
    for (size_t i = 0; i < cosigner_pubkeys.size(); ++i) {
        const CPubKey& cpubkey = cosigner_pubkeys[i];
        if (const std::optional<CKey> key = wallet.GetKey(cpubkey.GetID())) {
            if (local_index != -1) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "Wallet controls multiple keys in musig2_config. Split keys across dedicated wallets.");
            }
            local_index = static_cast<int>(i);
            local_privkey = *key;
        }
    }

    // Method 2: For Taproot descriptor wallets, try looking up by the tap_internal_key directly
    if (local_index == -1 && !input.m_tap_internal_key.IsNull()) {
        // The tap_internal_key is already validated to match the MuSig aggregation
        // Try to get the key for the internal key from the solving provider using xonly lookup
        std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(utxo.scriptPubKey);
        if (provider) {
            CKey temp_key;
            // Use GetKeyByXOnly which tries both Y-coordinate parities
            if (provider->GetKeyByXOnly(input.m_tap_internal_key, temp_key)) {
                // Got the private key! Now find which entry in cosigner_pubkeys corresponds to it
                for (size_t i = 0; i < cosigner_pubkeys.size(); ++i) {
                    const CPubKey& cpubkey = cosigner_pubkeys[i];

                    // Check if this compressed pubkey corresponds to the tap_internal_key
                    // by converting it to xonly and comparing
                    secp256k1_pubkey pk_full;
                    if (secp256k1_ec_pubkey_parse(GetSigningContext(), &pk_full, cpubkey.data(), cpubkey.size())) {
                        secp256k1_xonly_pubkey pk_xonly;
                        if (secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &pk_xonly, nullptr, &pk_full)) {
                            unsigned char xonly_bytes[32];
                            secp256k1_xonly_pubkey_serialize(GetSigningContext(), xonly_bytes, &pk_xonly);

                            if (std::memcmp(xonly_bytes, input.m_tap_internal_key.data(), 32) == 0) {
                                // This pubkey matches! Use this as the local signer
                                local_index = static_cast<int>(i);
                                local_privkey = temp_key;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if (local_index == -1) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Wallet does not control any private key from musig2_config.pubkeys");
    }

    // Convert pubkeys to secp256k1 representation and aggregate
    std::vector<secp256k1_pubkey> pubkeys_parsed;
    pubkeys_parsed.reserve(cosigner_pubkeys.size());
    for (const auto& cpubkey : cosigner_pubkeys) {
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &pk, cpubkey.data(), cpubkey.size())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid pubkey in musig2_config");
        }
        pubkeys_parsed.push_back(pk);
    }

    std::vector<const secp256k1_pubkey*> pubkey_ptrs;
    pubkey_ptrs.reserve(pubkeys_parsed.size());
    for (auto& pk : pubkeys_parsed) {
        pubkey_ptrs.push_back(&pk);
    }

    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_pk;
    if (!secp256k1_musig_pubkey_agg(GetSigningContext(), nullptr, &agg_pk, &cache,
                                     pubkey_ptrs.data(), pubkey_ptrs.size())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "MuSig2 key aggregation failed");
    }

    // Validate that the aggregated MuSig2 key matches the PSBT's tap_internal_key
    unsigned char agg_pk_bytes[32];
    if (!secp256k1_xonly_pubkey_serialize(GetSigningContext(), agg_pk_bytes, &agg_pk)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize aggregated MuSig2 pubkey");
    }

    if (input.m_tap_internal_key != XOnlyPubKey(agg_pk_bytes)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "MuSig2 aggregated key does not match PSBT tap_internal_key. "
            "The pubkeys in musig2_config must aggregate to the spending key.");
    }

    // Serialize cosigner pubkeys into PSBT proprietary field for downstream RPCs
    DataStream pubkey_stream{};
    WriteCompactSize(pubkey_stream, static_cast<uint64_t>(cosigner_pubkeys.size()));
    for (const auto& pk : cosigner_pubkeys) {
        pubkey_stream.write(std::as_bytes(std::span<const unsigned char>(pk.data(), pk.size())));
    }
    const auto serialized_pubkeys = MakeUCharSpan(std::span<const std::byte>(pubkey_stream.data(), pubkey_stream.size()));
    ReplaceFsEntry(input.m_proprietary,
                   wallet::fairsign::Identifier(),
                   0,
                   wallet::fairsign::kInputMuSigPubKeysKey,
                   serialized_pubkeys);

    // Generate MuSig2 nonce for the local participant
    // CRITICAL SECURITY: Fresh cryptographic randomness for EVERY nonce generation
    // ============================================================================
    // Each call to adaptor.prepare MUST generate a unique nonce, even if called
    // with identical PSBT. Nonce reuse in Schnorr signatures enables:
    //   - Single-key: Direct private key extraction
    //   - MuSig2: Wagner's attack to extract private keys from aggregate sig
    //
    // GetStrongRandBytes() provides fresh entropy on EVERY call, ensuring nonces
    // are cryptographically independent across prepare() invocations.
    auto musig_state = std::make_unique<MuSigEphemeralState>();

    secp256k1_pubkey local_pubkey_full;
    if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &local_pubkey_full,
                                   local_privkey.GetPubKey().data(), local_privkey.GetPubKey().size())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse local MuSig2 pubkey");
    }

    unsigned char session_secrand[32];
    GetStrongRandBytes(session_secrand);  // Fresh random bytes for THIS nonce only

    std::array<unsigned char, 32> msg_digest_array{};
    std::copy(msg_digest.begin(), msg_digest.end(), msg_digest_array.begin());

    if (!secp256k1_musig_nonce_gen(GetSigningContext(),
                                    &musig_state->secnonce,
                                    &musig_state->pubnonce,
                                    session_secrand,
                                    reinterpret_cast<const unsigned char*>(local_privkey.begin()),
                                    &local_pubkey_full,
                                    msg_digest_array.data(),
                                    &cache,
                                    nullptr)) {
        memory_cleanse(session_secrand, sizeof(session_secrand));
        throw JSONRPCError(RPC_WALLET_ERROR, "MuSig2 nonce generation failed");
    }
    memory_cleanse(session_secrand, sizeof(session_secrand));

    unsigned char pubnonce_bytes[66];
    if (!secp256k1_musig_pubnonce_serialize(GetSigningContext(), pubnonce_bytes, &musig_state->pubnonce)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize MuSig2 public nonce");
    }

    const std::string nonce_suffix = std::string(wallet::fairsign::kInputMuSigPubNoncePrefix) + std::to_string(local_index);
    ReplaceFsEntry(input.m_proprietary,
                   wallet::fairsign::Identifier(),
                   0,
                   nonce_suffix,
                   std::span<const unsigned char>(pubnonce_bytes, sizeof(pubnonce_bytes)));

    // Clear stale partial signatures for this participant
    const std::string partial_suffix = std::string(wallet::fairsign::kInputMuSigPartialPrefix) + std::to_string(local_index);
    RemoveFsEntry(input.m_proprietary,
                  wallet::fairsign::Identifier(),
                  0,
                  partial_suffix);

    // Remove any pre-existing aggregated artefacts to force fresh ceremony
    RemoveFsEntry(input.m_proprietary,
                  wallet::fairsign::Identifier(),
                  0,
                  wallet::fairsign::kInputAdaptorSigKey);
    RemoveFsEntry(input.m_proprietary,
                  wallet::fairsign::Identifier(),
                  0,
                  wallet::fairsign::kInputCommitmentKey);
    RemoveFsEntry(input.m_proprietary,
                  wallet::fairsign::Identifier(),
                  0,
                  wallet::fairsign::kInputNonceKey);
    RemoveFsEntry(input.m_proprietary,
                  wallet::fairsign::Identifier(),
                  0,
                  wallet::fairsign::kInputMuSigAggNonceKey);

    ReplaceFsEntry(input.m_proprietary,
                   wallet::fairsign::Identifier(),
                   0,
                   wallet::fairsign::kInputAdaptorPointKey,
                   std::span<const unsigned char>(adaptor_point.begin(), XOnlyPubKey::size()));

    // Populate Fair-Sign session state
    FairSignInputState state;
    state.musig_state = std::move(musig_state);
    state.adaptor_point = adaptor_point;
    state.has_partial = false;
    state.sighash_type = sighash_type;
    state.is_keypath = is_keypath_spend;
    state.tapleaf_hash = tapleaf_hash;
    std::copy(msg_digest.begin(), msg_digest.end(), state.message_digest.begin());
    state.signing_key = XOnlyPubKey(agg_pk_bytes);
    state.has_keyagg_cache = true;
    std::memcpy(&state.keyagg_cache, &cache, sizeof(cache));
    state.musig_local_index = local_index;
    state.musig_total_signers = static_cast<int>(cosigner_pubkeys.size());
    state.nonce_parity = -1; // Determined after aggregation
    state.commitment = uint256{};
    state.r_nonce.reset();
    state.r_prime.reset();

    wallet.SetFairSignInputState(txid, input_idx, std::move(state));
    return true;
}

static bool ProduceMuSig2AdaptorPartial(
    CWallet& wallet,
    PartiallySignedTransaction& psbt,
    size_t input_idx,
    const uint256& txid)
{
    PSBTInput& input = psbt.inputs[input_idx];

    const auto pubkeys_value = GetFsEntry(input.m_proprietary,
                                          wallet::fairsign::Identifier(),
                                          0,
                                          wallet::fairsign::kInputMuSigPubKeysKey);
    if (!pubkeys_value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Input %u missing musig_pubkeys metadata. Call adaptor.prepare with musig2_config first.", input_idx));
    }

    DataStream pubkeys_stream(std::span<const unsigned char>(pubkeys_value->data(), pubkeys_value->size()));
    const uint64_t num_pubkeys_u64 = ReadCompactSize(pubkeys_stream);
    if (num_pubkeys_u64 == 0 || num_pubkeys_u64 > 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Invalid musig_pubkeys count (%u) in PSBT input %u",
                      static_cast<unsigned>(num_pubkeys_u64), input_idx));
    }
    const size_t total_signers = static_cast<size_t>(num_pubkeys_u64);

    std::vector<CPubKey> cosigner_pubkeys;
    cosigner_pubkeys.reserve(total_signers);
    for (size_t i = 0; i < total_signers; ++i) {
        std::vector<unsigned char> pk_bytes(33);
        pubkeys_stream.read(std::as_writable_bytes(std::span<unsigned char>(pk_bytes.data(), pk_bytes.size())));
        CPubKey pk;
        pk.Set(pk_bytes.begin(), pk_bytes.end());
        if (!pk.IsFullyValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Invalid MuSig2 pubkey at index %u in PSBT input %u",
                          static_cast<unsigned>(i), input_idx));
        }
        cosigner_pubkeys.push_back(pk);
    }

    int local_index = -1;
    CKey local_privkey;
    for (size_t i = 0; i < cosigner_pubkeys.size(); ++i) {
        if (const std::optional<CKey> key = wallet.GetKey(cosigner_pubkeys[i].GetID())) {
            local_index = static_cast<int>(i);
            local_privkey = *key;
            break;
        }
    }

    if (local_index == -1) {
        return false; // Wallet not participating in this MuSig input
    }

    if (!local_privkey.IsValid()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Local MuSig2 private key is invalid");
    }

    // Collect MuSig2 public nonces from PSBT proprietary fields
    std::vector<std::array<unsigned char, 66>> pubnonce_bytes(total_signers);
    std::vector<bool> have_pubnonce(total_signers, false);

    const std::string nonce_prefix(wallet::fairsign::kInputMuSigPubNoncePrefix);
    const std::string partial_prefix(wallet::fairsign::kInputMuSigPartialPrefix);

    for (const auto& entry : input.m_proprietary) {
        auto key_info = DecodeProprietaryKey(entry);
        if (!key_info) continue;
        if (key_info->identifier != wallet::fairsign::Identifier() || key_info->subtype != 0) continue;

        if (key_info->suffix.size() >= nonce_prefix.size() &&
            key_info->suffix.compare(0, nonce_prefix.size(), nonce_prefix) == 0) {
            const std::string index_str = key_info->suffix.substr(nonce_prefix.size());
            int32_t idx = -1;
            if (!ParseInt32(index_str, &idx) || idx < 0 || idx >= int(total_signers)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid musig_pubnonce index '%s' in PSBT input %u", index_str, input_idx));
            }
            if (entry.value.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("MuSig2 pubnonce for signer %d has invalid length (%u)", idx, entry.value.size()));
            }
            std::copy(entry.value.begin(), entry.value.end(), pubnonce_bytes[idx].begin());
            have_pubnonce[idx] = true;
        }
    }

    for (size_t i = 0; i < total_signers; ++i) {
        if (!have_pubnonce[i]) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("MuSig2 pubnonce for signer index %u missing in input %u",
                          static_cast<unsigned>(i), input_idx));
        }
    }

    std::vector<secp256k1_musig_pubnonce> pubnonce_objs(total_signers);
    std::vector<const secp256k1_musig_pubnonce*> pubnonce_ptrs(total_signers);
    for (size_t i = 0; i < total_signers; ++i) {
        if (!secp256k1_musig_pubnonce_parse(GetSigningContext(), &pubnonce_objs[i], pubnonce_bytes[i].data())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Invalid MuSig2 pubnonce for signer index %u", static_cast<unsigned>(i)));
        }
        pubnonce_ptrs[i] = &pubnonce_objs[i];
    }

    secp256k1_musig_aggnonce aggnonce;
    if (!secp256k1_musig_nonce_agg(GetSigningContext(), &aggnonce, pubnonce_ptrs.data(), total_signers)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to aggregate MuSig2 public nonces");
    }

    unsigned char aggnonce_bytes[132];
    if (!secp256k1_musig_aggnonce_serialize(GetSigningContext(), aggnonce_bytes, &aggnonce)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize MuSig2 aggregated nonce");
    }

    // Collect any existing partial signatures from the PSBT
    std::vector<std::array<unsigned char, 32>> partial_bytes(total_signers);
    std::vector<bool> have_partial(total_signers, false);

    for (const auto& entry : input.m_proprietary) {
        auto key_info = DecodeProprietaryKey(entry);
        if (!key_info) continue;
        if (key_info->identifier != wallet::fairsign::Identifier() || key_info->subtype != 0) continue;

        if (key_info->suffix.size() >= partial_prefix.size() &&
            key_info->suffix.compare(0, partial_prefix.size(), partial_prefix) == 0) {
            const std::string index_str = key_info->suffix.substr(partial_prefix.size());
            int32_t idx = -1;
            if (!ParseInt32(index_str, &idx) || idx < 0 || idx >= int(total_signers)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid musig_partial index '%s' in PSBT input %u", index_str, input_idx));
            }
            if (entry.value.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("MuSig2 partial signature for signer %d has invalid length (%u)", idx, entry.value.size()));
            }
            std::copy(entry.value.begin(), entry.value.end(), partial_bytes[idx].begin());
            have_partial[idx] = true;
        }
    }

    const CPubKey local_pubkey = local_privkey.GetPubKey();
    if (!local_pubkey.IsFullyValid()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Local MuSig2 public key is invalid");
    }

    secp256k1_pubkey local_pubkey_full;
    if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &local_pubkey_full,
                                   local_pubkey.data(), local_pubkey.size())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse local MuSig2 public key");
    }

    std::array<unsigned char, 32> local_partial_bytes{};
    bool local_partial_present = have_partial[local_index];
    secp256k1_musig_partial_sig local_partial_sig;
    bool local_partial_sig_valid{false};

    if (local_partial_present) {
        if (!secp256k1_musig_partial_sig_parse(GetSigningContext(), &local_partial_sig, partial_bytes[local_index].data())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Existing MuSig2 partial signature for signer %d is invalid", local_index));
        }
        std::copy(partial_bytes[local_index].begin(), partial_bytes[local_index].end(), local_partial_bytes.begin());
        local_partial_sig_valid = true;
    }

    bool aggregated_ready{false};
    std::array<unsigned char, 64> aggregated_sig_bytes{};
    std::array<unsigned char, 32> aggregated_r_bytes{};
    uint256 aggregated_commitment{};

    {
        LOCK(wallet.cs_wallet);
        FairSignInputState* state_ptr = wallet.GetMutableFairSignInputState(txid, input_idx);
        if (!state_ptr || !state_ptr->musig_state) {
            return false;
        }

        MuSigEphemeralState* musig_state = state_ptr->musig_state.get();
        std::memcpy(&musig_state->aggnonce, &aggnonce, sizeof(aggnonce));

        state_ptr->musig_local_index = local_index;
        state_ptr->musig_total_signers = static_cast<int>(total_signers);

        unsigned char adaptor_ser[33];
        adaptor_ser[0] = 0x02;
        std::memcpy(adaptor_ser + 1, state_ptr->adaptor_point.begin(), 32);

        secp256k1_pubkey adaptor_full;
        if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &adaptor_full, adaptor_ser, sizeof(adaptor_ser))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to convert adaptor point to full pubkey");
        }

        if (!secp256k1_musig_nonce_process(GetSigningContext(),
                                            &musig_state->session,
                                            &musig_state->aggnonce,
                                            state_ptr->message_digest.data(),
                                            &state_ptr->keyagg_cache,
                                            &adaptor_full)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to process MuSig2 aggregate nonce with adaptor");
        }

        if (!local_partial_sig_valid) {
            secp256k1_keypair keypair;
            if (!secp256k1_keypair_create(GetSigningContext(), &keypair,
                    reinterpret_cast<const unsigned char*>(local_privkey.begin()))) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create MuSig2 keypair for local signer");
            }
            if (!secp256k1_musig_partial_sign(GetSigningContext(),
                                              &local_partial_sig,
                                              &musig_state->secnonce,
                                              &keypair,
                                              &state_ptr->keyagg_cache,
                                              &musig_state->session)) {
                memory_cleanse(&keypair, sizeof(keypair));
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "MuSig2 partial signing failed (nonce already used). Restart with adaptor.prepare");
            }
            memory_cleanse(&keypair, sizeof(keypair));
            if (!secp256k1_musig_partial_sig_serialize(GetSigningContext(), local_partial_bytes.data(), &local_partial_sig)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize MuSig2 partial signature");
            }
            local_partial_sig_valid = true;
            local_partial_present = true;
        }

        if (!secp256k1_musig_partial_sig_verify(GetSigningContext(),
                                                &local_partial_sig,
                                                &pubnonce_objs[local_index],
                                                &local_pubkey_full,
                                                &state_ptr->keyagg_cache,
                                                &musig_state->session)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Local MuSig2 partial signature failed verification");
        }

        std::copy(local_partial_bytes.begin(), local_partial_bytes.end(), partial_bytes[local_index].begin());
        have_partial[local_index] = true;

        const bool all_partials_present = std::all_of(have_partial.begin(), have_partial.end(), [](bool v) { return v; });

        if (!all_partials_present) {
            state_ptr->has_partial = false;
            state_ptr->r_prime.reset();
            state_ptr->nonce_parity = -1;
            state_ptr->commitment = uint256{};
            memory_cleanse(state_ptr->pre_sig.data(), state_ptr->pre_sig.size());
        } else {
            std::vector<secp256k1_musig_partial_sig> partial_sigs(total_signers);
            std::vector<const secp256k1_musig_partial_sig*> partial_sig_ptrs(total_signers);
            for (size_t i = 0; i < total_signers; ++i) {
                if (i == static_cast<size_t>(local_index)) {
                    partial_sigs[i] = local_partial_sig;
                } else {
                    if (!secp256k1_musig_partial_sig_parse(GetSigningContext(), &partial_sigs[i], partial_bytes[i].data())) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Invalid MuSig2 partial signature for signer index %u", static_cast<unsigned>(i)));
                    }
                }
                partial_sig_ptrs[i] = &partial_sigs[i];
            }

            unsigned char agg_sig64[64];
            if (!secp256k1_musig_partial_sig_agg(GetSigningContext(), agg_sig64,
                                                 &musig_state->session,
                                                 partial_sig_ptrs.data(),
                                                 total_signers)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to aggregate MuSig2 partial signatures");
            }

            int nonce_parity = 0;
            if (!secp256k1_musig_nonce_parity(GetSigningContext(), &nonce_parity, &musig_state->session)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute MuSig2 nonce parity");
            }

            std::copy(agg_sig64, agg_sig64 + 64, aggregated_sig_bytes.begin());
            std::copy(agg_sig64, agg_sig64 + 32, aggregated_r_bytes.begin());

            XOnlyPubKey r_prime_x(std::span<const unsigned char>(aggregated_r_bytes.data(), aggregated_r_bytes.size()));
            const uint256 commitment = ComputeAdaptorCommitment(r_prime_x,
                                                                state_ptr->adaptor_point,
                                                                state_ptr->signing_key,
                                                                state_ptr->message_digest);
            aggregated_commitment = commitment;

            std::memcpy(state_ptr->pre_sig.data(), agg_sig64, 64);
            state_ptr->has_partial = true;
            state_ptr->r_prime = r_prime_x;
            state_ptr->nonce_parity = nonce_parity;
            state_ptr->commitment = commitment;

            aggregated_ready = true;
        }
    }

    // Update PSBT proprietary fields outside wallet lock
    const std::string partial_suffix = partial_prefix + std::to_string(local_index);
    ReplaceFsEntry(input.m_proprietary,
                   wallet::fairsign::Identifier(),
                   0,
                   partial_suffix,
                   std::span<const unsigned char>(local_partial_bytes.data(), local_partial_bytes.size()));

    ReplaceFsEntry(input.m_proprietary,
                   wallet::fairsign::Identifier(),
                   0,
                   wallet::fairsign::kInputMuSigAggNonceKey,
                   std::span<const unsigned char>(aggnonce_bytes, sizeof(aggnonce_bytes)));

    if (aggregated_ready) {
        ReplaceFsEntry(input.m_proprietary,
                       wallet::fairsign::Identifier(),
                       0,
                       wallet::fairsign::kInputAdaptorSigKey,
                       std::span<const unsigned char>(aggregated_sig_bytes.data(), aggregated_sig_bytes.size()));

        ReplaceFsEntry(input.m_proprietary,
                       wallet::fairsign::Identifier(),
                       0,
                       wallet::fairsign::kInputNonceKey,
                       std::span<const unsigned char>(aggregated_r_bytes.data(), aggregated_r_bytes.size()));

        ReplaceFsEntry(input.m_proprietary,
                       wallet::fairsign::Identifier(),
                       0,
                       wallet::fairsign::kInputCommitmentKey,
                       std::span<const unsigned char>(aggregated_commitment.begin(), 32));
    } else {
        RemoveFsEntry(input.m_proprietary,
                      wallet::fairsign::Identifier(),
                      0,
                      wallet::fairsign::kInputAdaptorSigKey);
        RemoveFsEntry(input.m_proprietary,
                      wallet::fairsign::Identifier(),
                      0,
                      wallet::fairsign::kInputNonceKey);
        RemoveFsEntry(input.m_proprietary,
                      wallet::fairsign::Identifier(),
                      0,
                      wallet::fairsign::kInputCommitmentKey);
    }

    memory_cleanse(local_partial_bytes.data(), local_partial_bytes.size());
    memory_cleanse(aggregated_sig_bytes.data(), aggregated_sig_bytes.size());
    memory_cleanse(aggregated_r_bytes.data(), aggregated_r_bytes.size());
    local_privkey = CKey();

    return true;
}

RPCHelpMan adaptor_prepare()
{
    return RPCHelpMan(
        "adaptor.prepare",
        "Prepare a Fair-Sign adaptor ceremony by attaching public nonces and commitments to a PSBT."
        " Inputs must be Taproot spends with wallet-controlled signing keys (key-path or annotated script-path)."
        " By default, rejects PSBTs with foreign unsigned non-Taproot inputs to prevent broken multi-party ceremonies.",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT"},
            {"musig2_config", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional MuSig2 configuration for cooperative multi-sig",
                {
                    {"pubkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of public keys to aggregate (xonly 32-byte or compressed 33-byte hex)",
                        {
                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Public key: xonly (32 bytes) or compressed (33 bytes) hex"},
                        }
                    },
                },
            },
            {"allow_nontaproot_signeable_values", RPCArg::Type::BOOL, RPCArg::Default{false},
                "Allow non-Taproot inputs not owned or pre-signed by this wallet (UNSAFE for multi-party contracts; breaks atomicity)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Updated PSBT"},
                {RPCResult::Type::ARR, "nonces", "Per-input nonce metadata exposed for audits and recovery",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "index", "Input index"},
                                {RPCResult::Type::STR, "mode", "nonce origin: single | musig_pubnonce | musig_aggnonce"},
                                {RPCResult::Type::NUM, "signer", "Signer index when mode=musig_pubnonce"},
                                {RPCResult::Type::STR_HEX, "nonce", "Encoded public nonce"},
                            }
                        }
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("adaptor.prepare", "\"psbt_base64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            PartiallySignedTransaction psbt;
            std::string error;
            if (!DecodeBase64PSBT(psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            if (!psbt.tx) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");
            }

            bool complete = false;
            const auto fill_err = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            // Parse allow_nontaproot_signeable_values parameter (default: false)
            bool allow_nontaproot_unsafe = false;
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                allow_nontaproot_unsafe = request.params[2].get_bool();
            }

            // PROTOCOL GUARD: Reject PSBTs with foreign unsigned non-Taproot inputs unless explicitly allowed.
            // Such inputs cannot participate in adaptor ceremony and will cause finalization failure if
            // the peer hasn't pre-signed them. This catches protocol errors early instead of wasting
            // nonce/secret exchange on a PSBT that can never be broadcast atomically.
            if (!allow_nontaproot_unsafe) {
                std::string foreign_unsigned_details;
                for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                    const PSBTInput& input = psbt.inputs[idx];
                    CTxOut utxo;
                    if (!psbt.GetInputUTXO(utxo, idx)) {
                        continue; // Missing UTXO, will fail later
                    }

                    // Classify as Taproot vs non-Taproot
                    CTxDestination dest;
                    bool is_taproot = false;
                    if (ExtractDestination(utxo.scriptPubKey, dest)) {
                        is_taproot = std::holds_alternative<WitnessV1Taproot>(dest);
                    }

                    // Skip Taproot inputs (they can participate in adaptor ceremony)
                    if (is_taproot) continue;

                    // Check if this wallet owns this non-Taproot input
                    isminetype mine = ISMINE_NO;
                    {
                        LOCK(pwallet->cs_wallet);
                        mine = pwallet->IsMine(utxo);
                    }
                    bool is_ours = (mine & ISMINE_SPENDABLE);

                    // Check if input is already signed (pre-signed by peer)
                    // Accept either finalized signatures OR partial signatures (from pre-sign without finalize)
                    bool has_final_sig = !input.final_script_witness.IsNull() || !input.final_script_sig.empty();
                    bool has_partial_sig = !input.partial_sigs.empty();
                    bool has_any_sig = has_final_sig || has_partial_sig;

                    // If non-Taproot, not ours, and not pre-signed → this is a protocol error
                    if (!is_ours && !has_any_sig) {
                        if (!foreign_unsigned_details.empty()) foreign_unsigned_details += ", ";
                        foreign_unsigned_details += strprintf("input %u", idx);
                    }
                }

                if (!foreign_unsigned_details.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("adaptor.prepare: PSBT contains foreign unsigned non-Taproot inputs (%s). "
                                  "For atomic multi-party contracts, all inputs must be either: "
                                  "(1) Taproot (witness_v1) for adaptor ceremony participation, OR "
                                  "(2) Pre-signed by their owner before ceremony (partial_sigs or final_scriptwitness/final_scriptsig present). "
                                  "Otherwise finalization will fail after ceremony. "
                                  "To bypass this safety check (UNSAFE for multi-party contracts), pass allow_nontaproot_signeable_values=true.",
                                  foreign_unsigned_details));
                }
            }

            const auto meta_opt = ExtractFsContractMeta(psbt);
            if (!meta_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT missing fs/contract_meta");
            }

            const auto contract_meta_opt = FindContractFairSignMetaByMeta(*pwallet, *meta_opt);
            if (!contract_meta_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "No matching contract found for contract_meta, or contract type not yet supported for Fair-Sign adaptor ceremony. "
                    "Supported: REPO, FORWARD (with acceptance). Pending: SPOT.");
            }

            // Verify and persist vault metadata before signing
            if (contract_meta_opt->kind == wallet::CovenantContractKind::FORWARD) {
                // Attempt to persist vault data if not already present
                if (auto forward_opt = FindForwardByMeta(*pwallet, *meta_opt)) {
                    pwallet->VerifyAndPersistForwardVaults(forward_opt->contract_id, psbt, /*allow_open_discovery=*/true);
                }
            } else if (contract_meta_opt->kind == wallet::CovenantContractKind::REPO) {
                // Attempt to persist vault data if not already present
                if (auto repo_opt = FindRepoByMeta(*pwallet, *meta_opt)) {
                    // HARDENING: Require collateral vault to be present before signing the opening PSBT
                    if (!pwallet->VerifyAndPersistRepoVault(repo_opt->offer_id, psbt)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "Opening PSBT is missing a valid collateral vault output. Refusing to sign.");
                    }

                    // HARDENING: Require principal delivery output to borrower with exact asset/amount
                    const CScript borrower_spk = GetScriptForDestination(repo_opt->borrower_dest);
                    const CAmount expected_principal_value = repo_opt->terms.principal_leg.is_native
                        ? static_cast<CAmount>(repo_opt->terms.principal_leg.units)
                        : wallet::DEFAULT_REPO_ASSET_OUTPUT_VALUE;

                    bool principal_ok = false;
                    for (const CTxOut& out : psbt.tx->vout) {
                        if (out.scriptPubKey != borrower_spk) continue;

                        if (repo_opt->terms.principal_leg.is_native) {
                            if (out.nValue == expected_principal_value) {
                                principal_ok = true;
                                break;
                            }
                        } else {
                            if (out.nValue != wallet::DEFAULT_REPO_ASSET_OUTPUT_VALUE) continue;
                            auto tag = assets::ParseAssetTag(out.vExt);
                            if (tag && tag->id == repo_opt->terms.principal_leg.asset_id &&
                                tag->amount == repo_opt->terms.principal_leg.units) {
                                principal_ok = true;
                                break;
                            }
                        }
                    }
                    if (!principal_ok) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "Opening PSBT missing correct principal delivery to borrower. Refusing to sign.");
                    }
                }
            }

            if (contract_meta_opt->adaptor_points.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Contract must have at least 2 adaptor points (offer + acceptance) for Fair-Sign ceremony");
            }

            const XOnlyPubKey offer_point = contract_meta_opt->adaptor_points[0];
            const XOnlyPubKey acceptance_point = contract_meta_opt->adaptor_points[1];
            (void)offer_point;  // Reserved for future use
            (void)acceptance_point;  // Reserved for future use

            const uint256 txid = psbt.tx->GetHash();
            PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

            const auto get_vault_metadata_for_script = [&](const CScript& spk) -> std::optional<wallet::VaultMetadata> {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(spk);
                if (managers.empty()) {
                    managers = pwallet->GetAllScriptPubKeyMans();
                }
                for (ScriptPubKeyMan* manager : managers) {
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    if (auto meta = desc_spkm->GetVaultMetadata(spk)) {
                        return meta;
                    }
                }
                return std::nullopt;
            };

            std::vector<std::optional<CKey>> signing_keys(psbt.inputs.size());
            std::vector<std::optional<XOnlyPubKey>> signing_points(psbt.inputs.size());
            std::vector<isminetype> input_mine(psbt.inputs.size(), ISMINE_NO);
            std::vector<std::string> key_sources(psbt.inputs.size());

            // Session-level adaptor point and secret: use the same T (and t) for all inputs
            // in this fair-sign session. Nonces remain per-input and unique.
            XOnlyPubKey session_adaptor_point = contract_meta_opt->adaptor_points[0];
            std::optional<std::array<unsigned char, 32>> session_secret;
                auto try_norm = [&](const std::optional<uint256>& cand, const XOnlyPubKey& T) -> std::optional<std::array<unsigned char, 32>> {
                    if (!cand) return std::nullopt;
                    std::array<unsigned char, 32> tmp{};
                    std::copy(cand->begin(), cand->end(), tmp.begin());
                    if (!NormalizeAdaptorSecretToAdaptorX(tmp, T)) return std::nullopt;
                    return tmp;
                };
            // Prefer a secret that matches offer_point; fall back to any provided point
            for (const std::optional<uint256>& cand : contract_meta_opt->adaptor_secrets) {
                if (auto s = try_norm(cand, contract_meta_opt->adaptor_points[0])) {
                    session_adaptor_point = contract_meta_opt->adaptor_points[0];
                    session_secret = s;
                    break;
                }
            }
            if (!session_secret) {
                for (const XOnlyPubKey& T : contract_meta_opt->adaptor_points) {
                    for (const std::optional<uint256>& cand : contract_meta_opt->adaptor_secrets) {
                        if (auto s = try_norm(cand, T)) {
                            session_adaptor_point = T;
                            session_secret = s;
                            break;
                        }
                    }
                    if (session_secret) break;
                }
            }

            auto resolve_privkey = [&](size_t idx,
                                       const CTxOut& utxo,
                                       const PSBTInput& input,
                                       const std::optional<wallet::VaultSigningIntent>& vault_intent = std::nullopt) -> std::optional<CKey> {
                if (idx < signing_keys.size() && signing_keys[idx]) {
                    return signing_keys[idx];
                }

                auto record_key = [&](const XOnlyPubKey& xonly,
                                      const CKey& candidate,
                                      std::string source) -> std::optional<CKey> {
                    signing_keys[idx] = candidate;
                    signing_points[idx] = xonly;
                    key_sources[idx] = std::move(source);
                    return signing_keys[idx];
                };

                auto try_fetch = [&](const XOnlyPubKey& xonly,
                                     const std::string& source_prefix) -> std::optional<CKey> {
                    CKey cached;
                    if (WalletTryGetKeyByXOnly(*pwallet, xonly, cached)) {
                        return record_key(xonly, cached, strprintf("%s_cached", source_prefix));
                    }
                    if (std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(utxo.scriptPubKey)) {
                        CKey candidate;
                        if (provider->GetKeyByXOnly(xonly, candidate)) {
                            return record_key(xonly, candidate, strprintf("%s_solving_xonly", source_prefix));
                        }
                    }

                    std::set<ScriptPubKeyMan*> spk_mans = pwallet->GetScriptPubKeyMans(utxo.scriptPubKey);
                    if (spk_mans.empty()) {
                        spk_mans = pwallet->GetAllScriptPubKeyMans();
                    }

                    for (ScriptPubKeyMan* spkm : spk_mans) {
                        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
                        if (!desc_spkm) continue;
                        CKey candidate;
                        if (desc_spkm->GetKeyByXOnly(xonly, candidate)) {
                            return record_key(xonly, candidate, strprintf("%s_descriptor_xonly", source_prefix));
                        }
                    }

                    for (unsigned char prefix : {0x02, 0x03}) {
                        unsigned char b[33] = {prefix};
                        std::copy(xonly.begin(), xonly.end(), b + 1);
                        CPubKey fullpubkey;
                        fullpubkey.Set(b, b + 33);

                        for (ScriptPubKeyMan* spkm : spk_mans) {
                            auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
                            if (!desc_spkm) continue;
                            std::unique_ptr<FlatSigningProvider> provider = desc_spkm->GetSigningProvider(fullpubkey);
                            if (provider) {
                                CKey candidate;
                                if (provider->GetKey(fullpubkey.GetID(), candidate)) {
                                    return record_key(xonly, candidate,
                                                      strprintf("%s_descriptor_parity_%u", source_prefix, (unsigned)prefix));
                                }
                            }
                        }

                        if (auto key_opt = pwallet->GetKey(fullpubkey.GetID())) {
                            return record_key(xonly, *key_opt,
                                              strprintf("%s_keystore_parity_%u", source_prefix, (unsigned)prefix));
                        }
                    }

                    return std::nullopt;
                };

                // Prefer tapleaf signing keys first (script-path spends)
                for (const auto& [tap_key, _] : input.m_tap_bip32_paths) {
                    if (auto key = try_fetch(tap_key, "tapleaf")) {
                        return key;
                    }
                }

                if (!input.m_tap_internal_key.IsNull()) {
                    if (auto key = try_fetch(input.m_tap_internal_key, "tapinternal")) {
                        return key;
                    }
                }

                if (!signing_keys[idx]) {
                    if (auto vault_meta = get_vault_metadata_for_script(utxo.scriptPubKey)) {
                        if (input.m_tap_scripts.empty()) {
                            // CRITICAL: If vault intent is present, use ONLY the intent-specified leaf
                            // even when tap_scripts is empty. This prevents wrong-leaf selection.
                            if (vault_intent.has_value()) {
                                // Find the leaf matching the intent
                                auto selected_leaf = wallet::SelectLeafByIntent(*vault_meta, *vault_intent);
                                if (!selected_leaf) {
                                    return std::nullopt;
                                }

                                // Try to get key for the intent-specified leaf's signer
                                if (auto key = try_fetch(selected_leaf->signing_key,
                                                        strprintf("vault_intent_%s", vault_intent->leaf_purpose))) {
                                    return key;
                                }
                                return std::nullopt;
                            }

                            // No intent - fall back to old heuristics
                            // Try internal key first (key-path path)
                            if (auto key = try_fetch(vault_meta->spenddata.internal_key, "vault_internal")) {
                                return key;
                            }
                            // Also consider cooperative leaf signers directly from vault metadata to
                            // allow the counterparty wallet to resolve its key even if tap_scripts
                            // were not attached to the PSBT.
                            for (const auto& leaf : vault_meta->leaves) {
                                if (leaf.purpose == "cooperative" || leaf.purpose.find("coop") != std::string::npos) {
                                    for (const XOnlyPubKey& xo : ExtractTaprootScriptSigners(leaf.script)) {
                                        if (auto key = try_fetch(xo, "vault_leaf_cooperative_signer")) {
                                            return key;
                                        }
                                    }
                                }
                            }
                        } else {
                            std::vector<const VaultLeafDescriptor*> matched_leaves;
                            for (const auto& leaf : vault_meta->leaves) {
                                bool matches_leaf = false;
                                for (const auto& [script_key, _] : input.m_tap_scripts) {
                                    if (script_key.second == leaf.leaf_version &&
                                        script_key.first == leaf.script) {
                                        matches_leaf = true;
                                        break;
                                    }
                                }
                                if (matches_leaf) {
                                    matched_leaves.push_back(&leaf);
                                }
                            }

                            if (!matched_leaves.empty()) {
                                // CRITICAL: If vault intent is present, ONLY consider the leaf specified by intent
                                // This prevents wrong-leaf selection when multiple leaves share the same signing key
                                if (vault_intent.has_value()) {
                                    std::vector<const VaultLeafDescriptor*> intent_filtered;
                                    for (const VaultLeafDescriptor* leaf : matched_leaves) {
                                        uint256 leaf_hash = (HashWriter{HASHER_TAPLEAF} << leaf->leaf_version << leaf->script).GetSHA256();
                                        if (leaf_hash == vault_intent->tapleaf_hash && leaf->purpose == vault_intent->leaf_purpose) {
                                            intent_filtered.push_back(leaf);
                                            break;  // Only one leaf should match
                                        }
                                    }
                                    matched_leaves = intent_filtered;
                                    if (matched_leaves.empty()) {
                                        return std::nullopt;
                                    }
                                }

                                std::vector<const VaultLeafDescriptor*> cooperative_leaves;
                                std::vector<const VaultLeafDescriptor*> other_leaves;
                                cooperative_leaves.reserve(matched_leaves.size());
                                other_leaves.reserve(matched_leaves.size());
                                for (const VaultLeafDescriptor* leaf : matched_leaves) {
                                    if (leaf->purpose == "cooperative" ||
                                        leaf->purpose.find("coop") != std::string::npos) {
                                        cooperative_leaves.push_back(leaf);
                                    } else {
                                        other_leaves.push_back(leaf);
                                    }
                                }

                                auto try_leaves = [&](const std::vector<const VaultLeafDescriptor*>& leaves)
                                    -> std::optional<CKey> {
                                        for (const VaultLeafDescriptor* leaf : leaves) {
                                            if (auto key = try_fetch(leaf->signing_key,
                                                                     strprintf("vault_leaf_%s", leaf->purpose))) {
                                                return key;
                                            }
                                        }
                                        return std::nullopt;
                                    };

                                if (auto key = try_leaves(cooperative_leaves)) return key;
                                if (auto key = try_leaves(other_leaves)) return key;
                            }
                        }
                    }
                }

                // Fallback: scan PSBT's tap_scripts to discover signer candidates by parsing the script itself.
                // This helps the counterparty wallet resolve its signing key even if its BIP32 paths
                // or local VaultMetadata are not attached for this input.
                if (!signing_keys[idx] && !input.m_tap_scripts.empty()) {
                    std::set<XOnlyPubKey> candidates;
                    for (const auto& [script_key, _] : input.m_tap_scripts) {
                        const std::vector<unsigned char>& script_bytes = script_key.first;
                        for (const XOnlyPubKey& xo : ExtractTaprootScriptSigners(script_bytes)) {
                            candidates.insert(xo);
                        }
                    }
                    if (!candidates.empty()) {
                        for (const XOnlyPubKey& xo : candidates) {
                            if (auto key = try_fetch(xo, "tapscript")) {
                                return key;
                            }
                        }
                    }
                }

                return std::nullopt;
            };

            // Clean up expired sessions before starting a new one
            {
                LOCK(pwallet->cs_wallet);
                pwallet->CleanupExpiredFairSignSessions();
            }

            pwallet->ClearFairSignSession(txid);

            // Initialize session with TTL
            {
                LOCK(pwallet->cs_wallet);
                pwallet->InitFairSignSession(txid, 600);  // 10 minutes default (FINANCING_PRIMITIVES.md §4.5)
            }

            // Collect UTXOs that will be locked for this ceremony
            // Only lock UTXOs that THIS wallet owns (not counterparty's inputs)
            std::vector<COutPoint> utxos_to_lock;
            pwallet->WalletLogPrintf("adaptor.prepare: Checking %d inputs for UTXO locking\n", psbt.inputs.size());

            for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                if (psbt.tx->vin.size() <= idx) continue;

                // Check if wallet owns this UTXO
                CTxOut utxo;
                if (!psbt.GetInputUTXO(utxo, idx)) {
                    pwallet->WalletLogPrintf("  Input %d: Missing UTXO info, skipping\n", idx);
                    continue;  // Missing UTXO info, skip
                }

                // Only lock if we own this output
                const isminetype mine_flags = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(utxo));
                input_mine[idx] = mine_flags;
                bool owns_input = (mine_flags & ISMINE_SPENDABLE);
                if (!owns_input) {
                    // Check ownership without vault intent filtering (just checking if we have keys)
                    if (idx < psbt.inputs.size() && resolve_privkey(idx, utxo, psbt.inputs[idx], std::nullopt)) {
                        owns_input = true;
                    }
                }

                pwallet->WalletLogPrintf("  Input %d: %s (IsMine=%u Owns=%d)\n", idx, psbt.tx->vin[idx].prevout.ToString(), (unsigned)mine_flags, owns_input ? 1 : 0);

                if (owns_input) {
                    utxos_to_lock.push_back(psbt.tx->vin[idx].prevout);
                }
            }

            pwallet->WalletLogPrintf("adaptor.prepare: Locking %d UTXOs for ceremony\n", utxos_to_lock.size());

            // Lock UTXOs for Fair-Sign ceremony (only those we own)
            if (!utxos_to_lock.empty()) {
                LOCK(pwallet->cs_wallet);
                if (!pwallet->LockFairSignUTXOs(txid, utxos_to_lock)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to lock UTXOs for Fair-Sign ceremony");
                }
            }

            // ========== MuSig2 PATH (secp256k1-zkp only) ==========
            // If musig2_config is provided, use MuSig2 cooperative signing path
            // Otherwise, fall through to existing n=1 single-signer path below
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                const UniValue& musig2_config = request.params[1].get_obj();
                const UniValue& pubkeys_arr = musig2_config.find_value("pubkeys");

                if (!pubkeys_arr.isArray() || pubkeys_arr.size() < 2) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "musig2_config.pubkeys must be array with at least 2 pubkeys");
                }

                // Parse pubkeys: accept both xonly (32 bytes) and compressed (33 bytes)
                // For Taproot, xonly is preferred since that's how descriptor wallets store keys
                std::vector<CPubKey> compressed_pubkeys;
                std::vector<XOnlyPubKey> xonly_pubkeys;

                for (size_t i = 0; i < pubkeys_arr.size(); ++i) {
                    const std::string& pubkey_hex = pubkeys_arr[i].get_str();
                    if (!IsHex(pubkey_hex)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex pubkey in musig2_config.pubkeys");
                    }

                    std::vector<unsigned char> pubkey_bytes = ParseHex(pubkey_hex);

                    if (pubkey_bytes.size() == 33) {
                        // Compressed pubkey - validate and store
                        CPubKey cpubkey;
                        cpubkey.Set(pubkey_bytes.begin(), pubkey_bytes.end());
                        if (!cpubkey.IsFullyValid()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid compressed pubkey in musig2_config.pubkeys");
                        }
                        compressed_pubkeys.push_back(cpubkey);
                    } else if (pubkey_bytes.size() == 32) {
                        // Xonly pubkey - store for later conversion in PrepareMuSig2AdaptorInput
                        XOnlyPubKey xonly;
                        std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), xonly.begin());
                        xonly_pubkeys.push_back(xonly);
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Pubkey must be 32 bytes (xonly) or 33 bytes (compressed)");
                    }
                }

                // Determine which adaptor point to use (default: offer_point)
                const XOnlyPubKey adaptor_point = offer_point;

                // Prepare MuSig2 adaptor nonces for each wallet-owned input
                size_t prepared_inputs = 0;
                for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                    if (PrepareMuSig2AdaptorInput(*pwallet, psbt, idx, compressed_pubkeys, xonly_pubkeys, adaptor_point, txid, txdata)) {
                        ++prepared_inputs;
                    }
                }

                if (prepared_inputs == 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "No wallet-controlled inputs for MuSig2 adaptor");
                }

                // Return updated PSBT with MuSig2 nonces
                DataStream ssTx{};
                ssTx << psbt;
                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("nonces", CollectPrepareNonceMetadata(psbt));
                return result;
            }

            // ========== EXISTING n=1 SINGLE-SIGNER PATH (unchanged) ==========
            size_t prepared_inputs{0};
            for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                PSBTInput& input = psbt.inputs[idx];
                CTxOut utxo;
                if (!psbt.GetInputUTXO(utxo, idx)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing UTXO information for input %u", idx));
                }

                // Determine whether wallet controls this Taproot input
                if (input.m_tap_internal_key.IsNull()) {
                    CTxDestination dest;
                    if (!ExtractDestination(utxo.scriptPubKey, dest) || !std::holds_alternative<WitnessV1Taproot>(dest)) {
                        continue; // Non-Taproot input; adaptor signing not required
                    }
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "PSBT missing tap_internal_key; recreate/fill PSBT with BIP32 derivations so the internal key is present");
                }
                const XOnlyPubKey internal_key = input.m_tap_internal_key;

                // CRITICAL: Extract vault intent BEFORE key resolution
                // This ensures resolve_privkey selects the correct leaf when multiple leaves share keys
                auto vault_intent = wallet::ExtractVaultIntent(input);

                if (!vault_intent) {
                    // CRITICAL: Detect vault inputs by checking if this scriptPubKey is registered as a vault
                    // Query the vault registry to see if this output is a known vault
                    std::optional<wallet::VaultMetadata> vault_meta;
                    std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(utxo.scriptPubKey);
                    if (managers.empty()) {
                        managers = pwallet->GetAllScriptPubKeyMans();
                    }
                    for (ScriptPubKeyMan* manager : managers) {
                        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                        if (!desc_spkm) continue;
                        auto meta = desc_spkm->GetVaultMetadata(utxo.scriptPubKey);
                        if (meta) {
                            vault_meta = meta;
                            break;
                        }
                    }

                    if (vault_meta) {
                        // This input is spending a registered vault but lacks vault intent
                        // The vault has multiple leaves (cooperative, timeout, etc.) and we need explicit selection
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("adaptor.prepare: Input %u spends a vault output (found in registry with %zu leaves) "
                                     "but PSBT is missing vault signing intent (fs/vault_intent proprietary field). "
                                     "The builder must embed the leaf intent (cooperative, timeout, etc.) in the PSBT "
                                     "before calling adaptor.prepare. This prevents ambiguous leaf selection when "
                                     "multiple leaves share the same signing key.", idx, vault_meta->leaves.size()));
                    }
                    // else: not a vault (regular wallet UTXO or unknown), allow to proceed without intent
                }

                if (!signing_keys[idx]) {
                    signing_keys[idx] = resolve_privkey(idx, utxo, input, vault_intent);
                }

                if (!signing_keys[idx]) {
                    continue; // Not our input
                }

                FSDBG("prepare: idx=%u", (unsigned)idx);
                FSDBG("  P (internal)   = %s", HexXOnly(internal_key));

                CKey privkey = *signing_keys[idx];

                const uint8_t sighash_type = input.sighash_type.has_value() ? static_cast<uint8_t>(*input.sighash_type) : static_cast<uint8_t>(SIGHASH_DEFAULT);

                ScriptExecutionData execdata;
                execdata.m_annex_init = true;
                execdata.m_annex_present = false;
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = 0xFFFFFFFF;  // No OP_CODESEPARATOR

                // Determine signing mode: key-path or script-path
                bool is_keypath_spend = input.m_tap_scripts.empty();
                std::optional<uint256> tapleaf_hash;
                std::vector<unsigned char> tapleaf_script_bytes;
                std::vector<unsigned char> tapleaf_control_bytes;
                bool tapleaf_has_witness = false;
                std::vector<XOnlyPubKey> script_signers;
                int script_signer_slot = -1;

                std::vector<CandidateTapLeaf> candidate_leaves;
                if (!is_keypath_spend) {
                    if (input.m_tap_scripts.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Script-path spend detected but no tap_scripts in PSBT input");
                    }
                    candidate_leaves.reserve(input.m_tap_scripts.size());
                    for (const auto& [leaf_key, control_blocks] : input.m_tap_scripts) {
                        CandidateTapLeaf cand;
                        cand.script = leaf_key.first;
                        cand.leaf_version = leaf_key.second;
                        cand.hash = ComputeTapleafHash(
                            cand.leaf_version,
                            std::span<const unsigned char>(cand.script.data(), cand.script.size()));
                        if (!control_blocks.empty()) {
                            const auto& cb = *control_blocks.begin();
                            cand.control.assign(cb.begin(), cb.end());
                        }
                        cand.signers = ExtractTaprootScriptSigners(cand.script);
                        candidate_leaves.push_back(std::move(cand));
                    }
                }

                // Determine which signing key this wallet controls (internal vs tapleaf)
                XOnlyPubKey signing_point = internal_key;
                if (signing_points[idx]) {
                    signing_point = *signing_points[idx];
                } else if (!is_keypath_spend) {
                    if (input.m_tap_bip32_paths.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Script-path spend detected but PSBT is missing tapleaf signing key metadata");
                    }
                    signing_point = input.m_tap_bip32_paths.begin()->first;
                }

                FSDBG("  Signing key    = %s", HexXOnly(signing_point));

                // VALIDATE vault signing intent if present
                // Note: Intent-based leaf filtering already happened in resolve_privkey,
                // ensuring signing_point is from the correct leaf. Here we validate and
                // configure signing parameters based on the validated intent.
                if (vault_intent) {
                    FSDBG("  Vault intent enforced: purpose='%s', leaf_hash=%s",
                          vault_intent->leaf_purpose, HexU256(vault_intent->tapleaf_hash));

                    // Validate intent against registry metadata
                    auto vault_meta = get_vault_metadata_for_script(utxo.scriptPubKey);
                    if (!vault_meta) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Vault intent present but no vault metadata found for input %d scriptPubKey", idx));
                    }

                    std::string validation_error;
                    if (!wallet::ValidateVaultIntent(*vault_meta, *vault_intent, validation_error)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Vault intent validation failed for input %d: %s", idx, validation_error));
                    }

                    // Select and configure signing for the intent-specified leaf
                    auto selected_leaf = wallet::SelectLeafByIntent(*vault_meta, *vault_intent);
                    if (!selected_leaf) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Vault intent specifies leaf that cannot be resolved for input %d", idx));
                    }

                    // Configure signing parameters for the validated leaf
                    is_keypath_spend = false;
                    tapleaf_script_bytes = selected_leaf->script;
                    tapleaf_control_bytes = vault_intent->control_block;
                    script_signers = ExtractTaprootScriptSigners(selected_leaf->script);
                    const auto it_slot = std::find(script_signers.begin(), script_signers.end(), signing_point);
                    script_signer_slot = it_slot == script_signers.end() ? -1 : static_cast<int>(std::distance(script_signers.begin(), it_slot));
                    tapleaf_hash = vault_intent->tapleaf_hash;
                    tapleaf_has_witness = !tapleaf_script_bytes.empty() && !tapleaf_control_bytes.empty();

                    FSDBG("  Configured signing: leaf='%s', signers=%zu, slot=%d",
                          vault_intent->leaf_purpose, script_signers.size(), script_signer_slot);
                } else {
                    // No intent present - determine if this input is a contract vault we control.
                    const COutPoint& prevout = psbt.tx->vin.at(idx).prevout;
                    bool is_contract_vault_input = false;
                    std::optional<wallet::VaultMetadata> cached_vault_meta = get_vault_metadata_for_script(utxo.scriptPubKey);

                    if (cached_vault_meta.has_value()) {
                        is_contract_vault_input = true;
                    }

                    if (contract_meta_opt->kind == wallet::CovenantContractKind::FORWARD) {
                        auto forward_record = FindForwardByMeta(*pwallet, *meta_opt);

                        auto matches_forward_vault = [&](const wallet::ForwardContractRecord& record) -> bool {
                            return (record.long_margin_vault && prevout == *record.long_margin_vault) ||
                                   (record.short_margin_vault && prevout == *record.short_margin_vault);
                        };

                        if (forward_record && matches_forward_vault(*forward_record)) {
                            is_contract_vault_input = true;
                        } else if (forward_record && forward_record->open_txid.has_value()) {
                            const Txid open_txid = Txid::FromUint256(*forward_record->open_txid);
                            const CWalletTx* open_wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(open_txid));
                            if (open_wtx) {
                                pwallet->VerifyAndPersistForwardVaults(forward_record->contract_id, open_wtx->tx);
                                if (auto refreshed = FindForwardByMeta(*pwallet, *meta_opt)) {
                                    if (matches_forward_vault(*refreshed)) {
                                        is_contract_vault_input = true;
                                    }
                                }
                            }
                        }
                    } else if (contract_meta_opt->kind == wallet::CovenantContractKind::REPO) {
                        if (auto repo_record = FindRepoByMeta(*pwallet, *meta_opt)) {
                            if (repo_record->vault_outpoint && prevout == *repo_record->vault_outpoint) {
                                is_contract_vault_input = true;
                            }
                        }
                    }

                    if (is_contract_vault_input) {
                        throw JSONRPCError(
                            RPC_INVALID_PARAMETER,
                            strprintf("adaptor.prepare: Input %u spends contract vault %s but PSBT is missing vault signing intent "
                                      "(fs/vault_intent proprietary field). Embed the intended leaf before calling adaptor.prepare.",
                                      idx, prevout.ToString()));
                    }

                    // Legacy fallback: non-vault inputs (funding/change) may proceed without intent.
                    FSDBG("  WARNING: No vault intent in PSBT - falling back to registry lookup");

                    if (contract_meta_opt->kind == wallet::CovenantContractKind::FORWARD) {
                        auto vault_meta = cached_vault_meta.has_value() ? cached_vault_meta : get_vault_metadata_for_script(utxo.scriptPubKey);
                        if (vault_meta.has_value()) {
                            const VaultLeafDescriptor* coop = nullptr;
                            for (const auto& leaf : vault_meta->leaves) {
                                if (leaf.purpose == "cooperative" || leaf.purpose.find("coop") != std::string::npos) {
                                    coop = &leaf;
                                    break;
                                }
                            }
                            if (coop) {
                                // Determine our tapleaf signing key for coop leaf
                                std::vector<XOnlyPubKey> coop_signers = ExtractTaprootScriptSigners(coop->script);
                                if (std::find(coop_signers.begin(), coop_signers.end(), signing_point) == coop_signers.end()) {
                                    // Swap to a signer we control if current signing_point isn't in coop leaf
                                    for (const XOnlyPubKey& xo : coop_signers) {
                                        CKey tmp;
                                        if (WalletTryGetKeyByXOnly(*pwallet, xo, tmp)) {
                                            signing_point = xo;
                                            signing_points[idx] = xo;
                                            signing_keys[idx] = tmp;
                                            break;
                                        }
                                    }
                                }

                                // Locate control block for coop leaf from spenddata
                                std::optional<std::vector<unsigned char>> control_opt;
                                for (const auto& [leaf_key, control_blocks] : vault_meta->spenddata.scripts) {
                                    if (leaf_key.second == coop->leaf_version && leaf_key.first == coop->script) {
                                        if (!control_blocks.empty()) {
                                            const auto& cb = *control_blocks.begin();
                                            control_opt = std::vector<unsigned char>(cb.begin(), cb.end());
                                        }
                                        break;
                                    }
                                }
                                if (control_opt) {
                                    is_keypath_spend = false;
                                    tapleaf_script_bytes = coop->script;
                                    tapleaf_control_bytes = *control_opt;
                                    script_signers = coop_signers;
                                    const auto it_slot = std::find(script_signers.begin(), script_signers.end(), signing_point);
                                    script_signer_slot = it_slot == script_signers.end() ? -1 : static_cast<int>(std::distance(script_signers.begin(), it_slot));
                                    tapleaf_hash = ComputeTapleafHash(
                                        coop->leaf_version,
                                        std::span<const unsigned char>(tapleaf_script_bytes.data(), tapleaf_script_bytes.size()));
                                    tapleaf_has_witness = !tapleaf_script_bytes.empty() && !tapleaf_control_bytes.empty();
                                }
                            }
                        }
                    }
                }

                if (!is_keypath_spend) {
                    const CandidateTapLeaf* chosen = nullptr;
                    const CandidateTapLeaf* fallback = nullptr;
                    for (const auto& cand : candidate_leaves) {
                        const auto slot_it = std::find(cand.signers.begin(), cand.signers.end(), signing_point);
                        if (slot_it == cand.signers.end()) continue;
                        if (!fallback) fallback = &cand;
                        if (cand.signers.size() > 1) {
                            chosen = &cand;
                            script_signer_slot = static_cast<int>(std::distance(cand.signers.begin(), slot_it));
                            script_signers = cand.signers;
                            tapleaf_script_bytes = cand.script;
                            tapleaf_control_bytes = cand.control;
                            tapleaf_hash = cand.hash;
                            tapleaf_has_witness = !tapleaf_script_bytes.empty() && !tapleaf_control_bytes.empty();
                            break;
                        }
                    }
                    if (!chosen && fallback && !tapleaf_hash.has_value()) {
                        chosen = fallback;
                        const auto slot_it = std::find(chosen->signers.begin(), chosen->signers.end(), signing_point);
                        script_signer_slot = static_cast<int>(std::distance(chosen->signers.begin(), slot_it));
                        script_signers = chosen->signers;
                        tapleaf_script_bytes = chosen->script;
                        tapleaf_control_bytes = chosen->control;
                        tapleaf_hash = chosen->hash;
                        tapleaf_has_witness = !tapleaf_script_bytes.empty() && !tapleaf_control_bytes.empty();
                    }
                    if (!chosen && !tapleaf_hash.has_value()) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "Unable to locate tapleaf script matching wallet signing key");
                    }
                    execdata.m_tapleaf_hash = *tapleaf_hash;
                    execdata.m_tapleaf_hash_init = true;
                    execdata.m_validation_weight_left_init = true;
                    execdata.m_validation_weight_left = MAX_STANDARD_P2WSH_SCRIPT_SIZE;
                    FSDBG("  Script-path spend detected, tapleaf_hash = %s", HexU256(*tapleaf_hash));
                }

                // BIP341/342: Use TAPROOT for keypath spends, TAPSCRIPT for script-path spends
                const SigVersion sig_version = is_keypath_spend ? SigVersion::TAPROOT : SigVersion::TAPSCRIPT;
                uint256 msg_digest;
                if (!SignatureHashSchnorr(msg_digest, execdata, *psbt.tx, idx, sighash_type, sig_version, txdata, MissingDataBehavior::FAIL)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute Schnorr signature hash");
                }

                FSDBG("  msg_digest      = %s", HexU256(msg_digest));
                FSDBG("  sighash_type    = %u", (unsigned)sighash_type);

                // R' model: n=1 adaptor signatures (no MuSig2 aggregation)
                FairSignInputState state;
                if (!is_keypath_spend) {
                    state.tapleaf_hash = tapleaf_hash;
                    state.tapleaf_script = tapleaf_script_bytes;
                    state.tapleaf_control_block = tapleaf_control_bytes;
                    state.has_tapleaf_witness = tapleaf_has_witness;
                    state.tapleaf_signers = script_signers;
                    state.tapleaf_signer_slot = script_signer_slot;
                    // CRITICAL: Store vault intent purpose for enforcement in adaptor.complete
                    if (vault_intent) {
                        state.vault_intent_purpose = vault_intent->leaf_purpose;
                    }
                } else {
                    state.tapleaf_signers.clear();
                    state.tapleaf_signer_slot = -1;
                }

                std::array<unsigned char, 32> base_seckey{};
                std::memcpy(base_seckey.data(), reinterpret_cast<const unsigned char*>(privkey.begin()), base_seckey.size());

                // Step 1: Derive full pubkey from privkey (gets correct Y coordinate)
                secp256k1_pubkey P_full;
                if (!secp256k1_ec_pubkey_create(GetSigningContext(), &P_full, base_seckey.data())) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create pubkey from privkey");
                }

                // Sanity check: verify privkey matches the expected signing key (internal or tapleaf)
                secp256k1_xonly_pubkey P_from_full;
                int pk_parity = 0;
                if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &P_from_full, &pk_parity, &P_full)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to xonly-derive signing pubkey");
                }
                unsigned char p_bytes[32];
                secp256k1_xonly_pubkey_serialize(GetSigningContext(), p_bytes, &P_from_full);
                if (std::memcmp(p_bytes, signing_point.data(), 32) != 0) {
                    pwallet->WalletLogPrintf("adaptor.prepare: Signing key mismatch idx=%u", (unsigned)idx);
                    throw JSONRPCError(RPC_WALLET_ERROR, "Privkey does not match Taproot signing key for this input");
                }
                // Ensure even-Y representation for BIP-340 signing
                if (pk_parity == 1) {
                    if (!secp256k1_ec_seckey_negate(GetSigningContext(), base_seckey.data())) {
                        memory_cleanse(p_bytes, sizeof(p_bytes));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to negate signing key for BIP-340 even-Y convention");
                    }
                    if (!secp256k1_ec_pubkey_create(GetSigningContext(), &P_full, base_seckey.data())) {
                        memory_cleanse(p_bytes, sizeof(p_bytes));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to recreate pubkey after negation");
                    }
                    if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &P_from_full, &pk_parity, &P_full)) {
                        memory_cleanse(p_bytes, sizeof(p_bytes));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive xonly pubkey after negation");
                    }
                    if (pk_parity != 0) {
                        memory_cleanse(p_bytes, sizeof(p_bytes));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to normalize signing key to even Y");
                    }
                }
                memory_cleanse(p_bytes, sizeof(p_bytes));

                std::optional<uint256> mr;
                secp256k1_xonly_pubkey Q_xonly;
                int q_parity = 0;
                std::array<unsigned char, 32> signing_seckey{};

                if (is_keypath_spend) {
                    if (!input.m_tap_merkle_root.IsNull()) {
                        mr = input.m_tap_merkle_root;
                    }

                    secp256k1_keypair keypair;
                    if (!secp256k1_keypair_create(GetSigningContext(), &keypair, base_seckey.data())) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create keypair for taproot tweak");
                    }

                    const uint256 tweak_u256 = TapTweak32(internal_key, mr);
                    unsigned char tweak32[32];
                    std::memcpy(tweak32, tweak_u256.begin(), 32);

                    if (mr) {
                        FSDBG("  merkle_root    = %s", HexU256(*mr));
                    } else {
                        FSDBG("  merkle_root    = <none>");
                    }
                    FSDBG("  TapTweak(P,MR) = %s", HexU256(tweak_u256));

                    if (!secp256k1_keypair_xonly_tweak_add(GetSigningContext(), &keypair, tweak32)) {
                        memory_cleanse(tweak32, sizeof(tweak32));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to apply Taproot tweak to keypair");
                    }

                    unsigned char tweaked_seckey[32];
                    if (!secp256k1_keypair_sec(GetSigningContext(), tweaked_seckey, &keypair)) {
                        memory_cleanse(tweak32, sizeof(tweak32));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract tweaked secret from keypair");
                    }

                    secp256k1_pubkey Q_full;
                    if (!secp256k1_ec_pubkey_create(GetSigningContext(), &Q_full, tweaked_seckey)) {
                        memory_cleanse(tweak32, sizeof(tweak32));
                        memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive tweaked pubkey");
                    }

                    if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &Q_xonly, &q_parity, &Q_full)) {
                        memory_cleanse(tweak32, sizeof(tweak32));
                        memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to obtain xonly tweaked pubkey");
                    }

                    if (q_parity == 1) {
                        if (!secp256k1_ec_seckey_negate(GetSigningContext(), tweaked_seckey)) {
                            memory_cleanse(tweak32, sizeof(tweak32));
                            memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to negate tweaked secret for even-Y");
                        }
                        if (!secp256k1_ec_pubkey_create(GetSigningContext(), &Q_full, tweaked_seckey)) {
                            memory_cleanse(tweak32, sizeof(tweak32));
                            memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to recreate tweaked pubkey after negation");
                        }
                        if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &Q_xonly, &q_parity, &Q_full)) {
                            memory_cleanse(tweak32, sizeof(tweak32));
                            memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive xonly tweaked pubkey after negation");
                        }
                    }

                    XOnlyPubKey output_key_xonly;
                    if (!ExtractWitnessTaprootKey(utxo.scriptPubKey, output_key_xonly)) {
                        memory_cleanse(tweak32, sizeof(tweak32));
                        memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract Taproot output key from UTXO");
                    }

                    unsigned char Q_bytes[32];
                    secp256k1_xonly_pubkey_serialize(GetSigningContext(), Q_bytes, &Q_xonly);

                    FSDBG("  Q (keypath)    = %s", Hex32(Q_bytes));
                    FSDBG("  Q (from UTXO)  = %s", HexXOnly(output_key_xonly));
                    FSDBG("  Q parity (y)   = %d (%s)", q_parity,
                          q_parity ? "odd - x' negated for BIP-340" : "even - x' unchanged");

                    if (std::memcmp(Q_bytes, output_key_xonly.data(), 32) != 0) {
                        pwallet->WalletLogPrintf(
                            "adaptor.prepare: Tweaked key mismatch idx=%u merkle=%s scripts=%zu",
                            (unsigned)idx,
                            HexU256(input.m_tap_merkle_root),
                            input.m_tap_scripts.size());
                        memory_cleanse(Q_bytes, sizeof(Q_bytes));
                        memory_cleanse(tweak32, sizeof(tweak32));
                        memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Tweaked output key does not match UTXO scriptPubKey");
                    }
                    memory_cleanse(Q_bytes, sizeof(Q_bytes));
                    memory_cleanse(tweak32, sizeof(tweak32));

                    std::memcpy(signing_seckey.begin(), tweaked_seckey, 32);
                    memory_cleanse(tweaked_seckey, sizeof(tweaked_seckey));
                } else {
                    Q_xonly = P_from_full;
                    q_parity = 0;
                    std::memcpy(signing_seckey.begin(), base_seckey.data(), 32);
                }

                memory_cleanse(base_seckey.data(), base_seckey.size());

                [[maybe_unused]] auto try_normalize = [&](const std::optional<uint256>& cand,
                                          const XOnlyPubKey& point) -> std::optional<std::array<unsigned char, 32>> {
                    if (!cand) return std::nullopt;
                    std::array<unsigned char, 32> tmp{};
                    std::copy(cand->begin(), cand->end(), tmp.begin());
                    if (!NormalizeAdaptorSecretToAdaptorX(tmp, point)) {
                        memory_cleanse(tmp.data(), tmp.size());
                        return std::nullopt;
                    }
                    return tmp;
                };

                // Try to normalize local adaptor secrets (if wallet holds them)
                XOnlyPubKey adaptor_point = session_adaptor_point;
                std::optional<std::array<unsigned char, 32>> normalized_secret = session_secret;

                // Step 2: Convert adaptor point T_x to full pubkey (assume even y)
                FSDBG("  T_x (adaptor)  = %s", HexXOnly(adaptor_point));
                FSDBG("  Has normalized t? %s", normalized_secret ? "YES" : "NO");

                unsigned char T_ser33[33];
                T_ser33[0] = 0x02;  // Even y-coordinate - CRITICAL ASSUMPTION
                std::memcpy(T_ser33 + 1, adaptor_point.data(), 32);
                secp256k1_pubkey T_full;
                if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &T_full, T_ser33, 33)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse adaptor point");
                }
                memory_cleanse(T_ser33, sizeof(T_ser33));

                FSDBG("  T parsed as:   0x02 || T_x (assumed even Y)");

#if TC_FS_DEBUG_SECRETS
                if (normalized_secret) {
                    // Verify normalized secret matches T_even
                    secp256k1_pubkey T_from_secret;
                    if (secp256k1_ec_pubkey_create(GetSigningContext(), &T_from_secret, normalized_secret->data())) {
                        secp256k1_xonly_pubkey T_xonly;
                        int t_parity = 0;
                        secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &T_xonly, &t_parity, &T_from_secret);
                        unsigned char t_x[32];
                        secp256k1_xonly_pubkey_serialize(GetSigningContext(), t_x, &T_xonly);
                        FSDBG("  [DEBUG] t·G_x = %s (parity=%d)", Hex32(t_x), t_parity);
                        FSDBG("  [DEBUG] T_x   = %s", HexXOnly(adaptor_point));
                        FSDBG("  [DEBUG] Match? %s", std::memcmp(t_x, adaptor_point.data(), 32) == 0 ? "YES" : "NO");
                    }
                }
#endif

                // Step 4: n=1 Adaptor Nonce Generation (R' = R + T model)
                // CRITICAL: Must ensure R' has EVEN Y for BIP-340 compatibility
                // Resample nonce k until R' = R + T has even Y parity

                // CRITICAL SECURITY: Fresh cryptographic randomness for EVERY nonce
                // ==================================================================
                // GetStrongRandBytes(aux) generates FRESH entropy on each prepare() call,
                // ensuring nonces are unique even for identical PSBT. Nonce reuse in
                // Schnorr signatures allows direct private key extraction.
                unsigned char aux[32];
                GetStrongRandBytes(aux);  // Fresh random bytes for THIS nonce only

                unsigned char nonce_k[32];
                secp256k1_pubkey R_full;
                secp256k1_xonly_pubkey R_xonly;
                secp256k1_pubkey R_prime_full;
                secp256k1_xonly_pubkey R_prime_xonly;
                int r_parity = 0;
                int r_prime_parity = 1;  // Force loop entry
                int attempts = 0;

                for (attempts = 0; attempts < 128 && r_prime_parity != 0; ++attempts) {
                    // Generate deterministic nonce k based on secret, message, adaptor point, and counter
                    // This ensures nonces are never reused and are deterministic for auditability
                    GenerateDeterministicNonce(nonce_k, signing_seckey.data(), msg_digest, adaptor_point, aux, attempts);

                    // Compute R = k·G
                    if (!secp256k1_ec_pubkey_create(GetSigningContext(), &R_full, nonce_k)) {
                        continue;  // Invalid nonce, retry
                    }

                    // Extract R parity and enforce BIP-340 even-Y convention
                    // CRITICAL: BIP-340 requires k to correspond to even-Y R
                    // If R has odd Y, we must negate k (just like regular BIP-340 signing)
                    if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &R_xonly, &r_parity, &R_full)) {
                        continue;
                    }

                    // BIP-340: if R has odd Y, negate k so k·G = -R (even Y)
                    if (r_parity == 1) {
                        if (!secp256k1_ec_seckey_negate(GetSigningContext(), nonce_k)) {
                            continue;  // Negation failed, retry
                        }
                        // Now k corresponds to -R (even Y), recompute R_full
                        if (!secp256k1_ec_pubkey_create(GetSigningContext(), &R_full, nonce_k)) {
                            continue;
                        }
                        // Update R_xonly and parity (should now be 0)
                        if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &R_xonly, &r_parity, &R_full)) {
                            continue;
                        }
                    }

                    // Now R has even Y (r_parity should be 0)
                    // Compute R' = R + T
                    const secp256k1_pubkey* pubkeys_to_add[2] = {&R_full, &T_full};
                    if (!secp256k1_ec_pubkey_combine(GetSigningContext(), &R_prime_full, pubkeys_to_add, 2)) {
                        continue;  // Point addition failed, retry
                    }

                    // Extract R' parity - THIS is what we need to be even
                    if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &R_prime_xonly, &r_prime_parity, &R_prime_full)) {
                        continue;
                    }

                    if (r_prime_parity == 0) {
                        break;  // ✅ R' has even Y, accept this nonce
                    }
                    // Otherwise r_prime_parity == 1 (odd), retry with new k
                }

                if (r_prime_parity != 0) {
                    memory_cleanse(nonce_k, sizeof(nonce_k));
                    memory_cleanse(aux, sizeof(aux));
                    memory_cleanse(signing_seckey.data(), signing_seckey.size());
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Failed to sample nonce with even R' after %d attempts", attempts));
                }

                // Cleanse auxiliary randomness (no longer needed)
                memory_cleanse(aux, sizeof(aux));

                // Store R_x for verification in partial()
                XOnlyPubKey r_nonce_x;
                unsigned char r_nonce_bytes[32];
                secp256k1_xonly_pubkey_serialize(GetSigningContext(), r_nonce_bytes, &R_xonly);
                std::memcpy(r_nonce_x.begin(), r_nonce_bytes, 32);

                // Extract R'_x for commitment and PSBT
                XOnlyPubKey r_prime_x;
                unsigned char r_prime_bytes[32];
                secp256k1_xonly_pubkey_serialize(GetSigningContext(), r_prime_bytes, &R_prime_xonly);
                std::memcpy(r_prime_x.begin(), r_prime_bytes, 32);

                FSDBG("  Nonce attempts  = %d (resampled until R' even)", attempts + 1);
                FSDBG("  Parities: Q_parity=%d R_parity=%d R'_parity=%d", q_parity, r_parity, r_prime_parity);
                FSDBG("  R_x             = %s", Hex32(r_nonce_bytes));
                FSDBG("  R parity (y)    = %d (not enforced)", r_parity);
                FSDBG("  R'_x            = %s", Hex32(r_prime_bytes));
                FSDBG("  R' parity (y)   = %d (MUST be 0)", r_prime_parity);
#if TC_FS_DEBUG_SECRETS
                FSDBG("  k (nonce secret)= %s", Hex32(nonce_k));

                // Verify k·G = R
                secp256k1_pubkey kG_verify;
                if (secp256k1_ec_pubkey_create(GetSigningContext(), &kG_verify, nonce_k)) {
                    secp256k1_xonly_pubkey kG_xonly;
                    int kG_parity = 0;
                    secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &kG_xonly, &kG_parity, &kG_verify);
                    unsigned char kG_x[32];
                    secp256k1_xonly_pubkey_serialize(GetSigningContext(), kG_x, &kG_xonly);
                    FSDBG("  [VERIFY] k·G_x   = %s (parity=%d)", Hex32(kG_x), kG_parity);
                    FSDBG("  [VERIFY] R_x     = %s (parity=%d)", Hex32(r_nonce_bytes), r_parity);
                    if (std::memcmp(kG_x, r_nonce_bytes, 32) != 0) {
                        FSDBG("  [VERIFY] ⚠ WARNING: k·G_x ≠ R_x!");
                    }
                    if (kG_parity != r_parity) {
                        FSDBG("  [VERIFY] ⚠ WARNING: k·G parity ≠ R parity!");
                    }
                }
#endif

                memory_cleanse(r_prime_bytes, sizeof(r_prime_bytes));

                // Store nonce k and tweaked secret for later use in partial()
                std::array<unsigned char, 32> nonce_secret_array;
                std::memcpy(nonce_secret_array.begin(), nonce_k, 32);
                memory_cleanse(nonce_k, sizeof(nonce_k));

                std::array<unsigned char, 32> tweaked_secret_array;
                std::memcpy(tweaked_secret_array.begin(), signing_seckey.data(), 32);
                memory_cleanse(signing_seckey.data(), signing_seckey.size());

                // Compute commitment H_tag("fs/adaptor")(R' || T || Q || m)
                XOnlyPubKey Q_x;
                unsigned char Q_x_bytes[32];
                secp256k1_xonly_pubkey_serialize(GetSigningContext(), Q_x_bytes, &Q_xonly);
                std::memcpy(Q_x.begin(), Q_x_bytes, 32);
                memory_cleanse(Q_x_bytes, sizeof(Q_x_bytes));

                std::array<unsigned char, 32> msg_digest_array;
                std::memcpy(msg_digest_array.data(), msg_digest.begin(), 32);
                const uint256 commitment = ComputeAdaptorCommitment(r_prime_x, adaptor_point, Q_x, msg_digest_array);

                FSDBG("  commitment      = %s", HexU256(commitment));

                // Store metadata for partial() step
                state.adaptor_point = adaptor_point;
                state.sighash_type = sighash_type;
                state.is_keypath = is_keypath_spend;
                if (tapleaf_hash) {
                    state.tapleaf_hash = *tapleaf_hash;
                } else {
                    state.tapleaf_hash.reset();
                }
                std::copy(msg_digest.begin(), msg_digest.end(), state.message_digest.begin());
                if (state.is_keypath) {
                    state.signing_key = Q_x;  // key-path uses tweaked output key
                } else {
                    state.signing_key = signing_point;  // script-path uses leaf signing key
                }
                state.has_partial = false;
                state.nonce_parity = r_prime_parity;  // R' parity (always 0; enforced by nonce retry)
                state.commitment = commitment;

                // Store n=1 ephemeral state (no MuSig2 structures needed)
                state.nonce_secret = nonce_secret_array;
                state.tweaked_secret = tweaked_secret_array;
                state.r_nonce = r_nonce_x;      // R (for verification: R + T should equal R')
                state.r_prime = r_prime_x;      // R' (even Y, used for BIP-340 challenge)

                if (normalized_secret) {
                    state.adaptor_secret = *normalized_secret;
                }

                // Write R', T, and commitment to PSBT
                ReplaceFsEntry(input.m_proprietary,
                               wallet::fairsign::Identifier(),
                               0,
                               "nonce_pub",
                               std::span<const unsigned char>(r_prime_x.begin(), XOnlyPubKey::size()));

                ReplaceFsEntry(input.m_proprietary,
                               wallet::fairsign::Identifier(),
                               0,
                               "commitment",
                               std::span<const unsigned char>(commitment.begin(), 32));

                // Write T to PSBT (will update with R' and commitment in partial)
                ReplaceFsEntry(input.m_proprietary,
                               wallet::fairsign::Identifier(),
                               0,
                               "adaptor_point",
                               std::span<const unsigned char>(state.adaptor_point.begin(), XOnlyPubKey::size()));

                // Store ephemeral state (secnonce, pubnonce, session) in memory
                pwallet->SetFairSignInputState(txid, idx, std::move(state));
                ++prepared_inputs;
            }

            if (prepared_inputs == 0) {
                std::string diag;
                diag.reserve(psbt.inputs.size() * 48);
                for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                    const bool has_key = signing_keys[idx].has_value();
                    const std::string& source = key_sources[idx];
                    diag += strprintf("input%u:ismine=%u,key=%s;", (unsigned)idx,
                                       static_cast<unsigned>(input_mine[idx]),
                                       has_key ? source.c_str() : "none");
                }
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("No wallet-controlled inputs eligible for adaptor preparation (%s)", diag));
            }

            DataStream ssTx{};
            ssTx << psbt;
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("nonces", CollectPrepareNonceMetadata(psbt));
            return result;
        }
    );
}

RPCHelpMan adaptor_partial()
{
    return RPCHelpMan(
        "adaptor.partial",
        "Produce partial adaptor signatures for wallet-controlled Taproot inputs (key-path or annotated script-path).",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Updated PSBT"},
                {RPCResult::Type::BOOL, "complete", "Whether all inputs now have final taproot signatures"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Final transaction hex (present when complete=true and extraction succeeded)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (present when hex is returned)"},
            }
        },
        RPCExamples{
            HelpExampleCli("adaptor.prepare", "\"psbt_base64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            PartiallySignedTransaction psbt;
            std::string error;
            if (!DecodeBase64PSBT(psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            if (!psbt.tx) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");
            }

            bool complete = false;
            const auto fill_err = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            const uint256 txid = psbt.tx->GetHash();

            // Check session TTL before proceeding
            {
                LOCK(pwallet->cs_wallet);
                const auto* session = pwallet->GetFairSignSession(txid);
                if (session && session->IsExpired()) {
                    const int64_t time_remaining = session->TimeRemaining();
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Fair-Sign ceremony expired (TTL exceeded). Session has %d seconds remaining. "
                                  "UTXOs have been auto-unlocked. Please restart with adaptor.prepare and fresh nonces.",
                                  time_remaining));
                }
            }

            size_t signed_inputs{0};
            for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                PSBTInput& input = psbt.inputs[idx];

                if (GetFsEntry(input.m_proprietary,
                               wallet::fairsign::Identifier(),
                               0,
                               wallet::fairsign::kInputMuSigPubKeysKey)) {
                    if (ProduceMuSig2AdaptorPartial(*pwallet, psbt, idx, txid)) {
                        ++signed_inputs;
                    }
                    continue;
                }

                // Get n=1 state fields (copy to avoid holding lock)
                XOnlyPubKey signing_key;  // Q (output key)
                std::array<unsigned char, 32> message_digest;
                XOnlyPubKey adaptor_point;
                XOnlyPubKey r_nonce;      // R (even Y, for challenge)
                XOnlyPubKey r_prime;      // R' (for commitment)
                std::array<unsigned char, 32> nonce_k;
                std::array<unsigned char, 32> tweaked_secret;
                uint256 commitment;
                int nonce_parity;
                (void)nonce_parity;  // Reserved for future use

                {
                    LOCK(pwallet->cs_wallet);
                    FairSignInputState* state_ptr = pwallet->GetMutableFairSignInputState(txid, idx);
                    if (!state_ptr || !state_ptr->nonce_secret.has_value()) continue;

                    signing_key = state_ptr->signing_key;
                    message_digest = state_ptr->message_digest;
                    adaptor_point = state_ptr->adaptor_point;
                    r_nonce = *state_ptr->r_nonce;
                    r_prime = *state_ptr->r_prime;
                    nonce_k = *state_ptr->nonce_secret;
                    tweaked_secret = *state_ptr->tweaked_secret;
                    commitment = state_ptr->commitment;
                    nonce_parity = state_ptr->nonce_parity;
                }

                // n=1 Adaptor Partial Signature: s' = k + e'·x' (mod n)
                // Compute BIP-340 challenge: e' = H("BIP0340/challenge", R' || Q || m)
                // CRITICAL: Use R' for challenge so final sig (R' || s) verifies correctly
                // Math: s·G = (k + e'·x' + t)·G = R + e'·Q + T = R' + e'·Q ✓

                // Use bytes-only challenge to avoid endianness confusion
                const auto e_bytes = ComputeBIP340ChallengeBytes(r_prime, signing_key, message_digest);
                unsigned char e_be[32];
                std::memcpy(e_be, e_bytes.data(), 32);  // These are the exact bytes for libsecp256k1

                FSDBG("partial: idx=%u", (unsigned)idx);
                FSDBG("  R_x (internal)  = %s", HexXOnly(r_nonce));
                FSDBG("  R'_x (for e')   = %s", HexXOnly(r_prime));
                FSDBG("  Q               = %s", HexXOnly(signing_key));
                FSDBG("  msg_digest      = %s", HexStr(MakeByteSpan(message_digest)));
                FSDBG("  e' (bytes→secp) = %s", Hex32(e_be));

                // Verify commitment hasn't changed
                std::array<unsigned char, 32> msg_digest_array;
                std::memcpy(msg_digest_array.data(), message_digest.data(), 32);
                const uint256 expected_commitment = ComputeAdaptorCommitment(r_prime, adaptor_point, signing_key, msg_digest_array);
                if (std::memcmp(commitment.begin(), expected_commitment.begin(), 32) != 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "partial: fs/adaptor commitment mismatch (R'/T/Q/m changed)");
                }

                // Compute s' = k + e·x' (mod n) - this is the adaptor pre-signature
                // Uses secp256k1 audited scalar arithmetic primitives (not "custom crypto")
                unsigned char s_prime[32];
                std::memcpy(s_prime, nonce_k.begin(), 32);

                // Multiply challenge by tweaked secret: e·x'
                unsigned char e_times_x[32];
                std::memcpy(e_times_x, tweaked_secret.begin(), 32);
                if (!secp256k1_ec_seckey_tweak_mul(GetSigningContext(), e_times_x, e_be)) {
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(e_times_x, sizeof(e_times_x));
                    memory_cleanse(e_be, sizeof(e_be));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute e·x'");
                }

                // Add: s' = k + e·x'
                if (!secp256k1_ec_seckey_tweak_add(GetSigningContext(), s_prime, e_times_x)) {
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(e_times_x, sizeof(e_times_x));
                    memory_cleanse(e_be, sizeof(e_be));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute s' = k + e·x'");
                }
                memory_cleanse(e_times_x, sizeof(e_times_x));
                memory_cleanse(e_be, sizeof(e_be));

#if TC_FS_DEBUG_SECRETS
                FSDBG("  x' (tweaked sec)= %s", Hex32(tweaked_secret.data()));

                // Verify x'·G = Q_even
                secp256k1_pubkey xG;
                if (secp256k1_ec_pubkey_create(GetSigningContext(), &xG, tweaked_secret.data())) {
                    secp256k1_xonly_pubkey xG_xonly;
                    int xG_parity = 0;
                    secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &xG_xonly, &xG_parity, &xG);
                    unsigned char xG_x[32];
                    secp256k1_xonly_pubkey_serialize(GetSigningContext(), xG_x, &xG_xonly);
                    FSDBG("  [VERIFY] x'·G_x  = %s (parity=%d)", Hex32(xG_x), xG_parity);
                    FSDBG("  [VERIFY] Q_x     = %s", HexXOnly(signing_key));
                    FSDBG("  [VERIFY] x'·G parity should be 0 for BIP-340");
                    if (std::memcmp(xG_x, signing_key.data(), 32) != 0) {
                        FSDBG("  [VERIFY] ⚠ WARNING: x'·G_x ≠ Q_x!");
                    }
                    if (xG_parity != 0) {
                        FSDBG("  [VERIFY] ⚠ WARNING: x'·G has odd parity!");
                    }
                }
#endif
                FSDBG("  s'               = %s", Hex32(s_prime));

                // DEBUG: Verify signature equation s'·G = R' + e·Q
#if TC_FS_DEBUG
                {
                    // Compute s'·G
                    secp256k1_pubkey sG;
                    unsigned char s_prime_tmp[32];
                    std::memcpy(s_prime_tmp, s_prime, 32);
                    if (secp256k1_ec_pubkey_create(GetSigningContext(), &sG, s_prime_tmp)) {

                        // Compute e·Q using pubkey scalar multiplication
                        // Parse Q as a pubkey (use 0x02 prefix for even Y assumption)
                        secp256k1_pubkey Q_pub;
                        unsigned char Q33[33] = {0x02};
                        std::memcpy(Q33 + 1, signing_key.data(), 32);

                        if (secp256k1_ec_pubkey_parse(GetSigningContext(), &Q_pub, Q33, 33)) {
                            unsigned char e_tmp[32];
                            std::memcpy(e_tmp, e_be, 32);

                            // e·Q (this modifies Q_pub in place)
                            if (secp256k1_ec_pubkey_tweak_mul(GetSigningContext(), &Q_pub, e_tmp)) {

                                // Compute R' as pubkey
                                secp256k1_pubkey Rprime_pub;
                                unsigned char Rp33[33] = {0x02};
                                std::memcpy(Rp33 + 1, r_prime.begin(), 32);

                                if (secp256k1_ec_pubkey_parse(GetSigningContext(), &Rprime_pub, Rp33, 33)) {
                                    // R' + e·Q
                                    secp256k1_pubkey RHS;
                                    const secp256k1_pubkey* add_pts[2] = {&Rprime_pub, &Q_pub};

                                    if (secp256k1_ec_pubkey_combine(GetSigningContext(), &RHS, add_pts, 2)) {
                                        // Compare x-only coordinates
                                        secp256k1_xonly_pubkey x_sG, x_rhs;
                                        int p1, p2;
                                        secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &x_sG, &p1, &sG);
                                        secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &x_rhs, &p2, &RHS);

                                        unsigned char sG_x[32], rhs_x[32];
                                        secp256k1_xonly_pubkey_serialize(GetSigningContext(), sG_x, &x_sG);
                                        secp256k1_xonly_pubkey_serialize(GetSigningContext(), rhs_x, &x_rhs);

                                        FSDBG("  [DEBUG] s'·G_x  = %s", Hex32(sG_x));
                                        FSDBG("  [DEBUG] R'+e·Q_x= %s", Hex32(rhs_x));

                                        if (std::memcmp(sG_x, rhs_x, 32) != 0) {
                                            FSDBG("  [DEBUG] ⚠ EQUATION MISMATCH: s'·G ≠ R' + e·Q");
                                        } else {
                                            FSDBG("  [DEBUG] ✓ Equation verified: s'·G = R' + e·Q");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    memory_cleanse(s_prime_tmp, sizeof(s_prime_tmp));
                }
#endif

                // Don't clear nonce_k and tweaked_secret yet - still needed for verification!

                // Verify adaptor pre-signature by checking k·G + T = R'
                // Since R was normalized to even Y in prepare(), k is already adjusted
                // Simple verification: R + T should equal R'

                // Compute R = k·G (k was already normalized in prepare() for even-Y R)
                secp256k1_pubkey R_check;
                if (!secp256k1_ec_pubkey_create(GetSigningContext(), &R_check, nonce_k.data())) {
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute R for verification");
                }

                // Parse T
                unsigned char T_ser33[33];
                T_ser33[0] = 0x02;  // Even y-coordinate
                std::memcpy(T_ser33 + 1, adaptor_point.data(), 32);
                secp256k1_pubkey T_full;
                if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &T_full, T_ser33, 33)) {
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(T_ser33, sizeof(T_ser33));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse T");
                }
                memory_cleanse(T_ser33, sizeof(T_ser33));

                // Compute R + T (should equal R')
                const secp256k1_pubkey* to_add[2] = {&R_check, &T_full};
                secp256k1_pubkey R_plus_T;
                if (!secp256k1_ec_pubkey_combine(GetSigningContext(), &R_plus_T, to_add, 2)) {
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute R + T");
                }

                // Extract x-only from R + T
                secp256k1_xonly_pubkey R_plus_T_xonly;
                int parity;
                if (!secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &R_plus_T_xonly, &parity, &R_plus_T)) {
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract x-only R + T");
                }

                // Verify R + T equals R' (compare x-coordinates)
                unsigned char r_plus_t_bytes[32];
                secp256k1_xonly_pubkey_serialize(GetSigningContext(), r_plus_t_bytes, &R_plus_T_xonly);

                FSDBG("  (R + T)_x        = %s", Hex32(r_plus_t_bytes));
                FSDBG("  (R + T) parity   = %d", parity);

                if (std::memcmp(r_plus_t_bytes, r_prime.begin(), 32) != 0) {
                    // Log error BEFORE cleansing buffers so hex values are readable
                    std::string error_msg = strprintf("Verification failed: (R+T)_x=%s par=%d vs R'_x=%s",
                                                     Hex32(r_plus_t_bytes), parity, HexXOnly(r_prime));
                    memory_cleanse(s_prime, sizeof(s_prime));
                    memory_cleanse(r_plus_t_bytes, sizeof(r_plus_t_bytes));
                    memory_cleanse(nonce_k.data(), nonce_k.size());
                    memory_cleanse(tweaked_secret.data(), tweaked_secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, error_msg);
                }
                memory_cleanse(r_plus_t_bytes, sizeof(r_plus_t_bytes));

                // Verification passed, clear sensitive secrets
                memory_cleanse(nonce_k.data(), nonce_k.size());
                memory_cleanse(tweaked_secret.data(), tweaked_secret.size());

                // Build pre-signature [R' || s']
                unsigned char pre_sig64[64];
                std::memcpy(pre_sig64, r_prime.begin(), 32);
                std::memcpy(pre_sig64 + 32, s_prime, 32);
                memory_cleanse(s_prime, sizeof(s_prime));

                // Write adaptor_sig to PSBT
                ReplaceFsEntry(input.m_proprietary,
                               wallet::fairsign::Identifier(),
                               0,
                               "adaptor_sig",
                               std::span<const unsigned char>(pre_sig64, 64));

                // Update state in wallet (lock again)
                {
                    LOCK(pwallet->cs_wallet);
                    FairSignInputState* state_ptr = pwallet->GetMutableFairSignInputState(txid, idx);
                    if (state_ptr) {
                        std::memcpy(state_ptr->pre_sig.data(), pre_sig64, 64);
                        state_ptr->has_partial = true;
                        // Clear n=1 ephemeral secrets (but keep r_nonce for complete())
                        state_ptr->nonce_secret.reset();
                        state_ptr->tweaked_secret.reset();
                        // Keep r_nonce and r_prime for complete() step
                    }
                }

                // Zero pre-signature from stack (already copied to PSBT and state)
                memory_cleanse(pre_sig64, sizeof(pre_sig64));

                ++signed_inputs;
            }

            if (signed_inputs == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No prepared adaptor inputs found");
            }

            DataStream ssTx{};
            ssTx << psbt;
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("complete", false);
            return result;
        }
    );
}

RPCHelpMan adaptor_commit_final()
{
    return RPCHelpMan(
        "adaptor.commit_final",
        "Compute final signature commitments for lock-step reveal protocol (FINANCING_PRIMITIVES.md §4.5). "
        "This prevents 'free option' attacks by ensuring neither party can see the counterparty's final signature before revealing their own. "
        "Returns commitments that should be exchanged with the counterparty before calling adaptor.complete.",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT with adaptor partials"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "commitments", "Per-input commitments to final signatures",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "index", "Input index"},
                                {RPCResult::Type::STR_HEX, "commitment", "SHA256(final_sig_64) commitment"},
                            }
                        }
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("adaptor.commit_final", "\"psbt_base64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            PartiallySignedTransaction psbt;
            std::string error;
            if (!DecodeBase64PSBT(psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            if (!psbt.tx) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");
            }

            const uint256 txid = psbt.tx->GetHash();

            UniValue commitments_arr(UniValue::VARR);

            for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                FairSignInputState state;
                if (!pwallet->GetFairSignInputState(txid, idx, state)) {
                    continue;  // Skip inputs we don't control
                }

                if (!state.has_partial) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Input %u missing adaptor partial signature. Call adaptor.partial first.", idx));
                }

                if (!state.adaptor_secret) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Input %u missing local adaptor secret. Cannot compute final signature for commitment.", idx));
                }

                // Compute final signature: s = s' + t
                unsigned char final_sig64[64];
                std::memcpy(final_sig64, state.pre_sig.data(), 32);  // R'_x

                unsigned char s_final[32];
                std::memcpy(s_final, state.pre_sig.data() + 32, 32);  // s'

                // Add adaptor secret: s = s' + t
                std::array<unsigned char, 32> secret_normalized = *state.adaptor_secret;
                if (!secp256k1_ec_seckey_tweak_add(GetSigningContext(), s_final, secret_normalized.data())) {
                    memory_cleanse(s_final, sizeof(s_final));
                    memory_cleanse(final_sig64, sizeof(final_sig64));
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Failed to compute final signature for input %u", idx));
                }

                std::memcpy(final_sig64 + 32, s_final, 32);
                memory_cleanse(s_final, sizeof(s_final));

                // Compute commitment: H(final_sig_64)
                uint256 commitment = Hash(MakeByteSpan(final_sig64));
                memory_cleanse(final_sig64, sizeof(final_sig64));

                // Store commitment in session state
                {
                    LOCK(pwallet->cs_wallet);
                    FairSignInputState* mutable_state = pwallet->GetMutableFairSignInputState(txid, idx);
                    if (mutable_state) {
                        mutable_state->final_sig_commitment = commitment;
                    }
                }

                // Return commitment for exchange
                UniValue commitment_obj(UniValue::VOBJ);
                commitment_obj.pushKV("index", idx);
                commitment_obj.pushKV("commitment", commitment.GetHex());
                commitments_arr.push_back(commitment_obj);
            }

            if (commitments_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "No wallet-controlled inputs with adaptor secrets found. Cannot generate commitments.");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("commitments", commitments_arr);
            return result;
        }
    );
}

RPCHelpMan adaptor_complete()
{
    return RPCHelpMan(
        "adaptor.complete",
        "Finalize adaptor signatures using revealed adaptor secrets. "
        "SECURITY: Enforces lock-step reveal protocol by requiring peer_commitments to prevent free option attacks (FINANCING_PRIMITIVES.md §4.5). "
        "Pass empty array [] for peer_commitments ONLY in automated Phase 4 cosign.adaptor_roundtrip flows.",
        std::vector<RPCArg>{
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT"},
            {"secrets", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Adaptor secrets keyed by input index",
                std::vector<RPCArg>{
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                        std::vector<RPCArg>{
                            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index"},
                            {"secret", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Adaptor secret (32-byte hex)"},
                        }
                    }
                }
            },
            {"peer_commitments", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Commitments from counterparty for lock-step reveal verification",
                std::vector<RPCArg>{
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                        std::vector<RPCArg>{
                            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index"},
                            {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "SHA256(final_sig_64) commitment from peer"},
                        }
                    }
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Updated PSBT"},
                {RPCResult::Type::BOOL, "complete", "Whether all inputs now have final taproot signatures"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Final transaction hex (present when complete=true and extraction succeeded)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (present when hex is returned)"},
            }
        },
        RPCExamples{
            HelpExampleCli("adaptor.prepare", "\"psbt_base64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            PartiallySignedTransaction psbt;
            std::string error;
            if (!DecodeBase64PSBT(psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            if (!psbt.tx) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");
            }

            std::map<size_t, std::array<unsigned char, 32>> explicit_secrets;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                const UniValue& secrets_arr = request.params[1];
                if (!secrets_arr.isArray()) {
                    throw JSONRPCError(RPC_TYPE_ERROR, "Expected array for secrets parameter");
                }
                for (unsigned int i = 0; i < secrets_arr.size(); ++i) {
                    const UniValue& elem = secrets_arr[i].get_obj();
                    size_t index = elem.find_value("index").getInt<size_t>();
                    if (index >= psbt.inputs.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Adaptor secret index out of range");
                    }
                    const std::string secret_hex = elem.find_value("secret").get_str();
                    explicit_secrets.emplace(index, HexToArray(secret_hex));
                }
            }

            // Parse and store peer commitments for lock-step reveal verification
            // MANDATORY by default (FINANCING_PRIMITIVES.md §4.5) to prevent free-option attacks
            std::map<size_t, uint256> peer_commitments;
            bool enforce_commit_reveal = true;  // Default: ENFORCE

            if (request.params.size() > 2 && !request.params[2].isNull()) {
                const UniValue& commitments_arr = request.params[2];
                if (!commitments_arr.isArray()) {
                    throw JSONRPCError(RPC_TYPE_ERROR, "Expected array for peer_commitments parameter");
                }

                // Allow explicit empty array [] to bypass (for Phase 4 cosign.adaptor_roundtrip only)
                if (commitments_arr.size() == 0) {
                    pwallet->WalletLogPrintf("WARNING: Commit-reveal protocol bypassed (peer_commitments=[]). "
                                             "This is UNSAFE for manual workflows and should only be used by automated "
                                             "Phase 4 cosign.adaptor_roundtrip.\n");
                    enforce_commit_reveal = false;
                } else {
                    // Parse commitments
                    for (unsigned int i = 0; i < commitments_arr.size(); ++i) {
                        const UniValue& elem = commitments_arr[i].get_obj();
                        size_t index = elem.find_value("index").getInt<size_t>();
                        if (index >= psbt.inputs.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Commitment index out of range");
                        }
                        const std::string commitment_hex = elem.find_value("commitment").get_str();
                        auto commitment_opt = uint256::FromHex(commitment_hex);
                        if (!commitment_opt) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment hex string");
                        }
                        peer_commitments.emplace(index, *commitment_opt);
                    }
                }
            } else {
                // No peer_commitments parameter provided - reject by default
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Missing required peer_commitments parameter. "
                    "The lock-step reveal protocol is mandatory to prevent free-option attacks (FINANCING_PRIMITIVES.md §4.5). "
                    "Obtain commitments from counterparty via adaptor.commit_final before calling adaptor.complete. "
                    "For automated Phase 4 flows only: pass empty array [] to bypass.");
            }

            const uint256 txid = psbt.tx->GetHash();

            size_t finalized_inputs{0};
            for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                PSBTInput& input = psbt.inputs[idx];

                // CRITICAL: Extract vault intent from PSBT first (survives PSBT merges/updates)
                auto vault_intent = wallet::ExtractVaultIntent(input);
                if (vault_intent) {
                }

                FairSignInputState state;
                if (!pwallet->GetFairSignInputState(txid, idx, state)) {
                    // State not found - this wallet didn't prepare this input
                    // If vault intent exists in PSBT, we can still enforce it
                    if (!vault_intent) {
                        continue;  // Skip inputs we didn't prepare and have no intent
                    }
                    // Use the PSBT intent even without state (for counterparty signing)
                    continue;  // For now, skip - this is the counterparty's input
                }

                // Prefer intent from stored state (most reliable), fallback to PSBT
                if (vault_intent && !state.vault_intent_purpose.has_value()) {
                    // State exists but no intent stored - use PSBT intent
                    state.vault_intent_purpose = vault_intent->leaf_purpose;
                }

                if (!state.has_partial) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Adaptor state for input %u is missing a partial signature", idx));
                }

                std::array<unsigned char, 32> secret{};
                bool from_state = false;
                (void)from_state;  // Reserved for future use
                if (const auto it = explicit_secrets.find(idx); it != explicit_secrets.end()) {
                    secret = it->second;
                    FSDBG("  Using explicit adaptor secret");
                } else if (state.adaptor_secret) {
                    secret = *state.adaptor_secret;
                    from_state = true;
                    FSDBG("  Using stored adaptor secret from prepare()");
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Adaptor secret not provided for input %u", idx));
                }

#if TC_FS_DEBUG_SECRETS
                FSDBG("  t (pre-norm)     = %s", Hex32(secret.data()));
                // Check parity before normalization
                secp256k1_pubkey T_before;
                if (secp256k1_ec_pubkey_create(GetSigningContext(), &T_before, secret.data())) {
                    secp256k1_xonly_pubkey T_xo;
                    int par_before = 0;
                    secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &T_xo, &par_before, &T_before);
                    FSDBG("  t·G parity (pre) = %d", par_before);
                }
#endif

                // Normalize secret to match even-Y lift of adaptor_point used in nonce_process
                if (!NormalizeAdaptorSecretToAdaptorX(secret, state.adaptor_point)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Adaptor secret does not match adaptor point");
                }

#if TC_FS_DEBUG_SECRETS
                FSDBG("  t (post-norm)    = %s", Hex32(secret.data()));
                // Verify normalized secret
                secp256k1_pubkey T_after;
                if (secp256k1_ec_pubkey_create(GetSigningContext(), &T_after, secret.data())) {
                    secp256k1_xonly_pubkey T_xo;
                    int par_after = 0;
                    secp256k1_xonly_pubkey_from_pubkey(GetSigningContext(), &T_xo, &par_after, &T_after);
                    unsigned char t_x[32];
                    secp256k1_xonly_pubkey_serialize(GetSigningContext(), t_x, &T_xo);
                    FSDBG("  t·G parity (post)= %d (should be 0)", par_after);
                    FSDBG("  t·G_x            = %s", Hex32(t_x));
                    FSDBG("  T_x (from state) = %s", HexXOnly(state.adaptor_point));
                    FSDBG("  Match? %s", std::memcmp(t_x, state.adaptor_point.data(), 32) == 0 ? "YES" : "NO");
                }
#endif

                FSDBG("complete: idx=%u", (unsigned)idx);
                FSDBG("  msg_digest(state)= %s", HexStr(MakeByteSpan(state.message_digest)));

                // Recompute message from current PSBT and compare
                PrecomputedTransactionData txdata_now = PrecomputePSBTData(psbt);
                ScriptExecutionData execdata;
                execdata.m_annex_init = true;
                execdata.m_annex_present = false;
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = 0xFFFFFFFF;  // No OP_CODESEPARATOR

                // For script-path spends, set tapleaf hash
                if (!state.is_keypath && state.tapleaf_hash.has_value()) {
                    execdata.m_tapleaf_hash_init = true;
                    execdata.m_tapleaf_hash = *state.tapleaf_hash;
                }

                // BIP341/342: Use the same SigVersion as prepare (TAPROOT for keypath, TAPSCRIPT for script-path)
                const SigVersion sig_version = state.is_keypath ? SigVersion::TAPROOT : SigVersion::TAPSCRIPT;
                uint256 msg_now;
                if (!SignatureHashSchnorr(msg_now, execdata, *psbt.tx, idx,
                        input.sighash_type ? (uint8_t)*input.sighash_type : (uint8_t)SIGHASH_DEFAULT,
                        sig_version, txdata_now, MissingDataBehavior::FAIL)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "complete: failed to recompute sighash");
                }

                FSDBG("  msg_digest(now)  = %s", HexU256(msg_now));
                if (std::memcmp(state.message_digest.data(), msg_now.begin(), 32) != 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "complete: PSBT mutated; message digest changed");
                }

                // n=1 Adaptor Complete: s = s' + t (mod n)
                // state.pre_sig contains [R' || s'] from partial step
                // BIP-340 final signature uses (R' || s) where R' has EVEN Y (enforced in prepare())
                // Math: s·G = (k + e'·x' + t)·G = R + e'·Q + T = R' + e'·Q
                // Verifier lifts R'_x to even Y, uses same R' → verification succeeds ✓
                unsigned char final_sig64[64];

                // Step 1: Copy R'_x from pre_sig (first 32 bytes)
                std::memcpy(final_sig64, state.pre_sig.data(), 32);

                FSDBG("  R'_x (final sig) = %s", Hex32(state.pre_sig.data()));
                FSDBG("  R' parity (y)    = %d (should always be 0)", state.nonce_parity);
                FSDBG("  T_x              = %s", HexXOnly(state.adaptor_point));
                FSDBG("  Q                = %s", HexXOnly(state.signing_key));
                FSDBG("  s'               = %s", Hex32(state.pre_sig.data() + 32));
                FSDBG("  t (adaptor)      = %s", Hex32(secret.data()));

                // Step 2: Compute s = s' + t
                unsigned char s_final[32];
                std::memcpy(s_final, state.pre_sig.data() + 32, 32);  // s'

                if (!secp256k1_ec_seckey_tweak_add(GetSigningContext(), s_final, secret.data())) {
                    memory_cleanse(s_final, sizeof(s_final));
                    memory_cleanse(secret.data(), secret.size());
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute s = s' + t");
                }

                FSDBG("  s (final)        = %s", Hex32(s_final));

                // Verify invariant: R' must have even Y (enforced in prepare() by nonce retry)
                if (state.nonce_parity != 0) {
                    memory_cleanse(s_final, sizeof(s_final));
                    memory_cleanse(secret.data(), secret.size());
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("INTERNAL ERROR: R' has odd parity %d (should be 0)", state.nonce_parity));
                }

                // Step 3: Copy s into final signature (no negation needed; R' is even)
                std::memcpy(final_sig64 + 32, s_final, 32);

                FSDBG("  Final sig: (R'_x || s)");

                memory_cleanse(s_final, sizeof(s_final));

                // Verify final signature against Q
                CTxOut utxo;
                if (!psbt.GetInputUTXO(utxo, idx)) {
                    memory_cleanse(final_sig64, sizeof(final_sig64));
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing UTXO information for input %u", idx));
                }

                XOnlyPubKey verify_key = state.signing_key;
                if (state.is_keypath) {
                    if (!ExtractWitnessTaprootKey(utxo.scriptPubKey, verify_key)) {
                        memory_cleanse(final_sig64, sizeof(final_sig64));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract Taproot output key");
                    }
                }

                FSDBG("  Q (verify key)   = %s", HexXOnly(verify_key));
                FSDBG("  Verifying: schnorrsig_verify(sig=(R'||s), msg, Q)");

                secp256k1_xonly_pubkey Q_x;
                if (!secp256k1_xonly_pubkey_parse(GetSigningContext(), &Q_x, verify_key.data())) {
                    memory_cleanse(final_sig64, sizeof(final_sig64));
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse taproot signing pubkey");
                }

                if (!secp256k1_schnorrsig_verify(
                        GetSigningContext(),
                        final_sig64,
                        state.message_digest.data(),
                        32,
                        &Q_x)) {
                    // SECURITY: Log full details server-side ONLY; never expose secrets to RPC client
                    // (FINDING 3: prevents adaptor secret leakage that would break atomicity)
                    pwallet->WalletLogPrintf(
                        "ADAPTOR_VERIFY_FAILED for input %u:\n"
                        "  R'=%s parity=%d\n"
                        "  Q=%s\n"
                        "  msg=%s\n"
                        "  s'=%s\n"
                        "  t=%s\n"
                        "  s(final)=%s\n",
                        (unsigned)idx,
                        Hex32(final_sig64),
                        state.nonce_parity,
                        HexXOnly(verify_key),
                        HexStr(MakeByteSpan(state.message_digest)),
                        Hex32(state.pre_sig.data() + 32),
                        Hex32(secret.data()),
                        Hex32(final_sig64 + 32));

                    memory_cleanse(final_sig64, sizeof(final_sig64));

                    // User-facing error: REDACTED (no secrets)
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Final signature verification failed for input %u. "
                                  "Check debug.log for detailed diagnostics. "
                                  "This may indicate PSBT mutation or incorrect adaptor secret.",
                                  (unsigned)idx));
                }

                FSDBG("  ✓ Verification PASSED!");

                // COMMIT-REVEAL PROTOCOL: Verify peer commitment if provided (FINANCING_PRIMITIVES.md §4.5)
                if (enforce_commit_reveal) {
                    auto peer_commit_it = peer_commitments.find(idx);
                    if (peer_commit_it == peer_commitments.end()) {
                        memory_cleanse(final_sig64, sizeof(final_sig64));
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Lock-step reveal protocol requires peer commitment for input %u but none provided. "
                                      "Ensure counterparty's adaptor.commit_final output includes this input index.",
                                      idx));
                    }

                    // Compute actual commitment from final signature
                    uint256 actual_commitment = Hash(MakeByteSpan(final_sig64));

                    // Verify it matches the peer's commitment
                    if (actual_commitment != peer_commit_it->second) {
                        memory_cleanse(final_sig64, sizeof(final_sig64));
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("COMMITMENT MISMATCH for input %u! "
                                      "Peer commitment: %s, Actual: %s. "
                                      "Counterparty may have provided incorrect commitment or adaptor secret. "
                                      "DO NOT REVEAL YOUR FINAL SIGNATURE.",
                                      idx,
                                      peer_commit_it->second.GetHex(),
                                      actual_commitment.GetHex()));
                    }

                    FSDBG("  ✓ Commitment verification PASSED!");
                }

                SmallVectorU8 final_signature(final_sig64, final_sig64 + 64);

                if (state.is_keypath) {
                    input.m_tap_key_sig.assign(final_signature.begin(), final_signature.end());
                } else {
                    // Script-path spend: build full witness stack [sig, script, control_block]
                    input.m_tap_key_sig.clear();

                    if (!state.tapleaf_hash.has_value()) {
                        memory_cleanse(final_sig64, sizeof(final_sig64));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Adaptor state missing tapleaf hash for script-path spend");
                    }

                    std::vector<unsigned char> leaf_script = state.tapleaf_script;
                    std::vector<unsigned char> control_block = state.tapleaf_control_block;
                    std::optional<int> leaf_version;

                    if (!state.has_tapleaf_witness || leaf_script.empty() || control_block.empty()) {
                        leaf_script.clear();
                        control_block.clear();
                        for (const auto& [script_key, control_blocks] : input.m_tap_scripts) {
                            const auto& script_bytes = script_key.first;
                            const int leaf_ver = script_key.second;
                            const uint256 leaf_hash = ComputeTapleafHash(
                                leaf_ver,
                                std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));
                            if (leaf_hash == *state.tapleaf_hash) {
                                leaf_script = script_bytes;
                                leaf_version = leaf_ver;
                                if (!control_blocks.empty()) {
                                    const auto& cb = *control_blocks.begin();
                                    control_block.assign(cb.begin(), cb.end());
                                }
                                break;
                            }
                        }
                        if (!leaf_script.empty() && !control_block.empty()) {
                            state.tapleaf_script = leaf_script;
                            state.tapleaf_control_block = control_block;
                            state.has_tapleaf_witness = true;
                        }
                    } else {
                        // Infer leaf version from cached control block or PSBT tap_scripts.
                        if (!control_block.empty()) {
                            leaf_version = control_block.front() & TAPROOT_LEAF_MASK;
                        }
                        if (!leaf_version.has_value()) {
                            for (const auto& [script_key, _] : input.m_tap_scripts) {
                                if (script_key.first == leaf_script) {
                                    leaf_version = script_key.second;
                                    break;
                                }
                            }
                        }
                    }

                    // Final fallback: if PSBT already contains a final_script_witness from the
                    // counterparty (e.g., first party completed before we prepared), recover
                    // the leaf script/control block directly from the witness stack.
                    if ((leaf_script.empty() || control_block.empty()) &&
                        !input.final_script_witness.IsNull() && input.final_script_witness.stack.size() >= 2) {
                        const auto& wit = input.final_script_witness.stack;
                        leaf_script = wit[wit.size() - 2];
                        control_block = wit[wit.size() - 1];
                        leaf_version = static_cast<int>(control_block.front() & TAPROOT_LEAF_MASK);
                        // If tapleaf_hash was not cached, compute it now from the script we recovered.
                        if (!state.tapleaf_hash.has_value()) {
                            const uint256 lhash = ComputeTapleafHash(*leaf_version,
                                std::span<const unsigned char>(leaf_script.data(), leaf_script.size()));
                            state.tapleaf_hash = lhash;
                        }
                    }

                    // CRITICAL: If vault intent exists (from state or PSBT), ENFORCE it
                    // Use state-stored leaf metadata if available, otherwise use PSBT vault_intent
                    if (state.vault_intent_purpose.has_value() || vault_intent.has_value()) {
                        std::string intent_purpose = state.vault_intent_purpose.value_or(vault_intent->leaf_purpose);

                        // Prefer state-stored leaf metadata, fallback to PSBT vault_intent
                        if (state.tapleaf_hash.has_value() && !state.tapleaf_script.empty() && !state.tapleaf_control_block.empty()) {
                            leaf_script = state.tapleaf_script;
                            control_block = state.tapleaf_control_block;
                            // Infer leaf version from control block
                            if (!control_block.empty()) {
                                leaf_version = control_block.front() & TAPROOT_LEAF_MASK;
                            }
                        } else if (vault_intent.has_value()) {
                            // Fallback: reconstruct leaf from vault metadata using intent
                            CTxOut utxo;
                            if (psbt.GetInputUTXO(utxo, idx)) {
                                // Look up vault metadata
                                std::optional<wallet::VaultMetadata> vault_meta;
                                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(utxo.scriptPubKey);
                                if (managers.empty()) {
                                    managers = pwallet->GetAllScriptPubKeyMans();
                                }
                                for (ScriptPubKeyMan* manager : managers) {
                                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                                    if (!desc_spkm) continue;
                                    auto meta = desc_spkm->GetVaultMetadata(utxo.scriptPubKey);
                                    if (meta) {
                                        vault_meta = meta;
                                        break;
                                    }
                                }

                                if (vault_meta) {
                                    auto selected_leaf = wallet::SelectLeafByIntent(*vault_meta, *vault_intent);
                                    if (selected_leaf) {
                                        leaf_script = selected_leaf->script;
                                        control_block = vault_intent->control_block;
                                        if (!control_block.empty()) {
                                            leaf_version = control_block.front() & TAPROOT_LEAF_MASK;
                                        }
                                    } else {
                                        throw JSONRPCError(RPC_WALLET_ERROR,
                                            strprintf("adaptor.complete: Could not find leaf matching intent for input %u", idx));
                                    }
                                } else {
                                    throw JSONRPCError(RPC_WALLET_ERROR,
                                        strprintf("adaptor.complete: Could not find vault metadata for input %u", idx));
                                }
                            } else {
                                throw JSONRPCError(RPC_WALLET_ERROR,
                                    strprintf("adaptor.complete: Could not get UTXO for input %u", idx));
                            }
                        } else {
                            throw JSONRPCError(RPC_WALLET_ERROR,
                                strprintf("adaptor.complete: Vault intent purpose '%s' present but no leaf metadata available for input %u",
                                         intent_purpose, idx));
                        }
                    }
                    // Fallback: Prefer cooperative leaf (multi-sig) if multiple leaves are present and no intent.
                    // This should ONLY be used for non-vault inputs (spot transactions).
                    // For vault inputs, adaptor.prepare should have already rejected missing intent.
                    else if (leaf_script.empty() || control_block.empty()) {
                        // CRITICAL: Check if this is a vault input - if so, fail instead of using heuristics
                        CTxOut utxo;
                        if (psbt.GetInputUTXO(utxo, idx)) {
                            std::optional<wallet::VaultMetadata> vault_meta;
                            std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(utxo.scriptPubKey);
                            if (managers.empty()) {
                                managers = pwallet->GetAllScriptPubKeyMans();
                            }
                            for (ScriptPubKeyMan* manager : managers) {
                                auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                                if (!desc_spkm) continue;
                                auto meta = desc_spkm->GetVaultMetadata(utxo.scriptPubKey);
                                if (meta) {
                                    vault_meta = meta;
                                    break;
                                }
                            }

                            if (vault_meta) {
                                throw JSONRPCError(RPC_WALLET_ERROR,
                                    strprintf("adaptor.complete: Input %u is a vault but has no stored intent. "
                                             "This indicates stale session state. Re-run adaptor.prepare with intent-embedded PSBT.", idx));
                            }
                        }
                    } else {
                        // Scan all available leaves and select a candidate with >1 signers that includes our key.
                        std::optional<std::vector<unsigned char>> coop_script;
                        std::optional<std::vector<unsigned char>> coop_control;
                        std::optional<int> coop_ver;
                        for (const auto& [script_key, cbs] : input.m_tap_scripts) {
                            const auto& sbytes = script_key.first;
                            const int ver = script_key.second;
                            auto signers = ExtractTaprootScriptSigners(sbytes);
                            if (signers.size() > 1) {
                                // Ensure our signing key participates
                                if (std::find(signers.begin(), signers.end(), state.signing_key) != signers.end()) {
                                    coop_script = sbytes;
                                    coop_ver = ver;
                                    if (!cbs.empty()) {
                                        const auto& cb = *cbs.begin();
                                        coop_control = std::vector<unsigned char>(cb.begin(), cb.end());
                                    }
                                    break;
                                }
                            }
                        }
                        if (coop_script && coop_control && coop_ver) {
                            leaf_script = *coop_script;
                            control_block = *coop_control;
                            leaf_version = *coop_ver;
                            const uint256 lhash = ComputeTapleafHash(*leaf_version,
                                std::span<const unsigned char>(leaf_script.data(), leaf_script.size()));
                            state.tapleaf_hash = lhash;
                            state.tapleaf_script = leaf_script;
                            state.tapleaf_control_block = control_block;
                            state.has_tapleaf_witness = true;
                        }
                    }

                    if (leaf_script.empty() || control_block.empty()) {
                        memory_cleanse(final_sig64, sizeof(final_sig64));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate tapleaf script/control block for script-path adaptor completion");
                    }

                    if (!leaf_version.has_value()) {
                        leaf_version = control_block.front() & TAPROOT_LEAF_MASK;
                    }

                    std::vector<XOnlyPubKey> tapleaf_signers = state.tapleaf_signers;
                    if (tapleaf_signers.empty()) {
                        tapleaf_signers = ExtractTaprootScriptSigners(leaf_script);
                        state.tapleaf_signers = tapleaf_signers;
                    }

                    // Enforce cooperative leaf for IM vaults when registry metadata is available.
                    {
                        auto get_vault_metadata_for_script = [&](const CScript& spk) -> std::optional<wallet::VaultMetadata> {
                            std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(spk);
                            if (managers.empty()) {
                                managers = pwallet->GetAllScriptPubKeyMans();
                            }
                            for (ScriptPubKeyMan* manager : managers) {
                                auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                                if (!desc_spkm) continue;
                                auto meta = desc_spkm->GetVaultMetadata(spk);
                                if (meta) return meta;
                            }
                            return std::nullopt;
                        };
                        if (auto vault_meta = get_vault_metadata_for_script(utxo.scriptPubKey)) {
                            const VaultLeafDescriptor* matched = nullptr;
                            for (const auto& leaf : vault_meta->leaves) {
                                if (leaf.script == leaf_script) { matched = &leaf; break; }
                            }
                            if (matched && matched->purpose.find("coop") == std::string::npos && matched->purpose != "cooperative") {
                                memory_cleanse(final_sig64, sizeof(final_sig64));
                                throw JSONRPCError(RPC_WALLET_ERROR,
                                    "adaptor.complete: refusing to finalize IM vault with non-cooperative leaf");
                            }
                        }
                    }

                    int signer_slot = state.tapleaf_signer_slot;
                    if (signer_slot < 0 || signer_slot >= static_cast<int>(tapleaf_signers.size())) {
                        const auto signer_it = std::find(tapleaf_signers.begin(), tapleaf_signers.end(), state.signing_key);
                        if (signer_it != tapleaf_signers.end()) {
                            signer_slot = static_cast<int>(std::distance(tapleaf_signers.begin(), signer_it));
                        }
                    }

                    if (signer_slot < 0 || signer_slot >= static_cast<int>(tapleaf_signers.size())) {
                        std::string signers_hex;
                        signers_hex.reserve(tapleaf_signers.size() * 67);
                        for (size_t i = 0; i < tapleaf_signers.size(); ++i) {
                            signers_hex += HexXOnly(tapleaf_signers[i]);
                            if (i + 1 < tapleaf_signers.size()) {
                                signers_hex += ",";
                            }
                        }
                        pwallet->WalletLogPrintf(
                            "adaptor.complete: signing key mismatch idx=%u key=%s slot=%d signers=[%s]\n",
                            (unsigned)idx,
                            HexXOnly(state.signing_key),
                            signer_slot,
                            signers_hex);
                        memory_cleanse(final_sig64, sizeof(final_sig64));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Adaptor state signing key not found in tapleaf script");
                    }
                    const size_t our_slot = static_cast<size_t>(signer_slot);

                    const uint256 leaf_hash = *state.tapleaf_hash;
                    const uint256 msg_digest_u256(std::span<const unsigned char>(state.message_digest.data(), state.message_digest.size()));
                    std::map<size_t, std::vector<unsigned char>> slot_signatures;

                    // Preserve any taproot script signatures already recorded in the PSBT.
                    for (const auto& [pubkey_leaf, sig_bytes] : input.m_tap_script_sigs) {
                        if (pubkey_leaf.second != leaf_hash) continue;
                        const auto sig_slot = std::find(tapleaf_signers.begin(), tapleaf_signers.end(), pubkey_leaf.first);
                        if (sig_slot == tapleaf_signers.end()) continue;
                        slot_signatures.emplace(std::distance(tapleaf_signers.begin(), sig_slot), sig_bytes);
                    }

                    // Attempt to recover signatures from an existing final_script_witness (pre-fix PSBTs).
                    if (!input.final_script_witness.IsNull() && input.final_script_witness.stack.size() >= 2) {
                        const auto& witness_stack = input.final_script_witness.stack;
                        const auto& existing_script = witness_stack[witness_stack.size() - 2];
                        const auto& existing_control = witness_stack.back();
                        if (existing_script == leaf_script && existing_control == control_block) {
                            for (size_t i = 0; i + 2 < witness_stack.size(); ++i) {
                                const auto& candidate_sig = witness_stack[i];
                                if (candidate_sig.size() != 64) continue;
                                for (size_t slot = 0; slot < tapleaf_signers.size(); ++slot) {
                                    if (slot_signatures.count(slot)) continue;
                                    if (tapleaf_signers[slot].VerifySchnorr(msg_digest_u256, candidate_sig)) {
                                        slot_signatures.emplace(slot, candidate_sig);
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Record our freshly produced signature.
                    slot_signatures[our_slot] = std::vector<unsigned char>(final_signature.begin(), final_signature.end());

                    // Keep PSBT taproot metadata in sync.
                    {
                        std::pair<std::vector<unsigned char>, int> script_key{leaf_script, *leaf_version};
                        auto& cb_set = input.m_tap_scripts[script_key];
                        cb_set.insert(control_block);
                    }
                    for (size_t slot = 0; slot < tapleaf_signers.size(); ++slot) {
                        const auto it_sig = slot_signatures.find(slot);
                        if (it_sig == slot_signatures.end()) continue;
                        input.m_tap_script_sigs[std::make_pair(tapleaf_signers[slot], leaf_hash)] = it_sig->second;
                    }
                    input.m_tap_key_sig.clear();

                    // Build the final witness stack ONLY if we have all required signatures.
                    // This prevents marking the input as "finalized" prematurely, which would
                    // cause m_tap_scripts to be cleared during PSBT serialization.
                    if (slot_signatures.size() == tapleaf_signers.size()) {
                        std::vector<std::vector<unsigned char>> witness_stack;
                        witness_stack.reserve(slot_signatures.size() + 2);
                        for (int slot = static_cast<int>(tapleaf_signers.size()) - 1; slot >= 0; --slot) {
                            const auto it_sig = slot_signatures.find(static_cast<size_t>(slot));
                            if (it_sig != slot_signatures.end()) {
                                witness_stack.push_back(it_sig->second);
                            }
                        }
                        witness_stack.push_back(leaf_script);
                        witness_stack.push_back(control_block);
                        input.final_script_witness.stack = std::move(witness_stack);
                    }

                    state.tapleaf_script = leaf_script;
                    state.tapleaf_control_block = control_block;
                    state.has_tapleaf_witness = true;
                    state.tapleaf_signers = tapleaf_signers;
                    state.tapleaf_signer_slot = static_cast<int>(our_slot);
                }

                // Zero final signature from stack (already copied to PSBT)
                memory_cleanse(final_sig64, sizeof(final_sig64));

                state.adaptor_secret = secret;
                pwallet->SetFairSignInputState(txid, idx, std::move(state));

                // Zero secret from local variable (already stored in state)
                memory_cleanse(secret.data(), secret.size());

                ++finalized_inputs;
            }

            if (finalized_inputs == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No adaptor states found for completion");
            }

            // Unlock UTXOs now that ceremony is complete
            {
                LOCK(pwallet->cs_wallet);
                pwallet->UnlockFairSignUTXOs(txid);
            }

            PartiallySignedTransaction finalized_psbt = psbt;
            bool complete_flag = FinalizePSBT(finalized_psbt);

            // Return the ORIGINAL psbt (with m_tap_scripts preserved), not the finalized copy
            // The finalized copy was only used to check completeness
            DataStream ssTx{};
            ssTx << psbt;  // CHANGED: Return original psbt, not finalized_psbt
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("complete", complete_flag);
            if (complete_flag) {
                PartiallySignedTransaction extract_psbt = finalized_psbt;
                CMutableTransaction final_mtx;
                if (FinalizeAndExtractPSBT(extract_psbt, final_mtx)) {
                    const CTransaction final_tx(final_mtx);
                    result.pushKV("hex", EncodeHexTx(final_tx));
                    result.pushKV("txid", final_tx.GetHash().ToString());
                }
            }
            return result;
        }
    );
}

RPCHelpMan adaptor_extract_secret()
{
    return RPCHelpMan(
        "adaptor.extract_secret",
        "Recover adaptor secrets from a finalized PSBT that spent Taproot inputs (key-path or annotated script-path) using adaptor signatures.",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "secrets", "Recovered adaptor secrets",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "index", "Input index"},
                                {RPCResult::Type::STR_HEX, "secret", "Adaptor secret (32-byte hex)"},
                            }
                        }
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleCli("adaptor.prepare", "\"psbt_base64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            PartiallySignedTransaction psbt;
            std::string error;
            if (!DecodeBase64PSBT(psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            if (!psbt.tx) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing the unsigned transaction");
            }

            const uint256 txid = psbt.tx->GetHash();

            UniValue secrets(UniValue::VARR);

            for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
                PSBTInput& input = psbt.inputs[idx];

                FairSignInputState state;
                if (!pwallet->GetFairSignInputState(txid, idx, state)) {
                    continue;
                }
                if (!state.has_partial) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Adaptor state for input %u is missing partial signature", idx));
                }

                const unsigned char* final_sig_ptr = nullptr;
                size_t final_sig_len = 0;

                if (!input.m_tap_key_sig.empty()) {
                    final_sig_ptr = input.m_tap_key_sig.data();
                    final_sig_len = input.m_tap_key_sig.size();
                } else if (!input.final_script_witness.IsNull() && input.final_script_witness.stack.size() == 1) {
                    const std::vector<unsigned char>& witness_sig = input.final_script_witness.stack[0];
                    final_sig_ptr = witness_sig.data();
                    final_sig_len = witness_sig.size();
                }

                if (final_sig_ptr == nullptr || final_sig_len != 64) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Final signature missing for input %u", idx));
                }

                // n=1 Extract adaptor secret from final signature
                // complete() does: s = s' + t, then if R' parity==1: s = -s
                // state.pre_sig contains [R' || s'] from partial step
                // final_sig contains [R' || s] from complete step

                // Extract s and s'
                const unsigned char* s_ptr = final_sig_ptr + 32;  // s (final, possibly negated)
                const unsigned char* s_prime_ptr = state.pre_sig.data() + 32;  // s' (pre-sig)

                unsigned char extracted_secret[32];

                if (state.nonce_parity == 0) {
                    // R' parity even: s = s' + t  →  t = s - s'
                    std::memcpy(extracted_secret, s_ptr, 32);

                    unsigned char neg_s_prime[32];
                    std::memcpy(neg_s_prime, s_prime_ptr, 32);
                    if (!secp256k1_ec_seckey_negate(GetSigningContext(), neg_s_prime)) {
                        memory_cleanse(neg_s_prime, sizeof(neg_s_prime));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to negate s'");
                    }

                    if (!secp256k1_ec_seckey_tweak_add(GetSigningContext(), extracted_secret, neg_s_prime)) {
                        memory_cleanse(extracted_secret, sizeof(extracted_secret));
                        memory_cleanse(neg_s_prime, sizeof(neg_s_prime));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute t = s - s'");
                    }
                    memory_cleanse(neg_s_prime, sizeof(neg_s_prime));
                } else {
                    // R' parity odd: s_final = -(s' + t)  →  s' + t = -s_final  →  t = -s_final - s'
                    unsigned char neg_s[32];
                    std::memcpy(neg_s, s_ptr, 32);
                    if (!secp256k1_ec_seckey_negate(GetSigningContext(), neg_s)) {
                        memory_cleanse(neg_s, sizeof(neg_s));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to negate s");
                    }

                    std::memcpy(extracted_secret, neg_s, 32);
                    memory_cleanse(neg_s, sizeof(neg_s));

                    unsigned char neg_s_prime[32];
                    std::memcpy(neg_s_prime, s_prime_ptr, 32);
                    if (!secp256k1_ec_seckey_negate(GetSigningContext(), neg_s_prime)) {
                        memory_cleanse(neg_s_prime, sizeof(neg_s_prime));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to negate s' in extraction");
                    }

                    if (!secp256k1_ec_seckey_tweak_add(GetSigningContext(), extracted_secret, neg_s_prime)) {
                        memory_cleanse(extracted_secret, sizeof(extracted_secret));
                        memory_cleanse(neg_s_prime, sizeof(neg_s_prime));
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute t = -s - s'");
                    }
                    memory_cleanse(neg_s_prime, sizeof(neg_s_prime));
                }

                std::array<unsigned char, 32> secret{};
                std::copy(extracted_secret, extracted_secret + 32, secret.begin());
                memory_cleanse(extracted_secret, sizeof(extracted_secret));

                state.adaptor_secret = secret;
                pwallet->SetFairSignInputState(txid, idx, std::move(state));

                UniValue obj(UniValue::VOBJ);
                obj.pushKV("index", idx);
                obj.pushKV("secret", ArrayToHex(secret));
                secrets.push_back(obj);
            }

            if (secrets.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No adaptor secrets could be extracted");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("secrets", secrets);

            // Clear session state now that secrets are recovered.
            pwallet->ClearFairSignSession(txid);

            return result;
        }
    );
}

// ========================================================================
// MUSIG2 ADAPTOR COORDINATION RPCs
// ========================================================================
// Fair-Sign session management

RPCHelpMan adaptor_unlock_all()
{
    return RPCHelpMan(
        "adaptor.unlock_all",
        "Unlock all Fair-Sign ceremony UTXOs and clean up expired sessions. "
        "Use this to recover from stuck ceremonies or locked coins.",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "unlocked_count", "Number of UTXOs unlocked"},
                {RPCResult::Type::NUM, "sessions_cleaned", "Number of expired sessions removed"},
            }
        },
        RPCExamples{
            HelpExampleCli("adaptor.unlock_all", "")
          + HelpExampleRpc("adaptor.unlock_all", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");
            CWallet* const pwallet = const_cast<CWallet*>(wallet.get());

            LOCK(pwallet->cs_wallet);

            auto [unlocked_count, sessions_cleaned] = pwallet->UnlockAllFairSignUTXOs();

            UniValue result(UniValue::VOBJ);
            result.pushKV("unlocked_count", (int)unlocked_count);
            result.pushKV("sessions_cleaned", (int)sessions_cleaned);
            return result;
        }
    );
}

// ========================================================================
// MuSig2 support is always compiled (using secp256k1-zkp native adaptor APIs)

RPCHelpMan musig_keyagg()
{
    return RPCHelpMan(
        "musig.keyagg",
        "Aggregate public keys for MuSig2 multi-signature scheme. "
        "Returns aggregated pubkey and keyagg_cache for use in adaptor ceremonies.",
        {
            {"pubkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of compressed public keys (33-byte hex) to aggregate",
                {
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Compressed public key (33-byte hex)"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "agg_pubkey", "Aggregated x-only public key (32 bytes)"},
                {RPCResult::Type::STR_HEX, "keyagg_cache", "Serialized keyagg cache (opaque blob for later use)"},
            }
        },
        RPCExamples{
            HelpExampleCli("musig.keyagg", "'[\"pubkey1\", \"pubkey2\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const UniValue& pubkeys_arr = request.params[0].get_array();
            if (pubkeys_arr.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "MuSig2 requires at least 2 pubkeys");
            }

            // Parse input pubkeys as compressed 33-byte pubkeys
            std::vector<secp256k1_pubkey> pubkeys;
            std::vector<const secp256k1_pubkey*> pubkey_ptrs;

            for (size_t i = 0; i < pubkeys_arr.size(); ++i) {
                const std::string pubkey_hex = pubkeys_arr[i].get_str();
                auto pubkey_bytes = ParseHex(pubkey_hex);

                if (pubkey_bytes.size() != 33) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid pubkey length at index %u (expected 33-byte compressed pubkey)", (unsigned)i));
                }

                secp256k1_pubkey full_pk;
                if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &full_pk, pubkey_bytes.data(), 33)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid compressed pubkey at index %u", (unsigned)i));
                }

                pubkeys.push_back(full_pk);
                pubkey_ptrs.push_back(&pubkeys[i]);
            }

            // Aggregate pubkeys - output is xonly
            secp256k1_musig_keyagg_cache cache;
            secp256k1_xonly_pubkey agg_pk_xonly;

            if (!secp256k1_musig_pubkey_agg(GetSigningContext(), nullptr, &agg_pk_xonly, &cache, pubkey_ptrs.data(), pubkeys.size())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to aggregate pubkeys");
            }

            // Serialize aggregated xonly pubkey
            unsigned char agg_pk_bytes[32];
            secp256k1_xonly_pubkey_serialize(GetSigningContext(), agg_pk_bytes, &agg_pk_xonly);

            // Serialize keyagg cache (opaque blob)
            unsigned char cache_bytes[sizeof(cache)];
            std::memcpy(cache_bytes, &cache, sizeof(cache));

            UniValue result(UniValue::VOBJ);
            result.pushKV("agg_pubkey", HexStr(agg_pk_bytes));
            result.pushKV("keyagg_cache", HexStr(cache_bytes));

            return result;
        }
    );
}

} // namespace wallet
