// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/crosschainmanager.h>
#include <wallet/ethhtlcbackend.h>
#include <rpc/register.h>
#include <wallet/fairsign.h>
#include <wallet/receive.h>
#include <wallet/context.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/keywrap_utils.h>
#include <wallet/vaultregistry.h>
#include <wallet/vault_signing.h>

#include <assets/asset.h>
#include <assets/icu_payload.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <key_io.h>
#include <pubkey.h>
#include <script/script.h>
#include <psbt.h>
#include <logging.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <policy/policy.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <node/context.h>
#include <node/transaction.h>
#include <validation.h>
#include <algorithm>
#include <array>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/rbf.h>
#include <util/any.h>
#include <util/transaction_identifier.h>
#include <util/time.h>
#include <wallet/coincontrol.h>
#include <wallet/contract.h>
#include <wallet/spend.h>
#include <policy/feerate.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <hash.h>

#include <algorithm>
#include <limits>
#include <set>
#include <span>
#include <stdexcept>
#include <chrono>
#include <cmath>

namespace kw = wallet::keywrap;
#include <tuple>
#include <string_view>
#include <map>
#include <optional>
#include <vector>

namespace wallet {

// Ensure all PSBT inputs share the same sighash_type before FillPSBT to avoid
// PSBTError::SIGHASH_MISMATCH when inputs come from heterogeneous sources.
static inline void NormalizePsbtSighash(PartiallySignedTransaction& psbt, int sighash_type)
{
    for (auto& in : psbt.inputs) {
        in.sighash_type = sighash_type;
    }
}

static std::optional<CTxOut> GetPsbtInputPrevout(const COutPoint& prevout, const PSBTInput& psbt_input)
{
    if (!psbt_input.witness_utxo.IsNull()) {
        return psbt_input.witness_utxo;
    }
    if (psbt_input.non_witness_utxo && prevout.n < psbt_input.non_witness_utxo->vout.size()) {
        return psbt_input.non_witness_utxo->vout[prevout.n];
    }
    return std::nullopt;
}

static void MergePsbtInputSolvingData(const CTxOut& prev_txout,
                                      const PSBTInput& psbt_input,
                                      FlatSigningProvider& provider)
{
    SignatureData sigdata;
    psbt_input.FillSignatureData(sigdata);

    if (!sigdata.redeem_script.empty()) {
        provider.scripts.emplace(CScriptID(sigdata.redeem_script), sigdata.redeem_script);
    }
    if (!sigdata.witness_script.empty()) {
        provider.scripts.emplace(CScriptID(sigdata.witness_script), sigdata.witness_script);
    }
    for (const auto& [keyid, pubkey_origin] : sigdata.misc_pubkeys) {
        provider.pubkeys.emplace(keyid, pubkey_origin.first);
        provider.origins.emplace(keyid, pubkey_origin);
    }
    for (const auto& [xonly_pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        const CPubKey full_pubkey{xonly_pubkey.GetEvenCorrespondingCPubKey()};
        if (!full_pubkey.IsFullyValid()) continue;
        const CKeyID keyid = full_pubkey.GetID();
        provider.pubkeys.emplace(keyid, full_pubkey);
        provider.origins.emplace(keyid, std::make_pair(full_pubkey, leaf_origin.second));
    }

    int witness_version = -1;
    std::vector<unsigned char> witness_program;
    if (prev_txout.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
        witness_version == 1 && witness_program.size() == XOnlyPubKey::size()) {
        XOnlyPubKey output_key;
        std::copy(witness_program.begin(), witness_program.end(), output_key.begin());
        if (!sigdata.tr_spenddata.internal_key.IsNull() || !sigdata.tr_spenddata.scripts.empty()) {
            provider.tr_spenddata[output_key] = sigdata.tr_spenddata;
        }
    }
}

static void SeedForeignPsbtInputForFunding(const CWallet& wallet,
                                           CCoinControl& coin_control,
                                           const COutPoint& prevout,
                                           const PSBTInput& psbt_input,
                                           const char* context)
{
    const auto prev_txout = GetPsbtInputPrevout(prevout, psbt_input);
    if (!prev_txout) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("%s missing prevout data for foreign input %s", context, prevout.ToString()));
    }

    auto& preset = coin_control.Select(prevout);
    preset.SetTxOut(*prev_txout);

    MergePsbtInputSolvingData(*prev_txout, psbt_input, coin_control.m_external_provider);

    const int input_vsize = CalculateMaximumSignedInputSize(*prev_txout,
                                                            prevout,
                                                            &coin_control.m_external_provider,
                                                            wallet.CanGrindR(),
                                                            &coin_control);
    if (input_vsize == -1) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("%s missing solving data for foreign input %s", context, prevout.ToString()));
    }
    coin_control.SetInputWeight(prevout, static_cast<int64_t>(input_vsize) * WITNESS_SCALE_FACTOR);
}

class ScopedCoinLocker {
public:
    explicit ScopedCoinLocker(CWallet& wallet) : m_wallet(wallet) {}

    void Lock(const COutPoint& outpoint)
    {
        LOCK(m_wallet.cs_wallet);
        if (m_wallet.IsLockedCoin(outpoint)) {
            return;
        }
        m_wallet.LockCoin(outpoint);
        m_locked.insert(outpoint);
    }

    template <typename Container>
    void LockMany(const Container& outpoints)
    {
        for (const COutPoint& outpoint : outpoints) {
            Lock(outpoint);
        }
    }

    void ReleaseAll()
    {
        LOCK(m_wallet.cs_wallet);
        for (const COutPoint& outpoint : m_locked) {
            m_wallet.UnlockCoin(outpoint);
        }
        m_locked.clear();
    }

    ~ScopedCoinLocker() { ReleaseAll(); }

private:
    CWallet& m_wallet;
    std::set<COutPoint, std::less<>> m_locked;
};

// Forward declarations
RPCHelpMan sendasset();
RPCHelpMan asset_build_delivery_template();
RPCHelpMan geticupayload();

namespace kw = wallet::keywrap;

// Helper function to get asset decimals from registry
static int GetAssetDecimals(CWallet* wallet, const uint256& asset_id)
{
    if (!wallet) return 8;

    auto entry_opt = wallet->chain().getAssetRegistryEntry(asset_id);
    if (entry_opt && entry_opt->decimals != 255) {
        return entry_opt->decimals;
    }
    return 8; // Default to 8 decimals
}

// Forward-declare script-only Taproot internal key derivation used to disable key-path on covenants
static XOnlyPubKey DeriveScriptOnlyInternalKey(const std::string& tag,
                                               const uint256& contract_id);
static void FinalizeVaultTaprootLeafWitness(CWallet& wallet,
                                            PartiallySignedTransaction& psbt,
                                            size_t input_index,
                                            const VaultMetadata& vault,
                                            const VaultLeafDescriptor& leaf,
                                            CKey& signing_key,
                                            const char* log_context);
static const VaultLeafDescriptor* FindForwardLeafByPurpose(const VaultMetadata& vault,
                                                           const std::string& purpose);

namespace {

constexpr uint32_t DEFAULT_REPO_SAFETY_K{6};
constexpr uint32_t DEFAULT_REPO_REORG_CONF{2};
using wallet::DEFAULT_REPO_ASSET_OUTPUT_VALUE;

// Helper: Check if principal and interest legs can be merged into single OUTPUTMATCH
static bool ShouldMergeRepoRepayLegs(const RepoTerms& terms)
{
    // Merge when both legs share the same asset (native or same asset_id)
    if (terms.principal_leg.is_native != terms.interest_leg.is_native) {
        return false; // One native, one asset → cannot merge
    }
    if (terms.principal_leg.is_native) {
        return true; // Both native BTC → merge
    }
    // Both are assets → merge only if same asset_id
    return terms.principal_leg.asset_id == terms.interest_leg.asset_id;
}

// Helper: Build repo repay covenant script (principal + interest payments)
// Returns merged single OUTPUTMATCH when same asset, or dual OUTPUTMATCH when different assets
static CScript BuildRepoRepayCovenantScript(const RepoTerms& terms,
                                            const CTxDestination& repay_dest,
                                            const XOnlyPubKey& borrower_key)
{
    const uint256 tap_match = ComputeTapMatch(GetScriptForDestination(repay_dest));
    std::vector<unsigned char> tap_match_bytes(tap_match.begin(), tap_match.end());
    CScript repay_script;

    if (ShouldMergeRepoRepayLegs(terms)) {
        // OPTIMIZED PATH: Single OUTPUTMATCH for merged principal + interest
        const uint64_t total_repay_units = terms.principal_leg.units + terms.interest_leg.units;
        repay_script << tap_match_bytes;
        std::vector<unsigned char> total_amount_le = EncodeLE64(total_repay_units);

        if (terms.principal_leg.is_native) {
            repay_script << total_amount_le << OP_OUTPUTMATCH_NATIVE;
        } else {
            std::vector<unsigned char> asset_bytes(terms.principal_leg.asset_id.begin(),
                                                   terms.principal_leg.asset_id.end());
            repay_script << asset_bytes << total_amount_le << OP_OUTPUTMATCH_ASSET;
        }
        repay_script << OP_VERIFY;
    } else {
        // DUAL PATH: Separate OUTPUTMATCH for principal and interest (different assets)
        // Check principal payment to lender
        repay_script << tap_match_bytes;
        std::vector<unsigned char> principal_amount_le = EncodeLE64(terms.principal_leg.units);
        if (terms.principal_leg.is_native) {
            repay_script << principal_amount_le << OP_OUTPUTMATCH_NATIVE;
        } else {
            std::vector<unsigned char> principal_asset_bytes(terms.principal_leg.asset_id.begin(),
                                                            terms.principal_leg.asset_id.end());
            repay_script << principal_asset_bytes << principal_amount_le << OP_OUTPUTMATCH_ASSET;
        }
        repay_script << OP_VERIFY;

        // Check interest payment to lender
        repay_script << tap_match_bytes;
        std::vector<unsigned char> interest_amount_le = EncodeLE64(terms.interest_leg.units);
        if (terms.interest_leg.is_native) {
            repay_script << interest_amount_le << OP_OUTPUTMATCH_NATIVE;
        } else {
            std::vector<unsigned char> interest_asset_bytes(terms.interest_leg.asset_id.begin(),
                                                           terms.interest_leg.asset_id.end());
            repay_script << interest_asset_bytes << interest_amount_le << OP_OUTPUTMATCH_ASSET;
        }
        repay_script << OP_VERIFY;
    }

    // Add borrower signature check
    repay_script << std::vector<unsigned char>(borrower_key.begin(), borrower_key.end())
                 << OP_CHECKSIG;

    return repay_script;
}

// Helper struct for BuildRepoAssetSkeleton
struct RepoAssetSkeletonResult
{
    CMutableTransaction tx;
    std::set<COutPoint> inputs_to_lock;
    std::vector<size_t> change_indices;
    std::optional<size_t> deliver_output_index;
    CAmount estimated_fee{0};
};

// Helper: Build sendasset skeleton for repo asset transfers
static RepoAssetSkeletonResult BuildRepoAssetSkeleton(CWallet& wallet,
                                                      const JSONRPCRequest& parent_request,
                                                      const AssetLeg& leg,
                                                      const CTxDestination& dest,
                                                      const char* context_tag,
                                                      const std::optional<double>& fee_rate_override = std::nullopt)
{
    Assert(!leg.is_native);

    JSONRPCRequest sendasset_req;
    sendasset_req.context = parent_request.context;
    sendasset_req.URI = parent_request.URI;
    sendasset_req.strMethod = "sendasset";

    UniValue params(UniValue::VARR);
    params.push_back(leg.asset_id.ToString());
    params.push_back(EncodeDestination(dest));
    params.push_back(UniValue(static_cast<int64_t>(leg.units)));

    UniValue opts(UniValue::VOBJ);
    opts.pushKV("return_skeleton", true);
    opts.pushKV("broadcast", false);
    if (fee_rate_override.has_value()) {
        opts.pushKV("fee_rate", *fee_rate_override);
    }
    params.push_back(opts);

    sendasset_req.params = params;

    UniValue skeleton = sendasset().HandleRequest(sendasset_req);
    if (!skeleton.isObject() || !skeleton.exists("hex")) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: sendasset did not return skeleton hex", context_tag));
    }

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, skeleton["hex"].get_str())) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: failed to decode sendasset skeleton", context_tag));
    }

    RepoAssetSkeletonResult result;
    result.tx = std::move(tx);

    if (skeleton.exists("estimated_fee")) {
        result.estimated_fee = AmountFromValue(skeleton["estimated_fee"]);
    }

    auto collect_inputs = [&](const UniValue& arr){
        for (size_t i = 0; i < arr.size(); ++i) {
            const UniValue& obj = arr[i];
            auto txid_opt = Txid::FromHex(obj["txid"].get_str());
            if (!txid_opt) continue;
            uint32_t vout = obj["vout"].getInt<uint32_t>();
            result.inputs_to_lock.insert(COutPoint(*txid_opt, vout));
        }
    };

    if (skeleton.exists("asset_inputs") && skeleton["asset_inputs"].isArray()) {
        collect_inputs(skeleton["asset_inputs"].get_array());
    }
    if (skeleton.exists("btc_inputs") && skeleton["btc_inputs"].isArray()) {
        collect_inputs(skeleton["btc_inputs"].get_array());
    }

    const CScript dest_spk = GetScriptForDestination(dest);
    for (size_t i = 0; i < result.tx.vout.size(); ++i) {
        const CTxOut& out = result.tx.vout[i];
        auto tag = assets::ParseAssetTag(out.vExt);
        if (tag && tag->id == leg.asset_id && tag->amount == leg.units && out.scriptPubKey == dest_spk) {
            result.deliver_output_index = i;
            break;
        }
    }
    if (!result.deliver_output_index) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("%s: unable to locate asset delivery output in skeleton", context_tag));
    }

    if (skeleton.exists("outputs") && skeleton["outputs"].isArray()) {
        const UniValue& outputs = skeleton["outputs"].get_array();
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& outobj = outputs[i];
            if (!outobj.exists("n")) continue;
            size_t n = outobj["n"].getInt<size_t>();
            std::string type;
            if (outobj.exists("type")) {
                type = outobj["type"].get_str();
            }
            bool mark_change = false;
            if (!type.empty() && type.find("change") != std::string::npos) {
                mark_change = true;
            } else {
                LOCK(wallet.cs_wallet);
                if (n < result.tx.vout.size()) {
                    const CTxOut& out = result.tx.vout[n];
                    if ((wallet.IsMine(out) & ISMINE_SPENDABLE) && n != *result.deliver_output_index) {
                        mark_change = true;
                    }
                }
            }
            if (mark_change) {
                result.change_indices.push_back(n);
            }
        }
    }

    wallet.WalletLogPrintf("%s: skeleton asset inputs=%u btc_inputs=%u change_outputs=%u deliver_index=%s amount=%u dest=%s\n",
        context_tag,
        skeleton.exists("asset_inputs") && skeleton["asset_inputs"].isArray() ? skeleton["asset_inputs"].size() : 0,
        skeleton.exists("btc_inputs") && skeleton["btc_inputs"].isArray() ? skeleton["btc_inputs"].size() : 0,
        result.change_indices.size(),
        result.deliver_output_index ? util::ToString(int(*result.deliver_output_index)) : "none",
        static_cast<unsigned int>(leg.units),
        EncodeDestination(dest));

    return result;
}

static int64_t EstimateTaprootScriptPathInputWeight(size_t script_size,
                                                    size_t control_block_size,
                                                    size_t signature_elements)
{
    // prevout (32) + index (4) + scriptSig length byte (1) + sequence (4)
    constexpr int64_t BASE_NONWITNESS_WEIGHT = (32 + 4 + 1 + 4) * WITNESS_SCALE_FACTOR;
    int64_t weight = BASE_NONWITNESS_WEIGHT;

    const size_t stack_elems = signature_elements + 2; // sigs + script + control block
    weight += GetSizeOfCompactSize(stack_elems);

    constexpr size_t TAPROOT_SIG_SIZE = 65; // 64-byte schnorr sig + sighash byte (worst-case)
    for (size_t i = 0; i < signature_elements; ++i) {
        weight += GetSizeOfCompactSize(TAPROOT_SIG_SIZE) + TAPROOT_SIG_SIZE;
    }

    weight += GetSizeOfCompactSize(script_size) + script_size;
    weight += GetSizeOfCompactSize(control_block_size) + control_block_size;
    return weight;
}

using TaprootLeafTuples = std::vector<std::tuple<unsigned char, unsigned char, std::vector<unsigned char>>>;

static size_t FindTaprootLeafDepth(const TaprootLeafTuples& tuples,
                                   const std::vector<unsigned char>& target_script)
{
    for (const auto& [depth, leaf_ver, script] : tuples) {
        if (script == target_script) {
            return static_cast<size_t>(depth);
        }
    }
    return 1; // default two-leaf tree depth
}

static std::optional<double> ParseFeeRateOverride(const UniValue& opts)
{
    if (opts.isNull()) return std::nullopt;
    const UniValue& val = opts.find_value("fee_rate");
    if (val.isNull()) return std::nullopt;
    if (!val.isNum()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.fee_rate must be numeric");
    }
    const double sat_vb = val.get_real();
    if (!std::isfinite(sat_vb) || sat_vb <= 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.fee_rate must be a positive finite value");
    }
    if (sat_vb > 1'000'000.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.fee_rate is unreasonably large");
    }
    return sat_vb;
}

static AssetDeliveryTemplate BuildRepoDeliveryTemplate(CWallet& wallet,
                                                       const JSONRPCRequest& parent_request,
                                                       const AssetLeg& leg,
                                                       const CTxDestination& dest,
                                                       const char* context_tag)
{
    AssetDeliveryTemplate tmpl;
    tmpl.is_native = leg.is_native;
    tmpl.asset_id = leg.asset_id;
    tmpl.units = leg.units;
    tmpl.script_pubkey = GetScriptForDestination(dest);

    if (leg.units == 0) {
        tmpl.commitment = ComputeAssetDeliveryCommitment(tmpl);
        return tmpl;
    }

    if (leg.is_native) {
        tmpl.vext.clear();
        tmpl.commitment = ComputeAssetDeliveryCommitment(tmpl);
        wallet.WalletLogPrintf("%s: built native delivery template units=%u dest=%s\n",
                               context_tag,
                               static_cast<unsigned int>(leg.units),
                               EncodeDestination(dest));
        return tmpl;
    }

    JSONRPCRequest template_req;
    template_req.context = parent_request.context;
    template_req.URI = parent_request.URI;
    template_req.strMethod = "asset.build_delivery_template";

    UniValue params(UniValue::VARR);
    params.push_back(leg.asset_id.ToString());
    params.push_back(EncodeDestination(dest));
    if (leg.units <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        params.push_back(UniValue(static_cast<int64_t>(leg.units)));
    } else {
        params.push_back(UniValue(strprintf("%llu", static_cast<unsigned long long>(leg.units))));
    }
    template_req.params = params;

    UniValue response;
    for (int attempt = 0; attempt < 3; ++attempt) {
        try {
            response = asset_build_delivery_template().HandleRequest(template_req);
            break;
        } catch (const UniValue& err) {
            const UniValue& code_val = err["code"];
            const UniValue& message_val = err["message"];
            const bool registry_missing =
                code_val.isNum() &&
                code_val.getInt<int>() == RPC_INVALID_PARAMETER &&
                message_val.isStr() &&
                message_val.get_str().find("Asset not found in registry") != std::string::npos;
            if (!registry_missing || attempt == 2) {
                throw;
            }
            wallet.WalletLogPrintf("%s: asset registry entry unavailable for %s (retry %d)\n",
                                   context_tag,
                                   leg.asset_id.ToString().substr(0, 16),
                                   attempt + 1);
            UninterruptibleSleep(std::chrono::milliseconds(200));
        }
    }

    if (response.isNull()) {
        response = asset_build_delivery_template().HandleRequest(template_req);
    }

    if (!response.isObject()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template returned non-object", context_tag));
    }

    const UniValue& is_native_val = response.find_value("is_native");
    if (!is_native_val.isBool() || is_native_val.get_bool()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template returned native flag unexpectedly", context_tag));
    }

    const UniValue& asset_hex_val = response.find_value("asset_id");
    if (!asset_hex_val.isStr() || asset_hex_val.get_str().size() != 64) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template missing asset_id", context_tag));
    }
    if (asset_hex_val.get_str() != leg.asset_id.ToString()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template asset_id mismatch", context_tag));
    }

    const UniValue& script_val = response.find_value("script_pubkey");
    if (!script_val.isStr()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template missing script_pubkey", context_tag));
    }
    const std::vector<unsigned char> script_bytes = ParseHex(script_val.get_str());
    CScript rpc_script(script_bytes.begin(), script_bytes.end());
    if (rpc_script != tmpl.script_pubkey) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template script mismatch", context_tag));
    }

    const UniValue& vext_val = response.find_value("vext");
    if (!vext_val.isStr()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template missing vext", context_tag));
    }
    tmpl.vext = ParseHex(vext_val.get_str());

    tmpl.commitment = ComputeAssetDeliveryCommitment(tmpl);

    const UniValue& commitment_val = response.find_value("commitment");
    if (commitment_val.isStr()) {
        auto commitment_rpc = uint256::FromHex(commitment_val.get_str());
        if (commitment_rpc && *commitment_rpc != tmpl.commitment) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: asset.build_delivery_template commitment mismatch", context_tag));
        }
    }

    wallet.WalletLogPrintf("%s: built asset delivery template asset=%s units=%u dest=%s\n",
                           context_tag,
                           leg.asset_id.ToString().substr(0, 16),
                           static_cast<unsigned int>(leg.units),
                           EncodeDestination(dest));
    return tmpl;
}

uint64_t ParsePositiveUInt64(const UniValue& value, const std::string& field)
{
    if (value.isNum()) {
        int64_t tmp = value.getInt<int64_t>();
        if (tmp < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be non-negative", field));
        }
        return static_cast<uint64_t>(tmp);
    }
    if (value.isStr()) {
        uint64_t out;
        if (!ParseUInt64(value.get_str(), &out)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unable to parse %s", field));
        }
        return out;
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be provided as number or string", field));
}

CTxDestination ParseScriptDestinationHex(const UniValue& parent, const std::string& key)
{
    const UniValue& value = parent.find_value(key);
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a hex-encoded script", key));
    }
    const std::string hex = value.get_str();
    if (!IsHex(hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be hex", key));
    }
    const std::vector<unsigned char> bytes = ParseHex(hex);
    CScript script(bytes.begin(), bytes.end());
    CTxDestination dest;
    if (!ExtractDestination(script, dest)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a standard spendable script", key));
    }
    return dest;
}

FairSignPolicy ParseFairSignPolicy(const UniValue& parent, const std::string& key)
{
    const UniValue& value = parent.find_value(key);
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", key));
    }
    FairSignPolicy policy;
    const UniValue& require_val = value.find_value("require_adaptor");
    if (require_val.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.require_adaptor is required", key));
    }
    policy.require_adaptor = require_val.get_bool();

    const UniValue& reveal_val = value.find_value("reveal_lockstep");
    policy.reveal_lockstep = reveal_val.isNull() ? false : reveal_val.get_bool();
    return policy;
}

XOnlyPubKey ParseXOnlyPubKeyHex(const UniValue& parent, const std::string& key)
{
    const UniValue& value = parent.find_value(key);
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a 32-byte hex string", key));
    }
    const std::string hex = value.get_str();
    if (!IsHex(hex) || hex.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be 32-byte hex", key));
    }
    const std::vector<unsigned char> bytes = ParseHex(hex);
    XOnlyPubKey point(std::span<const unsigned char>(bytes.data(), bytes.size()));
    if (!point.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid x-only public key", key));
    }
    return point;
}

std::optional<XOnlyPubKey> ExtractInternalKeyForDestination(CWallet& wallet, const CTxDestination& dest)
{
    const CScript spk = GetScriptForDestination(dest);
    std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(spk);
    for (ScriptPubKeyMan* manager : managers) {
        if (manager == nullptr) continue;
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;

        auto provider = desc_spkm->GetSolvingProvider(spk);
        if (!provider) continue;

        auto* flat_provider = dynamic_cast<FlatSigningProvider*>(provider.get());
        if (flat_provider && !flat_provider->pubkeys.empty()) {
            return XOnlyPubKey(flat_provider->pubkeys.begin()->second);
        }
    }
    return std::nullopt;
}

int64_t ParseSignedInt64(const UniValue& value, const std::string& field)
{
    if (value.isNum()) {
        return value.getInt<int64_t>();
    }
    if (value.isStr()) {
        int64_t out;
        if (ParseInt64(value.get_str(), &out)) {
            return out;
        }
        CAmount parsed;
        if (!ParseFixedPoint(value.get_str(), 8, &parsed)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unable to parse %s", field));
        }
        return parsed;
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be provided as number or string", field));
}

std::optional<XOnlyPubKey> LookupTaprootInternalKey(const CWallet& wallet, const CTxDestination& dest)
{
    const auto* tap = std::get_if<WitnessV1Taproot>(&dest);
    if (!tap) return std::nullopt;

    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(dest));
    if (!provider) return std::nullopt;

    TaprootSpendData spenddata;
    if (!provider->GetTaprootSpendData(*tap, spenddata)) return std::nullopt;
    if (spenddata.internal_key.IsNull()) return std::nullopt;
    return spenddata.internal_key;
}

void MaybePopulateLocalMarginKey(CWallet& wallet,
                                 const CTxDestination& dest,
                                 std::optional<XOnlyPubKey>& field)
{
    if (field.has_value()) return;
    if (auto key = LookupTaprootInternalKey(wallet, dest)) {
        field = *key;
    }
}

static std::optional<XOnlyPubKey> ResolveForwardMarginKey(
    CWallet& wallet,
    const CTxDestination& dest,
    const std::optional<XOnlyPubKey>& existing,
    const std::optional<XOnlyPubKey>& provided,
    const char* field_label,
    ForwardSide local_side,
    ForwardSide key_owner_side)
{
    const auto KeyHex = [](const XOnlyPubKey& key) {
        return HexStr(std::vector<unsigned char>(key.begin(), key.end()));
    };

    const bool wallet_controls_dest = (local_side == key_owner_side);

    if (wallet_controls_dest) {
        auto local = LookupTaprootInternalKey(wallet, dest);
        if (!local) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("%s: wallet unable to derive internal key for locally controlled margin destination",
                          field_label));
        }
        if (existing && *existing != *local) {
            wallet.WalletLogPrintf("%s: updating stale locally stored key %s to freshly derived key %s\n",
                                   field_label,
                                   KeyHex(*existing),
                                   KeyHex(*local));
        }
        if (provided && *provided != *local) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("%s: counterparty provided mismatched internal key %s (expected %s)",
                          field_label,
                          KeyHex(*provided),
                          KeyHex(*local)));
        }
        return local;
    }

    // Counterparty-controlled destination: we rely on their disclosure.
    if (existing && provided && *existing != *provided) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s: counterparty-provided key %s conflicts with previously recorded key %s",
                      field_label,
                      KeyHex(*provided),
                      KeyHex(*existing)));
    }
    if (provided) return provided;
    if (existing) return existing;
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf("%s: missing counterparty internal key for their margin destination",
                  field_label));
}

UniValue EncodeInternalKeyOptional(const std::optional<XOnlyPubKey>& key_opt)
{
    if (!key_opt) return UniValue();
    return UniValue(HexStr(std::vector<unsigned char>(key_opt->begin(), key_opt->end())));
}

std::optional<XOnlyPubKey> ParseInternalKeyOptional(const UniValue& value, const std::string& field_name)
{
    if (value.isNull()) {
        return std::nullopt;
    }
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be hex string", field_name));
    }
    const std::string& hex = value.get_str();
    if (!IsHex(hex) || hex.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be 32-byte hex", field_name));
    }
    std::vector<unsigned char> bytes = ParseHex(hex);
    XOnlyPubKey key;
    std::copy(bytes.begin(), bytes.end(), key.begin());
    if (!key.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid X-only pubkey", field_name));
    }
    return key;
}

struct FeePolicySnapshot {
    bool rbf{false};
    bool cpfp{false};
    bool anchors{false};
    uint32_t min_satvb{0};
    uint32_t target_satvb{0};
};

const std::vector<unsigned char>& FS_IDENTIFIER = fairsign::Identifier();
const std::vector<unsigned char>& X_IDENTIFIER = fairsign::AdvisoryIdentifier();

void AddProprietaryEntry(std::set<PSBTProprietary>& container,
                         const std::vector<unsigned char>& identifier,
                         uint64_t subtype,
                         std::string_view key_suffix,
                         std::span<const unsigned char> value)
{
    DataStream ss_key{};
    WriteCompactSize(ss_key, PSBT_GLOBAL_PROPRIETARY);
    ss_key << identifier;
    WriteCompactSize(ss_key, subtype);
    // Suffix is NOT length-prefixed, write raw bytes
    for (auto byte : key_suffix) {
        ss_key << static_cast<uint8_t>(byte);
    }

    PSBTProprietary entry;
    entry.identifier = identifier;
    entry.subtype = subtype;
    entry.key = std::vector<unsigned char>(UCharCast(ss_key.data()), UCharCast(ss_key.data() + ss_key.size()));
    entry.value = std::vector<unsigned char>(value.begin(), value.end());
    container.insert(entry);
}

std::vector<unsigned char> EncodeFairSignPolicy(const FairSignPolicy& policy)
{
    uint8_t bits = 0;
    if (policy.require_adaptor) bits |= 1 << 0;
    if (policy.reveal_lockstep) bits |= 1 << 1;
    return {bits};
}

std::vector<unsigned char> EncodeRepoDeadlines(const RepoTerms& terms)
{
    DataStream ss{};
    ss << static_cast<uint32_t>(terms.maturity_height);
    ss << static_cast<uint32_t>(terms.safety_k);
    ss << static_cast<uint32_t>(terms.reorg_conf);
    return std::vector<unsigned char>(UCharCast(ss.data()), UCharCast(ss.data() + ss.size()));
}

std::vector<unsigned char> EncodeFeePolicy(const FeePolicySnapshot& fee)
{
    DataStream ss{};
    ss << static_cast<uint8_t>(fee.rbf ? 1 : 0);
    ss << static_cast<uint8_t>(fee.cpfp ? 1 : 0);
    ss << static_cast<uint8_t>(fee.anchors ? 1 : 0);
    ss << fee.min_satvb;
    ss << fee.target_satvb;
    return std::vector<unsigned char>(UCharCast(ss.data()), UCharCast(ss.data() + ss.size()));
}

FeePolicySnapshot ParseFeePolicy(const UniValue& obj)
{
    FeePolicySnapshot policy;
    const UniValue& rbf_val = obj.find_value("rbf");
    if (rbf_val.isBool()) {
        policy.rbf = rbf_val.get_bool();
    }
    const UniValue& cpfp_val = obj.find_value("cpfp");
    if (cpfp_val.isBool()) {
        policy.cpfp = cpfp_val.get_bool();
    }
    const UniValue& anchors_val = obj.find_value("anchors");
    if (anchors_val.isBool()) {
        policy.anchors = anchors_val.get_bool();
    }
    const UniValue& min_satvb_val = obj.find_value("min_satvb");
    if (min_satvb_val.isNum()) {
        policy.min_satvb = static_cast<uint32_t>(min_satvb_val.getInt<int64_t>());
    }
    const UniValue& target_satvb_val = obj.find_value("target_satvb");
    if (target_satvb_val.isNum()) {
        policy.target_satvb = static_cast<uint32_t>(target_satvb_val.getInt<int64_t>());
    }
    return policy;
}

/**
 * Convert fee strategy string ("low", "medium", "high") to FeePolicySnapshot
 * Maps UI-friendly strategy names to concrete fee policies with target rates.
 */
FeePolicySnapshot FeeStrategyToPolicy(const std::string& strategy)
{
    FeePolicySnapshot policy;
    policy.rbf = true;  // Enable RBF for all strategies to allow fee bumping
    policy.cpfp = false;
    policy.anchors = false;

    if (strategy == "low") {
        policy.min_satvb = 1;
        policy.target_satvb = 2;
    } else if (strategy == "high") {
        policy.min_satvb = 25;
        policy.target_satvb = 50;
    } else {
        // Default to medium for empty string, "medium", or unknown values
        policy.min_satvb = 5;
        policy.target_satvb = 10;
    }

    return policy;
}

std::vector<unsigned char> EncodeOutputMatch(const RepoOfferRecord& record,
                                             const CTxDestination& repay_dest)
{
    // Note: This encodes BOTH principal + interest as a combined repay amount
    // for backward compatibility with existing PSBT metadata format
    DataStream ss{};
    const bool is_native = record.terms.principal_leg.is_native;
    ss << static_cast<uint8_t>(is_native ? 1 : 0);
    ss << ComputeTapMatch(GetScriptForDestination(repay_dest));
    const uint64_t repay_units = record.terms.principal_leg.units + record.terms.interest_leg.units;
    ss << static_cast<uint64_t>(repay_units);
    if (!is_native) {
        ss << record.terms.principal_leg.asset_id;
    }
    return std::vector<unsigned char>(UCharCast(ss.data()), UCharCast(ss.data() + ss.size()));
}

std::vector<unsigned char> EncodeOutputMatchGeneric(const CTxDestination& dest,
                                                     bool is_native,
                                                     uint64_t amount,
                                                     const uint256& asset_id = uint256{})
{
    DataStream ss{};
    ss << static_cast<uint8_t>(is_native ? 1 : 0);
    ss << ComputeTapMatch(GetScriptForDestination(dest));
    ss << amount;
    if (!is_native) {
        ss << asset_id;
    }
    return std::vector<unsigned char>(UCharCast(ss.data()), UCharCast(ss.data() + ss.size()));
}

std::vector<unsigned char> EncodeOutputAssetMetadata(const CTxOut& out)
{
    DataStream ss{};
    if (auto tag = assets::ParseAssetTag(out.vExt)) {
        ss << static_cast<uint8_t>(0);
        ss << tag->id;
        ss << static_cast<uint64_t>(tag->amount);
    } else {
        ss << static_cast<uint8_t>(1);
        ss << static_cast<uint64_t>(out.nValue);
    }
    return std::vector<unsigned char>(UCharCast(ss.data()), UCharCast(ss.data() + ss.size()));
}

void AnnotateRepoGlobalMetadata(PartiallySignedTransaction& psbt,
                                const RepoOfferRecord& record,
                                const CTxDestination& repay_dest,
                                const FeePolicySnapshot& fee)
{
    const std::vector<unsigned char> policy_bytes = EncodeFairSignPolicy(record.fs_policy);
    AddProprietaryEntry(psbt.m_proprietary, FS_IDENTIFIER, 0, "policy", policy_bytes);

    std::vector<unsigned char> meta_bytes(sizeof(uint256));
    const uint256 contract_meta = ComputeRepoContractMeta(record, repay_dest);
    std::copy(contract_meta.begin(), contract_meta.end(), meta_bytes.begin());
    AddProprietaryEntry(psbt.m_proprietary, FS_IDENTIFIER, 0, "contract_meta", meta_bytes);

    const std::array<unsigned char, 4> repo_tag{'r','e','p','o'};
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "contract_type", repo_tag);

    const std::vector<unsigned char> deadlines_bytes = EncodeRepoDeadlines(record.terms);
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "deadlines", deadlines_bytes);

    const std::vector<unsigned char> fee_bytes = EncodeFeePolicy(fee);
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "fee_policy", fee_bytes);

    const std::vector<unsigned char> match_bytes = EncodeOutputMatch(record, repay_dest);
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "outputmatch/0", match_bytes);
}

void AnnotateRepoOutputs(PartiallySignedTransaction& psbt,
                         const std::vector<size_t>& change_indices)
{
    for (size_t idx = 0; idx < psbt.tx->vout.size(); ++idx) {
        const CTxOut& out = psbt.tx->vout[idx];
        const std::vector<unsigned char> asset_bytes = EncodeOutputAssetMetadata(out);
        AddProprietaryEntry(psbt.outputs[idx].m_proprietary, X_IDENTIFIER, 0, "asset", asset_bytes);
    }
    for (size_t change_idx : change_indices) {
        const std::array<unsigned char, 1> change_flag{1};
        AddProprietaryEntry(psbt.outputs.at(change_idx).m_proprietary, X_IDENTIFIER, 0, "is_change", change_flag);
    }
}

struct OutputMatchSpec {
    CTxDestination dest;
    bool is_native;
    uint64_t amount;
    uint256 asset_id;
};

void AnnotateForwardGlobalMetadata(PartiallySignedTransaction& psbt,
                                    const ForwardContractRecord& record,
                                    const FeePolicySnapshot& fee,
                                    const std::vector<OutputMatchSpec>& outputmatches = {})
{
    const std::vector<unsigned char> policy_bytes = EncodeFairSignPolicy(record.fs_policy);
    AddProprietaryEntry(psbt.m_proprietary, FS_IDENTIFIER, 0, "policy", policy_bytes);

    std::vector<unsigned char> meta_bytes(sizeof(uint256));
    const uint256 contract_meta = ComputeForwardContractMeta(record);
    std::copy(contract_meta.begin(), contract_meta.end(), meta_bytes.begin());
    AddProprietaryEntry(psbt.m_proprietary, FS_IDENTIFIER, 0, "contract_meta", meta_bytes);

    const std::array<unsigned char, 4> forward_tag{'f','w','d','x'};
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "contract_type", forward_tag);

    // Encode deadlines (deadline_short, deadline_long)
    std::vector<unsigned char> deadlines_bytes(sizeof(uint32_t) * 2);
    WriteLE32(deadlines_bytes.data(), record.terms.deadline_short);
    WriteLE32(deadlines_bytes.data() + sizeof(uint32_t), record.terms.deadline_long);
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "deadlines", deadlines_bytes);

    const std::vector<unsigned char> fee_bytes = EncodeFeePolicy(fee);
    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "fee_policy", fee_bytes);

    // Add outputmatch entries for covenant verification (FINANCING_PRIMITIVES §4.4)
    for (size_t i = 0; i < outputmatches.size(); ++i) {
        const auto& spec = outputmatches[i];
        const std::vector<unsigned char> match_bytes = EncodeOutputMatchGeneric(
            spec.dest, spec.is_native, spec.amount, spec.asset_id
        );
        const std::string key = strprintf("outputmatch/%d", i);
        AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, key, match_bytes);
    }
}

void AnnotateForwardOutputs(PartiallySignedTransaction& psbt,
                            const std::vector<size_t>& change_indices)
{
    for (size_t idx = 0; idx < psbt.tx->vout.size(); ++idx) {
        const CTxOut& out = psbt.tx->vout[idx];
        const std::vector<unsigned char> asset_bytes = EncodeOutputAssetMetadata(out);
        AddProprietaryEntry(psbt.outputs[idx].m_proprietary, X_IDENTIFIER, 0, "asset", asset_bytes);
    }
    for (size_t change_idx : change_indices) {
        const std::array<unsigned char, 1> change_flag{1};
        AddProprietaryEntry(psbt.outputs.at(change_idx).m_proprietary, X_IDENTIFIER, 0, "is_change", change_flag);
    }
}

void AnnotateTaprootInputsWithInternalKeys(CWallet& wallet,
                                           PartiallySignedTransaction& psbt)
{
    LOCK(wallet.cs_wallet);
    for (size_t idx = 0; idx < psbt.inputs.size(); ++idx) {
        PSBTInput& psbt_in = psbt.inputs[idx];

        CTxOut utxo;
        bool have_utxo = psbt.GetInputUTXO(utxo, idx);

        if (!have_utxo) {
            const CTxIn& txin = psbt.tx->vin.at(idx);
            const auto it = wallet.mapWallet.find(txin.prevout.hash);
            if (it != wallet.mapWallet.end()) {
                const CWalletTx& wtx = it->second;
                if (txin.prevout.n < wtx.tx->vout.size()) {
                    utxo = wtx.tx->vout[txin.prevout.n];
                    have_utxo = true;
                }
            }
        }

        if (!have_utxo) {
            continue;
        }

        // Always stash the UTXO so adaptor.prepare sees it
        psbt_in.witness_utxo = utxo;

        // Check if this is a Taproot output and extract the output key
        CTxDestination dest;
        if (!ExtractDestination(utxo.scriptPubKey, dest)) {
            continue;
        }

        XOnlyPubKey output_key;
        if (const auto* tap = std::get_if<WitnessV1Taproot>(&dest)) {
            output_key = *tap;
        } else if (const auto* unknown = std::get_if<WitnessUnknown>(&dest)) {
            if (unknown->GetWitnessVersion() == 1 && unknown->GetWitnessProgram().size() == 32) {
                output_key = XOnlyPubKey(std::span<const unsigned char>(unknown->GetWitnessProgram()));
            } else {
                continue;  // Not Taproot
            }
        } else {
            continue;  // Not Taproot
        }

        if (psbt_in.m_tap_internal_key.IsNull()) {
            std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(utxo.scriptPubKey);
            if (provider) {
                TaprootSpendData tap_data;
                bool have_spend = provider->GetTaprootSpendData(output_key, tap_data);

                if (!have_spend || tap_data.merkle_root.IsNull() || tap_data.scripts.empty()) {
                    TaprootBuilder builder;
                    if (provider->GetTaprootBuilder(output_key, builder)) {
                        TaprootSpendData built = builder.GetSpendData();
                        if (tap_data.internal_key.IsNull() && !built.internal_key.IsNull()) {
                            tap_data.internal_key = built.internal_key;
                        }
                        if (tap_data.merkle_root.IsNull() && !built.merkle_root.IsNull()) {
                            tap_data.merkle_root = built.merkle_root;
                        }
                        for (auto& [leaf, control_blocks] : built.scripts) {
                            tap_data.scripts[leaf].insert(control_blocks.begin(), control_blocks.end());
                        }
                        have_spend = true;
                    }
                }

                if (have_spend) {
                    if (!tap_data.internal_key.IsNull()) {
                        psbt_in.m_tap_internal_key = tap_data.internal_key;
                    }
                    if (!tap_data.merkle_root.IsNull()) {
                        psbt_in.m_tap_merkle_root = tap_data.merkle_root;
                    }
                    // If caller already annotated BIP32 leaf hashes, restrict inserted scripts to those leaves
                    std::set<uint256> allowed_leaf_hashes;
                    for (const auto& [xonly, leaf_origin] : psbt_in.m_tap_bip32_paths) {
                        const auto& leaf_hashes = leaf_origin.first;
                        allowed_leaf_hashes.insert(leaf_hashes.begin(), leaf_hashes.end());
                    }
                    const bool restrict_by_hash = !allowed_leaf_hashes.empty();
                    for (const auto& [leaf, control_blocks] : tap_data.scripts) {
                        const auto& script_bytes = leaf.first;
                        const int leaf_ver = leaf.second;
                        const uint256 leaf_hash = ComputeTapleafHash(
                            leaf_ver,
                            std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));
                        if (restrict_by_hash && allowed_leaf_hashes.count(leaf_hash) == 0) continue;
                        auto& dest_set = psbt_in.m_tap_scripts[leaf];
                        dest_set.insert(control_blocks.begin(), control_blocks.end());
                    }
                }
            }
        }

        if (psbt_in.m_tap_internal_key.IsNull() && !psbt_in.m_tap_bip32_paths.empty()) {
            psbt_in.m_tap_internal_key = psbt_in.m_tap_bip32_paths.begin()->first;
        }

        // As a last resort, fall back to the output key so downstream code sees some
        // value. Adaptor signing will still assert if the key is incorrect, but this
        // keeps watch-only PSBTs flowing through.
        if (psbt_in.m_tap_internal_key.IsNull()) {
            psbt_in.m_tap_internal_key = output_key;
        }
    }
}

// Moved outside anonymous namespace to be accessible from contract.cpp

UniValue RepoOfferToJSON(const RepoOfferRecord& record)
{
    const CTxDestination repay_dest = record.RepayDestination();

    UniValue obj = RepoOfferCanonicalJson(record, repay_dest);
    obj.pushKV("salt", record.salt.GetHex());
    obj.pushKV("commitment", record.commitment_hex);
    obj.pushKV("created_height", record.created_height);
    obj.pushKV("created_time", record.created_time);
    obj.pushKV("borrower_address", EncodeDestination(record.borrower_dest));
    obj.pushKV("lender_address", EncodeDestination(record.lender_dest));
    if (record.lender_internal_key.has_value()) {
        std::vector<unsigned char> internal_bytes(record.lender_internal_key->begin(), record.lender_internal_key->end());
        obj.pushKV("lender_internal_key", HexStr(internal_bytes));
    }
    if (record.borrower_internal_key.has_value()) {
        std::vector<unsigned char> internal_bytes(record.borrower_internal_key->begin(), record.borrower_internal_key->end());
        obj.pushKV("borrower_internal_key", HexStr(internal_bytes));
    }
    if (!record.maker_role.empty()) {
        obj.pushKV("maker_role", record.maker_role);
    }
    if (!record.fee_policy_strategy.empty()) {
        obj.pushKV("fee_policy_strategy", record.fee_policy_strategy);
    }
    if (record.lender_dest_override) {
        obj.pushKV("repay_address_override", EncodeDestination(*record.lender_dest_override));
    }
    if (record.vault_outpoint) {
        UniValue vault(UniValue::VOBJ);
        vault.pushKV("txid", record.vault_outpoint->hash.ToString());
        vault.pushKV("vout", record.vault_outpoint->n);
        vault.pushKV("amount", ValueFromAmount(record.vault_amount));
        obj.pushKV("vault", std::move(vault));
    }
    if (record.acceptance) {
        UniValue acceptance = RepoAcceptanceCanonicalJson(record, *record.acceptance);
        acceptance.pushKV("salt", record.acceptance->salt.GetHex());
        acceptance.pushKV("commitment", record.acceptance->commitment_hex);
        obj.pushKV("acceptance", std::move(acceptance));
    }
    if (record.repay_txid) {
        UniValue repay(UniValue::VOBJ);
        repay.pushKV("txid", record.repay_txid->ToString());
        if (record.repay_height) {
            repay.pushKV("height", *record.repay_height);
        }
        if (record.repay_time) {
            repay.pushKV("time", *record.repay_time);
        }
        obj.pushKV("repay_tx", std::move(repay));
    }
    if (record.default_txid) {
        UniValue def(UniValue::VOBJ);
        def.pushKV("txid", record.default_txid->ToString());
        if (record.default_height) {
            def.pushKV("height", *record.default_height);
        }
        if (record.default_time) {
            def.pushKV("time", *record.default_time);
        }
        obj.pushKV("default_tx", std::move(def));
    }
    return obj;
}

// Forward declaration
AssetLeg ParseSpotLeg(const UniValue& leg_obj);

RepoTerms ParseRepoTerms(const UniValue& terms_obj)
{
    RepoTerms terms;

    // Parse principal leg
    const UniValue& principal_leg_val = terms_obj.find_value("principal_leg");
    if (!principal_leg_val.isNull() && principal_leg_val.isObject()) {
        terms.principal_leg = ParseSpotLeg(principal_leg_val);
    } else {
        // Backward compatibility: parse from legacy flat fields
        AssetLeg principal;
        const UniValue& native_val = terms_obj.find_value("principal_is_native");
        principal.is_native = native_val.isNull() ? false : native_val.get_bool();

        const UniValue& asset_val = terms_obj.exists("principal_asset_id") ? terms_obj.find_value("principal_asset_id") : terms_obj.find_value("asset_id");
        if (!principal.is_native) {
            if (asset_val.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.principal_asset_id or terms.principal_leg is required");
            }
            const std::string asset_hex = asset_val.get_str();
            if (!IsHex(asset_hex) || asset_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.principal_asset_id must be 32-byte hex");
            }
            const auto asset_id = uint256::FromHex(asset_hex);
            if (!asset_id || asset_id->IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.principal_asset_id is invalid or reserved");
            }
            principal.asset_id = *asset_id;
        } else {
            principal.asset_id.SetNull();
        }

        const UniValue& principal_val = terms_obj.find_value("principal_units");
        if (principal_val.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.principal_units or terms.principal_leg is required");
        }
        principal.units = ParsePositiveUInt64(principal_val, "terms.principal_units");
        if (principal.units == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.principal_units must be > 0");
        }
        if (principal.is_native && principal.units > static_cast<uint64_t>(MAX_MONEY)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.principal_units exceeds MAX_MONEY");
        }
        terms.principal_leg = principal;
    }

    // Parse interest leg
    const UniValue& interest_leg_val = terms_obj.find_value("interest_leg");
    if (!interest_leg_val.isNull() && interest_leg_val.isObject()) {
        terms.interest_leg = ParseSpotLeg(interest_leg_val);
    } else {
        // Backward compatibility or default: same asset as principal
        AssetLeg interest;
        interest.is_native = terms.principal_leg.is_native;
        interest.asset_id = terms.principal_leg.asset_id;

        const UniValue& interest_val = terms_obj.find_value("interest_units");
        if (interest_val.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.interest_units or terms.interest_leg is required");
        }
        interest.units = ParsePositiveUInt64(interest_val, "terms.interest_units");
        if (interest.is_native && interest.units > static_cast<uint64_t>(MAX_MONEY)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.interest_units exceeds MAX_MONEY");
        }
        terms.interest_leg = interest;
    }

    // Validate interest matches principal asset if using legacy API
    if (interest_leg_val.isNull() &&
        (terms.interest_leg.is_native != terms.principal_leg.is_native ||
         terms.interest_leg.asset_id != terms.principal_leg.asset_id)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Legacy API requires interest asset to match principal asset. Use interest_leg for multi-asset");
    }

    // Parse collateral leg
    const UniValue& collateral_leg_val = terms_obj.find_value("collateral_leg");
    if (!collateral_leg_val.isNull() && collateral_leg_val.isObject()) {
        terms.collateral_leg = ParseSpotLeg(collateral_leg_val);
    } else {
        // Backward compatibility: parse from legacy BTC-only fields
        AssetLeg collateral;
        collateral.is_native = true;  // Legacy always BTC
        collateral.asset_id.SetNull();

        CAmount collateral_sats{0};
        const UniValue& collateral_sats_val = terms_obj.find_value("collateral_sats");
        if (!collateral_sats_val.isNull()) {
            collateral_sats = ParseSignedInt64(collateral_sats_val, "terms.collateral_sats");
        } else {
            const UniValue& collateral_btc_val = terms_obj.find_value("collateral_btc");
            if (collateral_btc_val.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.collateral_sats, terms.collateral_btc, or terms.collateral_leg is required");
            }
            collateral_sats = AmountFromValue(collateral_btc_val);
        }
        if (collateral_sats <= 0 || collateral_sats > MAX_MONEY) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Collateral must be within valid money range");
        }
        collateral.units = static_cast<uint64_t>(collateral_sats);
        terms.collateral_leg = collateral;
    }

    const UniValue& maturity_val = terms_obj.find_value("maturity_height");
    if (maturity_val.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.maturity_height is required");
    }
    terms.maturity_height = static_cast<uint32_t>(ParseSignedInt64(maturity_val, "terms.maturity_height"));
    if (terms.maturity_height <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.maturity_height must be positive");
    }

    const UniValue& safety_val = terms_obj.find_value("safety_k");
    terms.safety_k = safety_val.isNull() ? DEFAULT_REPO_SAFETY_K : static_cast<uint32_t>(ParsePositiveUInt64(safety_val, "terms.safety_k"));

    const UniValue& reorg_val = terms_obj.find_value("reorg_conf");
    terms.reorg_conf = reorg_val.isNull() ? DEFAULT_REPO_REORG_CONF : static_cast<uint32_t>(ParsePositiveUInt64(reorg_val, "terms.reorg_conf"));
    if (terms.reorg_conf == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.reorg_conf must be > 0");
    }

    return terms;
}

AssetLeg ParseSpotLeg(const UniValue& leg_obj)
{
    AssetLeg leg;
    const UniValue& native_val = leg_obj.find_value("is_native");
    leg.is_native = native_val.isNull() ? false : native_val.get_bool();

    if (!leg.is_native) {
        const UniValue& asset_val = leg_obj.find_value("asset_id");
        if (asset_val.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id is required for non-native leg");
        }
        const std::string asset_hex = asset_val.get_str();
        if (!IsHex(asset_hex) || asset_hex.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be 32-byte hex");
        }
        const auto asset_id = uint256::FromHex(asset_hex);
        if (!asset_id || asset_id->IsNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id is invalid or reserved");
        }
        leg.asset_id = *asset_id;
    } else {
        leg.asset_id.SetNull();
    }

    const UniValue& units_val = leg_obj.find_value("units");
    if (units_val.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "units is required");
    }
    leg.units = ParsePositiveUInt64(units_val, "units");
    if (leg.units == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "units must be > 0");
    }

    if (leg.is_native && leg.units > static_cast<uint64_t>(MAX_MONEY)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Native leg units exceed MAX_MONEY");
    }

    // Parse decimals field (GUI stores this to preserve precision)
    const UniValue& decimals_val = leg_obj.find_value("decimals");
    if (!decimals_val.isNull()) {
        int dec = decimals_val.getInt<int>();
        if (dec < 0 || dec > 18) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals must be between 0 and 18");
        }
        leg.decimals = dec;
    }

    return leg;
}

SpotTerms ParseSpotTerms(const UniValue& terms_obj)
{
    SpotTerms terms;
    const UniValue& alice_leg_val = terms_obj.find_value("alice_leg");
    if (!alice_leg_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "alice_leg is required");
    }
    terms.alice_deliver = ParseSpotLeg(alice_leg_val.get_obj());

    const UniValue& bob_leg_val = terms_obj.find_value("bob_leg");
    if (!bob_leg_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bob_leg is required");
    }
    terms.bob_deliver = ParseSpotLeg(bob_leg_val.get_obj());

    // Optional ICU commitment requirement hint from RPC terms.
    const UniValue& require_commitment_val = terms_obj.find_value("require_commitment_proof");
    if (!require_commitment_val.isNull()) {
        if (!require_commitment_val.isBool()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "require_commitment_proof must be boolean when provided");
        }
        terms.require_commitment_proof = require_commitment_val.get_bool();
    }

    return terms;
}

CTxDestination ParseDestinationRequired(const UniValue& obj, const std::string& key)
{
    const UniValue& value = obj.find_value(key);
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is required", key));
    }
    const std::string addr = value.get_str();
    const CTxDestination dest = DecodeDestination(addr);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid address for %s", key));
    }
    return dest;
}

std::vector<RPCResult> RepoTermsResultDescription()
{
    return {
        // New structured leg format
        {RPCResult::Type::OBJ, "principal_leg", "Principal asset leg",
            {
                {RPCResult::Type::BOOL, "is_native", "True when the leg is denominated in BTC"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "32-byte asset identifier when non-native"},
                {RPCResult::Type::NUM, "units", "Exact units (sats or asset units) delivered"},
            }
        },
        {RPCResult::Type::OBJ, "interest_leg", "Interest asset leg",
            {
                {RPCResult::Type::BOOL, "is_native", "True when the leg is denominated in BTC"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "32-byte asset identifier when non-native"},
                {RPCResult::Type::NUM, "units", "Exact units (sats or asset units) delivered"},
            }
        },
        {RPCResult::Type::OBJ, "collateral_leg", "Collateral asset leg",
            {
                {RPCResult::Type::BOOL, "is_native", "True when the leg is denominated in BTC"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "32-byte asset identifier when non-native"},
                {RPCResult::Type::NUM, "units", "Exact units (sats or asset units) delivered"},
            }
        },

        // Legacy flat fields (for backward compatibility)
        {RPCResult::Type::BOOL, "principal_is_native", "True when the principal leg is denominated in BTC"},
        {RPCResult::Type::STR_HEX, "principal_asset_id", /*optional=*/true, "32-byte asset identifier for non-native principal legs"},
        {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Compatibility alias for principal asset id (null when native)"},
        {RPCResult::Type::NUM, "principal_units", "Principal units (or sats when native) delivered at open"},
        {RPCResult::Type::NUM, "interest_units", "Fixed interest units owed by the borrower"},
        {RPCResult::Type::NUM, "repay_units", "Total units owed at repayment"},
        {RPCResult::Type::STR_AMOUNT, "collateral_sats", /*optional=*/true, "BTC collateral amount (only when collateral is native)"},
        {RPCResult::Type::NUM, "collateral_sats_raw", /*optional=*/true, "Collateral in satoshis (only when collateral is native)"},
        {RPCResult::Type::NUM, "maturity_height", "Block height activating the default branch"},
        {RPCResult::Type::NUM, "safety_k", "Pre-maturity safety window used for UX warnings"},
        {RPCResult::Type::NUM, "reorg_conf", "Confirmations required past maturity before default sweep"},
    };
}

std::vector<RPCResult> RepoFsPolicyResultDescription()
{
    return {
        {RPCResult::Type::BOOL, "require_adaptor", "Require adaptor signatures (Fair-Sign)"},
        {RPCResult::Type::BOOL, "reveal_lockstep", "Enforce lock-step final signature reveal"},
    };
}

std::vector<RPCResult> RepoSinksResultDescription()
{
    return {
        {RPCResult::Type::STR_HEX, "collateral_spk", "Hex-encoded Taproot script for the collateral vault"},
        {RPCResult::Type::STR_HEX, "repay_spk", "Hex-encoded Taproot script for the repayment sink"},
    };
}

std::vector<RPCResult> RepoSinksAckResultDescription()
{
    return {
        {RPCResult::Type::STR_HEX, "repay_spk", "Hex-encoded Taproot repayment script acknowledged by the counterparty"},
    };
}

std::vector<RPCResult> RepoAcceptanceResultDescription()
{
    return {
        {RPCResult::Type::NUM, "version", "Acceptance payload version"},
        {RPCResult::Type::STR, "contract_type", "Contract type (repo)"},
        {RPCResult::Type::STR_HEX, "offer_id", "Offer identifier"},
        {RPCResult::Type::STR_HEX, "id", "Acceptance identifier"},
        {RPCResult::Type::OBJ, "sinks_ack", "Acknowledged sink set", RepoSinksAckResultDescription()},
        {RPCResult::Type::OBJ, "fs_policy_ack", "Acknowledged Fair-Sign policy", RepoFsPolicyResultDescription()},
        {RPCResult::Type::STR_HEX, "fs_tx_adaptor_point", "Counterparty adaptor point (x-only, hex)"},
        {RPCResult::Type::STR_HEX, "salt", "Acceptance salt"},
        {RPCResult::Type::STR_HEX, "commitment", "Acceptance commitment"},
        {RPCResult::Type::STR_HEX, "borrower_internal_key", /*optional=*/true, "Borrower's internal key for vault construction (x-only, hex)"},
        {RPCResult::Type::STR_HEX, "lender_internal_key", /*optional=*/true, "Untweaked lender key (x-only, hex)"},
        {RPCResult::Type::ARR, "repay_templates", /*optional=*/true, "Pre-built repayment delivery templates",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "purpose", "Template purpose (repay_principal, repay_interest, or repay_merged)"},
                        {RPCResult::Type::BOOL, "is_native", "Whether repayment is native BTC"},
                        {RPCResult::Type::NUM, "units", "Raw units represented by the template"},
                        {RPCResult::Type::STR_HEX, "script_pubkey", "Destination scriptPubKey"},
                        {RPCResult::Type::STR_HEX, "commitment", "Commitment hash over script and TLV metadata"},
                        {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Asset identifier when non-native"},
                        {RPCResult::Type::STR_HEX, "vext", /*optional=*/true, "Asset TLV bytes when non-native"},
                    }
                },
            }
        },
        {RPCResult::Type::OBJ, "default_collateral_template", /*optional=*/true, "Pre-built collateral sweep template",
            {
                {RPCResult::Type::STR, "purpose", "Template purpose (default_collateral)"},
                {RPCResult::Type::BOOL, "is_native", "Whether sweep is native BTC"},
                {RPCResult::Type::NUM, "units", "Raw units represented by the template"},
                {RPCResult::Type::STR_HEX, "script_pubkey", "Destination scriptPubKey"},
                {RPCResult::Type::STR_HEX, "commitment", "Commitment hash over script and TLV metadata"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Asset identifier when non-native"},
                {RPCResult::Type::STR_HEX, "vext", /*optional=*/true, "Asset TLV bytes when non-native"},
            }
        },
    };
}

std::vector<RPCResult> RepoOfferResultDescription()
{
    return {
        {RPCResult::Type::NUM, "version", "Offer payload version"},
        {RPCResult::Type::STR, "contract_type", "Contract type (repo)"},
        {RPCResult::Type::STR_HEX, "id", "Offer identifier"},
        {RPCResult::Type::OBJ, "terms", "Canonicalised repo terms", RepoTermsResultDescription()},
        {RPCResult::Type::OBJ, "sinks", "Canonical sink set", RepoSinksResultDescription()},
        {RPCResult::Type::OBJ, "fs_policy", "Fair-Sign policy", RepoFsPolicyResultDescription()},
        {RPCResult::Type::STR_HEX, "fs_tx_adaptor_point", "Global adaptor point (x-only, hex)"},
        {RPCResult::Type::STR_HEX, "salt", "Salt used when computing the commitment"},
        {RPCResult::Type::STR_HEX, "commitment", "Commitment hash"},
        {RPCResult::Type::NUM, "created_height", "Wallet chain height when the offer was recorded"},
        {RPCResult::Type::NUM_TIME, "created_time", "Wall-clock creation timestamp"},
        {RPCResult::Type::STR, "borrower_address", "Borrower covenant address (bech32m)"},
        {RPCResult::Type::STR, "lender_address", "Initial repayment address (bech32m)"},
        {RPCResult::Type::STR_HEX, "lender_internal_key", /*optional=*/true, "Untweaked lender key used in default covenant leaf (x-only, hex)"},
        {RPCResult::Type::STR_HEX, "borrower_internal_key", /*optional=*/true, "Untweaked borrower key (x-only, hex)"},
        {RPCResult::Type::STR, "maker_role", /*optional=*/true, "Which side created the offer (borrower or lender)"},
        {RPCResult::Type::STR, "fee_policy_strategy", /*optional=*/true, "Fee policy strategy used for the contract"},
        {RPCResult::Type::STR, "repay_address_override", /*optional=*/true, "Current repayment override"},
        {RPCResult::Type::OBJ, "vault", /*optional=*/true, "Tracked collateral vault outpoint once known",
            {
                {RPCResult::Type::STR_HEX, "txid", "Vault funding transaction id"},
                {RPCResult::Type::NUM, "vout", "Vault output index"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Vault amount in BTC"},
            }
        },
        {RPCResult::Type::OBJ, "acceptance", /*optional=*/true, "Counterparty acceptance payload", RepoAcceptanceResultDescription()},
        {RPCResult::Type::OBJ, "repay_tx", /*optional=*/true, "Repayment transaction details once detected",
            {
                {RPCResult::Type::STR_HEX, "txid", "Repayment transaction id"},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "Block height when repayment was confirmed"},
                {RPCResult::Type::NUM_TIME, "time", /*optional=*/true, "Timestamp when repayment was confirmed"},
            }
        },
        {RPCResult::Type::OBJ, "default_tx", /*optional=*/true, "Default/liquidation transaction details once detected",
            {
                {RPCResult::Type::STR_HEX, "txid", "Default transaction id"},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "Block height when default was confirmed"},
                {RPCResult::Type::NUM_TIME, "time", /*optional=*/true, "Timestamp when default was confirmed"},
            }
        },
    };
}

std::vector<RPCResult> RepoTaprootResultDescription()
{
    return {
        {RPCResult::Type::STR_HEX, "output_key", "Tweaked Taproot output key"},
        {RPCResult::Type::STR_HEX, "internal_key", "Internal Taproot key"},
        {RPCResult::Type::STR_HEX, "script_pubkey", "Hex-encoded covenant scriptPubKey"},
        {RPCResult::Type::ARR, "tree", "Taproot script tree",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "depth", "Depth of the leaf"},
                        {RPCResult::Type::NUM, "leaf_version", "Taproot leaf version"},
                        {RPCResult::Type::STR_HEX, "script", "Hex-encoded leaf script"},
                    }
                }
            }
        },
    };
}

std::vector<RPCResult> RepoDeadlinesResultDescription()
{
    return {
        {RPCResult::Type::NUM, "maturity_height", "Block height that unlocks the default branch"},
        {RPCResult::Type::NUM, "safety_k", "Safety window (in blocks) prior to maturity"},
        {RPCResult::Type::NUM, "reorg_conf", "Confirmations required past maturity before default sweep"},
    };
}

[[maybe_unused]] std::vector<RPCResult> RepoStatusResultDescription()
{
    return {
        {RPCResult::Type::STR_HEX, "id", "Contract identifier"},
        {RPCResult::Type::STR, "kind", "Contract kind (currently always 'repo')"},
        {RPCResult::Type::STR, "state", "Current state (proposed|accepted)"},
        {RPCResult::Type::OBJ, "offer", "Latest offer snapshot", RepoOfferResultDescription()},
        {RPCResult::Type::OBJ, "deadlines", "Contract deadlines", RepoDeadlinesResultDescription()},
        {RPCResult::Type::ARR, "utxos", "Tracked covenant UTXOs",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "Funding transaction id"},
                        {RPCResult::Type::NUM, "vout", "Output index"},
                        {RPCResult::Type::STR, "role", /*optional=*/true, "Role of the output within the contract"},
                    }
                }
            }
        },
        {RPCResult::Type::NUM, "confs", "Confirmations for the contract registration height"},
    };
}

std::vector<RPCResult> SpotLegResultDescription()
{
    return {
        {RPCResult::Type::BOOL, "is_native", "True when the leg is denominated in BTC"},
        {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "32-byte asset identifier when non-native"},
        {RPCResult::Type::NUM, "units", "Exact units (sats or asset units) delivered"},
    };
}

std::vector<RPCResult> SpotTermsResultDescription()
{
    return {
        {RPCResult::Type::OBJ, "alice_leg", "Assets Alice delivers to Bob", SpotLegResultDescription()},
        {RPCResult::Type::OBJ, "bob_leg", "Assets Bob delivers to Alice", SpotLegResultDescription()},
    };
}

std::vector<RPCResult> SpotSinksResultDescription()
{
    return {
        {RPCResult::Type::STR_HEX, "alice_recv_spk", "Hex-encoded script where Alice receives Bob's leg"},
        {RPCResult::Type::STR_HEX, "bob_recv_spk", /*optional=*/true, "Hex-encoded script where Bob receives Alice's leg"},
    };
}

std::vector<RPCResult> SpotSinksAckResultDescription()
{
    return {
        {RPCResult::Type::STR_HEX, "bob_recv_spk", "Hex-encoded script acknowledged by Bob for receiving assets"},
    };
}

std::vector<RPCResult> SpotAcceptanceResultDescription()
{
    return {
        {RPCResult::Type::NUM, "version", "Acceptance payload version"},
        {RPCResult::Type::STR, "contract_type", "Contract type (spot)"},
        {RPCResult::Type::STR_HEX, "offer_id", "Offer identifier"},
        {RPCResult::Type::STR_HEX, "id", "Acceptance identifier"},
        {RPCResult::Type::OBJ, "sinks_ack", "Acknowledged sink set", SpotSinksAckResultDescription()},
        {RPCResult::Type::OBJ, "fs_policy_ack", "Acknowledged Fair-Sign policy", RepoFsPolicyResultDescription()},
        {RPCResult::Type::STR_HEX, "fs_tx_adaptor_point", "Counterparty adaptor point (x-only, hex)"},
        {RPCResult::Type::STR_HEX, "salt", "Acceptance salt"},
        {RPCResult::Type::STR_HEX, "commitment", "Acceptance commitment"},
    };
}

std::vector<RPCResult> SpotOfferResultDescription()
{
    return {
        {RPCResult::Type::NUM, "version", "Offer payload version"},
        {RPCResult::Type::STR, "contract_type", "Contract type (spot)"},
        {RPCResult::Type::STR_HEX, "id", "Offer identifier"},
        {RPCResult::Type::OBJ, "terms", "Spot swap legs", SpotTermsResultDescription()},
        {RPCResult::Type::OBJ, "sinks", "Receiving scripts", SpotSinksResultDescription()},
        {RPCResult::Type::OBJ, "fs_policy", "Fair-Sign policy", RepoFsPolicyResultDescription()},
        {RPCResult::Type::STR_HEX, "fs_tx_adaptor_point", "Global adaptor point (x-only, hex)"},
        {RPCResult::Type::STR_HEX, "salt", "Salt used for the commitment"},
        {RPCResult::Type::STR_HEX, "commitment", "Offer commitment"},
        {RPCResult::Type::NUM, "created_height", "Wallet chain height when the offer was recorded"},
        {RPCResult::Type::NUM_TIME, "created_time", "Wall-clock creation timestamp"},
        {RPCResult::Type::STR, "alice_address", "Bech32m address Alice receives on"},
        {RPCResult::Type::STR, "bob_address_hint", /*optional=*/true, "Bob's receive address if provided"},
        {RPCResult::Type::OBJ_DYN, "acceptance", /*optional=*/true, "Counterparty acceptance payload",
            {
                {RPCResult::Type::ELISION, "", ""},
            }
        },
    };
}

RepoAcceptanceRecord ParseRepoAcceptanceObject(const RepoOfferRecord& offer,
                                               const UniValue& acceptance_obj);

RepoOfferRecord ParseRepoOfferObject(const UniValue& offer_obj,
                                     int fallback_height,
                                     int64_t fallback_time)
{
    if (!offer_obj.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer must be an object");
    }

    RepoOfferRecord record;
    record.created_height = fallback_height;
    record.created_time = fallback_time;

    const UniValue& version_val = offer_obj.find_value("version");
    const int version = version_val.isNull() ? 1 : version_val.getInt<int>();
    if (version != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported offer.version");
    }

    const UniValue& type_val = offer_obj.find_value("contract_type");
    if (!type_val.isStr() || type_val.get_str() != "repo") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.contract_type must be 'repo'");
    }

    const UniValue& id_val = offer_obj.find_value("id");
    if (!id_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.id is required");
    }
    auto offer_id_opt = uint256::FromHex(id_val.get_str());
    if (!offer_id_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id hex");
    }
    record.offer_id = *offer_id_opt;

    const UniValue& terms_val = offer_obj.find_value("terms");
    if (!terms_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.terms must be an object");
    }
    record.terms = ParseRepoTerms(terms_val.get_obj());

    const UniValue& sinks_val = offer_obj.find_value("sinks");
    if (!sinks_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.sinks must be an object");
    }
    record.borrower_dest = ParseScriptDestinationHex(sinks_val.get_obj(), "collateral_spk");
    CTxDestination repay_dest = ParseScriptDestinationHex(sinks_val.get_obj(), "repay_spk");
    record.lender_dest = repay_dest;

    record.fs_policy = ParseFairSignPolicy(offer_obj, "fs_policy");
    record.fs_tx_adaptor_point = ParseXOnlyPubKeyHex(offer_obj, "fs_tx_adaptor_point");

    const UniValue& salt_val = offer_obj.find_value("salt");
    if (!salt_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.salt is required");
    }
    auto salt_opt = uint256::FromHex(salt_val.get_str());
    if (!salt_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid salt hex");
    }
    record.salt = *salt_opt;

    const UniValue& commitment_val = offer_obj.find_value("commitment");
    if (!commitment_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.commitment is required");
    }
    record.commitment_hex = commitment_val.get_str();

    const UniValue& borrower_addr_val = offer_obj.find_value("borrower_address");
    if (borrower_addr_val.isStr()) {
        CTxDestination decoded = DecodeDestination(borrower_addr_val.get_str());
        if (IsValidDestination(decoded) && decoded != record.borrower_dest) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "borrower_address does not match sinks.collateral_spk");
        }
    }

    const UniValue& lender_addr_val = offer_obj.find_value("lender_address");
    if (lender_addr_val.isStr()) {
        CTxDestination decoded = DecodeDestination(lender_addr_val.get_str());
        if (IsValidDestination(decoded) && decoded != record.lender_dest) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "lender_address does not match sinks.repay_spk");
        }
    }

    const UniValue& lender_internal_val = offer_obj.find_value("lender_internal_key");
    if (lender_internal_val.isStr()) {
        record.lender_internal_key = ParseXOnlyPubKeyHex(offer_obj, "lender_internal_key");
    } else if (!lender_internal_val.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.lender_internal_key must be a 32-byte hex string when provided");
    }

    const UniValue& borrower_internal_val = offer_obj.find_value("borrower_internal_key");
    if (borrower_internal_val.isStr()) {
        record.borrower_internal_key = ParseXOnlyPubKeyHex(offer_obj, "borrower_internal_key");
    } else if (!borrower_internal_val.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.borrower_internal_key must be a 32-byte hex string when provided");
    }

    const UniValue& maker_role_val = offer_obj.find_value("maker_role");
    if (maker_role_val.isStr()) {
        record.maker_role = maker_role_val.get_str();
    }

    const UniValue& fee_policy_val = offer_obj.find_value("fee_policy_strategy");
    if (fee_policy_val.isStr()) {
        record.fee_policy_strategy = fee_policy_val.get_str();
    }

    const UniValue& override_val = offer_obj.find_value("repay_address_override");
    if (override_val.isStr()) {
        CTxDestination override_dest = DecodeDestination(override_val.get_str());
        if (!IsValidDestination(override_dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid repay_address_override");
        }
        record.lender_dest_override = override_dest;
    }

    const UniValue& created_height_val = offer_obj.find_value("created_height");
    if (created_height_val.isNum()) {
        record.created_height = created_height_val.getInt<int>();
    }
    const UniValue& created_time_val = offer_obj.find_value("created_time");
    if (created_time_val.isNum()) {
        record.created_time = created_time_val.getInt<int64_t>();
    }

    const UniValue& vault_val = offer_obj.find_value("vault");
    if (vault_val.isObject()) {
        const UniValue& txid_val = vault_val.find_value("txid");
        const UniValue& vout_val = vault_val.find_value("vout");
        const UniValue& amount_val = vault_val.find_value("amount");
        if (txid_val.isStr() && vout_val.isNum()) {
            const auto txhash = Txid::FromHex(txid_val.get_str());
            if (!txhash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vault.txid invalid");
            }
            record.vault_outpoint = COutPoint(*txhash, vout_val.getInt<uint32_t>());
            if (amount_val.isNum() || amount_val.isStr()) {
                record.vault_amount = AmountFromValue(amount_val);
            }
        }
    }

    const std::string expected_commitment = RepoOfferCommitmentHex(record, record.lender_dest);
    if (expected_commitment != record.commitment_hex) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer commitment mismatch");
    }

    const UniValue& acceptance_val = offer_obj.find_value("acceptance");
    if (acceptance_val.isObject()) {
        RepoAcceptanceRecord acceptance = ParseRepoAcceptanceObject(record, acceptance_val.get_obj());
        if (acceptance.repay_dest_ack != record.lender_dest) {
            record.lender_dest_override = acceptance.repay_dest_ack;
        }
        record.acceptance = acceptance;
    }

    return record;
}

RepoAcceptanceRecord ParseRepoAcceptanceObject(const RepoOfferRecord& offer,
                                               const UniValue& acceptance_obj)
{
    if (!acceptance_obj.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance must be an object");
    }

    RepoAcceptanceRecord acceptance;

    const UniValue& version_val = acceptance_obj.find_value("version");
    const int version = version_val.isNull() ? 1 : version_val.getInt<int>();
    if (version != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported acceptance.version");
    }

    const UniValue& contract_type_val = acceptance_obj.find_value("contract_type");
    if (!contract_type_val.isStr() || contract_type_val.get_str() != "repo") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.contract_type must be 'repo'");
    }

    const UniValue& offer_id_val = acceptance_obj.find_value("offer_id");
    if (!offer_id_val.isStr() || offer_id_val.get_str() != offer.offer_id.GetHex()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.offer_id does not match offer");
    }

    const UniValue& id_val = acceptance_obj.find_value("id");
    if (!id_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.id is required");
    }
    auto acceptance_id_opt = uint256::FromHex(id_val.get_str());
    if (!acceptance_id_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid acceptance_id hex");
    }
    acceptance.acceptance_id = *acceptance_id_opt;

    const UniValue& sinks_ack_val = acceptance_obj.find_value("sinks_ack");
    if (!sinks_ack_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.sinks_ack must be an object");
    }
    acceptance.repay_dest_ack = ParseScriptDestinationHex(sinks_ack_val.get_obj(), "repay_spk");

    acceptance.fs_policy = ParseFairSignPolicy(acceptance_obj, "fs_policy_ack");
    if (acceptance.fs_policy.require_adaptor != offer.fs_policy.require_adaptor ||
        acceptance.fs_policy.reveal_lockstep != offer.fs_policy.reveal_lockstep) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.fs_policy_ack must match offer fs_policy");
    }
    acceptance.fs_tx_adaptor_point = ParseXOnlyPubKeyHex(acceptance_obj, "fs_tx_adaptor_point");

    const UniValue& templates_val = acceptance_obj.find_value("repay_templates");
    if (!templates_val.isNull()) {
        if (!templates_val.isArray()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates must be an array when provided");
        }
        for (size_t i = 0; i < templates_val.size(); ++i) {
            const UniValue& entry = templates_val[i];
            if (!entry.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates elements must be objects");
            }

            const UniValue& purpose_val = entry.find_value("purpose");
            if (!purpose_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates purpose is required");
            }
            const std::string purpose = purpose_val.get_str();

            const UniValue& native_val = entry.find_value("is_native");
            if (!native_val.isBool()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates[].is_native must be bool");
            }
            const bool is_native = native_val.get_bool();

            const UniValue& units_val = entry.find_value("units");
            if (!units_val.isNum()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates[].units must be numeric");
            }
            uint64_t units = units_val.getInt<uint64_t>();

            const UniValue& script_val = entry.find_value("script_pubkey");
            if (!script_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates[].script_pubkey required");
            }
            const std::vector<unsigned char> script_bytes = ParseHex(script_val.get_str());
            CScript script(script_bytes.begin(), script_bytes.end());
            if (script != GetScriptForDestination(acceptance.repay_dest_ack)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates script mismatch with repayment sink");
            }

            AssetDeliveryTemplate tmpl;
            tmpl.is_native = is_native;
            tmpl.units = units;
            tmpl.script_pubkey = script;
            if (!is_native) {
                const UniValue& asset_val = entry.find_value("asset_id");
                if (!asset_val.isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates[].asset_id required for non-native");
                }
                auto asset_opt = uint256::FromHex(asset_val.get_str());
                if (!asset_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates[].asset_id invalid");
                }
                tmpl.asset_id = *asset_opt;

                const UniValue& vext_val = entry.find_value("vext");
                if (!vext_val.isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates[].vext required for non-native");
                }
                tmpl.vext = ParseHex(vext_val.get_str());
            } else {
                tmpl.asset_id.SetNull();
                tmpl.vext.clear();
            }

            tmpl.commitment = ComputeAssetDeliveryCommitment(tmpl);

            const UniValue& commitment_val = entry.find_value("commitment");
            if (commitment_val.isStr()) {
                auto commitment_opt = uint256::FromHex(commitment_val.get_str());
                if (!commitment_opt || *commitment_opt != tmpl.commitment) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates commitment mismatch");
                }
            }

            if (purpose == "repay_principal" || purpose == "repay_merged") {
                acceptance.repay_principal_template = tmpl;
                if (purpose == "repay_merged") {
                    acceptance.repay_interest_template.reset();
                }
            } else if (purpose == "repay_interest") {
                acceptance.repay_interest_template = tmpl;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.repay_templates purpose must be repay_principal, repay_interest, or repay_merged");
            }
        }
    }

    const UniValue& collateral_template_val = acceptance_obj.find_value("default_collateral_template");
    if (!collateral_template_val.isNull()) {
        if (!collateral_template_val.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template must be an object");
        }

        const UniValue& purpose_val = collateral_template_val.find_value("purpose");
        if (!purpose_val.isStr() || purpose_val.get_str() != "default_collateral") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.purpose must be 'default_collateral'");
        }

        const UniValue& native_val = collateral_template_val.find_value("is_native");
        if (!native_val.isBool()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.is_native must be bool");
        }
        const bool is_native = native_val.get_bool();

        const UniValue& units_val = collateral_template_val.find_value("units");
        if (!units_val.isNum()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.units must be numeric");
        }
        uint64_t units = units_val.getInt<uint64_t>();

        const UniValue& script_val = collateral_template_val.find_value("script_pubkey");
        if (!script_val.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.script_pubkey required");
        }
        const std::vector<unsigned char> script_bytes = ParseHex(script_val.get_str());
        CScript script(script_bytes.begin(), script_bytes.end());
        if (script != GetScriptForDestination(acceptance.repay_dest_ack)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template script mismatch with repayment sink");
        }

        AssetDeliveryTemplate tmpl;
        tmpl.is_native = is_native;
        tmpl.units = units;
        tmpl.script_pubkey = script;
        if (!is_native) {
            const UniValue& asset_val = collateral_template_val.find_value("asset_id");
            if (!asset_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.asset_id required for non-native");
            }
            auto asset_opt = uint256::FromHex(asset_val.get_str());
            if (!asset_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.asset_id invalid");
            }
            tmpl.asset_id = *asset_opt;

            const UniValue& vext_val = collateral_template_val.find_value("vext");
            if (!vext_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template.vext required for non-native");
            }
            tmpl.vext = ParseHex(vext_val.get_str());
        } else {
            tmpl.asset_id.SetNull();
            tmpl.vext.clear();
        }

        tmpl.commitment = ComputeAssetDeliveryCommitment(tmpl);

        const UniValue& commitment_val2 = collateral_template_val.find_value("commitment");
        if (commitment_val2.isStr()) {
            auto commitment_opt = uint256::FromHex(commitment_val2.get_str());
            if (!commitment_opt || *commitment_opt != tmpl.commitment) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.default_collateral_template commitment mismatch");
            }
        }

        acceptance.default_collateral_template = tmpl;
    }

    const UniValue& salt_val = acceptance_obj.find_value("salt");
    if (!salt_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.salt is required");
    }
    auto salt_opt = uint256::FromHex(salt_val.get_str());
    if (!salt_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid salt hex");
    }
    acceptance.salt = *salt_opt;

    const UniValue& commitment_val = acceptance_obj.find_value("commitment");
    if (!commitment_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.commitment is required");
    }
    const std::string commitment_hex = commitment_val.get_str();

    const uint256 expected = ComputeRepoAcceptanceCommitment(offer, acceptance);
    if (expected.GetHex() != commitment_hex) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance commitment mismatch");
    }

    acceptance.commitment_hex = commitment_hex;
    return acceptance;
}


SpotAcceptanceRecord ParseSpotAcceptanceObject(const SpotOfferRecord& offer,
                                               const UniValue& acceptance_obj)
{
    if (!acceptance_obj.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance must be an object");
    }

    SpotAcceptanceRecord acceptance;

    const UniValue& version_val = acceptance_obj.find_value("version");
    const int version = version_val.isNull() ? 1 : version_val.getInt<int>();
    if (version != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported acceptance.version");
    }

    const UniValue& type_val = acceptance_obj.find_value("contract_type");
    if (!type_val.isStr() || type_val.get_str() != "spot") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.contract_type must be 'spot'");
    }

    const UniValue& offer_id_val = acceptance_obj.find_value("offer_id");
    if (!offer_id_val.isStr() || offer_id_val.get_str() != offer.offer_id.GetHex()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.offer_id does not match offer");
    }

    const UniValue& id_val = acceptance_obj.find_value("id");
    if (!id_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.id is required");
    }
    auto acceptance_id_opt = uint256::FromHex(id_val.get_str());
    if (!acceptance_id_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid acceptance_id hex");
    }
    acceptance.acceptance_id = *acceptance_id_opt;

    const UniValue& sinks_ack_val = acceptance_obj.find_value("sinks_ack");
    if (!sinks_ack_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.sinks_ack must be an object");
    }
    acceptance.bob_recv_dest = ParseScriptDestinationHex(sinks_ack_val.get_obj(), "bob_recv_spk");

    acceptance.fs_policy = ParseFairSignPolicy(acceptance_obj, "fs_policy_ack");
    if (acceptance.fs_policy.require_adaptor != offer.fs_policy.require_adaptor ||
        acceptance.fs_policy.reveal_lockstep != offer.fs_policy.reveal_lockstep) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.fs_policy_ack must match offer fs_policy");
    }
    acceptance.fs_tx_adaptor_point = ParseXOnlyPubKeyHex(acceptance_obj, "fs_tx_adaptor_point");

    const UniValue& salt_val = acceptance_obj.find_value("salt");
    if (!salt_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.salt is required");
    }
    auto salt_opt = uint256::FromHex(salt_val.get_str());
    if (!salt_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid salt hex");
    }
    acceptance.salt = *salt_opt;

    const UniValue& commitment_val = acceptance_obj.find_value("commitment");
    if (!commitment_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.commitment is required");
    }
    const std::string commitment_hex = commitment_val.get_str();

    const uint256 expected = ComputeSpotAcceptanceCommitment(offer, acceptance);
    if (expected.GetHex() != commitment_hex) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance commitment mismatch");
    }

    acceptance.commitment_hex = commitment_hex;
    return acceptance;
}

SpotOfferRecord ParseSpotOfferObject(const UniValue& offer_obj,
                                     int fallback_height,
                                     int64_t fallback_time)
{
    if (!offer_obj.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer must be an object");
    }

    SpotOfferRecord record;
    record.created_height = fallback_height;
    record.created_time = fallback_time;

    const UniValue& version_val = offer_obj.find_value("version");
    const int version = version_val.isNull() ? 1 : version_val.getInt<int>();
    if (version != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported offer.version");
    }

    const UniValue& type_val = offer_obj.find_value("contract_type");
    if (!type_val.isStr() || type_val.get_str() != "spot") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.contract_type must be 'spot'");
    }

    const UniValue& id_val = offer_obj.find_value("id");
    if (!id_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.id is required");
    }
    auto offer_id_opt = uint256::FromHex(id_val.get_str());
    if (!offer_id_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id hex");
    }
    record.offer_id = *offer_id_opt;

    const UniValue& terms_val = offer_obj.find_value("terms");
    if (!terms_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.terms must be an object");
    }
    record.terms = ParseSpotTerms(terms_val.get_obj());

    const UniValue& sinks_val = offer_obj.find_value("sinks");
    if (!sinks_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.sinks must be an object");
    }
    record.alice_recv_dest = ParseScriptDestinationHex(sinks_val.get_obj(), "alice_recv_spk");
    const UniValue& bob_spk_val = sinks_val.get_obj().find_value("bob_recv_spk");
    if (!bob_spk_val.isNull()) {
        record.bob_recv_dest_hint = ParseScriptDestinationHex(sinks_val.get_obj(), "bob_recv_spk");
    }

    record.fs_policy = ParseFairSignPolicy(offer_obj, "fs_policy");
    record.fs_tx_adaptor_point = ParseXOnlyPubKeyHex(offer_obj, "fs_tx_adaptor_point");

    const UniValue& salt_val = offer_obj.find_value("salt");
    if (!salt_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.salt is required");
    }
    auto salt_opt = uint256::FromHex(salt_val.get_str());
    if (!salt_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid salt hex");
    }
    record.salt = *salt_opt;

    const UniValue& commitment_val = offer_obj.find_value("commitment");
    if (!commitment_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.commitment is required");
    }
    const std::string commitment_hex = commitment_val.get_str();

    const uint256 expected = ComputeSpotOfferCommitment(record);
    if (expected.GetHex() != commitment_hex) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer commitment mismatch");
    }
    record.commitment_hex = commitment_hex;

    const UniValue& alice_addr_val = offer_obj.find_value("alice_address");
    if (alice_addr_val.isStr()) {
        CTxDestination dest = DecodeDestination(alice_addr_val.get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid alice_address");
        }
        if (GetScriptForDestination(dest) != GetScriptForDestination(record.alice_recv_dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "alice_address does not match sinks.alice_recv_spk");
        }
    }

    const UniValue& bob_addr_val = offer_obj.find_value("bob_address_hint");
    if (bob_addr_val.isStr()) {
        CTxDestination dest = DecodeDestination(bob_addr_val.get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid bob_address_hint");
        }
        record.bob_recv_dest_hint = dest;
    }

    const UniValue& acceptance_val = offer_obj.find_value("acceptance");
    if (acceptance_val.isObject()) {
        SpotAcceptanceRecord acceptance = ParseSpotAcceptanceObject(record, acceptance_val.get_obj());
        record.acceptance = acceptance;
        record.bob_recv_dest_hint = acceptance.bob_recv_dest;
    }

    return record;
}


UniValue BuildStatusPayload(const RepoOfferRecord& record, int tip_height, const CWallet* wallet = nullptr)
{
    UniValue status(UniValue::VOBJ);
    status.pushKV("id", record.offer_id.GetHex());
    status.pushKV("kind", "repo");

    const RepoContractState lifecycle = record.DerivedState(wallet);
    status.pushKV("state", RepoContractStateToString(lifecycle));
    status.pushKV("offer", RepoOfferToJSON(record));

    UniValue deadlines(UniValue::VOBJ);
    deadlines.pushKV("maturity_height", record.terms.maturity_height);
    deadlines.pushKV("safety_k", record.terms.safety_k);
    deadlines.pushKV("reorg_conf", record.terms.reorg_conf);
    status.pushKV("deadlines", std::move(deadlines));

    UniValue utxos(UniValue::VARR);
    if (!record.repay_txid && !record.default_txid && record.vault_outpoint) {
        UniValue utxo(UniValue::VOBJ);
        utxo.pushKV("txid", record.vault_outpoint->hash.ToString());
        utxo.pushKV("vout", record.vault_outpoint->n);
        utxo.pushKV("amount", ValueFromAmount(record.vault_amount));
        utxo.pushKV("role", "vault");
        utxos.push_back(std::move(utxo));
    }
    status.pushKV("utxos", std::move(utxos));

    if (lifecycle == RepoContractState::REPAID && record.repay_txid) {
        UniValue closure(UniValue::VOBJ);
        closure.pushKV("type", "repaid");
        closure.pushKV("txid", record.repay_txid->ToString());
        if (record.repay_height) {
            closure.pushKV("height", *record.repay_height);
        }
        if (record.repay_time) {
            closure.pushKV("time", *record.repay_time);
        }
        status.pushKV("closure", std::move(closure));
    } else if (lifecycle == RepoContractState::DEFAULTED && record.default_txid) {
        UniValue closure(UniValue::VOBJ);
        closure.pushKV("type", "defaulted");
        closure.pushKV("txid", record.default_txid->ToString());
        if (record.default_height) {
            closure.pushKV("height", *record.default_height);
        }
        if (record.default_time) {
            closure.pushKV("time", *record.default_time);
        }
        status.pushKV("closure", std::move(closure));
    }

    if (record.created_height > 0 && tip_height >= record.created_height) {
        status.pushKV("confs", tip_height - record.created_height + 1);
    } else {
        status.pushKV("confs", 0);
    }

    // Include vault covenant script if available (for script preview)
    if (record.vault_covenant_script.has_value()) {
        status.pushKV("vault_script_hex", HexStr(*record.vault_covenant_script));
    }

    return status;
}

UniValue BuildSpotStatusPayload(const SpotOfferRecord& record, int tip_height)
{
    UniValue status(UniValue::VOBJ);
    status.pushKV("id", record.offer_id.GetHex());
    status.pushKV("kind", "spot");
    status.pushKV("state", record.acceptance ? "accepted" : "proposed");
    status.pushKV("offer", SpotOfferToJSON(record));
    status.pushKV("deadlines", UniValue(UniValue::VOBJ));
    status.pushKV("utxos", UniValue(UniValue::VARR));
    if (record.created_height > 0 && tip_height >= record.created_height) {
        status.pushKV("confs", tip_height - record.created_height + 1);
    } else {
        status.pushKV("confs", 0);
    }
    return status;
}

} // namespace (closes anonymous namespace)

static WitnessV1Taproot BuildForwardLongVaultTaproot(const ForwardContractRecord& record);
static WitnessV1Taproot BuildForwardShortVaultTaproot(const ForwardContractRecord& record);

// Spot contract helpers (outside anonymous namespace for RPC lambda access)
enum class SpotRole : uint8_t {
    NONE = 0,
    ALICE,
    BOB,
};

SpotRole DetermineSpotRole(const SpotOfferRecord& offer)
{
    if (offer.local_fs_tx_adaptor_secret) {
        return SpotRole::ALICE;
    }
    if (offer.acceptance && offer.acceptance->local_fs_tx_adaptor_secret) {
        return SpotRole::BOB;
    }
    return SpotRole::NONE;
}

const AssetLeg& LegForRole(const SpotOfferRecord& offer, SpotRole role)
{
    if (role == SpotRole::ALICE) return offer.terms.alice_deliver;
    if (role == SpotRole::BOB) return offer.terms.bob_deliver;
    throw std::logic_error("LegForRole called with NONE role");
}

CTxDestination ReceiveDestinationForRole(const SpotOfferRecord& offer, const SpotAcceptanceRecord& acceptance, SpotRole role)
{
    if (role == SpotRole::ALICE) return acceptance.bob_recv_dest;
    if (role == SpotRole::BOB) return offer.alice_recv_dest;
    throw std::logic_error("ReceiveDestinationForRole called with NONE role");
}

struct ParsedSpotInput
{
    COutPoint prevout;
    CTxOut txout;
    bool is_asset{false};
    uint256 asset_id;
    uint64_t asset_units{0};
};

struct SpotUserInputs
{
    std::vector<ParsedSpotInput> native_inputs;
    std::vector<ParsedSpotInput> asset_inputs;
    CAmount native_total{0};
    uint64_t asset_total{0};
};

// Additional spot helpers moved outside anonymous namespace
constexpr CAmount DEFAULT_SPOT_ASSET_OUTPUT_VALUE{1000}; // Match DEFAULT_ASSET_OUTPUT_VALUE for consistency

std::vector<unsigned char> EncodeSpotOutputMatch(const AssetLeg& leg, const CTxDestination& dest)
{
    DataStream ss{};
    ss << static_cast<uint8_t>(leg.is_native ? 1 : 0);
    ss << ComputeTapMatch(GetScriptForDestination(dest));
    ss << static_cast<uint64_t>(leg.units);
    if (!leg.is_native) {
        ss << leg.asset_id;
    }
    return std::vector<unsigned char>(UCharCast(ss.data()), UCharCast(ss.data() + ss.size()));
}

void ValidateSpotLegBalance(CWallet& wallet, const AssetLeg& leg, const std::string& operation)
{
    if (leg.is_native) {
        CAmount available_balance = GetBalance(wallet).m_mine_trusted;
        if (available_balance < static_cast<CAmount>(leg.units)) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient native balance to %s (need %s, have %s)",
                    operation, FormatMoney(leg.units), FormatMoney(available_balance)));
        }
    }
}

SpotUserInputs ParseSpotUserInputs(CWallet& wallet, const UniValue& arr)
{
    if (!arr.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "my_inputs must be an array");
    }
    SpotUserInputs result;
    for (unsigned int i = 0; i < arr.size(); ++i) {
        const UniValue& input_obj = arr[i];
        if (!input_obj.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Each my_inputs entry must be an object");
        }
        const UniValue& txid_val = input_obj.find_value("txid");
        const UniValue& vout_val = input_obj.find_value("vout");
        if (!txid_val.isStr() || !vout_val.isNum()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "my_inputs must have txid (string) and vout (number)");
        }
        const auto txid = Txid::FromHex(txid_val.get_str());
        if (!txid) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid in my_inputs");
        }
        const uint32_t vout = vout_val.getInt<uint32_t>();
        const COutPoint prevout{*txid, vout};

        CTxOut txout;
        {
            LOCK(wallet.cs_wallet);
            const auto* wtx = wallet.GetWalletTx(Txid{prevout.hash});
            if (!wtx || prevout.n >= wtx->tx->vout.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "my_inputs entry not found in wallet");
        }
            txout = wtx->tx->vout[prevout.n];
        }

        ParsedSpotInput parsed;
        parsed.prevout = prevout;
        parsed.txout = txout;

        if (auto tag = assets::ParseAssetTag(txout.vExt)) {
            parsed.is_asset = true;
            parsed.asset_id = tag->id;
            parsed.asset_units = tag->amount;
            result.asset_inputs.push_back(parsed);
            result.asset_total += tag->amount;
        } else {
            parsed.is_asset = false;
            result.native_inputs.push_back(parsed);
            result.native_total += txout.nValue;
        }
    }
    return result;
}

UniValue RepoTermsToJSON(const RepoTerms& terms)
{
    UniValue obj(UniValue::VOBJ);

    // New structured format
    UniValue principal_leg_obj(UniValue::VOBJ);
    principal_leg_obj.pushKV("is_native", terms.principal_leg.is_native);
    if (!terms.principal_leg.is_native) {
        principal_leg_obj.pushKV("asset_id", terms.principal_leg.asset_id.GetHex());
    }
    principal_leg_obj.pushKV("units", UniValue((int64_t)terms.principal_leg.units));
    obj.pushKV("principal_leg", principal_leg_obj);

    UniValue interest_leg_obj(UniValue::VOBJ);
    interest_leg_obj.pushKV("is_native", terms.interest_leg.is_native);
    if (!terms.interest_leg.is_native) {
        interest_leg_obj.pushKV("asset_id", terms.interest_leg.asset_id.GetHex());
    }
    interest_leg_obj.pushKV("units", UniValue((int64_t)terms.interest_leg.units));
    obj.pushKV("interest_leg", interest_leg_obj);

    UniValue collateral_leg_obj(UniValue::VOBJ);
    collateral_leg_obj.pushKV("is_native", terms.collateral_leg.is_native);
    if (!terms.collateral_leg.is_native) {
        collateral_leg_obj.pushKV("asset_id", terms.collateral_leg.asset_id.GetHex());
    }
    collateral_leg_obj.pushKV("units", UniValue((int64_t)terms.collateral_leg.units));
    obj.pushKV("collateral_leg", collateral_leg_obj);

    // Legacy flat format for backward compatibility
    if (!terms.principal_leg.is_native) {
        obj.pushKV("principal_asset_id", terms.principal_leg.asset_id.GetHex());
        obj.pushKV("asset_id", terms.principal_leg.asset_id.GetHex()); // backward compatible alias
    }
    obj.pushKV("principal_is_native", terms.principal_leg.is_native);
    obj.pushKV("principal_units", UniValue((int64_t)terms.principal_leg.units));
    obj.pushKV("interest_units", UniValue((int64_t)terms.interest_leg.units));

    // Repay units is the sum of principal + interest
    const uint64_t repay_units = terms.principal_leg.units + terms.interest_leg.units;
    obj.pushKV("repay_units", UniValue((int64_t)repay_units));

    // Collateral as BTC amount (legacy compat)
    if (terms.collateral_leg.is_native) {
        obj.pushKV("collateral_sats", ValueFromAmount(static_cast<CAmount>(terms.collateral_leg.units)));
        obj.pushKV("collateral_sats_raw", UniValue((int64_t)terms.collateral_leg.units));
    }

    obj.pushKV("maturity_height", terms.maturity_height);
    obj.pushKV("safety_k", terms.safety_k);
    obj.pushKV("reorg_conf", terms.reorg_conf);
    return obj;
}

RPCHelpMan repo_propose()
{
    return RPCHelpMan(
        "repo.propose",
        "Create a repo financing offer skeleton and store it in the wallet registry.",
        std::vector<RPCArg>{
            {"terms", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Repo contract terms",
                {
                    {"principal_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte asset identifier for principal leg (omit when native)"},
                    {"principal_is_native", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Set true when borrowing BTC"},
                    {"principal_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units lent at open"},
                    {"interest_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units owed as interest"},
                    {"repay_units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Total units owed (defaults to principal + interest)"},
                    {"collateral_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Collateral in satoshis"},
                    {"collateral_btc", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Collateral in BTC"},
                    {"maturity_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height when default path activates"},
                    {"safety_k", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Safety window before maturity (default 6)"},
                    {"reorg_conf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Reorg confirmations buffer (default 2)"},
                    {"borrower_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Borrower covenant address (bech32m)"},
                    {"lender_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Lender repayment address (bech32m)"},
                    {"fee_policy", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Fee policy strategy: 'low' (~2 sat/vB), 'medium' (~10 sat/vB), or 'high' (~50 sat/vB). Default: 'medium'"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ, "offer", "Offer payload to share with counterparty", RepoOfferResultDescription()},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.propose", "\"{\\\"principal_asset_id\\\":\\\"" + std::string(64, 'a') + "\\\",\\\"principal_units\\\":1000000,\\\"interest_units\\\":50000,\\\"collateral_btc\\\":2,\\\"maturity_height\\\":850000,\\\"borrower_address\\\":\\\"bcrt1...\\\",\\\"lender_address\\\":\\\"bcrt1...\\\"}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& terms_obj = request.params[0].get_obj();
            std::string maker_role = "lender";
            if (terms_obj.exists("role") && terms_obj["role"].isStr()) {
                maker_role = terms_obj["role"].get_str();
                std::transform(maker_role.begin(), maker_role.end(), maker_role.begin(), ::tolower);
            }
            const bool maker_is_lender = maker_role == "lender";
            const bool maker_is_borrower = maker_role == "borrower";

            RepoTerms terms = ParseRepoTerms(terms_obj);
            const CTxDestination borrower_dest = ParseDestinationRequired(terms_obj, "borrower_address");
            const CTxDestination lender_dest = ParseDestinationRequired(terms_obj, "lender_address");

            // SECURITY CHECK: Lender must verify that lender_address is an address they control
            // This prevents accidental or malicious creation of offers with repay addresses the lender doesn't own,
            // which would redirect repayments to an attacker or cause loss of funds
            if (maker_is_lender || (!maker_is_lender && !maker_is_borrower)) {
                const CScript lender_spk = GetScriptForDestination(lender_dest);
                const isminetype mine = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(lender_spk));
                if (!(mine & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Security: Cannot create offer - the lender address (%s) is not spendable by this wallet. "
                                 "This could redirect repayments to an address you don't control. "
                                 "Only create offers where lender_address is your own address.",
                                 EncodeDestination(lender_dest)));
                }
                pwallet->WalletLogPrintf("Security check passed: Lender address %s is controlled by this wallet\n",
                                        EncodeDestination(lender_dest));
            } else {
                pwallet->WalletLogPrintf("Security check skipped: Maker role is '%s', lender address supplied by counterparty\n", maker_role);
            }

            uint256 offer_id = GetRandHash();
            auto [adaptor_secret, adaptor_point] = GenerateFairSignAdaptor();

            RepoOfferRecord record;
            record.offer_id = offer_id;
            record.terms = terms;
            record.borrower_dest = borrower_dest;
            record.lender_dest = lender_dest;

            // Extract lender's internal (untweaked) key from repayment address
            // This is required for signing the default leaf later
            if (auto lender_internal = ExtractInternalKeyForDestination(*pwallet, lender_dest)) {
                record.lender_internal_key = *lender_internal;
                std::vector<unsigned char> lender_internal_bytes(lender_internal->begin(), lender_internal->end());
                pwallet->WalletLogPrintf("repo.propose: Extracted lender_internal_key=%s from lender_dest\n",
                                         HexStr(lender_internal_bytes));
            } else {
                pwallet->WalletLogPrintf("repo.propose: WARNING: Could not extract lender_internal_key from lender_dest. Default sweep may fail to sign.\n");
            }

            // Extract borrower's internal (untweaked) key from borrower address (for borrower-initiated offers)
            // In lender-initiated offers, this will be extracted during acceptance
            if (auto borrower_internal = ExtractInternalKeyForDestination(*pwallet, borrower_dest)) {
                record.borrower_internal_key = *borrower_internal;
                std::vector<unsigned char> borrower_internal_bytes(borrower_internal->begin(), borrower_internal->end());
                pwallet->WalletLogPrintf("repo.propose: Extracted borrower_internal_key=%s from borrower_dest\n",
                                         HexStr(borrower_internal_bytes));
            } else {
                pwallet->WalletLogPrintf("repo.propose: Could not extract borrower_internal_key from borrower_dest (may be extracted during acceptance)\n");
            }

            record.maker_role = maker_role;  // Save maker's role for export to offer JSON

            // Extract and store fee policy strategy from terms
            const UniValue& fee_policy_val = terms_obj.find_value("fee_policy");
            if (fee_policy_val.isStr()) {
                record.fee_policy_strategy = fee_policy_val.get_str();
            } else {
                // Default to medium if not specified
                record.fee_policy_strategy = "medium";
            }

            record.fs_policy = FairSignPolicy{};
            record.fs_tx_adaptor_point = adaptor_point;
            record.local_fs_tx_adaptor_secret = adaptor_secret;
            record.salt = GetRandHash();
            record.created_time = GetTime();
            {
                LOCK(pwallet->cs_wallet);
                record.created_height = pwallet->GetLastBlockHeight();
            }
            record.commitment_hex = RepoOfferCommitmentHex(record, record.lender_dest);

            RepoOfferRecord stored = pwallet->RegisterRepoOffer(std::move(record));

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", stored.offer_id.GetHex());
            result.pushKV("offer", RepoOfferToJSON(stored));
            return result;
        }
    );
}

RPCHelpMan repo_import_offer()
{
    return RPCHelpMan(
        "repo.import_offer",
        "Import a repo offer JSON payload into the wallet registry.",
        std::vector<RPCArg>{
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Offer payload", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ, "offer", /*optional=*/false, "Wallet-normalised offer payload", RepoOfferResultDescription()},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.import_offer", "\"{...offer json...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& offer_obj = request.params[0].get_obj();

            int fallback_height;
            {
                LOCK(pwallet->cs_wallet);
                fallback_height = pwallet->GetLastBlockHeight();
            }
            const int64_t fallback_time = GetTime();

            RepoOfferRecord record = ParseRepoOfferObject(offer_obj, fallback_height, fallback_time);

            // DO NOT extract internal keys during import - the offer is canonical
            // Both parties must use the same keys that are in the offer to build matching covenants
            // Internal keys will be extracted later during acceptance/signing when needed

            if (auto existing = pwallet->FindRepoOffer(record.offer_id)) {
                if (existing->commitment_hex != record.commitment_hex) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Existing repo offer has different commitment");
                }
                if (existing->borrower_dest != record.borrower_dest || existing->lender_dest != record.lender_dest) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Existing repo offer has different participants");
                }
                if (!record.lender_dest_override && existing->lender_dest_override) {
                    record.lender_dest_override = existing->lender_dest_override;
                }
                if (!record.acceptance && existing->acceptance) {
                    record.acceptance = existing->acceptance;
                } else if (record.acceptance && existing->acceptance) {
                    if (record.acceptance->commitment_hex != existing->acceptance->commitment_hex) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Acceptance commitment mismatch");
                    }
                }
                if (existing->vault_outpoint && !record.vault_outpoint) {
                    record.vault_outpoint = existing->vault_outpoint;
                    record.vault_amount = existing->vault_amount;
                }
                record.created_height = existing->created_height ? existing->created_height : record.created_height;
                record.created_time = existing->created_time ? existing->created_time : record.created_time;
                record.local_fs_tx_adaptor_secret = existing->local_fs_tx_adaptor_secret;
            }

            RepoOfferRecord stored = pwallet->RegisterRepoOffer(std::move(record));

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", stored.offer_id.GetHex());
            result.pushKV("offer", RepoOfferToJSON(stored));
            return result;
        }
    );
}

RPCHelpMan repo_export_offer()
{
    return RPCHelpMan(
        "repo.export_offer",
        "Return the canonical wallet view of a repo offer for counterparty sharing.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ, "offer", /*optional=*/false, "Offer payload", RepoOfferResultDescription()},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.export_offer", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", record_opt->offer_id.GetHex());
            result.pushKV("offer", RepoOfferToJSON(*record_opt));
            return result;
        }
    );
}

RPCHelpMan repo_share_offer()
{
    return RPCHelpMan(
        "repo.share_offer",
        "Export a repo offer and create a cosign session for secure sharing with counterparty.\n"
        "This is a convenience wrapper that combines repo.export_offer with cosign.init.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"context", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Human-readable context label (default: \"repo-offer\")"},
            {"transport", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Transport: auto|websocket|nostr (default: auto)"},
            {"ttl", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Session TTL in seconds (default: 1800)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Repo offer identifier"},
                {RPCResult::Type::OBJ, "offer", "Exported repo offer payload", RepoOfferResultDescription()},
                {RPCResult::Type::OBJ, "cosign", "Cosign session details",
                    {
                        {RPCResult::Type::STR, "session_id", "Cosign session identifier"},
                        {RPCResult::Type::STR, "invite_link", "Invite link for counterparty"},
                        {RPCResult::Type::STR, "sas", "Short Authentication String"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.share_offer", std::string(64, 'a'))
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id hex");
            }

            // Get offer from wallet
            LOCK(pwallet->cs_wallet);
            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }

            // Build offer export
            UniValue offer_data(UniValue::VOBJ);
            offer_data.pushKV("offer_id", record_opt->offer_id.GetHex());
            offer_data.pushKV("offer", RepoOfferToJSON(*record_opt));

            // Prepare cosign.init parameters (positional: psbt, context, transport, ttl)
            UniValue cosign_params(UniValue::VARR);
            cosign_params.push_back("");  // empty psbt
            cosign_params.push_back(request.params[1].isNull() ? "repo-offer" : request.params[1].get_str());  // context
            cosign_params.push_back(request.params[2].isNull() ? "auto" : request.params[2].get_str());  // transport
            cosign_params.push_back(request.params[3].isNull() ? 1800 : request.params[3].getInt<int>());  // ttl

            // Call cosign.init
            JSONRPCRequest cosign_req;
            cosign_req.context = request.context;
            cosign_req.strMethod = "cosign.init";
            cosign_req.params = cosign_params;

            UniValue cosign_result = tableRPC.execute(cosign_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", offer_data["offer_id"]);
            result.pushKV("offer", offer_data["offer"]);
            result.pushKV("cosign", cosign_result);

            return result;
        }
    );
}

RPCHelpMan repo_list_offers()
{
    return RPCHelpMan(
        "repo.list_offers",
        "List repo offers currently tracked by the wallet.",
        {},
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "", RepoOfferResultDescription()},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.list_offers", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            std::vector<RepoOfferRecord> records = pwallet->ListRepoOffers();
            std::sort(records.begin(), records.end(), [](const RepoOfferRecord& a, const RepoOfferRecord& b) {
                if (a.created_time == b.created_time) return a.offer_id < b.offer_id;
                return a.created_time < b.created_time;
            });

            UniValue result(UniValue::VARR);
            for (const auto& record : records) {
                result.push_back(RepoOfferToJSON(record));
            }
            return result;
        }
    );
}

RPCHelpMan repo_collect_acceptance()
{
    return RPCHelpMan(
        "repo.collect_acceptance",
        "Join a cosign session via invite link and collect acceptance data from counterparty.\n"
        "This is a convenience wrapper that combines cosign.join with cosign.recv and repo.import_acceptance.",
        std::vector<RPCArg>{
            {"offer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"invite_link", RPCArg::Type::STR, RPCArg::Optional::NO, "Cosign invite link (cosign:?r=...)"},
            {"timeout_ms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Timeout for receiving acceptance (default: 30000ms)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", "Acceptance identifier"},
                {RPCResult::Type::OBJ, "acceptance", "Imported acceptance payload", RepoAcceptanceResultDescription()},
                {RPCResult::Type::OBJ, "cosign", "Cosign session details",
                    {
                        {RPCResult::Type::STR, "session_id", "Cosign session identifier"},
                        {RPCResult::Type::STR, "peer_sas", "Peer Short Authentication String"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.collect_acceptance", std::string(64, 'a') + " \"cosign:?r=abc123&t=websocket#c=alpha-bravo-charlie\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            // Validate offer_id
            const std::string offer_id_hex = request.params[0].get_str();
            if (!IsHex(offer_id_hex) || offer_id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "offer_id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(offer_id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id hex");
            }

            const std::string invite_link = request.params[1].get_str();
            const int timeout_ms = request.params[2].isNull() ? 30000 : request.params[2].getInt<int>();

            // Step 1: Join cosign session via invite link
            JSONRPCRequest join_req;
            join_req.context = request.context;
            join_req.strMethod = "cosign.join";
            UniValue join_params(UniValue::VARR);
            join_params.push_back(invite_link);
            join_req.params = join_params;

            UniValue join_result = tableRPC.execute(join_req);
            const std::string session_id = join_result["session_id"].get_str();
            const std::string peer_sas = join_result["peer_sas"].get_str();

            // Step 1.5: Complete SPAKE2/Noise handshake (SECURITY: Phase 4 requirement)
            // This establishes encrypted channel before any send/recv operations
            JSONRPCRequest handshake_req;
            handshake_req.context = request.context;
            handshake_req.strMethod = "cosign.handshake_auto";
            UniValue handshake_params(UniValue::VARR);
            handshake_params.push_back(session_id);
            handshake_params.push_back(false);  // responder (joined session)
            handshake_req.params = handshake_params;

            UniValue handshake_result = tableRPC.execute(handshake_req);
            if (!handshake_result.exists("handshake_complete") || !handshake_result["handshake_complete"].isBool() || !handshake_result["handshake_complete"].get_bool()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Handshake failed: encrypted channel not established");
            }

            // Step 2: Receive acceptance data via cosign.recv
            JSONRPCRequest recv_req;
            recv_req.context = request.context;
            recv_req.strMethod = "cosign.recv";
            UniValue recv_params(UniValue::VARR);
            recv_params.push_back(session_id);
            recv_params.push_back(timeout_ms);
            recv_req.params = recv_params;

            UniValue recv_result = tableRPC.execute(recv_req);

            // Extract acceptance payload
            if (!recv_result["payload"].isObject() || !recv_result["payload"]["acceptance"].isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected acceptance object in received payload");
            }

            UniValue acceptance_data = recv_result["payload"]["acceptance"];

            // Step 3: Import acceptance using repo.import_acceptance
            JSONRPCRequest import_req;
            import_req.context = request.context;
            import_req.strMethod = "repo.import_acceptance";
            UniValue import_params(UniValue::VARR);
            import_params.push_back(offer_id->GetHex());
            import_params.push_back(acceptance_data);
            import_req.params = import_params;

            UniValue import_result = tableRPC.execute(import_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", import_result["accept_id"]);
            result.pushKV("acceptance", import_result["acceptance"]);

            UniValue cosign_info(UniValue::VOBJ);
            cosign_info.pushKV("session_id", session_id);
            cosign_info.pushKV("peer_sas", peer_sas);
            cosign_info.pushKV("messages_received", recv_result["seq"]);
            result.pushKV("cosign", cosign_info);

            return result;
        }
    );
}

RPCHelpMan repo_sign_over_channel()
{
    return RPCHelpMan(
        "repo.sign_over_channel",
        "Coordinate Fair-Sign ceremony over an active cosign session.\n"
        "Sends nonce commitments, exchanges partial signatures, and completes the signing process.",
        std::vector<RPCArg>{
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Active cosign session identifier"},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Partially Signed Bitcoin Transaction (base64)"},
            {"is_initiator", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this party initiates the ceremony (default: true)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Completed PSBT with all signatures (base64)"},
                {RPCResult::Type::OBJ, "ceremony_stats", "Ceremony statistics",
                    {
                        {RPCResult::Type::NUM, "messages_sent", "Number of messages sent"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                        {RPCResult::Type::NUM, "duration_ms", "Ceremony duration in milliseconds"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.sign_over_channel", "\"69d967c0e415c9a3\" \"cHNidP8BA...\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string session_id = request.params[0].get_str();
            const std::string psbt_str = request.params[1].get_str();
            const bool is_initiator = request.params[2].isNull() ? true : request.params[2].get_bool();

            auto start_time = std::chrono::steady_clock::now();
            int messages_sent = 0;
            int messages_received = 0;

            // Step 1: Prepare adaptor ceremony (generate nonces & commitments)
            JSONRPCRequest prepare_req;
            prepare_req.context = request.context;
            UniValue prepare_params(UniValue::VARR);
            prepare_params.push_back(psbt_str);
            prepare_req.params = prepare_params;
            prepare_req.strMethod = "adaptor.prepare";

            UniValue prepare_result = tableRPC.execute(prepare_req);
            const std::string prepared_psbt = prepare_result["psbt"].get_str();

            // Extract commitments
            UniValue commitments(UniValue::VARR);
            if (prepare_result["commitments"].isArray()) {
                commitments = prepare_result["commitments"];
            }

            // Step 2: Exchange nonce commitments via cosign
            if (is_initiator) {
                // Initiator sends commitments first
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "nonce_commitments");
                payload.pushKV("commitments", commitments);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;

                // Receive peer's commitments
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000); // 30s timeout
                recv_req.params = recv_params;
                UniValue recv_result = tableRPC.execute(recv_req);
                messages_received++;
            } else {
                // Responder receives commitments first
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000); // 30s timeout
                recv_req.params = recv_params;
                UniValue recv_result = tableRPC.execute(recv_req);
                messages_received++;

                // Then sends own commitments
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "nonce_commitments");
                payload.pushKV("commitments", commitments);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;
            }

            // Step 3: Create partial adaptor signatures
            JSONRPCRequest partial_req;
            partial_req.context = request.context;
            partial_req.strMethod = "adaptor.partial";
            UniValue partial_params(UniValue::VARR);
            partial_params.push_back(prepared_psbt);
            partial_req.params = partial_params;

            UniValue partial_result = tableRPC.execute(partial_req);
            const std::string partial_psbt = partial_result["psbt"].get_str();

            // Step 4: Exchange partial signatures
            if (is_initiator) {
                // Send partial PSBT
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "partial_psbt");
                payload.pushKV("psbt", partial_psbt);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;

                // Receive peer's partial PSBT
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                UniValue recv_result = tableRPC.execute(recv_req);
                messages_received++;
            } else {
                // Responder receives first
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                UniValue recv_result = tableRPC.execute(recv_req);
                messages_received++;

                // Then sends
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "partial_psbt");
                payload.pushKV("psbt", partial_psbt);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;
            }

            // Step 5: Complete the adaptor ceremony
            JSONRPCRequest complete_req;
            complete_req.context = request.context;
            complete_req.strMethod = "adaptor.complete";
            UniValue complete_params(UniValue::VARR);
            complete_params.push_back(partial_psbt);
            complete_params.push_back(commitments); // Pass empty array to bypass commit-reveal
            complete_req.params = complete_params;

            UniValue complete_result = tableRPC.execute(complete_req);

            auto end_time = std::chrono::steady_clock::now();
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", complete_result["psbt"]);

            UniValue stats(UniValue::VOBJ);
            stats.pushKV("messages_sent", messages_sent);
            stats.pushKV("messages_received", messages_received);
            stats.pushKV("duration_ms", duration_ms);
            result.pushKV("ceremony_stats", stats);

            return result;
        }
    );
}

RPCHelpMan repo_accept()
{
    return RPCHelpMan(
        "repo.accept",
        "Record acceptance for a repo offer and return the canonical acceptance payload.\n"
        "IMPORTANT: Review terms carefully before accepting. Use 'confirmed' parameter to proceed.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Acceptance options",
                {
                    {"repay_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Updated repayment address (bech32m)"},
                    {"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be true after reviewing terms to accept"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", /*optional=*/true, "Acceptance identifier (only if confirmed=true)"},
                {RPCResult::Type::OBJ, "acceptance", /*optional=*/true, "Canonical acceptance payload (only if confirmed=true)", RepoAcceptanceResultDescription()},
                {RPCResult::Type::OBJ, "terms", /*optional=*/true, "Contract terms for review (if confirmed is missing/false)"},
                {RPCResult::Type::STR, "action_required", /*optional=*/true, "Instructions for user (if confirmed is missing/false)"},
                {RPCResult::Type::STR, "warning", /*optional=*/true, "Warning message (if confirmed is missing/false)"},
            }
        },
        RPCExamples{
            HelpExampleCli("repo.accept", "\"offer_id\"") + " (shows terms for review)\n" +
            HelpExampleCli("repo.accept", "\"offer_id\" '{\"confirmed\": true}'") + " (accepts after review)"
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto stored_opt = pwallet->FindRepoOffer(*offer_id);
            if (!stored_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            RepoOfferRecord stored = *stored_opt;

            // SECURITY CHECK: Determine role and verify address ownership
            // - Borrower-initiated offers: lender_address="" → acceptor is lender (will fill address during acceptance)
            // - Lender-initiated offers: borrower_address="" → acceptor is borrower (will fill address during acceptance)

            // Check if borrower_address is owned
            const CScript borrower_spk = GetScriptForDestination(stored.borrower_dest);
            const isminetype borrower_mine = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(borrower_spk));
            bool is_borrower = (borrower_mine & ISMINE_SPENDABLE);

            if (is_borrower) {
                // Accepting as BORROWER - verify we own the borrower address
                pwallet->WalletLogPrintf("Security check passed: Accepting as BORROWER, address %s is controlled by this wallet\n",
                                        EncodeDestination(stored.borrower_dest));
            } else {
                // Accepting as LENDER - verify lender address (if non-empty)
                const CTxDestination& lender_check = stored.lender_dest_override ? *stored.lender_dest_override : stored.lender_dest;

                // If lender_address is non-empty, it must be owned by this wallet
                        if (IsValidDestination(lender_check)) {
                            const CScript lender_spk = GetScriptForDestination(lender_check);
                            const isminetype lender_mine = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(lender_spk));
                    if (!(lender_mine & ISMINE_SPENDABLE)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Security: Cannot accept offer as lender - the lender address (%s) is not spendable by this wallet.",
                                     EncodeDestination(lender_check)));
                    }
                    pwallet->WalletLogPrintf("Security check passed: Accepting as LENDER, address %s is controlled by this wallet\n",
                                            EncodeDestination(lender_check));
                } else {
                    // Lender address is empty/invalid - this is a borrower-initiated offer
                    pwallet->WalletLogPrintf("Security check passed: Accepting as LENDER (borrower-initiated offer, will provide lender address)\n");
                }
            }

            // Check if user has confirmed after reviewing terms
            bool confirmed = false;
            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& opts = request.params[1].get_obj();
                const UniValue& confirmed_val = opts.find_value("confirmed");
                if (!confirmed_val.isNull()) {
                    confirmed = confirmed_val.get_bool();
                }
            }

            // If not confirmed, display terms for review
            if (!confirmed) {
                UniValue terms(UniValue::VOBJ);

                // Contract type and role
                terms.pushKV("contract_type", "REPO");
                bool is_lender = false;
                        if (stored.lender_dest_override) {
                            isminetype mine = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(GetScriptForDestination(*stored.lender_dest_override)));
                            is_lender = (mine != ISMINE_NO);
                }
                terms.pushKV("your_role", is_lender ? "LENDER" : "BORROWER");

                // Financial terms
                UniValue financial(UniValue::VOBJ);
                financial.pushKV("principal", ValueFromAmount(stored.terms.principal_leg.units));
                financial.pushKV("interest", ValueFromAmount(stored.terms.interest_leg.units));
                const uint64_t total_repay = stored.terms.principal_leg.units + stored.terms.interest_leg.units;
                financial.pushKV("total_repayment", ValueFromAmount(total_repay));
                financial.pushKV("collateral_asset", stored.terms.collateral_leg.is_native ? "BTC" : stored.terms.collateral_leg.asset_id.ToString());
                financial.pushKV("collateral_amount", ValueFromAmount(stored.terms.collateral_leg.units));
                financial.pushKV("maturity_blocks", (int)stored.terms.maturity_height);

                // Calculate approximate time
                int blocks_to_maturity = stored.terms.maturity_height - pwallet->chain().getHeight().value_or(0);
                if (blocks_to_maturity > 0) {
                    financial.pushKV("blocks_until_maturity", blocks_to_maturity);
                    financial.pushKV("approx_hours_until_maturity", blocks_to_maturity / 6);
                }
                terms.pushKV("financial_terms", financial);

                // Destinations
                UniValue destinations(UniValue::VOBJ);
                destinations.pushKV("lender_address", EncodeDestination(stored.lender_dest));
                destinations.pushKV("borrower_address", EncodeDestination(stored.borrower_dest));
                terms.pushKV("destinations", destinations);

                // Risks
                UniValue risks(UniValue::VARR);
                if (!is_lender) {
                    risks.push_back("⚠️ You may lose your collateral if you fail to repay");
                    risks.push_back("⚠️ Interest continues to accrue after maturity");
                    risks.push_back("⚠️ This agreement is irreversible once signed");
                } else {
                    risks.push_back("⚠️ Borrower may default on repayment");
                    risks.push_back("⚠️ Collateral value may fluctuate");
                    risks.push_back("⚠️ Recovery depends on collateral liquidation");
                }
                terms.pushKV("risks", risks);

                // Summary
                UniValue summary(UniValue::VOBJ);
                const uint64_t repay_total = stored.terms.principal_leg.units + stored.terms.interest_leg.units;
                if (is_lender) {
                    summary.pushKV("you_will_send", strprintf("%s (principal)", ValueFromAmount(stored.terms.principal_leg.units).get_str()));
                    summary.pushKV("you_will_receive", strprintf("%s (principal + interest)", ValueFromAmount(repay_total).get_str()));
                } else {
                    summary.pushKV("you_will_receive", strprintf("%s (principal)", ValueFromAmount(stored.terms.principal_leg.units).get_str()));
                    summary.pushKV("you_must_repay", strprintf("%s (principal + interest)", ValueFromAmount(repay_total).get_str()));
                    summary.pushKV("collateral_locked", ValueFromAmount(stored.terms.collateral_leg.units));
                }
                terms.pushKV("summary", summary);

                UniValue result(UniValue::VOBJ);
                result.pushKV("terms", terms);
                result.pushKV("action_required", "Review terms carefully. To accept, call again with options: {\"confirmed\": true}");
                result.pushKV("warning", "⚠️ This action is IRREVERSIBLE. Only proceed if you understand and accept all terms.");
                return result;
            }

            CTxDestination repay_ack = stored.lender_dest_override ? *stored.lender_dest_override : stored.lender_dest;
            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& opts = request.params[1].get_obj();
                const UniValue& repay_val = opts.find_value("repay_address");
                if (!repay_val.isNull()) {
                    CTxDestination dest = DecodeDestination(repay_val.get_str());
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid repay_address");
                    }
                    repay_ack = dest;
                }
            }

            auto [adaptor_secret, adaptor_point] = GenerateFairSignAdaptor();

            RepoAcceptanceRecord acceptance;
            acceptance.acceptance_id = GetRandHash();
            acceptance.fs_policy = stored.fs_policy;
            acceptance.fs_tx_adaptor_point = adaptor_point;
            acceptance.local_fs_tx_adaptor_secret = adaptor_secret;
            acceptance.salt = GetRandHash();
            acceptance.repay_dest_ack = repay_ack;

            const bool merge_repay = ShouldMergeRepoRepayLegs(stored.terms);
            bool skip_templates_due_to_missing_metadata = false;
            // Try to build repay templates, but allow failure for WRAP_REQUIRED assets
            // where borrower doesn't have DEK yet (will be rebuilt during actual repayment)
            const auto have_registry_for = [&](const AssetLeg& leg) -> bool {
                if (leg.is_native) return true;
                auto entry = pwallet->chain().getAssetRegistryEntry(leg.asset_id);
                return entry.has_value();
            };

            const bool principal_ok = have_registry_for(stored.terms.principal_leg);
            const bool interest_ok = have_registry_for(stored.terms.interest_leg);

            if (!principal_ok || !interest_ok) {
                const std::string asset_hint = stored.terms.principal_leg.is_native
                    ? std::string("<native>")
                    : stored.terms.principal_leg.asset_id.ToString().substr(0, 16);
                pwallet->WalletLogPrintf("repo.accept: Skipping repay template build (asset registry unavailable) for asset %s\n",
                                         asset_hint);
                skip_templates_due_to_missing_metadata = true;
            } else {
                try {
                    if (merge_repay) {
                        AssetLeg combined = stored.terms.principal_leg;
                        combined.units += stored.terms.interest_leg.units;
                        acceptance.repay_principal_template = BuildRepoDeliveryTemplate(
                            *pwallet,
                            request,
                            combined,
                            repay_ack,
                            "repo.accept.repay_combined");
                        acceptance.repay_interest_template.reset();
                    } else {
                        if (stored.terms.principal_leg.units > 0) {
                            acceptance.repay_principal_template = BuildRepoDeliveryTemplate(
                                *pwallet,
                                request,
                                stored.terms.principal_leg,
                                repay_ack,
                                "repo.accept.repay_principal");
                        }
                        if (stored.terms.interest_leg.units > 0) {
                            acceptance.repay_interest_template = BuildRepoDeliveryTemplate(
                                *pwallet,
                                request,
                                stored.terms.interest_leg,
                                repay_ack,
                                "repo.accept.repay_interest");
                        }
                    }
                } catch (const UniValue& err) {
                const UniValue& message_val = err["message"];
                if (message_val.isStr()) {
                    const std::string message = message_val.get_str();
                    const bool missing_icu_key = message.find("missing ICU encryption key") != std::string::npos;
                    const bool registry_missing = message.find("Asset not found in registry") != std::string::npos;
                    if (missing_icu_key || registry_missing) {
                        const std::string asset_hint = stored.terms.principal_leg.is_native
                            ? std::string("<native>")
                            : stored.terms.principal_leg.asset_id.ToString().substr(0, 16);
                        const char* reason = missing_icu_key ? "missing ICU key" : "asset registry unavailable";
                        pwallet->WalletLogPrintf("repo.accept: Skipping repay template build (%s) for asset %s (will rebuild during repayment when data available): %s\n",
                                                 reason,
                                                 asset_hint,
                                                 message);
                        acceptance.repay_principal_template.reset();
                        acceptance.repay_interest_template.reset();
                        skip_templates_due_to_missing_metadata = true;
                    }
                }
                if (skip_templates_due_to_missing_metadata) {
                    // fallthrough to post-processing without rethrow
                } else {
                    throw;
                }
            }
            }

            // Build collateral template independently (borrower has collateral asset and its DEK)
            // This template will be used by lender for default sweep, so it must be built even if
            // repay templates were skipped (borrower doesn't have principal/interest DEK yet)
            acceptance.default_collateral_template.reset();
            if (!stored.terms.collateral_leg.is_native) {
                try {
                    acceptance.default_collateral_template = BuildRepoDeliveryTemplate(
                        *pwallet,
                        request,
                        stored.terms.collateral_leg,
                        repay_ack,
                        "repo.accept.default_collateral");
                } catch (const UniValue& err) {
                    // If collateral template build fails, log but continue
                    // (lender can rebuild during sweep if needed via BuildRepoAssetSkeleton fallback)
                    const UniValue& message_val = err["message"];
                    if (message_val.isStr()) {
                        pwallet->WalletLogPrintf("repo.accept: Failed to build collateral template for asset %s: %s\n",
                                                 stored.terms.collateral_leg.asset_id.ToString().substr(0, 16),
                                                 message_val.get_str());
                    }
                    acceptance.default_collateral_template.reset();
                }
            }

            acceptance.commitment_hex = RepoAcceptanceCommitmentHex(stored, acceptance);

            // Extract borrower's internal key for vault construction (borrower has wallet access during acceptance)
            if (!stored.borrower_internal_key.has_value()) {
                const CScript borrower_spk = GetScriptForDestination(stored.borrower_dest);
                std::set<ScriptPubKeyMan*> borrower_managers = pwallet->GetScriptPubKeyMans(borrower_spk);
                for (ScriptPubKeyMan* manager : borrower_managers) {
                    if (manager == nullptr) continue;
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;

                    auto provider = desc_spkm->GetSolvingProvider(borrower_spk);
                    if (provider) {
                        auto* flat_provider = dynamic_cast<FlatSigningProvider*>(provider.get());
                        if (flat_provider && !flat_provider->pubkeys.empty()) {
                            stored.borrower_internal_key = XOnlyPubKey(flat_provider->pubkeys.begin()->second);
                            pwallet->WalletLogPrintf("Extracted borrower internal key during acceptance: %s\n", HexStr(*stored.borrower_internal_key));
                            break;
                        }
                    }
                }
            }

            // Extract lender's internal key for vault construction (lender has wallet access during acceptance)
            if (!stored.lender_internal_key.has_value()) {
                if (auto lender_internal = ExtractInternalKeyForDestination(*pwallet, stored.lender_dest)) {
                    stored.lender_internal_key = *lender_internal;
                    pwallet->WalletLogPrintf("Extracted lender internal key during acceptance: %s\n", HexStr(*lender_internal));
                }
            }

            RepoOfferRecord updated;
            try {
                updated = pwallet->RegisterRepoAcceptance(*offer_id, std::move(acceptance));
                // Preserve the extracted internal keys
                if (stored.borrower_internal_key.has_value() && !updated.borrower_internal_key.has_value()) {
                    updated.borrower_internal_key = stored.borrower_internal_key;
                    pwallet->RegisterRepoOffer(updated); // Re-register to persist internal key
                }
                if (stored.lender_internal_key.has_value() && !updated.lender_internal_key.has_value()) {
                    updated.lender_internal_key = stored.lender_internal_key;
                    pwallet->RegisterRepoOffer(updated); // Re-register to persist internal key
                }
            } catch (const std::runtime_error& err) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err.what());
            }
            const RepoAcceptanceRecord& stored_acceptance = *updated.acceptance;

            UniValue acceptance_json = RepoAcceptanceCanonicalJson(updated, stored_acceptance);
            acceptance_json.pushKV("salt", stored_acceptance.salt.GetHex());
            acceptance_json.pushKV("commitment", stored_acceptance.commitment_hex);
            // Include internal keys for vault construction (extracted during acceptance)
            if (updated.borrower_internal_key.has_value()) {
                acceptance_json.pushKV("borrower_internal_key", HexStr(*updated.borrower_internal_key));
            }
            if (updated.lender_internal_key.has_value()) {
                acceptance_json.pushKV("lender_internal_key", HexStr(*updated.lender_internal_key));
            }

            if (stored_acceptance.default_collateral_template) {
                UniValue collateral_template(UniValue::VOBJ);
                collateral_template.pushKV("purpose", "default_collateral");
                collateral_template.pushKV("is_native", stored_acceptance.default_collateral_template->is_native);
                collateral_template.pushKV("units", static_cast<int64_t>(stored_acceptance.default_collateral_template->units));
                collateral_template.pushKV("script_pubkey", HexStr(stored_acceptance.default_collateral_template->script_pubkey));
                collateral_template.pushKV("commitment", stored_acceptance.default_collateral_template->commitment.GetHex());
                if (!stored_acceptance.default_collateral_template->is_native) {
                    collateral_template.pushKV("asset_id", stored_acceptance.default_collateral_template->asset_id.GetHex());
                    collateral_template.pushKV("vext", HexStr(stored_acceptance.default_collateral_template->vext));
                }
                acceptance_json.pushKV("default_collateral_template", std::move(collateral_template));
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", stored_acceptance.acceptance_id.GetHex());
            result.pushKV("acceptance", std::move(acceptance_json));
            return result;
        }
    );
}


RPCHelpMan repo_build_open()
{
    return RPCHelpMan(
        "repo.build_open",
        "Construct the opening PSBT for a repo offer, funding the collateral vault and including the lender's principal payout. "
        "Two-party workflow: Lender calls with auto_fund_principal=true, borrower receives PSBT and calls with psbt= and auto_fund_collateral=true to add collateral funding.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional funding overrides",
                {
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                    {"auto_fund_principal", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Lender mode: automatically attach wallet-controlled asset inputs for principal"},
                    {"auto_fund_collateral", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Borrower mode: automatically attach wallet-controlled BTC inputs for collateral"},
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Existing PSBT to add funding to (used with auto_fund_collateral)"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT containing the funded covenant transaction"},
                {RPCResult::Type::NUM, "fee", "Fee (in " + CURRENCY_UNIT + ") paid by the wallet to fund this PSBT"},
                {RPCResult::Type::NUM, "changepos", "Index of the change output or -1 if none"},
                {RPCResult::Type::NUM, "principal_output_index", "Index of the principal asset output within the PSBT"},
                {RPCResult::Type::NUM, "covenant_output_index", "Index of the covenant Taproot output within the PSBT"},
                {RPCResult::Type::NUM, "asset_change_output_index", "Index of the asset change output when auto_fund_principal is used, otherwise -1"},
                {RPCResult::Type::OBJ, "taproot", "Taproot construction details", RepoTaprootResultDescription()},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT already contains all signatures"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.build_open", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            const RepoOfferRecord& record = *record_opt;

            if (!record.acceptance) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer must be accepted via repo.accept before building the opening transaction");
            }

            const CTxDestination repay_dest = record.lender_dest_override ? *record.lender_dest_override : record.lender_dest;

            // Parse options early to determine workflow mode
            const UniValue opts = request.params.size() > 1 && request.params[1].isObject() ? request.params[1].get_obj() : UniValue::VNULL;
            const UniValue& auto_fund_val = opts.isNull() ? NullUniValue : opts.find_value("auto_fund_principal");
            const bool auto_fund_principal = !auto_fund_val.isNull() && auto_fund_val.get_bool();
            const UniValue& auto_fund_coll_val = opts.isNull() ? NullUniValue : opts.find_value("auto_fund_collateral");
            const bool auto_fund_collateral = !auto_fund_coll_val.isNull() && auto_fund_coll_val.get_bool();
            const UniValue& psbt_val = opts.isNull() ? NullUniValue : opts.find_value("psbt");

            // Extract fee strategy from options (overrides stored fee_policy_strategy)
            const UniValue& strategy_val = opts.isNull() ? NullUniValue : opts.find_value("strategy");
            std::string fee_strategy_override;
            if (!strategy_val.isNull() && strategy_val.isStr()) {
                fee_strategy_override = strategy_val.get_str();
                LogPrintf("repo.build_open: GUI provided fee strategy override='%s'\n", fee_strategy_override);
            } else {
                LogPrintf("repo.build_open: No fee strategy in options, will use stored fee_policy_strategy='%s'\n", record.fee_policy_strategy);
            }

            // Get borrower scriptPubKey (needed for output matching later)
            const CScript borrower_spk = GetScriptForDestination(record.borrower_dest);

            // Validate wallet ownership based on mode
            if (!auto_fund_principal && !auto_fund_collateral) {
                // Traditional borrower-only mode: validate borrower address
                LOCK(pwallet->cs_wallet);
                if (!(pwallet->IsMine(borrower_spk) & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Borrower address is not spendable by this wallet");
                }
            }

            // CRITICAL: Both internal keys must be present for deterministic covenant construction
            // These keys are extracted during propose/accept and transmitted in the acceptance payload
            if (!record.borrower_internal_key.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Borrower internal key not available. The borrower must accept the offer first to extract their internal key.");
            }
            if (!record.lender_internal_key.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Lender internal key not available. The lender must accept the offer (or proposer must control lender address) to extract their internal key.");
            }

            const XOnlyPubKey borrower_key = *record.borrower_internal_key;
            const XOnlyPubKey lender_key = *record.lender_internal_key;
            pwallet->WalletLogPrintf("Using stored internal keys for vault construction: borrower=%s, lender=%s\n",
                                     HexStr(borrower_key), HexStr(lender_key));

            // Build repay covenant: merged OUTPUTMATCH when same asset, dual when different
            CScript repay_script = BuildRepoRepayCovenantScript(record.terms, repay_dest, borrower_key);

            CScript default_script;
            default_script << CScriptNum(record.terms.maturity_height)
                           << OP_CHECKLOCKTIMEVERIFY
                           << OP_DROP
                           << std::vector<unsigned char>(lender_key.begin(), lender_key.end())
                           << OP_CHECKSIG;

            TaprootBuilder builder;
            builder.Add(/*depth=*/1, std::vector<unsigned char>(repay_script.begin(), repay_script.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add repo repay leaf to Taproot tree");
            }
            builder.Add(/*depth=*/1, std::vector<unsigned char>(default_script.begin(), default_script.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add repo default leaf to Taproot tree");
            }
            if (!builder.IsComplete()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Taproot covenant tree is incomplete");
            }
            // Disable unilateral key-path on REPO vault
            builder.Finalize(DeriveScriptOnlyInternalKey("repo-vault", record.offer_id));
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize Taproot covenant tree");
            }
            WitnessV1Taproot covenant_output{builder.GetOutput()};
            const CScript covenant_spk = GetScriptForDestination(covenant_output);

            const auto cache_script_if_known = [&](const CScript& spk) {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(spk);
                if (managers.empty()) {
                    for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                        if (manager == nullptr) continue;
                        SignatureData sigdata;
                        if (manager->CanProvide(spk, sigdata)) {
                            managers.insert(manager);
                        }
                    }
                }
                if (managers.empty()) return;
                std::set<CScript> scripts{spk};
                for (ScriptPubKeyMan* manager : managers) {
                    if (manager == nullptr) continue;
                    pwallet->CacheNewScriptPubKeys(scripts, manager);
                }
            };

            const auto register_covenant_vault = [&](const CScript& covenant_spk) {
                // Build vault metadata leaves (same for both roles)
                std::vector<VaultLeafDescriptor> leaves;
                leaves.push_back(VaultBuilder::CreateLeaf(
                    repay_script,
                    borrower_key,
                    "repay",
                    std::nullopt  // No timelock on repay leaf
                ));
                leaves.push_back(VaultBuilder::CreateLeaf(
                    default_script,
                    lender_key,
                    "default",
                    record.terms.maturity_height  // CLTV timelock
                ));

                // Determine which role this wallet should register based on which keys it controls
                // Check if wallet controls borrower keys (for REPO_BORROWER role)
                std::set<ScriptPubKeyMan*> borrower_managers = pwallet->GetScriptPubKeyMans(borrower_spk);
                bool is_borrower_wallet = !borrower_managers.empty();

                // Check if wallet controls lender keys (for REPO_LENDER role)
                const CScript repay_spk = GetScriptForDestination(repay_dest);
                std::set<ScriptPubKeyMan*> lender_managers = pwallet->GetScriptPubKeyMans(repay_spk);
                bool is_lender_wallet = !lender_managers.empty();

                // Register vault with appropriate role (only once per wallet, not once per SPKM)
                if (is_borrower_wallet) {
                    auto borrower_metadata = VaultBuilder::Build(builder, record.offer_id, VaultRole::REPO_BORROWER, leaves);
                    if (borrower_metadata) {
                        for (ScriptPubKeyMan* manager : borrower_managers) {
                            if (manager == nullptr) continue;
                            auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                            if (!desc_spkm) continue;
                            // Use borrower_spk (descriptor base script) to map vault to descriptor index
                            if (desc_spkm->RegisterCovenantVault(borrower_spk, *borrower_metadata)) {
                                pwallet->WalletLogPrintf("Registered repo vault for REPO_BORROWER role (offer_id=%s)\n", record.offer_id.ToString());
                                // Cache covenant script only for the manager that registered it
                                std::set<CScript> scripts{covenant_spk};
                                pwallet->CacheNewScriptPubKeys(scripts, manager);
                                break;  // Only register once
                            }
                        }
                    }
                } else if (is_lender_wallet) {
                    auto lender_metadata = VaultBuilder::Build(builder, record.offer_id, VaultRole::REPO_LENDER, leaves);
                    if (lender_metadata) {
                        for (ScriptPubKeyMan* manager : lender_managers) {
                            if (manager == nullptr) continue;
                            auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                            if (!desc_spkm) continue;
                            // Use repay_spk (lender's descriptor base script) to map vault to descriptor index
                            if (desc_spkm->RegisterCovenantVault(repay_spk, *lender_metadata)) {
                                pwallet->WalletLogPrintf("Registered repo vault for REPO_LENDER role (offer_id=%s)\n", record.offer_id.ToString());
                                // Cache covenant script only for the manager that registered it
                                std::set<CScript> scripts{covenant_spk};
                                pwallet->CacheNewScriptPubKeys(scripts, manager);
                                break;  // Only register once
                            }
                        }
                    }
                }
            };

            // Register covenant vault for borrower-controlled wallets
            register_covenant_vault(covenant_spk);

            // Persist covenant script to record for vault detection
            // CRITICAL: Must update in-memory record AND persist to DB
            {
                LOCK(pwallet->cs_wallet);
                if (!pwallet->SetRepoVaultCovenantScript(*offer_id, covenant_spk)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist vault covenant script");
                }
                pwallet->WalletLogPrintf("Persisted vault covenant script for offer %s\n", offer_id->GetHex());
            }

            // LENDER MODE: Add principal funding to existing PSBT from borrower
            if (auto_fund_principal && !psbt_val.isNull()) {
                const std::string psbt_str = psbt_val.get_str();
                PartiallySignedTransaction psbtx;
                std::string error;
                if (!DecodeBase64PSBT(psbtx, psbt_str, error)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode PSBT: %s", error));
                }

                // Validate that covenant output exists or can be added
                std::optional<size_t> covenant_idx;
                for (size_t i = 0; i < psbtx.tx->vout.size(); ++i) {
                    if (psbtx.tx->vout[i].scriptPubKey == covenant_spk) {
                        covenant_idx = i;
                        break;
                    }
                }

                CMutableTransaction final_tx;
                final_tx.version = psbtx.tx->version;
                final_tx.nLockTime = psbtx.tx->nLockTime;
                CAmount lender_fee = 0;
                int appended_change_index = -1;
                int asset_change_index = -1;

                // Check if principal is an asset (requires sendasset) or native BTC (use FundTransaction)
                if (!record.terms.principal_leg.is_native) {
                    // ASSET PRINCIPAL: Use sendasset() to properly fund with asset inputs + TLV
                    JSONRPCRequest sendasset_req;
                    sendasset_req.context = request.context;
                    sendasset_req.URI = request.URI;
                    sendasset_req.strMethod = "sendasset";

                    // Build params: [asset_id, borrower_address, amount, {return_skeleton: true}]
                    UniValue sendasset_params(UniValue::VARR);
                    sendasset_params.push_back(record.terms.principal_leg.asset_id.ToString());
                    sendasset_params.push_back(EncodeDestination(record.borrower_dest));
                    sendasset_params.push_back(record.terms.principal_leg.units);

                    UniValue sendasset_opts(UniValue::VOBJ);
                    sendasset_opts.pushKV("return_skeleton", true);
                    sendasset_opts.pushKV("broadcast", false);
                    {
                        const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                        FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                        LogPrintf("repo.build_open: Principal sendasset using strategy='%s', target_satvb=%u, passing fee_rate=%u to sendasset\n",
                                 effective_strategy, fee_snapshot.target_satvb, fee_snapshot.target_satvb);
                        sendasset_opts.pushKV("fee_rate", fee_snapshot.target_satvb);
                    }
                    sendasset_params.push_back(sendasset_opts);

                    sendasset_req.params = sendasset_params;

                    // Call sendasset() to get skeleton with asset inputs and principal output
                    UniValue skeleton_result = sendasset().HandleRequest(sendasset_req);

                    if (!skeleton_result.isObject() || !skeleton_result.exists("hex")) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset did not return valid skeleton for principal");
                    }

                    CMutableTransaction principal_skeleton;
                    if (!DecodeHexTx(principal_skeleton, skeleton_result["hex"].get_str())) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode sendasset skeleton for principal");
                    }

                    // Merge transactions: borrower's inputs/outputs + lender's principal skeleton
                    final_tx.vin = psbtx.tx->vin;  // Start with borrower's inputs (maker base PSBT)
                    for (const CTxIn& txin : principal_skeleton.vin) {
                        final_tx.vin.push_back(txin);  // Add lender's asset inputs
                    }

                    // Start with borrower's outputs (covenant + any borrower change)
                    final_tx.vout = psbtx.tx->vout;

                    // Find the principal output in skeleton
                    std::optional<size_t> skeleton_principal_idx;
                    const CScript borrower_spk = GetScriptForDestination(record.borrower_dest);
                    const CAmount expected_principal_value = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                    for (size_t i = 0; i < principal_skeleton.vout.size(); ++i) {
                        if (principal_skeleton.vout[i].scriptPubKey == borrower_spk &&
                            principal_skeleton.vout[i].nValue == expected_principal_value) {
                            skeleton_principal_idx = i;
                            break;
                        }
                    }

                    if (!skeleton_principal_idx) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "sendasset skeleton missing principal output");
                    }

                    // Add principal output to final tx
                    final_tx.vout.push_back(principal_skeleton.vout[*skeleton_principal_idx]);

                    // Append any change outputs from skeleton (asset change + optional BTC change)
                    for (size_t i = 0; i < principal_skeleton.vout.size(); ++i) {
                        if (i == *skeleton_principal_idx) continue;  // Skip principal (already added)

                        const CTxOut& out = principal_skeleton.vout[i];
                        const size_t new_idx = final_tx.vout.size();
                        final_tx.vout.push_back(out);

                        // Track asset change output
                        if (auto tag = assets::ParseAssetTag(out.vExt)) {
                            if (tag->id == record.terms.principal_leg.asset_id && tag->amount != record.terms.principal_leg.units) {
                                asset_change_index = static_cast<int>(new_idx);
                            }
                        }

                        // Track BTC change if needed
                        if (appended_change_index == -1 && out.scriptPubKey != covenant_spk && out.scriptPubKey != borrower_spk) {
                            // Check if this looks like BTC change (no asset tag)
                            if (!assets::ParseAssetTag(out.vExt)) {
                                appended_change_index = static_cast<int>(new_idx);
                            }
                        }
                    }

                    std::optional<CTxOut> preserved_btc_change;
                    if (appended_change_index >= 0 && static_cast<size_t>(appended_change_index) < final_tx.vout.size()) {
                        preserved_btc_change = final_tx.vout[appended_change_index];
                    }

                    const auto extension_snapshots = CollectOutputExtensionSnapshots(final_tx);
                    std::vector<CRecipient> recipients;
                    recipients.reserve(final_tx.vout.size());
                    for (size_t i = 0; i < final_tx.vout.size(); ++i) {
                        CTxDestination dest;
                        if (!ExtractDestination(final_tx.vout[i].scriptPubKey, dest)) {
                            throw JSONRPCError(RPC_WALLET_ERROR,
                                strprintf("Merged principal output %u is not fundable", i));
                        }
                        recipients.push_back({dest, final_tx.vout[i].nValue, false});
                    }

                    CMutableTransaction tx_to_fund;
                    tx_to_fund.version = final_tx.version;
                    tx_to_fund.nLockTime = final_tx.nLockTime;
                    tx_to_fund.vin = final_tx.vin;

                    CCoinControl coin_control;
                    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
                    coin_control.m_avoid_asset_utxos = true;
                    coin_control.m_change_type = OutputType::BECH32M;
                    {
                        const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                        FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                        coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb * 1000));
                        coin_control.fOverrideFeeRate = true;
                    }
                    for (size_t i = 0; i < psbtx.inputs.size() && i < tx_to_fund.vin.size(); ++i) {
                        SeedForeignPsbtInputForFunding(*pwallet,
                                                       coin_control,
                                                       tx_to_fund.vin[i].prevout,
                                                       psbtx.inputs[i],
                                                       "Failed to finalize principal funding fees");
                    }

                    auto fund_res = FundTransaction(*pwallet, tx_to_fund, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
                    if (!fund_res) {
                        bilingual_str err = util::ErrorString(fund_res);
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to finalize principal funding fees: %s", err.original));
                    }

                    CMutableTransaction funded_tx(*fund_res->tx);
                    if (!extension_snapshots.empty() && !ReapplyOutputExtensionSnapshots(extension_snapshots, funded_tx)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to restore principal asset output metadata after fee funding");
                    }

                    final_tx = std::move(funded_tx);
                    lender_fee = fund_res->fee;
                    appended_change_index = fund_res->change_pos ? static_cast<int>(*fund_res->change_pos) : -1;
                    if (appended_change_index == -1 && preserved_btc_change.has_value()) {
                        for (size_t idx = 0; idx < final_tx.vout.size(); ++idx) {
                            const CTxOut& out = final_tx.vout[idx];
                            if (out.scriptPubKey == preserved_btc_change->scriptPubKey &&
                                out.nValue == preserved_btc_change->nValue &&
                                out.vExt == preserved_btc_change->vExt) {
                                appended_change_index = static_cast<int>(idx);
                                break;
                            }
                        }
                    }

                    asset_change_index = -1;
                    for (size_t idx = 0; idx < final_tx.vout.size(); ++idx) {
                        if (auto tag = assets::ParseAssetTag(final_tx.vout[idx].vExt)) {
                            if (tag->id == record.terms.principal_leg.asset_id && tag->amount != record.terms.principal_leg.units) {
                                asset_change_index = static_cast<int>(idx);
                                break;
                            }
                        }
                    }

                } else {
                    // NATIVE BTC PRINCIPAL: Use FundTransaction
                    std::vector<CRecipient> recipients;
                    recipients.push_back({record.borrower_dest, static_cast<CAmount>(record.terms.principal_leg.units), false});

                    CMutableTransaction funding_template;
                    funding_template.version = psbtx.tx->version;
                    funding_template.nLockTime = psbtx.tx->nLockTime;

                    CCoinControl coin_control;
                    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;

                    // PROTOCOL PREFERENCE: Prefer Taproot UTXOs for multi-party adaptor ceremonies.
                    // Non-Taproot inputs cannot participate in adaptor ceremony and require pre-signing
                    // which breaks atomicity. We try Taproot-only first, then fall back if insufficient funds.
                    coin_control.m_avoid_address_reuse = false; // Allow any UTXO, but we'll filter
                    coin_control.m_change_type = OutputType::BECH32M; // Force Taproot change for contract funding

                    // Set fee rate from strategy
                    {
                        const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                        FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                        LogPrintf("repo.build_open: Funding transaction - Setting fee_rate from strategy='%s', target_satvb=%u\n",
                                 effective_strategy, fee_snapshot.target_satvb);
                        coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb * 1000));
                        coin_control.fOverrideFeeRate = true;
                    }

                    // First attempt: Try to fund with Taproot-only UTXOs for optimal atomicity
                    std::set<COutPoint> taproot_coins;
                    {
                        LOCK(pwallet->cs_wallet);
                        auto coins_map = wallet::ListCoins(*pwallet);
                        for (const auto& [dest, outputs] : coins_map) {
                            if (std::holds_alternative<WitnessV1Taproot>(dest)) {
                                for (const COutput& out : outputs) {
                                    if (out.depth >= 0 && !pwallet->IsLockedCoin(out.outpoint)) {
                                        taproot_coins.insert(out.outpoint);
                                    }
                                }
                            }
                        }
                    }

                    util::Result<CreatedTransactionResult> fund_res = [&]() -> util::Result<CreatedTransactionResult> {
                        if (!taproot_coins.empty()) {
                            // Pre-select only Taproot coins - create fresh CCoinControl to avoid copy issues
                            CCoinControl taproot_only_control;
                            taproot_only_control.m_feerate = coin_control.m_feerate;
                            taproot_only_control.m_fee_mode = coin_control.m_fee_mode;
                            taproot_only_control.fOverrideFeeRate = coin_control.fOverrideFeeRate;
                            taproot_only_control.m_change_type = coin_control.m_change_type; // CRITICAL: Copy Taproot change type
                            taproot_only_control.m_allow_other_inputs = false; // Strict Taproot-only
                            for (const COutPoint& outpoint : taproot_coins) {
                                taproot_only_control.Select(outpoint);
                            }
                            pwallet->WalletLogPrintf("repo.build_open: Attempting Taproot-only funding (principal) with %zu UTXOs\n", taproot_coins.size());
                            auto result = FundTransaction(*pwallet, funding_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, taproot_only_control);
                            if (result) {
                                pwallet->WalletLogPrintf("repo.build_open: Successfully funded principal with Taproot-only UTXOs\n");
                                return result;
                            }
                        }
                        // Fallback: try with any UTXO
                        pwallet->WalletLogPrintf("repo.build_open: Taproot-only funding failed or unavailable, falling back to any UTXO\n");
                        return FundTransaction(*pwallet, funding_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
                    }();
                    if (!fund_res) {
                        bilingual_str err = util::ErrorString(fund_res);
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to fund principal: %s", err.original));
                    }

                    const CreatedTransactionResult& funded = fund_res.value();
                    lender_fee = funded.fee;

                    // Merge: borrower's inputs + lender's inputs
                    final_tx.vin = psbtx.tx->vin;
                    for (const CTxIn& txin : funded.tx->vin) {
                        final_tx.vin.push_back(txin);
                    }

                    // Outputs: borrower's original outputs (preserving vExt)
                    final_tx.vout = psbtx.tx->vout;

                    // Append principal output
                    for (size_t i = 0; i < funded.tx->vout.size(); ++i) {
                        const CTxOut& out = funded.tx->vout[i];
                        if (out.scriptPubKey == GetScriptForDestination(record.borrower_dest) &&
                            out.nValue == static_cast<CAmount>(record.terms.principal_leg.units)) {
                            final_tx.vout.push_back(out);
                            break;
                        }
                    }

                    // Append lender's BTC change if any
                    if (funded.change_pos && *funded.change_pos < funded.tx->vout.size()) {
                        const CTxOut& change_out = funded.tx->vout[*funded.change_pos];
                        appended_change_index = static_cast<int>(final_tx.vout.size());
                        final_tx.vout.push_back(change_out);
                    }
                }

                // Create PSBT from merged transaction
                PartiallySignedTransaction funded_psbt(final_tx);

                const size_t borrower_input_count = psbtx.inputs.size();
                const size_t borrower_output_count = psbtx.outputs.size();

                // Copy borrower's PSBT input/output metadata so contract annotations survive
                for (size_t i = 0; i < borrower_input_count && i < funded_psbt.inputs.size(); ++i) {
                    funded_psbt.inputs[i] = psbtx.inputs[i];
                }
                for (size_t i = 0; i < borrower_output_count && i < funded_psbt.outputs.size(); ++i) {
                    funded_psbt.outputs[i] = psbtx.outputs[i];
                }

                // Fill witness_utxo for lender's inputs
                for (size_t i = borrower_input_count; i < final_tx.vin.size(); ++i) {
                    const CTxIn& txin = final_tx.vin[i];
                    const CWalletTx* wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(txin.prevout.hash));
                    if (wtx && txin.prevout.n < wtx->tx->vout.size()) {
                        funded_psbt.inputs[i].witness_utxo = wtx->tx->vout[txin.prevout.n];
                    }
                }

                funded_psbt.m_proprietary = psbtx.m_proprietary;
                funded_psbt.unknown = psbtx.unknown;

                // Normalize sighash across inputs BEFORE FillPSBT to avoid mismatch errors
                NormalizePsbtSighash(funded_psbt, SIGHASH_DEFAULT);
                NormalizePsbtSighash(funded_psbt, SIGHASH_DEFAULT);
                bool funded_complete = false;
                if (const auto fill_err = pwallet->FillPSBT(funded_psbt, funded_complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                // Redundant normalization post-FillPSBT to cover any library side-effects
                NormalizePsbtSighash(funded_psbt, SIGHASH_DEFAULT);

                DataStream ssTx{};
                ssTx << funded_psbt;
                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("fee", ValueFromAmount(lender_fee));
                result.pushKV("changepos", appended_change_index);

                // Find and validate output indices in final merged PSBT
                std::optional<size_t> principal_idx;
                covenant_idx.reset();
                const CScript borrower_spk = GetScriptForDestination(record.borrower_dest);
                const CAmount expected_principal_value = record.terms.principal_leg.is_native ?
                    static_cast<CAmount>(record.terms.principal_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                for (size_t i = 0; i < funded_psbt.tx->vout.size(); ++i) {
                    const CTxOut& out = funded_psbt.tx->vout[i];
                    if (!principal_idx && out.scriptPubKey == borrower_spk) {
                        if (out.nValue != expected_principal_value) {
                            throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                                "Principal output amount mismatch: expected %s, got %s",
                                FormatMoney(expected_principal_value), FormatMoney(out.nValue)));
                        }
                        if (!record.terms.principal_leg.is_native) {
                            auto tag = assets::ParseAssetTag(out.vExt);
                            if (!tag || tag->id != record.terms.principal_leg.asset_id ||
                                tag->amount != record.terms.principal_leg.units) {
                                throw JSONRPCError(RPC_WALLET_ERROR, "Principal asset tag mismatch");
                            }
                        }
                        principal_idx = i;
                    }
                    if (!covenant_idx && out.scriptPubKey == covenant_spk) {
                        covenant_idx = i;
                    }
                }
                if (!principal_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Principal output missing from funded PSBT");
                }
                if (!covenant_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Covenant output missing from funded PSBT");
                }

                result.pushKV("principal_output_index", static_cast<int>(*principal_idx));
                result.pushKV("covenant_output_index", static_cast<int>(*covenant_idx));
                result.pushKV("asset_change_output_index", asset_change_index);

                UniValue taproot_obj(UniValue::VOBJ);
                taproot_obj.pushKV("output_key", HexStr(builder.GetOutput()));
                taproot_obj.pushKV("internal_key", HexStr(borrower_key));
                taproot_obj.pushKV("script_pubkey", HexStr(covenant_spk));
                UniValue tree_arr(UniValue::VARR);
                for (const auto& info : builder.GetTreeTuples()) {
                    UniValue leaf_obj(UniValue::VOBJ);
                    leaf_obj.pushKV("depth", static_cast<int>(std::get<0>(info)));
                    leaf_obj.pushKV("leaf_version", static_cast<int>(std::get<1>(info)));
                    leaf_obj.pushKV("script", HexStr(std::get<2>(info)));
                    tree_arr.push_back(leaf_obj);
                }
                taproot_obj.pushKV("tree", tree_arr);
                result.pushKV("taproot", taproot_obj);

                // Check if PSBT is complete
                CMutableTransaction dummy_tx;
                bool is_complete = FinalizeAndExtractPSBT(funded_psbt, dummy_tx);
                result.pushKV("complete", is_complete);
                return result;
            }

            // BORROWER MODE: Add collateral funding to existing PSBT from lender
            if (auto_fund_collateral && !psbt_val.isNull()) {
                const std::string psbt_str = psbt_val.get_str();
                PartiallySignedTransaction psbtx;
                std::string error;
                if (!DecodeBase64PSBT(psbtx, psbt_str, error)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode PSBT: %s", error));
                }

                // Find and validate covenant and principal outputs in lender's PSBT
                std::optional<size_t> covenant_idx;
                std::optional<size_t> principal_idx;
                const CScript borrower_spk = GetScriptForDestination(record.borrower_dest);
                const CAmount expected_principal_value = record.terms.principal_leg.is_native ?
                    static_cast<CAmount>(record.terms.principal_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                for (size_t i = 0; i < psbtx.tx->vout.size(); ++i) {
                    const CTxOut& out = psbtx.tx->vout[i];
                    if (out.scriptPubKey == covenant_spk) {
                        covenant_idx = i;
                    }
                    if (!principal_idx && out.scriptPubKey == borrower_spk) {
                        if (out.nValue != expected_principal_value) {
                            throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                                "Principal output amount mismatch: expected %s, got %s",
                                FormatMoney(expected_principal_value), FormatMoney(out.nValue)));
                        }
                        if (!record.terms.principal_leg.is_native) {
                            auto tag = assets::ParseAssetTag(out.vExt);
                            if (!tag || tag->id != record.terms.principal_leg.asset_id ||
                                tag->amount != record.terms.principal_leg.units) {
                                throw JSONRPCError(RPC_WALLET_ERROR, "Principal asset tag mismatch");
                            }
                        }
                        principal_idx = i;
                    }
                }
                if (!covenant_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Could not find covenant output in lender's PSBT");
                }
                if (!principal_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Principal output missing from lender's PSBT");
                }

                CMutableTransaction final_tx;
                final_tx.version = psbtx.tx->version;
                final_tx.nLockTime = psbtx.tx->nLockTime;
                CAmount borrower_fee = 0;
                int appended_change_index = -1;
                int asset_change_index = -1;

                // Check if collateral is an asset (requires sendasset) or native BTC (use FundTransaction)
                if (!record.terms.collateral_leg.is_native) {
                    // ASSET COLLATERAL: Use sendasset() to properly fund with asset inputs + TLV
                    JSONRPCRequest sendasset_req;
                    sendasset_req.context = request.context;
                    sendasset_req.URI = request.URI;
                    sendasset_req.strMethod = "sendasset";

                    // Build params: [asset_id, covenant_address, amount, {return_skeleton: true}]
                    UniValue sendasset_params(UniValue::VARR);
                    sendasset_params.push_back(record.terms.collateral_leg.asset_id.ToString());

                    // Get covenant address for sendasset destination
                    const CTxDestination covenant_dest = WitnessV1Taproot{builder.GetOutput()};
                    sendasset_params.push_back(EncodeDestination(covenant_dest));
                    sendasset_params.push_back(record.terms.collateral_leg.units);

                    UniValue sendasset_opts(UniValue::VOBJ);
                    sendasset_opts.pushKV("return_skeleton", true);
                    sendasset_opts.pushKV("broadcast", false);
                    {
                        const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                        FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                        LogPrintf("repo.build_open: Collateral sendasset using strategy='%s', target_satvb=%u, passing fee_rate=%u to sendasset\n",
                                 effective_strategy, fee_snapshot.target_satvb, fee_snapshot.target_satvb);
                        sendasset_opts.pushKV("fee_rate", fee_snapshot.target_satvb);
                    }
                    sendasset_params.push_back(sendasset_opts);

                    sendasset_req.params = sendasset_params;

                    // Call sendasset() to get skeleton with asset inputs, covenant output, and change
                    UniValue skeleton_result = sendasset().HandleRequest(sendasset_req);

                    if (!skeleton_result.isObject() || !skeleton_result.exists("hex")) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset did not return valid skeleton for collateral");
                    }

                    CMutableTransaction collateral_skeleton;
                    if (!DecodeHexTx(collateral_skeleton, skeleton_result["hex"].get_str())) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode sendasset skeleton for collateral");
                    }

                    // Merge transactions: lender's inputs/outputs + borrower's collateral skeleton
                    final_tx.vin = psbtx.tx->vin;
                    for (const CTxIn& txin : collateral_skeleton.vin) {
                        final_tx.vin.push_back(txin);
                    }

                    // Start with lender's outputs (principal + covenant placeholder)
                    final_tx.vout = psbtx.tx->vout;

                    // Find the covenant output in skeleton (should have proper asset tag)
                    std::optional<size_t> skeleton_covenant_idx;
                    for (size_t i = 0; i < collateral_skeleton.vout.size(); ++i) {
                        if (collateral_skeleton.vout[i].scriptPubKey == covenant_spk) {
                            skeleton_covenant_idx = i;
                            break;
                        }
                    }

                    if (!skeleton_covenant_idx) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "sendasset skeleton missing covenant output");
                    }

                    // Replace lender's covenant placeholder with skeleton's properly-tagged covenant output
                    final_tx.vout[*covenant_idx] = collateral_skeleton.vout[*skeleton_covenant_idx];

                    // Append any change outputs from skeleton (asset change + optional BTC change)
                    for (size_t i = 0; i < collateral_skeleton.vout.size(); ++i) {
                        if (i == *skeleton_covenant_idx) continue; // Skip covenant (already placed)

                        const CTxOut& out = collateral_skeleton.vout[i];
                        const size_t new_idx = final_tx.vout.size();
                        final_tx.vout.push_back(out);

                        // Track asset change output
                        if (auto tag = assets::ParseAssetTag(out.vExt)) {
                            if (tag->id == record.terms.collateral_leg.asset_id && tag->amount != record.terms.collateral_leg.units) {
                                asset_change_index = static_cast<int>(new_idx);
                            }
                        }

                        // Track BTC change if needed
                        if (appended_change_index == -1 && out.scriptPubKey != covenant_spk) {
                            // Check if this looks like BTC change (no asset tag, not covenant)
                            if (!assets::ParseAssetTag(out.vExt)) {
                                appended_change_index = static_cast<int>(new_idx);
                            }
                        }
                    }

                    std::optional<CTxOut> preserved_btc_change;
                    if (appended_change_index >= 0 && static_cast<size_t>(appended_change_index) < final_tx.vout.size()) {
                        preserved_btc_change = final_tx.vout[appended_change_index];
                    }

                    const auto extension_snapshots = CollectOutputExtensionSnapshots(final_tx);
                    std::vector<CRecipient> recipients;
                    recipients.reserve(final_tx.vout.size());
                    for (size_t i = 0; i < final_tx.vout.size(); ++i) {
                        CTxDestination dest;
                        if (!ExtractDestination(final_tx.vout[i].scriptPubKey, dest)) {
                            throw JSONRPCError(RPC_WALLET_ERROR,
                                strprintf("Merged collateral output %u is not fundable", i));
                        }
                        recipients.push_back({dest, final_tx.vout[i].nValue, false});
                    }

                    CMutableTransaction tx_to_fund;
                    tx_to_fund.version = final_tx.version;
                    tx_to_fund.nLockTime = final_tx.nLockTime;
                    tx_to_fund.vin = final_tx.vin;

                    CCoinControl coin_control;
                    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
                    coin_control.m_avoid_asset_utxos = true;
                    coin_control.m_change_type = OutputType::BECH32M;
                    {
                        const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                        FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                        coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb * 1000));
                        coin_control.fOverrideFeeRate = true;
                    }
                    for (size_t i = 0; i < psbtx.inputs.size() && i < tx_to_fund.vin.size(); ++i) {
                        SeedForeignPsbtInputForFunding(*pwallet,
                                                       coin_control,
                                                       tx_to_fund.vin[i].prevout,
                                                       psbtx.inputs[i],
                                                       "Failed to finalize collateral funding fees");
                    }

                    auto fund_res = FundTransaction(*pwallet, tx_to_fund, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
                    if (!fund_res) {
                        bilingual_str err = util::ErrorString(fund_res);
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to finalize collateral funding fees: %s", err.original));
                    }

                    CMutableTransaction funded_tx(*fund_res->tx);
                    if (!extension_snapshots.empty() && !ReapplyOutputExtensionSnapshots(extension_snapshots, funded_tx)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to restore collateral asset output metadata after fee funding");
                    }

                    final_tx = std::move(funded_tx);
                    borrower_fee = fund_res->fee;
                    appended_change_index = fund_res->change_pos ? static_cast<int>(*fund_res->change_pos) : -1;
                    if (appended_change_index == -1 && preserved_btc_change.has_value()) {
                        for (size_t idx = 0; idx < final_tx.vout.size(); ++idx) {
                            const CTxOut& out = final_tx.vout[idx];
                            if (out.scriptPubKey == preserved_btc_change->scriptPubKey &&
                                out.nValue == preserved_btc_change->nValue &&
                                out.vExt == preserved_btc_change->vExt) {
                                appended_change_index = static_cast<int>(idx);
                                break;
                            }
                        }
                    }

                    asset_change_index = -1;
                    for (size_t idx = 0; idx < final_tx.vout.size(); ++idx) {
                        if (auto tag = assets::ParseAssetTag(final_tx.vout[idx].vExt)) {
                            if (tag->id == record.terms.collateral_leg.asset_id && tag->amount != record.terms.collateral_leg.units) {
                                asset_change_index = static_cast<int>(idx);
                                break;
                            }
                        }
                    }

                } else {
                    // NATIVE BTC COLLATERAL: Use FundTransaction
                    std::vector<CRecipient> recipients;
                    recipients.push_back({CNoDestination(), static_cast<CAmount>(record.terms.collateral_leg.units), false});

                    CMutableTransaction funding_template;
                    funding_template.version = psbtx.tx->version;
                    funding_template.nLockTime = psbtx.tx->nLockTime;

                    CCoinControl coin_control;
                    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;

                    // PROTOCOL PREFERENCE: Prefer Taproot UTXOs for multi-party adaptor ceremonies.
                    // Non-Taproot inputs cannot participate in adaptor ceremony and require pre-signing
                    // which breaks atomicity. We try Taproot-only first, then fall back if insufficient funds.
                    coin_control.m_avoid_address_reuse = false; // Allow any UTXO, but we'll filter
                    coin_control.m_change_type = OutputType::BECH32M; // Force Taproot change for contract funding

                    // Set fee rate from strategy
                    {
                        const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                        FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                        LogPrintf("repo.build_open: Funding transaction - Setting fee_rate from strategy='%s', target_satvb=%u\n",
                                 effective_strategy, fee_snapshot.target_satvb);
                        coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb * 1000));
                        coin_control.fOverrideFeeRate = true;
                    }

                    // First attempt: Try to fund with Taproot-only UTXOs for optimal atomicity
                    std::set<COutPoint> taproot_coins;
                    {
                        LOCK(pwallet->cs_wallet);
                        auto coins_map = wallet::ListCoins(*pwallet);
                        for (const auto& [dest, outputs] : coins_map) {
                            if (std::holds_alternative<WitnessV1Taproot>(dest)) {
                                for (const COutput& out : outputs) {
                                    if (out.depth >= 0 && !pwallet->IsLockedCoin(out.outpoint)) {
                                        taproot_coins.insert(out.outpoint);
                                    }
                                }
                            }
                        }
                    }

                    util::Result<CreatedTransactionResult> fund_res = [&]() -> util::Result<CreatedTransactionResult> {
                        if (!taproot_coins.empty()) {
                            // Pre-select only Taproot coins - create fresh CCoinControl to avoid copy issues
                            CCoinControl taproot_only_control;
                            taproot_only_control.m_feerate = coin_control.m_feerate;
                            taproot_only_control.m_fee_mode = coin_control.m_fee_mode;
                            taproot_only_control.fOverrideFeeRate = coin_control.fOverrideFeeRate;
                            taproot_only_control.m_change_type = coin_control.m_change_type; // CRITICAL: Copy Taproot change type
                            taproot_only_control.m_allow_other_inputs = false; // Strict Taproot-only
                            for (const COutPoint& outpoint : taproot_coins) {
                                taproot_only_control.Select(outpoint);
                            }
                            pwallet->WalletLogPrintf("repo.build_open: Attempting Taproot-only funding (collateral) with %zu UTXOs\n", taproot_coins.size());
                            auto result = FundTransaction(*pwallet, funding_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, taproot_only_control);
                            if (result) {
                                pwallet->WalletLogPrintf("repo.build_open: Successfully funded collateral with Taproot-only UTXOs\n");
                                return result;
                            }
                        }
                        // Fallback: try with any UTXO
                        pwallet->WalletLogPrintf("repo.build_open: Taproot-only funding failed or unavailable, falling back to any UTXO\n");
                        return FundTransaction(*pwallet, funding_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
                    }();
                    if (!fund_res) {
                        bilingual_str err = util::ErrorString(fund_res);
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to fund collateral: %s", err.original));
                    }

                    const CreatedTransactionResult& funded = fund_res.value();
                    borrower_fee = funded.fee;

                    // Merge: lender's inputs + borrower's inputs
                    final_tx.vin = psbtx.tx->vin;
                    for (const CTxIn& txin : funded.tx->vin) {
                        final_tx.vin.push_back(txin);
                    }

                    // Outputs: lender's original outputs (preserving vExt)
                    final_tx.vout = psbtx.tx->vout;

                    // Append borrower's BTC change if any
                    if (funded.change_pos && *funded.change_pos < funded.tx->vout.size()) {
                        const CTxOut& change_out = funded.tx->vout[*funded.change_pos];
                        appended_change_index = static_cast<int>(final_tx.vout.size());
                        final_tx.vout.push_back(change_out);
                    }
                }

                // Create PSBT from merged transaction
                PartiallySignedTransaction funded_psbt(final_tx);

                const size_t lender_input_count = psbtx.inputs.size();
                const size_t lender_output_count = psbtx.outputs.size();

                // Copy lender's PSBT input/output metadata so contract annotations survive
                for (size_t i = 0; i < lender_input_count && i < funded_psbt.inputs.size(); ++i) {
                    funded_psbt.inputs[i] = psbtx.inputs[i];
                }
                for (size_t i = 0; i < lender_output_count && i < funded_psbt.outputs.size(); ++i) {
                    funded_psbt.outputs[i] = psbtx.outputs[i];
                }

                // Fill witness_utxo for borrower's inputs
                for (size_t i = lender_input_count; i < final_tx.vin.size(); ++i) {
                    const CTxIn& txin = final_tx.vin[i];
                    const CWalletTx* wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(txin.prevout.hash));
                    if (wtx && txin.prevout.n < wtx->tx->vout.size()) {
                        funded_psbt.inputs[i].witness_utxo = wtx->tx->vout[txin.prevout.n];
                    }
                }

                funded_psbt.m_proprietary = psbtx.m_proprietary;
                funded_psbt.unknown = psbtx.unknown;

                bool funded_complete = false;
                if (const auto fill_err = pwallet->FillPSBT(funded_psbt, funded_complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                NormalizePsbtSighash(funded_psbt, SIGHASH_DEFAULT);

                DataStream ssTx{};
                ssTx << funded_psbt;
                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("fee", ValueFromAmount(borrower_fee));
                result.pushKV("changepos", appended_change_index);

                // Find output indices (reuse expected_principal_value/principal_idx defined above)
                principal_idx.reset();
                covenant_idx.reset();
                for (size_t i = 0; i < funded_psbt.tx->vout.size(); ++i) {
                    const CTxOut& out = funded_psbt.tx->vout[i];
                    if (!principal_idx && out.scriptPubKey == borrower_spk && out.nValue == expected_principal_value) {
                        principal_idx = i;
                    }
                    if (!covenant_idx && out.scriptPubKey == covenant_spk) {
                        covenant_idx = i;
                    }
                }

                result.pushKV("principal_output_index", principal_idx.has_value() ? static_cast<int>(*principal_idx) : -1);
                result.pushKV("covenant_output_index", covenant_idx.has_value() ? static_cast<int>(*covenant_idx) : -1);
                result.pushKV("asset_change_output_index", asset_change_index);

                UniValue taproot_obj(UniValue::VOBJ);
                taproot_obj.pushKV("output_key", HexStr(builder.GetOutput()));
                taproot_obj.pushKV("internal_key", HexStr(borrower_key));
                taproot_obj.pushKV("script_pubkey", HexStr(covenant_spk));
                UniValue tree_arr(UniValue::VARR);
                for (const auto& info : builder.GetTreeTuples()) {
                    UniValue leaf_obj(UniValue::VOBJ);
                    leaf_obj.pushKV("depth", static_cast<int>(std::get<0>(info)));
                    leaf_obj.pushKV("leaf_version", static_cast<int>(std::get<1>(info)));
                    leaf_obj.pushKV("script", HexStr(std::get<2>(info)));
                    tree_arr.push_back(leaf_obj);
                }
                taproot_obj.pushKV("tree", tree_arr);
                result.pushKV("taproot", taproot_obj);

                // Check if PSBT is complete
                CMutableTransaction dummy_tx;
                bool is_complete = FinalizeAndExtractPSBT(funded_psbt, dummy_tx);
                result.pushKV("complete", is_complete);
                return result;
            }

            // NORMAL MODE: Build from scratch
            std::vector<CRecipient> recipients;
            if (record.terms.principal_leg.is_native) {
                recipients.push_back({record.borrower_dest, static_cast<CAmount>(record.terms.principal_leg.units), /*subtract fee*/ false});
            } else {
                recipients.push_back({record.borrower_dest, DEFAULT_REPO_ASSET_OUTPUT_VALUE, /*subtract fee*/ false});
            }

            // When lender builds (auto_fund_principal=true), don't include covenant in FundTransaction recipients
            // The covenant output will be added manually after, and borrower will fund it via auto_fund_collateral mode
            if (!auto_fund_principal) {
                // Covenant holds collateral only (principal goes directly to borrower, not into vault)
                // Native collateral: use satoshi amount; Asset collateral: use dust amount (asset tag in vExt)
                const CAmount covenant_value = record.terms.collateral_leg.is_native ?
                    static_cast<CAmount>(record.terms.collateral_leg.units) :
                    DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                recipients.push_back({covenant_output, covenant_value, /*subtract fee*/ false});
            }

            // BORROWER AS MAKER MODE WITH ASSET COLLATERAL: Handle completely separately (like BORROWER MODE at 4026-4282)
            // Build the complete PSBT inline and return early, don't try to fit into NORMAL MODE flow
            if (!auto_fund_principal && !record.terms.collateral_leg.is_native) {
                // Call sendasset for collateral
                JSONRPCRequest sendasset_req;
                sendasset_req.context = request.context;
                sendasset_req.URI = request.URI;
                sendasset_req.strMethod = "sendasset";

                UniValue sendasset_params(UniValue::VARR);
                sendasset_params.push_back(record.terms.collateral_leg.asset_id.ToString());
                sendasset_params.push_back(EncodeDestination(covenant_output));
                sendasset_params.push_back(record.terms.collateral_leg.units);

                UniValue sendasset_opts(UniValue::VOBJ);
                sendasset_opts.pushKV("return_skeleton", true);
                sendasset_opts.pushKV("broadcast", false);
                // Use fee strategy from options (or stored policy), not hardcoded 1.5
                {
                    const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                    FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                    LogPrintf("repo.build_open: Collateral sendasset using strategy='%s', target_satvb=%u, passing fee_rate=%u to sendasset\n",
                             effective_strategy, fee_snapshot.target_satvb, fee_snapshot.target_satvb);
                    sendasset_opts.pushKV("fee_rate", fee_snapshot.target_satvb);
                }
                sendasset_params.push_back(sendasset_opts);

                sendasset_req.params = sendasset_params;

                UniValue skeleton_result = sendasset().HandleRequest(sendasset_req);
                if (!skeleton_result.isObject() || !skeleton_result.exists("hex")) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset did not return valid skeleton for collateral");
                }

                CMutableTransaction collateral_skeleton;
                if (!DecodeHexTx(collateral_skeleton, skeleton_result["hex"].get_str())) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode sendasset skeleton for collateral");
                }

                // Find covenant in skeleton
                std::optional<size_t> skeleton_covenant_idx;
                for (size_t i = 0; i < collateral_skeleton.vout.size(); ++i) {
                    if (collateral_skeleton.vout[i].scriptPubKey == covenant_spk) {
                        skeleton_covenant_idx = i;
                        break;
                    }
                }
                if (!skeleton_covenant_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "sendasset skeleton missing covenant output");
                }

                // Use skeleton directly - taker-lender will add principal later (lines 3783-3850)
                CMutableTransaction final_tx = collateral_skeleton;

                CAmount borrower_fee = 0;
                if (skeleton_result.exists("fee")) {
                    borrower_fee = AmountFromValue(skeleton_result["fee"]);
                }

                // Build PSBT and return (matching BORROWER MODE pattern at lines 4205-4282)
                PartiallySignedTransaction psbt(final_tx);

                // Fill witness_utxo for our inputs
                for (size_t i = 0; i < final_tx.vin.size(); ++i) {
                    const CTxIn& txin = final_tx.vin[i];
                    const CWalletTx* wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(txin.prevout.hash));
                    if (wtx && txin.prevout.n < wtx->tx->vout.size()) {
                        psbt.inputs[i].witness_utxo = wtx->tx->vout[txin.prevout.n];
                    }
                }

                bool psbt_complete = false;
                if (const auto fill_err = pwallet->FillPSBT(psbt, psbt_complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);

                // Use fee strategy from options (or stored policy)
                {
                    const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                    FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                    LogPrintf("repo.build_open: Annotating PSBT with strategy='%s', target_satvb=%u, min_satvb=%u\n",
                             effective_strategy, fee_snapshot.target_satvb, fee_snapshot.min_satvb);
                    if (pwallet->m_signal_rbf) fee_snapshot.rbf = true;
                    AnnotateRepoGlobalMetadata(psbt, record, repay_dest, fee_snapshot);
                }

                DataStream ssTx{};
                ssTx << psbt;

                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("fee", ValueFromAmount(borrower_fee));
                result.pushKV("changepos", -1);

                // Find covenant output index
                result.pushKV("principal_output_index", -1);  // Taker-lender will add principal
                result.pushKV("covenant_output_index", static_cast<int>(*skeleton_covenant_idx));
                result.pushKV("asset_change_output_index", -1);

                UniValue taproot_obj(UniValue::VOBJ);
                taproot_obj.pushKV("output_key", HexStr(builder.GetOutput()));
                taproot_obj.pushKV("internal_key", HexStr(borrower_key));
                taproot_obj.pushKV("script_pubkey", HexStr(covenant_spk));
                UniValue tree_arr(UniValue::VARR);
                for (const auto& info : builder.GetTreeTuples()) {
                    UniValue leaf_obj(UniValue::VOBJ);
                    leaf_obj.pushKV("depth", static_cast<int>(std::get<0>(info)));
                    leaf_obj.pushKV("leaf_version", static_cast<int>(std::get<1>(info)));
                    leaf_obj.pushKV("script", HexStr(std::get<2>(info)));
                    tree_arr.push_back(leaf_obj);
                }
                taproot_obj.pushKV("tree", tree_arr);
                result.pushKV("taproot", taproot_obj);

                CMutableTransaction dummy_tx;
                const bool is_complete = FinalizeAndExtractPSBT(psbt, dummy_tx);
                result.pushKV("complete", is_complete);
                return result;
            }

            // BORROWER AS MAKER WITH NATIVE COLLATERAL + ASSET PRINCIPAL:
            // Borrower funds only the covenant with native collateral.
            // Lender will add principal (asset) output when merging the PSBT.
            // This prevents adding an asset tag without asset inputs ("asset-mint-unauthorized").
            if (!auto_fund_principal && record.terms.collateral_leg.is_native && !record.terms.principal_leg.is_native) {
                // Only fund the covenant, no principal placeholder needed
                std::vector<CRecipient> collateral_recipients;
                const CAmount covenant_value = static_cast<CAmount>(record.terms.collateral_leg.units);
                collateral_recipients.push_back({covenant_output, covenant_value, /*subtract fee*/ false});

                CCoinControl coin_control;
                coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;

                // Set fee rate from strategy
                {
                    const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                    FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                    LogPrintf("repo.build_open: Borrower/maker native collateral + asset principal - Setting coin_control fee_rate from strategy='%s', target_satvb=%u\n",
                             effective_strategy, fee_snapshot.target_satvb);
                    coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb * 1000));
                    coin_control.fOverrideFeeRate = true;
                }

                CMutableTransaction tx_template;
                tx_template.version = 2;

                auto fund_res = FundTransaction(*pwallet, tx_template, collateral_recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
                if (!fund_res) {
                    bilingual_str err = util::ErrorString(fund_res);
                    throw JSONRPCError(RPC_WALLET_ERROR, err.original);
                }

                const CreatedTransactionResult& tx_result = fund_res.value();
                CMutableTransaction funded_tx(*tx_result.tx);

                // Find covenant output index
                std::optional<size_t> covenant_idx;
                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    if (funded_tx.vout[i].scriptPubKey == covenant_spk) {
                        covenant_idx = i;
                        break;
                    }
                }
                if (!covenant_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify covenant output in funded transaction");
                }

                // Build PSBT
                PartiallySignedTransaction psbt(funded_tx);

                // Fill witness_utxo for our inputs
                for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
                    const CTxIn& txin = funded_tx.vin[i];
                    const CWalletTx* wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(txin.prevout.hash));
                    if (wtx && txin.prevout.n < wtx->tx->vout.size()) {
                        psbt.inputs[i].witness_utxo = wtx->tx->vout[txin.prevout.n];
                    }
                }

                bool psbt_complete = false;
                if (const auto fill_err = pwallet->FillPSBT(psbt, psbt_complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);

                // Annotate PSBT with metadata
                {
                    const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                    FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                    LogPrintf("repo.build_open: Borrower/maker native collateral + asset principal - Annotating PSBT with strategy='%s'\n", effective_strategy);
                    if (pwallet->m_signal_rbf) fee_snapshot.rbf = true;
                    AnnotateRepoGlobalMetadata(psbt, record, repay_dest, fee_snapshot);
                }

                DataStream ssTx{};
                ssTx << psbt;

                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("fee", ValueFromAmount(tx_result.fee));
                result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);

                // Principal will be added by lender-taker
                result.pushKV("principal_output_index", -1);
                result.pushKV("covenant_output_index", static_cast<int>(*covenant_idx));
                result.pushKV("asset_change_output_index", -1);

                UniValue taproot_obj(UniValue::VOBJ);
                taproot_obj.pushKV("output_key", HexStr(builder.GetOutput()));
                taproot_obj.pushKV("internal_key", HexStr(borrower_key));
                taproot_obj.pushKV("script_pubkey", HexStr(covenant_spk));
                UniValue tree_arr(UniValue::VARR);
                for (const auto& info : builder.GetTreeTuples()) {
                    UniValue leaf_obj(UniValue::VOBJ);
                    leaf_obj.pushKV("depth", static_cast<int>(std::get<0>(info)));
                    leaf_obj.pushKV("leaf_version", static_cast<int>(std::get<1>(info)));
                    leaf_obj.pushKV("script", HexStr(std::get<2>(info)));
                    tree_arr.push_back(leaf_obj);
                }
                taproot_obj.pushKV("tree", tree_arr);
                result.pushKV("taproot", taproot_obj);

                CMutableTransaction dummy_tx;
                const bool is_complete = FinalizeAndExtractPSBT(psbt, dummy_tx);
                result.pushKV("complete", is_complete);
                return result;
            }

            // NORMAL MODE: lender is maker (funds principal, borrower adds collateral later)
            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;

            // Set fee rate from strategy
            {
                const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                LogPrintf("repo.build_open: Lender/borrower native path - Setting coin_control fee_rate from strategy='%s', target_satvb=%u (CFeeRate=%d sat/kvB)\n",
                         effective_strategy, fee_snapshot.target_satvb, fee_snapshot.target_satvb * 1000);
                coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb * 1000));
                coin_control.fOverrideFeeRate = true;
            }

            const UniValue& locktime_val = opts.isNull() ? NullUniValue : opts.find_value("locktime");

            CMutableTransaction tx_template;
            tx_template.version = 2;
            if (!locktime_val.isNull()) {
                int64_t locktime = ParseSignedInt64(locktime_val, "options.locktime");
                if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options.locktime out of range");
                }
                tx_template.nLockTime = static_cast<uint32_t>(locktime);
            }

            auto fund_res = FundTransaction(*pwallet, tx_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
            if (!fund_res) {
                bilingual_str err = util::ErrorString(fund_res);
                throw JSONRPCError(RPC_WALLET_ERROR, err.original);
            }

            const CreatedTransactionResult& tx_result = fund_res.value();
            CMutableTransaction funded_tx(*tx_result.tx);

            struct PrincipalAssetContribution {
                COutPoint outpoint;
                CTxOut txout;
                uint64_t units;
            };
            std::vector<PrincipalAssetContribution> principal_asset_inputs;
            uint64_t principal_asset_change_units{0};
            std::optional<CTxDestination> principal_change_dest;

            // LENDER MODE: When auto_fund_principal=true and principal is an asset,
            // delegate to sendasset() with return_skeleton=true
            // This handles: asset UTXO selection, change, asset TLV construction, KYC proofs, key wrapping
            CMutableTransaction skeleton_tx;
            if (auto_fund_principal && !record.terms.principal_leg.is_native) {
                JSONRPCRequest sendasset_req;
                sendasset_req.context = request.context;
                sendasset_req.URI = request.URI;  // Preserve wallet routing (/wallet/<name>)
                sendasset_req.strMethod = "sendasset";

                // Build params: [asset_id, borrower_address, amount, {return_skeleton: true}]
                UniValue sendasset_params(UniValue::VARR);
                sendasset_params.push_back(record.terms.principal_leg.asset_id.ToString());
                sendasset_params.push_back(EncodeDestination(record.borrower_dest));
                sendasset_params.push_back(record.terms.principal_leg.units);

                // Options: return_skeleton=true, broadcast=false
                UniValue sendasset_opts(UniValue::VOBJ);
                sendasset_opts.pushKV("return_skeleton", true);
                sendasset_opts.pushKV("broadcast", false);
                {
                    const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                    FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                    LogPrintf("repo.build_open: Principal sendasset using strategy='%s', target_satvb=%u, passing fee_rate=%u to sendasset\n",
                             effective_strategy, fee_snapshot.target_satvb, fee_snapshot.target_satvb);
                    sendasset_opts.pushKV("fee_rate", fee_snapshot.target_satvb);
                }
                sendasset_params.push_back(sendasset_opts);

                sendasset_req.params = sendasset_params;

                // Call sendasset()
                UniValue skeleton_result = sendasset().HandleRequest(sendasset_req);

                // Extract skeleton: contains hex, asset_inputs, btc_inputs, outputs
                if (!skeleton_result.isObject() || !skeleton_result.exists("hex")) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset did not return valid skeleton");
                }

                // Decode the transaction skeleton
                if (!DecodeHexTx(skeleton_tx, skeleton_result["hex"].get_str())) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode sendasset skeleton");
                }

                // Use skeleton as base funded_tx
                funded_tx = skeleton_tx;
            }

            const CAmount expected_principal_value = record.terms.principal_leg.is_native ? static_cast<CAmount>(record.terms.principal_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

            // Covenant holds collateral only (principal goes directly to borrower, not into vault)
            // Native collateral: use satoshi amount; Asset collateral: use dust amount (asset tag in vExt)
            const CAmount expected_covenant_value = record.terms.collateral_leg.is_native ?
                static_cast<CAmount>(record.terms.collateral_leg.units) :
                DEFAULT_REPO_ASSET_OUTPUT_VALUE;

            std::optional<size_t> principal_original_index;
            std::optional<size_t> covenant_original_index;

            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                const CTxOut& out = funded_tx.vout[i];
                if (!principal_original_index && out.scriptPubKey == borrower_spk && out.nValue == expected_principal_value) {
                    principal_original_index = i;
                    continue;
                }
                if (!covenant_original_index && out.scriptPubKey == covenant_spk && out.nValue == expected_covenant_value) {
                    covenant_original_index = i;
                }
            }

            if (!principal_original_index) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify principal output in funded transaction");
            }

            // When lender builds (auto_fund_principal=true), covenant output wasn't funded, so add it manually now
            if (auto_fund_principal && !covenant_original_index) {
                CTxOut covenant_out;
                covenant_out.scriptPubKey = covenant_spk;
                covenant_out.nValue = expected_covenant_value;
                funded_tx.vout.push_back(covenant_out);
                covenant_original_index = funded_tx.vout.size() - 1;
            }

            if (!covenant_original_index) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify covenant output in funded transaction");
            }

            // Only set vExt when lender is building (auto_fund_principal=true) and principal is an asset.
            // When borrower is maker (auto_fund_principal=false), they create a bare placeholder output.
            // The lender will add the proper asset output with matching inputs when merging the PSBT.
            // If borrower adds asset tag without asset inputs, it causes "asset-mint-unauthorized".
            if (auto_fund_principal && !record.terms.principal_leg.is_native) {
                // Only set vExt if sendasset didn't already populate it (with ICU_KEYWRAP if needed)
                if (funded_tx.vout[*principal_original_index].vExt.empty()) {
                    funded_tx.vout[*principal_original_index].vExt = BuildAssetTagTlv(record.terms.principal_leg.asset_id, record.terms.principal_leg.units);
                }
            }

            std::optional<unsigned int> final_change_pos;
            std::vector<size_t> change_indices;
            const auto track_change = [&](size_t original_index, size_t new_index) {
                if (tx_result.change_pos && original_index == *tx_result.change_pos) {
                    final_change_pos = static_cast<unsigned int>(new_index);
                    change_indices.push_back(new_index);
                }
            };

            std::vector<CTxOut> reordered;
            reordered.reserve(funded_tx.vout.size());

            reordered.push_back(funded_tx.vout[*principal_original_index]);
            track_change(*principal_original_index, 0);

            // If principal and covenant refer to same original index (shouldn't), avoid double push
            reordered.push_back(funded_tx.vout[*covenant_original_index]);
            track_change(*covenant_original_index, 1);

            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                if (i == *principal_original_index || i == *covenant_original_index) continue;
                track_change(i, reordered.size());
                reordered.push_back(funded_tx.vout[i]);
            }

            funded_tx.vout = std::move(reordered);

            int asset_change_output_index = -1;
            const auto register_change_output_if_needed = [&](int index) {
                if (index < 0) return;
                change_indices.push_back(static_cast<size_t>(index));
                cache_script_if_known(funded_tx.vout[index].scriptPubKey);
            };

            if (!principal_asset_inputs.empty()) {
                for (const auto& contrib : principal_asset_inputs) {
                    funded_tx.vin.emplace_back(contrib.outpoint);
                    funded_tx.vin.back().nSequence = MAX_BIP125_RBF_SEQUENCE;
                }

                if (principal_asset_change_units > 0) {
                    Assert(principal_change_dest.has_value());
                    CTxOut asset_change(DEFAULT_REPO_ASSET_OUTPUT_VALUE, GetScriptForDestination(*principal_change_dest));
                    asset_change.vExt = BuildAssetTagTlv(record.terms.principal_leg.asset_id, principal_asset_change_units);
                    asset_change_output_index = funded_tx.vout.size();
                    funded_tx.vout.push_back(std::move(asset_change));
                    register_change_output_if_needed(asset_change_output_index);
                }
            } else if (auto_fund_principal && !record.terms.principal_leg.is_native) {
                for (size_t idx = 0; idx < funded_tx.vout.size(); ++idx) {
                    const CTxOut& out = funded_tx.vout[idx];
                    if (auto tag = assets::ParseAssetTag(out.vExt)) {
                        if (tag->id == record.terms.principal_leg.asset_id && tag->amount != record.terms.principal_leg.units) {
                            asset_change_output_index = static_cast<int>(idx);
                            register_change_output_if_needed(asset_change_output_index);
                            break;
                        }
                    }
                }
            }

            const size_t principal_index = 0;
            const size_t covenant_index = 1;

            PartiallySignedTransaction psbt(funded_tx);
            // Use fee strategy from options (or stored policy), converting to FeePolicySnapshot
            {
                const std::string effective_strategy = !fee_strategy_override.empty() ? fee_strategy_override : record.fee_policy_strategy;
                FeePolicySnapshot fee_snapshot = FeeStrategyToPolicy(effective_strategy);
                LogPrintf("repo.build_open: Lender path - Annotating PSBT with strategy='%s', target_satvb=%u, min_satvb=%u\n",
                         effective_strategy, fee_snapshot.target_satvb, fee_snapshot.min_satvb);
                // Override RBF with wallet preference if explicitly set
                if (pwallet->m_signal_rbf) {
                    fee_snapshot.rbf = true;
                }
                AnnotateRepoGlobalMetadata(psbt, record, repay_dest, fee_snapshot);
            }
            if (final_change_pos) {
                change_indices.push_back(*final_change_pos);
            }
            std::sort(change_indices.begin(), change_indices.end());
            change_indices.erase(std::unique(change_indices.begin(), change_indices.end()), change_indices.end());
            AnnotateRepoOutputs(psbt, change_indices);
            NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);
            NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);
            bool complete = false;
            const auto fill_err = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);

            DataStream ssTx{};
            ssTx << psbt;

            AnnotateTaprootInputsWithInternalKeys(*pwallet, psbt);

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", EncodeBase64(ssTx.str()));

            auto& psbt_out = psbt.outputs[covenant_index];
            const TaprootLeafTuples taproot_leaves = builder.GetTreeTuples();
            psbt_out.m_tap_internal_key = borrower_key;
            psbt_out.m_tap_tree = taproot_leaves;

            UniValue taproot(UniValue::VOBJ);
            taproot.pushKV("output_key", HexStr(std::vector<unsigned char>(covenant_output.begin(), covenant_output.end())));
            taproot.pushKV("internal_key", HexStr(std::vector<unsigned char>(borrower_key.begin(), borrower_key.end())));
            taproot.pushKV("script_pubkey", HexStr(covenant_spk));

            UniValue leaves(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : taproot_leaves) {
                UniValue leaf(UniValue::VOBJ);
                leaf.pushKV("depth", depth);
                leaf.pushKV("leaf_version", leaf_ver);
                leaf.pushKV("script", HexStr(script));
                leaves.push_back(leaf);
            }
            taproot.pushKV("tree", leaves);

            result.pushKV("fee", ValueFromAmount(tx_result.fee));
            result.pushKV("changepos", final_change_pos ? int(*final_change_pos) : -1);
            result.pushKV("principal_output_index", static_cast<int>(principal_index));
            result.pushKV("covenant_output_index", static_cast<int>(covenant_index));
            result.pushKV("asset_change_output_index", asset_change_output_index);
            result.pushKV("taproot", std::move(taproot));
            result.pushKV("complete", complete);
            return result;
        }
    );
}

RPCHelpMan repo_build_repay_release()
{
    return RPCHelpMan(
        "repo.build_repay_release",
        "Construct the repayment PSBT for an accepted repo contract. The PSBT spends the vault via the repay leaf, pays the lender the fixed repay amount, and releases collateral back to the borrower.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    RPCArg{"vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override vault outpoint txid (used if wallet registry is unaware)"},
                    RPCArg{"vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override vault outpoint index"},
                    RPCArg{"vault_amount", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Vault amount (BTC) when tx not yet known to wallet"},
                    RPCArg{"collateral_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination for released collateral (defaults to fresh wallet address)"},
                    RPCArg{"manual_inputs", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Disable automatic asset input selection and use options.inputs"},
                    RPCArg{
                        "inputs",
                        RPCArg::Type::ARR,
                        RPCArg::Optional::OMITTED,
                        "Manual additional inputs (requires manual_inputs=true)",
                        std::vector<RPCArg>{
                            RPCArg{
                                "",
                                RPCArg::Type::OBJ,
                                RPCArg::Optional::NO,
                                "",
                                std::vector<RPCArg>{
                                    RPCArg{"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Input txid"},
                                    RPCArg{"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input vout"},
                                }
                            }
                        }
                    },
                    RPCArg{"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                    RPCArg{"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override fee rate in sat/vB (wallet estimate if omitted)"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::NUM, "fee", "Wallet-computed fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet change output or -1 if none"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the covenant input within the PSBT"},
                {RPCResult::Type::NUM, "principal_output_index", "Index of the principal payment output to lender"},
                {RPCResult::Type::NUM, "interest_output_index", "Index of the interest payment output to lender"},
                {RPCResult::Type::NUM, "repay_output_index", "Index of the repay output (legacy, points to principal)"},
                {RPCResult::Type::NUM, "collateral_output_index", "Index of the collateral release output"},
                {RPCResult::Type::NUM, "asset_change_output_index", "Index of the asset change output or -1 if none"},
                {RPCResult::Type::OBJ, "taproot", "Taproot spend data", RepoTaprootResultDescription()},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT already contains all signatures"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Signed transaction hex (present when complete=true)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction identifier (present when complete=true)"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.build_repay_release", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            RepoOfferRecord record = *record_opt;

            if (!record.acceptance) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer must be accepted before building repayment transaction");
            }

            const CTxDestination repay_dest = record.lender_dest_override ? *record.lender_dest_override : record.lender_dest;

            const CScript borrower_spk = GetScriptForDestination(record.borrower_dest);
            {
                LOCK(pwallet->cs_wallet);
                if (!(pwallet->IsMine(borrower_spk) & ISMINE_SPENDABLE)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Borrower address is not spendable by this wallet");
                }
            }

            // Use the borrower's internal key stored during acceptance (same key used in build_open)
            if (!record.borrower_internal_key.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Borrower internal key not available. Offer must be accepted first.");
            }
            const XOnlyPubKey borrower_key = *record.borrower_internal_key;

            // Use lender's internal (untweaked) key if available, otherwise fall back to extracting from address
            XOnlyPubKey lender_key;
            if (record.lender_internal_key.has_value()) {
                lender_key = *record.lender_internal_key;
                pwallet->WalletLogPrintf("Using stored lender internal key for vault construction: %s\n", HexStr(lender_key));
            } else {
                // Fallback for legacy offers without lender_internal_key
                const auto lender_key_opt = ExtractTaprootKey(repay_dest);
                if (!lender_key_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Lender address must be Taproot bech32m address");
                }
                lender_key = *lender_key_opt;
                pwallet->WalletLogPrintf("WARNING: Using tweaked key from lender address (legacy offer): %s\n", HexStr(lender_key));
            }

            // Build repay covenant: merged OUTPUTMATCH when same asset, dual when different
            CScript repay_script = BuildRepoRepayCovenantScript(record.terms, repay_dest, borrower_key);

            CScript default_script;
            default_script << CScriptNum(record.terms.maturity_height)
                           << OP_CHECKLOCKTIMEVERIFY
                           << OP_DROP
                           << std::vector<unsigned char>(lender_key.begin(), lender_key.end())
                           << OP_CHECKSIG;

            TaprootBuilder builder;
            const std::vector<unsigned char> repay_script_bytes(repay_script.begin(), repay_script.end());
            builder.Add(/*depth=*/1, repay_script_bytes, TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add repay leaf to Taproot tree");
            }
            builder.Add(/*depth=*/1, std::vector<unsigned char>(default_script.begin(), default_script.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add default leaf to Taproot tree");
            }
            if (!builder.IsComplete()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Taproot covenant tree is incomplete");
            }
            // Disable unilateral key-path on REPO vault
            builder.Finalize(DeriveScriptOnlyInternalKey("repo-vault", record.offer_id));
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize Taproot covenant tree");
            }
            WitnessV1Taproot covenant_output{builder.GetOutput()};
            const CScript covenant_spk = GetScriptForDestination(covenant_output);
            const TaprootLeafTuples taproot_leaves = builder.GetTreeTuples();
            const size_t repay_leaf_depth = FindTaprootLeafDepth(taproot_leaves, repay_script_bytes);
            const size_t repay_control_block_size = 33 + 32 * repay_leaf_depth;
            const int64_t vault_input_weight = EstimateTaprootScriptPathInputWeight(
                repay_script_bytes.size(),
                repay_control_block_size,
                /*signature_elements=*/1);

            // Ensure borrower wallet has registered the covenant vault
            // (should have been done in repo_build_open, but register again in case wallet was restarted)
            {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(borrower_spk);
                if (!managers.empty()) {
                    // Build vault metadata with leaf descriptors
                    std::vector<VaultLeafDescriptor> leaves;
                    leaves.push_back(VaultBuilder::CreateLeaf(
                        repay_script,
                        borrower_key,
                        "repay",
                        std::nullopt
                    ));
                    leaves.push_back(VaultBuilder::CreateLeaf(
                        default_script,
                        lender_key,
                        "default",
                        record.terms.maturity_height
                    ));

                    auto vault_metadata_opt = VaultBuilder::Build(
                        builder,
                        record.offer_id,
                        VaultRole::REPO_BORROWER,
                        leaves
                    );

                    if (vault_metadata_opt) {
                        std::set<CScript> scripts{covenant_spk};
                        for (ScriptPubKeyMan* manager : managers) {
                            if (manager == nullptr) continue;

                            auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                            if (!desc_spkm) continue;

                            // Use borrower_spk (descriptor base script) to map vault to descriptor index
                            desc_spkm->RegisterCovenantVault(borrower_spk, *vault_metadata_opt);
                            pwallet->CacheNewScriptPubKeys(scripts, manager);
                        }
                    }
                }
            }

            UniValue opts = request.params.size() > 1 && request.params[1].isObject() ? request.params[1].get_obj() : UniValue::VNULL;
            std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

            CTxDestination collateral_dest;
            bool collateral_specified = false;
            if (!opts.isNull()) {
                const UniValue& addr_val = opts.find_value("collateral_address");
                if (!addr_val.isNull()) {
                    collateral_dest = DecodeDestination(addr_val.get_str());
                    if (!IsValidDestination(collateral_dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid collateral_address");
                    }
                    collateral_specified = true;
                }
            }
            if (!collateral_specified) {
                // Default to returning collateral to the borrower's original address
                collateral_dest = record.borrower_dest;
            }

            std::optional<COutPoint> vault_op_override;
            if (!opts.isNull()) {
                const UniValue& vault_txid_val = opts.find_value("vault_txid");
                const UniValue& vault_vout_val = opts.find_value("vault_vout");
                if (!vault_txid_val.isNull() || !vault_vout_val.isNull()) {
                    if (vault_txid_val.isNull() || vault_vout_val.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.vault_txid and options.vault_vout must be provided together");
                    }
                    const std::string vault_txid_hex = vault_txid_val.get_str();
                    if (!IsHex(vault_txid_hex) || vault_txid_hex.size() != 64) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.vault_txid must be 32-byte hex");
                    }
                    const auto txhash = Txid::FromHex(vault_txid_hex);
                    if (!txhash) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.vault_txid invalid");
                    }
                    uint32_t vout = vault_vout_val.getInt<uint32_t>();
                    vault_op_override = COutPoint(*txhash, vout);
                }
            }

            const COutPoint vault_outpoint = record.vault_outpoint ? *record.vault_outpoint : (vault_op_override ? *vault_op_override : COutPoint());
            if (vault_outpoint.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint unknown; provide options.vault_txid and options.vault_vout");
            }

            // Obtain the vault prevout for amount/script validation.
            Coin vault_coin;
            bool have_coin = false;
            {
                LOCK(pwallet->cs_wallet);
                if (const CWalletTx* wtx = pwallet->GetWalletTx(vault_outpoint.hash)) {
                    if (vault_outpoint.n < wtx->tx->vout.size()) {
                        vault_coin.out = wtx->tx->vout[vault_outpoint.n];
                        have_coin = true;
                    }
                }
            }
            if (!have_coin) {
                std::map<COutPoint, Coin> coins;
                coins.emplace(vault_outpoint, Coin());
                pwallet->chain().findCoins(coins);
                auto it_coin = coins.find(vault_outpoint);
                if (it_coin != coins.end() && !it_coin->second.out.IsNull()) {
                    vault_coin = it_coin->second;
                    have_coin = true;
                }
            }

            if (!have_coin) {
                if (record.vault_amount == 0) {
                    const UniValue& amount_override = !opts.isNull() ? opts.find_value("vault_amount") : NullUniValue;
                    if (amount_override.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to locate vault output; specify options.vault_amount");
                    }
                    vault_coin.out.nValue = AmountFromValue(amount_override);
                } else {
                    vault_coin.out.nValue = record.vault_amount;
                }
                vault_coin.out.scriptPubKey = covenant_spk;
            }

            if (vault_coin.out.scriptPubKey != covenant_spk) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Provided vault outpoint does not match expected covenant script");
            }

            if (!record.vault_outpoint) {
                pwallet->SetRepoVaultOutpoint(*offer_id, vault_outpoint, vault_coin.out.nValue, covenant_spk);
                record.vault_outpoint = vault_outpoint;
                record.vault_amount = vault_coin.out.nValue;
                record.vault_covenant_script = covenant_spk;
            }

            int asset_change_output_index = -1;

            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            coin_control.m_avoid_asset_utxos = true;
            if (fee_rate_override.has_value()) {
                const CAmount sat_per_kvb = static_cast<CAmount>(std::llround(*fee_rate_override * 1000.0));
                coin_control.m_feerate = CFeeRate(sat_per_kvb);
                coin_control.fOverrideFeeRate = true;
            }
            coin_control.SetInputWeight(vault_outpoint, vault_input_weight);

            bool manual_inputs = false;
            if (!opts.isNull()) {
                const UniValue& manual_val = opts.find_value("manual_inputs");
                if (!manual_val.isNull()) manual_inputs = manual_val.get_bool();
            }
            if (manual_inputs) {
                coin_control.m_allow_other_inputs = false;
            }

            std::set<COutPoint, std::less<>> skeleton_prevouts;
            std::vector<CTxOut> skeleton_change_outputs;
            ScopedCoinLocker asset_reserver(*pwallet);
            std::optional<CTxOut> principal_delivery_txo;
            std::optional<CTxOut> interest_delivery_txo;

            auto integrate_skeleton = [&](const AssetLeg& leg,
                                          const char* context_tag,
                                          std::optional<CTxOut>& deliver_slot,
                                          CMutableTransaction& tx_template) {
                    RepoAssetSkeletonResult skeleton = BuildRepoAssetSkeleton(*pwallet, request, leg, repay_dest, context_tag, fee_rate_override);

                asset_reserver.LockMany(skeleton.inputs_to_lock);

                for (const CTxIn& vin : skeleton.tx.vin) {
                    CTxIn vin_copy = vin;
                    vin_copy.nSequence = MAX_BIP125_RBF_SEQUENCE;
                    if (skeleton_prevouts.insert(vin_copy.prevout).second) {
                        tx_template.vin.push_back(vin_copy);
                    }
                    coin_control.Select(vin_copy.prevout);
                }

                for (size_t change_idx : skeleton.change_indices) {
                    if (change_idx < skeleton.tx.vout.size()) {
                        skeleton_change_outputs.push_back(skeleton.tx.vout[change_idx]);
                    }
                }

                deliver_slot = skeleton.tx.vout[*skeleton.deliver_output_index];
            };

            CMutableTransaction tx_template;
            tx_template.version = 2;
            if (!opts.isNull()) {
                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    int64_t locktime = ParseSignedInt64(locktime_val, "options.locktime");
                    if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.locktime out of range");
                    }
                    tx_template.nLockTime = static_cast<uint32_t>(locktime);
                }
            }

            coin_control.m_locktime = tx_template.nLockTime;
            coin_control.m_version = tx_template.version;

            tx_template.vin.emplace_back(vault_outpoint);
            tx_template.vin.back().nSequence = MAX_BIP125_RBF_SEQUENCE;
            coin_control.Select(vault_outpoint).SetTxOut(vault_coin.out);

            // OPTIMIZATION: When principal and interest share the same asset, call sendasset ONCE with merged amount
            if (!manual_inputs) {
                const bool should_merge = ShouldMergeRepoRepayLegs(record.terms);
                const bool principal_is_asset = !record.terms.principal_leg.is_native;
                const bool interest_is_asset = !record.terms.interest_leg.is_native;

                if (should_merge && principal_is_asset) {
                    // MERGED PATH: Single sendasset call for principal + interest
                    AssetLeg merged_leg;
                    merged_leg.asset_id = record.terms.principal_leg.asset_id;
                    merged_leg.is_native = false;
                    merged_leg.units = record.terms.principal_leg.units + record.terms.interest_leg.units;

                    integrate_skeleton(merged_leg, "repo.build_repay_release.merged", principal_delivery_txo, tx_template);
                    // Mark interest_delivery_txo as unused (will use principal_delivery_txo for the merged output)
                } else {
                    // DUAL PATH: Separate sendasset calls for different assets
                    if (principal_is_asset) {
                        integrate_skeleton(record.terms.principal_leg, "repo.build_repay_release.principal", principal_delivery_txo, tx_template);
                    }
                    if (interest_is_asset) {
                        integrate_skeleton(record.terms.interest_leg, "repo.build_repay_release.interest", interest_delivery_txo, tx_template);
                    }
                }
            }

            if (manual_inputs) {
                const UniValue& manual_arr = opts.find_value("inputs");
                if (!manual_arr.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options.inputs must be provided when manual_inputs=true");
                }
                for (const UniValue& entry : manual_arr.getValues()) {
                    if (!entry.isObject()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "inputs array must contain objects");
                    }
                    const UniValue& txid_val = entry.find_value("txid");
                    const UniValue& vout_val = entry.find_value("vout");
                    if (txid_val.isNull() || vout_val.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Each manual input requires txid and vout");
                    }
                    const std::string txhex = txid_val.get_str();
                    if (!IsHex(txhex) || txhex.size() != 64) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Manual input txid must be 32-byte hex");
                    }
                    const auto tx_hash = Txid::FromHex(txhex);
                    if (!tx_hash) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Manual input txid invalid");
                    }
                    uint32_t vout = vout_val.getInt<uint32_t>();
                    COutPoint prev(*tx_hash, vout);
                    if (skeleton_prevouts.insert(prev).second) {
                        tx_template.vin.emplace_back(prev);
                        tx_template.vin.back().nSequence = MAX_BIP125_RBF_SEQUENCE;
                        coin_control.Select(prev);
                    }
                }
            }

            // Only restrict to preselected inputs if user explicitly requested manual_inputs
            // Otherwise, allow FundTransaction to add more BTC inputs for fee payment
            if (manual_inputs && !skeleton_prevouts.empty()) {
                coin_control.m_allow_other_inputs = false;
            }

            std::vector<CRecipient> recipients;

            RepoAcceptanceRecord& acceptance = *record.acceptance;
            bool acceptance_mutated = false;

            // OPTIMIZATION: When merged, create single repay output instead of separate principal+interest
            const bool should_merge = ShouldMergeRepoRepayLegs(record.terms);

            const auto ensure_template = [&](std::optional<AssetDeliveryTemplate>& slot,
                                             const AssetLeg& leg,
                                             const char* context_tag) -> const AssetDeliveryTemplate* {
                if (slot || leg.units == 0) {
                    return slot ? &*slot : nullptr;
                }
                slot = BuildRepoDeliveryTemplate(
                    *pwallet,
                    request,
                    leg,
                    repay_dest,
                    context_tag);
                acceptance_mutated = true;
                return &*slot;
            };

            if (should_merge) {
                if (!acceptance.repay_principal_template) {
                    AssetLeg combined = record.terms.principal_leg;
                    combined.units += record.terms.interest_leg.units;
                    ensure_template(acceptance.repay_principal_template, combined, "repo.build_repay_release.merged");
                    acceptance.repay_interest_template.reset();
                }
            } else {
                if (record.terms.principal_leg.units > 0 && !acceptance.repay_principal_template) {
                    ensure_template(acceptance.repay_principal_template, record.terms.principal_leg, "repo.build_repay_release.principal");
                }
                if (record.terms.interest_leg.units > 0 && !acceptance.repay_interest_template) {
                    ensure_template(acceptance.repay_interest_template, record.terms.interest_leg, "repo.build_repay_release.interest");
                }
            }

            if (acceptance_mutated) {
                record = pwallet->RegisterRepoOffer(std::move(record));
                acceptance = *record.acceptance;
            }

            const AssetDeliveryTemplate* repay_principal_tmpl = acceptance.repay_principal_template ? &*acceptance.repay_principal_template : nullptr;
            const AssetDeliveryTemplate* repay_interest_tmpl = acceptance.repay_interest_template ? &*acceptance.repay_interest_template : nullptr;

            std::optional<CAmount> merged_placeholder;

            if (should_merge) {
                // Single merged repay output
                const uint64_t total_repay_units = record.terms.principal_leg.units + record.terms.interest_leg.units;
                merged_placeholder = record.terms.principal_leg.is_native ?
                    static_cast<CAmount>(total_repay_units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                recipients.push_back({repay_dest, *merged_placeholder, /*subtract fee*/ false});
            } else {
                // Separate principal and interest outputs
                const CAmount principal_placeholder = record.terms.principal_leg.is_native ?
                    static_cast<CAmount>(record.terms.principal_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                recipients.push_back({repay_dest, principal_placeholder, /*subtract fee*/ false});

                const CAmount interest_placeholder = record.terms.interest_leg.is_native ?
                    static_cast<CAmount>(record.terms.interest_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                recipients.push_back({repay_dest, interest_placeholder, /*subtract fee*/ false});
            }

            const CAmount collateral_placeholder = record.terms.collateral_leg.is_native ?
                static_cast<CAmount>(record.terms.collateral_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
            recipients.push_back({collateral_dest, collateral_placeholder, /*subtract fee*/ false});

            for (const CTxOut& change_out : skeleton_change_outputs) {
                CTxDestination change_dest;
                if (!ExtractDestination(change_out.scriptPubKey, change_dest)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to decode change destination from sendasset skeleton");
                }
                recipients.push_back({change_dest, change_out.nValue, /*subtract fee*/ false});
            }

            auto fund_res = FundTransaction(*pwallet, tx_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
            if (!fund_res) {
                bilingual_str err = util::ErrorString(fund_res);
                throw JSONRPCError(RPC_WALLET_ERROR, err.original);
            }

            const CreatedTransactionResult& tx_result = fund_res.value();
            CMutableTransaction funded_tx(*tx_result.tx);

            const CScript repay_spk = GetScriptForDestination(repay_dest);
            const CScript collateral_spk = GetScriptForDestination(collateral_dest);

            std::optional<size_t> principal_original_index;
            std::optional<size_t> interest_original_index;
            std::optional<size_t> collateral_original_index;

            if (should_merge) {
                // MERGED PATH: Find single merged repay output
                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    const CTxOut& out = funded_tx.vout[i];
                    if (!principal_original_index && out.scriptPubKey == repay_spk && out.nValue == *merged_placeholder) {
                        principal_original_index = i;
                        // No interest_original_index in merged mode
                        continue;
                    }
                    if (!collateral_original_index && out.scriptPubKey == collateral_spk && out.nValue == collateral_placeholder) {
                        collateral_original_index = i;
                    }
                }

                if (!principal_original_index) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify merged repay output in funded transaction");
                }
            } else {
                // DUAL PATH: Find separate principal and interest outputs
                const CAmount principal_placeholder = record.terms.principal_leg.is_native ?
                    static_cast<CAmount>(record.terms.principal_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                const CAmount interest_placeholder = record.terms.interest_leg.is_native ?
                    static_cast<CAmount>(record.terms.interest_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    const CTxOut& out = funded_tx.vout[i];
                    if (!principal_original_index && out.scriptPubKey == repay_spk && out.nValue == principal_placeholder) {
                        principal_original_index = i;
                        continue;
                    }
                    if (!interest_original_index && out.scriptPubKey == repay_spk && out.nValue == interest_placeholder) {
                        interest_original_index = i;
                        continue;
                    }
                    if (!collateral_original_index && out.scriptPubKey == collateral_spk && out.nValue == collateral_placeholder) {
                        collateral_original_index = i;
                    }
                }

                if (!principal_original_index) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify principal output in funded transaction");
                }
                if (!interest_original_index) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify interest output in funded transaction");
                }
            }

            if (!collateral_original_index) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify collateral output in funded transaction");
            }

            if (should_merge) {
                if (!repay_principal_tmpl) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Acceptance record missing merged repayment template");
                }
                if (!repay_principal_tmpl->is_native && repay_principal_tmpl->asset_id != record.terms.principal_leg.asset_id) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Repayment template asset mismatch");
                }
                const uint64_t expected_units = record.terms.principal_leg.units + record.terms.interest_leg.units;
                if (repay_principal_tmpl->units != expected_units && !repay_principal_tmpl->is_native) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Repayment template units mismatch for merged path");
                }
                CTxOut& repay_out = funded_tx.vout[*principal_original_index];
                repay_out.scriptPubKey = repay_principal_tmpl->script_pubkey;
                if (repay_principal_tmpl->is_native) {
                    repay_out.nValue = static_cast<CAmount>(repay_principal_tmpl->units);
                    repay_out.vExt.clear();
                } else {
                    repay_out.nValue = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                    repay_out.vExt = repay_principal_tmpl->vext;
                }
            } else {
                if (repay_principal_tmpl) {
                    if (!repay_principal_tmpl->is_native && repay_principal_tmpl->asset_id != record.terms.principal_leg.asset_id) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Principal repayment template asset mismatch");
                    }
                    CTxOut& principal_out = funded_tx.vout[*principal_original_index];
                    principal_out.scriptPubKey = repay_principal_tmpl->script_pubkey;
                    if (repay_principal_tmpl->is_native) {
                        principal_out.nValue = static_cast<CAmount>(repay_principal_tmpl->units);
                        principal_out.vExt.clear();
                    } else {
                        principal_out.nValue = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                        principal_out.vExt = repay_principal_tmpl->vext;
                    }
                } else {
                    if (!record.terms.principal_leg.is_native) {
                        if (principal_delivery_txo) {
                            funded_tx.vout[*principal_original_index] = *principal_delivery_txo;
                        } else if (funded_tx.vout[*principal_original_index].vExt.empty()) {
                            // Only set vExt if sendasset didn't already populate it (with ICU_KEYWRAP if needed)
                            funded_tx.vout[*principal_original_index].vExt = BuildAssetTagTlv(
                                record.terms.principal_leg.asset_id,
                                record.terms.principal_leg.units
                            );
                        }
                    }
                }

                if (repay_interest_tmpl) {
                    if (!repay_interest_tmpl->is_native && repay_interest_tmpl->asset_id != record.terms.interest_leg.asset_id) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Interest repayment template asset mismatch");
                    }
                    CTxOut& interest_out = funded_tx.vout[*interest_original_index];
                    interest_out.scriptPubKey = repay_interest_tmpl->script_pubkey;
                    if (repay_interest_tmpl->is_native) {
                        interest_out.nValue = static_cast<CAmount>(repay_interest_tmpl->units);
                        interest_out.vExt.clear();
                    } else {
                        interest_out.nValue = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                        interest_out.vExt = repay_interest_tmpl->vext;
                    }
                } else {
                    if (!record.terms.interest_leg.is_native) {
                        if (interest_delivery_txo) {
                            funded_tx.vout[*interest_original_index] = *interest_delivery_txo;
                        } else if (funded_tx.vout[*interest_original_index].vExt.empty()) {
                            // Only set vExt if sendasset didn't already populate it (with ICU_KEYWRAP if needed)
                            funded_tx.vout[*interest_original_index].vExt = BuildAssetTagTlv(
                                record.terms.interest_leg.asset_id,
                                record.terms.interest_leg.units
                            );
                        }
                    }
                }
            }
            if (!record.terms.collateral_leg.is_native) {
                // Only set vExt if sendasset didn't already populate it (with ICU_KEYWRAP if needed)
                if (funded_tx.vout[*collateral_original_index].vExt.empty()) {
                    funded_tx.vout[*collateral_original_index].vExt = BuildAssetTagTlv(
                        record.terms.collateral_leg.asset_id,
                        record.terms.collateral_leg.units
                    );
                }
            }

            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                CTxOut& out = funded_tx.vout[i];
                for (const CTxOut& change_out : skeleton_change_outputs) {
                    if (out.scriptPubKey == change_out.scriptPubKey && out.nValue == change_out.nValue) {
                        out.vExt = change_out.vExt;
                        if (asset_change_output_index == -1) {
                            if (auto tag = assets::ParseAssetTag(change_out.vExt)) {
                                asset_change_output_index = static_cast<int>(i);
                            }
                        }
                        break;
                    }
                }
            }

            std::optional<unsigned int> final_change_pos;
            const auto track_change = [&](size_t original_index, size_t new_index) {
                if (tx_result.change_pos && original_index == *tx_result.change_pos) {
                    final_change_pos = static_cast<unsigned int>(new_index);
                }
            };

            std::vector<CTxOut> reordered;
            reordered.reserve(funded_tx.vout.size());

            if (should_merge) {
                // MERGED PATH: principal output (merged repay), then collateral, then rest
                reordered.push_back(funded_tx.vout[*principal_original_index]);
                track_change(*principal_original_index, 0);

                reordered.push_back(funded_tx.vout[*collateral_original_index]);
                track_change(*collateral_original_index, 1);

                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    if (i == *principal_original_index || i == *collateral_original_index) continue;
                    track_change(i, reordered.size());
                    reordered.push_back(funded_tx.vout[i]);
                }
            } else {
                // DUAL PATH: principal, interest, collateral, then rest
                reordered.push_back(funded_tx.vout[*principal_original_index]);
                track_change(*principal_original_index, 0);

                reordered.push_back(funded_tx.vout[*interest_original_index]);
                track_change(*interest_original_index, 1);

                reordered.push_back(funded_tx.vout[*collateral_original_index]);
                track_change(*collateral_original_index, 2);

                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    if (i == *principal_original_index || i == *interest_original_index || i == *collateral_original_index) continue;
                    track_change(i, reordered.size());
                    reordered.push_back(funded_tx.vout[i]);
                }
            }

            funded_tx.vout = std::move(reordered);

            if (!skeleton_change_outputs.empty()) {
                int new_asset_index = -1;
                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    const CTxOut& out = funded_tx.vout[i];
                    for (const CTxOut& change_out : skeleton_change_outputs) {
                        if (out.scriptPubKey == change_out.scriptPubKey && out.nValue == change_out.nValue && out.vExt == change_out.vExt) {
                            if (auto tag = assets::ParseAssetTag(out.vExt)) {
                                new_asset_index = static_cast<int>(i);
                                break;
                            }
                        }
                    }
                    if (new_asset_index != -1) break;
                }
                asset_change_output_index = new_asset_index;
            }

            // Output indices after reordering
            size_t principal_output_index = 0;
            size_t interest_output_index;
            size_t collateral_output_index;

            if (should_merge) {
                // MERGED PATH: [0] = merged repay, [1] = collateral, no separate interest
                interest_output_index = 0; // Same as principal in merged mode (for legacy compat)
                collateral_output_index = 1;
            } else {
                // DUAL PATH: [0] = principal, [1] = interest, [2] = collateral
                interest_output_index = 1;
                collateral_output_index = 2;
            }

            PartiallySignedTransaction psbt(funded_tx);
            bool complete = false;

            // Populate Taproot spend data for the vault input.
            size_t vault_input_index = std::numeric_limits<size_t>::max();
            for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
                if (funded_tx.vin[i].prevout == vault_outpoint) {
                    vault_input_index = i;
                    break;
                }
            }
            if (vault_input_index == std::numeric_limits<size_t>::max()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Vault input missing from funded transaction");
            }

            // CRITICAL: Retrieve vault metadata from registry (not rebuild from builder)
            // Vaults are registered under the borrower destination script, not the vault covenant script
            std::optional<VaultMetadata> vault_meta;
            {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(borrower_spk);
                if (managers.empty()) {
                    for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                        if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                            managers.insert(manager);
                        }
                    }
                }
                for (ScriptPubKeyMan* manager : managers) {
                    if (auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                        // GetVaultMetadata uses the vault covenant script as the lookup key
                        vault_meta = desc_spkm->GetVaultMetadata(covenant_spk);
                        if (vault_meta) break;
                    }
                }
            }

            if (!vault_meta) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry");
            }

            // Use spenddata from registered vault (not freshly built)
            const TaprootSpendData& spenddata = vault_meta->spenddata;
            auto& psbt_in = psbt.inputs[vault_input_index];
            psbt_in.m_tap_internal_key = spenddata.internal_key;
            psbt_in.m_tap_merkle_root = spenddata.merkle_root;
            for (const auto& [script_key, control_blocks] : spenddata.scripts) {
                auto& entry = psbt_in.m_tap_scripts[script_key];
                entry.insert(control_blocks.begin(), control_blocks.end());
            }
            psbt_in.witness_utxo = vault_coin.out;
            // Use binding sighash for the vault input
            psbt_in.sighash_type = SIGHASH_DEFAULT;

            // Explicitly set binding sighash for non-vault inputs to SIGHASH_ALL to
            // satisfy asset policy checks that reject ANYONECANPAY and avoid
            // ambiguity for key-path inputs.
            for (size_t i = 0; i < psbt.inputs.size(); ++i) {
                if (i == vault_input_index) continue;
                psbt.inputs[i].sighash_type = SIGHASH_ALL;
            }

            const auto fill_err = pwallet->FillPSBT(psbt, complete, /*sighash_type=*/SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            // Reinforce per-input policy: keep DEFAULT for vault and ALL for others
            for (size_t i = 0; i < psbt.inputs.size(); ++i) {
                if (i == vault_input_index) {
                    psbt.inputs[i].sighash_type = SIGHASH_DEFAULT;
                } else {
                    psbt.inputs[i].sighash_type = SIGHASH_ALL;
                }
            }

            auto& psbt_covenant_out = psbt.outputs[collateral_output_index];
            psbt_covenant_out.m_tap_internal_key = borrower_key;
            psbt_covenant_out.m_tap_tree = taproot_leaves;

            AnnotateTaprootInputsWithInternalKeys(*pwallet, psbt);

            const VaultLeafDescriptor* repay_leaf = FindForwardLeafByPurpose(*vault_meta, "repay");
            if (!repay_leaf) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Repay leaf not found in vault metadata");
            }

            CKey borrower_privkey;
            bool have_privkey = false;
            {
                LOCK(pwallet->cs_wallet);
                for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    if (desc_spkm->GetKeyByXOnly(repay_leaf->signing_key, borrower_privkey)) {
                        have_privkey = true;
                        pwallet->WalletLogPrintf("repo.build_repay_release: Found borrower private key in descriptor %s\n",
                                                 desc_spkm->GetID().ToString());
                        break;
                    }
                }
            }

            UniValue taproot(UniValue::VOBJ);
            taproot.pushKV("output_key", HexStr(std::vector<unsigned char>(covenant_output.begin(), covenant_output.end())));
            taproot.pushKV("internal_key", HexStr(std::vector<unsigned char>(borrower_key.begin(), borrower_key.end())));
            taproot.pushKV("script_pubkey", HexStr(covenant_spk));

            UniValue leaves(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : taproot_leaves) {
                UniValue leaf(UniValue::VOBJ);
                leaf.pushKV("depth", depth);
                leaf.pushKV("leaf_version", leaf_ver);
                leaf.pushKV("script", HexStr(script));
                leaves.push_back(leaf);
            }
            taproot.pushKV("tree", leaves);

            UniValue result(UniValue::VOBJ);
            if (have_privkey) {
                FinalizeVaultTaprootLeafWitness(*pwallet,
                                                psbt,
                                                vault_input_index,
                                                *vault_meta,
                                                *repay_leaf,
                                                borrower_privkey,
                                                "repo.build_repay_release");

                CMutableTransaction mtx(*psbt.tx);
                for (size_t i = 0; i < psbt.inputs.size(); ++i) {
                    if (!psbt.inputs[i].final_script_witness.IsNull()) {
                        mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
                    }
                }
                CTransaction final_tx(mtx);

                DataStream signed_psbt{};
                signed_psbt << psbt;
                result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
                result.pushKV("hex", EncodeHexTx(final_tx));
                result.pushKV("txid", final_tx.GetHash().ToString());
                complete = true;
            } else {
                DataStream ssTx{};
                ssTx << psbt;
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
            }

            result.pushKV("fee", ValueFromAmount(tx_result.fee));
            result.pushKV("changepos", final_change_pos ? int(*final_change_pos) : -1);
            result.pushKV("vault_input_index", int(vault_input_index));
            result.pushKV("principal_output_index", int(principal_output_index));
            result.pushKV("interest_output_index", int(interest_output_index));
            result.pushKV("repay_output_index", int(principal_output_index)); // Legacy compat: points to principal
            result.pushKV("collateral_output_index", int(collateral_output_index));
            result.pushKV("asset_change_output_index", asset_change_output_index);
            result.pushKV("taproot", std::move(taproot));
            result.pushKV("complete", complete);
            return result;
        }
    );
}

RPCHelpMan repo_build_default_sweep()
{
    return RPCHelpMan(
        "repo.build_default_sweep",
        "Construct the default-path PSBT for an accepted repo contract. The PSBT spends the vault via the default leaf after maturity and delivers the collateral to the lender.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override vault outpoint txid (if registry unaware)"},
                    {"vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override vault outpoint index"},
                    {"vault_amount", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Vault amount (BTC) when tx not yet known to wallet"},
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime (defaults to maturity height)"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override fee rate in sat/vB (wallet estimate if omitted)"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", /*optional=*/true, "Base64-encoded PSBT (watch-only path)"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Complete transaction hex (hot wallet path)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction ID (hot wallet path)"},
                {RPCResult::Type::NUM, "fee", "Wallet-computed fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet change output or -1 if none"},
                {RPCResult::Type::NUM, "asset_change_output_index", "Index of the asset change output or -1 if none"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the covenant input"},
                {RPCResult::Type::NUM, "sweep_output_index", "Index of the lender sweep output"},
                {RPCResult::Type::BOOL, "complete", "Whether the transaction is fully signed"},
                {RPCResult::Type::OBJ, "signing_info", /*optional=*/true, "Signing metadata for external signers (watch-only path)",
                    {
                        {RPCResult::Type::STR_HEX, "leaf_hash", "Default leaf hash"},
                        {RPCResult::Type::STR_HEX, "leaf_script", "Default leaf script"},
                        {RPCResult::Type::STR_HEX, "lender_key", "Lender's x-only pubkey"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.build_default_sweep", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            RepoOfferRecord record = *record_opt;

            if (!record.acceptance) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer must be accepted before building default sweep");
            }

            const CTxDestination repay_dest = record.lender_dest_override ? *record.lender_dest_override : record.lender_dest;

            const CScript lender_spk = GetScriptForDestination(repay_dest);
            {
                LOCK(pwallet->cs_wallet);
                // Allow both ISMINE_SPENDABLE (hot wallet) and ISMINE_WATCH_ONLY (watch-only wallet)
                // Watch-only wallets can still build PSBTs for external signing
                isminetype mine_type = pwallet->IsMine(lender_spk);
                if (!(mine_type & (ISMINE_SPENDABLE | ISMINE_WATCH_ONLY))) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Lender address is not recognized by this wallet");
                }
            }

            // Use the borrower's internal key stored during acceptance (same key used in build_open)
            if (!record.borrower_internal_key.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Borrower internal key not available. Offer must be accepted first.");
            }
            const XOnlyPubKey borrower_key = *record.borrower_internal_key;

            // Use lender's internal (untweaked) key if available, otherwise fall back to extracting from address
            XOnlyPubKey lender_key;
            if (record.lender_internal_key.has_value()) {
                lender_key = *record.lender_internal_key;
                pwallet->WalletLogPrintf("Using stored lender internal key for vault construction: %s\n", HexStr(lender_key));
            } else {
                // Fallback for legacy offers without lender_internal_key
                const auto lender_key_opt = ExtractTaprootKey(repay_dest);
                if (!lender_key_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Lender address must be Taproot bech32m address");
                }
                lender_key = *lender_key_opt;
                pwallet->WalletLogPrintf("WARNING: Using tweaked key from lender address (legacy offer): %s\n", HexStr(lender_key));
            }

            // Build repay covenant: merged OUTPUTMATCH when same asset, dual when different
            CScript repay_script = BuildRepoRepayCovenantScript(record.terms, repay_dest, borrower_key);

            CScript default_script;
            default_script << CScriptNum(record.terms.maturity_height)
                           << OP_CHECKLOCKTIMEVERIFY
                           << OP_DROP
                           << std::vector<unsigned char>(lender_key.begin(), lender_key.end())
                           << OP_CHECKSIG;

            TaprootBuilder builder;
            const std::vector<unsigned char> repay_script_bytes(repay_script.begin(), repay_script.end());
            builder.Add(/*depth=*/1, repay_script_bytes, TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add repay leaf to Taproot tree");
            }
            const std::vector<unsigned char> default_script_bytes(default_script.begin(), default_script.end());
            builder.Add(/*depth=*/1, default_script_bytes, TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add default leaf to Taproot tree");
            }
            if (!builder.IsComplete()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Taproot covenant tree is incomplete");
            }
            // Disable unilateral key-path on REPO vault
            builder.Finalize(DeriveScriptOnlyInternalKey("repo-vault", record.offer_id));
            if (!builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to finalize Taproot covenant tree");
            }
            WitnessV1Taproot covenant_output{builder.GetOutput()};
            const CScript covenant_spk = GetScriptForDestination(covenant_output);
            const TaprootLeafTuples taproot_leaves = builder.GetTreeTuples();
            const size_t default_leaf_depth = FindTaprootLeafDepth(taproot_leaves, default_script_bytes);
            const size_t default_control_block_size = 33 + 32 * default_leaf_depth;
            const int64_t vault_input_weight = EstimateTaprootScriptPathInputWeight(
                default_script_bytes.size(),
                default_control_block_size,
                /*signature_elements=*/1);

            // Fallback registration: ensure lender wallet recognizes covenant vault for default path
            // This registers the full vault metadata with key caching, not just the script
            {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(lender_spk);
                if (!managers.empty()) {
                    // Build vault metadata with both leaves
                    std::vector<VaultLeafDescriptor> leaves;
                    leaves.push_back(VaultBuilder::CreateLeaf(
                        repay_script,
                        borrower_key,
                        "repay",
                        std::nullopt
                    ));
                    leaves.push_back(VaultBuilder::CreateLeaf(
                        default_script,
                        lender_key,
                        "default",
                        record.terms.maturity_height
                    ));

                    auto lender_metadata = VaultBuilder::Build(builder, record.offer_id, VaultRole::REPO_LENDER, leaves);
                    if (lender_metadata) {
                        for (ScriptPubKeyMan* manager : managers) {
                            if (manager == nullptr) continue;
                            auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                            if (!desc_spkm) continue;
                            // Register vault with full metadata (includes key caching)
                            if (desc_spkm->RegisterCovenantVault(lender_spk, *lender_metadata)) {
                                pwallet->WalletLogPrintf("Fallback: Registered repo vault for REPO_LENDER role in build_default_sweep (offer_id=%s)\n", record.offer_id.ToString());
                                // Cache covenant script only for the manager that registered it
                                std::set<CScript> scripts{covenant_spk};
                                pwallet->CacheNewScriptPubKeys(scripts, manager);
                                break;  // Only register once
                            }
                        }
                    }
                }
            }

            int tip_height;
            {
                LOCK(pwallet->cs_wallet);
                tip_height = pwallet->GetLastBlockHeight();
            }
            const int min_height = static_cast<int>(record.terms.maturity_height) + static_cast<int>(record.terms.reorg_conf);
            if (tip_height < min_height) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Maturity not satisfied with required confirmations");
            }

            UniValue opts = request.params.size() > 1 && request.params[1].isObject() ? request.params[1].get_obj() : UniValue::VNULL;
            std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

            std::optional<COutPoint> vault_op_override;
            if (!opts.isNull()) {
                const UniValue& vault_txid_val = opts.find_value("vault_txid");
                const UniValue& vault_vout_val = opts.find_value("vault_vout");
                if (!vault_txid_val.isNull() || !vault_vout_val.isNull()) {
                    if (vault_txid_val.isNull() || vault_vout_val.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.vault_txid and options.vault_vout must be provided together");
                    }
                    const std::string vault_txid_hex = vault_txid_val.get_str();
                    if (!IsHex(vault_txid_hex) || vault_txid_hex.size() != 64) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.vault_txid must be 32-byte hex");
                    }
                    const auto txhash = Txid::FromHex(vault_txid_hex);
                    if (!txhash) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.vault_txid invalid");
                    }
                    uint32_t vout = vault_vout_val.getInt<uint32_t>();
                    vault_op_override = COutPoint(*txhash, vout);
                }
            }

            const COutPoint vault_outpoint = record.vault_outpoint ? *record.vault_outpoint : (vault_op_override ? *vault_op_override : COutPoint());
            if (vault_outpoint.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Vault outpoint unknown; provide options.vault_txid and options.vault_vout");
            }

            Coin vault_coin;
            bool have_coin = false;
            {
                LOCK(pwallet->cs_wallet);
                if (const CWalletTx* wtx = pwallet->GetWalletTx(vault_outpoint.hash)) {
                    if (vault_outpoint.n < wtx->tx->vout.size()) {
                        vault_coin.out = wtx->tx->vout[vault_outpoint.n];
                        have_coin = true;
                    }
                }
            }
            if (!have_coin) {
                std::map<COutPoint, Coin> coins;
                coins.emplace(vault_outpoint, Coin());
                pwallet->chain().findCoins(coins);
                auto it_coin = coins.find(vault_outpoint);
                if (it_coin != coins.end() && !it_coin->second.out.IsNull()) {
                    vault_coin = it_coin->second;
                    have_coin = true;
                }
            }
            if (!have_coin) {
                if (record.vault_amount == 0) {
                    const UniValue& amount_override = !opts.isNull() ? opts.find_value("vault_amount") : NullUniValue;
                    if (amount_override.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to locate vault output; specify options.vault_amount");
                    }
                    vault_coin.out.nValue = AmountFromValue(amount_override);
                } else {
                    vault_coin.out.nValue = record.vault_amount;
                }
                vault_coin.out.scriptPubKey = covenant_spk;
            }
            if (vault_coin.out.scriptPubKey != covenant_spk) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Provided vault outpoint does not match expected covenant script");
            }

            if (!record.vault_outpoint) {
                pwallet->SetRepoVaultOutpoint(*offer_id, vault_outpoint, vault_coin.out.nValue, covenant_spk);
                record.vault_outpoint = vault_outpoint;
                record.vault_amount = vault_coin.out.nValue;
                record.vault_covenant_script = covenant_spk;
            }

            int asset_change_output_index = -1;

            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            if (fee_rate_override.has_value()) {
                coin_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_override * 1000));
                coin_control.fOverrideFeeRate = true;
            }
            coin_control.SetInputWeight(vault_outpoint, vault_input_weight);
            CMutableTransaction tx_template;
            tx_template.version = 2;
            tx_template.nLockTime = record.terms.maturity_height;
            if (!opts.isNull()) {
                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    int64_t locktime = ParseSignedInt64(locktime_val, "options.locktime");
                    if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.locktime out of range");
                    }
                    tx_template.nLockTime = static_cast<uint32_t>(locktime);
                }
            }

            coin_control.m_locktime = tx_template.nLockTime;
            coin_control.m_version = tx_template.version;

            tx_template.vin.emplace_back(vault_outpoint);
            tx_template.vin.back().nSequence = 0; // Enable CLTV
            coin_control.Select(vault_outpoint).SetTxOut(vault_coin.out);

            std::optional<size_t> sweep_original_index;
            CMutableTransaction funded_tx;
            CAmount transaction_fee = 0;
            std::optional<unsigned int> btc_change_pos;

            // ASSET COLLATERAL: prefer acceptance template, fallback to skeleton for legacy offers
            if (!record.terms.collateral_leg.is_native) {
                const AssetDeliveryTemplate* collateral_template = nullptr;
                if (record.acceptance && record.acceptance->default_collateral_template) {
                    collateral_template = &*record.acceptance->default_collateral_template;
                    if (!collateral_template->is_native &&
                        collateral_template->asset_id != record.terms.collateral_leg.asset_id) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Collateral template asset mismatch");
                    }
                }

                if (collateral_template) {
                    coin_control.m_avoid_asset_utxos = true;
                    coin_control.m_allow_other_inputs = true;

                    std::vector<CRecipient> recipients;
                    const CAmount sweep_amount = collateral_template->is_native ? static_cast<CAmount>(collateral_template->units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                    recipients.push_back({repay_dest, sweep_amount, /*subtract fee*/ false});

                    auto fund_res = FundTransaction(*pwallet, tx_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
                    if (!fund_res) {
                        bilingual_str err = util::ErrorString(fund_res);
                        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
                    }

                    const CreatedTransactionResult& tx_result = fund_res.value();
                    funded_tx = CMutableTransaction(*tx_result.tx);
                    transaction_fee = tx_result.fee;
                    btc_change_pos = tx_result.change_pos;

                    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                        CTxOut& out = funded_tx.vout[i];
                        if (out.scriptPubKey != collateral_template->script_pubkey) continue;
                        if (collateral_template->is_native) {
                            out.nValue = static_cast<CAmount>(collateral_template->units);
                            out.vExt.clear();
                        } else {
                            out.nValue = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                            out.vExt = collateral_template->vext;
                        }
                        sweep_original_index = i;
                        break;
                    }
                    if (!sweep_original_index) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate collateral sweep output after funding");
                    }
                } else {
                    RepoAssetSkeletonResult skeleton = BuildRepoAssetSkeleton(*pwallet, request, record.terms.collateral_leg, repay_dest, "repo.build_default_sweep", fee_rate_override);

                    {
                        LOCK(pwallet->cs_wallet);
                        for (const COutPoint& outpoint : skeleton.inputs_to_lock) {
                            if (!pwallet->IsLockedCoin(outpoint)) {
                                pwallet->LockCoin(outpoint);
                            }
                        }
                    }

                    std::set<COutPoint> skeleton_prevouts;
                    for (const CTxIn& vin : skeleton.tx.vin) {
                        CTxIn vin_copy = vin;
                        vin_copy.nSequence = 0; // Enable CLTV for vault enforcement
                        if (skeleton_prevouts.insert(vin_copy.prevout).second) {
                            tx_template.vin.push_back(vin_copy);
                        }
                        coin_control.Select(vin_copy.prevout);
                    }

                    if (!skeleton.deliver_output_index) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset skeleton missing delivery output");
                    }
                    CTxOut sweep_delivery = skeleton.tx.vout[*skeleton.deliver_output_index];
                    tx_template.vout.push_back(sweep_delivery);
                    sweep_original_index = tx_template.vout.size() - 1;

                    for (size_t change_idx : skeleton.change_indices) {
                        if (change_idx < skeleton.tx.vout.size()) {
                            tx_template.vout.push_back(skeleton.tx.vout[change_idx]);
                        }
                    }

                    coin_control.m_avoid_asset_utxos = true;
                    std::vector<CRecipient> recipients;
                    auto fund_res = FundTransaction(*pwallet, tx_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
                    if (!fund_res) {
                        LOCK(pwallet->cs_wallet);
                        for (const COutPoint& outpoint : skeleton.inputs_to_lock) {
                            pwallet->UnlockCoin(outpoint);
                        }
                        bilingual_str err = util::ErrorString(fund_res);
                        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
                    }

                    const CreatedTransactionResult& tx_result = fund_res.value();
                    funded_tx = CMutableTransaction(*tx_result.tx);
                    transaction_fee = tx_result.fee;
                    btc_change_pos = tx_result.change_pos;

                    if (!skeleton.change_indices.empty()) {
                        size_t first_change = *skeleton.change_indices.begin();
                        if (first_change < skeleton.tx.vout.size()) {
                            const CTxOut& change_out = skeleton.tx.vout[first_change];
                            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                                if (funded_tx.vout[i].scriptPubKey == change_out.scriptPubKey &&
                                    funded_tx.vout[i].nValue == change_out.nValue) {
                                    asset_change_output_index = static_cast<int>(i);
                                    break;
                                }
                            }
                        }
                    }

                    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                        if (funded_tx.vout[i].scriptPubKey == lender_spk &&
                            funded_tx.vout[i].nValue == sweep_delivery.nValue) {
                            sweep_original_index = i;
                            break;
                        }
                    }
                }
            } else {
                // NATIVE BTC COLLATERAL: Use traditional FundTransaction approach
                coin_control.m_allow_other_inputs = true;
                coin_control.m_avoid_asset_utxos = false;

                std::vector<CRecipient> recipients;
                const CAmount sweep_amount = static_cast<CAmount>(record.terms.collateral_leg.units);
                recipients.push_back({repay_dest, sweep_amount, /*subtract fee*/ true});

                auto fund_res = FundTransaction(*pwallet, tx_template, recipients, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, coin_control);
                if (!fund_res) {
                    bilingual_str err = util::ErrorString(fund_res);
                    throw JSONRPCError(RPC_WALLET_ERROR, err.original);
                }

                const CreatedTransactionResult& tx_result = fund_res.value();
                funded_tx = CMutableTransaction(*tx_result.tx);
                transaction_fee = tx_result.fee;
                btc_change_pos = tx_result.change_pos;

                // Find sweep output
                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    if (funded_tx.vout[i].scriptPubKey == lender_spk) {
                        sweep_original_index = i;
                        break;
                    }
                }
            }

            if (!sweep_original_index) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to identify sweep output in funded transaction");
            }

            // Reorder outputs: sweep first, then everything else
            std::vector<CTxOut> reordered;
            reordered.reserve(funded_tx.vout.size());
            reordered.push_back(funded_tx.vout[*sweep_original_index]);

            // Track how asset change position changes after reordering
            int final_asset_change_pos = asset_change_output_index;
            if (asset_change_output_index >= 0) {
                if (static_cast<size_t>(asset_change_output_index) < *sweep_original_index) {
                    final_asset_change_pos = asset_change_output_index + 1;
                } else if (static_cast<size_t>(asset_change_output_index) > *sweep_original_index) {
                    final_asset_change_pos = asset_change_output_index; // Position relative to non-sweep outputs
                } else {
                    // asset_change_output_index was the sweep index, which shouldn't happen
                    final_asset_change_pos = -1;
                }
            }

            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                if (i == *sweep_original_index) continue;
                reordered.push_back(funded_tx.vout[i]);
            }
            funded_tx.vout = std::move(reordered);
            const size_t sweep_output_index = 0;

            PartiallySignedTransaction psbt(funded_tx);

            // Prepare taproot spend data for input.
            size_t vault_input_index = std::numeric_limits<size_t>::max();
            for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
                if (funded_tx.vin[i].prevout == vault_outpoint) {
                    vault_input_index = i;
                    break;
                }
            }
            if (vault_input_index == std::numeric_limits<size_t>::max()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Vault input missing from funded transaction");
            }

            // CRITICAL: Always populate witness_utxo for Taproot signing
            // Without this, SignatureHashSchnorr will fail and no signature will be produced
            psbt.inputs[vault_input_index].witness_utxo = vault_coin.out;

            // CRITICAL: Retrieve vault metadata from registry (not rebuild from builder)
            // Vaults are registered under the borrower destination script, not the vault covenant script
            const CScript borrower_spk = GetScriptForDestination(record.borrower_dest);
            std::optional<VaultMetadata> vault_meta;
            {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(borrower_spk);
                if (managers.empty()) {
                    for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                        if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                            managers.insert(manager);
                        }
                    }
                }
                for (ScriptPubKeyMan* manager : managers) {
                    if (auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                        // GetVaultMetadata uses the vault covenant script as the lookup key
                        vault_meta = desc_spkm->GetVaultMetadata(covenant_spk);
                        if (vault_meta) break;
                    }
                }
            }

            if (!vault_meta) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry");
            }

            // Find default leaf in vault metadata and use its EXACT script for leaf hash
            // This ensures the leaf hash matches what was registered, avoiding subtle mismatches
            const VaultLeafDescriptor* default_leaf = nullptr;
            for (const auto& leaf : vault_meta->leaves) {
                if (leaf.purpose == "default") {
                    default_leaf = &leaf;
                    break;
                }
            }
            if (!default_leaf) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Default leaf not found in vault metadata");
            }

            // Compute leaf hash from the EXACT script stored in vault metadata
            const uint256 default_leaf_hash = ComputeTapleafHash(
                default_leaf->leaf_version,
                std::span<const unsigned char>(default_leaf->script.data(), default_leaf->script.size()));

            NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);
            bool complete = false;
            const auto fill_err_default = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true);
            if (fill_err_default) {
                throw JSONRPCPSBTError(*fill_err_default);
            }

            NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);

            // Detect if we have the lender's private key (hot wallet vs watch-only)
            // Use the same robust approach as forward.build_im_timeout
            CKey lender_privkey;
            bool have_privkey = false;
            {
                LOCK(pwallet->cs_wallet);
                for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;

                    // GetKeyByXOnly returns false for watch-only descriptors
                    if (desc_spkm->GetKeyByXOnly(lender_key, lender_privkey)) {
                        have_privkey = true;
                        pwallet->WalletLogPrintf("build_default_sweep: Found lender private key in descriptor %s\n",
                                                desc_spkm->GetID().ToString());
                        break;
                    }
                }
            }

            // TWO-PATH SOLUTION: Branch based on key availability
            if (have_privkey) {
                // HOT WALLET PATH: Directly sign and return complete transaction
                pwallet->WalletLogPrintf("build_default_sweep: Using hot wallet path (direct signing)\n");

                FinalizeVaultTaprootLeafWitness(*pwallet,
                                                psbt,
                                                vault_input_index,
                                                *vault_meta,
                                                *default_leaf,
                                                lender_privkey,
                                                "build_default_sweep");

                // Convert PSBT to final transaction
                CMutableTransaction mtx(*psbt.tx);
                for (size_t i = 0; i < psbt.inputs.size(); ++i) {
                    if (!psbt.inputs[i].final_script_witness.IsNull()) {
                        mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
                    }
                }

                CTransaction final_tx(mtx);

                DataStream signed_psbt_stream{};
                signed_psbt_stream << psbt;
                const std::string signed_psbt_b64 = EncodeBase64(signed_psbt_stream.str());

                // Return complete transaction
                const std::string hex = EncodeHexTx(final_tx);
                const Txid txid = final_tx.GetHash();

                pwallet->WalletLogPrintf("build_default_sweep: Successfully signed default sweep (hot wallet)\n");

                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", signed_psbt_b64);
                result.pushKV("hex", hex);
                result.pushKV("txid", txid.ToString());
                result.pushKV("complete", true);
                result.pushKV("fee", ValueFromAmount(transaction_fee));
                result.pushKV("changepos", btc_change_pos ? int(*btc_change_pos) : -1);
                result.pushKV("asset_change_output_index", final_asset_change_pos);
                result.pushKV("vault_input_index", int(vault_input_index));
                result.pushKV("sweep_output_index", int(sweep_output_index));
                return result;

            } else {
                // WATCH-ONLY PATH: Return clean PSBT with only default leaf
                pwallet->WalletLogPrintf("build_default_sweep: Using watch-only path (PSBT for external signer)\n");

                // Use spenddata from registered vault
                const TaprootSpendData& spenddata = vault_meta->spenddata;
                auto& psbt_in = psbt.inputs[vault_input_index];
                psbt_in.m_tap_internal_key = spenddata.internal_key;
                psbt_in.m_tap_merkle_root = spenddata.merkle_root;

                // CRITICAL: Only include the default leaf in tap_scripts
                for (const auto& [script_key, control_blocks] : spenddata.scripts) {
                    const uint256 script_hash = (HashWriter{} << uint8_t(script_key.second) << script_key.first).GetSHA256();
                    if (script_hash == default_leaf_hash) {
                        auto& entry = psbt_in.m_tap_scripts[script_key];
                        entry.insert(control_blocks.begin(), control_blocks.end());
                    }
                }

                psbt_in.witness_utxo = vault_coin.out;
                psbt_in.sighash_type = SIGHASH_DEFAULT;

                // Add BIP32 derivation for the lender key on the default leaf
                std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(lender_spk);
                KeyOriginInfo origin;
                CPubKey full_pub;
                if (provider && provider->GetKeyOriginByXOnly(lender_key, origin)) {
                    auto& derivation = psbt_in.m_tap_bip32_paths[lender_key];
                    derivation.first.insert(default_leaf_hash);
                    derivation.second = origin;
                    if (provider->GetPubKeyByXOnly(lender_key, full_pub)) {
                        psbt_in.hd_keypaths.emplace(full_pub, origin);
                    }
                }

                DataStream ssTx{};
                ssTx << psbt;

                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("complete", false);
                result.pushKV("fee", ValueFromAmount(transaction_fee));
                result.pushKV("changepos", btc_change_pos ? int(*btc_change_pos) : -1);
                result.pushKV("asset_change_output_index", final_asset_change_pos);
                result.pushKV("vault_input_index", int(vault_input_index));
                result.pushKV("sweep_output_index", int(sweep_output_index));

                // Add signing info for external signers
                UniValue signing_info(UniValue::VOBJ);
                signing_info.pushKV("leaf_hash", HexStr(default_leaf_hash));
                signing_info.pushKV("leaf_script", HexStr(default_script));
                signing_info.pushKV("lender_key", HexStr(lender_key));
                result.pushKV("signing_info", signing_info);

                return result;
            }
        }
    );
}

RPCHelpMan repo_sign_default_sweep()
{
    return RPCHelpMan(
        "repo.sign_default_sweep",
        "Sign a repo default sweep PSBT using the wallet's vault registry.\n"
        "This RPC produces the tapscript witness for the lender's default path and returns both the signed PSBT\n"
        "and the final transaction hex for broadcast.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Partially Signed Bitcoin Transaction (base64)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Signed PSBT (base64) including the final witness"},
                {RPCResult::Type::STR_HEX, "hex", "Fully signed transaction ready for broadcast"},
                {RPCResult::Type::STR_HEX, "txid", "Transaction identifier"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the covenant input that was signed"},
                {RPCResult::Type::BOOL, "complete", "Always true once the vault path is signed"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.sign_default_sweep", "\"" + std::string(64, 'a') + "\" \"cHNidP8BA...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            EnsureWalletIsUnlocked(*pwallet);

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            const RepoOfferRecord record = *record_opt;

            if (!record.vault_outpoint.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Repo offer does not have a registered vault outpoint");
            }
            const COutPoint vault_outpoint = *record.vault_outpoint;

            const std::string psbt_b64 = request.params[1].get_str();
            PartiallySignedTransaction psbt;
            std::string err;
            if (!DecodeBase64PSBT(psbt, psbt_b64, err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("PSBT decode failed: %s", err));
            }
            if (!psbt.tx) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "PSBT missing unsigned transaction");
            }

            size_t vault_input_index = std::numeric_limits<size_t>::max();
            for (size_t i = 0; i < psbt.tx->vin.size(); ++i) {
                if (psbt.tx->vin[i].prevout == vault_outpoint) {
                    vault_input_index = i;
                    break;
                }
            }
            if (vault_input_index == std::numeric_limits<size_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT does not contain the repo vault input");
            }
            if (vault_input_index >= psbt.inputs.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT input set malformed");
            }

            auto& psbt_in = psbt.inputs[vault_input_index];
            if (psbt_in.witness_utxo.IsNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT missing witness_utxo for vault input");
            }
            const CScript& covenant_spk = psbt_in.witness_utxo.scriptPubKey;

            std::optional<VaultMetadata> vault_meta;
            {
                LOCK(pwallet->cs_wallet);
                for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    vault_meta = desc_spkm->GetVaultMetadata(covenant_spk);
                    if (vault_meta.has_value()) {
                        break;
                    }
                }
            }
            if (!vault_meta.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry");
            }

            const VaultLeafDescriptor* default_leaf = nullptr;
            for (const auto& leaf : vault_meta->leaves) {
                if (leaf.purpose == "default") {
                    default_leaf = &leaf;
                    break;
                }
            }
            if (!default_leaf) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Default leaf not found in vault metadata");
            }

            const XOnlyPubKey lender_key = default_leaf->signing_key;

            CKey lender_privkey;
            bool have_privkey{false};
            {
                LOCK(pwallet->cs_wallet);
                for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    if (desc_spkm->GetKeyByXOnly(lender_key, lender_privkey)) {
                        have_privkey = true;
                        pwallet->WalletLogPrintf("repo.sign_default_sweep: Found lender private key in descriptor %s\n",
                                                 desc_spkm->GetID().ToString());
                        break;
                    }
                }
            }
            if (!have_privkey) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not control the lender key for this vault");
            }

            FinalizeVaultTaprootLeafWitness(*pwallet,
                                            psbt,
                                            vault_input_index,
                                            *vault_meta,
                                            *default_leaf,
                                            lender_privkey,
                                            "repo.sign_default_sweep");

            CMutableTransaction mtx(*psbt.tx);
            for (size_t i = 0; i < psbt.inputs.size(); ++i) {
                if (!psbt.inputs[i].final_script_witness.IsNull()) {
                    mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
                }
            }

            CTransaction final_tx(mtx);

            DataStream ssTx{};
            ssTx << psbt;
            const std::string signed_psbt = EncodeBase64(ssTx.str());
            const std::string hex = EncodeHexTx(final_tx);
            const Txid txid = final_tx.GetHash();

            pwallet->WalletLogPrintf("repo.sign_default_sweep: Signed default sweep for offer %s (input=%zu)\n",
                                     record.offer_id.ToString(), vault_input_index);

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", signed_psbt);
            result.pushKV("hex", hex);
            result.pushKV("txid", txid.ToString());
            result.pushKV("vault_input_index", int(vault_input_index));
            result.pushKV("complete", true);
            return result;
        }
    );
}

RPCHelpMan repo_update_repay_address()
{
    return RPCHelpMan(
        "repo.update_repay_address",
        "Update the lender repayment destination for an accepted repo contract. The new address must be Taproot (bech32m).",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "New repayment address (Taproot)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "id", "Repo identifier"},
                {RPCResult::Type::STR, "repay_address", "Updated repayment address"},
                {RPCResult::Type::STR_HEX, "xonly", "Tweaked (output) Taproot pubkey for the repayment address"},
                {RPCResult::Type::STR_HEX, "internal_xonly", "Untweaked internal Taproot pubkey for the repayment address"},
                {RPCResult::Type::OBJ, "share", "Payload the counterparty must import", std::vector<RPCResult>{
                    {RPCResult::Type::STR_HEX, "offer_id", "Repo identifier"},
                    {RPCResult::Type::STR_HEX, "commitment", "Offer commitment for validation"},
                    {RPCResult::Type::STR, "repay_address", "Updated repayment address"},
                    {RPCResult::Type::STR_HEX, "xonly", "Tweaked (output) Taproot pubkey of the new address"},
                    {RPCResult::Type::STR_HEX, "internal_xonly", "Untweaked internal Taproot pubkey of the new address"},
                }},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.update_repay_address", "\"" + std::string(64, 'a') + "\" \"bcrt1p...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }

            const std::string addr_str = request.params[1].get_str();
            CTxDestination new_dest = DecodeDestination(addr_str);
            if (!IsValidDestination(new_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid repayment address");
            }

            const auto tap_key_opt = ExtractTaprootKey(new_dest);
            if (!tap_key_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Repayment address must be Taproot bech32m");
            }

            auto lender_internal = ExtractInternalKeyForDestination(*pwallet, new_dest);
            if (!lender_internal.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to derive internal Taproot key for repayment address");
            }

            if (!pwallet->UpdateRepoRepayDestination(*offer_id, new_dest, lender_internal)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to update repayment address");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("id", id_hex);
            result.pushKV("repay_address", addr_str);
            const std::string tap_hex = HexStr(std::vector<unsigned char>(tap_key_opt->begin(), tap_key_opt->end()));
            result.pushKV("xonly", tap_hex);
            const std::string internal_hex = HexStr(std::vector<unsigned char>(lender_internal->begin(), lender_internal->end()));
            result.pushKV("internal_xonly", internal_hex);
            UniValue share(UniValue::VOBJ);
            share.pushKV("offer_id", id_hex);
            share.pushKV("commitment", record_opt->commitment_hex);
            share.pushKV("repay_address", addr_str);
            share.pushKV("xonly", tap_hex);
            share.pushKV("internal_xonly", internal_hex);
            result.pushKV("share", std::move(share));
            return result;
        }
    );
}

RPCHelpMan repo_import_repay_address()
{
    return RPCHelpMan(
        "repo.import_repay_address",
        "Import a repayment override payload provided by the counterparty.",
        std::vector<RPCArg>{
            {"payload", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Payload returned by repo.update_repay_address", {
                {"offer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo identifier"},
                {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Offer commitment for validation"},
                {"repay_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Updated repayment address (Taproot)"},
                {"xonly", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "X-only pubkey of the new Taproot address"},
                {"internal_xonly", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Untweaked internal Taproot pubkey of the new address"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "id", "Repo identifier"},
                {RPCResult::Type::STR, "repay_address", "Imported repayment address"},
                {RPCResult::Type::STR_HEX, "xonly", "Tweaked (output) Taproot pubkey of the imported address"},
                {RPCResult::Type::STR_HEX, "internal_xonly", /*optional=*/true, "Untweaked internal Taproot pubkey of the imported address"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("repo.import_repay_address", "\"{\\\"offer_id\\\":\\\"...\\\",\\\"repay_address\\\":\\\"bcrt1p...\\\"}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue payload = request.params[0].get_obj();
            const UniValue& id_val = payload.find_value("offer_id");
            const UniValue& commitment_val = payload.find_value("commitment");
            const UniValue& repay_val = payload.find_value("repay_address");
            const UniValue& xonly_val = payload.find_value("xonly");
            const UniValue& internal_val = payload.find_value("internal_xonly");

            if (!id_val.isStr() || !IsHex(id_val.get_str()) || id_val.get_str().size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payload.offer_id must be 32-byte hex");
            }
            if (!commitment_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payload.commitment must be hex string");
            }
            if (!repay_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payload.repay_address is required");
            }
            if (!xonly_val.isStr() || !IsHex(xonly_val.get_str()) || xonly_val.get_str().size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payload.xonly must be 32-byte hex");
            }
            std::optional<XOnlyPubKey> internal_key;
            if (!internal_val.isNull()) {
                if (!internal_val.isStr() || !IsHex(internal_val.get_str()) || internal_val.get_str().size() != 64) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "payload.internal_xonly must be 32-byte hex when provided");
                }
                internal_key = ParseXOnlyPubKeyHex(payload, "internal_xonly");
            }

            const std::string id_hex = id_val.get_str();
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payload.offer_id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            RepoOfferRecord record = *record_opt;

            if (record.commitment_hex != commitment_val.get_str()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Commitment mismatch");
            }

            CTxDestination repay_dest = DecodeDestination(repay_val.get_str());
            if (!IsValidDestination(repay_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid repay_address");
            }

            const auto tap_key_opt = ExtractTaprootKey(repay_dest);
            if (!tap_key_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Repayment address must be Taproot bech32m");
            }

            const std::string tap_hex = HexStr(std::vector<unsigned char>(tap_key_opt->begin(), tap_key_opt->end()));
            if (tap_hex != xonly_val.get_str()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "X-only pubkey mismatch");
            }

            if (!pwallet->UpdateRepoRepayDestination(*offer_id, repay_dest, internal_key)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to import repayment address");
            }

            if (auto updated_opt = pwallet->FindRepoOffer(*offer_id)) {
                RepoOfferRecord updated_record = *updated_opt;
                if (updated_record.acceptance) {
                    RepoAcceptanceRecord acceptance_updated = *updated_record.acceptance;
                    acceptance_updated.repay_principal_template.reset();
                    acceptance_updated.repay_interest_template.reset();

                    const bool merge_repay = ShouldMergeRepoRepayLegs(updated_record.terms);
                    if (merge_repay) {
                        AssetLeg combined = updated_record.terms.principal_leg;
                        combined.units += updated_record.terms.interest_leg.units;
                        acceptance_updated.repay_principal_template = BuildRepoDeliveryTemplate(
                            *pwallet,
                            request,
                            combined,
                            repay_dest,
                            "repo.import_repay_address.repay_combined");
                    } else {
                        if (updated_record.terms.principal_leg.units > 0) {
                            acceptance_updated.repay_principal_template = BuildRepoDeliveryTemplate(
                                *pwallet,
                                request,
                                updated_record.terms.principal_leg,
                                repay_dest,
                                "repo.import_repay_address.repay_principal");
                        }
                        if (updated_record.terms.interest_leg.units > 0) {
                            acceptance_updated.repay_interest_template = BuildRepoDeliveryTemplate(
                                *pwallet,
                                request,
                                updated_record.terms.interest_leg,
                                repay_dest,
                                "repo.import_repay_address.repay_interest");
                        }
                    }

                    acceptance_updated.default_collateral_template.reset();
                    if (!updated_record.terms.collateral_leg.is_native) {
                        acceptance_updated.default_collateral_template = BuildRepoDeliveryTemplate(
                            *pwallet,
                            request,
                            updated_record.terms.collateral_leg,
                            repay_dest,
                            "repo.import_repay_address.default_collateral");
                    }

                    RepoOfferRecord commit_offer = updated_record;
                    commit_offer.acceptance = acceptance_updated;
                    acceptance_updated.commitment_hex = RepoAcceptanceCommitmentHex(commit_offer, acceptance_updated);
                    updated_record.acceptance = acceptance_updated;
                    pwallet->RegisterRepoOffer(updated_record);
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("id", id_hex);
            result.pushKV("repay_address", repay_val.get_str());
            result.pushKV("xonly", tap_hex);
            if (internal_key.has_value()) {
                result.pushKV("internal_xonly", HexStr(std::vector<unsigned char>(internal_key->begin(), internal_key->end())));
            } else {
                pwallet->WalletLogPrintf("repo.import_repay_address: WARNING: payload did not include internal_xonly; falling back to tweaked key for default path\n");
            }
            return result;
        }
    );
}

RPCHelpMan repo_import_acceptance()
{
    return RPCHelpMan(
        "repo.import_acceptance",
        "Import an acceptance payload provided by the counterparty.",
        std::vector<RPCArg>{
            {"acceptance", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Acceptance payload from repo.accept", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", "Acceptance identifier"},
                {RPCResult::Type::OBJ, "acceptance", "Canonical acceptance payload", RepoAcceptanceResultDescription()},
            }
        },
        RPCExamples{
            HelpExampleCli("repo.import_acceptance", "\"{...accept json...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& acceptance_obj = request.params[0].get_obj();

            const UniValue& offer_id_val = acceptance_obj.find_value("offer_id");
            if (!offer_id_val.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.offer_id is required");
            }
            const std::string offer_id_hex = offer_id_val.get_str();
            if (!IsHex(offer_id_hex) || offer_id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.offer_id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(offer_id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.offer_id invalid");
            }

            auto stored_opt = pwallet->FindRepoOffer(*offer_id);
            if (!stored_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            RepoOfferRecord stored = *stored_opt;

            // Parse borrower's internal key if provided (from borrower's acceptance)
            const UniValue& borrower_key_val = acceptance_obj.find_value("borrower_internal_key");
            if (borrower_key_val.isStr()) {
                const std::string key_hex = borrower_key_val.get_str();
                if (IsHex(key_hex) && key_hex.size() == 64) {
                    auto key_bytes = ParseHex(key_hex);
                    stored.borrower_internal_key = XOnlyPubKey(key_bytes);
                    pwallet->WalletLogPrintf("Imported borrower internal key from acceptance: %s\n", key_hex);
                }
            }

            // Parse lender's internal key if provided (from lender's acceptance)
            const UniValue& lender_key_val = acceptance_obj.find_value("lender_internal_key");
            if (lender_key_val.isStr()) {
                const std::string key_hex = lender_key_val.get_str();
                if (IsHex(key_hex) && key_hex.size() == 64) {
                    auto key_bytes = ParseHex(key_hex);
                    stored.lender_internal_key = XOnlyPubKey(key_bytes);
                    pwallet->WalletLogPrintf("Imported lender internal key from acceptance: %s\n", key_hex);
                }
            }

            const CTxDestination expected_repay_dest = stored.lender_dest_override ? *stored.lender_dest_override
                                                                                  : stored.lender_dest;

            // SECURITY CHECK (early): Block repayment redirection attempts before parsing templates.
            const UniValue& sinks_ack_val = acceptance_obj.find_value("sinks_ack");
            if (!sinks_ack_val.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.sinks_ack must be an object");
            }
            const CTxDestination ack_dest = ParseScriptDestinationHex(sinks_ack_val.get_obj(), "repay_spk");
            if (ack_dest != expected_repay_dest) {
                const std::string ack_str = EncodeDestination(ack_dest);
                const std::string expected_str = EncodeDestination(expected_repay_dest);
                pwallet->WalletLogPrintf(
                    "WARNING: Repo acceptance repayment ack mismatch (ack=%s expected=%s)\n",
                    ack_str,
                    expected_str);
                throw JSONRPCError(
                    RPC_VERIFY_ERROR,
                    strprintf("Security: Borrower's repay address acknowledgment (%s) does not match lender's specified address (%s). "
                              "This could be an attempt to redirect repayment. Rejecting acceptance.",
                              ack_str,
                              expected_str));
            }

            RepoAcceptanceRecord acceptance = ParseRepoAcceptanceObject(stored, acceptance_obj);

            // SECURITY CHECK: Verify that borrower isn't trying to malleate lender's repay address
            // The lender's repay address should match what they originally specified in the offer
            if (acceptance.repay_dest_ack != expected_repay_dest) {
                pwallet->WalletLogPrintf("WARNING: Borrower's repay_dest_ack (%s) differs from lender's expected address (%s)\n",
                                        EncodeDestination(acceptance.repay_dest_ack),
                                        EncodeDestination(expected_repay_dest));
                throw JSONRPCError(RPC_VERIFY_ERROR,
                    strprintf("Security: Borrower's repay address acknowledgment (%s) does not match lender's specified address (%s). "
                             "This could be an attempt to redirect repayment. Rejecting acceptance.",
                             EncodeDestination(acceptance.repay_dest_ack),
                             EncodeDestination(expected_repay_dest)));
            }

            RepoOfferRecord updated;
            try {
                updated = pwallet->RegisterRepoAcceptance(*offer_id, std::move(acceptance));
                // Preserve the imported internal keys
                if (stored.borrower_internal_key.has_value()) {
                    updated.borrower_internal_key = stored.borrower_internal_key;
                    pwallet->RegisterRepoOffer(updated); // Re-register to persist internal key
                }
                if (stored.lender_internal_key.has_value()) {
                    updated.lender_internal_key = stored.lender_internal_key;
                    pwallet->RegisterRepoOffer(updated); // Re-register to persist internal key
                }
            } catch (const std::runtime_error& err) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err.what());
            }
            const RepoAcceptanceRecord& stored_acceptance = *updated.acceptance;

            UniValue acceptance_json = RepoAcceptanceCanonicalJson(updated, stored_acceptance);
            acceptance_json.pushKV("salt", stored_acceptance.salt.GetHex());
            acceptance_json.pushKV("commitment", stored_acceptance.commitment_hex);
            // Include internal keys if available
            if (updated.borrower_internal_key.has_value()) {
                acceptance_json.pushKV("borrower_internal_key", HexStr(*updated.borrower_internal_key));
            }
            if (updated.lender_internal_key.has_value()) {
                acceptance_json.pushKV("lender_internal_key", HexStr(*updated.lender_internal_key));
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", stored_acceptance.acceptance_id.GetHex());
            result.pushKV("acceptance", std::move(acceptance_json));
            return result;
        }
    );
}


RPCHelpMan repo_export_acceptance()
{
    return RPCHelpMan(
        "repo.export_acceptance",
        "Export the acceptance payload for sharing with the counterparty.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Repo offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", "Acceptance identifier"},
                {RPCResult::Type::OBJ, "acceptance", "Canonical acceptance payload", RepoAcceptanceResultDescription()},
            }
        },
        RPCExamples{
            HelpExampleCli("repo.export_acceptance", std::string(64, 'a'))
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindRepoOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown repo offer id");
            }
            const RepoOfferRecord& record = *record_opt;
            if (!record.acceptance) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer has no acceptance recorded");
            }

            UniValue acceptance_json = RepoAcceptanceCanonicalJson(record, *record.acceptance);
            acceptance_json.pushKV("salt", record.acceptance->salt.GetHex());
            acceptance_json.pushKV("commitment", record.acceptance->commitment_hex);
            // Include borrower's internal key if available
            if (record.borrower_internal_key.has_value()) {
                acceptance_json.pushKV("borrower_internal_key", HexStr(*record.borrower_internal_key));
            }
            if (record.acceptance->default_collateral_template) {
                const AssetDeliveryTemplate& tmpl = *record.acceptance->default_collateral_template;
                UniValue collateral_template(UniValue::VOBJ);
                collateral_template.pushKV("purpose", "default_collateral");
                collateral_template.pushKV("is_native", tmpl.is_native);
                collateral_template.pushKV("units", static_cast<int64_t>(tmpl.units));
                collateral_template.pushKV("script_pubkey", HexStr(tmpl.script_pubkey));
                collateral_template.pushKV("commitment", tmpl.commitment.GetHex());
                if (!tmpl.is_native) {
                    collateral_template.pushKV("asset_id", tmpl.asset_id.GetHex());
                    collateral_template.pushKV("vext", HexStr(tmpl.vext));
                }
                acceptance_json.pushKV("default_collateral_template", std::move(collateral_template));
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", record.acceptance->acceptance_id.GetHex());
            result.pushKV("acceptance", std::move(acceptance_json));
            return result;
        }
    );
}

// Forward declarations
UniValue ForwardTermsToJSON(const ForwardTerms& terms);

// ── Difficulty-derivative summaries shared by contract.list / contract.status ─────────────────────────
// The wallet's role in a difficulty contract is whichever payout address it controls: a CFD party owns its
// leg's owner_key (IM return) and the other leg's cp_key (its claim); an option party owns the writer leg's
// owner_key (writer) or its cp_key (buyer). Requires cs_wallet for IsMine.
static std::string DifficultyRole(const DifficultyContractRecord& rec, const CWallet& wallet)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const DifficultyContractTerms& t = rec.terms;
    auto mine = [&](const XOnlyPubKey& k) {
        return !k.IsNull() && (wallet.IsMine(GetScriptForDestination(WitnessV1Taproot{k})) & ISMINE_SPENDABLE);
    };
    if (t.IsOption()) {
        const DifficultyLegTerms& wl = t.OptionWriterLeg();
        if (mine(wl.owner_key)) return "writer";
        if (mine(wl.cp_key)) return "buyer";
        return "unknown";
    }
    if (mine(t.long_leg.owner_key) || mine(t.short_leg.cp_key)) return "long";
    if (mine(t.short_leg.owner_key) || mine(t.long_leg.cp_key)) return "short";
    return "unknown";
}

// True iff this leg is funded (has a vault outpoint) AND that vault has been spent — i.e. the leg has been
// settled (or cooperatively closed). The wallet's spend view is authoritative for the UI because every
// difficulty payout pays a wallet address, so the settling tx is always a wallet tx. Requires cs_wallet.
static bool DifficultyLegSettled(const CWallet& wallet, const DifficultyContractRecord& rec, bool is_short)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const COutPoint& op = rec.VaultOutpoint(is_short);
    return !op.IsNull() && wallet.IsSpent(op);
}

// Lifecycle derived from the record + the wallet's spend view: "accepted" (no open tx) -> "opened" ->
// "partially_settled"/"settled" as funded vaults are spent. A CFD funds both legs; an option funds only the
// writer's leg. Requires cs_wallet (IsSpent).
static std::string DifficultyStatus(const CWallet& wallet, const DifficultyContractRecord& rec)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (rec.open_txid.IsNull()) return "accepted";
    if (rec.terms.IsOption()) {
        return DifficultyLegSettled(wallet, rec, rec.terms.OptionWriterIsShort()) ? "settled" : "opened";
    }
    const bool long_settled = DifficultyLegSettled(wallet, rec, /*is_short=*/false);
    const bool short_settled = DifficultyLegSettled(wallet, rec, /*is_short=*/true);
    if (long_settled && short_settled) return "settled";
    if (long_settled || short_settled) return "partially_settled";
    return "opened";
}

// Push the common difficulty term/lifecycle fields onto an object (used for both list entries and status).
// Requires cs_wallet for the per-leg settled flags. (Term fields don't need it, but the flags do.)
static void AppendDifficultyFields(const CWallet& wallet, const DifficultyContractRecord& rec, UniValue& e)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const DifficultyContractTerms& t = rec.terms;
    e.pushKV("kind", t.IsOption() ? "option" : "cfd");
    e.pushKV("strike_nbits", strprintf("%08x", t.strike_nbits));
    e.pushKV("fixing_height", static_cast<uint64_t>(t.fixing_height));
    e.pushKV("settle_lock_height", static_cast<uint64_t>(t.settle_lock_height));

    auto leg_json = [](const DifficultyLegTerms& L) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("im", ValueFromAmount(L.im));
        o.pushKV("lambda_q", static_cast<uint64_t>(L.lambda_q));
        o.pushKV("lambda", L.lambda_q / 65536.0);
        return o;
    };
    e.pushKV("long_leg", leg_json(t.long_leg));
    e.pushKV("short_leg", leg_json(t.short_leg));

    if (t.IsOption()) {
        e.pushKV("writer_side", t.OptionWriterIsShort() ? "short" : "long");
        e.pushKV("premium", ValueFromAmount(t.premium));
    }
    if (!rec.long_vault.IsNull()) e.pushKV("long_vault", rec.long_vault.ToString());
    if (!rec.short_vault.IsNull()) e.pushKV("short_vault", rec.short_vault.ToString());
    if (!rec.open_txid.IsNull()) {
        e.pushKV("open_txid", rec.open_txid.GetHex());
        // Per-leg settled flags (funded vault spent) so the UI can offer only live legs.
        e.pushKV("long_settled", DifficultyLegSettled(wallet, rec, /*is_short=*/false));
        e.pushKV("short_settled", DifficultyLegSettled(wallet, rec, /*is_short=*/true));
    }
}

// ---- Scalar-feed bilateral CFD list helpers (mirror the difficulty ones above) ----------------------
// The local wallet's role, derived from KEY OWNERSHIP (never the proposer side): a scalar CFD funds two
// legs; owner_key of a leg is that leg's party, cp_key is its counterparty. There is no option variant.
static std::string ScalarCfdRole(const ScalarCfdContractRecord& rec, const CWallet& wallet)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const ScalarCfdContractTerms& t = rec.terms;
    auto mine = [&](const XOnlyPubKey& k) {
        return !k.IsNull() && (wallet.IsMine(GetScriptForDestination(WitnessV1Taproot{k})) & ISMINE_SPENDABLE);
    };
    if (mine(t.long_leg.owner_key) || mine(t.short_leg.cp_key)) return "long";
    if (mine(t.short_leg.owner_key) || mine(t.long_leg.cp_key)) return "short";
    return "unknown";
}

// True iff this leg is funded (has a vault outpoint) AND that vault has been spent — settled or coop-closed.
static bool ScalarCfdLegSettled(const CWallet& wallet, const ScalarCfdContractRecord& rec, bool is_short)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const COutPoint& op = rec.VaultOutpoint(is_short);
    return !op.IsNull() && wallet.IsSpent(op);
}

// Lifecycle derived from the record + the wallet's spend view. Persisted scalar records begin at
// "accepted" (there is no proposed-offer registry state), so this never returns "proposed":
// "accepted" (no open tx) -> "opened" -> "partially_settled"/"settled" as the two funded vaults are spent.
static std::string ScalarCfdStatus(const CWallet& wallet, const ScalarCfdContractRecord& rec)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (rec.open_txid.IsNull()) return "accepted";
    const bool long_settled = ScalarCfdLegSettled(wallet, rec, /*is_short=*/false);
    const bool short_settled = ScalarCfdLegSettled(wallet, rec, /*is_short=*/true);
    if (long_settled && short_settled) return "settled";
    if (long_settled || short_settled) return "partially_settled";
    return "opened";
}

// Push the common scalar-feed term/lifecycle fields (mirrors AppendDifficultyFields). Requires cs_wallet
// for the per-leg settled flags.
static void AppendScalarCfdFields(const CWallet& wallet, const ScalarCfdContractRecord& rec, UniValue& e)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const ScalarCfdContractTerms& t = rec.terms;
    e.pushKV("kind", "cfd");                       // scalar-feed CFD has no option variant
    e.pushKV("payoff_mode", static_cast<uint64_t>(t.payoff_mode));
    e.pushKV("underlying_asset_id", t.underlying_asset_id.GetHex());
    e.pushKV("feed_id", static_cast<uint64_t>(t.feed_id));
    e.pushKV("fixing_ref", static_cast<uint64_t>(t.fixing_ref));
    e.pushKV("publication_deadline_height", static_cast<uint64_t>(t.publication_deadline_height));
    e.pushKV("settle_lock_height", static_cast<uint64_t>(t.settle_lock_height));
    e.pushKV("scalar_format_id", static_cast<uint64_t>(t.scalar_format_id));
    e.pushKV("strike", t.strike.GetHex());
    e.pushKV("fallback_scalar", t.fallback_scalar.GetHex());
    if (!t.collateral_asset_id.IsNull()) e.pushKV("collateral_asset_id", t.collateral_asset_id.GetHex());

    auto leg_json = [](const ScalarCfdLegTerms& L) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("im", static_cast<uint64_t>(L.im));  // collateral units (sats if native), not TSC
        o.pushKV("lambda_q", static_cast<uint64_t>(L.lambda_q));
        o.pushKV("lambda", L.lambda_q / 65536.0);
        return o;
    };
    e.pushKV("long_leg", leg_json(t.long_leg));
    e.pushKV("short_leg", leg_json(t.short_leg));

    if (!rec.long_vault.IsNull()) e.pushKV("long_vault", rec.long_vault.ToString());
    if (!rec.short_vault.IsNull()) e.pushKV("short_vault", rec.short_vault.ToString());
    if (!rec.open_txid.IsNull()) {
        e.pushKV("open_txid", rec.open_txid.GetHex());
        e.pushKV("long_settled", ScalarCfdLegSettled(wallet, rec, /*is_short=*/false));
        e.pushKV("short_settled", ScalarCfdLegSettled(wallet, rec, /*is_short=*/true));
    }
}

RPCHelpMan contract_status()
{
    return RPCHelpMan(
        "contract.status",
        "Return the current wallet view of a financing contract.",
        {
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Contract identifier"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Contract status payload", {
                {RPCResult::Type::STR_HEX, "id", "Contract identifier"},
                {RPCResult::Type::STR, "kind", "Contract type (repo, spot, forward)"},
                {RPCResult::Type::STR, "state", "Contract state (proposed, accepted, opened, repaid, defaulted, closed)"},
                {RPCResult::Type::OBJ_DYN, "offer", "Offer details",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
                {RPCResult::Type::OBJ_DYN, "deadlines", "Contract deadlines",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
                {RPCResult::Type::ARR, "utxos", "Associated UTXOs",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "Transaction ID"},
                                {RPCResult::Type::NUM, "vout", "Output index"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "Output amount"},
                                {RPCResult::Type::STR, "role", "UTXO classification (vault, long_vault, short_vault, escrow)"},
                            }
                        },
                    }
                },
                RPCResult{
                    RPCResult::Type::OBJ,
                    "closure",
                    /*optional=*/true,
                    "Closure metadata when contract is repaid or defaulted",
                    {
                        {RPCResult::Type::STR, "type", "Lifecycle outcome (repaid or defaulted)"},
                        {RPCResult::Type::STR_HEX, "txid", "Lifecycle transaction id"},
                        {RPCResult::Type::NUM, "height", "Block height of lifecycle transaction"},
                        {RPCResult::Type::NUM_TIME, "time", "Block time of lifecycle transaction"},
                    }
                },
                {RPCResult::Type::NUM, "confs", "Confirmations since creation"},
                {RPCResult::Type::STR_HEX, "vault_script_hex", /*optional=*/true, "Vault covenant script when available"},
            }, /*skip_type_check=*/true // payload shape is polymorphic across repo/spot/forward/difficulty
        },
        RPCExamples{
            "\n" + HelpExampleCli("contract.status", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto id = uint256::FromHex(id_hex);
            if (!id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            int tip_height;
            {
                LOCK(pwallet->cs_wallet);
                tip_height = pwallet->GetLastBlockHeight();
            }

            if (auto repo_opt = pwallet->FindRepoOffer(*id)) {
                {
                    LOCK(pwallet->cs_wallet);
                    pwallet->EnsureRepoClosureMetadata(*id);
                    repo_opt = pwallet->FindRepoOffer(*id);
                }
                if (repo_opt) {
                    return BuildStatusPayload(*repo_opt, tip_height, pwallet.get());
                }
            }
            if (auto spot_opt = pwallet->FindSpotOffer(*id)) {
                return BuildSpotStatusPayload(*spot_opt, tip_height);
            }
            if (auto forward_opt = pwallet->FindForwardContract(*id)) {
                UniValue result(UniValue::VOBJ);
                result.pushKV("id", id->GetHex());
                result.pushKV("kind", "forward");

                // Determine lifecycle state
                std::string state;
                if (!forward_opt->acceptance_commitment_hex.has_value()) {
                    state = "proposed";
                } else if (forward_opt->coop_close_txid) {
                    state = "cooperatively_closed";
                } else if (forward_opt->timeout_txid) {
                    state = "defaulted";
                } else if (forward_opt->self_delivery_txid && (forward_opt->escrow_claim_txid || forward_opt->escrow_refund_txid)) {
                    // Self-delivery followed by counter-party claim/refund -> contract fully closed
                    state = "closed";
                } else if (forward_opt->escrow_claim_txid) {
                    state = "settled_claim";
                } else if (forward_opt->escrow_refund_txid) {
                    state = "settled_refund";
                } else if (forward_opt->self_delivery_txid) {
                    state = "delivery_pending";
                } else if (forward_opt->open_txid && forward_opt->open_height) {
                    // CRITICAL: Require BOTH open_txid AND open_height (confirmation)
                    // to prevent premature "opened" state during ceremony/pre-broadcast
                    state = "opened";
                } else {
                    state = "accepted";
                }

                result.pushKV("state", state);
                result.pushKV("offer", ForwardTermsToJSON(forward_opt->terms));

                UniValue deadlines(UniValue::VOBJ);
                deadlines.pushKV("deadline_short", forward_opt->terms.deadline_short);
                deadlines.pushKV("deadline_long", forward_opt->terms.deadline_long);
                result.pushKV("deadlines", deadlines);

                // Populate UTXOs (vaults and escrow)
                UniValue utxos(UniValue::VARR);
                const bool is_settled = forward_opt->escrow_claim_txid || forward_opt->escrow_refund_txid ||
                                       forward_opt->timeout_txid || forward_opt->coop_close_txid;

                // Add long vault if exists and not settled
                if (forward_opt->long_margin_vault && !is_settled) {
                    UniValue utxo(UniValue::VOBJ);
                    utxo.pushKV("txid", forward_opt->long_margin_vault->hash.ToString());
                    utxo.pushKV("vout", forward_opt->long_margin_vault->n);
                    utxo.pushKV("amount", ValueFromAmount(forward_opt->long_margin_value));
                    utxo.pushKV("role", "long_vault");
                    utxos.push_back(std::move(utxo));
                }

                // Add short vault if exists and not settled
                if (forward_opt->short_margin_vault && !is_settled) {
                    UniValue utxo(UniValue::VOBJ);
                    utxo.pushKV("txid", forward_opt->short_margin_vault->hash.ToString());
                    utxo.pushKV("vout", forward_opt->short_margin_vault->n);
                    utxo.pushKV("amount", ValueFromAmount(forward_opt->short_margin_value));
                    utxo.pushKV("role", "short_vault");
                    utxos.push_back(std::move(utxo));
                }

                // Add escrow output if self-delivery happened
                if (forward_opt->self_delivery_txid && !forward_opt->escrow_claim_txid && !forward_opt->escrow_refund_txid) {
                    LOCK(pwallet->cs_wallet);
                    const CWalletTx* wtx = pwallet->GetWalletTx(Txid::FromUint256(*forward_opt->self_delivery_txid));
                    if (wtx) {
                        CTransactionRef tx = wtx->tx;
                        // Self-delivery creates escrow output(s) - scan for them
                        // Output 0 is typically the escrow for the non-delivering party
                        if (tx->vout.size() > 0) {
                            UniValue escrow_utxo(UniValue::VOBJ);
                            escrow_utxo.pushKV("txid", forward_opt->self_delivery_txid->ToString());
                            escrow_utxo.pushKV("vout", 0);
                            escrow_utxo.pushKV("amount", ValueFromAmount(tx->vout[0].nValue));
                            escrow_utxo.pushKV("role", "escrow");
                            utxos.push_back(std::move(escrow_utxo));
                        }
                    }
                }

                result.pushKV("utxos", utxos);

                int confs = tip_height - forward_opt->created_height + 1;
                result.pushKV("confs", std::max(0, confs));

                return result;
            }

            if (auto diff_opt = pwallet->FindDifficultyContract(*id)) {
                // Contract-type discriminator under "type" (AppendDifficultyFields adds "kind"=cfd/option,
                // so the two never collide); forward status uses "kind"=forward, but the payload is
                // skip_type_check'd and each consumer switches on its own type.
                UniValue result(UniValue::VOBJ);
                result.pushKV("id", id->GetHex());
                result.pushKV("type", "difficulty");
                {
                    LOCK(pwallet->cs_wallet);
                    result.pushKV("role", DifficultyRole(*diff_opt, *pwallet));
                    result.pushKV("state", DifficultyStatus(*pwallet, *diff_opt));
                    AppendDifficultyFields(*pwallet, *diff_opt, result);
                }
                return result;
            }

            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown contract id");
        }
    );
}

RPCHelpMan contract_list()
{
    return RPCHelpMan(
        "contract.list",
        "List all contracts in the wallet registry (repo, spot, forward, difficulty, scalarcfd).",
        {
            {"filter", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional filters",
                {
                    {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter by contract type: 'repo', 'spot', 'forward', 'difficulty', 'scalarcfd'"},
                    {"state", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter by state: 'proposed', 'accepted', 'opened', 'repaid', 'defaulted', 'closed'; difficulty and scalarcfd also emit 'partially_settled' and 'settled'"},
                    {"role", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter by role: 'lender', 'borrower', 'alice', 'bob', 'long', 'short', 'writer', 'buyer'"},
                }
            }
        },
        RPCResult{
            RPCResult::Type::ARR, "", "Array of contract summaries", {
                // Each contract type (repo/spot/forward/difficulty/scalarcfd) adds its own type-specific fields
                // on top of the common ones below, so the per-entry object is intentionally not strictly typed.
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "id", "Contract identifier"},
                        {RPCResult::Type::STR, "type", "Contract type (repo, spot, forward, difficulty, scalarcfd)"},
                        {RPCResult::Type::STR, "role", "User role in this contract"},
                        {RPCResult::Type::STR, "status", "Contract status"},
                        {RPCResult::Type::NUM, "maturity_height", /*optional=*/true, "Maturity block height (repo/forward)"},
                        {RPCResult::Type::STR_AMOUNT, "principal_amount", /*optional=*/true, "Principal amount (repo)"},
                        {RPCResult::Type::STR_AMOUNT, "collateral_amount", /*optional=*/true, "Collateral amount (repo)"},
                        {RPCResult::Type::NUM, "created_height", "Block height when contract was created"},
                    }, /*skip_type_check=*/true
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("contract.list", "") +
            "\n" + HelpExampleCli("contract.list", "{\\\"type\\\":\\\"repo\\\",\\\"status\\\":\\\"opened\\\"}") +
            "\n" + HelpExampleRpc("contract.list", "{\\\"type\\\":\\\"repo\\\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            // Parse filters
            std::optional<std::string> filter_type;
            std::optional<std::string> filter_state;
            std::optional<std::string> filter_role;

            if (request.params.size() > 0 && !request.params[0].isNull()) {
                const UniValue& filter_obj = request.params[0].get_obj();
                if (filter_obj.exists("type")) {
                    filter_type = filter_obj["type"].get_str();
                }
                if (filter_obj.exists("state")) {
                    filter_state = filter_obj["state"].get_str();
                }
                if (filter_obj.exists("role")) {
                    filter_role = filter_obj["role"].get_str();
                }
            }

            UniValue results(UniValue::VARR);

            LOCK(pwallet->cs_wallet);

            // List all repo contracts
            if (!filter_type || *filter_type == "repo") {
                for (const auto& repo : pwallet->ListRepoOffers()) {
                    // Use DerivedState() method to determine state
                    RepoContractState state_enum = repo.DerivedState(pwallet.get());
                    std::string state;
                    switch (state_enum) {
                        case RepoContractState::PROPOSED:
                            state = "proposed";
                            break;
                        case RepoContractState::ACCEPTED:
                            state = "accepted";
                            break;
                        case RepoContractState::OPENED:
                            state = "opened";
                            break;
                        case RepoContractState::REPAID:
                            state = "repaid";
                            break;
                        case RepoContractState::DEFAULTED:
                            state = "defaulted";
                            break;
                        default:
                            state = "unknown";
                    }

                    // Apply state filter
                    if (filter_state && *filter_state != state) {
                        continue;
                    }

                    // Determine role based on maker_role and whether this wallet created the offer
                    // local_fs_tx_adaptor_secret is a marker for "I am the maker" (offer creator)
                    const bool i_am_maker = repo.local_fs_tx_adaptor_secret.has_value();
                    std::string role;
                    if (repo.maker_role == "lender") {
                        role = i_am_maker ? std::string("lender") : std::string("borrower");
                    } else if (repo.maker_role == "borrower") {
                        role = i_am_maker ? std::string("borrower") : std::string("lender");
                    } else {
                        // Legacy records lack maker_role. Don't guess from i_am_maker
                        // alone (the old heuristic flipped borrower-makers to "lender"
                        // after restart). Use address ownership as the authoritative
                        // source: the wallet that owns borrower_dest is the borrower.
                        const CScript borrower_spk = GetScriptForDestination(repo.borrower_dest);
                        const CScript lender_spk = GetScriptForDestination(repo.lender_dest);
                        const isminetype borrower_mine = pwallet->IsMine(borrower_spk);
                        const isminetype lender_mine = pwallet->IsMine(lender_spk);
                        if (borrower_mine != ISMINE_NO && lender_mine == ISMINE_NO) {
                            role = "borrower";
                        } else if (lender_mine != ISMINE_NO && borrower_mine == ISMINE_NO) {
                            role = "lender";
                        } else {
                            // Last-resort fallback (both or neither are mine — e.g. watch-only).
                            role = i_am_maker ? std::string("lender") : std::string("borrower");
                        }
                    }

                    // Apply role filter
                    if (filter_role && *filter_role != role) {
                        continue;
                    }

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("id", repo.offer_id.GetHex());
                    entry.pushKV("type", "repo");
                    entry.pushKV("role", role);
                    entry.pushKV("status", state);
                    entry.pushKV("maturity_height", repo.terms.maturity_height);

                    // Convert amounts from units (using correct decimals for each asset)
                    if (repo.terms.collateral_leg.is_native) {
                        entry.pushKV("collateral_amount", ValueFromAmount(repo.terms.collateral_leg.units));
                        entry.pushKV("collateral_asset", "TSC");
                    } else {
                        int decimals = GetAssetDecimals(pwallet.get(), repo.terms.collateral_leg.asset_id);
                        double amount = static_cast<double>(repo.terms.collateral_leg.units) / std::pow(10.0, decimals);
                        entry.pushKV("collateral_amount", amount);
                        entry.pushKV("collateral_asset", repo.terms.collateral_leg.asset_id.GetHex());
                    }

                    if (repo.terms.principal_leg.is_native) {
                        entry.pushKV("principal_amount", ValueFromAmount(repo.terms.principal_leg.units));
                        entry.pushKV("principal_asset", "TSC");
                    } else {
                        int decimals = GetAssetDecimals(pwallet.get(), repo.terms.principal_leg.asset_id);
                        double amount = static_cast<double>(repo.terms.principal_leg.units) / std::pow(10.0, decimals);
                        entry.pushKV("principal_amount", amount);
                        entry.pushKV("principal_asset", repo.terms.principal_leg.asset_id.GetHex());
                    }

                    // Interest amount and asset
                    if (repo.terms.interest_leg.is_native) {
                        entry.pushKV("interest_amount", ValueFromAmount(repo.terms.interest_leg.units));
                        entry.pushKV("interest_asset", "TSC");
                    } else {
                        int decimals = GetAssetDecimals(pwallet.get(), repo.terms.interest_leg.asset_id);
                        double amount = static_cast<double>(repo.terms.interest_leg.units) / std::pow(10.0, decimals);
                        entry.pushKV("interest_amount", amount);
                        entry.pushKV("interest_asset", repo.terms.interest_leg.asset_id.GetHex());
                    }

                    // LTV (loan-to-value) = principal / collateral
                    double ltv = 0.0;
                    if (repo.terms.collateral_leg.units > 0) {
                        ltv = (static_cast<double>(repo.terms.principal_leg.units) / static_cast<double>(repo.terms.collateral_leg.units)) * 100.0;
                    }
                    entry.pushKV("ltv", ltv);

                    entry.pushKV("created_height", repo.created_height);

                    results.push_back(entry);
                }
            }

            // List all spot contracts
            if (!filter_type || *filter_type == "spot") {
                for (const auto& spot : pwallet->ListSpotOffers()) {
                    // Do not surface unaccepted spot offers in the contract book.
                    // Makers still persist their own offers for recovery, but only
                    // accepted/executed swaps appear in contract.list.
                    if (!spot.acceptance.has_value()) {
                        continue;
                    }

                    std::string state = "accepted";
                    // Check if transaction is confirmed on-chain
                    if (spot.settle_txid.has_value()) {
                        const CWalletTx* wtx = pwallet->GetWalletTx(Txid::FromUint256(*spot.settle_txid));
                        if (wtx && wtx->isConfirmed()) {
                            state = "executed";
                        }
                    }

                    if (filter_state && *filter_state != state) {
                        continue;
                    }

                    // Determine role: alice (offer creator) or bob (counterparty)
                    std::string role = spot.local_fs_tx_adaptor_secret.has_value() ? "alice" : "bob";
                    if (filter_role && *filter_role != role) {
                        continue;
                    }

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("id", spot.offer_id.GetHex());
                    entry.pushKV("type", "spot");
                    entry.pushKV("role", role);
                    entry.pushKV("status", state);
                    entry.pushKV("created_height", spot.created_height);

                    // Add SPOT-specific swap details (alice_leg and bob_leg)
                    // Alice deliver amount and asset
                    double alice_display_amount = 0.0;
                    if (spot.terms.alice_deliver.is_native) {
                        alice_display_amount = ValueFromAmount(spot.terms.alice_deliver.units).get_real();
                        entry.pushKV("alice_deliver_amount", ValueFromAmount(spot.terms.alice_deliver.units));
                        entry.pushKV("alice_deliver_asset", "TSC");
                    } else {
                        // Use stored decimals if available, fall back to GetAssetDecimals
                        int decimals = spot.terms.alice_deliver.decimals.value_or(
                            GetAssetDecimals(pwallet.get(), spot.terms.alice_deliver.asset_id)
                        );
                        alice_display_amount = static_cast<double>(spot.terms.alice_deliver.units) / std::pow(10.0, decimals);
                        entry.pushKV("alice_deliver_amount", alice_display_amount);
                        entry.pushKV("alice_deliver_asset", spot.terms.alice_deliver.asset_id.GetHex());
                    }

                    // Bob deliver amount and asset
                    double bob_display_amount = 0.0;
                    if (spot.terms.bob_deliver.is_native) {
                        bob_display_amount = ValueFromAmount(spot.terms.bob_deliver.units).get_real();
                        entry.pushKV("bob_deliver_amount", ValueFromAmount(spot.terms.bob_deliver.units));
                        entry.pushKV("bob_deliver_asset", "TSC");
                    } else {
                        // Use stored decimals if available, fall back to GetAssetDecimals
                        int decimals = spot.terms.bob_deliver.decimals.value_or(
                            GetAssetDecimals(pwallet.get(), spot.terms.bob_deliver.asset_id)
                        );
                        bob_display_amount = static_cast<double>(spot.terms.bob_deliver.units) / std::pow(10.0, decimals);
                        entry.pushKV("bob_deliver_amount", bob_display_amount);
                        entry.pushKV("bob_deliver_asset", spot.terms.bob_deliver.asset_id.GetHex());
                    }

                    // Calculate exchange rate using DISPLAY amounts, not raw units
                    double exchange_rate = 0.0;
                    if (alice_display_amount > 0) {
                        exchange_rate = bob_display_amount / alice_display_amount;
                    }
                    entry.pushKV("exchange_rate", exchange_rate);

                    results.push_back(entry);
                }
            }

            // List all forward contracts
            if (!filter_type || *filter_type == "forward") {
                for (const auto& forward : pwallet->ListForwardContracts()) {
                    std::string state = "proposed";
                    if (forward.acceptance_commitment_hex.has_value()) {
                        state = "accepted";
                    }
                    if (forward.open_txid.has_value() && forward.open_height.has_value()) {
                        // CRITICAL: Require BOTH open_txid AND open_height (confirmation)
                        state = "opened";
                    }
                    if (forward.coop_close_txid.has_value()) {
                        state = "closed";
                    } else if (forward.self_delivery_txid.has_value()) {
                        if (forward.escrow_claim_txid.has_value() || forward.escrow_refund_txid.has_value()) {
                            state = "closed";
                        } else {
                            state = "delivery_pending";
                        }
                    } else if (forward.timeout_txid.has_value()) {
                        state = "defaulted";
                    }

                    if (filter_state && *filter_state != state) {
                        continue;
                    }

                    // Determine role from local_side: LONG or SHORT
                    std::string role = (forward.local_side == ForwardSide::LONG) ? "long" : "short";
                    if (filter_role && *filter_role != role) {
                        continue;
                    }

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("id", forward.contract_id.GetHex());
                    entry.pushKV("type", "forward");
                    entry.pushKV("role", role);
                    entry.pushKV("status", state);
                    entry.pushKV("maturity_height", forward.terms.deadline_long);
                    entry.pushKV("created_height", forward.created_height);

                    // Add delivery leg details
                    entry.pushKV("long_deliver_amount", ValueFromAmount(forward.terms.long_party.deliver_leg.units));
                    entry.pushKV("long_deliver_asset", forward.terms.long_party.deliver_leg.is_native ? "TSC" : forward.terms.long_party.deliver_leg.asset_id.GetHex());
                    entry.pushKV("short_deliver_amount", ValueFromAmount(forward.terms.short_party.deliver_leg.units));
                    entry.pushKV("short_deliver_asset", forward.terms.short_party.deliver_leg.is_native ? "TSC" : forward.terms.short_party.deliver_leg.asset_id.GetHex());

                    // Add initial margin details
                    entry.pushKV("long_margin_amount", ValueFromAmount(forward.terms.long_party.margin_leg.units));
                    entry.pushKV("long_margin_asset", forward.terms.long_party.margin_leg.is_native ? "TSC" : forward.terms.long_party.margin_leg.asset_id.GetHex());
                    entry.pushKV("short_margin_amount", ValueFromAmount(forward.terms.short_party.margin_leg.units));
                    entry.pushKV("short_margin_asset", forward.terms.short_party.margin_leg.is_native ? "TSC" : forward.terms.short_party.margin_leg.asset_id.GetHex());

                    // Calculate IM percentages based on delivery notionals
                    // NOTE: Percentage is only meaningful when IM asset matches delivery asset
                    // When assets differ, we'd need price conversion which isn't available in contract terms
                    double long_im_percent = 0.0;
                    double short_im_percent = 0.0;

                    // Long party IM %
                    bool long_assets_match = (forward.terms.long_party.margin_leg.is_native == forward.terms.long_party.deliver_leg.is_native) &&
                                            (forward.terms.long_party.margin_leg.is_native ||
                                             forward.terms.long_party.margin_leg.asset_id == forward.terms.long_party.deliver_leg.asset_id);
                    if (long_assets_match) {
                        double long_notional = ValueFromAmount(forward.terms.long_party.deliver_leg.units).get_real();
                        double long_im_amount = ValueFromAmount(forward.terms.long_party.margin_leg.units).get_real();
                        long_im_percent = (long_notional > 0) ? (long_im_amount / long_notional * 100.0) : 0.0;
                    }

                    // Short party IM %
                    bool short_assets_match = (forward.terms.short_party.margin_leg.is_native == forward.terms.short_party.deliver_leg.is_native) &&
                                             (forward.terms.short_party.margin_leg.is_native ||
                                              forward.terms.short_party.margin_leg.asset_id == forward.terms.short_party.deliver_leg.asset_id);
                    if (short_assets_match) {
                        double short_notional = ValueFromAmount(forward.terms.short_party.deliver_leg.units).get_real();
                        double short_im_amount = ValueFromAmount(forward.terms.short_party.margin_leg.units).get_real();
                        short_im_percent = (short_notional > 0) ? (short_im_amount / short_notional * 100.0) : 0.0;
                    }

                    entry.pushKV("long_im_percent", long_im_percent);
                    entry.pushKV("short_im_percent", short_im_percent);

                    // Add premium details (if applicable)
                    if (forward.terms.premium_leg.units > 0) {
                        entry.pushKV("premium_amount", ValueFromAmount(forward.terms.premium_leg.units));
                        entry.pushKV("premium_asset", forward.terms.premium_leg.is_native ? "TSC" : forward.terms.premium_leg.asset_id.GetHex());
                    } else {
                        entry.pushKV("premium_amount", 0.0);
                        entry.pushKV("premium_asset", "");
                    }

                    // Add deadline details
                    entry.pushKV("deadline_short", forward.terms.deadline_short);
                    entry.pushKV("deadline_long", forward.terms.deadline_long);

                    results.push_back(entry);
                }
            }

            // List all difficulty-derivative contracts (CFD + option)
            if (!filter_type || *filter_type == "difficulty") {
                for (const auto& diff : pwallet->ListDifficultyContracts()) {
                    const std::string status = DifficultyStatus(*pwallet, diff);
                    if (filter_state && *filter_state != status) {
                        continue;
                    }
                    const std::string role = DifficultyRole(diff, *pwallet);
                    if (filter_role && *filter_role != role) {
                        continue;
                    }

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("id", diff.contract_id.GetHex());
                    entry.pushKV("type", "difficulty");
                    entry.pushKV("role", role);
                    entry.pushKV("status", status);
                    entry.pushKV("created_height", 0); // difficulty records do not track a creation height
                    AppendDifficultyFields(*pwallet, diff, entry);
                    results.push_back(entry);
                }
            }

            // List all scalar-feed bilateral CFDs (the difficulty sibling; direct bilateral, no order book)
            if (!filter_type || *filter_type == "scalarcfd") {
                for (const auto& scfd : pwallet->ListScalarCfdContracts()) {
                    const std::string status = ScalarCfdStatus(*pwallet, scfd);
                    if (filter_state && *filter_state != status) {
                        continue;
                    }
                    const std::string role = ScalarCfdRole(scfd, *pwallet);
                    if (filter_role && *filter_role != role) {
                        continue;
                    }

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("id", scfd.contract_id.GetHex());
                    entry.pushKV("type", "scalarcfd");
                    entry.pushKV("role", role);
                    entry.pushKV("status", status);
                    entry.pushKV("created_height", 0); // scalar-feed records do not track a creation height
                    AppendScalarCfdFields(*pwallet, scfd, entry);
                    results.push_back(entry);
                }
            }

            return results;
        }
    );
}

RPCHelpMan spot_propose()
{
    return RPCHelpMan(
        "spot.propose",
        "Create a spot swap offer and store it in the wallet registry.",
        std::vector<RPCArg>{
            {"params", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Spot swap parameters",
                {
                    {"terms", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Spot swap legs", std::vector<RPCArg>{}},
                    {"alice_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Alice receive address (bech32m)"},
                    {"bob_address_hint", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional Bob receive address hint (bech32m)"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ_DYN, "offer", "Offer payload to share with counterparty", {{RPCResult::Type::ELISION, "", ""}}},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli(
                "spot.propose",
                "{\\\"terms\\\":{\\\"alice_leg\\\":{\\\"is_native\\\":true,\\\"units\\\":100000000},"
                "\\\"bob_leg\\\":{\\\"asset_id\\\":\\\"" + std::string(64, 'a') + "\\\",\\\"units\\\":50000000}},"
                "\\\"alice_address\\\":\\\"bcrt1alice...\\\",\\\"bob_address_hint\\\":\\\"bcrt1bob...\\\"}"
            )
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& params = request.params[0].get_obj();
            const UniValue& terms_val = params.find_value("terms");
            if (!terms_val.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "params.terms must be an object");
            }
            SpotTerms terms = ParseSpotTerms(terms_val.get_obj());

            const CTxDestination alice_dest = ParseDestinationRequired(params, "alice_address");
            if (!ExtractTaprootKey(alice_dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "alice_address must be a Taproot bech32m address");
            }
            const CScript alice_script = GetScriptForDestination(alice_dest);
            const isminetype alice_mine = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(alice_script));
            if (!(alice_mine & ISMINE_SPENDABLE)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "alice_address must belong to this wallet");
            }

            ValidateSpotLegBalance(*pwallet, terms.alice_deliver, "propose spot swap");

            std::optional<CTxDestination> bob_hint;
            const UniValue& bob_addr_val = params.find_value("bob_address_hint");
            if (!bob_addr_val.isNull()) {
                CTxDestination bob_dest = DecodeDestination(bob_addr_val.get_str());
                if (!IsValidDestination(bob_dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid bob_address_hint");
                }
                if (!wallet::ExtractTaprootKey(bob_dest)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "bob_address_hint must be a Taproot bech32m address");
                }
                bob_hint = bob_dest;
            }

            auto [adaptor_secret, adaptor_point] = wallet::GenerateFairSignAdaptor();

            wallet::SpotOfferRecord record;
            record.offer_id = GetRandHash();
            record.terms = terms;
            record.fs_policy = wallet::FairSignPolicy{};
            record.fs_tx_adaptor_point = adaptor_point;
            record.local_fs_tx_adaptor_secret = adaptor_secret;
            record.alice_recv_dest = alice_dest;
            record.bob_recv_dest_hint = bob_hint;
            record.salt = GetRandHash();
            record.created_time = GetTime();
            {
                LOCK(pwallet->cs_wallet);
                record.created_height = pwallet->GetLastBlockHeight();
            }
            record.commitment_hex = wallet::SpotOfferCommitmentHex(record);

            // ALWAYS persist maker's own offers (they have local_fs_tx_adaptor_secret)
            // so they can later import the taker's acceptance
            wallet::SpotOfferRecord stored = pwallet->RegisterSpotOffer(std::move(record));

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", stored.offer_id.GetHex());
            result.pushKV("offer", wallet::SpotOfferToJSON(stored));
            return result;
        }
    );
}

RPCHelpMan spot_import_offer()
{
    return RPCHelpMan(
        "spot.import_offer",
        "Import a spot swap offer JSON payload into the wallet registry.",
        std::vector<RPCArg>{
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Offer payload", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ_DYN, "offer", "Wallet-normalised offer payload",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.import_offer", "{...}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            int fallback_height;
            int64_t fallback_time;
            {
                LOCK(pwallet->cs_wallet);
                fallback_height = pwallet->GetLastBlockHeight();
            }
            fallback_time = GetTime();

            wallet::SpotOfferRecord record = ParseSpotOfferObject(request.params[0].get_obj(), fallback_height, fallback_time);
            wallet::SpotOfferRecord stored = pwallet->RegisterSpotOffer(std::move(record));

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", stored.offer_id.GetHex());
            result.pushKV("offer", wallet::SpotOfferToJSON(stored));
            return result;
        }
    );
}

RPCHelpMan spot_export_offer()
{
    return RPCHelpMan(
        "spot.export_offer",
        "Return the canonical offer JSON for a stored spot offer.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ_DYN, "offer", "Canonical spot offer payload",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.export_offer", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindSpotOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown spot offer id");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer", wallet::SpotOfferToJSON(*record_opt));
            return result;
        }
    );
}

RPCHelpMan spot_share_offer()
{
    return RPCHelpMan(
        "spot.share_offer",
        "Export a spot swap offer and create a cosign session for secure sharing with counterparty.\n"
        "This is a convenience wrapper that combines spot.export_offer with cosign.init.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
            {"context", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Human-readable context label (default: \"spot-swap\")"},
            {"transport", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Transport: auto|websocket|nostr (default: auto)"},
            {"ttl", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Session TTL in seconds (default: 1800)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Spot offer identifier"},
                {RPCResult::Type::OBJ, "offer", "Exported spot offer payload", SpotOfferResultDescription()},
                {RPCResult::Type::OBJ, "cosign", "Cosign session details",
                    {
                        {RPCResult::Type::STR, "session_id", "Cosign session identifier"},
                        {RPCResult::Type::STR, "invite_link", "Invite link for counterparty"},
                        {RPCResult::Type::STR, "sas", "Short Authentication String"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.share_offer", std::string(64, 'a'))
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id hex");
            }

            // Get spot offer from wallet
            LOCK(pwallet->cs_wallet);
            auto record_opt = pwallet->FindSpotOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown spot offer id");
            }

            // Build offer export
            UniValue offer_data(UniValue::VOBJ);
            offer_data.pushKV("offer_id", record_opt->offer_id.GetHex());
            offer_data.pushKV("offer", wallet::SpotOfferToJSON(*record_opt));

            // Prepare cosign.init parameters (positional: psbt, context, transport, ttl)
            UniValue cosign_params(UniValue::VARR);
            cosign_params.push_back("");  // empty psbt
            cosign_params.push_back(request.params[1].isNull() ? "spot-swap" : request.params[1].get_str());  // context
            cosign_params.push_back(request.params[2].isNull() ? "auto" : request.params[2].get_str());  // transport
            cosign_params.push_back(request.params[3].isNull() ? 1800 : request.params[3].getInt<int>());  // ttl

            // Call cosign.init
            JSONRPCRequest cosign_req;
            cosign_req.context = request.context;
            cosign_req.strMethod = "cosign.init";
            cosign_req.params = cosign_params;

            UniValue cosign_result = tableRPC.execute(cosign_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", offer_data["offer_id"]);
            result.pushKV("offer", offer_data["offer"]);
            result.pushKV("cosign", cosign_result);

            return result;
        }
    );
}

RPCHelpMan spot_collect_acceptance()
{
    return RPCHelpMan(
        "spot.collect_acceptance",
        "Join a cosign session via invite link and collect acceptance data from counterparty.\n"
        "This is a convenience wrapper that combines cosign.join with cosign.recv and spot.import_acceptance.",
        std::vector<RPCArg>{
            {"offer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
            {"invite_link", RPCArg::Type::STR, RPCArg::Optional::NO, "Cosign invite link (cosign:?r=...)"},
            {"timeout_ms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Timeout for receiving acceptance (default: 30000ms)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", "Acceptance identifier"},
                {RPCResult::Type::OBJ, "acceptance", "Imported acceptance payload", SpotAcceptanceResultDescription()},
                {RPCResult::Type::OBJ, "cosign", "Cosign session details",
                    {
                        {RPCResult::Type::STR, "session_id", "Cosign session identifier"},
                        {RPCResult::Type::STR, "peer_sas", "Peer Short Authentication String"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.collect_acceptance", std::string(64, 'a') + " \"cosign:?r=abc123&t=websocket#c=alpha-bravo-charlie\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            // Validate offer_id
            const std::string offer_id_hex = request.params[0].get_str();
            if (!IsHex(offer_id_hex) || offer_id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "offer_id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(offer_id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer_id hex");
            }

            const std::string invite_link = request.params[1].get_str();
            const int timeout_ms = request.params[2].isNull() ? 30000 : request.params[2].getInt<int>();

            // Join cosign session
            JSONRPCRequest join_req;
            join_req.context = request.context;
            join_req.strMethod = "cosign.join";
            UniValue join_params(UniValue::VARR);
            join_params.push_back(invite_link);
            join_req.params = join_params;

            UniValue join_result = tableRPC.execute(join_req);
            const std::string session_id = join_result["session_id"].get_str();
            const std::string peer_sas = join_result["peer_sas"].get_str();

            // Complete SPAKE2/Noise handshake (SECURITY: Phase 4 requirement)
            // This establishes encrypted channel before any send/recv operations
            JSONRPCRequest handshake_req;
            handshake_req.context = request.context;
            handshake_req.strMethod = "cosign.handshake_auto";
            UniValue handshake_params(UniValue::VARR);
            handshake_params.push_back(session_id);
            handshake_params.push_back(false);  // responder (joined session)
            handshake_req.params = handshake_params;

            UniValue handshake_result = tableRPC.execute(handshake_req);
            if (!handshake_result.exists("handshake_complete") || !handshake_result["handshake_complete"].isBool() || !handshake_result["handshake_complete"].get_bool()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Handshake failed: encrypted channel not established");
            }

            // Receive acceptance data
            JSONRPCRequest recv_req;
            recv_req.context = request.context;
            recv_req.strMethod = "cosign.recv";
            UniValue recv_params(UniValue::VARR);
            recv_params.push_back(session_id);
            recv_params.push_back(timeout_ms);
            recv_req.params = recv_params;

            UniValue recv_result = tableRPC.execute(recv_req);

            // Extract acceptance payload
            if (!recv_result["payload"].isObject() || !recv_result["payload"]["acceptance"].isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected acceptance object in received payload");
            }

            UniValue acceptance_data = recv_result["payload"]["acceptance"];

            // Import acceptance
            JSONRPCRequest import_req;
            import_req.context = request.context;
            import_req.strMethod = "spot.import_acceptance";
            UniValue import_params(UniValue::VARR);
            import_params.push_back(offer_id->GetHex());
            import_params.push_back(acceptance_data);
            import_req.params = import_params;

            UniValue import_result = tableRPC.execute(import_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", import_result["accept_id"]);
            result.pushKV("acceptance", import_result["acceptance"]);

            UniValue cosign_info(UniValue::VOBJ);
            cosign_info.pushKV("session_id", session_id);
            cosign_info.pushKV("peer_sas", peer_sas);
            cosign_info.pushKV("messages_received", recv_result["seq"]);
            result.pushKV("cosign", cosign_info);

            return result;
        }
    );
}

RPCHelpMan spot_sign_over_channel()
{
    return RPCHelpMan(
        "spot.sign_over_channel",
        "Coordinate Fair-Sign ceremony over an active cosign session.\n"
        "Sends nonce commitments, exchanges partial signatures, and completes the signing process.",
        std::vector<RPCArg>{
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Active cosign session identifier"},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Partially Signed Bitcoin Transaction (base64)"},
            {"is_initiator", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this party initiates the ceremony (default: true)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Completed PSBT with all signatures (base64)"},
                {RPCResult::Type::OBJ, "ceremony_stats", "Ceremony statistics",
                    {
                        {RPCResult::Type::NUM, "messages_sent", "Number of messages sent"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                        {RPCResult::Type::NUM, "duration_ms", "Ceremony duration in milliseconds"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.sign_over_channel", "\"69d967c0e415c9a3\" \"cHNidP8BA...\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string session_id = request.params[0].get_str();
            const std::string psbt_str = request.params[1].get_str();
            const bool is_initiator = request.params[2].isNull() ? true : request.params[2].get_bool();

            // SECURITY: Ensure handshake is complete before ceremony (Phase 4 requirement)
            // NOTE: This is defensive - aggregators should call handshake_auto before this,
            // but we verify here in case session_id was obtained elsewhere
            JSONRPCRequest handshake_req;
            handshake_req.context = request.context;
            handshake_req.strMethod = "cosign.handshake_auto";
            UniValue handshake_params(UniValue::VARR);
            handshake_params.push_back(session_id);
            handshake_params.push_back(is_initiator);
            handshake_req.params = handshake_params;

            UniValue handshake_result = tableRPC.execute(handshake_req);
            if (!handshake_result.exists("handshake_complete") || !handshake_result["handshake_complete"].isBool() || !handshake_result["handshake_complete"].get_bool()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Handshake failed: encrypted channel not established before ceremony");
            }

            auto start_time = std::chrono::steady_clock::now();
            int messages_sent = 0;
            int messages_received = 0;

            // Prepare adaptor ceremony
            JSONRPCRequest prepare_req;
            prepare_req.context = request.context;
            UniValue prepare_params(UniValue::VARR);
            prepare_params.push_back(psbt_str);
            prepare_req.params = prepare_params;
            prepare_req.strMethod = "adaptor.prepare";

            UniValue prepare_result = tableRPC.execute(prepare_req);
            const std::string prepared_psbt = prepare_result["psbt"].get_str();

            UniValue commitments(UniValue::VARR);
            if (prepare_result["commitments"].isArray()) {
                commitments = prepare_result["commitments"];
            }

            // Exchange nonce commitments
            if (is_initiator) {
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "nonce_commitments");
                payload.pushKV("commitments", commitments);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;

                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;
            } else {
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;

                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "nonce_commitments");
                payload.pushKV("commitments", commitments);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;
            }

            // Create partial signatures
            JSONRPCRequest partial_req;
            partial_req.context = request.context;
            partial_req.strMethod = "adaptor.partial";
            UniValue partial_params(UniValue::VARR);
            partial_params.push_back(prepared_psbt);
            partial_req.params = partial_params;

            UniValue partial_result = tableRPC.execute(partial_req);
            const std::string partial_psbt = partial_result["psbt"].get_str();

            // Exchange partial signatures
            if (is_initiator) {
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "partial_psbt");
                payload.pushKV("psbt", partial_psbt);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;

                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;
            } else {
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;

                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "partial_psbt");
                payload.pushKV("psbt", partial_psbt);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;
            }

            // Complete ceremony
            JSONRPCRequest complete_req;
            complete_req.context = request.context;
            complete_req.strMethod = "adaptor.complete";
            UniValue complete_params(UniValue::VARR);
            complete_params.push_back(partial_psbt);
            complete_params.push_back(commitments);
            complete_req.params = complete_params;

            UniValue complete_result = tableRPC.execute(complete_req);

            auto end_time = std::chrono::steady_clock::now();
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", complete_result["psbt"]);

            UniValue stats(UniValue::VOBJ);
            stats.pushKV("messages_sent", messages_sent);
            stats.pushKV("messages_received", messages_received);
            stats.pushKV("duration_ms", duration_ms);
            result.pushKV("ceremony_stats", stats);

            return result;
        }
    );
}

RPCHelpMan spot_list_offers()
{
    return RPCHelpMan(
        "spot.list_offers",
        "List all spot swap offers known to the wallet.",
        std::vector<RPCArg>{},
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "", SpotOfferResultDescription()},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.list_offers", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            UniValue arr(UniValue::VARR);
            for (const auto& record : pwallet->ListSpotOffers()) {
                arr.push_back(wallet::SpotOfferToJSON(record));
            }
            return arr;
        }
    );
}

RPCHelpMan spot_accept()
{
    return RPCHelpMan(
        "spot.accept",
        "Record acceptance for a spot offer and return the canonical acceptance payload.\n"
        "IMPORTANT: Review trade terms carefully before accepting. Use 'confirmed' parameter to proceed.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Acceptance options",
                {
                    {"bob_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Bob receive address (bech32m)"},
                    {"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be true after reviewing terms to accept"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", /*optional=*/true, "Acceptance identifier (only if confirmed=true)"},
                {RPCResult::Type::OBJ_DYN, "acceptance", /*optional=*/true, "Canonical acceptance payload (only if confirmed=true)",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
                {RPCResult::Type::OBJ, "terms", /*optional=*/true, "Trade terms for review (if confirmed is missing/false)"},
                {RPCResult::Type::STR, "action_required", /*optional=*/true, "Instructions for user (if confirmed is missing/false)"},
                {RPCResult::Type::STR, "warning", /*optional=*/true, "Warning message (if confirmed is missing/false)"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.accept", "\"offer_id\"") + " (shows terms for review)\n" +
            HelpExampleCli("spot.accept", "\"offer_id\" '{\"confirmed\": true}'") + " (accepts after review)"
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto stored_opt = pwallet->FindSpotOffer(*offer_id);
            if (!stored_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown spot offer id");
            }
            wallet::SpotOfferRecord stored = *stored_opt;

            if (stored.acceptance) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Offer already accepted");
            }

            // Check if user has confirmed after reviewing terms
            bool confirmed = false;
            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& opts = request.params[1].get_obj();
                const UniValue& confirmed_val = opts.find_value("confirmed");
                if (!confirmed_val.isNull()) {
                    confirmed = confirmed_val.get_bool();
                }
            }

            // If not confirmed, display terms for review
            if (!confirmed) {
                UniValue terms(UniValue::VOBJ);

                terms.pushKV("contract_type", "SPOT");

                // Determine role
                wallet::SpotRole role = wallet::DetermineSpotRole(stored);
                std::string role_str = "UNKNOWN";
                if (role == wallet::SpotRole::ALICE) role_str = "ALICE (Offerer)";
                else if (role == wallet::SpotRole::BOB) role_str = "BOB (Acceptor)";
                terms.pushKV("your_role", role_str);

                // Trade details
                UniValue trade(UniValue::VOBJ);
                trade.pushKV("you_send_asset", role == wallet::SpotRole::ALICE ?
                    (stored.terms.alice_deliver.is_native ? std::string("BTC") : stored.terms.alice_deliver.asset_id.ToString()) :
                    (stored.terms.bob_deliver.is_native ? std::string("BTC") : stored.terms.bob_deliver.asset_id.ToString()));
                trade.pushKV("you_send_amount", role == wallet::SpotRole::ALICE ?
                    ValueFromAmount(stored.terms.alice_deliver.units) :
                    ValueFromAmount(stored.terms.bob_deliver.units));
                trade.pushKV("you_receive_asset", role == wallet::SpotRole::ALICE ?
                    (stored.terms.bob_deliver.is_native ? std::string("BTC") : stored.terms.bob_deliver.asset_id.ToString()) :
                    (stored.terms.alice_deliver.is_native ? std::string("BTC") : stored.terms.alice_deliver.asset_id.ToString()));
                trade.pushKV("you_receive_amount", role == wallet::SpotRole::ALICE ?
                    ValueFromAmount(stored.terms.bob_deliver.units) :
                    ValueFromAmount(stored.terms.alice_deliver.units));

                // Calculate exchange rate using DISPLAY amounts (respecting decimals)
                double alice_display_amount = 0.0;
                double bob_display_amount = 0.0;

                if (stored.terms.alice_deliver.is_native) {
                    alice_display_amount = ValueFromAmount(stored.terms.alice_deliver.units).get_real();
                } else {
                    int alice_decimals = stored.terms.alice_deliver.decimals.value_or(
                        GetAssetDecimals(pwallet.get(), stored.terms.alice_deliver.asset_id)
                    );
                    alice_display_amount = static_cast<double>(stored.terms.alice_deliver.units) /
                                           std::pow(10.0, alice_decimals);
                }

                if (stored.terms.bob_deliver.is_native) {
                    bob_display_amount = ValueFromAmount(stored.terms.bob_deliver.units).get_real();
                } else {
                    int bob_decimals = stored.terms.bob_deliver.decimals.value_or(
                        GetAssetDecimals(pwallet.get(), stored.terms.bob_deliver.asset_id)
                    );
                    bob_display_amount = static_cast<double>(stored.terms.bob_deliver.units) /
                                         std::pow(10.0, bob_decimals);
                }

                if (alice_display_amount > 0.0 && bob_display_amount > 0.0) {
                    double rate = bob_display_amount / alice_display_amount;
                    trade.pushKV("implied_rate", strprintf("%.8f", rate));
                }
                terms.pushKV("trade_terms", trade);

                // Destinations
                UniValue destinations(UniValue::VOBJ);
                destinations.pushKV("alice_address", EncodeDestination(stored.alice_recv_dest));
                destinations.pushKV("bob_address", stored.bob_recv_dest_hint ?
                    EncodeDestination(*stored.bob_recv_dest_hint) : "(to be provided)");
                terms.pushKV("destinations", destinations);

                // Risks
                UniValue risks(UniValue::VARR);
                risks.push_back("⚠️ Atomic swap is IRREVERSIBLE once executed");
                risks.push_back("⚠️ Ensure you're trading with a trusted counterparty");
                risks.push_back("⚠️ Verify the asset IDs and amounts carefully");
                risks.push_back("⚠️ Network fees apply to all transactions");
                terms.pushKV("risks", risks);

                // Summary
                UniValue summary(UniValue::VOBJ);
                summary.pushKV("action", "You are accepting a spot trade offer");
                summary.pushKV("result", "Assets will be atomically swapped - both parties receive their assets or neither does");
                terms.pushKV("summary", summary);

                UniValue result(UniValue::VOBJ);
                result.pushKV("terms", terms);
                result.pushKV("action_required", "Review terms carefully. To accept, call again with options: {\"confirmed\": true}");
                result.pushKV("warning", "⚠️ This trade is ATOMIC and IRREVERSIBLE. Verify all details before confirming.");
                return result;
            }

            CTxDestination bob_dest;
            bool have_bob_dest = false;
            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& opts = request.params[1].get_obj();
                const UniValue& bob_addr_val = opts.find_value("bob_address");
                if (!bob_addr_val.isNull()) {
                    bob_dest = DecodeDestination(bob_addr_val.get_str());
                    if (!IsValidDestination(bob_dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid bob_address");
                    }
                    have_bob_dest = true;
                }
            }
            if (!have_bob_dest) {
                if (!stored.bob_recv_dest_hint) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Bob receive address must be provided");
                }
                bob_dest = *stored.bob_recv_dest_hint;
                have_bob_dest = true;
            }
            if (!wallet::ExtractTaprootKey(bob_dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "bob_address must be a Taproot bech32m address");
            }
            const CScript bob_script = GetScriptForDestination(bob_dest);
            const isminetype bob_mine = WITH_LOCK(pwallet->cs_wallet, return pwallet->IsMine(bob_script));
            if (!(bob_mine & wallet::ISMINE_SPENDABLE)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "bob_address must belong to this wallet");
            }

            ValidateSpotLegBalance(*pwallet, stored.terms.bob_deliver, "accept spot swap");

            auto [adaptor_secret, adaptor_point] = wallet::GenerateFairSignAdaptor();

            wallet::SpotAcceptanceRecord acceptance;
            acceptance.acceptance_id = GetRandHash();
            acceptance.fs_policy = stored.fs_policy;
            acceptance.fs_tx_adaptor_point = adaptor_point;
            acceptance.local_fs_tx_adaptor_secret = adaptor_secret;
            acceptance.salt = GetRandHash();
            acceptance.bob_recv_dest = bob_dest;
            acceptance.commitment_hex = wallet::SpotAcceptanceCommitmentHex(stored, acceptance);

            wallet::SpotOfferRecord updated;
            try {
                updated = pwallet->RegisterSpotAcceptance(*offer_id, std::move(acceptance));
            } catch (const std::runtime_error& err) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err.what());
            }
            const wallet::SpotAcceptanceRecord& stored_acceptance = *updated.acceptance;

            UniValue acceptance_json = wallet::SpotAcceptanceToJSON(updated, stored_acceptance);

            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", stored_acceptance.acceptance_id.GetHex());
            result.pushKV("acceptance", std::move(acceptance_json));
            return result;
        }
    );
}

RPCHelpMan spot_import_acceptance()
{
    return RPCHelpMan(
        "spot.import_acceptance",
        "Import a spot acceptance JSON payload and attach it to a stored offer.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
            {"acceptance", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Acceptance payload", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "accept_id", "Acceptance identifier"},
                {RPCResult::Type::OBJ_DYN, "acceptance", "Canonical acceptance payload",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.import_acceptance", "\"" + std::string(64, 'a') + "\" {..}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindSpotOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown spot offer id");
            }
            wallet::SpotOfferRecord record = *record_opt;

            wallet::SpotAcceptanceRecord acceptance = ParseSpotAcceptanceObject(record, request.params[1].get_obj());
            acceptance.local_fs_tx_adaptor_secret.reset();

            wallet::SpotOfferRecord updated;
            try {
                updated = pwallet->RegisterSpotAcceptance(*offer_id, std::move(acceptance));
            } catch (const std::runtime_error& err) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err.what());
            }
            const wallet::SpotAcceptanceRecord& stored_acceptance = *updated.acceptance;

            UniValue result(UniValue::VOBJ);
            result.pushKV("accept_id", stored_acceptance.acceptance_id.GetHex());
            result.pushKV("acceptance", wallet::SpotAcceptanceToJSON(updated, stored_acceptance));
            return result;
        }
    );
}

RPCHelpMan spot_build_atomic()
{
    return RPCHelpMan(
        "spot.build_atomic",
        "Construct the atomic swap PSBT for a spot offer.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override fee rate in sat/vB (wallet estimate if omitted)"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT already contains all signatures"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee paid by this wallet"},
                {RPCResult::Type::NUM, "changepos", "Index of the native (BTC) change output, or -1 if none"},
                {RPCResult::Type::STR, "my_role", "Wallet's role in the swap: 'alice', 'bob', or 'observer'"},
                {RPCResult::Type::NUM, "my_output_index", "Index of the output receiving assets to this wallet, or -1 if observer"},
                {RPCResult::Type::NUM, "asset_change_index", "Index of the asset change output, or -1 if none"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.build_atomic", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindSpotOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown spot offer id");
            }
            const wallet::SpotOfferRecord& record = *record_opt;
            if (!record.acceptance) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer must be accepted before building atomic swap");
            }
            const wallet::SpotAcceptanceRecord& acceptance = *record.acceptance;

            UniValue opts = request.params.size() > 1 && request.params[1].isObject() ? request.params[1].get_obj() : UniValue::VNULL;

            // Parse fee_rate override if provided
            std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

            struct SpotOutputSpec {
                CTxOut out;
                wallet::AssetLeg leg;
                CTxDestination dest;
                uint256 tap_match;
                bool is_change{false};
                bool is_my_delivery{false};
            };

            auto build_contract_output = [&](const wallet::AssetLeg& leg,
                                             const CTxDestination& dest,
                                             bool is_my_delivery) -> SpotOutputSpec {
                SpotOutputSpec spec;
                spec.leg = leg;
                spec.dest = dest;
                spec.is_my_delivery = is_my_delivery;
                spec.tap_match = ComputeTapMatch(GetScriptForDestination(dest));
                spec.out.scriptPubKey = GetScriptForDestination(dest);
                if (leg.is_native) {
                    spec.out.nValue = static_cast<CAmount>(leg.units);
                } else {
                    spec.out.nValue = wallet::DEFAULT_SPOT_ASSET_OUTPUT_VALUE;
                    spec.out.vExt = wallet::BuildAssetTagTlv(leg.asset_id, leg.units);
                }
                if (IsDust(spec.out, pwallet->chain().relayDustFee())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Resulting contract output would be below dust threshold");
                }
                return spec;
            };

            wallet::SpotRole role = wallet::DetermineSpotRole(record);
            const bool participant = role != wallet::SpotRole::NONE;
            const wallet::AssetLeg* my_leg = participant ? &wallet::LegForRole(record, role) : nullptr;

            // Check if this is an augmentation (taker path)
            const bool is_augmentation = !opts.isNull() && opts.exists("psbt");

            // AUGMENTATION PATTERN: Each wallet builds ONLY their own leg output
            // - Maker (Alice) path: Build Alice's leg output, fund with Alice's inputs
            // - Taker (Bob) path: Build Bob's leg output, augment Alice's PSBT by adding Bob's inputs & outputs
            // This ensures each wallet can properly handle holder-only assets, ZK proofs, KYC, etc.
            std::vector<SpotOutputSpec> contract_outputs;
            contract_outputs.reserve(2);

            // BOTH maker and augmenter build ONLY their own leg output
            // This is critical for holder-only assets, ZK proofs, KYC, etc.
            // that only the asset-controlling wallet can properly create
            if (role == wallet::SpotRole::ALICE) {
                // Alice builds: Alice's asset to Bob (alice_leg → bob_recv_dest)
                contract_outputs.push_back(build_contract_output(record.terms.alice_deliver,
                                                                acceptance.bob_recv_dest,
                                                                true)); // is_my_delivery
            } else {
                // Bob builds: Bob's asset to Alice (bob_leg → alice_recv_dest)
                contract_outputs.push_back(build_contract_output(record.terms.bob_deliver,
                                                                record.alice_recv_dest,
                                                                true)); // is_my_delivery
            }

            std::sort(contract_outputs.begin(), contract_outputs.end(), [](const SpotOutputSpec& a, const SpotOutputSpec& b) {
                auto a_tuple = std::make_tuple(
                    a.is_change ? 1 : 0,
                    a.leg.is_native ? 0 : 1,
                    a.leg.is_native ? uint256() : a.leg.asset_id,
                    a.leg.units,
                    a.tap_match
                );
                auto b_tuple = std::make_tuple(
                    b.is_change ? 1 : 0,
                    b.leg.is_native ? 0 : 1,
                    b.leg.is_native ? uint256() : b.leg.asset_id,
                    b.leg.units,
                    b.tap_match
                );
                return a_tuple < b_tuple;
            });

            // Count how many commitment proof OP_RETURNs will be needed
            // Only assets with WRAP_REQUIRED policy need commitment proofs
            int commitment_count = 0;

            // Check Alice's asset
            if (!record.terms.alice_deliver.is_native) {
                auto alice_policy_opt = pwallet->chain().getAssetRegistryEntry(record.terms.alice_deliver.asset_id);
                if (alice_policy_opt && (alice_policy_opt->icu_flags & assets::WRAP_REQUIRED)) {
                    commitment_count++;  // Bob receives ICU_KEYWRAP asset, needs commitment
                }
            }

            // Check Bob's asset
            if (!record.terms.bob_deliver.is_native) {
                auto bob_policy_opt = pwallet->chain().getAssetRegistryEntry(record.terms.bob_deliver.asset_id);
                if (bob_policy_opt && (bob_policy_opt->icu_flags & assets::WRAP_REQUIRED)) {
                    commitment_count++;  // Alice receives ICU_KEYWRAP asset, needs commitment
                }
            }

            CMutableTransaction tx_template;
            if (!is_augmentation) {
                // MAKER: Build new transaction with maker's own leg output
                tx_template.version = 2;
                if (!opts.isNull()) {
                    const UniValue& locktime_val = opts.find_value("locktime");
                    if (!locktime_val.isNull()) {
                        int64_t locktime = wallet::ParseSignedInt64(locktime_val, "options.locktime");
                        if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.locktime out of range");
                        }
                        tx_template.nLockTime = static_cast<uint32_t>(locktime);
                    }
                }

                for (const auto& spec : contract_outputs) {
                    tx_template.vout.push_back(spec.out);
                }

                // Add placeholder OP_RETURN outputs for commitment proofs
                // These reserve space in fee calculation; spot.add_commitment_proof will replace them
                // Use zero hash as marker for replacement
                if (commitment_count > 0) {
                    LogPrintf("spot.build_atomic: Adding %d placeholder OP_RETURN(s) for ICU_KEYWRAP commitment proofs\n", commitment_count);
                    for (int i = 0; i < commitment_count; ++i) {
                        CScript placeholder_script;
                        placeholder_script << OP_RETURN << std::vector<unsigned char>(32, 0);
                        CTxOut placeholder_out;
                        placeholder_out.nValue = 0;
                        placeholder_out.scriptPubKey = placeholder_script;
                        tx_template.vout.push_back(placeholder_out);
                    }
                }
            }

            FeePolicySnapshot fee_snapshot;
            if (!opts.isNull()) {
                const UniValue& fee_policy_val = opts.find_value("fee_policy");
                if (fee_policy_val.isObject()) {
                    fee_snapshot = ParseFeePolicy(fee_policy_val.get_obj());
                }
            }

            // Apply fee_rate override if provided (takes precedence over fee_policy)
            if (fee_rate_override) {
                fee_snapshot.target_satvb = static_cast<uint32_t>(*fee_rate_override);
                LogPrintf("spot.build_atomic: FEE_RATE OVERRIDE APPLIED: %u sat/vB (from %.2f)\n", fee_snapshot.target_satvb, *fee_rate_override);
            } else {
                LogPrintf("spot.build_atomic: NO FEE_RATE OVERRIDE - using default target_satvb: %u\n", fee_snapshot.target_satvb);
            }

            bool signal_rbf = fee_snapshot.rbf || pwallet->m_signal_rbf;
            fee_snapshot.rbf = signal_rbf;

            auto annotate_psbt = [&](PartiallySignedTransaction& psbt,
                                     const std::vector<SpotOutputSpec>& specs,
                                     const std::vector<int>& change_indices,
                                     const FeePolicySnapshot& fee_snapshot_local,
                                     const uint256& contract_meta) {
                std::vector<unsigned char> meta_bytes(sizeof(uint256));
                std::copy(contract_meta.begin(), contract_meta.end(), meta_bytes.begin());
                AddProprietaryEntry(psbt.m_proprietary, wallet::fairsign::Identifier(), 0, "contract_meta", meta_bytes);

                const std::vector<unsigned char> policy_bytes = wallet::EncodeFairSignPolicy(record.fs_policy);
                AddProprietaryEntry(psbt.m_proprietary, wallet::fairsign::Identifier(), 0, "policy", policy_bytes);

                const std::array<unsigned char, 4> spot_tag{'s','p','o','t'};
                AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "contract_type", spot_tag);

                const std::vector<unsigned char> fee_bytes = EncodeFeePolicy(fee_snapshot_local);
                AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0, "fee_policy", fee_bytes);

                for (size_t idx = 0; idx < specs.size(); ++idx) {
                    auto om_bytes = EncodeSpotOutputMatch(specs[idx].leg, specs[idx].dest);
                    AddProprietaryEntry(psbt.m_proprietary, X_IDENTIFIER, 0,
                                        strprintf("outputmatch/%u", static_cast<unsigned>(idx)), om_bytes);
                }

                for (size_t idx = 0; idx < psbt.tx->vout.size(); ++idx) {
                    const CTxOut& out = psbt.tx->vout[idx];
                    const std::vector<unsigned char> asset_bytes = wallet::EncodeOutputAssetMetadata(out);
                    AddProprietaryEntry(psbt.outputs[idx].m_proprietary, X_IDENTIFIER, 0, "asset", asset_bytes);
                }
                for (int change_index : change_indices) {
                    const std::array<unsigned char, 1> change_flag{1};
                    AddProprietaryEntry(psbt.outputs.at(change_index).m_proprietary, X_IDENTIFIER, 0, "is_change", change_flag);
                }
            };

            //  ==================================================================
            // TAKER (Bob) AUGMENTATION PATH: Deserialize base PSBT and verify
            // ==================================================================
            // Declare these outside the if block so they're available for preserving PSBT metadata later
            CMutableTransaction base_tx_from_psbt;
            PartiallySignedTransaction base_psbt;

            if (is_augmentation) {
                std::vector<CTxOut> base_outputs;
                const std::string base_psbt_str = opts["psbt"].get_str();
                std::string decode_error;
                if (!DecodeBase64PSBT(base_psbt, base_psbt_str, decode_error) || !base_psbt.tx) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode base PSBT: %s", decode_error));
                }

                base_tx_from_psbt = CMutableTransaction(*base_psbt.tx);
                base_outputs = base_psbt.tx->vout;

                // Verify base PSBT contains the maker's leg output
                // The augmenter (this wallet) will add their own leg via sendasset/FundTransaction
                // Build expected maker's output for verification
                SpotOutputSpec expected_maker_output;
                if (role == wallet::SpotRole::ALICE) {
                    // Alice is augmenter, so Bob was maker - verify Bob's leg
                    expected_maker_output = build_contract_output(record.terms.bob_deliver,
                                                                  record.alice_recv_dest,
                                                                  false); // Not my delivery
                } else {
                    // Bob is augmenter, so Alice was maker - verify Alice's leg
                    expected_maker_output = build_contract_output(record.terms.alice_deliver,
                                                                  acceptance.bob_recv_dest,
                                                                  false); // Not my delivery
                }

                // Find maker's contract output in base PSBT (skip change outputs)
                bool found_maker_output = false;
                for (const auto& base_out : base_outputs) {
                    // Check if this output matches the maker's expected contract output
                    if (base_out.scriptPubKey == expected_maker_output.out.scriptPubKey) {
                        // Verify the leg details match
                        if (expected_maker_output.leg.is_native) {
                            if (base_out.nValue == expected_maker_output.out.nValue) {
                                found_maker_output = true;
                                break;
                            }
                        } else {
                            // Asset output - verify asset tag
                            auto base_tag = assets::ParseAssetTag(base_out.vExt);
                            if (base_tag && base_tag->id == expected_maker_output.leg.asset_id &&
                                base_tag->amount == expected_maker_output.leg.units) {
                                found_maker_output = true;
                                break;
                            }
                        }
                    }
                }

                if (!found_maker_output) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Base PSBT does not contain expected maker's contract output");
                }

                // No need to set contract_outputs here - already set earlier for augmenter's own leg

                // Save base transaction for tx_template initialization below
                tx_template = base_tx_from_psbt;
            }

            wallet::SpotUserInputs user_inputs;
            if (!opts.isNull()) {
                const UniValue& my_inputs_val = opts.find_value("my_inputs");
                if (!my_inputs_val.isNull()) {
                    if (!participant) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Wallet is not a participant in this swap; omit options.my_inputs");
                    }
                    user_inputs = ParseSpotUserInputs(*pwallet, my_inputs_val);
                }
            }

            std::optional<CTxDestination> explicit_change;
            if (!opts.isNull()) {
                const UniValue& change_val = opts.find_value("my_change_address");
                if (!change_val.isNull()) {
                    CTxDestination dest = DecodeDestination(change_val.get_str());
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid my_change_address");
                    }
                    if (!wallet::ExtractTaprootKey(dest)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "my_change_address must be a Taproot address");
                    }
                    explicit_change = dest;
                }
            }

            const uint256 contract_meta = wallet::ComputeSpotContractMeta(record, &acceptance);

            if (!participant) {
                PartiallySignedTransaction psbt(tx_template);
                annotate_psbt(psbt, contract_outputs, {}, fee_snapshot, contract_meta);

                UniValue result(UniValue::VOBJ);
                DataStream ssTx{};
                ssTx << psbt;
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("complete", false);
                result.pushKV("fee", ValueFromAmount(0));
                result.pushKV("changepos", -1);
                result.pushKV("my_role", "observer");
                result.pushKV("my_output_index", -1);
                result.pushKV("asset_change_index", -1);
                return result;
            }

            if (my_leg && !my_leg->is_native) {
                for (const wallet::ParsedSpotInput& input : user_inputs.asset_inputs) {
                    if (input.asset_id != my_leg->asset_id) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "my_inputs asset id does not match contract leg");
                    }
                }
            } else if (my_leg && my_leg->is_native && !user_inputs.asset_inputs.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset inputs cannot be provided for native legs");
            }

            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = signal_rbf;
            coin_control.m_locktime = tx_template.nLockTime;
            coin_control.m_version = tx_template.version;
            if (explicit_change) {
                coin_control.destChange = *explicit_change;
            }
            if (fee_snapshot.target_satvb > 0) {
                coin_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_snapshot.target_satvb) * 1000); // sat/vB -> sat/kB
                coin_control.fOverrideFeeRate = true;
                LogPrintf("spot.build_atomic: CCoinControl fee_rate SET: %u sat/vB (fOverrideFeeRate=true)\n", fee_snapshot.target_satvb);
            } else {
                LogPrintf("spot.build_atomic: WARNING - fee_snapshot.target_satvb is ZERO, no fee override\n");
            }

            if (!user_inputs.native_inputs.empty()) {
                coin_control.m_allow_other_inputs = false;
                for (const wallet::ParsedSpotInput& input : user_inputs.native_inputs) {
                    coin_control.Select(input.prevout);
                }
            }

            std::vector<wallet::CRecipient> recipients;
            recipients.reserve(contract_outputs.size());
            for (const auto& spec : contract_outputs) {
                recipients.push_back(wallet::CRecipient{spec.dest, spec.out.nValue, false});
            }

            // CRITICAL: Each wallet calls sendasset for their own asset leg
            // This ensures proper asset transfer construction with KYC, key wrapping, and other wallet-specific features
            // Alice wallet → calls sendasset to send TOKA
            // Bob wallet → calls sendasset to send TOKB
            // Then PSBTs are combined for atomic swap
            CMutableTransaction funded_tx;
            CAmount fee_amount = 0;
            ScopedCoinLocker coin_reserver(*pwallet);

            if (my_leg && !my_leg->is_native) {
                // Delegate to sendasset with return_skeleton=true
                // This handles: asset UTXO selection, change, asset TLV construction, KYC proofs, key wrapping
                JSONRPCRequest sendasset_req;
                sendasset_req.context = request.context;
                sendasset_req.URI = request.URI;  // Preserve wallet routing (/wallet/<name>)
                sendasset_req.strMethod = "sendasset";

                // Build params: [asset_id, counterparty_address, amount, {return_skeleton: true}]
                UniValue sendasset_params(UniValue::VARR);
                sendasset_params.push_back(my_leg->asset_id.ToString());

                // Determine counterparty's receive address
                const CTxDestination& counterparty_dest = (role == wallet::SpotRole::ALICE) ? acceptance.bob_recv_dest : record.alice_recv_dest;
                sendasset_params.push_back(EncodeDestination(counterparty_dest));
                sendasset_params.push_back(my_leg->units);

                // Options: return_skeleton=true, broadcast=false
                UniValue sendasset_opts(UniValue::VOBJ);
                sendasset_opts.pushKV("return_skeleton", true);
                sendasset_opts.pushKV("broadcast", false);
                if (fee_snapshot.target_satvb > 0) {
                    sendasset_opts.pushKV("fee_rate", fee_snapshot.target_satvb);
                }
                sendasset_params.push_back(sendasset_opts);

                sendasset_req.params = sendasset_params;

                // Call sendasset()
                UniValue skeleton_result = sendasset().HandleRequest(sendasset_req);

                // Extract skeleton: contains hex, asset_inputs, btc_inputs, outputs
                if (!skeleton_result.isObject() || !skeleton_result.exists("hex")) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset did not return valid skeleton");
                }

                // Decode the transaction skeleton
                CMutableTransaction skeleton_tx;
                if (!DecodeHexTx(skeleton_tx, skeleton_result["hex"].get_str())) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode sendasset skeleton");
                }

                // AUGMENTATION vs MAKER: Different handling
                if (is_augmentation) {
                    // AUGMENTATION (Taker): Merge skeleton inputs into existing tx_template
                    // tx_template already has both contract outputs from maker
                    funded_tx = tx_template;  // Start with maker's outputs
                    // Add taker's asset inputs from skeleton
                    for (const auto& inp : skeleton_tx.vin) {
                        funded_tx.vin.push_back(inp);
                    }
                    // Add taker's change outputs from skeleton (skip the contract output)
                    for (const auto& out : skeleton_tx.vout) {
                        // Skip outputs that match existing outputs (to avoid duplicates)
                        bool is_duplicate = false;
                        for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                            const auto& existing = funded_tx.vout[i];
                            // Match on scriptPubKey and value/vExt
                            if (out.scriptPubKey == existing.scriptPubKey &&
                                out.nValue == existing.nValue &&
                                out.vExt == existing.vExt) {
                                is_duplicate = true;
                                break;
                            }
                        }
                        if (!is_duplicate) {
                            funded_tx.vout.push_back(out);
                        }
                    }
                } else {
                    // MAKER: Use skeleton as base (will add counterparty output later)
                    funded_tx = skeleton_tx;
                }

                // Extract asset inputs for locking
                if (skeleton_result.exists("asset_inputs")) {
                    const UniValue& asset_inputs_arr = skeleton_result["asset_inputs"];
                    for (size_t i = 0; i < asset_inputs_arr.size(); ++i) {
                        const UniValue& inp = asset_inputs_arr[i];
                        Txid txid = Txid::FromHex(inp["txid"].get_str()).value();
                        uint32_t vout = inp["vout"].getInt<uint32_t>();
                        coin_reserver.Lock(COutPoint(txid, vout));
                    }
                }

                // Extract BTC inputs for locking
                if (skeleton_result.exists("btc_inputs")) {
                    const UniValue& btc_inputs_arr = skeleton_result["btc_inputs"];
                    for (size_t i = 0; i < btc_inputs_arr.size(); ++i) {
                        const UniValue& inp = btc_inputs_arr[i];
                        Txid txid = Txid::FromHex(inp["txid"].get_str()).value();
                        uint32_t vout = inp["vout"].getInt<uint32_t>();
                        coin_reserver.Lock(COutPoint(txid, vout));
                    }
                }
            } else if (my_leg && my_leg->is_native) {
                // For native BTC leg, use FundTransaction
                if (is_augmentation) {
                    // AUGMENTATION (Taker): Build funding tx with ONLY placeholder OP_RETURNs for accurate fee calculation
                    // FundTransaction expects empty tx (no contract outputs) and adds them from recipients
                    CMutableTransaction funding_tx;
                    funding_tx.version = tx_template.version;
                    funding_tx.nLockTime = tx_template.nLockTime;

                    // Add ONLY placeholder OP_RETURNs from maker's tx_template
                    for (const auto& out : tx_template.vout) {
                        if (out.nValue == 0 && out.scriptPubKey.size() >= 2 &&
                            out.scriptPubKey[0] == OP_RETURN) {
                            funding_tx.vout.push_back(out);
                        }
                    }

                    auto fund_res = wallet::FundTransaction(*pwallet, funding_tx, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
                    if (!fund_res) {
                        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original);
                    }
                    const wallet::CreatedTransactionResult& tx_result = fund_res.value();
                    CMutableTransaction funded_helper = CMutableTransaction(*tx_result.tx);
                    fee_amount = tx_result.fee;

                    // 2. Merge: Start with maker's outputs, add taker's inputs and change
                    funded_tx = tx_template;
                    for (const auto& inp : funded_helper.vin) {
                        funded_tx.vin.push_back(inp);
                    }
                    // Add any new change outputs from funding_tx (skip contract outputs)
                    for (const auto& out : funded_helper.vout) {
                        // Skip outputs that match existing outputs (to avoid duplicates)
                        bool is_duplicate = false;
                        for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                            const auto& existing = funded_tx.vout[i];
                            // Match on scriptPubKey and value/vExt
                            if (out.scriptPubKey == existing.scriptPubKey &&
                                out.nValue == existing.nValue &&
                                out.vExt == existing.vExt) {
                                is_duplicate = true;
                                break;
                            }
                        }
                        if (!is_duplicate) {
                            funded_tx.vout.push_back(out);
                        }
                    }
                } else {
                    // MAKER: Create empty tx but include placeholder OP_RETURNs for accurate fee calculation
                    // FundTransaction expects empty tx (no contract outputs) and adds them from recipients
                    CMutableTransaction tx_to_fund;
                    tx_to_fund.version = tx_template.version;
                    tx_to_fund.nLockTime = tx_template.nLockTime;

                    // Add ONLY placeholder OP_RETURNs (contract outputs come from recipients parameter)
                    for (const auto& out : tx_template.vout) {
                        if (out.nValue == 0 && out.scriptPubKey.size() >= 2 &&
                            out.scriptPubKey[0] == OP_RETURN) {
                            tx_to_fund.vout.push_back(out);
                        }
                    }

                    auto fund_res = wallet::FundTransaction(*pwallet, tx_to_fund, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
                    if (!fund_res) {
                        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original);
                    }
                    const wallet::CreatedTransactionResult& tx_result = fund_res.value();
                    funded_tx = CMutableTransaction(*tx_result.tx);
                    fee_amount = tx_result.fee;
                }

                for (const wallet::ParsedSpotInput& input : user_inputs.native_inputs) {
                    coin_reserver.Lock(input.prevout);
                }
            } else {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Unexpected: participant with no leg");
            }

            int asset_change_new_index = -1;
            std::vector<int> change_indices;

            if (is_augmentation) {
                // AUGMENTATION: Preserve all outputs from Alice's PSBT, just add Bob's inputs
                // funded_tx already has Alice's inputs + both contract outputs + Alice's change
                // We only add Bob's change outputs if any

                const auto original_vout = funded_tx.vout;
                const size_t alice_output_count = tx_template.vout.size();

                // Identify Bob's new change outputs (anything beyond Alice's original outputs)
                for (size_t i = alice_output_count; i < original_vout.size(); ++i) {
                    change_indices.push_back(static_cast<int>(i));
                    auto tag = assets::ParseAssetTag(original_vout[i].vExt);
                    if (tag && my_leg && tag->id == my_leg->asset_id) {
                        asset_change_new_index = static_cast<int>(i);
                    } else if (!tag && my_leg && my_leg->is_native && i >= alice_output_count) {
                        // Native change from Bob (new output)
                        asset_change_new_index = static_cast<int>(i);
                    }
                }
            } else {
                // MAKER: Rebuild outputs - add counterparty placeholder + change
                const auto original_vout = funded_tx.vout;
                std::vector<bool> matched(original_vout.size(), false);

                // Track indices into original_vout for MY outputs
                std::vector<std::optional<size_t>> my_output_indices;
                my_output_indices.reserve(contract_outputs.size());

                for (const auto& spec : contract_outputs) {
                    if (spec.is_my_delivery) {
                        // MY output - should be in funded_tx from sendasset
                        bool found = false;
                        for (size_t i = 0; i < original_vout.size(); ++i) {
                            if (matched[i]) continue;

                            // Match on scriptPubKey
                            if (original_vout[i].scriptPubKey != spec.out.scriptPubKey) {
                                continue;
                            }

                            // For native outputs, also match on nValue
                            // For asset outputs, match on asset tag (sendasset may use different nValue)
                            if (spec.leg.is_native) {
                                if (original_vout[i].nValue != spec.out.nValue) {
                                    continue;
                                }
                            } else {
                                // Asset output - verify asset tag matches
                                auto skeleton_tag = assets::ParseAssetTag(original_vout[i].vExt);
                                if (!skeleton_tag || skeleton_tag->id != spec.leg.asset_id || skeleton_tag->amount != spec.leg.units) {
                                    continue;
                                }
                            }

                            matched[i] = true;
                            my_output_indices.push_back(i);
                            // vExt is already set by sendasset in original_vout
                            found = true;
                            break;
                        }
                        if (!found) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to locate my output in funded transaction");
                        }
                    } else {
                        // COUNTERPARTY output - mark as having no original_vout index
                        my_output_indices.push_back(std::nullopt);
                    }
                }

                // Collect change outputs
                std::vector<SpotOutputSpec> change_specs;
                change_specs.reserve(original_vout.size() - contract_outputs.size());
                for (size_t i = 0; i < original_vout.size(); ++i) {
                    if (matched[i]) continue;
                    SpotOutputSpec spec;
                    spec.out = original_vout[i];
                    spec.is_change = true;
                    auto tag = assets::ParseAssetTag(spec.out.vExt);
                    if (tag) {
                        spec.leg.is_native = false;
                        spec.leg.asset_id = tag->id;
                        spec.leg.units = tag->amount;
                    } else {
                        spec.leg.is_native = true;
                        spec.leg.asset_id.SetNull();
                        spec.leg.units = spec.out.nValue;
                    }
                    change_specs.push_back(spec);
                }

                // Rebuild output vector: contract outputs first, then change
                funded_tx.vout.clear();
                for (size_t i = 0; i < contract_outputs.size(); ++i) {
                    if (my_output_indices[i].has_value()) {
                        // MY output - get from original_vout
                        funded_tx.vout.push_back(original_vout[my_output_indices[i].value()]);
                    } else {
                        // COUNTERPARTY output - use spec directly (unfunded placeholder)
                        funded_tx.vout.push_back(contract_outputs[i].out);
                    }
                }
                for (const auto& change_spec : change_specs) {
                    change_indices.push_back(funded_tx.vout.size());
                    if (!change_spec.leg.is_native && change_spec.leg.asset_id == (my_leg ? my_leg->asset_id : uint256())) {
                        asset_change_new_index = funded_tx.vout.size();
                    }
                    funded_tx.vout.push_back(change_spec.out);
                }
            }

            PartiallySignedTransaction psbt(funded_tx);
            annotate_psbt(psbt, contract_outputs, change_indices, fee_snapshot, contract_meta);

            // CRITICAL FIX: In augmentation path, preserve maker's PSBT input metadata (especially witness_utxo)
            // When Bob augments Alice's PSBT, Alice's inputs are not in Bob's wallet, so FillPSBT won't
            // populate witness_utxo for them. Without witness_utxo, the ceremony validation will fail
            // because it cannot determine if inputs are Taproot.
            if (is_augmentation) {
                // base_psbt was decoded earlier (line ~8553) and contains the maker's PSBT input metadata
                // The first base_psbt.inputs.size() inputs in the merged PSBT are from the maker
                const size_t maker_input_count = base_tx_from_psbt.vin.size();
                for (size_t i = 0; i < maker_input_count && i < base_psbt.inputs.size() && i < psbt.inputs.size(); ++i) {
                    // Preserve all PSBT input metadata from the maker's original PSBT
                    // This includes witness_utxo, non_witness_utxo, bip32 paths, etc.
                    psbt.inputs[i] = base_psbt.inputs[i];
                }
            }

            bool complete = false;
            const auto fill_err = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            NormalizePsbtSighash(psbt, SIGHASH_DEFAULT);

            UniValue result(UniValue::VOBJ);
            DataStream ssTx{};
            ssTx << psbt;
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("complete", complete);
            result.pushKV("fee", ValueFromAmount(fee_amount));

            int native_change_index = -1;
            for (int idx : change_indices) {
                if (!assets::ParseAssetTag(psbt.tx->vout[idx].vExt)) {
                    native_change_index = idx;
                    break;
                }
            }
            result.pushKV("changepos", native_change_index);
            result.pushKV("my_role", role == wallet::SpotRole::ALICE ? "alice" : "bob");

            int my_output_index = -1;
            for (size_t i = 0; i < contract_outputs.size(); ++i) {
                if (contract_outputs[i].is_my_delivery) {
                    my_output_index = static_cast<int>(i);
                    break;
                }
            }
            result.pushKV("my_output_index", my_output_index);
            result.pushKV("asset_change_index", asset_change_new_index);
            return result;
        }
    );
}

RPCHelpMan spot_add_commitment_proof()
{
    return RPCHelpMan(
        "spot.add_commitment_proof",
        "Add ICU decryption commitment proof OP_RETURN to a joined spot atomic swap PSBT.\n"
        "This proves the calling party can decrypt the counterparty's holder-only asset before signing.\n"
        "Each party calls this independently to add their own commitment proof.\n"
        "Format: OP_RETURN SHA256(canonical_text || my_receive_address)",
        std::vector<RPCArg>{
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT (should be joined from both parties)"},
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT with commitment proof added"},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The commitment hash added to OP_RETURN"},
                {RPCResult::Type::STR, "commitment_preimage_info", "Description of preimage: canonical_text || receive_address"},
                {RPCResult::Type::STR, "canonical_text", /* optional */ true, "Decrypted canonical ICU text (UTF-8), for UI preview only"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.add_commitment_proof", "\"cHNidP8BA...\" \"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            // Decode PSBT
            PartiallySignedTransaction psbtx;
            std::string error;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode PSBT: %s", error));
            }

            const std::string id_hex = request.params[1].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindSpotOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Spot offer not found");
            }

            const wallet::SpotOfferRecord& record = *record_opt;
            if (!record.acceptance) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Spot offer not yet accepted");
            }

            const wallet::SpotAcceptanceRecord& acceptance = *record.acceptance;
            wallet::SpotRole role = wallet::DetermineSpotRole(record);

            if (role == wallet::SpotRole::NONE) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not a participant in this swap");
            }

            // Determine counterparty's asset and my receive address
            const wallet::AssetLeg* counterparty_leg = nullptr;
            CTxDestination my_recv_dest;

            if (role == wallet::SpotRole::ALICE) {
                counterparty_leg = &record.terms.bob_deliver;
                my_recv_dest = record.alice_recv_dest;
            } else {
                counterparty_leg = &record.terms.alice_deliver;
                my_recv_dest = acceptance.bob_recv_dest;
            }

            // Only add commitment for non-native (asset) legs
            if (!counterparty_leg || counterparty_leg->is_native) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Counterparty leg is native (BTC). Commitment proofs only apply to assets.");
            }

            // Find the PSBT output that's sending us the counterparty's asset
            CTxOut* counterparty_output = nullptr;
            for (auto& out : psbtx.tx->vout) {
                auto parsed_tag = assets::ParseAssetTag(out.vExt);
                if (parsed_tag && parsed_tag->id == counterparty_leg->asset_id &&
                    out.scriptPubKey == GetScriptForDestination(my_recv_dest)) {
                    counterparty_output = &out;
                    break;
                }
            }

            if (!counterparty_output) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Counterparty asset output not found in PSBT. Asset: %s, Dest: %s. "
                             "Ensure PSBTs from both parties have been joined.",
                             counterparty_leg->asset_id.ToString(),
                             EncodeDestination(my_recv_dest)));
            }

            // Parse the asset tag to extract ICU_KEYWRAP
            auto parsed_tag = assets::ParseAssetTag(counterparty_output->vExt);
            if (!parsed_tag || !parsed_tag->has_keywrap) {
                // Diagnostic: show what we found in the PSBT output
                std::string diagnostic = parsed_tag
                    ? strprintf("AssetTag found but has_keywrap=false. vExt=%s", HexStr(counterparty_output->vExt))
                    : strprintf("Failed to parse AssetTag. vExt=%s", HexStr(counterparty_output->vExt));
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Counterparty asset has no ICU_KEYWRAP. Asset: %s. %s. "
                             "Ensure spot.build_atomic was called with WRAP_REQUIRED assets.",
                             counterparty_leg->asset_id.ToString(), diagnostic));
            }

            const std::string my_recv_addr = EncodeDestination(my_recv_dest);
            pwallet->WalletLogPrintf("spot.add_commitment_proof: asset=%s, my_recv_addr=%s, has_keywrap=true, "
                                   "wrapped_key_len=%d, suite_id=%u\n",
                                   counterparty_leg->asset_id.ToString(),
                                   my_recv_addr,
                                   static_cast<int>(parsed_tag->keywrap_wrapped_key.size()),
                                   parsed_tag->keywrap_suite_id);

            // Call geticupayload with PSBT parameters to decrypt
            JSONRPCRequest geticupayload_req;
            geticupayload_req.context = request.context;
            geticupayload_req.URI = request.URI;
            geticupayload_req.strMethod = "geticupayload";

            UniValue geticupayload_params(UniValue::VARR);
            geticupayload_params.push_back(counterparty_leg->asset_id.ToString());

            UniValue geticupayload_opts(UniValue::VOBJ);
            geticupayload_opts.pushKV("wrapped_key", parsed_tag->keywrap_wrapped_key);
            geticupayload_opts.pushKV("receive_address", my_recv_addr);
            geticupayload_opts.pushKV("receive_scriptpubkey", HexStr(counterparty_output->scriptPubKey));

            geticupayload_params.push_back(geticupayload_opts);
            geticupayload_req.params = geticupayload_params;

            UniValue icu_result = geticupayload().HandleRequest(geticupayload_req);

            // Primary path: PSBT-based decryption using wrapped_key + receive_address.
            bool decrypted_ok = icu_result.isObject() &&
                                icu_result.exists("decrypted") &&
                                icu_result["decrypted"].get_bool();

            if (!decrypted_ok) {
                // Fallback: allow wallet's UTXO-based ICU decryption to try, matching
                // the behavior used elsewhere in the codebase and in functional tests.
                std::string primary_reason = icu_result.exists("failure_reason")
                                             ? icu_result["failure_reason"].get_str()
                                             : "unknown";

                JSONRPCRequest fallback_req;
                fallback_req.context = request.context;
                fallback_req.URI = request.URI;
                fallback_req.strMethod = "geticupayload";

                UniValue fallback_params(UniValue::VARR);
                fallback_params.push_back(counterparty_leg->asset_id.ToString());
                fallback_req.params = fallback_params;

                UniValue fallback_res = geticupayload().HandleRequest(fallback_req);
                bool fallback_ok = fallback_res.isObject() &&
                                   fallback_res.exists("decrypted") &&
                                   fallback_res["decrypted"].get_bool();

                if (!fallback_ok) {
                    std::string fallback_reason = fallback_res.exists("failure_reason")
                                                  ? fallback_res["failure_reason"].get_str()
                                                  : "unknown";
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        strprintf("Failed to decrypt counterparty asset %s.\n"
                                 "PSBT-based decryption failed: %s\n"
                                 "UTXO-based decryption failed: %s\n"
                                 "Diagnostics:\n"
                                 "  receive_address: %s\n"
                                 "  wrapped_key_len: %d bytes\n"
                                 "  suite_id: %u\n"
                                 "Possible causes:\n"
                                 "  - Wallet doesn't have private key for receive_address\n"
                                 "  - Script mismatch during keywrap creation vs. PSBT output\n"
                                 "  - Wallet has no UTXOs of this asset yet (expected for first-time swaps)",
                                 counterparty_leg->asset_id.ToString(),
                                 primary_reason,
                                 fallback_reason,
                                 my_recv_addr,
                                 static_cast<int>(parsed_tag->keywrap_wrapped_key.size()),
                                 parsed_tag->keywrap_suite_id));
                }

                icu_result = fallback_res;
            }

            if (!icu_result.exists("plaintext")) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "geticupayload succeeded but returned no plaintext");
            }

            // Parse the decrypted CanonicalIcuPayload
            std::vector<unsigned char> plaintext_bytes = ParseHex(icu_result["plaintext"].get_str());
            auto canonical = assets::ParseCanonicalIcuPayload(plaintext_bytes);
            if (!canonical) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to parse decrypted ICU payload structure");
            }

            const std::vector<unsigned char>& canonical_text_bytes = canonical->canonical_text;

            // Compute commitment: SHA256(canonical_text_bytes || receive_address_string)
            const std::string recv_addr_str = EncodeDestination(my_recv_dest);
            std::vector<unsigned char> preimage;
            preimage.insert(preimage.end(), canonical_text_bytes.begin(), canonical_text_bytes.end());
            preimage.insert(preimage.end(), recv_addr_str.begin(), recv_addr_str.end());

            uint256 commitment_hash = Hash(preimage);

            // Build OP_RETURN output
            CScript opreturn_script;
            opreturn_script << OP_RETURN << ToByteVector(commitment_hash);

            CTxOut commitment_output;
            commitment_output.nValue = 0;
            commitment_output.scriptPubKey = opreturn_script;

            // Look for placeholder OP_RETURN (zero hash) to replace
            // Placeholders are added by spot.build_atomic to reserve space in fee calculation
            bool replaced = false;
            for (size_t i = 0; i < psbtx.tx->vout.size(); ++i) {
                const CTxOut& existing = psbtx.tx->vout[i];
                if (existing.nValue == 0 && existing.scriptPubKey.size() >= 34) {
                    // Check if this is OP_RETURN with 32 zero bytes
                    std::vector<unsigned char> script_data(existing.scriptPubKey.begin(), existing.scriptPubKey.end());
                    if (script_data.size() >= 34 &&
                        script_data[0] == OP_RETURN &&
                        script_data[1] == 0x20 && // PUSHDATA 32 bytes
                        std::all_of(script_data.begin() + 2, script_data.begin() + 34, [](unsigned char c) { return c == 0; })) {
                        // Replace placeholder with real commitment
                        psbtx.tx->vout[i] = commitment_output;
                        replaced = true;
                        pwallet->WalletLogPrintf("Spot commitment proof replaced placeholder at index %d\n", i);
                        break;
                    }
                }
            }

            if (!replaced) {
                // No placeholder found, append (backward compatibility)
                psbtx.tx->vout.push_back(commitment_output);
                psbtx.outputs.emplace_back();
                pwallet->WalletLogPrintf("Spot commitment proof appended (no placeholder found)\n");
            }

            pwallet->WalletLogPrintf("Spot commitment proof added: hash=%s, asset=%s, role=%s\n",
                                   commitment_hash.ToString(),
                                   counterparty_leg->asset_id.ToString(),
                                   role == wallet::SpotRole::ALICE ? "alice" : "bob");

            // Return result
            UniValue result(UniValue::VOBJ);
            DataStream ssTx{};
            ssTx << psbtx;
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("commitment_hash", commitment_hash.ToString());
            // Optional: return canonical text for UI preview (UTF-8)
            std::string canonical_text_str(canonical_text_bytes.begin(), canonical_text_bytes.end());
            result.pushKV("canonical_text", canonical_text_str);
            result.pushKV("commitment_preimage_info",
                         strprintf("SHA256(canonical_text[%d bytes] || %s)",
                                  canonical_text_bytes.size(),
                                  recv_addr_str));

            return result;
        }
    );
}

RPCHelpMan spot_mark_executed()
{
    return RPCHelpMan(
        "spot.mark_executed",
        "Record the settlement transaction ID for a spot atomic swap offer.\n"
        "This is used by contract.list to distinguish between 'accepted' and 'executed' states.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Spot offer identifier"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement transaction ID (hex)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "id", "Spot offer identifier"},
                {RPCResult::Type::STR_HEX, "settle_txid", "Recorded settlement transaction ID"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("spot.mark_executed",
                                 "\"" + std::string(64, 'a') + "\" \"" + std::string(64, 'b') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            if (request.params.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "spot.mark_executed requires id and txid");
            }

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto offer_id = uint256::FromHex(id_hex);
            if (!offer_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            const std::string txid_hex = request.params[1].get_str();
            if (!IsHex(txid_hex) || txid_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must be 32-byte hex");
            }
            const auto settle_txid_opt = uint256::FromHex(txid_hex);
            if (!settle_txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "txid invalid");
            }

            auto record_opt = pwallet->FindSpotOffer(*offer_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Spot offer not found");
            }

            wallet::SpotOfferRecord record = *record_opt;
            if (!record.acceptance) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Spot offer not yet accepted");
            }

            record.settle_txid = *settle_txid_opt;

            wallet::SpotOfferRecord stored = pwallet->RegisterSpotOffer(std::move(record));

            UniValue result(UniValue::VOBJ);
            result.pushKV("id", stored.offer_id.GetHex());
            if (stored.settle_txid) {
                result.pushKV("settle_txid", stored.settle_txid->GetHex());
            }
            return result;
        }
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// FORWARD CONTRACT (IM-Capped DvP) - FINANCING_PRIMITIVES §3.2
// ═══════════════════════════════════════════════════════════════════════════════

std::vector<RPCResult> ForwardPartyTermsResultDescription()
{
    return {
        {RPCResult::Type::OBJ, "deliver_leg", "Asset this party must deliver", SpotLegResultDescription()},
        {RPCResult::Type::OBJ, "margin_leg", "Initial margin asset/amount", SpotLegResultDescription()},
        {RPCResult::Type::STR, "margin_dest", "Bech32m address to receive IM refund"},
        {RPCResult::Type::STR, "settlement_receive_dest", "Bech32m address to receive counterparty's delivery"},
    };
}

std::vector<RPCResult> ForwardTermsResultDescription()
{
    return {
        {RPCResult::Type::OBJ, "long_party", "Alice (long) party terms", ForwardPartyTermsResultDescription()},
        {RPCResult::Type::OBJ, "short_party", "Bob (short) party terms", ForwardPartyTermsResultDescription()},
        {RPCResult::Type::NUM, "deadline_short", "Block height Bob must act by (T)"},
        {RPCResult::Type::NUM, "deadline_long", "Block height Alice must act by (T+K)"},
        {RPCResult::Type::OBJ, "premium_upfront", /*optional=*/true, "Upfront premium asset/amount (P0, omitted if zero)", SpotLegResultDescription()},
        {RPCResult::Type::STR, "premium_dest", /*optional=*/true, "Premium sink address if P0 > 0"},
        {RPCResult::Type::OBJ, "premium", /*optional=*/true, "Combined premium object (GUI compatibility)", {
            {RPCResult::Type::NUM, "units", "Premium amount in base units"},
            {RPCResult::Type::BOOL, "is_native", "True if premium is in native currency"},
            {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Asset identifier if non-native"},
            {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Decimal places for display"},
            {RPCResult::Type::STR, "payee_dest", "Address receiving the premium"},
            {RPCResult::Type::STR, "payer", /*optional=*/true, "Which party pays (long or short)"},
        }},
        {RPCResult::Type::NUM, "safety_k", "Safety window before deadlines"},
        {RPCResult::Type::NUM, "reorg_conf", "Confirmations past deadline before timeout"},
    };
}

UniValue AssetLegToJSON(const AssetLeg& leg)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("is_native", leg.is_native);
    if (!leg.is_native) {
        obj.pushKV("asset_id", leg.asset_id.GetHex());
    }
    obj.pushKV("units", leg.units);
    return obj;
}

UniValue ForwardPartyTermsToJSON(const ForwardPartyTerms& party)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("deliver_leg", AssetLegToJSON(party.deliver_leg));
    obj.pushKV("margin_leg", AssetLegToJSON(party.margin_leg));
    obj.pushKV("margin_dest", EncodeDestination(party.margin_dest));
    obj.pushKV("settlement_receive_dest", EncodeDestination(party.settlement_receive_dest));
    return obj;
}

UniValue ForwardTermsToJSON(const ForwardTerms& terms)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("long_party", ForwardPartyTermsToJSON(terms.long_party));
    obj.pushKV("short_party", ForwardPartyTermsToJSON(terms.short_party));
    obj.pushKV("deadline_short", terms.deadline_short);
    obj.pushKV("deadline_long", terms.deadline_long);

    // Serialize premium as structured AssetLeg to preserve is_native and asset_id
    if (terms.premium_leg.units > 0) {
        obj.pushKV("premium_upfront", AssetLegToJSON(terms.premium_leg));
        obj.pushKV("premium_dest", EncodeDestination(terms.premium_dest));

        // Compatibility: GUI expects a combined premium object with payer/destination
        UniValue premium(UniValue::VOBJ);
        premium.pushKV("units", static_cast<int64_t>(terms.premium_leg.units));
        premium.pushKV("is_native", terms.premium_leg.is_native);
        if (!terms.premium_leg.is_native) {
            premium.pushKV("asset_id", terms.premium_leg.asset_id.GetHex());
        }
        if (terms.premium_leg.decimals.has_value()) {
            premium.pushKV("decimals", *terms.premium_leg.decimals);
        }
        premium.pushKV("payee_dest", EncodeDestination(terms.premium_dest));

        const CScript premium_spk = GetScriptForDestination(terms.premium_dest);
        const CScript short_spk = GetScriptForDestination(terms.short_party.settlement_receive_dest);
        const CScript long_spk = GetScriptForDestination(terms.long_party.settlement_receive_dest);
        if (premium_spk == short_spk) {
            premium.pushKV("payer", "long");
        } else if (premium_spk == long_spk) {
            premium.pushKV("payer", "short");
        }

        obj.pushKV("premium", premium);
    }

    obj.pushKV("safety_k", terms.safety_k);
    obj.pushKV("reorg_conf", terms.reorg_conf);
    return obj;
}

ForwardPartyTerms ParseForwardPartyTerms(const UniValue& obj, const std::string& prefix)
{
    ForwardPartyTerms party;

    const UniValue& deliver_val = obj.find_value("deliver_leg");
    if (!deliver_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.deliver_leg is required", prefix));
    }
    party.deliver_leg = ParseSpotLeg(deliver_val.get_obj());

    const UniValue& margin_val = obj.find_value("margin_leg");
    if (!margin_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.margin_leg is required", prefix));
    }
    party.margin_leg = ParseSpotLeg(margin_val.get_obj());

    const UniValue& margin_dest_val = obj.find_value("margin_dest");
    if (!margin_dest_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.margin_dest is required", prefix));
    }
    party.margin_dest = DecodeDestination(margin_dest_val.get_str());
    if (!IsValidDestination(party.margin_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid %s.margin_dest", prefix));
    }

    const UniValue& settlement_val = obj.find_value("settlement_receive_dest");
    if (!settlement_val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.settlement_receive_dest is required", prefix));
    }
    party.settlement_receive_dest = DecodeDestination(settlement_val.get_str());
    if (!IsValidDestination(party.settlement_receive_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid %s.settlement_receive_dest", prefix));
    }

    return party;
}

ForwardTerms ParseForwardTerms(const UniValue& terms_obj)
{
    ForwardTerms terms;
    std::string premium_dest_override;

    const UniValue& long_val = terms_obj.find_value("long_party");
    if (!long_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.long_party is required");
    }
    terms.long_party = ParseForwardPartyTerms(long_val.get_obj(), "long_party");

    const UniValue& short_val = terms_obj.find_value("short_party");
    if (!short_val.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.short_party is required");
    }
    terms.short_party = ParseForwardPartyTerms(short_val.get_obj(), "short_party");

    const UniValue& deadline_short_val = terms_obj.find_value("deadline_short");
    if (deadline_short_val.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.deadline_short is required");
    }
    terms.deadline_short = static_cast<uint32_t>(ParsePositiveUInt64(deadline_short_val, "terms.deadline_short"));
    if (terms.deadline_short == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.deadline_short must be > 0");
    }

    const UniValue& deadline_long_val = terms_obj.find_value("deadline_long");
    if (deadline_long_val.isNull()) {
        // Default: T+1000 blocks
        terms.deadline_long = terms.deadline_short + 1000;
    } else {
        terms.deadline_long = static_cast<uint32_t>(ParsePositiveUInt64(deadline_long_val, "terms.deadline_long"));
        if (terms.deadline_long <= terms.deadline_short) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.deadline_long must be > deadline_short");
        }
    }

    // Premium leg (optional, defaults to native 0 sats)
    const UniValue& premium_val = terms_obj.find_value("premium_upfront");
    if (premium_val.isNull()) {
        // Compatibility: fall back to GUI-provided "premium" object (units/is_native/asset_id/payee_dest)
        const UniValue& premium_obj = terms_obj.find_value("premium");
        if (premium_obj.isObject()) {
            // Units (default 0 if missing)
            const UniValue& units_val = premium_obj.find_value("units");
            terms.premium_leg.units = units_val.isNull() ? 0 : ParsePositiveUInt64(units_val, "premium.units");

            // Asset type (defaults to native unless asset_id provided)
            const UniValue& asset_val = premium_obj.find_value("asset_id");
            const UniValue& is_native_val = premium_obj.find_value("is_native");
            const bool has_asset_id = !asset_val.isNull() && !asset_val.get_str().empty();
            terms.premium_leg.is_native = is_native_val.isNull() ? !has_asset_id : is_native_val.get_bool();
            if (terms.premium_leg.is_native) {
                terms.premium_leg.asset_id.SetNull();
            } else {
                if (!has_asset_id) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "premium.asset_id is required for non-native premium");
                }
                const auto asset_id = uint256::FromHex(asset_val.get_str());
                if (!asset_id || asset_id->IsNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "premium.asset_id is invalid or reserved");
                }
                terms.premium_leg.asset_id = *asset_id;
            }

            // Optional decimals (preserve precision from GUI)
            const UniValue& decimals_val = premium_obj.find_value("decimals");
            if (!decimals_val.isNull()) {
                int dec = decimals_val.getInt<int>();
                if (dec < 0 || dec > 18) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "premium.decimals must be between 0 and 18");
                }
                terms.premium_leg.decimals = dec;
            }

            // Optional payee destination fallback
            const UniValue& payee_val = premium_obj.find_value("payee_dest");
            if (payee_val.isStr()) {
                premium_dest_override = payee_val.get_str();
            }
        } else {
            terms.premium_leg.is_native = true;
            terms.premium_leg.units = 0;
            terms.premium_leg.asset_id.SetNull();
        }
    } else {
        // Support two formats:
        // 1. Number → native BTC (backwards compat)
        // 2. Object → {is_native, asset_id?, units}
        if (premium_val.isNum() || premium_val.isStr()) {
            // Backwards compat: number → native BTC
            terms.premium_leg.is_native = true;
            terms.premium_leg.asset_id.SetNull();
            terms.premium_leg.units = static_cast<uint64_t>(AmountFromValue(premium_val));
        } else if (premium_val.isObject()) {
            // New format: asset leg object
            terms.premium_leg = ParseSpotLeg(premium_val.get_obj());
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.premium_upfront must be a number (native sats) or object (asset leg)");
        }
    }

    // Premium destination (optional, defaults to short party's settlement address when premium > 0)
    const UniValue& premium_dest_val = terms_obj.find_value("premium_dest");
    if (!premium_dest_val.isNull()) {
        terms.premium_dest = DecodeDestination(premium_dest_val.get_str());
        if (!IsValidDestination(terms.premium_dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid premium_dest");
        }
        if (!ExtractTaprootKey(terms.premium_dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.premium_dest must be Taproot bech32m");
        }
    } else if (!premium_dest_override.empty()) {
        terms.premium_dest = DecodeDestination(premium_dest_override);
        if (!IsValidDestination(terms.premium_dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid premium.payee_dest");
        }
        if (!ExtractTaprootKey(terms.premium_dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "premium.payee_dest must be Taproot bech32m");
        }
    } else if (terms.premium_leg.units > 0) {
        // Default: premium goes to short party (seller receives upfront payment)
        terms.premium_dest = terms.short_party.settlement_receive_dest;
    } else {
        // Explicitly set CNoDestination when premium is zero
        // (commitment hashing skips serialization when units == 0, so this aligns)
        terms.premium_dest = CNoDestination{};
    }

    const UniValue& safety_val = terms_obj.find_value("safety_k");
    terms.safety_k = safety_val.isNull() ? DEFAULT_REPO_SAFETY_K : static_cast<uint32_t>(ParsePositiveUInt64(safety_val, "terms.safety_k"));

    const UniValue& reorg_val = terms_obj.find_value("reorg_conf");
    terms.reorg_conf = reorg_val.isNull() ? DEFAULT_REPO_REORG_CONF : static_cast<uint32_t>(ParsePositiveUInt64(reorg_val, "terms.reorg_conf"));
    if (terms.reorg_conf == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "terms.reorg_conf must be > 0");
    }

    return terms;
}

RPCHelpMan forward_propose()
{
    return RPCHelpMan(
        "forward.propose",
        "Create a forward contract offer (two-sided IM-capped DvP) and store it in the wallet registry.",
        std::vector<RPCArg>{
            {"terms", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Forward contract terms",
                std::vector<RPCArg>{
                    {"long_party", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Alice (long) party specification", std::vector<RPCArg>{}},
                    {"short_party", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Bob (short) party specification", std::vector<RPCArg>{}},
                    {"deadline_short", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height Bob must act by (T)"},
                    {"deadline_long", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Block height Alice must act by (T+K, defaults to T+1000)"},
                    {"premium_upfront", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Upfront premium in sats (default 0)"},
                    {"safety_k", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Safety window (default 6)"},
                    {"reorg_conf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Reorg confirmations (default 2)"},
                },
            },
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Additional options",
                std::vector<RPCArg>{
                    {"local_side", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Proposer's side: 'long' or 'short' (default 'long')"},
                },
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ, "offer", "Offer payload to share with counterparty",
                    {
                        {RPCResult::Type::NUM, "version", "Protocol version"},
                        {RPCResult::Type::STR, "contract_type", "Contract type (\"forward\")"},
                        {RPCResult::Type::STR_HEX, "id", "Offer ID"},
                        {RPCResult::Type::STR_HEX, "salt", "Commitment salt"},
                        {RPCResult::Type::STR_HEX, "commitment", "Offer commitment"},
                        {RPCResult::Type::STR, "proposer_side", "Proposer's side (\"long\" or \"short\")"},
                        {RPCResult::Type::OBJ, "terms", "Contract terms", ForwardTermsResultDescription()},
                        {RPCResult::Type::OBJ, "fs_policy", "Fair-Sign policy",
                            {
                                {RPCResult::Type::BOOL, "require_adaptor", "Requires adaptor signatures"},
                                {RPCResult::Type::BOOL, "reveal_lockstep", "Lockstep revelation"},
                            }
                        },
                        {RPCResult::Type::STR_HEX, "fs_tx_adaptor_point", "Proposer's adaptor point"},
                        {RPCResult::Type::NUM, "created_height", "Block height when created"},
                        {RPCResult::Type::NUM, "created_time", "Unix timestamp when created"},
                        {RPCResult::Type::OBJ, "internal_keys", /*optional=*/true, "Known untweaked taproot keys for margin vaults",
                            {
                                {RPCResult::Type::STR_HEX, "long_margin", /*optional=*/true, "Long party internal key (only present if wallet derived it)"},
                                {RPCResult::Type::STR_HEX, "short_margin", /*optional=*/true, "Short party internal key (only present if wallet derived it)"},
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.propose", "\"{...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& terms_obj = request.params[0].get_obj();
            ForwardTerms terms = ParseForwardTerms(terms_obj);

            ForwardSide local_side = ForwardSide::LONG;
            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& opts = request.params[1].get_obj();
                const UniValue& side_val = opts.find_value("local_side");
                if (!side_val.isNull()) {
                    const std::string side_str = side_val.get_str();
                    if (side_str == "long") {
                        local_side = ForwardSide::LONG;
                    } else if (side_str == "short") {
                        local_side = ForwardSide::SHORT;
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "local_side must be 'long' or 'short'");
                    }
                }
            }

            // Validate Taproot addresses
            if (!ExtractTaprootKey(terms.long_party.margin_dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "long_party.margin_dest must be Taproot bech32m");
            }
            if (!ExtractTaprootKey(terms.short_party.margin_dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "short_party.margin_dest must be Taproot bech32m");
            }
            if (!ExtractTaprootKey(terms.long_party.settlement_receive_dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "long_party.settlement_receive_dest must be Taproot bech32m");
            }
            if (!ExtractTaprootKey(terms.short_party.settlement_receive_dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "short_party.settlement_receive_dest must be Taproot bech32m");
            }

            uint256 offer_id = GetRandHash();
            auto [adaptor_secret, adaptor_point] = GenerateFairSignAdaptor();

            ForwardContractRecord record;
            record.contract_id = offer_id;
            record.terms = terms;
            record.local_side = local_side;
            record.fs_policy = FairSignPolicy{};
            record.fs_tx_adaptor_point = adaptor_point;
            record.local_fs_tx_adaptor_secret = adaptor_secret;
            record.salt = GetRandHash();
            record.created_time = GetTime();
            {
                LOCK(pwallet->cs_wallet);
                record.created_height = pwallet->GetLastBlockHeight();
            }
            MaybePopulateLocalMarginKey(*pwallet, terms.long_party.margin_dest, record.long_margin_internal_key);
            MaybePopulateLocalMarginKey(*pwallet, terms.short_party.margin_dest, record.short_margin_internal_key);
            record.commitment_hex = ForwardOfferCommitmentHex(terms, local_side, record.salt);

            // Persist to wallet registry and cache covenant vault scripts
            ForwardContractRecord stored = pwallet->RegisterForwardContract(std::move(record));
            CacheForwardVaultScripts(*pwallet, stored);

            UniValue offer(UniValue::VOBJ);
            offer.pushKV("version", 1);
            offer.pushKV("contract_type", "forward");
            offer.pushKV("id", offer_id.GetHex());
            offer.pushKV("salt", stored.salt.GetHex());
            offer.pushKV("commitment", stored.commitment_hex);
            offer.pushKV("proposer_side", local_side == ForwardSide::LONG ? "long" : "short");
            offer.pushKV("terms", ForwardTermsToJSON(terms));

            // Fair-Sign adaptor point
            UniValue fs_policy(UniValue::VOBJ);
            fs_policy.pushKV("require_adaptor", true);
            fs_policy.pushKV("reveal_lockstep", false);
            offer.pushKV("fs_policy", fs_policy);
            offer.pushKV("fs_tx_adaptor_point", HexStr(std::vector<unsigned char>(adaptor_point.begin(), adaptor_point.end())));

            offer.pushKV("created_height", stored.created_height);
            offer.pushKV("created_time", stored.created_time);

            UniValue internal_keys(UniValue::VOBJ);
            if (stored.local_side == ForwardSide::LONG) {
                if (auto key = EncodeInternalKeyOptional(stored.long_margin_internal_key); !key.isNull()) {
                    internal_keys.pushKV("long_margin", key);
                }
            } else if (stored.local_side == ForwardSide::SHORT) {
                if (auto key = EncodeInternalKeyOptional(stored.short_margin_internal_key); !key.isNull()) {
                    internal_keys.pushKV("short_margin", key);
                }
            }
            if (!internal_keys.empty()) {
                offer.pushKV("internal_keys", internal_keys);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", offer_id.GetHex());
            result.pushKV("offer", offer);
            return result;
        }
    );
}

// Helper: Build OP_OUTPUTMATCH segment for AssetLeg
CScript BuildOutputMatchForLeg(const AssetLeg& leg, const CTxDestination& dest)
{
    CScript script;
    const uint256 tap_match = ComputeTapMatch(GetScriptForDestination(dest));
    std::vector<unsigned char> tap_match_bytes(tap_match.begin(), tap_match.end());
    script << tap_match_bytes;

    if (leg.is_native) {
        script << EncodeLE64(leg.units) << OP_OUTPUTMATCH_NATIVE;
    } else {
        std::vector<unsigned char> asset_bytes(leg.asset_id.begin(), leg.asset_id.end());
        script << asset_bytes << EncodeLE64(leg.units) << OP_OUTPUTMATCH_ASSET;
    }
    return script;
}

// Build B_ESCROW taptree (created when Bob self-delivers)
// Leaf BE-CLAIM: Alice claims B iff same tx pays A -> Bob
// Leaf BE-REFUND: Bob refunds B after T+K
WitnessV1Taproot BuildBEscrowTaproot(const ForwardTerms& terms, const XOnlyPubKey& alice_key, const XOnlyPubKey& bob_key, const uint256& contract_id)
{
    // BE-CLAIM: Alice must pay A->Bob in same tx
    CScript be_claim = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
    be_claim << OP_VERIFY;
    be_claim << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

    // BE-REFUND: Bob refunds after T+K
    CScript be_refund;
    be_refund << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    be_refund << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(be_claim.begin(), be_claim.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    builder.Add(1, std::vector<unsigned char>(be_refund.begin(), be_refund.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    // Internal key: script-only NUMS to disable unilateral key-path
    const XOnlyPubKey nums = DeriveScriptOnlyInternalKey("forward-b-escrow", contract_id);
    builder.Finalize(nums);
    if (!builder.IsValid()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct B_ESCROW taptree");
    }
    return WitnessV1Taproot{builder.GetOutput()};
}

// Build A_ESCROW taptree (created when Alice self-delivers)
// Leaf AE-CLAIM: Bob claims A iff same tx pays B -> Alice
// Leaf AE-REFUND: Alice refunds A after T+K
WitnessV1Taproot BuildAEscrowTaproot(const ForwardTerms& terms, const XOnlyPubKey& alice_key, const XOnlyPubKey& bob_key, const uint256& contract_id)
{
    // AE-CLAIM: Bob must pay B->Alice in same tx
    CScript ae_claim = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
    ae_claim << OP_VERIFY;
    ae_claim << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

    // AE-REFUND: Alice refunds after T+K
    CScript ae_refund;
    ae_refund << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    ae_refund << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(ae_claim.begin(), ae_claim.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    builder.Add(1, std::vector<unsigned char>(ae_refund.begin(), ae_refund.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    // Internal key: script-only NUMS to disable unilateral key-path
    const XOnlyPubKey nums = DeriveScriptOnlyInternalKey("forward-a-escrow", contract_id);
    builder.Finalize(nums);
    if (!builder.IsValid()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct A_ESCROW taptree");
    }
    return WitnessV1Taproot{builder.GetOutput()};
}

static TaprootBuilder CreateForwardVaultBuilder(const ForwardContractRecord& record,
                                                ForwardSide side)
{
    Assume(record.long_margin_internal_key.has_value());
    Assume(record.short_margin_internal_key.has_value());

    const ForwardTerms& terms = record.terms;
    const XOnlyPubKey alice_key = *record.long_margin_internal_key;
    const XOnlyPubKey bob_key = *record.short_margin_internal_key;

    const WitnessV1Taproot b_escrow_taproot = BuildBEscrowTaproot(terms, alice_key, bob_key, record.contract_id);
    const WitnessV1Taproot a_escrow_taproot = BuildAEscrowTaproot(terms, alice_key, bob_key, record.contract_id);

    TaprootBuilder builder;

    if (side == ForwardSide::SHORT) {
        CScript b_self = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
        b_self << OP_VERIFY;
        CScript b_escrow_match = BuildOutputMatchForLeg(terms.short_party.deliver_leg, b_escrow_taproot);
        b_self.insert(b_self.end(), b_escrow_match.begin(), b_escrow_match.end());
        b_self << OP_VERIFY;
        b_self << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        CScript b_counter;
        // NO CLTV - can be used immediately after long delivers (escrow exists)
        CScript short_margin_match = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
        b_counter.insert(b_counter.end(), short_margin_match.begin(), short_margin_match.end());
        b_counter << OP_VERIFY;
        CScript short_payment_match = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
        b_counter.insert(b_counter.end(), short_payment_match.begin(), short_payment_match.end());
        b_counter << OP_VERIFY;
        b_counter << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        CScript b_timeout;
        b_timeout << CScriptNum(terms.deadline_short) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        b_timeout << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        CScript coop = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
        coop << OP_VERIFY;
        CScript match2 = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
        coop.insert(coop.end(), match2.begin(), match2.end());
        coop << OP_VERIFY;
        CScript match3 = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
        coop.insert(coop.end(), match3.begin(), match3.end());
        coop << OP_VERIFY;
        CScript match4 = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
        coop.insert(coop.end(), match4.begin(), match4.end());
        coop << OP_VERIFY;
        coop << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIGVERIFY;
        coop << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        builder.Add(2, std::vector<unsigned char>(b_self.begin(), b_self.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(2, std::vector<unsigned char>(b_counter.begin(), b_counter.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(2, std::vector<unsigned char>(b_timeout.begin(), b_timeout.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(2, std::vector<unsigned char>(coop.begin(), coop.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        // Disable unilateral key-path: use script-only internal key for IM (short)
        builder.Finalize(DeriveScriptOnlyInternalKey("forward-im-short", record.contract_id));
        if (!builder.IsValid()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct Bob IM vault taptree");
        }
    } else {
        CScript a_self;
        a_self << CScriptNum(terms.deadline_short) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        CScript a_margin_match = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
        a_self.insert(a_self.end(), a_margin_match.begin(), a_margin_match.end());
        a_self << OP_VERIFY;
        CScript a_escrow_match = BuildOutputMatchForLeg(terms.long_party.deliver_leg, a_escrow_taproot);
        a_self.insert(a_self.end(), a_escrow_match.begin(), a_escrow_match.end());
        a_self << OP_VERIFY;
        a_self << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        CScript a_counter;
        // NO CLTV - can be used immediately after short delivers (escrow exists)
        CScript long_margin_match = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
        a_counter.insert(a_counter.end(), long_margin_match.begin(), long_margin_match.end());
        a_counter << OP_VERIFY;
        CScript long_payment_match = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
        a_counter.insert(a_counter.end(), long_payment_match.begin(), long_payment_match.end());
        a_counter << OP_VERIFY;
        a_counter << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        CScript a_timeout;
        a_timeout << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        a_timeout << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        CScript coop = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
        coop << OP_VERIFY;
        CScript match2 = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
        coop.insert(coop.end(), match2.begin(), match2.end());
        coop << OP_VERIFY;
        CScript match3 = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
        coop.insert(coop.end(), match3.begin(), match3.end());
        coop << OP_VERIFY;
        CScript match4 = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
        coop.insert(coop.end(), match4.begin(), match4.end());
        coop << OP_VERIFY;
        coop << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIGVERIFY;
        coop << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        builder.Add(2, std::vector<unsigned char>(a_self.begin(), a_self.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(2, std::vector<unsigned char>(a_counter.begin(), a_counter.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(2, std::vector<unsigned char>(a_timeout.begin(), a_timeout.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(2, std::vector<unsigned char>(coop.begin(), coop.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        // Disable unilateral key-path: use script-only internal key for IM (long)
        builder.Finalize(DeriveScriptOnlyInternalKey("forward-im-long", record.contract_id));
        if (!builder.IsValid()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct Alice IM vault taptree");
        }
    }

    return builder;
}

static WitnessV1Taproot BuildForwardVaultTaproot(const ForwardContractRecord& record,
                                                 ForwardSide side)
{
    TaprootBuilder builder = CreateForwardVaultBuilder(record, side);
    return WitnessV1Taproot{builder.GetOutput()};
}

[[maybe_unused]] static WitnessV1Taproot BuildForwardLongVaultTaproot(const ForwardContractRecord& record)
{
    return BuildForwardVaultTaproot(record, ForwardSide::LONG);
}

[[maybe_unused]] static WitnessV1Taproot BuildForwardShortVaultTaproot(const ForwardContractRecord& record)
{
    return BuildForwardVaultTaproot(record, ForwardSide::SHORT);
}

// Forward declaration moved to wallet.h to allow calling from CWallet::LoadWallet
void CacheForwardVaultScripts(CWallet& wallet, const ForwardContractRecord& record)
{
    if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
        wallet.WalletLogPrintf("Forward[%s]: CacheForwardVaultScripts skipped (missing internal keys)\n",
                              record.contract_id.GetHex());
        return;
    }

    LOCK(wallet.cs_wallet);

    wallet.WalletLogPrintf("Forward[%s]: CacheForwardVaultScripts starting...\n",
                          record.contract_id.GetHex());

    const ForwardTerms& terms = record.terms;
    const XOnlyPubKey alice_key = *record.long_margin_internal_key;
    const XOnlyPubKey bob_key = *record.short_margin_internal_key;

    // Register SHORT vault (Bob's)
    // BOTH parties need to register BOTH vaults so they can retrieve them later for any operation
    {
        TaprootBuilder builder = CreateForwardVaultBuilder(record, ForwardSide::SHORT);
        const WitnessV1Taproot vault_output{builder.GetOutput()};
        const CScript vault_spk = GetScriptForDestination(vault_output);
        const CScript margin_spk = GetScriptForDestination(terms.short_party.margin_dest);

        // Get ALL descriptor managers to ensure keys are cached everywhere
        // This is critical for multi-SPKM wallets where the vault might be signed by any SPKM
        std::set<ScriptPubKeyMan*> managers;
        for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
            if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                managers.insert(manager);
            }
        }
        if (!managers.empty()) {
            // Build leaf descriptors for SHORT vault
            std::vector<VaultLeafDescriptor> leaves;

            // b_self leaf (self-delivery)
        CScript b_self = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
        b_self << OP_VERIFY;
        const WitnessV1Taproot b_escrow_taproot = BuildBEscrowTaproot(terms, alice_key, bob_key, record.contract_id);
        CScript b_escrow_match = BuildOutputMatchForLeg(terms.short_party.deliver_leg, b_escrow_taproot);
        b_self.insert(b_self.end(), b_escrow_match.begin(), b_escrow_match.end());
        b_self << OP_VERIFY;
        b_self << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;
        leaves.push_back(VaultBuilder::CreateLeaf(b_self, bob_key, "self_delivery", std::nullopt));

        // b_counter_delivery: short reclaims IM while claiming A escrow (mirrors long counter flow)
        CScript b_counter;
        // NO CLTV - can be used immediately after long delivers (escrow exists)
        CScript short_margin_match = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
        b_counter.insert(b_counter.end(), short_margin_match.begin(), short_margin_match.end());
        b_counter << OP_VERIFY;
        CScript short_payment_match = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
        b_counter.insert(b_counter.end(), short_payment_match.begin(), short_payment_match.end());
        b_counter << OP_VERIFY;
        b_counter << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;
        leaves.push_back(VaultBuilder::CreateLeaf(b_counter, bob_key, "b_counter_delivery", std::nullopt));

            // b_timeout leaf
            CScript b_timeout;
            b_timeout << CScriptNum(terms.deadline_short) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
            b_timeout << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;
            leaves.push_back(VaultBuilder::CreateLeaf(b_timeout, alice_key, "timeout", terms.deadline_short));

            // coop leaf (cooperative close)
            CScript coop = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
            coop << OP_VERIFY;
            CScript match2 = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
            coop.insert(coop.end(), match2.begin(), match2.end());
            coop << OP_VERIFY;
            CScript match3 = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
            coop.insert(coop.end(), match3.begin(), match3.end());
            coop << OP_VERIFY;
            CScript match4 = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
            coop.insert(coop.end(), match4.begin(), match4.end());
            coop << OP_VERIFY;
            coop << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIGVERIFY;
            coop << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;
            leaves.push_back(VaultBuilder::CreateLeaf(coop, bob_key, "cooperative", std::nullopt));

            auto vault_metadata_opt = VaultBuilder::Build(builder, record.contract_id, VaultRole::FORWARD_SHORT, leaves);
            if (vault_metadata_opt) {
                std::set<CScript> scripts{vault_spk};
                for (ScriptPubKeyMan* manager : managers) {
                    if (manager == nullptr) continue;
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    // Register under vault owner's margin script (Bob's)
                    desc_spkm->RegisterCovenantVault(margin_spk, *vault_metadata_opt);
                    // ALSO register under counterparty's margin script (Alice's) so Alice can sweep Bob's vault
                    const CScript alice_margin_spk = GetScriptForDestination(terms.long_party.margin_dest);
                    desc_spkm->RegisterCovenantVault(alice_margin_spk, *vault_metadata_opt);
                    wallet.CacheNewScriptPubKeys(scripts, manager);
                }
            }
        }
    }

    // Register LONG vault (Alice's)
    // BOTH parties need to register BOTH vaults so they can retrieve them later for any operation
    {
        TaprootBuilder builder = CreateForwardVaultBuilder(record, ForwardSide::LONG);
        const WitnessV1Taproot vault_output{builder.GetOutput()};
        const CScript vault_spk = GetScriptForDestination(vault_output);
        const CScript margin_spk = GetScriptForDestination(terms.long_party.margin_dest);

        // Get ALL descriptor managers to ensure keys are cached everywhere
        // This is critical for multi-SPKM wallets where the vault might be signed by any SPKM
        std::set<ScriptPubKeyMan*> managers;
        for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
            if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                managers.insert(manager);
            }
        }
        if (!managers.empty()) {
            // Build leaf descriptors for LONG vault
            std::vector<VaultLeafDescriptor> leaves;

            // a_self leaf (self-delivery)
        CScript a_self;
        a_self << CScriptNum(terms.deadline_short) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        CScript a_margin_match = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
        a_self.insert(a_self.end(), a_margin_match.begin(), a_margin_match.end());
        a_self << OP_VERIFY;
        const WitnessV1Taproot a_escrow_taproot = BuildAEscrowTaproot(terms, alice_key, bob_key, record.contract_id);
        CScript a_escrow_match = BuildOutputMatchForLeg(terms.long_party.deliver_leg, a_escrow_taproot);
        a_self.insert(a_self.end(), a_escrow_match.begin(), a_escrow_match.end());
        a_self << OP_VERIFY;
        a_self << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;
        leaves.push_back(VaultBuilder::CreateLeaf(a_self, alice_key, "self_delivery", std::nullopt));

        // a_counter_delivery: long reclaims IM concurrently with escrow claim
        CScript a_counter;
        // NO CLTV - can be used immediately after short delivers (escrow exists)
        CScript long_margin_match = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
        a_counter.insert(a_counter.end(), long_margin_match.begin(), long_margin_match.end());
        a_counter << OP_VERIFY;
        CScript long_payment_match = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
        a_counter.insert(a_counter.end(), long_payment_match.begin(), long_payment_match.end());
        a_counter << OP_VERIFY;
        a_counter << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;
        leaves.push_back(VaultBuilder::CreateLeaf(a_counter, alice_key, "a_counter_delivery", std::nullopt));

            // a_timeout leaf
            CScript a_timeout;
            a_timeout << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
            a_timeout << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;
            leaves.push_back(VaultBuilder::CreateLeaf(a_timeout, bob_key, "timeout", terms.deadline_long));

            // coop leaf (same as SHORT, but Alice signs)
            CScript coop = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
            coop << OP_VERIFY;
            CScript match2 = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
            coop.insert(coop.end(), match2.begin(), match2.end());
            coop << OP_VERIFY;
            CScript match3 = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
            coop.insert(coop.end(), match3.begin(), match3.end());
            coop << OP_VERIFY;
            CScript match4 = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
            coop.insert(coop.end(), match4.begin(), match4.end());
            coop << OP_VERIFY;
            coop << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIGVERIFY;
            coop << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;
            leaves.push_back(VaultBuilder::CreateLeaf(coop, alice_key, "cooperative", std::nullopt));

            auto vault_metadata_opt = VaultBuilder::Build(builder, record.contract_id, VaultRole::FORWARD_LONG, leaves);
            if (vault_metadata_opt) {
                std::set<CScript> scripts{vault_spk};
                for (ScriptPubKeyMan* manager : managers) {
                    if (manager == nullptr) continue;
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    // Register under vault owner's margin script (Alice's)
                    desc_spkm->RegisterCovenantVault(margin_spk, *vault_metadata_opt);
                    // ALSO register under counterparty's margin script (Bob's) so Bob can sweep Alice's vault
                    const CScript bob_margin_spk = GetScriptForDestination(terms.short_party.margin_dest);
                    desc_spkm->RegisterCovenantVault(bob_margin_spk, *vault_metadata_opt);
                    wallet.CacheNewScriptPubKeys(scripts, manager);
                }
            }
        }
    }

    // Register B_ESCROW vault (created when short self-delivers)
    {
        CScript be_claim = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
        be_claim << OP_VERIFY;
        be_claim << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        CScript be_refund;
        be_refund << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        be_refund << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        TaprootBuilder builder;
        builder.Add(1, std::vector<unsigned char>(be_claim.begin(), be_claim.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(1, std::vector<unsigned char>(be_refund.begin(), be_refund.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        // Disable unilateral key-path on B_ESCROW
        builder.Finalize(DeriveScriptOnlyInternalKey("forward-b-escrow", record.contract_id));
        if (!builder.IsValid()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct B escrow taptree");
        }

        std::vector<VaultLeafDescriptor> leaves;
        leaves.push_back(VaultBuilder::CreateLeaf(be_claim, alice_key, "b_escrow_claim", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(be_refund, bob_key, "b_escrow_refund", terms.deadline_long));

        auto metadata_opt = VaultBuilder::Build(builder, record.contract_id, VaultRole::FORWARD_ESCROW_B, leaves);
        if (metadata_opt) {
            const CScript escrow_spk = GetScriptForDestination(WitnessV1Taproot{builder.GetOutput()});
            const CScript base_spk = GetScriptForDestination(terms.short_party.settlement_receive_dest);

            std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(base_spk);
            if (managers.empty()) {
                for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
                    if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                        managers.insert(manager);
                    }
                }
            }

            if (!managers.empty()) {
                std::set<CScript> scripts{escrow_spk};
                for (ScriptPubKeyMan* manager : managers) {
                    if (!manager) continue;
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    desc_spkm->RegisterCovenantVault(escrow_spk, *metadata_opt);
                    wallet.CacheNewScriptPubKeys(scripts, manager);
                }
            }
        }
    }

    // Register A_ESCROW vault (created when long self-delivers)
    {
        CScript ae_claim = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
        ae_claim << OP_VERIFY;
        ae_claim << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        CScript ae_refund;
        ae_refund << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        ae_refund << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        TaprootBuilder builder;
        builder.Add(1, std::vector<unsigned char>(ae_claim.begin(), ae_claim.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(1, std::vector<unsigned char>(ae_refund.begin(), ae_refund.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        // Disable unilateral key-path on A_ESCROW
        builder.Finalize(DeriveScriptOnlyInternalKey("forward-a-escrow", record.contract_id));
        if (!builder.IsValid()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct A escrow taptree");
        }

        std::vector<VaultLeafDescriptor> leaves;
        leaves.push_back(VaultBuilder::CreateLeaf(ae_claim, bob_key, "a_escrow_claim", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(ae_refund, alice_key, "a_escrow_refund", terms.deadline_long));

        auto metadata_opt = VaultBuilder::Build(builder, record.contract_id, VaultRole::FORWARD_ESCROW_A, leaves);
        if (metadata_opt) {
            const CScript escrow_spk = GetScriptForDestination(WitnessV1Taproot{builder.GetOutput()});
            const CScript base_spk = GetScriptForDestination(terms.long_party.settlement_receive_dest);

            std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(base_spk);
            if (managers.empty()) {
                for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
                    if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                        managers.insert(manager);
                    }
                }
            }

            if (!managers.empty()) {
                std::set<CScript> scripts{escrow_spk};
                for (ScriptPubKeyMan* manager : managers) {
                    if (!manager) continue;
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                    if (!desc_spkm) continue;
                    desc_spkm->RegisterCovenantVault(base_spk, *metadata_opt);
                    wallet.CacheNewScriptPubKeys(scripts, manager);
                }
            }
        }
    }

    wallet.WalletLogPrintf("Forward[%s]: CacheForwardVaultScripts completed (registered LONG, SHORT, and B_ESCROW vaults)\n",
                          record.contract_id.GetHex());
}

static std::optional<VaultMetadata> BuildForwardEscrowMetadata(const ForwardContractRecord& record,
                                                               VaultRole role)
{
    const ForwardTerms& terms = record.terms;
    if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
        return std::nullopt;
    }

    const XOnlyPubKey alice_key = *record.long_margin_internal_key;
    const XOnlyPubKey bob_key = *record.short_margin_internal_key;
    TaprootBuilder builder;
    std::vector<VaultLeafDescriptor> leaves;

    if (role == VaultRole::FORWARD_ESCROW_B) {
        CScript be_claim = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
        be_claim << OP_VERIFY;
        be_claim << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        CScript be_refund;
        be_refund << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        be_refund << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        builder.Add(1, std::vector<unsigned char>(be_claim.begin(), be_claim.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(1, std::vector<unsigned char>(be_refund.begin(), be_refund.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Finalize(DeriveScriptOnlyInternalKey("forward-b-escrow", record.contract_id));
        if (!builder.IsValid()) return std::nullopt;

        leaves.push_back(VaultBuilder::CreateLeaf(be_claim, alice_key, "b_escrow_claim", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(be_refund, bob_key, "b_escrow_refund", terms.deadline_long));
    } else if (role == VaultRole::FORWARD_ESCROW_A) {
        CScript ae_claim = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
        ae_claim << OP_VERIFY;
        ae_claim << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

        CScript ae_refund;
        ae_refund << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        ae_refund << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

        builder.Add(1, std::vector<unsigned char>(ae_claim.begin(), ae_claim.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Add(1, std::vector<unsigned char>(ae_refund.begin(), ae_refund.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Finalize(DeriveScriptOnlyInternalKey("forward-a-escrow", record.contract_id));
        if (!builder.IsValid()) return std::nullopt;

        leaves.push_back(VaultBuilder::CreateLeaf(ae_claim, bob_key, "a_escrow_claim", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(ae_refund, alice_key, "a_escrow_refund", terms.deadline_long));
    } else {
        return std::nullopt;
    }

    return VaultBuilder::Build(builder, record.contract_id, role, leaves);
}

// Ensure vault outpoints are available in the wallet record before building covenant spends.
// If either margin vault is missing but we know the transaction that created it, re-parse that
// transaction via VerifyAndPersistForwardVaults. Registry entries are refreshed unconditionally
// so descriptor managers retain taproot metadata after restarts.
static void EnsureForwardVaultState(CWallet& wallet,
                                    const JSONRPCRequest& request,
                                    ForwardContractRecord& record,
                                    const std::optional<uint256>& tx_hint = std::nullopt)
{
    auto fmt_outpoint = [](const std::optional<COutPoint>& op) -> std::string {
        if (!op) return "unset";
        return strprintf("%s:%u", op->hash.ToString(), op->n);
    };

    LogPrintf("Forward[%s]: EnsureForwardVaultState start (long=%s short=%s tx_hint=%s open_txid=%s)\n",
              record.contract_id.GetHex(),
              fmt_outpoint(record.long_margin_vault),
              fmt_outpoint(record.short_margin_vault),
              tx_hint ? tx_hint->GetHex() : "unset",
              record.open_txid ? record.open_txid->GetHex() : "unset");

    auto refresh_record = [&]() {
        if (auto refreshed = wallet.FindForwardContract(record.contract_id)) {
            record = *refreshed;
        }
    };

    auto looks_like_vault = [&](const COutPoint& outpoint, ForwardSide side) -> bool {
        const AssetLeg& margin_leg = (side == ForwardSide::LONG)
            ? record.terms.long_party.margin_leg
            : record.terms.short_party.margin_leg;
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
        if (!wtx || !wtx->tx || outpoint.n >= wtx->tx->vout.size()) return false;
        const CTxOut& out = wtx->tx->vout[outpoint.n];
        const bool amount_match = margin_leg.is_native
            ? out.nValue == static_cast<CAmount>(margin_leg.units)
            : out.nValue == DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        int wit_version;
        std::vector<unsigned char> wit_program;
        return amount_match && out.scriptPubKey.IsWitnessProgram(wit_version, wit_program);
    };

    bool long_looks_valid = record.long_margin_vault && looks_like_vault(*record.long_margin_vault, ForwardSide::LONG);
    bool short_looks_valid = record.short_margin_vault && looks_like_vault(*record.short_margin_vault, ForwardSide::SHORT);

    const bool need_refresh = !long_looks_valid || !short_looks_valid;
    if (need_refresh) {
        std::optional<uint256> txid = tx_hint;
        if (!txid && record.open_txid) {
            txid = record.open_txid;
        }
        if (txid) {
            const Txid needle = Txid::FromUint256(*txid);
            CTransactionRef tx;
            const CWalletTx* wtx = WITH_LOCK(wallet.cs_wallet, return wallet.GetWalletTx(needle));
            if (wtx) {
                LogPrintf("Forward[%s]: EnsureForwardVaultState using wallet tx %s\n",
                          record.contract_id.GetHex(), needle.ToString());
                tx = wtx->tx;
            } else {
                node::NodeContext* node_ctx = nullptr;
                if (auto wallet_ctx = util::AnyPtr<wallet::WalletContext>(request.context)) {
                    node_ctx = wallet_ctx->node_context;
                }
                if (!node_ctx) {
                    node_ctx = util::AnyPtr<node::NodeContext>(request.context);
                }
                if (node_ctx && node_ctx->chainman) {
                    uint256 hash_block;
                    tx = node::GetTransaction(/*block_index=*/nullptr,
                                              node_ctx->mempool.get(),
                                              needle.ToUint256(),
                                              hash_block,
                                              node_ctx->chainman->m_blockman);
                    if (tx) {
                        LogPrintf("Forward[%s]: EnsureForwardVaultState fetched tx %s from node context\n",
                                  record.contract_id.GetHex(), needle.ToString());
                    } else {
                        LogPrintf("Forward[%s]: EnsureForwardVaultState could not fetch tx %s from node context\n",
                                  record.contract_id.GetHex(), needle.ToString());
                    }
                } else {
                    LogPrintf("Forward[%s]: EnsureForwardVaultState could not access node context to fetch tx %s\n",
                              record.contract_id.GetHex(), needle.ToString());
                }
            }
            if (tx && wallet.VerifyAndPersistForwardVaults(record.contract_id, tx, /*allow_open_discovery=*/true)) {
                refresh_record();
                LogPrintf("Forward[%s]: EnsureForwardVaultState persisted vaults via tx %s (long=%s short=%s)\n",
                          record.contract_id.GetHex(), needle.ToString(),
                          fmt_outpoint(record.long_margin_vault),
                          fmt_outpoint(record.short_margin_vault));
            }
        }
    }

    CacheForwardVaultScripts(wallet, record);
    LogPrintf("Forward[%s]: EnsureForwardVaultState done (long=%s short=%s)\n",
              record.contract_id.GetHex(),
              fmt_outpoint(record.long_margin_vault),
              fmt_outpoint(record.short_margin_vault));
}

struct ForwardAssetSkeletonResult
{
    CMutableTransaction tx;
    std::set<COutPoint> inputs_to_lock;
    std::vector<size_t> change_indices;
    std::optional<size_t> deliver_output_index;
    CAmount estimated_fee{0};
};

static ForwardAssetSkeletonResult BuildForwardNativeSkeleton(CWallet& wallet,
                                                            const JSONRPCRequest& parent_request,
                                                            const CTxDestination& dest,
                                                            CAmount amount,
                                                            const std::optional<double>& fee_rate_satvb,
                                                            const char* context_tag)
{
    // Build a minimal transaction paying 'amount' sats to 'dest' and let the wallet
    // select ONLY its own BTC inputs and add native change. Then we graft these inputs
    // and change outputs into the cooperative close PSBT.

    CMutableTransaction tx_template;
    tx_template.version = 2;

    std::vector<CRecipient> recipients;
    recipients.push_back({dest, amount, /*subtract_fee=*/false});

    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = wallet.m_signal_rbf;

    if (fee_rate_satvb.has_value()) {
        coin_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_satvb) * 1000); // sat/vB -> sat/kB
        coin_control.fOverrideFeeRate = true;
    }

    auto fund_res = FundTransaction(wallet, tx_template, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
    if (!fund_res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original + (std::string)" (" + context_tag + ")");
    }
    const CreatedTransactionResult& tx_result = *fund_res;

    ForwardAssetSkeletonResult result;
    result.tx = CMutableTransaction(*tx_result.tx);
    result.estimated_fee = tx_result.fee;
    if (tx_result.change_pos) {
        result.change_indices.push_back(*tx_result.change_pos);
    }
    for (const CTxIn& vin : result.tx.vin) {
        result.inputs_to_lock.insert(vin.prevout);
    }
    // Locate the deliver output index by matching script + value
    const CScript dest_spk = GetScriptForDestination(dest);
    for (size_t i = 0; i < result.tx.vout.size(); ++i) {
        if (result.tx.vout[i].scriptPubKey == dest_spk && result.tx.vout[i].nValue == amount) {
            result.deliver_output_index = i;
            break;
        }
    }
    if (!result.deliver_output_index) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("%s: unable to locate native delivery output in skeleton", context_tag));
    }
    return result;
}

static ForwardAssetSkeletonResult BuildForwardAssetSkeleton(CWallet& wallet,
                                                            const JSONRPCRequest& parent_request,
                                                            const AssetLeg& leg,
                                                            const CTxDestination& dest,
                                                            const std::optional<double>& fee_rate_satvb,
                                                            const char* context_tag)
{
    Assert(!leg.is_native);

    JSONRPCRequest sendasset_req;
    sendasset_req.context = parent_request.context;
    sendasset_req.URI = parent_request.URI;
    sendasset_req.strMethod = "sendasset";

    UniValue params(UniValue::VARR);
    params.push_back(leg.asset_id.ToString());
    params.push_back(EncodeDestination(dest));
    params.push_back(UniValue(static_cast<int64_t>(leg.units)));

    UniValue opts(UniValue::VOBJ);
    opts.pushKV("return_skeleton", true);
    opts.pushKV("broadcast", false);
    if (fee_rate_satvb.has_value()) {
        opts.pushKV("fee_rate", *fee_rate_satvb);
    }
    params.push_back(opts);

    sendasset_req.params = params;

    UniValue skeleton = sendasset().HandleRequest(sendasset_req);
    if (!skeleton.isObject() || !skeleton.exists("hex")) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: sendasset did not return skeleton hex", context_tag));
    }

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, skeleton["hex"].get_str())) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: failed to decode sendasset skeleton", context_tag));
    }

    ForwardAssetSkeletonResult result;
    result.tx = std::move(tx);

    if (skeleton.exists("estimated_fee")) {
        result.estimated_fee = AmountFromValue(skeleton["estimated_fee"]);
    }

    auto collect_inputs = [&](const UniValue& arr){
        for (size_t i = 0; i < arr.size(); ++i) {
            const UniValue& obj = arr[i];
            auto txid_opt = Txid::FromHex(obj["txid"].get_str());
            if (!txid_opt) continue;
            uint32_t vout = obj["vout"].getInt<uint32_t>();
            result.inputs_to_lock.insert(COutPoint(*txid_opt, vout));
        }
    };

    if (skeleton.exists("asset_inputs") && skeleton["asset_inputs"].isArray()) {
        collect_inputs(skeleton["asset_inputs"].get_array());
    }
    if (skeleton.exists("btc_inputs") && skeleton["btc_inputs"].isArray()) {
        collect_inputs(skeleton["btc_inputs"].get_array());
    }

    const CScript dest_spk = GetScriptForDestination(dest);
    for (size_t i = 0; i < result.tx.vout.size(); ++i) {
        const CTxOut& out = result.tx.vout[i];
        auto tag = assets::ParseAssetTag(out.vExt);
        if (tag && tag->id == leg.asset_id && tag->amount == leg.units && out.scriptPubKey == dest_spk) {
            result.deliver_output_index = i;
            break;
        }
    }
    if (!result.deliver_output_index) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("%s: unable to locate asset delivery output in skeleton", context_tag));
    }

    if (skeleton.exists("outputs") && skeleton["outputs"].isArray()) {
        const UniValue& outputs = skeleton["outputs"].get_array();
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& outobj = outputs[i];
            if (!outobj.exists("n")) continue;
            size_t n = outobj["n"].getInt<size_t>();
            std::string type;
            if (outobj.exists("type")) {
                type = outobj["type"].get_str();
            }
            bool mark_change = false;
            if (!type.empty() && type.find("change") != std::string::npos) {
                mark_change = true;
            } else {
                // Fallback: treat wallet-owned outputs (except the delivery output) as change.
                LOCK(wallet.cs_wallet);
                if (n < result.tx.vout.size()) {
                    const CTxOut& out = result.tx.vout[n];
                    if ((wallet.IsMine(out) & ISMINE_SPENDABLE) && n != result.deliver_output_index) {
                        mark_change = true;
                    }
                }
            }
            if (mark_change) {
                result.change_indices.push_back(n);
            }
        }
    }

    return result;
}

static std::optional<VaultMetadata> GetForwardVaultMetadataForOutpoint(CWallet& wallet,
                                                                       const COutPoint& outpoint,
                                                                       const CScript& base_spk)
{
    std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(base_spk);
    if (managers.empty()) {
        for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
            if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                managers.insert(manager);
            }
        }
    }
    if (managers.empty()) return std::nullopt;

    CScript covenant_spk;
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx = wallet.GetWalletTx(Txid::FromUint256(outpoint.hash));
        if (wtx && outpoint.n < wtx->tx->vout.size()) {
            covenant_spk = wtx->tx->vout[outpoint.n].scriptPubKey;
        }
    }
    if (covenant_spk.empty()) return std::nullopt;

    for (ScriptPubKeyMan* manager : managers) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;
        auto metadata = desc_spkm->GetVaultMetadata(covenant_spk);
        if (metadata) return metadata;
    }

    return std::nullopt;
}

static std::optional<VaultMetadata> GetForwardVaultMetadataByScript(CWallet& wallet,
                                                                    const CScript& script)
{
    std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(script);
    if (managers.empty()) {
        for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
            if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                managers.insert(manager);
            }
        }
    }
    if (managers.empty()) return std::nullopt;

    for (ScriptPubKeyMan* manager : managers) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;
        if (auto metadata = desc_spkm->GetVaultMetadata(script)) {
            return metadata;
        }
    }
    return std::nullopt;
}

// Helper to find vault scriptPubKey by contract_id and role for UTXO discovery
static std::optional<CScript> GetVaultScriptByRole(CWallet& wallet,
                                                     const uint256& contract_id,
                                                     VaultRole role)
{
    LOCK(wallet.cs_wallet);

    // Iterate through all SPKMs to find vaults
    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc_spkm) continue;

        // Get all scripts from this SPKM
        auto scripts = desc_spkm->GetScriptPubKeys();
        for (const CScript& script : scripts) {
            auto vault_meta = desc_spkm->GetVaultMetadata(script);
            if (!vault_meta) continue;

            // Check if this vault matches our contract_id and role
            if (vault_meta->contract_id == contract_id && vault_meta->role == role) {
                return script;
            }
        }
    }

    return std::nullopt;
}

static std::optional<VaultMetadata> GetForwardVaultMetadataByRole(CWallet& wallet,
                                                                  const ForwardContractRecord& record,
                                                                  VaultRole role)
{
    auto script_opt = GetVaultScriptByRole(wallet, record.contract_id, role);
    if (!script_opt) {
        return std::nullopt;
    }
    return GetForwardVaultMetadataByScript(wallet, *script_opt);
}

// Generic: find vault metadata by (contract_id, role) across all SPKMs. Returns nullopt
// if not uniquely resolvable (0 or >1 matches).
static std::optional<VaultMetadata> GetVaultMetadataByContractRole(CWallet& wallet,
                                                                   const uint256& contract_id,
                                                                   VaultRole role)
{
    std::optional<VaultMetadata> found;
    size_t matches = 0;
    LOCK(wallet.cs_wallet);
    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc_spkm) continue;
        auto scripts = desc_spkm->GetScriptPubKeys();
        for (const CScript& script : scripts) {
            if (auto meta = desc_spkm->GetVaultMetadata(script)) {
                if (meta->contract_id == contract_id && meta->role == role) {
                    if (!found) {
                        found = *meta;
                    }
                    matches++;
                }
            }
        }
    }
    if (matches > 1) {
        LogPrintf("VaultRegistry: contract %s role %d has %zu matching metadata entries (returning first)\n",
                  contract_id.GetHex(), static_cast<int>(role), matches);
    }
    return found;
}

// Synthesize witness_utxo for PSBT input if not set (watch-only path)
static void SynthesizeWitnessUTXOIfMissing(PartiallySignedTransaction& psbt,
                                           size_t input_index,
                                           const CScript& spk,
                                           CAmount value)
{
    CTxOut tmp;
    if (psbt.GetInputUTXO(tmp, input_index)) return;
    CTxOut utxo;
    utxo.scriptPubKey = spk;
    utxo.nValue = value;
    psbt.inputs[input_index].witness_utxo = utxo;
}

// Annotate a PSBT input for tapscript signing of a specific leaf purpose in a vault
static void AnnotateTapLeafForSigning(CWallet& wallet,
                                      PSBTInput& psbt_in,
                                      const VaultMetadata& vault,
                                      const std::string& purpose,
                                      const CTxDestination& signing_dest)
{
    const TaprootSpendData& spenddata = vault.spenddata;
    psbt_in.m_tap_internal_key = spenddata.internal_key;
    psbt_in.m_tap_merkle_root = spenddata.merkle_root;

    const VaultLeafDescriptor* leaf = FindForwardLeafByPurpose(vault, purpose);
    if (!leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Vault missing leaf '%s'", purpose));
    }
    // Prune to exact leaf
    psbt_in.m_tap_scripts.clear();
    auto it = spenddata.scripts.find({leaf->script, leaf->leaf_version});
    if (it != spenddata.scripts.end()) {
        psbt_in.m_tap_scripts[{leaf->script, leaf->leaf_version}] = it->second;
    }

    // Annotate BIP32 derivation for signing key on this leaf
    const uint256 leaf_hash = ComputeTapleafHash(
        leaf->leaf_version,
        std::span<const unsigned char>(leaf->script.data(), leaf->script.size()));
    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(signing_dest));
    if (provider) {
        KeyOriginInfo origin;
        CPubKey full_pub;
        if (provider->GetKeyOriginByXOnly(leaf->signing_key, origin)) {
            auto& deriv = psbt_in.m_tap_bip32_paths[leaf->signing_key];
            deriv.first.insert(leaf_hash);
            deriv.second = origin;
            if (provider->GetPubKeyByXOnly(leaf->signing_key, full_pub)) {
                psbt_in.hd_keypaths.emplace(full_pub, origin);
            }
        }
    }
    // Drop any other derivations
    for (auto it2 = psbt_in.m_tap_bip32_paths.begin(); it2 != psbt_in.m_tap_bip32_paths.end();) {
        if (it2->first == leaf->signing_key) {
            ++it2;
        } else {
            it2 = psbt_in.m_tap_bip32_paths.erase(it2);
        }
    }

    // CRITICAL: Embed explicit vault signing intent to prevent wrong-leaf selection
    // This ensures the signer will enforce the exact leaf specified here, rather than
    // heuristically picking "any satisfiable leaf" which can lead to timelock failures.
    VaultSigningIntent intent = CreateIntentFromLeaf(*leaf, spenddata);
    if (!EmbedVaultIntent(psbt_in, intent)) {
        LogPrintf("AnnotateTapLeafForSigning: WARNING - Failed to embed vault intent for purpose '%s'\n", purpose.c_str());
        // Don't fail hard yet - migration period allows warnings
    } else {
        LogPrintf("AnnotateTapLeafForSigning: Embedded vault intent for purpose '%s', leaf hash %s\n",
                 purpose.c_str(), intent.tapleaf_hash.ToString().c_str());
    }
}

// Build the tapscript witness for a vault leaf using a wallet-controlled key.
static void FinalizeVaultTaprootLeafWitness(CWallet& wallet,
                                            PartiallySignedTransaction& psbt,
                                            size_t input_index,
                                            const VaultMetadata& vault,
                                            const VaultLeafDescriptor& leaf,
                                            CKey& signing_key,
                                            const char* log_context)
{
    CPubKey full_pub = signing_key.GetPubKey();
    XOnlyPubKey signing_xonly(full_pub);
    if (signing_xonly != leaf.signing_key) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("%s: Derived public key does not match expected tapscript key", log_context));
    }

    const uint256 leaf_hash = ComputeTapleafHash(
        leaf.leaf_version,
        std::span<const unsigned char>(leaf.script.data(), leaf.script.size()));

    const TaprootSpendData& spenddata = vault.spenddata;
    std::vector<unsigned char> control_block;
    for (const auto& [script_pair, blocks] : spenddata.scripts) {
        const uint256 candidate_hash = ComputeTapleafHash(
            script_pair.second,
            std::span<const unsigned char>(script_pair.first.data(), script_pair.first.size()));
        if (candidate_hash == leaf_hash) {
            if (!blocks.empty()) {
                control_block = *blocks.begin();
            }
            break;
        }
    }

    if (control_block.empty()) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("%s: Control block not found for leaf '%s'", log_context, leaf.purpose));
    }

    wallet.WalletLogPrintf("%s: Control block size=%zu\n", log_context, control_block.size());

    PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_hash;

    uint256 sighash;
    if (!SignatureHashSchnorr(sighash,
                              execdata,
                              *psbt.tx,
                              input_index,
                              SIGHASH_DEFAULT,
                              SigVersion::TAPSCRIPT,
                              txdata,
                              MissingDataBehavior::FAIL)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("%s: Failed to compute tapscript sighash", log_context));
    }

    std::array<unsigned char, 64> sig_array;
    const uint256 aux_rand = GetRandHash();
    if (!signing_key.SignSchnorr(sighash, sig_array, /*merkle_root=*/nullptr, aux_rand)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("%s: Failed to create Schnorr signature", log_context));
    }
    std::vector<unsigned char> signature(sig_array.begin(), sig_array.end());

    if (control_block.size() < 33 || (control_block.size() - 33) % 32 != 0) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("%s: Invalid control block size: %zu", log_context, control_block.size()));
    }

    auto& psbt_in = psbt.inputs[input_index];
    psbt_in.final_script_witness.stack = {
        signature,
        leaf.script,
        control_block
    };

    wallet.WalletLogPrintf("%s: Finalized tapscript witness with %zu elements\n",
                           log_context,
                           psbt_in.final_script_witness.stack.size());
}

static bool WalletGetKeyByXOnly(CWallet& wallet,
                                const XOnlyPubKey& key,
                                CKey& out_key)
{
    LOCK(wallet.cs_wallet);
    for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;
        if (desc_spkm->GetKeyByXOnly(key, out_key) && out_key.IsValid()) {
            return true;
        }
    }
    return false;
}

static bool ScriptContainsOpcode(const CScript& script, opcodetype opcode)
{
    CScript::const_iterator it = script.begin();
    opcodetype op;
    std::vector<unsigned char> data;
    while (script.GetOp(it, op, data)) {
        if (op == opcode) return true;
    }
    return false;
}

static const VaultLeafDescriptor* FindForwardLeafByPurpose(const VaultMetadata& vault,
                                                           const std::string& purpose)
{
    [[maybe_unused]] int index = 0;
    for (const auto& leaf : vault.leaves) {
        CScript script(leaf.script.begin(), leaf.script.end());
        [[maybe_unused]] const bool has_cltv = ScriptContainsOpcode(script, OP_CHECKLOCKTIMEVERIFY);
        [[maybe_unused]] const bool has_csv = ScriptContainsOpcode(script, OP_CHECKSEQUENCEVERIFY);
        [[maybe_unused]] const uint256 leaf_hash = ComputeTapleafHash(static_cast<unsigned char>(leaf.leaf_version),
            std::span<const unsigned char>(leaf.script.data(), leaf.script.size()));
        if (leaf.purpose == purpose) {
            return &leaf;
        }
        ++index;
    }
    return nullptr;
}

static void EnsureForwardKeyCached(CWallet& wallet,
                                   const CTxDestination& dest,
                                   const XOnlyPubKey& key)
{
    const CScript script = GetScriptForDestination(dest);
    std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(script);

    if (managers.empty()) {
        LogPrintf("EnsureForwardKeyCached: Direct lookup failed for %s, trying all SPKMs\n",
                  EncodeDestination(dest));
    }

    // We need *every* descriptor SPKM in the cache pass, even if the direct lookup worked.
    std::set<ScriptPubKeyMan*> cache_targets;
    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        if (spkm && dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)) {
            cache_targets.insert(spkm);
            managers.insert(spkm);
        }
    }

    if (managers.empty()) {
        LogPrintf("EnsureForwardKeyCached: No descriptor managers found for key %s\n", HexStr(key));
        return;
    }

    // Step 1: Retrieve the private key from ANY SPKM that can derive it
    CKey private_key;
    bool key_found = false;
    for (ScriptPubKeyMan* manager : managers) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;
        if (desc_spkm->GetKeyByXOnly(key, private_key)) {
            key_found = true;
            LogPrintf("EnsureForwardKeyCached: Retrieved key %s from SPKM %s\n",
                      HexStr(key), HexStr(desc_spkm->GetID()));
            break;  // Got the key, now cache it everywhere
        }
    }

    if (!key_found) {
        LogPrintf("EnsureForwardKeyCached: WARNING - Failed to retrieve key %s from any SPKM\n", HexStr(key));
        return;
    }

    // Step 2: Cache the recovered key in ALL descriptor SPKMs
    // This ensures that whichever SPKM the signing logic touches first will have the key
    bool key_cached = false;
    for (ScriptPubKeyMan* manager : cache_targets) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;
        if (desc_spkm->CacheVaultKey(key, private_key)) {
            LogPrintf("EnsureForwardKeyCached: Successfully cached key %s in SPKM %s vault registry\n",
                      HexStr(key), HexStr(desc_spkm->GetID()));
            key_cached = true;
        } else {
            LogPrintf("EnsureForwardKeyCached: WARNING - CacheVaultKey returned false for key %s in SPKM %s\n",
                      HexStr(key), HexStr(desc_spkm->GetID()));
        }
    }

    if (!key_cached) {
        LogPrintf("EnsureForwardKeyCached: WARNING - Failed to cache key %s in any manager\n", HexStr(key));
    }
}

static bool WalletHasForwardKey(CWallet& wallet,
                                const CTxDestination& dest,
                                const XOnlyPubKey& key)
{
    EnsureForwardKeyCached(wallet, dest, key);

    const CScript script = GetScriptForDestination(dest);
    std::set<ScriptPubKeyMan*> managers = wallet.GetScriptPubKeyMans(script);
    if (managers.empty()) {
        for (ScriptPubKeyMan* manager : wallet.GetAllScriptPubKeyMans()) {
            if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                managers.insert(manager);
            }
        }
    }
    if (managers.empty()) return false;

    for (ScriptPubKeyMan* manager : managers) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
        if (!desc_spkm) continue;
        CKey priv_key;
        if (desc_spkm->GetKeyByXOnly(key, priv_key) && priv_key.IsValid()) {
            return true;
        }
    }
    return false;
}

static void VerifyForwardSignability(CWallet& wallet, const ForwardContractRecord& record)
{
    if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Forward contract missing margin internal keys - re-import counterparty payloads");
    }

    const ForwardTerms& terms = record.terms;
    const XOnlyPubKey& long_key = *record.long_margin_internal_key;
    const XOnlyPubKey& short_key = *record.short_margin_internal_key;

    std::map<VaultRole, VaultMetadata> metadata_cache;
    auto get_metadata = [&](VaultRole role) -> const VaultMetadata& {
        auto cached = metadata_cache.find(role);
        if (cached != metadata_cache.end()) return cached->second;

        auto meta_opt = GetForwardVaultMetadataByRole(wallet, record, role);
        if (!meta_opt) {
            CacheForwardVaultScripts(wallet, record);
            meta_opt = GetForwardVaultMetadataByRole(wallet, record, role);
        }
        if (!meta_opt) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("Forward contract missing vault metadata for role %s",
                          VaultRoleToString(role)));
        }
        auto [it, inserted] = metadata_cache.emplace(role, std::move(*meta_opt));
        (void)inserted;
        return it->second;
    };

    auto require_leaf = [&](VaultRole role,
                            const char* purpose,
                            const XOnlyPubKey& expected_key,
                            const CTxDestination& signing_dest,
                            const char* description)
    {
        const VaultMetadata& metadata = get_metadata(role);
        const VaultLeafDescriptor* leaf = FindForwardLeafByPurpose(metadata, purpose);
        if (!leaf) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("Forward contract missing %s leaf '%s' in %s vault",
                          description,
                          purpose,
                          VaultRoleToString(role)));
        }
        if (leaf->signing_key != expected_key) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("Leaf '%s' in %s vault uses unexpected signing key",
                          purpose,
                          VaultRoleToString(role)));
        }
        if (!WalletHasForwardKey(wallet, signing_dest, expected_key)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("Wallet missing private key for %s leaf '%s'",
                          description,
                          purpose));
        }
    };

    if (record.local_side == ForwardSide::LONG) {
        require_leaf(VaultRole::FORWARD_LONG, "self_delivery", long_key, terms.long_party.margin_dest, "long self-delivery");
        require_leaf(VaultRole::FORWARD_ESCROW_B, "b_escrow_claim", long_key, terms.long_party.margin_dest, "escrow claim");
        require_leaf(VaultRole::FORWARD_SHORT, "timeout", long_key, terms.long_party.margin_dest, "counterparty IM timeout sweep");
        require_leaf(VaultRole::FORWARD_ESCROW_A, "a_escrow_refund", long_key, terms.long_party.margin_dest, "escrow refund");
    } else {
        require_leaf(VaultRole::FORWARD_SHORT, "self_delivery", short_key, terms.short_party.margin_dest, "short self-delivery");
        require_leaf(VaultRole::FORWARD_ESCROW_A, "a_escrow_claim", short_key, terms.short_party.margin_dest, "escrow claim");
        require_leaf(VaultRole::FORWARD_LONG, "timeout", short_key, terms.short_party.margin_dest, "counterparty IM timeout sweep");
        require_leaf(VaultRole::FORWARD_ESCROW_B, "b_escrow_refund", short_key, terms.short_party.margin_dest, "escrow refund");
    }
}

static void AnnotateForwardLeafBip32(CWallet& wallet,
                                     const CTxDestination& margin_dest,
                                     const VaultMetadata& vault,
                                     const std::string& purpose,
                                     PSBTInput& psbt_in)
{
    const VaultLeafDescriptor* leaf = FindForwardLeafByPurpose(vault, purpose);
    if (!leaf) return;

    const uint256 leaf_hash = ComputeTapleafHash(
        leaf->leaf_version,
        std::span<const unsigned char>(leaf->script.data(), leaf->script.size()));

    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(margin_dest));
    if (!provider) return;

    KeyOriginInfo origin;
    CPubKey full_pub;
    if (provider->GetKeyOriginByXOnly(leaf->signing_key, origin)) {
        auto& derivation = psbt_in.m_tap_bip32_paths[leaf->signing_key];
        derivation.first.insert(leaf_hash);
        derivation.second = origin;
        if (provider->GetPubKeyByXOnly(leaf->signing_key, full_pub)) {
            psbt_in.hd_keypaths.emplace(full_pub, origin);
        }
    }
}

// Annotate all Taproot script signers for a given leaf into the PSBT's tap_bip32 map
// for keys the local wallet controls. This enables counterparties to resolve their
// signing keys even when the original PSBT did not include their BIP32 derivation.
static void AnnotateAllLeafSigners(CWallet& wallet,
                                   const std::vector<unsigned char>& leaf_script,
                                   int leaf_version,
                                   PSBTInput& psbt_in)
{
    if (leaf_script.empty()) return;

    const uint256 leaf_hash = ComputeTapleafHash(
        leaf_version,
        std::span<const unsigned char>(leaf_script.data(), leaf_script.size()));

    // Extract potential signer x-only pubkeys from the script by scanning for
    // 32-byte pushes immediately preceding CHECKSIG/VERIFY.
    std::vector<XOnlyPubKey> signers;
    {
        CScript script(leaf_script.begin(), leaf_script.end());
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
            if ((opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY) && have_pending_push && pending_push.size() == XOnlyPubKey::size()) {
                signers.emplace_back(std::span<const unsigned char>(pending_push.data(), pending_push.size()));
            }
            have_pending_push = false;
        }
    }

    if (signers.empty()) return;

    std::unique_ptr<SigningProvider> provider;
    {
        // Try a generic provider from any known SPKM; we'll check key-by-key below.
        // We don't need a specific script here as we lookup by x-only anyway.
        provider = wallet.GetSolvingProvider(CScript());
        if (!provider) return;
    }

    for (const XOnlyPubKey& xo : signers) {
        KeyOriginInfo origin;
        CPubKey full_pub;
        if (provider->GetKeyOriginByXOnly(xo, origin)) {
            auto& derivation = psbt_in.m_tap_bip32_paths[xo];
            derivation.first.insert(leaf_hash);
            derivation.second = origin;
            if (provider->GetPubKeyByXOnly(xo, full_pub)) {
                psbt_in.hd_keypaths.emplace(full_pub, origin);
            }
        }
    }
}

static UniValue BuildForwardSelfDeliveryShort(CWallet& wallet,
                                              ForwardContractRecord& record,
                                              const uint256& contract_id,
                                              const UniValue& opts,
                                              bool manual_inputs,
                                              const std::optional<uint32_t>& locktime_override,
                                              const JSONRPCRequest& request)
{
    const ForwardTerms& terms = record.terms;
    // Ensure vault scripts are cached in this wallet (both parties)
    CacheForwardVaultScripts(wallet, record);
    std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

    std::optional<COutPoint> short_vault_override;
    if (!opts.isNull()) {
        const UniValue& vault_txid_val = opts.find_value("short_vault_txid");
        const UniValue& vault_vout_val = opts.find_value("short_vault_vout");
        if (!vault_txid_val.isNull() && !vault_vout_val.isNull()) {
            auto txid_opt = uint256::FromHex(vault_txid_val.get_str());
            if (!txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid short_vault_txid");
            }
            short_vault_override = COutPoint(Txid::FromUint256(*txid_opt), vault_vout_val.getInt<uint32_t>());
        }
    }

    COutPoint short_vault;
    if (short_vault_override) {
        short_vault = *short_vault_override;
    } else if (record.short_margin_vault) {
        short_vault = *record.short_margin_vault;
    } else {
        // Look up short vault scriptPubKey from registry instead of rebuilding
        auto short_vault_spk_opt = GetVaultScriptByRole(wallet, contract_id, VaultRole::FORWARD_SHORT);
        if (!short_vault_spk_opt) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Short vault not registered in wallet registry - run forward.build_open first or pass short_vault_txid/short_vault_vout");
        }
        const CScript& short_vault_spk = *short_vault_spk_opt;

        std::optional<std::pair<COutPoint, CAmount>> located_vault;
        {
            LOCK(wallet.cs_wallet);
            CoinFilterParams discovery_filter;
            discovery_filter.only_spendable = false;
            discovery_filter.skip_locked = false;
            discovery_filter.include_immature_coinbase = true;

            CoinsResult coins = AvailableCoins(wallet, nullptr, std::nullopt, discovery_filter);
            for (const COutput& coin : coins.All()) {
                if (coin.txout.scriptPubKey == short_vault_spk) {
                    located_vault.emplace(coin.outpoint, coin.txout.nValue);
                    break;
                }
            }
        }

        if (!located_vault) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract must have short vault established or specify short_vault_txid/short_vault_vout in options");
        }
        short_vault = located_vault->first;
        record.short_margin_value = located_vault->second;
        record.short_margin_vault = short_vault;
        wallet.SetForwardMarginVault(contract_id, ForwardSide::SHORT, short_vault, located_vault->second);
    }

    // Look up B escrow scriptPubKey from registry instead of rebuilding
    auto be_escrow_spk_opt = GetVaultScriptByRole(wallet, contract_id, VaultRole::FORWARD_ESCROW_B);
    if (!be_escrow_spk_opt) {
        throw JSONRPCError(RPC_WALLET_ERROR, "B escrow vault not registered in wallet registry - run forward.build_open first");
    }
    const CScript be_escrow_spk = *be_escrow_spk_opt;

    // Extract destination from scriptPubKey
    CTxDestination be_escrow_dest;
    if (!ExtractDestination(be_escrow_spk, be_escrow_dest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract destination from B escrow scriptPubKey");
    }

    const CAmount escrow_sats = terms.short_party.deliver_leg.is_native
        ? static_cast<CAmount>(terms.short_party.deliver_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
    const CAmount margin_sats = terms.short_party.margin_leg.is_native
        ? static_cast<CAmount>(terms.short_party.margin_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

    CMutableTransaction funded_tx;
    funded_tx.version = 2;
    funded_tx.nLockTime = locktime_override.value_or(0);
    funded_tx.vin.emplace_back(short_vault);
    funded_tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;

    // Use the escrow scriptPubKey from registry (already have be_escrow_spk)
    const CScript margin_spk = GetScriptForDestination(terms.short_party.margin_dest);
    funded_tx.vout.emplace_back(escrow_sats, be_escrow_spk);
    funded_tx.vout.emplace_back(margin_sats, margin_spk);

    if (!terms.short_party.deliver_leg.is_native) {
        funded_tx.vout[0].vExt = BuildAssetTagTlv(
            terms.short_party.deliver_leg.asset_id,
            terms.short_party.deliver_leg.units
        );
    }
    if (!terms.short_party.margin_leg.is_native) {
        funded_tx.vout[1].vExt = BuildAssetTagTlv(
            terms.short_party.margin_leg.asset_id,
            terms.short_party.margin_leg.units
        );
    }

    std::set<COutPoint> skeleton_inputs_to_lock;
    bool skeleton_inputs_locked = false;
    std::vector<CTxOut> skeleton_change_outputs;  // Save skeleton change for later
    try {
    if (!terms.short_party.deliver_leg.is_native && !manual_inputs) {
        // Use sendasset skeleton for asset delivery leg
        ForwardAssetSkeletonResult skeleton = BuildForwardAssetSkeleton(
            wallet,
            request,
            terms.short_party.deliver_leg,
            be_escrow_dest,
            fee_rate_override,
            "forward.build_self_delivery_short.deliver");

        // Add skeleton inputs
        for (const CTxIn& vin : skeleton.tx.vin) {
            funded_tx.vin.push_back(vin);
        }

        // Track inputs to lock
        skeleton_inputs_to_lock = std::move(skeleton.inputs_to_lock);

        // Save skeleton change outputs for later (we'll add them after funding)
        for (size_t change_idx : skeleton.change_indices) {
            if (change_idx < skeleton.tx.vout.size()) {
                skeleton_change_outputs.push_back(skeleton.tx.vout[change_idx]);
            }
        }
    } else if (!terms.short_party.deliver_leg.is_native && manual_inputs) {
        if (!opts.isNull()) {
            const UniValue& inputs_val = opts.find_value("inputs");
            if (!inputs_val.isNull() && inputs_val.isArray()) {
                for (size_t i = 0; i < inputs_val.size(); ++i) {
                    const UniValue& input_obj = inputs_val[i].get_obj();
                    const std::string txid_hex = input_obj.find_value("txid").get_str();
                    const uint32_t vout = input_obj.find_value("vout").getInt<uint32_t>();
                    auto txid_opt = uint256::FromHex(txid_hex);
                    if (!txid_opt) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input txid");
                    }
                    funded_tx.vin.emplace_back(Txid::FromUint256(*txid_opt), vout);
                }
            }
        }
    } else if (terms.short_party.deliver_leg.is_native && !manual_inputs) {
        const CAmount required = static_cast<CAmount>(terms.short_party.deliver_leg.units);
        CAmount collected = 0;

        CCoinControl btc_cc;
        btc_cc.m_avoid_asset_utxos = true;
        btc_cc.m_include_unsafe_inputs = true;

        CoinsResult btc_candidates;
        {
            LOCK(wallet.cs_wallet);
            btc_candidates = AvailableCoins(wallet, &btc_cc);
        }

        for (const COutput& candidate : btc_candidates.All()) {
            if (!candidate.spendable) continue;
            if (assets::ParseAssetTag(candidate.txout.vExt)) continue;
            funded_tx.vin.emplace_back(candidate.outpoint);
            collected += candidate.txout.nValue;
            if (collected >= required) break;
        }

        if (collected < required) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient BTC for delivery: need %lld sats, have %lld sats",
                    static_cast<long long>(required), static_cast<long long>(collected)));
        }

        const CAmount change = collected - required;
        if (change > 0) {
            CTxOut change_out(change, GetScriptForDestination(terms.short_party.settlement_receive_dest));
            funded_tx.vout.push_back(change_out);
        }
    } else if (manual_inputs && !opts.isNull()) {
        const UniValue& inputs_val = opts.find_value("inputs");
        if (!inputs_val.isNull() && inputs_val.isArray()) {
            for (size_t i = 0; i < inputs_val.size(); ++i) {
                const UniValue& input_obj = inputs_val[i].get_obj();
                const std::string txid_hex = input_obj.find_value("txid").get_str();
                const uint32_t vout = input_obj.find_value("vout").getInt<uint32_t>();
                auto txid_opt = uint256::FromHex(txid_hex);
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input txid");
                }
                funded_tx.vin.emplace_back(Txid::FromUint256(*txid_opt), vout);
            }
        }
    }

    CCoinControl fee_control;
    fee_control.m_signal_bip125_rbf = wallet.m_signal_rbf;
    fee_control.m_include_unsafe_inputs = true;
    if (fee_rate_override) {
        const CAmount sat_per_k = static_cast<CAmount>(std::llround(*fee_rate_override * 1000.0));
        fee_control.m_feerate = CFeeRate(sat_per_k);
        fee_control.fOverrideFeeRate = true;
    }

    for (const auto& input : funded_tx.vin) {
        fee_control.Select(input.prevout);
    }

    std::vector<CRecipient> recipients;
    recipients.emplace_back(CRecipient{be_escrow_dest, escrow_sats, false});
    recipients.emplace_back(CRecipient{terms.short_party.margin_dest, margin_sats, false});

    // Include skeleton change outputs in recipients so they survive funding
    for (const CTxOut& change_out : skeleton_change_outputs) {
        CTxDestination change_dest;
        if (ExtractDestination(change_out.scriptPubKey, change_dest)) {
            recipients.emplace_back(CRecipient{change_dest, change_out.nValue, false});
        }
    }

    CMutableTransaction fee_template = funded_tx;
    fee_template.vout.clear();

    auto fund_res = FundTransaction(wallet, fee_template, recipients, std::nullopt, false, fee_control);
    if (!fund_res) {
        bilingual_str err = util::ErrorString(fund_res);
        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
    }
    const CreatedTransactionResult& tx_result = fund_res.value();

    funded_tx = CMutableTransaction(*tx_result.tx);
    funded_tx.nLockTime = locktime_override.value_or(funded_tx.nLockTime);

    // Re-apply asset tags to escrow and margin outputs (FundTransaction strips vExt)
    // Also re-apply asset tags to skeleton change outputs
    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
        CTxOut& out = funded_tx.vout[i];
        // Escrow output
        if (out.scriptPubKey == be_escrow_spk && out.nValue == escrow_sats) {
            if (!terms.short_party.deliver_leg.is_native) {
                out.vExt = BuildAssetTagTlv(terms.short_party.deliver_leg.asset_id, terms.short_party.deliver_leg.units);
            }
        }
        // Margin output
        else if (out.scriptPubKey == margin_spk && out.nValue == margin_sats) {
            if (!terms.short_party.margin_leg.is_native) {
                out.vExt = BuildAssetTagTlv(terms.short_party.margin_leg.asset_id, terms.short_party.margin_leg.units);
            }
        }
        // Skeleton change outputs
        else {
            for (const CTxOut& change_out : skeleton_change_outputs) {
                if (out.scriptPubKey == change_out.scriptPubKey && out.nValue == change_out.nValue) {
                    out.vExt = change_out.vExt;  // Restore asset tag
                    break;
                }
            }
        }
    }

    size_t vault_input_idx = SIZE_MAX;
    for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
        if (funded_tx.vin[i].prevout == short_vault) {
            vault_input_idx = i;
            break;
        }
    }
    if (vault_input_idx == SIZE_MAX) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing short vault input");
    }
    funded_tx.vin[vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    size_t actual_escrow_idx = SIZE_MAX;
    size_t actual_margin_idx = SIZE_MAX;
    const CAmount margin_value = margin_sats;

    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
        const CTxOut& out = funded_tx.vout[i];
        if (out.scriptPubKey == be_escrow_spk && out.nValue == escrow_sats && actual_escrow_idx == SIZE_MAX) {
            actual_escrow_idx = i;
        } else if (out.scriptPubKey == margin_spk && out.nValue == margin_value && actual_margin_idx == SIZE_MAX) {
            actual_margin_idx = i;
        }
    }
    if (actual_escrow_idx == SIZE_MAX || actual_margin_idx == SIZE_MAX) {
        if (actual_margin_idx == SIZE_MAX) {
            const int change_index = tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1;
            if (change_index < 0 || change_index >= static_cast<int>(funded_tx.vout.size())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing margin output and change output for refund");
            }
            CTxOut& change_out = funded_tx.vout[change_index];
            if (change_out.nValue <= margin_sats) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient change to carve out margin refund output");
            }
            change_out.nValue -= margin_sats;

            CTxOut margin_out(margin_sats, margin_spk);
            if (!terms.long_party.margin_leg.is_native) {
                margin_out.vExt = BuildAssetTagTlv(terms.long_party.margin_leg.asset_id, terms.long_party.margin_leg.units);
            }
            funded_tx.vout.push_back(margin_out);
            actual_margin_idx = funded_tx.vout.size() - 1;
        }
        if (actual_escrow_idx == SIZE_MAX) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing required outputs");
        }
    }

    PartiallySignedTransaction psbt(funded_tx);

    FeePolicySnapshot fee_snapshot;
    fee_snapshot.rbf = wallet.m_signal_rbf;
    std::vector<OutputMatchSpec> outputmatches;
    outputmatches.push_back({be_escrow_dest, terms.short_party.deliver_leg.is_native, terms.short_party.deliver_leg.units, terms.short_party.deliver_leg.asset_id});
    outputmatches.push_back({terms.short_party.margin_dest, terms.short_party.margin_leg.is_native, terms.short_party.margin_leg.units, terms.short_party.margin_leg.asset_id});
    AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
    std::vector<size_t> change_indices; if (tx_result.change_pos) change_indices.push_back(*tx_result.change_pos);
    AnnotateForwardOutputs(psbt, change_indices);

    // Ensure witness_utxo present
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* vault_wtx = wallet.GetWalletTx(Txid::FromUint256(short_vault.hash));
        if (vault_wtx && short_vault.n < vault_wtx->tx->vout.size()) {
            psbt.inputs[vault_input_idx].witness_utxo = vault_wtx->tx->vout[short_vault.n];
        }
    }
    SynthesizeWitnessUTXOIfMissing(psbt, vault_input_idx, margin_spk, margin_sats);

    // Resolve metadata and annotate leaf
    auto vault_meta = GetForwardVaultMetadataForOutpoint(wallet, short_vault, margin_spk);
    if (!vault_meta) vault_meta = GetVaultMetadataByContractRole(wallet, contract_id, VaultRole::FORWARD_SHORT);
    if (!vault_meta) throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry - run forward.build_open first");
    EnsureForwardKeyCached(wallet, terms.short_party.margin_dest, vault_meta->spenddata.internal_key);
    AnnotateTapLeafForSigning(wallet, psbt.inputs[vault_input_idx], *vault_meta, "self_delivery", terms.short_party.margin_dest);

    const VaultLeafDescriptor* self_leaf = FindForwardLeafByPurpose(*vault_meta, "self_delivery");
    if (!self_leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Vault metadata missing self_delivery leaf");
    }

    [[maybe_unused]] bool fill_complete = false;
    const auto fill_err = wallet.FillPSBT(psbt, fill_complete, SIGHASH_DEFAULT, true, true);
    if (fill_err) throw JSONRPCPSBTError(*fill_err);
    psbt.tx->vin[vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    CKey margin_priv;
    const bool have_privkey = WalletGetKeyByXOnly(wallet, self_leaf->signing_key, margin_priv);

    // Lock skeleton-selected UTXOs
    UniValue result(UniValue::VOBJ);
    if (!skeleton_inputs_to_lock.empty()) {
        LOCK(wallet.cs_wallet);
        for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
            wallet.LockCoin(outpoint);
        }
        skeleton_inputs_locked = true;

        UniValue locked_inputs(UniValue::VARR);
        for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("txid", outpoint.hash.ToString());
            entry.pushKV("vout", static_cast<int>(outpoint.n));
            locked_inputs.push_back(entry);
        }
        result.pushKV("locked_inputs", locked_inputs);
    }

    if (have_privkey) {
        FinalizeVaultTaprootLeafWitness(wallet,
                                        psbt,
                                        vault_input_idx,
                                        *vault_meta,
                                        *self_leaf,
                                        margin_priv,
                                        "forward.build_self_delivery_short");

        CMutableTransaction mtx(*psbt.tx);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!psbt.inputs[i].final_script_witness.IsNull()) {
                mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
            }
        }
        CTransaction final_tx(mtx);

        DataStream signed_psbt{};
        signed_psbt << psbt;

        result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
        result.pushKV("hex", EncodeHexTx(final_tx));
        result.pushKV("txid", final_tx.GetHash().ToString());
        result.pushKV("complete", true);
    } else {
        DataStream ssTx{};
        ssTx << psbt;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        result.pushKV("complete", false);
    }

    result.pushKV("fee", ValueFromAmount(tx_result.fee));
    result.pushKV("side", "short");
    result.pushKV("vault_input_index", static_cast<int>(vault_input_idx));
    result.pushKV("short_vault_input_index", static_cast<int>(vault_input_idx));
    result.pushKV("delivery_output_index", -1);
    result.pushKV("escrow_output_index", static_cast<int>(actual_escrow_idx));
    result.pushKV("margin_output_index", static_cast<int>(actual_margin_idx));
    result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);
    return result;
    } catch (...) {
        if (skeleton_inputs_locked) {
            LOCK(wallet.cs_wallet);
            for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
                wallet.UnlockCoin(outpoint);
            }
        }
        throw;
    }
}

static UniValue BuildForwardSelfDeliveryLong(CWallet& wallet,
                                             ForwardContractRecord& record,
                                             const uint256& contract_id,
                                             const UniValue& opts,
                                             bool manual_inputs,
                                             const std::optional<uint32_t>& locktime_override,
                                             const JSONRPCRequest& request)
{
    const ForwardTerms& terms = record.terms;
    // Ensure vault scripts are cached in this wallet (both parties)
    CacheForwardVaultScripts(wallet, record);
    std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

    std::optional<COutPoint> long_vault_override;
    if (!opts.isNull()) {
        const UniValue& vault_txid_val = opts.find_value("long_vault_txid");
        const UniValue& vault_vout_val = opts.find_value("long_vault_vout");
        if (!vault_txid_val.isNull() && !vault_vout_val.isNull()) {
            auto txid_opt = uint256::FromHex(vault_txid_val.get_str());
            if (!txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid long_vault_txid");
            }
            long_vault_override = COutPoint(Txid::FromUint256(*txid_opt), vault_vout_val.getInt<uint32_t>());
        }
    }

    COutPoint long_vault;
    if (long_vault_override) {
        long_vault = *long_vault_override;
    } else if (record.long_margin_vault) {
        long_vault = *record.long_margin_vault;
    } else {
        // Look up long vault scriptPubKey from registry instead of rebuilding
        auto long_vault_spk_opt = GetVaultScriptByRole(wallet, contract_id, VaultRole::FORWARD_LONG);
        if (!long_vault_spk_opt) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Long vault not registered in wallet registry - run forward.build_open first");
        }
        const CScript& long_vault_spk = *long_vault_spk_opt;

        std::optional<std::pair<COutPoint, CAmount>> located_vault;
        {
            LOCK(wallet.cs_wallet);
            CoinFilterParams discovery_filter;
            discovery_filter.only_spendable = false;
            discovery_filter.skip_locked = false;
            discovery_filter.include_immature_coinbase = true;

            CoinsResult coins = AvailableCoins(wallet, nullptr, std::nullopt, discovery_filter);
            for (const COutput& coin : coins.All()) {
                if (coin.txout.scriptPubKey == long_vault_spk) {
                    located_vault.emplace(coin.outpoint, coin.txout.nValue);
                    break;
                }
            }
        }

        if (!located_vault) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract must have long vault established or specify long_vault_txid/long_vault_vout in options");
        }

        long_vault = located_vault->first;
        record.long_margin_vault = long_vault;
        record.long_margin_value = located_vault->second;
        wallet.SetForwardMarginVault(contract_id, ForwardSide::LONG, long_vault, located_vault->second);
    }

    // Look up A escrow scriptPubKey from registry instead of rebuilding
    auto ae_escrow_spk_opt = GetVaultScriptByRole(wallet, contract_id, VaultRole::FORWARD_ESCROW_A);
    if (!ae_escrow_spk_opt) {
        throw JSONRPCError(RPC_WALLET_ERROR, "A escrow vault not registered in wallet registry - run forward.build_open first");
    }
    const CScript ae_escrow_spk = *ae_escrow_spk_opt;

    // Extract destination from scriptPubKey
    CTxDestination ae_escrow_dest;
    if (!ExtractDestination(ae_escrow_spk, ae_escrow_dest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract destination from A escrow scriptPubKey");
    }

    const CAmount escrow_sats = terms.long_party.deliver_leg.is_native
        ? static_cast<CAmount>(terms.long_party.deliver_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
    const CAmount margin_sats = terms.long_party.margin_leg.is_native
        ? static_cast<CAmount>(terms.long_party.margin_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

    const uint32_t required_locktime = terms.deadline_short;
    uint32_t tx_locktime = required_locktime;
    if (locktime_override) {
        if (*locktime_override < required_locktime) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("options.locktime must be >= %u for long self-delivery", required_locktime));
        }
        tx_locktime = *locktime_override;
    }

    CMutableTransaction funded_tx;
    funded_tx.version = 2;
    funded_tx.nLockTime = tx_locktime;
    funded_tx.vin.emplace_back(long_vault);
    funded_tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;

    // Use the escrow scriptPubKey from registry (already have ae_escrow_spk)
    const CScript margin_spk = GetScriptForDestination(terms.long_party.margin_dest);
    funded_tx.vout.emplace_back(escrow_sats, ae_escrow_spk);
    funded_tx.vout.emplace_back(margin_sats, margin_spk);

    if (!terms.long_party.deliver_leg.is_native) {
        funded_tx.vout[0].vExt = BuildAssetTagTlv(
            terms.long_party.deliver_leg.asset_id,
            terms.long_party.deliver_leg.units
        );
    }
    if (!terms.long_party.margin_leg.is_native) {
        funded_tx.vout[1].vExt = BuildAssetTagTlv(
            terms.long_party.margin_leg.asset_id,
            terms.long_party.margin_leg.units
        );
    }

    bool skeleton_inputs_locked = false;
    std::set<COutPoint> skeleton_inputs_to_lock;
    std::vector<CTxOut> skeleton_change_outputs;  // Save skeleton change for later
    try {
    if (!terms.long_party.deliver_leg.is_native && !manual_inputs) {
        // Use sendasset skeleton for asset delivery leg
        ForwardAssetSkeletonResult skeleton = BuildForwardAssetSkeleton(
            wallet,
            request,
            terms.long_party.deliver_leg,
            ae_escrow_dest,
            fee_rate_override,
            "forward.build_self_delivery_long.deliver");

        // Add skeleton inputs
        for (const CTxIn& vin : skeleton.tx.vin) {
            funded_tx.vin.push_back(vin);
        }

        // Track inputs to lock
        skeleton_inputs_to_lock = std::move(skeleton.inputs_to_lock);

        // Save skeleton change outputs for later (we'll add them after funding)
        for (size_t change_idx : skeleton.change_indices) {
            if (change_idx < skeleton.tx.vout.size()) {
                skeleton_change_outputs.push_back(skeleton.tx.vout[change_idx]);
            }
        }
    } else if (!terms.long_party.deliver_leg.is_native && manual_inputs) {
        if (!opts.isNull()) {
            const UniValue& inputs_val = opts.find_value("inputs");
            if (!inputs_val.isNull() && inputs_val.isArray()) {
                for (size_t i = 0; i < inputs_val.size(); ++i) {
                    const UniValue& input_obj = inputs_val[i].get_obj();
                    const std::string txid_hex = input_obj.find_value("txid").get_str();
                    const uint32_t vout = input_obj.find_value("vout").getInt<uint32_t>();
                    auto txid_opt = uint256::FromHex(txid_hex);
                    if (!txid_opt) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input txid");
                    }
                    funded_tx.vin.emplace_back(Txid::FromUint256(*txid_opt), vout);
                }
            }
        }
    } else if (terms.long_party.deliver_leg.is_native && !manual_inputs) {
        const CAmount required = static_cast<CAmount>(terms.long_party.deliver_leg.units);
        CAmount collected = 0;

        CCoinControl btc_cc;
        btc_cc.m_avoid_asset_utxos = true;
        btc_cc.m_include_unsafe_inputs = true;

        CoinsResult btc_candidates;
        {
            LOCK(wallet.cs_wallet);
            btc_candidates = AvailableCoins(wallet, &btc_cc);
        }

        for (const COutput& candidate : btc_candidates.All()) {
            if (!candidate.spendable) continue;
            if (assets::ParseAssetTag(candidate.txout.vExt)) continue;
            funded_tx.vin.emplace_back(candidate.outpoint);
            collected += candidate.txout.nValue;
            if (collected >= required) break;
        }

        if (collected < required) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient BTC for delivery: need %lld sats, have %lld sats",
                    static_cast<long long>(required), static_cast<long long>(collected)));
        }

        const CAmount change = collected - required;
        if (change > 0) {
            CTxOut change_out(change, GetScriptForDestination(terms.long_party.settlement_receive_dest));
            funded_tx.vout.push_back(change_out);
        }
    } else if (manual_inputs && !opts.isNull()) {
        const UniValue& inputs_val = opts.find_value("inputs");
        if (!inputs_val.isNull() && inputs_val.isArray()) {
            for (size_t i = 0; i < inputs_val.size(); ++i) {
                const UniValue& input_obj = inputs_val[i].get_obj();
                const std::string txid_hex = input_obj.find_value("txid").get_str();
                const uint32_t vout = input_obj.find_value("vout").getInt<uint32_t>();
                auto txid_opt = uint256::FromHex(txid_hex);
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input txid");
                }
                funded_tx.vin.emplace_back(Txid::FromUint256(*txid_opt), vout);
            }
        }
    }

    CCoinControl fee_control;
    fee_control.m_signal_bip125_rbf = wallet.m_signal_rbf;
    fee_control.m_include_unsafe_inputs = true;
    if (fee_rate_override) {
        const CAmount sat_per_k = static_cast<CAmount>(std::llround(*fee_rate_override * 1000.0));
        fee_control.m_feerate = CFeeRate(sat_per_k);
        fee_control.fOverrideFeeRate = true;
    }

    for (const auto& input : funded_tx.vin) {
        fee_control.Select(input.prevout);
    }

    std::vector<CRecipient> recipients;
    recipients.emplace_back(CRecipient{ae_escrow_dest, escrow_sats, false});
    recipients.emplace_back(CRecipient{terms.long_party.margin_dest, margin_sats, false});

    // Include skeleton change outputs in recipients so they survive funding
    for (const CTxOut& change_out : skeleton_change_outputs) {
        CTxDestination change_dest;
        if (ExtractDestination(change_out.scriptPubKey, change_dest)) {
            recipients.emplace_back(CRecipient{change_dest, change_out.nValue, false});
        }
    }

    CMutableTransaction fee_template = funded_tx;
    fee_template.vout.clear();

    auto fund_res = FundTransaction(wallet, fee_template, recipients, std::nullopt, false, fee_control);
    if (!fund_res) {
        bilingual_str err = util::ErrorString(fund_res);
        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
    }
    const CreatedTransactionResult& tx_result = fund_res.value();

    funded_tx = CMutableTransaction(*tx_result.tx);
    funded_tx.nLockTime = tx_locktime;

    // Re-apply asset tags to escrow and margin outputs (FundTransaction strips vExt)
    // Also re-apply asset tags to skeleton change outputs
    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
        CTxOut& out = funded_tx.vout[i];
        // Escrow output
        if (out.scriptPubKey == ae_escrow_spk && out.nValue == escrow_sats) {
            if (!terms.long_party.deliver_leg.is_native) {
                out.vExt = BuildAssetTagTlv(terms.long_party.deliver_leg.asset_id, terms.long_party.deliver_leg.units);
            }
        }
        // Margin output
        else if (out.scriptPubKey == margin_spk && out.nValue == margin_sats) {
            if (!terms.long_party.margin_leg.is_native) {
                out.vExt = BuildAssetTagTlv(terms.long_party.margin_leg.asset_id, terms.long_party.margin_leg.units);
            }
        }
        // Skeleton change outputs
        else {
            for (const CTxOut& change_out : skeleton_change_outputs) {
                if (out.scriptPubKey == change_out.scriptPubKey && out.nValue == change_out.nValue) {
                    out.vExt = change_out.vExt;  // Restore asset tag
                    break;
                }
            }
        }
    }

    size_t vault_input_idx = SIZE_MAX;
    for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
        if (funded_tx.vin[i].prevout == long_vault) {
            vault_input_idx = i;
            break;
        }
    }
    if (vault_input_idx == SIZE_MAX) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing long vault input");
    }
    funded_tx.vin[vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    size_t actual_escrow_idx = SIZE_MAX;
    size_t actual_margin_idx = SIZE_MAX;
    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
        const CTxOut& out = funded_tx.vout[i];
        if (out.scriptPubKey == ae_escrow_spk && out.nValue == escrow_sats && actual_escrow_idx == SIZE_MAX) {
            actual_escrow_idx = i;
        } else if (out.scriptPubKey == margin_spk && out.nValue == margin_sats && actual_margin_idx == SIZE_MAX) {
            actual_margin_idx = i;
        }
    }
    if (actual_escrow_idx == SIZE_MAX || actual_margin_idx == SIZE_MAX) {
        if (actual_margin_idx == SIZE_MAX) {
            const int change_index = tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1;
            if (change_index < 0 || change_index >= static_cast<int>(funded_tx.vout.size())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing margin output and change output for refund");
            }
            CTxOut& change_out = funded_tx.vout[change_index];
            if (change_out.nValue <= margin_sats) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient change to carve out margin refund output");
            }
            change_out.nValue -= margin_sats;

            CTxOut margin_out(margin_sats, margin_spk);
            if (!terms.long_party.margin_leg.is_native) {
                margin_out.vExt = BuildAssetTagTlv(terms.long_party.margin_leg.asset_id, terms.long_party.margin_leg.units);
            }
            funded_tx.vout.push_back(margin_out);
            actual_margin_idx = funded_tx.vout.size() - 1;
        }
        if (actual_escrow_idx == SIZE_MAX) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing required outputs");
        }
    }

    PartiallySignedTransaction psbt(funded_tx);

    FeePolicySnapshot fee_snapshot; fee_snapshot.rbf = wallet.m_signal_rbf;
    std::vector<OutputMatchSpec> outputmatches;
    outputmatches.push_back({ae_escrow_dest, terms.long_party.deliver_leg.is_native, terms.long_party.deliver_leg.units, terms.long_party.deliver_leg.asset_id});
    outputmatches.push_back({terms.long_party.margin_dest, terms.long_party.margin_leg.is_native, terms.long_party.margin_leg.units, terms.long_party.margin_leg.asset_id});
    AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
    std::vector<size_t> change_indices; if (tx_result.change_pos) change_indices.push_back(*tx_result.change_pos);
    AnnotateForwardOutputs(psbt, change_indices);

    // Ensure witness_utxo present
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* vault_wtx = wallet.GetWalletTx(Txid::FromUint256(long_vault.hash));
        if (vault_wtx && long_vault.n < vault_wtx->tx->vout.size()) {
            psbt.inputs[vault_input_idx].witness_utxo = vault_wtx->tx->vout[long_vault.n];
        }
    }
    SynthesizeWitnessUTXOIfMissing(psbt, vault_input_idx, margin_spk, margin_sats);

    // Resolve metadata and annotate leaf
    auto vault_meta = GetForwardVaultMetadataForOutpoint(wallet, long_vault, margin_spk);
    if (!vault_meta) vault_meta = GetVaultMetadataByContractRole(wallet, contract_id, VaultRole::FORWARD_LONG);
    if (!vault_meta) throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry - run forward.build_open first");
    EnsureForwardKeyCached(wallet, terms.long_party.margin_dest, vault_meta->spenddata.internal_key);
    AnnotateTapLeafForSigning(wallet, psbt.inputs[vault_input_idx], *vault_meta, "self_delivery", terms.long_party.margin_dest);

    const VaultLeafDescriptor* self_leaf = FindForwardLeafByPurpose(*vault_meta, "self_delivery");
    if (!self_leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Vault metadata missing self_delivery leaf");
    }

    [[maybe_unused]] bool fill_complete = false;
    const auto fill_err = wallet.FillPSBT(psbt, fill_complete, SIGHASH_DEFAULT, true, true);
    if (fill_err) throw JSONRPCPSBTError(*fill_err);
    psbt.tx->vin[vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    CKey margin_priv;
    const bool have_privkey = WalletGetKeyByXOnly(wallet, self_leaf->signing_key, margin_priv);

    UniValue result(UniValue::VOBJ);

    if (have_privkey) {
        FinalizeVaultTaprootLeafWitness(wallet,
                                        psbt,
                                        vault_input_idx,
                                        *vault_meta,
                                        *self_leaf,
                                        margin_priv,
                                        "forward.build_self_delivery_long");

        CMutableTransaction mtx(*psbt.tx);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!psbt.inputs[i].final_script_witness.IsNull()) {
                mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
            }
        }
        CTransaction final_tx(mtx);

        DataStream signed_psbt{};
        signed_psbt << psbt;

        result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
        result.pushKV("hex", EncodeHexTx(final_tx));
        result.pushKV("txid", final_tx.GetHash().ToString());
        result.pushKV("complete", true);
    } else {
        DataStream ssTx{};
        ssTx << psbt;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        result.pushKV("complete", false);
    }

    if (!skeleton_inputs_to_lock.empty()) {
        LOCK(wallet.cs_wallet);
        for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
            wallet.LockCoin(outpoint);
        }
        skeleton_inputs_locked = true;

        UniValue locked_inputs(UniValue::VARR);
        for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("txid", outpoint.hash.ToString());
            entry.pushKV("vout", static_cast<int>(outpoint.n));
            locked_inputs.push_back(entry);
        }
        result.pushKV("locked_inputs", locked_inputs);
    }

    result.pushKV("fee", ValueFromAmount(tx_result.fee));
    result.pushKV("side", "long");
    result.pushKV("vault_input_index", static_cast<int>(vault_input_idx));
    result.pushKV("long_vault_input_index", static_cast<int>(vault_input_idx));
    result.pushKV("escrow_output_index", static_cast<int>(actual_escrow_idx));
    result.pushKV("margin_output_index", static_cast<int>(actual_margin_idx));
    result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);
    return result;
    } catch (...) {
        if (skeleton_inputs_locked) {
            LOCK(wallet.cs_wallet);
            for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
                wallet.UnlockCoin(outpoint);
            }
        }
        throw;
    }
}

static UniValue BuildForwardEscrowClaimLong(CWallet& wallet,
                                            const JSONRPCRequest& request,
                                            const ForwardContractRecord& record,
                                            const COutPoint& escrow_outpoint,
                                            const std::optional<COutPoint>& vault_outpoint,
                                            bool manual_inputs,
                                            const std::optional<uint32_t>& locktime_override,
                                            const UniValue& opts)
{
    const ForwardTerms& terms = record.terms;
    std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = locktime_override.value_or(0);
    // Note: counter_delivery leaf has NO CLTV, so no nLockTime requirement

    tx.vin.emplace_back(escrow_outpoint);
    tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;
    const size_t escrow_input_idx = 0;

    // Add vault input if provided (needed for margin recovery + native BTC in multi-asset contracts)
    std::optional<size_t> vault_input_idx;
    if (vault_outpoint) {
        tx.vin.emplace_back(*vault_outpoint);
        tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;
        vault_input_idx = tx.vin.size() - 1;
    }

    // First: Create claim output (from escrow)
    CTxOut claim_out;
    claim_out.scriptPubKey = GetScriptForDestination(terms.long_party.settlement_receive_dest);
    const CAmount claim_sats = terms.short_party.deliver_leg.is_native
        ? static_cast<CAmount>(terms.short_party.deliver_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
    claim_out.nValue = claim_sats;
    if (!terms.short_party.deliver_leg.is_native) {
        claim_out.vExt = BuildAssetTagTlv(terms.short_party.deliver_leg.asset_id, terms.short_party.deliver_leg.units);
    }
    tx.vout.push_back(claim_out);
    const size_t claim_output_idx = tx.vout.size() - 1;

    // Add vault margin output if vault input is provided
    std::optional<size_t> margin_output_idx;
    if (vault_outpoint) {
        CTxOut margin_out;
        margin_out.scriptPubKey = GetScriptForDestination(terms.long_party.margin_dest);
        const CAmount margin_sats = terms.long_party.margin_leg.is_native
            ? static_cast<CAmount>(terms.long_party.margin_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        margin_out.nValue = margin_sats;
        if (!terms.long_party.margin_leg.is_native) {
            margin_out.vExt = BuildAssetTagTlv(terms.long_party.margin_leg.asset_id, terms.long_party.margin_leg.units);
        }
        tx.vout.push_back(margin_out);
        margin_output_idx = tx.vout.size() - 1;
    }

    std::set<COutPoint> skeleton_inputs_to_lock;
    std::vector<CTxOut> skeleton_change_outputs;
    std::vector<size_t> change_output_indices;
    size_t payment_output_idx = SIZE_MAX;

    // Second: Handle payment output (to short party)
    if (!terms.long_party.deliver_leg.is_native && !manual_inputs) {
        // Use sendasset skeleton for asset payment leg
        ForwardAssetSkeletonResult skeleton = BuildForwardAssetSkeleton(
            wallet,
            request,
            terms.long_party.deliver_leg,
            terms.short_party.settlement_receive_dest,
            fee_rate_override,
            "forward.build_escrow_claim.payment");

        // Add skeleton inputs
        for (const CTxIn& vin : skeleton.tx.vin) {
            tx.vin.push_back(vin);
        }

        // Use skeleton's delivery output as payment (includes full ICU/KYC metadata!)
        if (skeleton.deliver_output_index && *skeleton.deliver_output_index < skeleton.tx.vout.size()) {
            tx.vout.push_back(skeleton.tx.vout[*skeleton.deliver_output_index]);
            payment_output_idx = tx.vout.size() - 1;
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Skeleton missing delivery output");
        }

        // Track inputs to lock
        skeleton_inputs_to_lock = std::move(skeleton.inputs_to_lock);

        // Append skeleton change outputs to transaction and track their indices
        for (size_t change_idx : skeleton.change_indices) {
            if (change_idx < skeleton.tx.vout.size()) {
                tx.vout.push_back(skeleton.tx.vout[change_idx]);
                skeleton_change_outputs.push_back(skeleton.tx.vout[change_idx]);
                change_output_indices.push_back(tx.vout.size() - 1);
            }
        }
    } else if (terms.long_party.deliver_leg.is_native && !manual_inputs) {
        const CAmount btc_needed = static_cast<CAmount>(terms.long_party.deliver_leg.units);

        CFeeRate eff_fee_rate;
        if (fee_rate_override) {
            eff_fee_rate = CFeeRate(static_cast<CAmount>(*fee_rate_override * 1000)); // sat/vB -> sat/kB
        } else if (wallet.m_pay_tx_fee != CFeeRate(0)) {
            eff_fee_rate = wallet.m_pay_tx_fee;
        } else {
            eff_fee_rate = CFeeRate(1000); // Default to 1 sat/vB
        }

        CoinsResult btc_candidates;
        {
            CCoinControl scan_control;
            scan_control.m_signal_bip125_rbf = wallet.m_signal_rbf;
            scan_control.m_avoid_asset_utxos = true;
            LOCK(wallet.cs_wallet);
            btc_candidates = AvailableCoins(wallet, &scan_control);
        }

        CAmount btc_total = 0;
        std::vector<COutPoint> selected_inputs;
        for (const COutput& candidate : btc_candidates.All()) {
            if (!candidate.spendable) continue;
            if (assets::ParseAssetTag(candidate.txout.vExt)) continue;
            selected_inputs.push_back(candidate.outpoint);
            btc_total += candidate.txout.nValue;
            if (btc_total >= btc_needed) break;
        }

        if (btc_total < btc_needed) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient BTC for payment (need %lld sats, have %lld sats)",
                    static_cast<long long>(btc_needed), static_cast<long long>(btc_total)));
        }

        for (const COutPoint& outpoint : selected_inputs) {
            CTxIn new_in(outpoint);
            new_in.nSequence = MAX_BIP125_RBF_SEQUENCE;
            tx.vin.emplace_back(std::move(new_in));
        }

        // Payment output to short party
        CTxOut payment_out(btc_needed, GetScriptForDestination(terms.short_party.settlement_receive_dest));
        tx.vout.push_back(payment_out);
        payment_output_idx = tx.vout.size() - 1;

        // Change output placeholder
        CAmount btc_change = btc_total - btc_needed;
        int change_pos = -1;
        if (btc_change > 0) {
            CTxOut change_out(btc_change, GetScriptForDestination(terms.long_party.settlement_receive_dest));
            tx.vout.push_back(change_out);
            change_pos = tx.vout.size() - 1;
        }

        auto compute_fee = [&](const CMutableTransaction& tx_template) -> CAmount {
            const CTransaction tx_final(tx_template);
            return eff_fee_rate.GetFee(GetVirtualTransactionSize(tx_final));
        };

        CAmount required_fee = compute_fee(tx);
        if (change_pos != -1) {
            CAmount available_for_fee = btc_change;
            CAmount adjusted_change = available_for_fee - required_fee;
            if (adjusted_change > 0) {
                tx.vout[change_pos].nValue = adjusted_change;
            } else {
                tx.vout.pop_back();
                change_pos = -1;
                required_fee = compute_fee(tx);
            }
        } else {
            if (btc_total < btc_needed + required_fee) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient BTC to cover payment fee (need %lld sats, have %lld sats)",
                              static_cast<long long>(btc_needed + required_fee), static_cast<long long>(btc_total)));
            }
        }

        if (change_pos != -1) {
            change_output_indices.push_back(static_cast<size_t>(change_pos));
        }
    } else if (manual_inputs && !opts.isNull()) {
        const UniValue& inputs_val = opts.find_value("inputs");
        if (!inputs_val.isNull() && inputs_val.isArray()) {
            for (size_t i = 0; i < inputs_val.size(); ++i) {
                const UniValue& input_obj = inputs_val[i].get_obj();
                const std::string txid_hex = input_obj.find_value("txid").get_str();
                const uint32_t vout = input_obj.find_value("vout").getInt<uint32_t>();
                auto txid_opt = uint256::FromHex(txid_hex);
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input txid");
                }
                tx.vin.emplace_back(Txid::FromUint256(*txid_opt), vout);
            }
        }

        // Create payment output manually (user provided inputs, but outputs follow contract terms)
        CTxOut payment_out;
        payment_out.scriptPubKey = GetScriptForDestination(terms.short_party.settlement_receive_dest);
        const CAmount payment_sats = terms.long_party.deliver_leg.is_native
            ? static_cast<CAmount>(terms.long_party.deliver_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        payment_out.nValue = payment_sats;
        if (!terms.long_party.deliver_leg.is_native) {
            payment_out.vExt = BuildAssetTagTlv(terms.long_party.deliver_leg.asset_id, terms.long_party.deliver_leg.units);
        }
        tx.vout.push_back(payment_out);
        payment_output_idx = tx.vout.size() - 1;
    }

    PartiallySignedTransaction psbt(tx);

    FeePolicySnapshot fee_snapshot;
    fee_snapshot.rbf = wallet.m_signal_rbf;

    std::vector<OutputMatchSpec> outputmatches;
    outputmatches.push_back({
        terms.short_party.settlement_receive_dest,
        terms.long_party.deliver_leg.is_native,
        terms.long_party.deliver_leg.units,
        terms.long_party.deliver_leg.asset_id
    });
    outputmatches.push_back({
        terms.long_party.settlement_receive_dest,
        terms.short_party.deliver_leg.is_native,
        terms.short_party.deliver_leg.units,
        terms.short_party.deliver_leg.asset_id
    });

    AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
    AnnotateForwardOutputs(psbt, change_output_indices);

    [[maybe_unused]] bool fill_complete = false;
    const auto fill_err = wallet.FillPSBT(psbt, fill_complete, SIGHASH_DEFAULT, true, true);
    if (fill_err) {
        throw JSONRPCPSBTError(*fill_err);
    }
    psbt.tx->vin[escrow_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* escrow_wtx = wallet.GetWalletTx(Txid::FromUint256(escrow_outpoint.hash));
        if (escrow_wtx && escrow_outpoint.n < escrow_wtx->tx->vout.size()) {
            psbt.inputs[escrow_input_idx].witness_utxo = escrow_wtx->tx->vout[escrow_outpoint.n];
        }
    }

    const CScript escrow_base_spk = GetScriptForDestination(terms.short_party.settlement_receive_dest);
    auto escrow_meta = GetForwardVaultMetadataForOutpoint(wallet, escrow_outpoint, escrow_base_spk);
    if (!escrow_meta) {
        // Fallback by role when wallet lacks the broadcast tx
        escrow_meta = GetForwardVaultMetadataByRole(wallet, record, VaultRole::FORWARD_ESCROW_B);
        if (!escrow_meta) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault not registered in wallet registry - run forward.build_open first");
        }
    }
    // Synthesize witness_utxo if not available
    {
        CTxOut _utxo_check;
        if (!psbt.GetInputUTXO(_utxo_check, escrow_input_idx)) {
        CTxOut utxo;
        utxo.scriptPubKey = escrow_meta->GetScriptPubKey();
        utxo.nValue = terms.short_party.deliver_leg.is_native
            ? static_cast<CAmount>(terms.short_party.deliver_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        psbt.inputs[escrow_input_idx].witness_utxo = utxo;
        }
    }
    if (escrow_meta->role != VaultRole::FORWARD_ESCROW_B) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected escrow vault role for long claim");
    }
    auto& psbt_in = psbt.inputs[escrow_input_idx];
    const TaprootSpendData& spenddata = escrow_meta->spenddata;
    psbt_in.m_tap_internal_key = spenddata.internal_key;
    psbt_in.m_tap_merkle_root = spenddata.merkle_root;

    // Find the b_escrow_claim leaf - we ONLY want to add THIS leaf to the PSBT, not all leaves
    const VaultLeafDescriptor* claim_leaf = FindForwardLeafByPurpose(*escrow_meta, "b_escrow_claim");
    if (!claim_leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault missing b_escrow_claim leaf metadata");
    }

    // Add ONLY the claim leaf script to the PSBT (not refund leaf)
    psbt_in.m_tap_scripts.clear();
    auto script_it = spenddata.scripts.find({claim_leaf->script, claim_leaf->leaf_version});
    if (script_it != spenddata.scripts.end()) {
        psbt_in.m_tap_scripts[{claim_leaf->script, claim_leaf->leaf_version}] = script_it->second;
    }
    wallet.WalletLogPrintf("BuildForwardEscrowClaimLong: After trimming, escrow input has %zu tap_scripts\n",
                          psbt_in.m_tap_scripts.size());
    EnsureForwardKeyCached(wallet, terms.long_party.margin_dest, claim_leaf->signing_key);
    AnnotateForwardLeafBip32(wallet, terms.long_party.margin_dest, *escrow_meta, "b_escrow_claim", psbt_in);
    if (!psbt_in.m_tap_bip32_paths.count(claim_leaf->signing_key)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Wallet missing long margin signing key for b_escrow_claim; re-import counterparty payloads or rerun forward.build_open");
    }
    for (auto it = psbt_in.m_tap_bip32_paths.begin(); it != psbt_in.m_tap_bip32_paths.end(); ) {
        if (it->first == claim_leaf->signing_key) {
            ++it;
        } else {
            it = psbt_in.m_tap_bip32_paths.erase(it);
        }
    }

    // Add vault metadata if vault input is provided
    std::optional<VaultMetadata> vault_meta;
    if (vault_outpoint && vault_input_idx) {
        // Set vault witness_utxo
        {
            LOCK(wallet.cs_wallet);
            const CWalletTx* vault_wtx = wallet.GetWalletTx(Txid::FromUint256(vault_outpoint->hash));
            if (vault_wtx && vault_outpoint->n < vault_wtx->tx->vout.size()) {
                psbt.inputs[*vault_input_idx].witness_utxo = vault_wtx->tx->vout[vault_outpoint->n];
            }
        }

        // Get vault metadata from registry
        const CScript vault_margin_spk = GetScriptForDestination(terms.long_party.margin_dest);
        vault_meta = GetForwardVaultMetadataForOutpoint(wallet, *vault_outpoint, vault_margin_spk);
        if (!vault_meta) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry - run forward.build_open first");
        }
        EnsureForwardKeyCached(wallet, terms.long_party.margin_dest, vault_meta->spenddata.internal_key);

        // Add vault taproot spend data and prune to EXACT self_delivery leaf
        auto& vault_psbt_in = psbt.inputs[*vault_input_idx];
        const TaprootSpendData& vault_spenddata = vault_meta->spenddata;
        vault_psbt_in.m_tap_internal_key = vault_spenddata.internal_key;
        vault_psbt_in.m_tap_merkle_root = vault_spenddata.merkle_root;
        const VaultMetadata& vault = *vault_meta;
        const VaultLeafDescriptor* counter_leaf = FindForwardLeafByPurpose(vault, "a_counter_delivery");
        const char* target_purpose = "a_counter_delivery";
        if (!counter_leaf) {
            counter_leaf = FindForwardLeafByPurpose(vault, "self_delivery");
            target_purpose = "self_delivery";
        }
        if (!counter_leaf) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Forward long vault missing counter/self_delivery leaf metadata");
        }
        vault_psbt_in.m_tap_scripts.clear();
        if (auto it = vault_spenddata.scripts.find({counter_leaf->script, counter_leaf->leaf_version}); it != vault_spenddata.scripts.end()) {
            vault_psbt_in.m_tap_scripts[{counter_leaf->script, counter_leaf->leaf_version}] = it->second;
        }
        AnnotateForwardLeafBip32(wallet, terms.long_party.margin_dest, vault, target_purpose, vault_psbt_in);
        for (auto it = vault_psbt_in.m_tap_bip32_paths.begin(); it != vault_psbt_in.m_tap_bip32_paths.end(); ) {
            if (it->first == counter_leaf->signing_key) { ++it; } else { it = vault_psbt_in.m_tap_bip32_paths.erase(it); }
        }

        // Re-apply sequence to vault input after FillPSBT
        psbt.tx->vin[*vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    }

    // Get vault signing key if vault input is present (must be done AFTER vault block to access vault_meta)
    CKey vault_priv;
    bool have_vault_key = false;
    const VaultLeafDescriptor* vault_leaf_to_sign = nullptr;
    if (vault_meta) {
        const VaultMetadata& vault = *vault_meta;
        vault_leaf_to_sign = FindForwardLeafByPurpose(vault, "a_counter_delivery");
        if (!vault_leaf_to_sign) {
            vault_leaf_to_sign = FindForwardLeafByPurpose(vault, "self_delivery");
        }
        if (vault_leaf_to_sign) {
            have_vault_key = WalletGetKeyByXOnly(wallet, vault_leaf_to_sign->signing_key, vault_priv);
        }
    }

    // Lock skeleton-selected UTXOs
    if (!skeleton_inputs_to_lock.empty()) {
        LOCK(wallet.cs_wallet);
        for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
            wallet.LockCoin(outpoint);
        }
    }

    // Find first BTC change output for changepos result
    int btc_change_pos = -1;
    for (size_t idx : change_output_indices) {
        if (idx < psbt.tx->vout.size()) {
            const CTxOut& out = psbt.tx->vout[idx];
            // BTC change has no asset tag in vExt
            if (out.vExt.empty() || !assets::ParseAssetTag(out.vExt)) {
                btc_change_pos = static_cast<int>(idx);
                break;
            }
        }
    }

    CKey claim_priv;
    const bool have_claim_key = claim_leaf && WalletGetKeyByXOnly(wallet, claim_leaf->signing_key, claim_priv);

    UniValue result(UniValue::VOBJ);

    auto psbt_fee_amount = [&]() -> CAmount {
        CAmount total_inputs{0};
        CAmount total_outputs{0};
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            CTxOut utxo;
            if (psbt.GetInputUTXO(utxo, i)) {
                total_inputs += utxo.nValue;
            }
        }
        for (const CTxOut& out : psbt.tx->vout) {
            total_outputs += out.nValue;
        }
        if (total_inputs >= total_outputs) {
            return total_inputs - total_outputs;
        }
        return 0;
    };

    if (have_claim_key && claim_leaf) {
        // Sign the escrow input
        FinalizeVaultTaprootLeafWitness(wallet,
                                        psbt,
                                        escrow_input_idx,
                                        *escrow_meta,
                                        *claim_leaf,
                                        claim_priv,
                                        "forward.build_escrow_claim_long.escrow");

        // Sign the vault input if present
        if (have_vault_key && vault_leaf_to_sign && vault_input_idx) {
            FinalizeVaultTaprootLeafWitness(wallet,
                                            psbt,
                                            *vault_input_idx,
                                            *vault_meta,
                                            *vault_leaf_to_sign,
                                            vault_priv,
                                            "forward.build_escrow_claim_long.vault");
        }

        CMutableTransaction mtx(*psbt.tx);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!psbt.inputs[i].final_script_witness.IsNull()) {
                mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
            }
        }
        CTransaction final_tx(mtx);

        DataStream signed_psbt{};
        signed_psbt << psbt;
        result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
        result.pushKV("hex", EncodeHexTx(final_tx));
        result.pushKV("txid", final_tx.GetHash().ToString());
        result.pushKV("complete", true);
    } else {
        DataStream ssTx{};
        ssTx << psbt;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        result.pushKV("complete", false);
    }

    result.pushKV("fee", ValueFromAmount(psbt_fee_amount()));
    result.pushKV("escrow_input_index", static_cast<int>(escrow_input_idx));
    result.pushKV("payment_output_index", static_cast<int>(payment_output_idx));
    result.pushKV("claim_output_index", static_cast<int>(claim_output_idx));
    result.pushKV("vault_input_index", vault_input_idx ? static_cast<int>(*vault_input_idx) : -1);
    result.pushKV("margin_output_index", margin_output_idx ? static_cast<int>(*margin_output_idx) : -1);
    result.pushKV("changepos", btc_change_pos);

    // Preserve diagnostic logging for developers
    wallet.WalletLogPrintf("BuildForwardEscrowClaimLong: Final check - escrow input has %zu tap_scripts\n",
                          psbt.inputs[escrow_input_idx].m_tap_scripts.size());
    for (const auto& [script_key, control_blocks] : psbt.inputs[escrow_input_idx].m_tap_scripts) {
        wallet.WalletLogPrintf("  Script: %s (leaf_ver=%d)\n",
                              HexStr(script_key.first),
                              script_key.second);
    }

    return result;
}

static UniValue BuildForwardEscrowClaimShort(CWallet& wallet,
                                             const JSONRPCRequest& request,
                                             const ForwardContractRecord& record,
                                             const COutPoint& escrow_outpoint,
                                             const std::optional<COutPoint>& vault_outpoint,
                                             bool manual_inputs,
                                             const std::optional<uint32_t>& locktime_override,
                                             const UniValue& opts)
{
    const ForwardTerms& terms = record.terms;

    std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

    // TODO: Implement manual fee computation using fee_rate_override (similar to escrow claim long)
    // Currently relies on FillPSBT which uses wallet default fee rate

    // Note: counter_delivery leaf has NO CLTV, so no nLockTime requirement
    uint32_t tx_locktime = locktime_override.value_or(0);

    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = tx_locktime;

    tx.vin.emplace_back(escrow_outpoint);
    tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;
    const size_t escrow_input_idx = 0;

    // Add vault input if provided (needed for margin recovery + native BTC in multi-asset contracts)
    std::optional<size_t> vault_input_idx;
    if (vault_outpoint) {
        tx.vin.emplace_back(*vault_outpoint);
        tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;
        vault_input_idx = tx.vin.size() - 1;
    }

    // First: Create claim output (from escrow)
    CTxOut claim_out;
    claim_out.scriptPubKey = GetScriptForDestination(terms.short_party.settlement_receive_dest);
    const CAmount claim_sats = terms.long_party.deliver_leg.is_native
        ? static_cast<CAmount>(terms.long_party.deliver_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
    claim_out.nValue = claim_sats;
    if (!terms.long_party.deliver_leg.is_native) {
        claim_out.vExt = BuildAssetTagTlv(terms.long_party.deliver_leg.asset_id, terms.long_party.deliver_leg.units);
    }
    tx.vout.push_back(claim_out);
    const size_t claim_output_idx = tx.vout.size() - 1;

    // Add vault margin output if vault input is provided
    std::optional<size_t> margin_output_idx;
    if (vault_outpoint) {
        CTxOut margin_out;
        margin_out.scriptPubKey = GetScriptForDestination(terms.short_party.margin_dest);
        const CAmount margin_sats = terms.short_party.margin_leg.is_native
            ? static_cast<CAmount>(terms.short_party.margin_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        margin_out.nValue = margin_sats;
        if (!terms.short_party.margin_leg.is_native) {
            margin_out.vExt = BuildAssetTagTlv(terms.short_party.margin_leg.asset_id, terms.short_party.margin_leg.units);
        }
        tx.vout.push_back(margin_out);
        margin_output_idx = tx.vout.size() - 1;
    }

    std::set<COutPoint> skeleton_inputs_to_lock;
    std::vector<CTxOut> skeleton_change_outputs;
    std::vector<size_t> change_output_indices;
    size_t payment_output_idx = SIZE_MAX;

    // Second: Handle payment output (to long party)
    if (!terms.short_party.deliver_leg.is_native && !manual_inputs) {
        // Use sendasset skeleton for asset payment leg
        ForwardAssetSkeletonResult skeleton = BuildForwardAssetSkeleton(
            wallet,
            request,
            terms.short_party.deliver_leg,
            terms.long_party.settlement_receive_dest,
            fee_rate_override,
            "forward.build_escrow_claim.payment");

        // Add skeleton inputs
        for (const CTxIn& vin : skeleton.tx.vin) {
            tx.vin.push_back(vin);
        }

        // Use skeleton's delivery output as payment (includes full ICU/KYC metadata!)
        if (skeleton.deliver_output_index && *skeleton.deliver_output_index < skeleton.tx.vout.size()) {
            tx.vout.push_back(skeleton.tx.vout[*skeleton.deliver_output_index]);
            payment_output_idx = tx.vout.size() - 1;
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Skeleton missing delivery output");
        }

        // Track inputs to lock
        skeleton_inputs_to_lock = std::move(skeleton.inputs_to_lock);

        // Append skeleton change outputs to transaction and track their indices
        for (size_t change_idx : skeleton.change_indices) {
            if (change_idx < skeleton.tx.vout.size()) {
                tx.vout.push_back(skeleton.tx.vout[change_idx]);
                skeleton_change_outputs.push_back(skeleton.tx.vout[change_idx]);
                change_output_indices.push_back(tx.vout.size() - 1);
            }
        }
    } else if (terms.short_party.deliver_leg.is_native && !manual_inputs) {
        const CAmount btc_needed = static_cast<CAmount>(terms.short_party.deliver_leg.units);

        CFeeRate eff_fee_rate;
        if (fee_rate_override) {
            eff_fee_rate = CFeeRate(static_cast<CAmount>(*fee_rate_override * 1000)); // sat/vB -> sat/kB
        } else if (wallet.m_pay_tx_fee != CFeeRate(0)) {
            eff_fee_rate = wallet.m_pay_tx_fee;
        } else {
            eff_fee_rate = CFeeRate(1000); // Default to 1 sat/vB
        }

        CoinsResult btc_candidates;
        {
            CCoinControl scan_control;
            scan_control.m_signal_bip125_rbf = wallet.m_signal_rbf;
            scan_control.m_avoid_asset_utxos = true;
            LOCK(wallet.cs_wallet);
            btc_candidates = AvailableCoins(wallet, &scan_control);
        }

        CAmount btc_total = 0;
        std::vector<COutPoint> selected_inputs;
        for (const COutput& candidate : btc_candidates.All()) {
            if (!candidate.spendable) continue;
            if (assets::ParseAssetTag(candidate.txout.vExt)) continue;
            selected_inputs.push_back(candidate.outpoint);
            btc_total += candidate.txout.nValue;
            if (btc_total >= btc_needed) break;
        }

        if (btc_total < btc_needed) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient BTC for payment (need %lld sats, have %lld sats)",
                    static_cast<long long>(btc_needed), static_cast<long long>(btc_total)));
        }

        for (const COutPoint& outpoint : selected_inputs) {
            CTxIn new_in(outpoint);
            new_in.nSequence = MAX_BIP125_RBF_SEQUENCE;
            tx.vin.emplace_back(std::move(new_in));
        }

        // Payment output to long party
        CTxOut payment_out(btc_needed, GetScriptForDestination(terms.long_party.settlement_receive_dest));
        tx.vout.push_back(payment_out);
        payment_output_idx = tx.vout.size() - 1;

        // Change output placeholder
        CAmount btc_change = btc_total - btc_needed;
        int change_pos = -1;
        if (btc_change > 0) {
            CTxOut change_out(btc_change, GetScriptForDestination(terms.short_party.settlement_receive_dest));
            tx.vout.push_back(change_out);
            change_pos = tx.vout.size() - 1;
        }

        auto compute_fee = [&](const CMutableTransaction& tx_template) -> CAmount {
            const CTransaction tx_final(tx_template);
            int64_t base_weight = GetTransactionWeight(tx_final);

            // Add estimated taproot script-path witness overhead for escrow input
            // Witness structure: [signature (65) | script (~100) | control_block (~65)]
            // Conservative estimate: 230 bytes witness data per taproot input
            constexpr int64_t TAPROOT_WITNESS_OVERHEAD = 230;
            base_weight += TAPROOT_WITNESS_OVERHEAD; // escrow input
            if (vault_outpoint) {
                base_weight += TAPROOT_WITNESS_OVERHEAD; // vault input if present
            }

            return eff_fee_rate.GetFee((base_weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
        };

        CAmount required_fee = compute_fee(tx);
        if (change_pos != -1) {
            CAmount available_for_fee = btc_change;
            CAmount adjusted_change = available_for_fee - required_fee;
            if (adjusted_change > 0) {
                tx.vout[change_pos].nValue = adjusted_change;
            } else {
                tx.vout.pop_back();
                change_pos = -1;
                required_fee = compute_fee(tx);
            }
        } else {
            if (btc_total < btc_needed + required_fee) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient BTC to cover payment fee (need %lld sats, have %lld sats)",
                              static_cast<long long>(btc_needed + required_fee), static_cast<long long>(btc_total)));
            }
        }

        if (change_pos != -1) {
            change_output_indices.push_back(static_cast<size_t>(change_pos));
        }
    } else if (manual_inputs && !opts.isNull()) {
        const UniValue& inputs_val = opts.find_value("inputs");
        if (!inputs_val.isNull() && inputs_val.isArray()) {
            for (size_t i = 0; i < inputs_val.size(); ++i) {
                const UniValue& input_obj = inputs_val[i].get_obj();
                const std::string txid_hex = input_obj.find_value("txid").get_str();
                const uint32_t vout = input_obj.find_value("vout").getInt<uint32_t>();
                auto txid_opt = uint256::FromHex(txid_hex);
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input txid");
                }
                tx.vin.emplace_back(Txid::FromUint256(*txid_opt), vout);
            }
        }

        // Create payment output manually (user provided inputs, but outputs follow contract terms)
        CTxOut payment_out;
        payment_out.scriptPubKey = GetScriptForDestination(terms.long_party.settlement_receive_dest);
        const CAmount payment_sats = terms.short_party.deliver_leg.is_native
            ? static_cast<CAmount>(terms.short_party.deliver_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        payment_out.nValue = payment_sats;
        if (!terms.short_party.deliver_leg.is_native) {
            payment_out.vExt = BuildAssetTagTlv(terms.short_party.deliver_leg.asset_id, terms.short_party.deliver_leg.units);
        }
        tx.vout.push_back(payment_out);
        payment_output_idx = tx.vout.size() - 1;
    }

    PartiallySignedTransaction psbt(tx);

    FeePolicySnapshot fee_snapshot;
    fee_snapshot.rbf = wallet.m_signal_rbf;
    if (fee_rate_override) {
        fee_snapshot.target_satvb = static_cast<uint32_t>(*fee_rate_override);
        fee_snapshot.min_satvb = static_cast<uint32_t>(*fee_rate_override);
    }

    std::vector<OutputMatchSpec> outputmatches;
    outputmatches.push_back({
        terms.long_party.settlement_receive_dest,
        terms.short_party.deliver_leg.is_native,
        terms.short_party.deliver_leg.units,
        terms.short_party.deliver_leg.asset_id
    });
    outputmatches.push_back({
        terms.short_party.settlement_receive_dest,
        terms.long_party.deliver_leg.is_native,
        terms.long_party.deliver_leg.units,
        terms.long_party.deliver_leg.asset_id
    });

    AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
    AnnotateForwardOutputs(psbt, change_output_indices);

    [[maybe_unused]] bool fill_complete = false;
    const auto fill_err = wallet.FillPSBT(psbt, fill_complete, SIGHASH_DEFAULT, true, true);
    if (fill_err) {
        throw JSONRPCPSBTError(*fill_err);
    }
    psbt.tx->vin[escrow_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* escrow_wtx = wallet.GetWalletTx(Txid::FromUint256(escrow_outpoint.hash));
        if (escrow_wtx && escrow_outpoint.n < escrow_wtx->tx->vout.size()) {
            psbt.inputs[escrow_input_idx].witness_utxo = escrow_wtx->tx->vout[escrow_outpoint.n];
        }
    }

    const CScript escrow_base_spk = GetScriptForDestination(terms.long_party.settlement_receive_dest);
    auto escrow_meta = GetForwardVaultMetadataForOutpoint(wallet, escrow_outpoint, escrow_base_spk);
    if (!escrow_meta) {
        escrow_meta = GetForwardVaultMetadataByRole(wallet, record, VaultRole::FORWARD_ESCROW_A);
    }
    if (!escrow_meta) {
        escrow_meta = BuildForwardEscrowMetadata(record, VaultRole::FORWARD_ESCROW_A);
    }
    if (!escrow_meta) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault not registered in wallet registry - run forward.build_open first");
    }
    {
        CTxOut _utxo_check;
        if (!psbt.GetInputUTXO(_utxo_check, escrow_input_idx)) {
        CTxOut utxo;
        utxo.scriptPubKey = escrow_meta->GetScriptPubKey();
        utxo.nValue = terms.long_party.deliver_leg.is_native
            ? static_cast<CAmount>(terms.long_party.deliver_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        psbt.inputs[escrow_input_idx].witness_utxo = utxo;
        }
    }
    if (escrow_meta->role != VaultRole::FORWARD_ESCROW_A) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected escrow vault role for short claim");
    }
    auto& psbt_in = psbt.inputs[escrow_input_idx];
    const TaprootSpendData& spenddata = escrow_meta->spenddata;
    psbt_in.m_tap_internal_key = spenddata.internal_key;
    psbt_in.m_tap_merkle_root = spenddata.merkle_root;

    // Find the a_escrow_claim leaf - we ONLY want to add THIS leaf to the PSBT, not all leaves
    const VaultLeafDescriptor* claim_leaf = FindForwardLeafByPurpose(*escrow_meta, "a_escrow_claim");
    if (!claim_leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault missing a_escrow_claim leaf metadata");
    }

    // Add ONLY the claim leaf script to the PSBT (not refund leaf)
    psbt_in.m_tap_scripts.clear();
    auto script_it = spenddata.scripts.find({claim_leaf->script, claim_leaf->leaf_version});
    if (script_it != spenddata.scripts.end()) {
        psbt_in.m_tap_scripts[{claim_leaf->script, claim_leaf->leaf_version}] = script_it->second;
    }
    EnsureForwardKeyCached(wallet, terms.short_party.margin_dest, claim_leaf->signing_key);
    AnnotateForwardLeafBip32(wallet, terms.short_party.margin_dest, *escrow_meta, "a_escrow_claim", psbt_in);
    if (!psbt_in.m_tap_bip32_paths.count(claim_leaf->signing_key)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Wallet missing short margin signing key for a_escrow_claim; re-import counterparty payloads or rerun forward.build_open");
    }
    for (auto it = psbt_in.m_tap_bip32_paths.begin(); it != psbt_in.m_tap_bip32_paths.end(); ) {
        if (it->first == claim_leaf->signing_key) {
            ++it;
        } else {
            it = psbt_in.m_tap_bip32_paths.erase(it);
        }
    }

    // Add vault metadata if vault input is provided
    std::optional<VaultMetadata> vault_meta;
    if (vault_outpoint && vault_input_idx) {
        // Set vault witness_utxo
        {
            LOCK(wallet.cs_wallet);
            const CWalletTx* vault_wtx = wallet.GetWalletTx(Txid::FromUint256(vault_outpoint->hash));
            if (vault_wtx && vault_outpoint->n < vault_wtx->tx->vout.size()) {
                psbt.inputs[*vault_input_idx].witness_utxo = vault_wtx->tx->vout[vault_outpoint->n];
            }
        }

        // Get vault metadata from registry
        const CScript vault_margin_spk = GetScriptForDestination(terms.short_party.margin_dest);
        vault_meta = GetForwardVaultMetadataForOutpoint(wallet, *vault_outpoint, vault_margin_spk);
        if (!vault_meta) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry - run forward.build_open first");
        }
        EnsureForwardKeyCached(wallet, terms.short_party.margin_dest, vault_meta->spenddata.internal_key);

        // Add vault taproot spend data and prune to EXACT self_delivery leaf
        auto& vault_psbt_in = psbt.inputs[*vault_input_idx];
        const TaprootSpendData& vault_spenddata = vault_meta->spenddata;
        vault_psbt_in.m_tap_internal_key = vault_spenddata.internal_key;
        vault_psbt_in.m_tap_merkle_root = vault_spenddata.merkle_root;
        const VaultMetadata& vault = *vault_meta;
        const VaultLeafDescriptor* counter_leaf = FindForwardLeafByPurpose(vault, "b_counter_delivery");
        const char* target_purpose = "b_counter_delivery";
        if (!counter_leaf) {
            counter_leaf = FindForwardLeafByPurpose(vault, "self_delivery");
            target_purpose = "self_delivery";
        }
        if (!counter_leaf) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Forward short vault missing counter/self_delivery leaf metadata");
        }
        vault_psbt_in.m_tap_scripts.clear();
        if (auto it = vault_spenddata.scripts.find({counter_leaf->script, counter_leaf->leaf_version}); it != vault_spenddata.scripts.end()) {
            vault_psbt_in.m_tap_scripts[{counter_leaf->script, counter_leaf->leaf_version}] = it->second;
        }
        AnnotateForwardLeafBip32(wallet, terms.short_party.margin_dest, vault, target_purpose, vault_psbt_in);
        for (auto it = vault_psbt_in.m_tap_bip32_paths.begin(); it != vault_psbt_in.m_tap_bip32_paths.end(); ) {
            if (it->first == counter_leaf->signing_key) { ++it; } else { it = vault_psbt_in.m_tap_bip32_paths.erase(it); }
        }

        // Re-apply sequence to vault input after FillPSBT
        psbt.tx->vin[*vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    }

    // Get vault signing key if vault input is present (must be done AFTER vault block to access vault_meta)
    CKey vault_priv;
    bool have_vault_key = false;
    const VaultLeafDescriptor* vault_leaf_to_sign = nullptr;
    if (vault_meta) {
        const VaultMetadata& vault = *vault_meta;
        vault_leaf_to_sign = FindForwardLeafByPurpose(vault, "b_counter_delivery");
        if (!vault_leaf_to_sign) {
            vault_leaf_to_sign = FindForwardLeafByPurpose(vault, "self_delivery");
        }
        if (vault_leaf_to_sign) {
            have_vault_key = WalletGetKeyByXOnly(wallet, vault_leaf_to_sign->signing_key, vault_priv);
        }
    }

    // Lock skeleton-selected UTXOs
    if (!skeleton_inputs_to_lock.empty()) {
        LOCK(wallet.cs_wallet);
        for (const COutPoint& outpoint : skeleton_inputs_to_lock) {
            wallet.LockCoin(outpoint);
        }
    }

    // Find first BTC change output for changepos result
    int btc_change_pos = -1;
    for (size_t idx : change_output_indices) {
        if (idx < psbt.tx->vout.size()) {
            const CTxOut& out = psbt.tx->vout[idx];
            // BTC change has no asset tag in vExt
            if (out.vExt.empty() || !assets::ParseAssetTag(out.vExt)) {
                btc_change_pos = static_cast<int>(idx);
                break;
            }
        }
    }

    CKey claim_priv;
    const bool have_claim_key = claim_leaf && WalletGetKeyByXOnly(wallet, claim_leaf->signing_key, claim_priv);

    UniValue result(UniValue::VOBJ);

    auto psbt_fee_amount = [&]() -> CAmount {
        CAmount total_inputs{0};
        CAmount total_outputs{0};
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            CTxOut utxo;
            if (psbt.GetInputUTXO(utxo, i)) {
                total_inputs += utxo.nValue;
            }
        }
        for (const CTxOut& out : psbt.tx->vout) {
            total_outputs += out.nValue;
        }
        if (total_inputs >= total_outputs) {
            return total_inputs - total_outputs;
        }
        return 0;
    };

    if (have_claim_key && claim_leaf) {
        // Sign the escrow input
        FinalizeVaultTaprootLeafWitness(wallet,
                                        psbt,
                                        escrow_input_idx,
                                        *escrow_meta,
                                        *claim_leaf,
                                        claim_priv,
                                        "forward.build_escrow_claim_short.escrow");

        // Sign the vault input if present
        if (have_vault_key && vault_leaf_to_sign && vault_input_idx) {
            FinalizeVaultTaprootLeafWitness(wallet,
                                            psbt,
                                            *vault_input_idx,
                                            *vault_meta,
                                            *vault_leaf_to_sign,
                                            vault_priv,
                                            "forward.build_escrow_claim_short.vault");
        }

        CMutableTransaction mtx(*psbt.tx);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!psbt.inputs[i].final_script_witness.IsNull()) {
                mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
            }
        }
        CTransaction final_tx(mtx);

        DataStream signed_psbt{};
        signed_psbt << psbt;
        result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
        result.pushKV("hex", EncodeHexTx(final_tx));
        result.pushKV("txid", final_tx.GetHash().ToString());
        result.pushKV("complete", true);
    } else {
        DataStream ssTx{};
        ssTx << psbt;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        result.pushKV("complete", false);
    }

    result.pushKV("fee", ValueFromAmount(psbt_fee_amount()));
    result.pushKV("escrow_input_index", static_cast<int>(escrow_input_idx));
    result.pushKV("payment_output_index", static_cast<int>(payment_output_idx));
    result.pushKV("claim_output_index", static_cast<int>(claim_output_idx));
    result.pushKV("vault_input_index", vault_input_idx ? static_cast<int>(*vault_input_idx) : -1);
    result.pushKV("margin_output_index", margin_output_idx ? static_cast<int>(*margin_output_idx) : -1);
    result.pushKV("changepos", btc_change_pos);

    return result;
}

static UniValue BuildForwardEscrowRefundShort(CWallet& wallet,
                                              const ForwardContractRecord& record,
                                              const COutPoint& escrow_outpoint,
                                              const std::optional<uint32_t>& locktime_override,
                                              const UniValue& opts)
{
    const ForwardTerms& terms = record.terms;

    uint32_t locktime = locktime_override.value_or(terms.deadline_long);
    if (locktime < terms.deadline_long) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "locktime must be >= deadline_long for escrow refund");
    }

    CTxDestination refund_dest = terms.short_party.settlement_receive_dest;
    if (!opts.isNull()) {
        const UniValue& refund_addr_val = opts.find_value("refund_address");
        if (!refund_addr_val.isNull()) {
            refund_dest = DecodeDestination(refund_addr_val.get_str());
            if (!IsValidDestination(refund_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid refund_address");
            }
        }
    }

    // Build initial transaction with escrow input
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = locktime;
    tx.vin.emplace_back(escrow_outpoint);
    tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;

    // Fund transaction to add wallet inputs for fees
    CCoinControl fee_control;
    fee_control.m_signal_bip125_rbf = wallet.m_signal_rbf;
    fee_control.m_include_unsafe_inputs = false;  // Only use confirmed inputs to avoid dependency issues

    // Extract fee_rate from options if provided
    if (!opts.isNull()) {
        const UniValue& fee_rate_val = opts.find_value("fee_rate");
        if (!fee_rate_val.isNull()) {
            double fee_rate_sat_vb = fee_rate_val.get_real();
            fee_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_rate_sat_vb * 1000)); // sat/vB to sat/kvB
            fee_control.fOverrideFeeRate = true;
        }
    }

    fee_control.Select(escrow_outpoint);

    const CAmount refund_sats = terms.short_party.deliver_leg.is_native
        ? static_cast<CAmount>(terms.short_party.deliver_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

    std::vector<CRecipient> recipients;
    recipients.emplace_back(CRecipient{refund_dest, refund_sats, false});

    auto fund_res = FundTransaction(wallet, tx, recipients, std::nullopt, false, fee_control);
    if (!fund_res) {
        bilingual_str err = util::ErrorString(fund_res);
        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
    }
    const CreatedTransactionResult& tx_result = fund_res.value();

    CMutableTransaction funded_tx = CMutableTransaction(*tx_result.tx);
    funded_tx.nLockTime = locktime;

    // Find escrow input index after funding
    size_t escrow_input_idx = SIZE_MAX;
    for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
        if (funded_tx.vin[i].prevout == escrow_outpoint) {
            escrow_input_idx = i;
            break;
        }
    }
    if (escrow_input_idx == SIZE_MAX) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing escrow input");
    }
    funded_tx.vin[escrow_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    funded_tx.vin[escrow_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    // Find refund output index and add asset tag if needed
    size_t refund_output_idx = SIZE_MAX;
    const CScript refund_spk = GetScriptForDestination(refund_dest);
    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
        if (funded_tx.vout[i].scriptPubKey == refund_spk && funded_tx.vout[i].nValue == refund_sats) {
            refund_output_idx = i;
            if (!terms.short_party.deliver_leg.is_native) {
                funded_tx.vout[i].vExt = BuildAssetTagTlv(terms.short_party.deliver_leg.asset_id, terms.short_party.deliver_leg.units);
            }
            break;
        }
    }
    if (refund_output_idx == SIZE_MAX) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing refund output");
    }

    PartiallySignedTransaction psbt(funded_tx);

    FeePolicySnapshot fee_snapshot;
    fee_snapshot.rbf = wallet.m_signal_rbf;

    std::vector<OutputMatchSpec> outputmatches;
    outputmatches.push_back({
        refund_dest,
        terms.short_party.deliver_leg.is_native,
        terms.short_party.deliver_leg.units,
        terms.short_party.deliver_leg.asset_id
    });

    AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
    std::vector<size_t> change_indices;
    if (tx_result.change_pos) {
        change_indices.push_back(*tx_result.change_pos);
    }
    AnnotateForwardOutputs(psbt, change_indices);

    bool complete = false;
    const auto fill_err = wallet.FillPSBT(psbt, complete, SIGHASH_DEFAULT, false, true);
    if (fill_err) {
        throw JSONRPCPSBTError(*fill_err);
    }

    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* escrow_wtx = wallet.GetWalletTx(Txid::FromUint256(escrow_outpoint.hash));
        if (escrow_wtx && escrow_outpoint.n < escrow_wtx->tx->vout.size()) {
            psbt.inputs[escrow_input_idx].witness_utxo = escrow_wtx->tx->vout[escrow_outpoint.n];
        }
    }

    const CScript escrow_base_spk = GetScriptForDestination(terms.short_party.settlement_receive_dest);
    auto escrow_meta = GetForwardVaultMetadataForOutpoint(wallet, escrow_outpoint, escrow_base_spk);
    if (!escrow_meta) {
        escrow_meta = GetForwardVaultMetadataByRole(wallet, record, VaultRole::FORWARD_ESCROW_B);
        if (!escrow_meta) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault not registered in wallet registry - run forward.build_open first");
        }
    }
    {
        CTxOut _utxo_check;
        if (!psbt.GetInputUTXO(_utxo_check, escrow_input_idx)) {
        CTxOut utxo;
        utxo.scriptPubKey = escrow_meta->GetScriptPubKey();
        utxo.nValue = terms.short_party.deliver_leg.is_native
            ? static_cast<CAmount>(terms.short_party.deliver_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        psbt.inputs[escrow_input_idx].witness_utxo = utxo;
        }
    }
    if (escrow_meta->role != VaultRole::FORWARD_ESCROW_B) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected escrow vault role for short refund");
    }
    EnsureForwardKeyCached(wallet, terms.short_party.margin_dest, escrow_meta->spenddata.internal_key);

    auto& psbt_in = psbt.inputs[escrow_input_idx];
    const TaprootSpendData& spenddata = escrow_meta->spenddata;
    psbt_in.m_tap_internal_key = spenddata.internal_key;
    psbt_in.m_tap_merkle_root = spenddata.merkle_root;
    for (const auto& [script_key, control_blocks] : spenddata.scripts) {
        auto& entry = psbt_in.m_tap_scripts[script_key];
        entry.insert(control_blocks.begin(), control_blocks.end());
    }

    const VaultLeafDescriptor* refund_leaf = nullptr;
    for (const auto& leaf : escrow_meta->leaves) {
        if (leaf.purpose == "b_escrow_refund") {
            refund_leaf = &leaf;
            break;
        }
    }
    if (!refund_leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault missing b_escrow_refund leaf metadata");
    }
    const uint8_t refund_leaf_version = refund_leaf->leaf_version;
    const XOnlyPubKey refund_key = refund_leaf->signing_key;
    const uint256 refund_leaf_hash = ComputeTapleafHash(
        refund_leaf_version,
        std::span<const unsigned char>(refund_leaf->script.data(), refund_leaf->script.size()));

    {
        std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(terms.short_party.margin_dest));
        KeyOriginInfo origin;
        CPubKey full_pub;
        if (provider && provider->GetKeyOriginByXOnly(refund_key, origin)) {
            auto& derivation = psbt_in.m_tap_bip32_paths[refund_key];
            derivation.first.insert(refund_leaf_hash);
            derivation.second = origin;
            if (provider->GetPubKeyByXOnly(refund_key, full_pub)) {
                psbt_in.hd_keypaths.emplace(full_pub, origin);
            }
        }
    }

    CKey refund_priv;
    const bool have_privkey = WalletGetKeyByXOnly(wallet, refund_leaf->signing_key, refund_priv);

    UniValue result(UniValue::VOBJ);

    if (have_privkey) {
        FinalizeVaultTaprootLeafWitness(wallet,
                                        psbt,
                                        escrow_input_idx,
                                        *escrow_meta,
                                        *refund_leaf,
                                        refund_priv,
                                        "forward.build_escrow_refund_short");

        CMutableTransaction mtx(*psbt.tx);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!psbt.inputs[i].final_script_witness.IsNull()) {
                mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
            }
        }
        CTransaction final_tx(mtx);

        DataStream signed_psbt{};
        signed_psbt << psbt;
        result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
        result.pushKV("hex", EncodeHexTx(final_tx));
        result.pushKV("txid", final_tx.GetHash().ToString());
        result.pushKV("complete", complete);  // Return actual completeness, not hardcoded true
    } else {
        DataStream ssTx{};
        ssTx << psbt;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        result.pushKV("complete", complete);
    }

    result.pushKV("fee", ValueFromAmount(tx_result.fee));
    result.pushKV("escrow_input_index", static_cast<int>(escrow_input_idx));
    result.pushKV("refund_output_index", static_cast<int>(refund_output_idx));
    result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);
    result.pushKV("escrow", "B");
    result.pushKV("side", "short");
    return result;
}

static UniValue BuildForwardEscrowRefundLong(CWallet& wallet,
                                             const ForwardContractRecord& record,
                                             const COutPoint& escrow_outpoint,
                                             const std::optional<uint32_t>& locktime_override,
                                             const UniValue& opts)
{
    const ForwardTerms& terms = record.terms;

    uint32_t locktime = locktime_override.value_or(terms.deadline_long);
    if (locktime < terms.deadline_long) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "locktime must be >= deadline_long for escrow refund");
    }

    CTxDestination refund_dest = terms.long_party.settlement_receive_dest;
    if (!opts.isNull()) {
        const UniValue& refund_addr_val = opts.find_value("refund_address");
        if (!refund_addr_val.isNull()) {
            refund_dest = DecodeDestination(refund_addr_val.get_str());
            if (!IsValidDestination(refund_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid refund_address");
            }
        }
    }

    // Build initial transaction with escrow input
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = locktime;
    tx.vin.emplace_back(escrow_outpoint);
    tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;

    // Fund transaction to add wallet inputs for fees
    CCoinControl fee_control;
    fee_control.m_signal_bip125_rbf = wallet.m_signal_rbf;
    fee_control.m_include_unsafe_inputs = false;  // Only use confirmed inputs to avoid dependency issues

    // Extract fee_rate from options if provided
    if (!opts.isNull()) {
        const UniValue& fee_rate_val = opts.find_value("fee_rate");
        if (!fee_rate_val.isNull()) {
            double fee_rate_sat_vb = fee_rate_val.get_real();
            fee_control.m_feerate = CFeeRate(static_cast<CAmount>(fee_rate_sat_vb * 1000)); // sat/vB to sat/kvB
            fee_control.fOverrideFeeRate = true;
        }
    }

    fee_control.Select(escrow_outpoint);

    const CAmount refund_sats = terms.long_party.deliver_leg.is_native
        ? static_cast<CAmount>(terms.long_party.deliver_leg.units)
        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

    std::vector<CRecipient> recipients;
    recipients.emplace_back(CRecipient{refund_dest, refund_sats, false});

    auto fund_res = FundTransaction(wallet, tx, recipients, std::nullopt, false, fee_control);
    if (!fund_res) {
        bilingual_str err = util::ErrorString(fund_res);
        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
    }
    const CreatedTransactionResult& tx_result = fund_res.value();

    CMutableTransaction funded_tx = CMutableTransaction(*tx_result.tx);
    funded_tx.nLockTime = locktime;

    // Find escrow input index after funding
    size_t escrow_input_idx = SIZE_MAX;
    for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
        if (funded_tx.vin[i].prevout == escrow_outpoint) {
            escrow_input_idx = i;
            break;
        }
    }
    if (escrow_input_idx == SIZE_MAX) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing escrow input");
    }
    funded_tx.vin[escrow_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

    // Find refund output index and add asset tag if needed
    size_t refund_output_idx = SIZE_MAX;
    const CScript refund_spk = GetScriptForDestination(refund_dest);
    for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
        if (funded_tx.vout[i].scriptPubKey == refund_spk && funded_tx.vout[i].nValue == refund_sats) {
            refund_output_idx = i;
            if (!terms.long_party.deliver_leg.is_native) {
                funded_tx.vout[i].vExt = BuildAssetTagTlv(terms.long_party.deliver_leg.asset_id, terms.long_party.deliver_leg.units);
            }
            break;
        }
    }
    if (refund_output_idx == SIZE_MAX) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing refund output");
    }

    PartiallySignedTransaction psbt(funded_tx);

    FeePolicySnapshot fee_snapshot;
    fee_snapshot.rbf = wallet.m_signal_rbf;

    std::vector<OutputMatchSpec> outputmatches;
    outputmatches.push_back({
        refund_dest,
        terms.long_party.deliver_leg.is_native,
        terms.long_party.deliver_leg.units,
        terms.long_party.deliver_leg.asset_id
    });

    AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
    std::vector<size_t> change_indices;
    if (tx_result.change_pos) {
        change_indices.push_back(*tx_result.change_pos);
    }
    AnnotateForwardOutputs(psbt, change_indices);

    bool complete = false;
    const auto fill_err = wallet.FillPSBT(psbt, complete, SIGHASH_DEFAULT, false, true);
    if (fill_err) {
        throw JSONRPCPSBTError(*fill_err);
    }

    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* escrow_wtx = wallet.GetWalletTx(Txid::FromUint256(escrow_outpoint.hash));
        if (escrow_wtx && escrow_outpoint.n < escrow_wtx->tx->vout.size()) {
            psbt.inputs[escrow_input_idx].witness_utxo = escrow_wtx->tx->vout[escrow_outpoint.n];
        }
    }

    const CScript escrow_base_spk = GetScriptForDestination(terms.long_party.settlement_receive_dest);
    auto escrow_meta = GetForwardVaultMetadataForOutpoint(wallet, escrow_outpoint, escrow_base_spk);
    if (!escrow_meta) {
        escrow_meta = GetForwardVaultMetadataByRole(wallet, record, VaultRole::FORWARD_ESCROW_A);
    }
    if (!escrow_meta) {
        escrow_meta = BuildForwardEscrowMetadata(record, VaultRole::FORWARD_ESCROW_A);
    }
    if (!escrow_meta) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault not registered in wallet registry - run forward.build_open first");
    }
    {
        CTxOut _utxo_check;
        if (!psbt.GetInputUTXO(_utxo_check, escrow_input_idx)) {
        CTxOut utxo;
        utxo.scriptPubKey = escrow_meta->GetScriptPubKey();
        utxo.nValue = terms.long_party.deliver_leg.is_native
            ? static_cast<CAmount>(terms.long_party.deliver_leg.units)
            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
        psbt.inputs[escrow_input_idx].witness_utxo = utxo;
        }
    }
    if (escrow_meta->role != VaultRole::FORWARD_ESCROW_A) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected escrow vault role for long refund");
    }
    EnsureForwardKeyCached(wallet, terms.long_party.margin_dest, escrow_meta->spenddata.internal_key);

    auto& psbt_in = psbt.inputs[escrow_input_idx];
    const TaprootSpendData& spenddata = escrow_meta->spenddata;
    psbt_in.m_tap_internal_key = spenddata.internal_key;
    psbt_in.m_tap_merkle_root = spenddata.merkle_root;
    for (const auto& [script_key, control_blocks] : spenddata.scripts) {
        auto& entry = psbt_in.m_tap_scripts[script_key];
        entry.insert(control_blocks.begin(), control_blocks.end());
    }

    const VaultLeafDescriptor* refund_leaf = nullptr;
    for (const auto& leaf : escrow_meta->leaves) {
        if (leaf.purpose == "a_escrow_refund") {
            refund_leaf = &leaf;
            break;
        }
    }
    if (!refund_leaf) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Escrow vault missing a_escrow_refund leaf metadata");
    }
    const uint8_t refund_leaf_version = refund_leaf->leaf_version;
    const XOnlyPubKey refund_key = refund_leaf->signing_key;
    const uint256 refund_leaf_hash = ComputeTapleafHash(
        refund_leaf_version,
        std::span<const unsigned char>(refund_leaf->script.data(), refund_leaf->script.size()));

    {
        std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(GetScriptForDestination(terms.long_party.margin_dest));
        KeyOriginInfo origin;
        CPubKey full_pub;
        if (provider && provider->GetKeyOriginByXOnly(refund_key, origin)) {
            auto& derivation = psbt_in.m_tap_bip32_paths[refund_key];
            derivation.first.insert(refund_leaf_hash);
            derivation.second = origin;
            if (provider->GetPubKeyByXOnly(refund_key, full_pub)) {
                psbt_in.hd_keypaths.emplace(full_pub, origin);
            }
        }
    }

    CKey refund_priv;
    const bool have_privkey = WalletGetKeyByXOnly(wallet, refund_leaf->signing_key, refund_priv);

    UniValue result(UniValue::VOBJ);

    if (have_privkey) {
        FinalizeVaultTaprootLeafWitness(wallet,
                                        psbt,
                                        escrow_input_idx,
                                        *escrow_meta,
                                        *refund_leaf,
                                        refund_priv,
                                        "forward.build_escrow_refund_long");

        CMutableTransaction mtx(*psbt.tx);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!psbt.inputs[i].final_script_witness.IsNull()) {
                mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
            }
        }
        CTransaction final_tx(mtx);

        DataStream signed_psbt{};
        signed_psbt << psbt;
        result.pushKV("psbt", EncodeBase64(signed_psbt.str()));
        result.pushKV("hex", EncodeHexTx(final_tx));
        result.pushKV("txid", final_tx.GetHash().ToString());
        result.pushKV("complete", complete);  // Return actual completeness, not hardcoded true
    } else {
        DataStream ssTx{};
        ssTx << psbt;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        result.pushKV("complete", complete);
    }

    result.pushKV("fee", ValueFromAmount(tx_result.fee));
    result.pushKV("escrow_input_index", static_cast<int>(escrow_input_idx));
    result.pushKV("refund_output_index", static_cast<int>(refund_output_idx));
    result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);
    result.pushKV("escrow", "A");
    result.pushKV("side", "long");
    return result;
}

RPCHelpMan forward_import_offer()
{
    return RPCHelpMan(
        "forward.import_offer",
        "Import a forward contract offer JSON payload into the wallet registry (stub - offer already stored by counterparty).",
        std::vector<RPCArg>{
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Offer payload", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.import_offer", "\"{...offer json...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& offer_obj = request.params[0].get_obj();

            // Parse and validate offer ID
            const std::string offer_id_hex = offer_obj.find_value("id").get_str();
            const uint256 contract_id = ParseHashV(UniValue(offer_id_hex), "id");

            // Parse salt
            const std::string salt_hex = offer_obj.find_value("salt").get_str();
            const auto offer_salt = uint256::FromHex(salt_hex);
            if (!offer_salt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid offer salt");
            }

            // Parse commitment
            const std::string commitment_hex = offer_obj.find_value("commitment").get_str();

            // Parse proposer side
            const std::string proposer_side_str = offer_obj.find_value("proposer_side").get_str();
            ForwardSide proposer_side;
            if (proposer_side_str == "long") {
                proposer_side = ForwardSide::LONG;
            } else if (proposer_side_str == "short") {
                proposer_side = ForwardSide::SHORT;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proposer_side");
            }

            // Parse terms
            const UniValue& terms_obj = offer_obj.find_value("terms");
            if (!terms_obj.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing terms");
            }
            ForwardTerms terms = ParseForwardTerms(terms_obj);

            // Verify commitment
            const std::string computed_commitment = ForwardOfferCommitmentHex(terms, proposer_side, *offer_salt);
            if (computed_commitment != commitment_hex) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer commitment mismatch");
            }

            // Parse proposer adaptor point
            const std::string proposer_adaptor_hex = offer_obj.find_value("fs_tx_adaptor_point").get_str();
            auto proposer_adaptor_bytes = ParseHex(proposer_adaptor_hex);
            XOnlyPubKey proposer_adaptor_point;
            if (proposer_adaptor_bytes.size() != proposer_adaptor_point.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.fs_tx_adaptor_point must be 32-byte hex");
            }
            std::copy(proposer_adaptor_bytes.begin(), proposer_adaptor_bytes.end(), proposer_adaptor_point.begin());

            ForwardContractRecord record;
            record.contract_id = contract_id;
            record.terms = terms;
            record.local_side = proposer_side == ForwardSide::LONG ? ForwardSide::SHORT : ForwardSide::LONG;
            record.fs_policy = FairSignPolicy{};
            record.fs_tx_adaptor_point = proposer_adaptor_point;
            record.salt = *offer_salt;
            record.commitment_hex = commitment_hex;
            record.created_time = GetTime();
            {
                LOCK(pwallet->cs_wallet);
                record.created_height = pwallet->GetLastBlockHeight();
            }

            std::optional<XOnlyPubKey> offer_long_key;
            std::optional<XOnlyPubKey> offer_short_key;
            const UniValue& internal_keys_val = offer_obj.find_value("internal_keys");
            if (!internal_keys_val.isNull()) {
                if (!internal_keys_val.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.internal_keys must be an object when provided");
                }
                const UniValue& long_key_val = internal_keys_val.find_value("long_margin");
                const UniValue& short_key_val = internal_keys_val.find_value("short_margin");
                offer_long_key = ParseInternalKeyOptional(long_key_val, "offer.internal_keys.long_margin");
                offer_short_key = ParseInternalKeyOptional(short_key_val, "offer.internal_keys.short_margin");
            }

            record.long_margin_internal_key = ResolveForwardMarginKey(
                *pwallet,
                terms.long_party.margin_dest,
                record.long_margin_internal_key,
                offer_long_key,
                "offer.internal_keys.long_margin",
                record.local_side,
                ForwardSide::LONG);
            record.short_margin_internal_key = ResolveForwardMarginKey(
                *pwallet,
                terms.short_party.margin_dest,
                record.short_margin_internal_key,
                offer_short_key,
                "offer.internal_keys.short_margin",
                record.local_side,
                ForwardSide::SHORT);
            MaybePopulateLocalMarginKey(*pwallet, terms.long_party.margin_dest, record.long_margin_internal_key);
            MaybePopulateLocalMarginKey(*pwallet, terms.short_party.margin_dest, record.short_margin_internal_key);

            ForwardContractRecord stored = pwallet->RegisterForwardContract(std::move(record));
            CacheForwardVaultScripts(*pwallet, stored);

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", contract_id.GetHex());
            return result;
        }
    );
}

RPCHelpMan forward_export_offer()
{
    return RPCHelpMan(
        "forward.export_offer",
        "Export a forward contract offer for counterparty sharing (stub).",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract offer identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::OBJ, "offer", "Forward contract offer payload",
                    {
                        {RPCResult::Type::STR_HEX, "offer_id", "Offer ID"},
                        {RPCResult::Type::OBJ, "terms", "Contract terms", ForwardTermsResultDescription()},
                        {RPCResult::Type::STR_HEX, "commitment_hex", "Offer commitment"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.export_offer", "\"<offer_id_hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "offer_id");

            auto record_opt = pwallet->FindForwardContract(contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract offer");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", contract_id.GetHex());
            UniValue offer_obj(UniValue::VOBJ);
            offer_obj.pushKV("offer_id", contract_id.GetHex());
            offer_obj.pushKV("terms", ForwardTermsToJSON(record_opt->terms));
            offer_obj.pushKV("commitment_hex", record_opt->commitment_hex);
            result.pushKV("offer", offer_obj);
            return result;
        }
    );
}

RPCHelpMan forward_share_offer()
{
    return RPCHelpMan(
        "forward.share_offer",
        "Export a forward contract offer and create a cosign session for secure sharing with counterparty.\n"
        "This is a convenience wrapper that combines forward.export_offer with cosign.init.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract offer identifier"},
            {"context", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Human-readable context label (default: \"forward-contract\")"},
            {"transport", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Transport: auto|websocket|nostr (default: auto)"},
            {"ttl", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Session TTL in seconds (default: 1800)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Forward contract offer identifier"},
                {RPCResult::Type::OBJ, "offer", "Forward contract offer payload",
                    {
                        {RPCResult::Type::STR_HEX, "offer_id", "Offer ID"},
                        {RPCResult::Type::OBJ, "terms", "Contract terms", ForwardTermsResultDescription()},
                        {RPCResult::Type::STR_HEX, "commitment_hex", "Offer commitment"},
                    }
                },
                {RPCResult::Type::OBJ, "cosign", "Cosign session details",
                    {
                        {RPCResult::Type::STR, "session_id", "Cosign session identifier"},
                        {RPCResult::Type::STR, "invite_link", "Invite link for counterparty"},
                        {RPCResult::Type::STR, "sas", "Short Authentication String"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.share_offer", std::string(64, 'a'))
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const uint256 contract_id = ParseHashV(request.params[0], "offer_id");

            // Get forward contract from wallet
            auto record_opt = pwallet->FindForwardContract(contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract offer");
            }

            // Build offer export
            UniValue offer_data(UniValue::VOBJ);
            offer_data.pushKV("offer_id", contract_id.GetHex());
            UniValue offer_obj(UniValue::VOBJ);
            offer_obj.pushKV("offer_id", contract_id.GetHex());
            offer_obj.pushKV("terms", ForwardTermsToJSON(record_opt->terms));
            offer_obj.pushKV("commitment_hex", record_opt->commitment_hex);
            offer_data.pushKV("offer", offer_obj);

            // Prepare cosign.init parameters
            UniValue cosign_params(UniValue::VARR);
            UniValue init_opts(UniValue::VOBJ);
            init_opts.pushKV("context", request.params[1].isNull() ? "forward-contract" : request.params[1].get_str());
            if (!request.params[2].isNull()) {
                init_opts.pushKV("transport", request.params[2].get_str());
            }
            if (!request.params[3].isNull()) {
                init_opts.pushKV("ttl", request.params[3].getInt<int>());
            }
            cosign_params.push_back(init_opts);

            // Call cosign.init
            JSONRPCRequest cosign_req;
            cosign_req.context = request.context;
            cosign_req.strMethod = "cosign.init";
            cosign_req.params = cosign_params;

            UniValue cosign_result = tableRPC.execute(cosign_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", offer_data["offer_id"]);
            result.pushKV("offer", offer_data["offer"]);
            result.pushKV("cosign", cosign_result);

            return result;
        }
    );
}

RPCHelpMan forward_collect_acceptance()
{
    return RPCHelpMan(
        "forward.collect_acceptance",
        "Join a cosign session via invite link and collect acceptance data from counterparty.\n"
        "This is a convenience wrapper that combines cosign.join with cosign.recv and forward.import_acceptance.",
        std::vector<RPCArg>{
            {"offer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract offer identifier"},
            {"invite_link", RPCArg::Type::STR, RPCArg::Optional::NO, "Cosign invite link (cosign:?r=...)"},
            {"timeout_ms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Timeout for receiving acceptance (default: 30000ms)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Forward contract offer identifier"},
                {RPCResult::Type::STR, "state", "Contract state after import"},
                {RPCResult::Type::OBJ, "cosign", "Cosign session details",
                    {
                        {RPCResult::Type::STR, "session_id", "Cosign session identifier"},
                        {RPCResult::Type::STR, "peer_sas", "Peer Short Authentication String"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.collect_acceptance", std::string(64, 'a') + " \"cosign:?r=abc123&t=websocket#c=alpha-bravo-charlie\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            ParseHashV(request.params[0], "offer_id");
            const std::string invite_link = request.params[1].get_str();
            const int timeout_ms = request.params[2].isNull() ? 30000 : request.params[2].getInt<int>();

            // Join cosign session
            JSONRPCRequest join_req;
            join_req.context = request.context;
            join_req.strMethod = "cosign.join";
            UniValue join_params(UniValue::VARR);
            join_params.push_back(invite_link);
            join_req.params = join_params;

            UniValue join_result = tableRPC.execute(join_req);
            const std::string session_id = join_result["session_id"].get_str();
            const std::string peer_sas = join_result["peer_sas"].get_str();

            // Complete SPAKE2/Noise handshake (SECURITY: Phase 4 requirement)
            // This establishes encrypted channel before any send/recv operations
            JSONRPCRequest handshake_req;
            handshake_req.context = request.context;
            handshake_req.strMethod = "cosign.handshake_auto";
            UniValue handshake_params(UniValue::VARR);
            handshake_params.push_back(session_id);
            handshake_params.push_back(false);  // responder (joined session)
            handshake_req.params = handshake_params;

            UniValue handshake_result = tableRPC.execute(handshake_req);
            if (!handshake_result.exists("handshake_complete") || !handshake_result["handshake_complete"].isBool() || !handshake_result["handshake_complete"].get_bool()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Handshake failed: encrypted channel not established");
            }

            // Receive acceptance data
            JSONRPCRequest recv_req;
            recv_req.context = request.context;
            recv_req.strMethod = "cosign.recv";
            UniValue recv_params(UniValue::VARR);
            recv_params.push_back(session_id);
            recv_params.push_back(timeout_ms);
            recv_req.params = recv_params;

            UniValue recv_result = tableRPC.execute(recv_req);

            // Extract acceptance payload
            if (!recv_result["payload"].isObject() || !recv_result["payload"]["acceptance"].isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected acceptance object in received payload");
            }

            UniValue acceptance_data = recv_result["payload"]["acceptance"];

            // Import acceptance
            JSONRPCRequest import_req;
            import_req.context = request.context;
            import_req.strMethod = "forward.import_acceptance";
            UniValue import_params(UniValue::VARR);
            import_params.push_back(acceptance_data);
            import_req.params = import_params;

            UniValue import_result = tableRPC.execute(import_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", import_result["offer_id"]);
            result.pushKV("state", import_result["state"]);

            UniValue cosign_info(UniValue::VOBJ);
            cosign_info.pushKV("session_id", session_id);
            cosign_info.pushKV("peer_sas", peer_sas);
            cosign_info.pushKV("messages_received", recv_result["seq"]);
            result.pushKV("cosign", cosign_info);

            return result;
        }
    );
}

RPCHelpMan forward_sign_over_channel()
{
    return RPCHelpMan(
        "forward.sign_over_channel",
        "Coordinate Fair-Sign ceremony over an active cosign session.\n"
        "Sends nonce commitments, exchanges partial signatures, and completes the signing process.",
        std::vector<RPCArg>{
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Active cosign session identifier"},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Partially Signed Bitcoin Transaction (base64)"},
            {"is_initiator", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this party initiates the ceremony (default: true)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Completed PSBT with all signatures (base64)"},
                {RPCResult::Type::OBJ, "ceremony_stats", "Ceremony statistics",
                    {
                        {RPCResult::Type::NUM, "messages_sent", "Number of messages sent"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                        {RPCResult::Type::NUM, "duration_ms", "Ceremony duration in milliseconds"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.sign_over_channel", "\"69d967c0e415c9a3\" \"cHNidP8BA...\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string session_id = request.params[0].get_str();
            const std::string psbt_str = request.params[1].get_str();
            const bool is_initiator = request.params[2].isNull() ? true : request.params[2].get_bool();

            // SECURITY: Ensure handshake is complete before ceremony (Phase 4 requirement)
            // NOTE: This is defensive - aggregators should call handshake_auto before this,
            // but we verify here in case session_id was obtained elsewhere
            JSONRPCRequest handshake_req;
            handshake_req.context = request.context;
            handshake_req.strMethod = "cosign.handshake_auto";
            UniValue handshake_params(UniValue::VARR);
            handshake_params.push_back(session_id);
            handshake_params.push_back(is_initiator);
            handshake_req.params = handshake_params;

            UniValue handshake_result = tableRPC.execute(handshake_req);
            if (!handshake_result.exists("handshake_complete") || !handshake_result["handshake_complete"].isBool() || !handshake_result["handshake_complete"].get_bool()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Handshake failed: encrypted channel not established before ceremony");
            }

            auto start_time = std::chrono::steady_clock::now();
            int messages_sent = 0;
            int messages_received = 0;

            // Prepare adaptor ceremony
            JSONRPCRequest prepare_req;
            prepare_req.context = request.context;
            UniValue prepare_params(UniValue::VARR);
            prepare_params.push_back(psbt_str);
            prepare_req.params = prepare_params;
            prepare_req.strMethod = "adaptor.prepare";

            UniValue prepare_result = tableRPC.execute(prepare_req);
            const std::string prepared_psbt = prepare_result["psbt"].get_str();

            UniValue commitments(UniValue::VARR);
            if (prepare_result["commitments"].isArray()) {
                commitments = prepare_result["commitments"];
            }

            // Exchange nonce commitments
            if (is_initiator) {
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "nonce_commitments");
                payload.pushKV("commitments", commitments);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;

                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;
            } else {
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;

                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "nonce_commitments");
                payload.pushKV("commitments", commitments);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;
            }

            // Create partial signatures
            JSONRPCRequest partial_req;
            partial_req.context = request.context;
            partial_req.strMethod = "adaptor.partial";
            UniValue partial_params(UniValue::VARR);
            partial_params.push_back(prepared_psbt);
            partial_req.params = partial_params;

            UniValue partial_result = tableRPC.execute(partial_req);
            const std::string partial_psbt = partial_result["psbt"].get_str();

            // Exchange partial signatures
            if (is_initiator) {
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "partial_psbt");
                payload.pushKV("psbt", partial_psbt);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;

                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;
            } else {
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(30000);
                recv_req.params = recv_params;
                tableRPC.execute(recv_req);
                messages_received++;

                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "partial_psbt");
                payload.pushKV("psbt", partial_psbt);
                send_params.push_back(payload);
                send_req.params = send_params;
                tableRPC.execute(send_req);
                messages_sent++;
            }

            // Complete ceremony
            JSONRPCRequest complete_req;
            complete_req.context = request.context;
            complete_req.strMethod = "adaptor.complete";
            UniValue complete_params(UniValue::VARR);
            complete_params.push_back(partial_psbt);
            complete_params.push_back(commitments);
            complete_req.params = complete_params;

            UniValue complete_result = tableRPC.execute(complete_req);

            auto end_time = std::chrono::steady_clock::now();
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", complete_result["psbt"]);

            UniValue stats(UniValue::VOBJ);
            stats.pushKV("messages_sent", messages_sent);
            stats.pushKV("messages_received", messages_received);
            stats.pushKV("duration_ms", duration_ms);
            result.pushKV("ceremony_stats", stats);

            return result;
        }
    );
}

RPCHelpMan forward_close_over_channel()
{
    return RPCHelpMan(
        "forward.close_over_channel",
        "Build cooperative close PSBT and coordinate Fair-Sign ceremony over an active cosign session.\n"
        "This is a convenience wrapper that combines forward.build_coop_close with cosign-based ceremony coordination.",
        std::vector<RPCArg>{
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Active cosign session identifier"},
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"settlement", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Settlement distribution (defaults to cooperative leaf layout)",
                std::vector<RPCArg>{
                    {"to_long", RPCArg::Type::ARR, RPCArg::Optional::NO, "Outputs to long party",
                        std::vector<RPCArg>{
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                std::vector<RPCArg>{
                                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Asset ID (omit for native BTC)"},
                                    {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Amount in sats or asset units"},
                                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination (defaults to long party's settlement address)"},
                                }
                            }
                        }
                    },
                    {"to_short", RPCArg::Type::ARR, RPCArg::Optional::NO, "Outputs to short party",
                        std::vector<RPCArg>{
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                std::vector<RPCArg>{
                                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Asset ID (omit for native BTC)"},
                                    {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Amount in sats or asset units"},
                                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination (defaults to short party's settlement address)"},
                                }
                            }
                        }
                    },
                }
            },
            {"is_initiator", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this party initiates the ceremony (default: true)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Completed cooperative close PSBT with all signatures (base64)"},
                {RPCResult::Type::NUM, "fee", "Estimated fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::OBJ, "ceremony_stats", "Ceremony statistics",
                    {
                        {RPCResult::Type::NUM, "messages_sent", "Number of messages sent"},
                        {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
                        {RPCResult::Type::NUM, "duration_ms", "Ceremony duration in milliseconds"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.close_over_channel", "\"69d967c0e415c9a3\" \"" + std::string(64, 'a') + "\" \"{\\\"to_long\\\":[...], \\\"to_short\\\":[...]}\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            const std::string session_id = request.params[0].get_str();
            const std::string contract_id_hex = request.params[1].get_str();
            const bool is_initiator = (request.params.size() > 3 && !request.params[3].isNull()) ? request.params[3].get_bool() : true;

            // Step 1: Build cooperative close PSBT
            JSONRPCRequest build_req;
            build_req.context = request.context;
            build_req.strMethod = "forward.build_coop_close";
            UniValue build_params(UniValue::VARR);
            build_params.push_back(contract_id_hex);

            // Add settlement if provided
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                build_params.push_back(request.params[2]);
            }

            build_req.params = build_params;
            UniValue build_result = tableRPC.execute(build_req);

            const std::string coop_close_psbt = build_result["psbt"].get_str();
            const CAmount fee = AmountFromValue(build_result["fee"]);

            // Step 2: Coordinate Fair-Sign ceremony over cosign channel
            JSONRPCRequest sign_req;
            sign_req.context = request.context;
            sign_req.strMethod = "forward.sign_over_channel";
            UniValue sign_params(UniValue::VARR);
            sign_params.push_back(session_id);
            sign_params.push_back(coop_close_psbt);
            sign_params.push_back(is_initiator);
            sign_req.params = sign_params;

            UniValue sign_result = tableRPC.execute(sign_req);

            // Combine results
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", sign_result["psbt"]);
            result.pushKV("fee", ValueFromAmount(fee));
            result.pushKV("ceremony_stats", sign_result["ceremony_stats"]);

            return result;
        }
    );
}

RPCHelpMan forward_list_offers()
{
    return RPCHelpMan(
        "forward.list_offers",
        "List all forward contract offers in wallet registry.",
        std::vector<RPCArg>{},
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                        {RPCResult::Type::STR, "state", "Contract state"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.list_offers", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            std::vector<ForwardContractRecord> contracts = pwallet->ListForwardContracts();
            UniValue result(UniValue::VARR);
            for (const auto& contract : contracts) {
                UniValue item(UniValue::VOBJ);
                item.pushKV("offer_id", contract.contract_id.GetHex());
                item.pushKV("state", ForwardContractStateToString(contract.DerivedState()));

                // Add lifecycle transaction IDs if available
                if (contract.open_txid) {
                    item.pushKV("open_txid", contract.open_txid->GetHex());
                }
                if (contract.self_delivery_txid) {
                    item.pushKV("self_delivery_txid", contract.self_delivery_txid->GetHex());
                }
                if (contract.coop_close_txid) {
                    item.pushKV("coop_close_txid", contract.coop_close_txid->GetHex());
                }
                if (contract.escrow_claim_txid) {
                    item.pushKV("escrow_claim_txid", contract.escrow_claim_txid->GetHex());
                }
                if (contract.escrow_refund_txid) {
                    item.pushKV("escrow_refund_txid", contract.escrow_refund_txid->GetHex());
                }
                if (contract.timeout_txid) {
                    item.pushKV("timeout_txid", contract.timeout_txid->GetHex());
                }

                result.push_back(item);
            }
            return result;
        }
    );
}

RPCHelpMan forward_import_acceptance()
{
    return RPCHelpMan(
        "forward.import_acceptance",
        "Import a forward contract acceptance payload.",
        std::vector<RPCArg>{
            {"acceptance", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Acceptance payload", std::vector<RPCArg>{}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "offer_id", "Unique offer identifier"},
                {RPCResult::Type::STR, "state", "Contract state after import"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.import_acceptance", "\"{...acceptance json...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& acceptance_obj = request.params[0].get_obj();
            const std::string offer_id_hex = acceptance_obj.find_value("offer_id").get_str();
            const uint256 contract_id = ParseHashV(UniValue(offer_id_hex), "offer_id");

            auto record_opt = pwallet->FindForwardContract(contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract offer");
            }

            // Parse acceptance commitment
            const std::string accept_commitment = acceptance_obj.find_value("commitment").get_str();

            // Parse acceptance salt
            const std::string salt_hex = acceptance_obj.find_value("salt").get_str();
            const uint256 acceptance_salt = ParseHashV(UniValue(salt_hex), "salt");

            // Parse counterparty adaptor point
            const std::string counter_adaptor_hex = acceptance_obj.find_value("fs_tx_adaptor_point").get_str();
            std::vector<unsigned char> counter_adaptor_bytes = ParseHex(counter_adaptor_hex);
            if (counter_adaptor_bytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid counterparty adaptor point");
            }
            XOnlyPubKey counter_point;
            std::copy(counter_adaptor_bytes.begin(), counter_adaptor_bytes.end(), counter_point.begin());

            std::optional<XOnlyPubKey> long_internal_accept;
            std::optional<XOnlyPubKey> short_internal_accept;
            const UniValue& acceptance_internals = acceptance_obj.find_value("internal_keys");
            if (!acceptance_internals.isNull()) {
                if (!acceptance_internals.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "acceptance.internal_keys must be an object when provided");
                }
                const UniValue& long_val = acceptance_internals.find_value("long_margin");
                const UniValue& short_val = acceptance_internals.find_value("short_margin");
                long_internal_accept = ParseInternalKeyOptional(long_val, "acceptance.internal_keys.long_margin");
                short_internal_accept = ParseInternalKeyOptional(short_val, "acceptance.internal_keys.short_margin");
            }

            ForwardContractRecord updated = *record_opt;
            updated.long_margin_internal_key = ResolveForwardMarginKey(
                *pwallet,
                updated.terms.long_party.margin_dest,
                updated.long_margin_internal_key,
                long_internal_accept,
                "acceptance.internal_keys.long_margin",
                updated.local_side,
                ForwardSide::LONG);
            updated.short_margin_internal_key = ResolveForwardMarginKey(
                *pwallet,
                updated.terms.short_party.margin_dest,
                updated.short_margin_internal_key,
                short_internal_accept,
                "acceptance.internal_keys.short_margin",
                updated.local_side,
                ForwardSide::SHORT);
            MaybePopulateLocalMarginKey(*pwallet, updated.terms.long_party.margin_dest, updated.long_margin_internal_key);
            MaybePopulateLocalMarginKey(*pwallet, updated.terms.short_party.margin_dest, updated.short_margin_internal_key);

            ForwardContractRecord stored = pwallet->RegisterForwardContract(std::move(updated));
            CacheForwardVaultScripts(*pwallet, stored);

            // Mark contract as accepted with proper signature
            pwallet->MarkForwardContractAccepted(contract_id, accept_commitment, acceptance_salt, counter_point, std::nullopt);

            UniValue result(UniValue::VOBJ);
            result.pushKV("offer_id", contract_id.GetHex());
            result.pushKV("state", "accepted");
            return result;
        }
    );
}

RPCHelpMan forward_build_open()
{
    return RPCHelpMan(
        "forward.build_open",
        "Construct the opening PSBT for a forward contract, creating both IM vaults atomically. "
        "CRITICAL: This creates Bob's IM vault (locks IM_B) and Alice's IM vault (locks IM_A) with their respective taptrees "
        "as specified in FINANCING_PRIMITIVES §3.2. Each vault can lock native BTC or any issued asset as initial margin. "
        "Two-party workflow: Long party calls with auto_fund_long=true (and optionally auto_fund_premium=true), short party receives PSBT and calls with psbt= and auto_fund_short=true to add short IM funding.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward offer identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional funding overrides",
                std::vector<RPCArg>{
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                    {"auto_fund_long", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Long party mode: automatically attach wallet-controlled inputs for long IM"},
                    {"auto_fund_short", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Short party mode: automatically attach wallet-controlled inputs for short IM"},
                    {"auto_fund_premium", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Include premium in long party funding (requires auto_fund_long)"},
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Existing PSBT to add funding to (used with auto_fund_short)"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override fee rate in sat/vB (wallet estimate if omitted)"},
                },
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT containing the funded covenant transaction"},
                {RPCResult::Type::NUM, "fee", "Fee (in " + CURRENCY_UNIT + ") paid by the wallet"},
                {RPCResult::Type::NUM, "premium_output_index", "Index of the premium output (P0)"},
                {RPCResult::Type::NUM, "bob_vault_index", "Index of Bob's IM vault output"},
                {RPCResult::Type::NUM, "alice_vault_index", "Index of Alice's IM vault output"},
                {RPCResult::Type::OBJ, "bob_vault_taproot", "Bob IM vault Taproot construction", RepoTaprootResultDescription()},
                {RPCResult::Type::OBJ, "alice_vault_taproot", "Alice IM vault Taproot construction", RepoTaprootResultDescription()},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT already contains all signatures"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.build_open", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            // ===== REGISTRY LOOKUP =====
            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            ForwardContractRecord record = *record_opt;

            // Ensure the forward contract's vault metadata is fully materialised before
            // constructing the cooperative close transaction. The asynchronous wallet scanner
            // eventually persists vault outpoints after the open transaction confirms, but the
            // adaptor ceremony requires the registry immediately so the PSBT carries explicit
            // vault intents on the very first prepare() call.
            if (!record.long_margin_vault.has_value() || !record.short_margin_vault.has_value()) {
                bool state_refreshed = false;
                {
                    LOCK(pwallet->cs_wallet);
                    state_refreshed = pwallet->EnsureForwardStateMetadata(record.contract_id);
                }
                if (state_refreshed) {
                    if (auto refreshed = pwallet->FindForwardContract(record.contract_id)) {
                        record = *refreshed;
                    }
                }
            }
            const ForwardTerms& terms = record.terms;

            bool updated_keys = false;
            if (!record.long_margin_internal_key) {
                record.long_margin_internal_key = LookupTaprootInternalKey(*pwallet, terms.long_party.margin_dest);
                if (record.long_margin_internal_key) updated_keys = true;
            }
            if (!record.short_margin_internal_key) {
                record.short_margin_internal_key = LookupTaprootInternalKey(*pwallet, terms.short_party.margin_dest);
                if (record.short_margin_internal_key) updated_keys = true;
            }

            if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Forward contract missing margin internal keys - re-import counterparty payloads");
            }

            if (updated_keys) {
                record = pwallet->RegisterForwardContract(std::move(record));
                CacheForwardVaultScripts(*pwallet, record);
            }

            EnsureForwardVaultState(*pwallet, request, record);

            VerifyForwardSignability(*pwallet, record);

            const XOnlyPubKey alice_key = *record.long_margin_internal_key;
            const XOnlyPubKey bob_key = *record.short_margin_internal_key;

            // ===== BUILD ESCROW OUTPUTS DETERMINISTICALLY =====
            const WitnessV1Taproot b_escrow_taproot = BuildBEscrowTaproot(terms, alice_key, bob_key, record.contract_id);
            const WitnessV1Taproot a_escrow_taproot = BuildAEscrowTaproot(terms, alice_key, bob_key, record.contract_id);

            // ===== BUILD BOB IM VAULT TAPTREE =====
            // Leaf B-SELF: Bob self-delivers, reclaims IM_B, creates B_ESCROW
            CScript b_self = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
            b_self << OP_VERIFY;
            CScript b_escrow_match = BuildOutputMatchForLeg(terms.short_party.deliver_leg, b_escrow_taproot);
            b_self.insert(b_self.end(), b_escrow_match.begin(), b_escrow_match.end());
            b_self << OP_VERIFY;
            b_self << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

            // Leaf B-COUNTER: Bob counter-delivers (reclaims IM while claiming A_ESCROW)
            CScript b_counter;
            // NO CLTV - can be used immediately after long delivers (escrow exists)
            CScript short_margin_match = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
            b_counter.insert(b_counter.end(), short_margin_match.begin(), short_margin_match.end());
            b_counter << OP_VERIFY;
            CScript short_payment_match = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
            b_counter.insert(b_counter.end(), short_payment_match.begin(), short_payment_match.end());
            b_counter << OP_VERIFY;
            b_counter << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

            // Leaf B-TIMEOUT: Alice seizes IM_B at T
            CScript b_timeout;
            b_timeout << CScriptNum(terms.deadline_short) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
            b_timeout << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

            // Leaf COOP: Joint close (4x OP_OUTPUTMATCH)
            CScript coop = BuildOutputMatchForLeg(terms.short_party.deliver_leg, terms.long_party.settlement_receive_dest);
            coop << OP_VERIFY;
            CScript match2 = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
            coop.insert(coop.end(), match2.begin(), match2.end());
            coop << OP_VERIFY;
            CScript match3 = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
            coop.insert(coop.end(), match3.begin(), match3.end());
            coop << OP_VERIFY;
            CScript match4 = BuildOutputMatchForLeg(terms.short_party.margin_leg, terms.short_party.margin_dest);
            coop.insert(coop.end(), match4.begin(), match4.end());
            coop << OP_VERIFY;
            coop << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIGVERIFY;
            coop << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

            TaprootBuilder bob_vault_builder;
            bob_vault_builder.Add(2, std::vector<unsigned char>(b_self.begin(), b_self.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            bob_vault_builder.Add(2, std::vector<unsigned char>(b_counter.begin(), b_counter.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            bob_vault_builder.Add(2, std::vector<unsigned char>(b_timeout.begin(), b_timeout.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            bob_vault_builder.Add(2, std::vector<unsigned char>(coop.begin(), coop.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            // Disable unilateral key-path: NUMS internal key for IM (short)
            bob_vault_builder.Finalize(DeriveScriptOnlyInternalKey("forward-im-short", record.contract_id));
            if (!bob_vault_builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct Bob IM vault taptree");
            }
            WitnessV1Taproot bob_vault_output{bob_vault_builder.GetOutput()};

            // ===== BUILD ALICE IM VAULT TAPTREE =====
            // Leaf A-SELF: Alice self-delivers (>= T), reclaims IM_A, creates A_ESCROW
            CScript a_self;
            a_self << CScriptNum(terms.deadline_short) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
            CScript a_margin_match = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
            a_self.insert(a_self.end(), a_margin_match.begin(), a_margin_match.end());
            a_self << OP_VERIFY;
            CScript a_escrow_match = BuildOutputMatchForLeg(terms.long_party.deliver_leg, a_escrow_taproot);
            a_self.insert(a_self.end(), a_escrow_match.begin(), a_escrow_match.end());
            a_self << OP_VERIFY;
            a_self << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

            // Leaf A-COUNTER: Alice counter-delivers (reclaims IM while claiming B_ESCROW)
            CScript a_counter;
            // NO CLTV - can be used immediately after short delivers (escrow exists)
            CScript long_margin_match = BuildOutputMatchForLeg(terms.long_party.margin_leg, terms.long_party.margin_dest);
            a_counter.insert(a_counter.end(), long_margin_match.begin(), long_margin_match.end());
            a_counter << OP_VERIFY;
            CScript long_payment_match = BuildOutputMatchForLeg(terms.long_party.deliver_leg, terms.short_party.settlement_receive_dest);
            a_counter.insert(a_counter.end(), long_payment_match.begin(), long_payment_match.end());
            a_counter << OP_VERIFY;
            a_counter << std::vector<unsigned char>(alice_key.begin(), alice_key.end()) << OP_CHECKSIG;

            // Leaf A-TIMEOUT: Bob seizes IM_A at T+K
            CScript a_timeout;
            a_timeout << CScriptNum(terms.deadline_long) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
            a_timeout << std::vector<unsigned char>(bob_key.begin(), bob_key.end()) << OP_CHECKSIG;

            TaprootBuilder alice_vault_builder;
            alice_vault_builder.Add(2, std::vector<unsigned char>(a_self.begin(), a_self.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            alice_vault_builder.Add(2, std::vector<unsigned char>(a_counter.begin(), a_counter.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            alice_vault_builder.Add(2, std::vector<unsigned char>(a_timeout.begin(), a_timeout.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            alice_vault_builder.Add(2, std::vector<unsigned char>(coop.begin(), coop.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
            // Disable unilateral key-path: NUMS internal key for IM (long)
            alice_vault_builder.Finalize(DeriveScriptOnlyInternalKey("forward-im-long", record.contract_id));
            if (!alice_vault_builder.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct Alice IM vault taptree");
            }
            WitnessV1Taproot alice_vault_output{alice_vault_builder.GetOutput()};

            const CScript bob_vault_spk = GetScriptForDestination(bob_vault_output);
            const CScript alice_vault_spk = GetScriptForDestination(alice_vault_output);

            // ===== PARSE MODE FLAGS EARLY (needed by recipient building logic) =====
            const UniValue opts = request.params.size() > 1 && request.params[1].isObject() ? request.params[1].get_obj() : UniValue::VNULL;

            // Parse mode flags
            const UniValue& auto_fund_long_val = opts.isNull() ? NullUniValue : opts.find_value("auto_fund_long");
            const bool auto_fund_long = !auto_fund_long_val.isNull() && auto_fund_long_val.get_bool();
            const UniValue& auto_fund_short_val = opts.isNull() ? NullUniValue : opts.find_value("auto_fund_short");
            const bool auto_fund_short = !auto_fund_short_val.isNull() && auto_fund_short_val.get_bool();
            const UniValue& auto_fund_premium_val = opts.isNull() ? NullUniValue : opts.find_value("auto_fund_premium");
            const bool auto_fund_premium = !auto_fund_premium_val.isNull() && auto_fund_premium_val.get_bool();
            const UniValue& psbt_val = opts.isNull() ? NullUniValue : opts.find_value("psbt");

            // Validate mode flags
            if (auto_fund_long && auto_fund_short) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both auto_fund_long and auto_fund_short");
            }
            if (auto_fund_short && psbt_val.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "auto_fund_short requires psbt parameter");
            }
            if (auto_fund_premium && !auto_fund_long) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "auto_fund_premium requires auto_fund_long");
            }
            if (!auto_fund_long && !auto_fund_short) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Must specify either auto_fund_long or auto_fund_short. "
                    "Single-wallet self-funding is deprecated. "
                    "Use two-party workflow: long party calls with auto_fund_long=true, "
                    "short party augments with auto_fund_short=true and psbt=<long_psbt>.");
            }

            std::set<COutPoint> used_asset_outpoints;

            struct AssetInputSpec {
                COutPoint outpoint;
            };
            std::vector<AssetInputSpec> asset_input_specs;

            struct AssetChangeSpec {
                CTxDestination dest;
                uint256 asset_id;
                uint64_t units;
            };
            std::vector<AssetChangeSpec> asset_change_specs;

            struct AssetOutputCandidate {
                CScript script;
                CAmount value;
                uint256 asset_id;
                uint64_t units;
            };
            std::vector<AssetOutputCandidate> asset_output_candidates;

            const auto select_asset_inputs = [&](const AssetLeg& leg, const char* label) {
                if (leg.is_native) return;

                CCoinControl asset_cc;
                asset_cc.m_avoid_asset_utxos = false;
                asset_cc.m_required_asset_id = leg.asset_id;
                asset_cc.m_include_unsafe_inputs = true;

                CoinsResult asset_candidates;
                {
                    LOCK(pwallet->cs_wallet);
                    asset_candidates = AvailableCoins(*pwallet, &asset_cc);
                }

                uint64_t accumulated_units{0};
                for (const COutput& candidate : asset_candidates.All()) {
                    if (!candidate.spendable) continue;
                    if (used_asset_outpoints.count(candidate.outpoint)) continue;
                    auto tag = assets::ParseAssetTag(candidate.txout.vExt);
                    if (!tag || tag->id != leg.asset_id) continue;

                    asset_input_specs.push_back({candidate.outpoint});
                    used_asset_outpoints.insert(candidate.outpoint);
                    accumulated_units += tag->amount;
                    if (accumulated_units >= leg.units) {
                        break;
                    }
                }

                if (accumulated_units < leg.units) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient funds for asset %s (%s requires %s units, have %s)",
                                  leg.asset_id.GetHex(), label,
                                  util::ToString(leg.units),
                                  util::ToString(accumulated_units)));
                }

                const uint64_t change_units = accumulated_units - leg.units;
                if (change_units > 0) {
                    EnsureWalletIsUnlocked(*pwallet);
                    auto dest_res = pwallet->GetNewDestination(OutputType::BECH32M, "forward-asset-change");
                    if (!dest_res) {
                        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(dest_res).original);
                    }
                    asset_change_specs.push_back({*dest_res, leg.asset_id, change_units});
                }
            };

            // ===== DETECT PREMIUM PAYMENT DIRECTION =====
            // Premium destination tells us who RECEIVES premium, hence who PAYS it:
            // - If premium_dest matches short party's address → long pays premium
            // - If premium_dest matches long party's address → short pays premium
            bool long_pays_premium = false;
            bool short_pays_premium = false;
            if (terms.premium_leg.units > 0) {
                // Check if premium goes to short party (long pays)
                const CScript short_settlement_spk = GetScriptForDestination(terms.short_party.settlement_receive_dest);
                const CScript premium_spk = GetScriptForDestination(terms.premium_dest);
                if (premium_spk == short_settlement_spk) {
                    long_pays_premium = true;
                }
                // Check if premium goes to long party (short pays)
                const CScript long_settlement_spk = GetScriptForDestination(terms.long_party.settlement_receive_dest);
                if (premium_spk == long_settlement_spk) {
                    short_pays_premium = true;
                }

                if (!long_pays_premium && !short_pays_premium) {
                    // Premium goes to neither party's settlement address - unusual but possible
                    // Default to long pays premium
                    long_pays_premium = true;
                }
            }

            // ===== BUILD RECIPIENTS (LONG MODE) =====
            std::vector<CRecipient> recipients;
            size_t premium_output_index = SIZE_MAX;

            // Premium output - create if premium exists, fund if long pays it
            if (terms.premium_leg.units > 0 && (auto_fund_premium || long_pays_premium)) {
                const CAmount premium_sats = terms.premium_leg.is_native
                    ? static_cast<CAmount>(terms.premium_leg.units)
                    : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                premium_output_index = recipients.size();
                recipients.push_back({terms.premium_dest, premium_sats, false});
                if (!terms.premium_leg.is_native) {
                    asset_output_candidates.push_back({
                        GetScriptForDestination(terms.premium_dest),
                        premium_sats,
                        terms.premium_leg.asset_id,
                        terms.premium_leg.units
                    });
                    select_asset_inputs(terms.premium_leg, "premium");
                }
            }

            // Alice IM vault (long margin) - ALWAYS funded in LONG MODE
            const AssetLeg& im_alice = terms.long_party.margin_leg;
            const CAmount alice_vault_sats = im_alice.is_native ? static_cast<CAmount>(im_alice.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
            recipients.push_back({alice_vault_output, alice_vault_sats, false});
            if (!im_alice.is_native) {
                asset_output_candidates.push_back({alice_vault_spk, alice_vault_sats, im_alice.asset_id, im_alice.units});
                select_asset_inputs(im_alice, "long margin");
            }

            // Bob IM vault (short margin) - Will be added as PLACEHOLDER after FundTransaction
            // NOTE: We do NOT add bob's vault to recipients for FundTransaction because that would
            // cause the long wallet to try to fund it. Instead, we'll manually insert it after funding.
            const AssetLeg& im_bob = terms.short_party.margin_leg;
            const CAmount bob_vault_sats = im_bob.is_native ? static_cast<CAmount>(im_bob.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;

            for (const AssetChangeSpec& change_spec : asset_change_specs) {
                const CAmount change_value = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                recipients.push_back({change_spec.dest, change_value, false});
                asset_output_candidates.push_back({
                    GetScriptForDestination(change_spec.dest),
                    change_value,
                    change_spec.asset_id,
                    change_spec.units
                });
            }

            // Parse fee_rate override
            std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);

            // Fund transaction
            CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            if (fee_rate_override) {
                coin_control.m_feerate = CFeeRate(static_cast<CAmount>(*fee_rate_override * 1000)); // sat/vB -> sat/kB
                coin_control.fOverrideFeeRate = true;
            }

            CMutableTransaction tx_template;
            tx_template.version = 2;

            // Parse locktime from options (already parsed above)
            if (!opts.isNull()) {
                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    int64_t locktime = ParseSignedInt64(locktime_val, "options.locktime");
                    if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.locktime out of range");
                    }
                    tx_template.nLockTime = static_cast<uint32_t>(locktime);
                }
            }

            // ===== SHORT MODE: Augment existing PSBT from long party =====
            if (auto_fund_short) {
                const std::string psbt_str = psbt_val.get_str();
                PartiallySignedTransaction psbtx;
                std::string error;
                if (!DecodeBase64PSBT(psbtx, psbt_str, error)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode PSBT: %s", error));
                }

                // Validate that both vault outputs exist in long party's PSBT
                std::optional<size_t> long_alice_vault_idx, long_bob_vault_idx, long_premium_idx;
                for (size_t i = 0; i < psbtx.tx->vout.size(); ++i) {
                    const CTxOut& out = psbtx.tx->vout[i];
                    if (out.scriptPubKey == bob_vault_spk && out.nValue == bob_vault_sats) {
                        long_bob_vault_idx = i;
                    }
                    if (out.scriptPubKey == alice_vault_spk && out.nValue == alice_vault_sats) {
                        long_alice_vault_idx = i;
                    }
                    if (terms.premium_leg.units > 0) {
                        const CScript premium_spk = GetScriptForDestination(terms.premium_dest);
                        const CAmount expected_premium_sats = terms.premium_leg.is_native
                            ? static_cast<CAmount>(terms.premium_leg.units)
                            : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                        if (out.scriptPubKey == premium_spk && out.nValue == expected_premium_sats) {
                            long_premium_idx = i;
                        }
                    }
                }

                if (!long_bob_vault_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Long party's PSBT missing Bob (short) IM vault output");
                }
                if (!long_alice_vault_idx) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Long party's PSBT missing Alice (long) IM vault output");
                }

                // Validate premium based on payment direction
                if (short_pays_premium && terms.premium_leg.units > 0) {
                    // TODO: Full implementation of short-paid premiums requires:
                    // - Long party creating premium output placeholder (unfunded)
                    // - Short party funding it via sendasset (for assets) or coin selection (native)
                    // - Merging premium inputs with Bob's IM inputs
                    // For now, throw an error directing user to use long-paid premiums
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Short-party premium payments not yet fully implemented in two-party flow. "
                        "Please structure the contract so the long party pays the premium to the short party.");
                }

                if (long_pays_premium && !long_premium_idx && terms.premium_leg.units > 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Long party should have funded premium but didn't include it in PSBT");
                }

                CMutableTransaction final_tx;
                final_tx.version = psbtx.tx->version;
                final_tx.nLockTime = psbtx.tx->nLockTime;
                CAmount short_fee = 0;
                int short_change_index = -1;
                [[maybe_unused]] int short_asset_change_index = -1;

                // ===== FUND SHORT OBLIGATIONS =====
                // Short party must fund: Bob's IM + (optionally) premium if short_pays_premium

                // Fund short margin (Bob's IM)
                const AssetLeg& im_bob = terms.short_party.margin_leg;
                if (!im_bob.is_native) {
                    // ASSET SHORT MARGIN: Use sendasset() skeleton
                    JSONRPCRequest sendasset_req;
                    sendasset_req.context = request.context;
                    sendasset_req.URI = request.URI;
                    sendasset_req.strMethod = "sendasset";

                    UniValue sendasset_params(UniValue::VARR);
                    sendasset_params.push_back(im_bob.asset_id.ToString());
                    sendasset_params.push_back(EncodeDestination(bob_vault_output));
                    sendasset_params.push_back(im_bob.units);

                    UniValue sendasset_opts(UniValue::VOBJ);
                    sendasset_opts.pushKV("return_skeleton", true);
                    sendasset_opts.pushKV("broadcast", false);
                    // Use explicit fee_rate override, or default to 2 sat/vB
                    sendasset_opts.pushKV("fee_rate", fee_rate_override.value_or(2.0));
                    sendasset_params.push_back(sendasset_opts);

                    sendasset_req.params = sendasset_params;

                    UniValue skeleton_result = sendasset().HandleRequest(sendasset_req);
                    if (!skeleton_result.isObject() || !skeleton_result.exists("hex")) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "sendasset did not return valid skeleton for short margin");
                    }

                    CMutableTransaction short_skeleton;
                    if (!DecodeHexTx(short_skeleton, skeleton_result["hex"].get_str())) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode sendasset skeleton for short margin");
                    }

                    // Merge: long inputs + short inputs
                    final_tx.vin = psbtx.tx->vin;
                    for (const CTxIn& txin : short_skeleton.vin) {
                        final_tx.vin.push_back(txin);
                    }

                    // Start with long's outputs (both vaults + premium + long's change)
                    final_tx.vout = psbtx.tx->vout;

                    // Find short margin vault in skeleton and replace the placeholder in long's PSBT
                    std::optional<size_t> skeleton_bob_vault_idx;
                    for (size_t i = 0; i < short_skeleton.vout.size(); ++i) {
                        if (short_skeleton.vout[i].scriptPubKey == bob_vault_spk) {
                            skeleton_bob_vault_idx = i;
                            break;
                        }
                    }
                    if (!skeleton_bob_vault_idx) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "sendasset skeleton missing short margin vault output");
                    }

                    // Replace long's bob vault placeholder with skeleton's properly-tagged output
                    final_tx.vout[*long_bob_vault_idx] = short_skeleton.vout[*skeleton_bob_vault_idx];

                    // Append short's change outputs (asset change + optional BTC change)
                    for (size_t i = 0; i < short_skeleton.vout.size(); ++i) {
                        if (i == *skeleton_bob_vault_idx) continue; // Skip vault (already placed)

                        const CTxOut& out = short_skeleton.vout[i];
                        const size_t new_idx = final_tx.vout.size();
                        final_tx.vout.push_back(out);

                        // Track asset change
                        if (auto tag = assets::ParseAssetTag(out.vExt)) {
                            if (tag->id == im_bob.asset_id && tag->amount != im_bob.units) {
                                short_asset_change_index = static_cast<int>(new_idx);
                            }
                        }

                        // Track BTC change
                        if (short_change_index == -1 && out.scriptPubKey != bob_vault_spk && out.scriptPubKey != alice_vault_spk) {
                            if (!assets::ParseAssetTag(out.vExt)) {
                                short_change_index = static_cast<int>(new_idx);
                            }
                        }
                    }

                    if (skeleton_result.exists("fee")) {
                        short_fee = AmountFromValue(skeleton_result["fee"]);
                    }

                } else {
                    // NATIVE BTC SHORT MARGIN: Manually select inputs but respect explicit fee overrides
                    const CAmount bob_margin_sats = static_cast<CAmount>(im_bob.units);

                    CFeeRate eff_fee_rate;
                    if (fee_rate_override) {
                        eff_fee_rate = CFeeRate(static_cast<CAmount>(*fee_rate_override * 1000)); // sat/vB -> sat/kB
                    } else if (pwallet->m_pay_tx_fee != CFeeRate(0)) {
                        eff_fee_rate = pwallet->m_pay_tx_fee;
                    } else {
                        eff_fee_rate = CFeeRate(1000); // 1 sat/vB fallback
                    }
                    // Use conservative estimate (~320 vbytes) to cover adaptor ceremony scaffolding
                    const CAmount estimated_fee = eff_fee_rate.GetFee(320);

                    CoinsResult btc_candidates;
                    {
                        CCoinControl short_coin_control;
                        short_coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
                        short_coin_control.m_avoid_asset_utxos = true;
                        LOCK(pwallet->cs_wallet);
                        btc_candidates = AvailableCoins(*pwallet, &short_coin_control);
                    }

                    CAmount accumulated_sats = 0;
                    std::vector<COutPoint> selected_inputs;
                    for (const COutput& candidate : btc_candidates.All()) {
                        if (!candidate.spendable) continue;
                        selected_inputs.push_back(candidate.outpoint);
                        accumulated_sats += candidate.txout.nValue;
                        if (accumulated_sats >= bob_margin_sats + estimated_fee) {
                            break;
                        }
                    }

                    if (accumulated_sats < bob_margin_sats + estimated_fee) {
                        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                            strprintf("Insufficient BTC for short margin (need %s, have %s)",
                                      FormatMoney(bob_margin_sats + estimated_fee),
                                      FormatMoney(accumulated_sats)));
                    }

                    // Merge: long inputs + short inputs
                    final_tx.vin = psbtx.tx->vin;
                    for (const COutPoint& outpoint : selected_inputs) {
                        CTxIn new_in(outpoint);
                        new_in.nSequence = MAX_BIP125_RBF_SEQUENCE;
                        final_tx.vin.push_back(new_in);
                    }

                    // Outputs: long's original outputs
                    final_tx.vout = psbtx.tx->vout;

                    // Replace Bob's vault placeholder with properly funded output (no asset tag needed for native BTC)
                    final_tx.vout[*long_bob_vault_idx].nValue = bob_margin_sats;

                    // Add change output if any
                    const CAmount change_amount = accumulated_sats - bob_margin_sats - estimated_fee;
                    if (change_amount > 0) {
                        EnsureWalletIsUnlocked(*pwallet);
                        auto dest_res = pwallet->GetNewDestination(OutputType::BECH32M, "forward-short-change");
                        if (!dest_res) {
                            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(dest_res).original);
                        }
                        CTxOut change_out;
                        change_out.scriptPubKey = GetScriptForDestination(*dest_res);
                        change_out.nValue = change_amount;
                        short_change_index = static_cast<int>(final_tx.vout.size());
                        final_tx.vout.push_back(change_out);
                    }

                    short_fee = estimated_fee;
                }

                // Create PSBT from merged transaction
                PartiallySignedTransaction funded_psbt(final_tx);

                const size_t long_input_count = psbtx.inputs.size();
                const size_t long_output_count = psbtx.outputs.size();

                // Copy long party's PSBT metadata (CRITICAL for covenant annotations)
                for (size_t i = 0; i < long_input_count && i < funded_psbt.inputs.size(); ++i) {
                    funded_psbt.inputs[i] = psbtx.inputs[i];
                }
                for (size_t i = 0; i < long_output_count && i < funded_psbt.outputs.size(); ++i) {
                    funded_psbt.outputs[i] = psbtx.outputs[i];
                }

                // Fill witness_utxo for short's inputs
                for (size_t i = long_input_count; i < final_tx.vin.size(); ++i) {
                    const CTxIn& txin = final_tx.vin[i];
                    const CWalletTx* wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(txin.prevout.hash));
                    if (wtx && txin.prevout.n < wtx->tx->vout.size()) {
                        funded_psbt.inputs[i].witness_utxo = wtx->tx->vout[txin.prevout.n];
                    }
                }

                // Preserve global PSBT metadata
                funded_psbt.m_proprietary = psbtx.m_proprietary;
                funded_psbt.unknown = psbtx.unknown;

                bool funded_complete = false;
                if (const auto fill_err = pwallet->FillPSBT(funded_psbt, funded_complete, SIGHASH_DEFAULT, false, true)) {
                    throw JSONRPCPSBTError(*fill_err);
                }

                AnnotateTaprootInputsWithInternalKeys(*pwallet, funded_psbt);

                // Return augmented PSBT
                DataStream ssTx{};
                ssTx << funded_psbt;
                UniValue result(UniValue::VOBJ);
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("fee", ValueFromAmount(short_fee));
                result.pushKV("complete", funded_complete);
                result.pushKV("premium_output_index", long_premium_idx.has_value() ? static_cast<int>(*long_premium_idx) : -1);
                result.pushKV("bob_vault_index", long_bob_vault_idx.has_value() ? static_cast<int>(*long_bob_vault_idx) : -1);
                result.pushKV("alice_vault_index", long_alice_vault_idx.has_value() ? static_cast<int>(*long_alice_vault_idx) : -1);

                // Taproot construction details (include tree for RPC schema compliance)
                UniValue bob_taproot(UniValue::VOBJ);
                bob_taproot.pushKV("output_key", HexStr(std::vector<unsigned char>(bob_vault_output.begin(), bob_vault_output.end())));
                bob_taproot.pushKV("internal_key", HexStr(std::vector<unsigned char>(bob_key.begin(), bob_key.end())));
                bob_taproot.pushKV("script_pubkey", HexStr(bob_vault_spk));

                UniValue bob_leaves(UniValue::VARR);
                for (const auto& [depth, leaf_ver, script] : bob_vault_builder.GetTreeTuples()) {
                    UniValue leaf(UniValue::VOBJ);
                    leaf.pushKV("depth", depth);
                    leaf.pushKV("leaf_version", leaf_ver);
                    leaf.pushKV("script", HexStr(script));
                    bob_leaves.push_back(leaf);
                }
                bob_taproot.pushKV("tree", bob_leaves);
                result.pushKV("bob_vault_taproot", bob_taproot);

                UniValue alice_taproot(UniValue::VOBJ);
                alice_taproot.pushKV("output_key", HexStr(std::vector<unsigned char>(alice_vault_output.begin(), alice_vault_output.end())));
                alice_taproot.pushKV("internal_key", HexStr(std::vector<unsigned char>(alice_key.begin(), alice_key.end())));
                alice_taproot.pushKV("script_pubkey", HexStr(alice_vault_spk));

                UniValue alice_leaves(UniValue::VARR);
                for (const auto& [depth, leaf_ver, script] : alice_vault_builder.GetTreeTuples()) {
                    UniValue leaf(UniValue::VOBJ);
                    leaf.pushKV("depth", depth);
                    leaf.pushKV("leaf_version", leaf_ver);
                    leaf.pushKV("script", HexStr(script));
                    alice_leaves.push_back(leaf);
                }
                alice_taproot.pushKV("tree", alice_leaves);
                result.pushKV("alice_vault_taproot", alice_taproot);

                // CRITICAL: Cache vault scripts with full covenant metadata
                // This ensures the wallet can recognize and spend vault outputs in cooperative close
                // and other operations. This matches the registration done in forward.accept.
                CacheForwardVaultScripts(*pwallet, record);

                // CRITICAL: Persist open_txid deterministically for SHORT party
                {
                    const Txid merged_txid = Txid::FromUint256(final_tx.GetHash());
                    LOCK(pwallet->cs_wallet);
                    auto record_opt = pwallet->FindForwardContract(*contract_id);
                    if (record_opt) {
                        ForwardContractRecord updated = *record_opt;
                        if (updated.open_txid && *updated.open_txid != merged_txid.ToUint256()) {
                            pwallet->WalletLogPrintf("⚠️  WARNING: open_txid changing from %s to %s for contract %s\n",
                                                   updated.open_txid->GetHex(),
                                                   merged_txid.ToString(),
                                                   contract_id->GetHex());
                        }
                        updated.open_txid = merged_txid.ToUint256();
                        pwallet->RegisterForwardContract(std::move(updated));
                        pwallet->WalletLogPrintf("Forward[%s]: SHORT mode persisted open_txid=%s\n",
                                                contract_id->GetHex(),
                                                merged_txid.ToString());
                    }
                }

                return result;
            }

            // ===== LONG MODE: Create base PSBT, fund long IM + premium =====
            // (Short IM vault is created as placeholder output, unfunded)

            for (const AssetInputSpec& spec : asset_input_specs) {
                tx_template.vin.emplace_back(spec.outpoint);
            }

            auto fund_res = FundTransaction(*pwallet, tx_template, recipients, std::nullopt, false, coin_control);
            if (!fund_res) {
                bilingual_str err = util::ErrorString(fund_res);
                throw JSONRPCError(RPC_WALLET_ERROR, err.original);
            }

            const CreatedTransactionResult& tx_result = fund_res.value();
            CMutableTransaction funded_tx(*tx_result.tx);

            // ===== INSERT BOB'S VAULT AS PLACEHOLDER (LONG MODE) =====
            // Bob's vault was not included in recipients, so we manually insert it now
            // Find Alice's vault position so we can insert Bob's vault adjacent to it
            std::optional<size_t> alice_pos;
            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                if (funded_tx.vout[i].scriptPubKey == alice_vault_spk &&
                    funded_tx.vout[i].nValue == alice_vault_sats) {
                    alice_pos = i;
                    break;
                }
            }
            if (!alice_pos) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate Alice IM vault in funded transaction");
            }

            // Insert Bob's vault right after Alice's vault
            CTxOut bob_vault_txout;
            bob_vault_txout.scriptPubKey = bob_vault_spk;
            bob_vault_txout.nValue = bob_vault_sats;
            // For asset margin, add placeholder TLV (will be replaced by short party)
            if (!im_bob.is_native) {
                bob_vault_txout.vExt = BuildAssetTagTlv(im_bob.asset_id, im_bob.units);
            }
            funded_tx.vout.insert(funded_tx.vout.begin() + *alice_pos + 1, bob_vault_txout);

            // ===== ATTACH ASSET TLVs TO OUTPUTS =====
            // Identify outputs by matching scriptPubKey + nValue
            const auto cache_vault_script = [&](const CTxDestination& base_dest,
                                                const CScript& vault_spk) {
                LOCK(pwallet->cs_wallet);
                const CScript base_spk = GetScriptForDestination(base_dest);
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(base_spk);
                if (managers.empty()) return;

                std::set<CScript> scripts{vault_spk};
                for (ScriptPubKeyMan* manager : managers) {
                    if (manager == nullptr) continue;
                    manager->RegisterCovenantScript(base_spk, vault_spk);
                    pwallet->CacheNewScriptPubKeys(scripts, manager);
                }
            };

            cache_vault_script(terms.long_party.margin_dest, alice_vault_spk);
            cache_vault_script(terms.short_party.margin_dest, bob_vault_spk);

            std::vector<bool> asset_output_matched(funded_tx.vout.size(), false);
            for (const AssetOutputCandidate& candidate : asset_output_candidates) {
                bool found = false;
                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    if (asset_output_matched[i]) continue;
                    CTxOut& out = funded_tx.vout[i];
                    if (out.scriptPubKey == candidate.script && out.nValue == candidate.value) {
                        out.vExt = BuildAssetTagTlv(candidate.asset_id, candidate.units);
                        asset_output_matched[i] = true;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate funded asset output");
                }
            }

            size_t actual_premium_idx = SIZE_MAX;
            size_t actual_bob_vault_idx = SIZE_MAX;
            size_t actual_alice_vault_idx = SIZE_MAX;
            const CScript premium_spk = GetScriptForDestination(terms.premium_dest);

            for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                const CTxOut& out = funded_tx.vout[i];
                if (out.scriptPubKey == bob_vault_spk && out.nValue == bob_vault_sats) {
                    actual_bob_vault_idx = i;
                    continue;
                }
                if (out.scriptPubKey == alice_vault_spk && out.nValue == alice_vault_sats) {
                    actual_alice_vault_idx = i;
                    continue;
                }
                if (premium_output_index != SIZE_MAX && out.scriptPubKey == premium_spk) {
                    actual_premium_idx = i;
                }
            }

            if (actual_bob_vault_idx == SIZE_MAX || actual_alice_vault_idx == SIZE_MAX) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded transaction missing IM vault outputs");
            }

            // NOTE: Long wallet defers persisting open_txid and vault outpoints until the final, short-augmented PSBT
            // is available. During adaptor.prepare (or once the opening tx hits the mempool), VerifyAndPersistForwardVaults
            // will record the authoritative txid and vault metadata. Cache the scriptPubKeys so later detection matches by script.
            ForwardContractRecord updated_record = record;
            updated_record.long_margin_script = alice_vault_spk;
            updated_record.short_margin_script = bob_vault_spk;
            pwallet->RegisterForwardContract(updated_record);
            record = updated_record;

            PartiallySignedTransaction psbt(funded_tx);

            // Annotate PSBT with Fair-Sign metadata
            FeePolicySnapshot fee_snapshot;
            fee_snapshot.rbf = pwallet->m_signal_rbf;
            if (fee_rate_override) {
                fee_snapshot.target_satvb = *fee_rate_override;
                fee_snapshot.min_satvb = *fee_rate_override; // Set min to target for explicit overrides
            }

            // Build outputmatch specs for covenant verification (§4.4)
            std::vector<OutputMatchSpec> outputmatches;

            // Alice's IM vault
            outputmatches.push_back({
                alice_vault_output,
                im_alice.is_native,
                im_alice.units,
                im_alice.asset_id
            });

            // Bob's IM vault
            outputmatches.push_back({
                bob_vault_output,
                im_bob.is_native,
                im_bob.units,
                im_bob.asset_id
            });

            // Premium (if present)
            if (terms.premium_leg.units > 0) {
                outputmatches.push_back({
                    terms.premium_dest,
                    terms.premium_leg.is_native,
                    terms.premium_leg.units,
                    terms.premium_leg.asset_id
                });
            }

            AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);

            // Track change outputs for annotation
            std::vector<size_t> change_indices;
            if (tx_result.change_pos) {
                change_indices.push_back(static_cast<size_t>(*tx_result.change_pos));
            }
            AnnotateForwardOutputs(psbt, {});

            bool complete = false;
            // Don't sign yet - adaptor ceremony will handle signing
            // But do request BIP32 derivations to populate metadata
            const auto fill_err = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, false, true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            AnnotateTaprootInputsWithInternalKeys(*pwallet, psbt);

            // Annotate vault outputs with Taproot spend data
            auto& bob_vault_psbt_out = psbt.outputs[actual_bob_vault_idx];
            bob_vault_psbt_out.m_tap_internal_key = bob_key;
            bob_vault_psbt_out.m_tap_tree = bob_vault_builder.GetTreeTuples();

            auto& alice_vault_psbt_out = psbt.outputs[actual_alice_vault_idx];
            alice_vault_psbt_out.m_tap_internal_key = alice_key;
            alice_vault_psbt_out.m_tap_tree = alice_vault_builder.GetTreeTuples();

            // Return PSBT + taproot construction details
            UniValue bob_taproot(UniValue::VOBJ);
            bob_taproot.pushKV("output_key", HexStr(std::vector<unsigned char>(bob_vault_output.begin(), bob_vault_output.end())));
            bob_taproot.pushKV("internal_key", HexStr(std::vector<unsigned char>(bob_key.begin(), bob_key.end())));
            bob_taproot.pushKV("script_pubkey", HexStr(bob_vault_spk));

            UniValue bob_leaves(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : bob_vault_builder.GetTreeTuples()) {
                UniValue leaf(UniValue::VOBJ);
                leaf.pushKV("depth", depth);
                leaf.pushKV("leaf_version", leaf_ver);
                leaf.pushKV("script", HexStr(script));
                bob_leaves.push_back(leaf);
            }
            bob_taproot.pushKV("tree", bob_leaves);

            UniValue alice_taproot(UniValue::VOBJ);
            alice_taproot.pushKV("output_key", HexStr(std::vector<unsigned char>(alice_vault_output.begin(), alice_vault_output.end())));
            alice_taproot.pushKV("internal_key", HexStr(std::vector<unsigned char>(alice_key.begin(), alice_key.end())));
            alice_taproot.pushKV("script_pubkey", HexStr(alice_vault_spk));

            UniValue alice_leaves(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : alice_vault_builder.GetTreeTuples()) {
                UniValue leaf(UniValue::VOBJ);
                leaf.pushKV("depth", depth);
                leaf.pushKV("leaf_version", leaf_ver);
                leaf.pushKV("script", HexStr(script));
                alice_leaves.push_back(leaf);
            }
            alice_taproot.pushKV("tree", alice_leaves);

            // CRITICAL: Cache vault scripts with full covenant metadata
            // This ensures the wallet can recognize and spend vault outputs in cooperative close
            // and other operations. This matches the registration done in forward.accept.
            CacheForwardVaultScripts(*pwallet, record);

            UniValue result(UniValue::VOBJ);
            DataStream ssTx{};
            ssTx << psbt;
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("complete", complete);
            result.pushKV("fee", ValueFromAmount(tx_result.fee));
            result.pushKV("premium_output_index", actual_premium_idx != SIZE_MAX ? static_cast<int>(actual_premium_idx) : -1);
            result.pushKV("bob_vault_index", actual_bob_vault_idx != SIZE_MAX ? static_cast<int>(actual_bob_vault_idx) : -1);
            result.pushKV("alice_vault_index", actual_alice_vault_idx != SIZE_MAX ? static_cast<int>(actual_alice_vault_idx) : -1);
            result.pushKV("bob_vault_taproot", bob_taproot);
            result.pushKV("alice_vault_taproot", alice_taproot);
            return result;
        }
    );
}

RPCHelpMan forward_accept()
{
    return RPCHelpMan(
        "forward.accept",
        "Record acceptance for a forward contract offer and return the canonical acceptance payload.\n"
        "IMPORTANT: Review contract terms carefully before accepting. Use 'confirmed' parameter to proceed.",
        std::vector<RPCArg>{
            {"offer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Forward offer JSON payload or 64-hex offer id",
                {
                    {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Offer identifier (must match first parameter)"},
                    {"salt", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Offer salt"},
                    {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Offer commitment"},
                    {"proposer_side", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposer's side ('long' or 'short')"},
                    {"terms", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "Forward contract terms",
                        {
                            {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Contract term fields"},
                        },
                    },
                    {"fs_policy", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "Fair-Sign policy",
                        {
                            {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Policy fields"},
                        },
                    },
                    {"fs_tx_adaptor_point", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proposer's adaptor point"},
                    {"internal_keys", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Untweaked taproot keys included with the offer",
                        {
                            {"long_margin", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Long party internal key"},
                            {"short_margin", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Short party internal key"},
                        }
                    },
                    {"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be true after reviewing terms to accept"},
                },
                RPCArgOptions{.skip_type_check = true, .type_str = {"string or json object"}}
            },
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional acceptance settings when passing a bare offer id",
                {
                    {"confirmed", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be true after reviewing terms to accept"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "acceptance_id", /*optional=*/true, "Acceptance identifier (only if confirmed=true)"},
                {RPCResult::Type::OBJ, "acceptance", /*optional=*/true, "Canonical acceptance payload (only if confirmed=true)",
                    {
                        {RPCResult::Type::STR_HEX, "offer_id", "Original offer identifier"},
                        {RPCResult::Type::STR_HEX, "salt", "Acceptance salt"},
                        {RPCResult::Type::STR_HEX, "commitment", "Acceptance commitment"},
                        {RPCResult::Type::STR_HEX, "fs_tx_adaptor_point", "Acceptor's adaptor point"},
                        {RPCResult::Type::OBJ, "internal_keys", /*optional=*/true, "Untweaked taproot keys learned from the acceptor",
                            {
                                {RPCResult::Type::STR_HEX, "long_margin", /*optional=*/true, "Long party internal key (if shared by acceptor)"},
                                {RPCResult::Type::STR_HEX, "short_margin", /*optional=*/true, "Short party internal key (if shared by acceptor)"},
                            }
                        },
                    }
                },
                {RPCResult::Type::OBJ, "terms", /*optional=*/true, "Contract terms for review (if confirmed is missing/false)"},
                {RPCResult::Type::STR, "action_required", /*optional=*/true, "Instructions for user (if confirmed is missing/false)"},
                {RPCResult::Type::STR, "warning", /*optional=*/true, "Warning message (if confirmed is missing/false)"},
            }
        },
        RPCExamples{
            HelpExampleCli("forward.accept", "\"{\\\"id\\\":\\\"...\\\", \\\"terms\\\":{...}}\"") + " (shows terms for review)\n" +
            HelpExampleCli("forward.accept", "\"{\\\"id\\\":\\\"...\\\", \\\"terms\\\":{...}, \\\"confirmed\\\": true}\"") + " (accepts after review)"
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            ForwardContractRecord offer_record;
            ForwardSide proposer_side;
            std::string commitment_hex;
            uint256 offer_salt;
            std::optional<XOnlyPubKey> long_internal_offer;
            std::optional<XOnlyPubKey> short_internal_offer;

            const UniValue& offer_param = request.params[0];
            UniValue options = (request.params.size() > 1 && request.params[1].isObject())
                ? request.params[1].get_obj()
                : UniValue::VNULL;
            if (offer_param.isStr()) {
                const std::string id_hex = offer_param.get_str();
                if (!IsHex(id_hex) || id_hex.size() != 64) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer id must be 32-byte hex");
                }
                const auto offer_id = uint256::FromHex(id_hex);
                if (!offer_id) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer id invalid");
                }

                auto stored_opt = pwallet->FindForwardContract(*offer_id);
                if (!stored_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract offer - import it first or provide full offer payload");
                }

                offer_record = *stored_opt;
                proposer_side = offer_record.local_side == ForwardSide::LONG ? ForwardSide::SHORT : ForwardSide::LONG;
                commitment_hex = offer_record.commitment_hex;
                offer_salt = offer_record.salt;
                long_internal_offer = offer_record.long_margin_internal_key;
                short_internal_offer = offer_record.short_margin_internal_key;
            } else if (offer_param.isObject()) {
                const UniValue& offer_obj = offer_param.get_obj();

                const std::string id_hex = offer_obj.find_value("id").get_str();
                if (!IsHex(id_hex) || id_hex.size() != 64) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer id must be 32-byte hex");
                }
                const auto offer_id = uint256::FromHex(id_hex);
                if (!offer_id) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer id invalid");
                }

                const std::string salt_hex = offer_obj.find_value("salt").get_str();
                const auto salt_opt = uint256::FromHex(salt_hex);
                if (!salt_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.salt invalid");
                }
                offer_salt = *salt_opt;

                commitment_hex = offer_obj.find_value("commitment").get_str();
                if (!IsHex(commitment_hex) || commitment_hex.size() != 64) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.commitment must be 32-byte hex");
                }

                const std::string proposer_side_str = offer_obj.find_value("proposer_side").get_str();
                if (proposer_side_str == "long") {
                    proposer_side = ForwardSide::LONG;
                } else if (proposer_side_str == "short") {
                    proposer_side = ForwardSide::SHORT;
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.proposer_side must be 'long' or 'short'");
                }

                const UniValue& terms_obj = offer_obj.find_value("terms");
                if (!terms_obj.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.terms must be an object");
                }
                ForwardTerms terms = ParseForwardTerms(terms_obj);

                const std::string proposer_adaptor_hex = offer_obj.find_value("fs_tx_adaptor_point").get_str();
                auto proposer_adaptor_bytes = ParseHex(proposer_adaptor_hex);
                XOnlyPubKey proposer_adaptor_point;
                if (proposer_adaptor_bytes.size() != proposer_adaptor_point.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.fs_tx_adaptor_point must be 32-byte hex");
                }
                std::copy(proposer_adaptor_bytes.begin(), proposer_adaptor_bytes.end(), proposer_adaptor_point.begin());

                const std::string computed_commitment = ForwardOfferCommitmentHex(terms, proposer_side, offer_salt);
                if (computed_commitment != commitment_hex) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer commitment verification failed");
                }

                offer_record.contract_id = *offer_id;
                offer_record.terms = terms;
                offer_record.local_side = proposer_side == ForwardSide::LONG ? ForwardSide::SHORT : ForwardSide::LONG;
                offer_record.fs_policy = FairSignPolicy{};
                offer_record.fs_tx_adaptor_point = proposer_adaptor_point;
                offer_record.salt = offer_salt;
                offer_record.commitment_hex = commitment_hex;
                {
                    LOCK(pwallet->cs_wallet);
                    offer_record.created_height = pwallet->GetLastBlockHeight();
                }
                offer_record.created_time = GetTime();

                std::optional<XOnlyPubKey> offer_long_internal;
                std::optional<XOnlyPubKey> offer_short_internal;
                const UniValue& offer_internals = offer_obj.find_value("internal_keys");
                if (!offer_internals.isNull()) {
                    if (!offer_internals.isObject()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "offer.internal_keys must be an object when provided");
                    }
                    const UniValue& long_val = offer_internals.find_value("long_margin");
                    const UniValue& short_val = offer_internals.find_value("short_margin");
                    offer_long_internal = ParseInternalKeyOptional(long_val, "offer.internal_keys.long_margin");
                    offer_short_internal = ParseInternalKeyOptional(short_val, "offer.internal_keys.short_margin");
                }
                offer_record.long_margin_internal_key = ResolveForwardMarginKey(
                    *pwallet,
                    terms.long_party.margin_dest,
                    offer_record.long_margin_internal_key,
                    offer_long_internal,
                    "offer.internal_keys.long_margin",
                    offer_record.local_side,
                    ForwardSide::LONG);
                offer_record.short_margin_internal_key = ResolveForwardMarginKey(
                    *pwallet,
                    terms.short_party.margin_dest,
                    offer_record.short_margin_internal_key,
                    offer_short_internal,
                    "offer.internal_keys.short_margin",
                    offer_record.local_side,
                    ForwardSide::SHORT);
                long_internal_offer = offer_record.long_margin_internal_key;
                short_internal_offer = offer_record.short_margin_internal_key;
            } else {
                throw JSONRPCError(RPC_TYPE_ERROR, "offer must be a 32-byte id string or JSON object");
            }

            MaybePopulateLocalMarginKey(*pwallet, offer_record.terms.long_party.margin_dest, offer_record.long_margin_internal_key);
            MaybePopulateLocalMarginKey(*pwallet, offer_record.terms.short_party.margin_dest, offer_record.short_margin_internal_key);

            // Check if user has confirmed after reviewing terms
            bool confirmed = false;
            if (offer_param.isObject()) {
                const UniValue& offer_obj_ref = offer_param.get_obj();
                const UniValue& confirmed_val = offer_obj_ref.find_value("confirmed");
                if (!confirmed_val.isNull()) {
                    confirmed = confirmed_val.get_bool();
                }
            }
            if (!confirmed && !options.isNull()) {
                const UniValue& confirmed_val = options.find_value("confirmed");
                if (!confirmed_val.isNull()) {
                    confirmed = confirmed_val.get_bool();
                }
            }

            // If not confirmed, display terms for review
            if (!confirmed) {
                UniValue terms(UniValue::VOBJ);

                terms.pushKV("contract_type", "FORWARD");
                terms.pushKV("contract_id", offer_record.contract_id.GetHex());

                // Determine role (proposer already knows they proposed, acceptor is the other side)
                ForwardSide acceptor_side = proposer_side == ForwardSide::LONG ? ForwardSide::SHORT : ForwardSide::LONG;
                terms.pushKV("proposer_role", proposer_side == ForwardSide::LONG ? "LONG" : "SHORT");
                terms.pushKV("your_role", acceptor_side == ForwardSide::LONG ? "LONG" : "SHORT");

                // Contract terms
                UniValue contract(UniValue::VOBJ);
                if (acceptor_side == ForwardSide::LONG) {
                    contract.pushKV("you_deliver", strprintf("%s %s",
                        ValueFromAmount(offer_record.terms.long_party.deliver_leg.units).get_str(),
                        offer_record.terms.long_party.deliver_leg.is_native ? "BTC" : "ASSET"));
                    contract.pushKV("counterparty_delivers", strprintf("%s %s",
                        ValueFromAmount(offer_record.terms.short_party.deliver_leg.units).get_str(),
                        offer_record.terms.short_party.deliver_leg.is_native ? "BTC" : "ASSET"));
                } else {
                    contract.pushKV("you_deliver", strprintf("%s %s",
                        ValueFromAmount(offer_record.terms.short_party.deliver_leg.units).get_str(),
                        offer_record.terms.short_party.deliver_leg.is_native ? "BTC" : "ASSET"));
                    contract.pushKV("counterparty_delivers", strprintf("%s %s",
                        ValueFromAmount(offer_record.terms.long_party.deliver_leg.units).get_str(),
                        offer_record.terms.long_party.deliver_leg.is_native ? "BTC" : "ASSET"));
                }

                // Premium (if any)
                if (offer_record.terms.premium_leg.units > 0) {
                    contract.pushKV("premium_amount", ValueFromAmount(offer_record.terms.premium_leg.units));
                    contract.pushKV("premium_asset", offer_record.terms.premium_leg.is_native ? "BTC" : offer_record.terms.premium_leg.asset_id.ToString());
                    contract.pushKV("premium_paid_by", "LONG");
                    contract.pushKV("premium_received_by", "SHORT");
                }

                contract.pushKV("deadline_short_blocks", (int)offer_record.terms.deadline_short);
                contract.pushKV("deadline_long_blocks", (int)offer_record.terms.deadline_long);
                terms.pushKV("contract_terms", contract);

                // Margin requirements
                UniValue margins(UniValue::VOBJ);
                if (acceptor_side == ForwardSide::LONG) {
                    margins.pushKV("your_initial_margin", ValueFromAmount(offer_record.terms.long_party.margin_leg.units));
                    margins.pushKV("your_margin_asset", offer_record.terms.long_party.margin_leg.is_native ? std::string("BTC") :
                        offer_record.terms.long_party.margin_leg.asset_id.ToString());
                    margins.pushKV("counterparty_margin", ValueFromAmount(offer_record.terms.short_party.margin_leg.units));
                } else {
                    margins.pushKV("your_initial_margin", ValueFromAmount(offer_record.terms.short_party.margin_leg.units));
                    margins.pushKV("your_margin_asset", offer_record.terms.short_party.margin_leg.is_native ? std::string("BTC") :
                        offer_record.terms.short_party.margin_leg.asset_id.ToString());
                    margins.pushKV("counterparty_margin", ValueFromAmount(offer_record.terms.long_party.margin_leg.units));
                }
                terms.pushKV("margin_requirements", margins);

                // Risks
                UniValue risks(UniValue::VARR);
                if (acceptor_side == ForwardSide::LONG) {
                    risks.push_back("⚠️ You pay premium upfront regardless of outcome");
                    risks.push_back("⚠️ Your margin may be liquidated if obligations not met");
                    risks.push_back("⚠️ Settlement depends on oracle/escrow cooperation");
                    risks.push_back("⚠️ Contract is irreversible once signed");
                } else {
                    risks.push_back("⚠️ You receive premium but have delivery obligation");
                    risks.push_back("⚠️ Your margin may be liquidated if obligations not met");
                    risks.push_back("⚠️ Potential loss if asset price moves against you");
                    risks.push_back("⚠️ Contract is irreversible once signed");
                }
                terms.pushKV("risks", risks);

                // Summary
                UniValue summary(UniValue::VOBJ);
                summary.pushKV("action", "You are accepting a forward contract offer");
                summary.pushKV("obligation", "You must deliver your asset at maturity to receive the counterparty's asset");
                summary.pushKV("margin_locked", "Your margin will be locked in a vault until contract settles");
                terms.pushKV("summary", summary);

                UniValue result(UniValue::VOBJ);
                result.pushKV("terms", terms);
                result.pushKV("action_required", "Review terms carefully. To accept, add \"confirmed\": true to the offer object");
                result.pushKV("warning", "⚠️ This contract involves MARGIN DEPOSITS and DELIVERY OBLIGATIONS. Only proceed if you understand all terms.");
                return result;
            }

            // Generate our counter-adaptor
            auto [adaptor_secret, adaptor_point] = GenerateFairSignAdaptor();

            // Generate acceptance salt and commitment
            uint256 acceptance_salt = GetRandHash();
            std::string acceptance_commitment = ForwardAcceptanceCommitmentHex(
                offer_record,
                adaptor_point,
                acceptance_salt
            );

            // Store offer and acceptance in wallet
            offer_record.counterparty_adaptor_point = adaptor_point;
            offer_record.local_fs_tx_adaptor_secret = adaptor_secret;
            offer_record.acceptance_commitment_hex = acceptance_commitment;
            offer_record.acceptance_salt = acceptance_salt;

            ForwardContractRecord stored = pwallet->RegisterForwardContract(std::move(offer_record));
            CacheForwardVaultScripts(*pwallet, stored);

            UniValue internal_keys(UniValue::VOBJ);
            if (stored.local_side == ForwardSide::LONG && stored.long_margin_internal_key) {
                internal_keys.pushKV("long_margin", EncodeInternalKeyOptional(stored.long_margin_internal_key));
            }
            if (stored.local_side == ForwardSide::SHORT && stored.short_margin_internal_key) {
                internal_keys.pushKV("short_margin", EncodeInternalKeyOptional(stored.short_margin_internal_key));
            }

            // Build acceptance response
            UniValue acceptance(UniValue::VOBJ);
            acceptance.pushKV("offer_id", stored.contract_id.GetHex());
            acceptance.pushKV("salt", acceptance_salt.GetHex());
            acceptance.pushKV("commitment", acceptance_commitment);
            acceptance.pushKV("fs_tx_adaptor_point", HexStr(std::vector<unsigned char>(adaptor_point.begin(), adaptor_point.end())));
            if (!internal_keys.empty()) {
                acceptance.pushKV("internal_keys", internal_keys);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("acceptance_id", stored.contract_id.GetHex());
            result.pushKV("acceptance", acceptance);
            return result;
        }
    );
}

RPCHelpMan forward_build_coop_close()
{
    return RPCHelpMan(
        "forward.build_coop_close",
        "Construct a cooperative close PSBT for a forward contract. Both parties must agree on the settlement terms and sign. This spends both IM vaults and distributes assets according to the agreed settlement.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"settlement", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Settlement distribution (defaults to cooperative leaf layout)",
                std::vector<RPCArg>{
                    {"to_long", RPCArg::Type::ARR, RPCArg::Optional::NO, "Outputs to long party",
                        std::vector<RPCArg>{
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                std::vector<RPCArg>{
                                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Asset ID (omit for native BTC)"},
                                    {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Amount in sats or asset units"},
                                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination (defaults to long party's settlement address)"},
                                }
                            }
                        }
                    },
                    {"to_short", RPCArg::Type::ARR, RPCArg::Optional::NO, "Outputs to short party",
                        std::vector<RPCArg>{
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                std::vector<RPCArg>{
                                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Asset ID (omit for native BTC)"},
                                    {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Amount in sats or asset units"},
                                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination (defaults to short party's settlement address)"},
                                }
                            }
                        }
                    },
                }
            },
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"long_vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override long vault outpoint txid"},
                    {"long_vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override long vault outpoint index"},
                    {"short_vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override short vault outpoint txid"},
                    {"short_vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override short vault outpoint index"},
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::NUM, "fee", "Estimated fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet-generated change output (-1 if none)"},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT contains all signatures"},
                {RPCResult::Type::OBJ_DYN, "roll_terms", /*optional=*/true, "Suggested forward terms to roll the position",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.build_coop_close", "\"" + std::string(64, 'a') + "\" \"{\\\"to_long\\\":[...], \\\"to_short\\\":[...]}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            ForwardContractRecord record = *record_opt;
            bool updated_keys = false;
            if (!record.long_margin_internal_key) {
                record.long_margin_internal_key = LookupTaprootInternalKey(*pwallet, record.terms.long_party.margin_dest);
                if (record.long_margin_internal_key) updated_keys = true;
            }
            if (!record.short_margin_internal_key) {
                record.short_margin_internal_key = LookupTaprootInternalKey(*pwallet, record.terms.short_party.margin_dest);
                if (record.short_margin_internal_key) updated_keys = true;
            }

            if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Forward contract missing margin internal keys - re-import counterparty payloads");
            }

            if (updated_keys) {
                record = pwallet->RegisterForwardContract(std::move(record));
                CacheForwardVaultScripts(*pwallet, record);
            }

            EnsureForwardVaultState(*pwallet, request, record);

            const auto locate_vault = [&](ForwardSide side) -> std::optional<std::pair<COutPoint, CAmount>> {
                // Look up vault scriptPubKey from registry instead of rebuilding
                VaultRole vault_role = (side == ForwardSide::LONG) ? VaultRole::FORWARD_LONG : VaultRole::FORWARD_SHORT;
                auto vault_spk_opt = GetVaultScriptByRole(*pwallet, record.contract_id, vault_role);
                if (!vault_spk_opt) return std::nullopt;
                const CScript& vault_spk = *vault_spk_opt;

                CoinFilterParams filter;
                filter.only_spendable = false;
                filter.skip_locked = false;
                filter.include_immature_coinbase = true;

                LOCK(pwallet->cs_wallet);
                CoinsResult coins = AvailableCoins(*pwallet, nullptr, std::nullopt, filter);
                for (const COutput& coin : coins.All()) {
                    if (coin.txout.scriptPubKey == vault_spk) {
                        return std::make_optional(std::make_pair(coin.outpoint, coin.txout.nValue));
                    }
                }
                return std::nullopt;
            };

            std::optional<COutPoint> long_vault_override;
            std::optional<COutPoint> short_vault_override;

            const UniValue* settlement_ptr = nullptr;
            UniValue auto_settlement(UniValue::VOBJ);

            if (request.params.size() > 1 && request.params[1].isObject()) {
                const UniValue& candidate = request.params[1].get_obj();
                const UniValue& cand_to_long = candidate.find_value("to_long");
                const UniValue& cand_to_short = candidate.find_value("to_short");
                if (cand_to_long.isArray() && cand_to_short.isArray()) {
                    settlement_ptr = &candidate;
                }
            }

            UniValue opts(UniValue::VNULL);

            auto get_opts = [&](size_t idx) -> UniValue {
                if (request.params.size() > idx && request.params[idx].isObject()) {
                    return request.params[idx].get_obj();
                }
                return UniValue();
            };

            const UniValue opts_param1 = get_opts(1);
            const UniValue opts_param2 = get_opts(2);
            bool split_funding = false;
            {
                const UniValue& o = !opts_param2.isNull() ? opts_param2 : opts_param1;
                if (!o.isNull()) {
                    const UniValue& split_val = o.find_value("split_funding");
                    if (!split_val.isNull()) split_funding = split_val.get_bool();
                }
            }

            std::vector<bool> auto_to_long_needs;
            std::vector<bool> auto_to_short_needs;
            const std::vector<bool>* to_long_needs_flags = nullptr;
            const std::vector<bool>* to_short_needs_flags = nullptr;

            if (!settlement_ptr) {
                struct SettlementEntry {
                    bool is_native{true};
                    uint64_t units{0};
                    std::optional<uint256> asset_id;
                    CTxDestination dest;
                    bool is_margin{false};
                };

                std::vector<SettlementEntry> to_long_entries;
                std::vector<SettlementEntry> to_short_entries;

                const auto add_entry = [&](std::vector<SettlementEntry>& entries,
                                            const CTxDestination& default_dest,
                                            const AssetLeg& leg,
                                            bool is_margin) {
                    if (leg.units == 0) return;
                    SettlementEntry entry;
                    entry.is_native = leg.is_native;
                    entry.units = leg.units;
                    if (!leg.is_native) entry.asset_id = leg.asset_id;
                    entry.dest = default_dest;
                    entry.is_margin = is_margin;
                    entries.push_back(std::move(entry));
                };

                add_entry(to_long_entries, record.terms.long_party.settlement_receive_dest, record.terms.short_party.deliver_leg, /*is_margin=*/false);
                add_entry(to_short_entries, record.terms.short_party.settlement_receive_dest, record.terms.long_party.deliver_leg, /*is_margin=*/false);
                add_entry(to_long_entries, record.terms.long_party.margin_dest, record.terms.long_party.margin_leg, /*is_margin=*/true);
                add_entry(to_short_entries, record.terms.short_party.margin_dest, record.terms.short_party.margin_leg, /*is_margin=*/true);

                const UniValue& cash_opts = !opts_param1.isNull() ? opts_param1 : opts_param2;
                const UniValue& cash_opt = cash_opts.isNull() ? UniValue::VNULL : cash_opts.find_value("cash_settlement");
                if (!cash_opt.isNull()) {
                    if (!cash_opt.isObject()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "cash_settlement must be an object");
                    }
                    const UniValue& payer_val = cash_opt.find_value("payer");
                    const UniValue& amount_val = cash_opt.find_value("amount");
                    if (payer_val.isNull() || !payer_val.isStr()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "cash_settlement.payer must be 'long' or 'short'");
                    }
                    if (amount_val.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "cash_settlement.amount is required");
                    }
                    CAmount cash_amount = ParseSignedInt64(amount_val, "cash_settlement.amount");
                    if (cash_amount <= 0 || !MoneyRange(cash_amount)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "cash_settlement.amount must be positive and within money range");
                    }

                    const std::string payer_str = ToLower(payer_val.get_str());
                    bool payer_is_long;
                    if (payer_str == "long") {
                        payer_is_long = true;
                    } else if (payer_str == "short") {
                        payer_is_long = false;
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "cash_settlement.payer must be 'long' or 'short'");
                    }

                    const UniValue& addr_val = cash_opt.find_value("address");
                    CTxDestination cash_dest = payer_is_long
                        ? record.terms.short_party.settlement_receive_dest
                        : record.terms.long_party.settlement_receive_dest;
                    if (!addr_val.isNull()) {
                        CTxDestination custom_dest = DecodeDestination(addr_val.get_str());
                        if (!IsValidDestination(custom_dest)) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "cash_settlement.address is invalid");
                        }
                        cash_dest = custom_dest;
                    }

                    auto adjust_margin = [&](std::vector<SettlementEntry>& entries,
                                              const CTxDestination& margin_dest) {
                        auto it = std::find_if(entries.begin(), entries.end(), [&](const SettlementEntry& e) {
                            return e.is_native && e.dest == margin_dest;
                        });
                        if (it == entries.end()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Margin entry not found for cash settlement");
                        }
                        if (it->units < static_cast<uint64_t>(cash_amount)) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "cash_settlement.amount exceeds margin availability");
                        }
                        it->units -= static_cast<uint64_t>(cash_amount);
                        if (it->units == 0) {
                            entries.erase(it);
                        }
                    };

                    if (payer_is_long) {
                        adjust_margin(to_long_entries, record.terms.long_party.margin_dest);
                        SettlementEntry payout;
                        payout.units = static_cast<uint64_t>(cash_amount);
                        payout.dest = cash_dest;
                        to_short_entries.push_back(std::move(payout));
                    } else {
                        adjust_margin(to_short_entries, record.terms.short_party.margin_dest);
                        SettlementEntry payout;
                        payout.units = static_cast<uint64_t>(cash_amount);
                        payout.dest = cash_dest;
                        to_long_entries.push_back(std::move(payout));
                    }
                }

                UniValue to_long_arr(UniValue::VARR);
                for (const SettlementEntry& entry : to_long_entries) {
                    auto_to_long_needs.push_back(!entry.is_margin);
                    UniValue obj(UniValue::VOBJ);
                    obj.pushKV("amount", UniValue(static_cast<int64_t>(entry.units)));
                    if (!entry.is_native && entry.asset_id) {
                        obj.pushKV("asset_id", entry.asset_id->GetHex());
                    }
                    obj.pushKV("address", EncodeDestination(entry.dest));
                    to_long_arr.push_back(obj);
                }

                UniValue to_short_arr(UniValue::VARR);
                for (const SettlementEntry& entry : to_short_entries) {
                    auto_to_short_needs.push_back(!entry.is_margin);
                    UniValue obj(UniValue::VOBJ);
                    obj.pushKV("amount", UniValue(static_cast<int64_t>(entry.units)));
                    if (!entry.is_native && entry.asset_id) {
                        obj.pushKV("asset_id", entry.asset_id->GetHex());
                    }
                    obj.pushKV("address", EncodeDestination(entry.dest));
                    to_short_arr.push_back(obj);
                }

                auto_settlement.pushKV("to_long", to_long_arr);
                auto_settlement.pushKV("to_short", to_short_arr);
                settlement_ptr = &auto_settlement;
                to_long_needs_flags = &auto_to_long_needs;
                to_short_needs_flags = &auto_to_short_needs;

                if (record.local_side == ForwardSide::LONG) {
                    for (size_t idx = 0; idx < auto_to_long_needs.size(); ++idx) {
                        auto_to_long_needs[idx] = false; // short's deliver leg funded by short
                    }
                } else {
                    for (size_t idx = 0; idx < auto_to_short_needs.size(); ++idx) {
                        auto_to_short_needs[idx] = false; // long's deliver leg funded by long when short builds
                    }
                }
            } else {
                if (!opts_param1.isNull()) {
                    opts = opts_param1;
                }
                if (!opts_param2.isNull()) {
                    opts = opts_param2; // manual settlement overrides take precedence when present
                }
                if (!opts.isNull()) {
                    const UniValue& cash_opt = opts.find_value("cash_settlement");
                    if (!cash_opt.isNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "cash_settlement not supported with manual settlement override");
                    }
                }
            }

            if (opts.isNull()) {
                if (!opts_param2.isNull()) {
                    opts = opts_param2;
                } else if (!opts_param1.isNull()) {
                    opts = opts_param1;
                }
            }

            const UniValue& to_long = settlement_ptr->find_value("to_long");
            const UniValue& to_short = settlement_ptr->find_value("to_short");

            if (!to_long.isArray() || !to_short.isArray()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "settlement.to_long and settlement.to_short must be arrays");
            }

            // Build transaction
            CMutableTransaction tx;
            tx.version = 2;
            tx.nLockTime = 0;

            // Parse options
            if (!opts_param2.isNull()) {
                opts = opts_param2;
            } else if (!opts_param1.isNull()) {
                opts = opts_param1;
            }

            if (!opts.isNull()) {
                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    tx.nLockTime = locktime_val.getInt<uint32_t>();
                }
                const UniValue& long_txid_val = opts.find_value("long_vault_txid");
                const UniValue& long_vout_val = opts.find_value("long_vault_vout");
                if (!long_txid_val.isNull() && !long_vout_val.isNull()) {
                    auto txid_opt = uint256::FromHex(long_txid_val.get_str());
                    if (!txid_opt) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid long_vault_txid");
                    }
                    long_vault_override = COutPoint(Txid::FromUint256(*txid_opt), long_vout_val.getInt<uint32_t>());
                }

                const UniValue& short_txid_val = opts.find_value("short_vault_txid");
                const UniValue& short_vout_val = opts.find_value("short_vault_vout");
                if (!short_txid_val.isNull() && !short_vout_val.isNull()) {
                    auto txid_opt = uint256::FromHex(short_txid_val.get_str());
                    if (!txid_opt) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid short_vault_txid");
                    }
                    short_vault_override = COutPoint(Txid::FromUint256(*txid_opt), short_vout_val.getInt<uint32_t>());
                }
            }

            if (long_vault_override) {
                record.long_margin_vault = *long_vault_override;
                const CAmount long_vault_value_default = record.terms.long_party.margin_leg.is_native
                    ? static_cast<CAmount>(record.terms.long_party.margin_leg.units)
                    : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                if (!record.long_margin_value) record.long_margin_value = long_vault_value_default;
                pwallet->SetForwardMarginVault(*contract_id, ForwardSide::LONG, *long_vault_override, record.long_margin_value);
            }
            if (short_vault_override) {
                record.short_margin_vault = *short_vault_override;
                const CAmount short_vault_value_default = record.terms.short_party.margin_leg.is_native
                    ? static_cast<CAmount>(record.terms.short_party.margin_leg.units)
                    : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                if (!record.short_margin_value) record.short_margin_value = short_vault_value_default;
                pwallet->SetForwardMarginVault(*contract_id, ForwardSide::SHORT, *short_vault_override, record.short_margin_value);
            }

        // Ensure vault outpoints are persisted before proceeding. The cooperative close
        // builder relies on the vault registry to embed intents; if the open transaction
        // was just processed, the asynchronous verifier may not have populated the cache yet.
            if ((!record.long_margin_vault.has_value() || !record.short_margin_vault.has_value()) && record.open_txid.has_value()) {
                const Txid open_txid = Txid::FromUint256(*record.open_txid);
                const CWalletTx* open_wtx = WITH_LOCK(pwallet->cs_wallet, return pwallet->GetWalletTx(open_txid));
                if (open_wtx) {
                    if (pwallet->VerifyAndPersistForwardVaults(record.contract_id, open_wtx->tx)) {
                        if (auto refreshed_record = pwallet->FindForwardContract(record.contract_id)) {
                            record = *refreshed_record;
                        }
                    }
                }
            }

            auto fmt_outpoint = [](const std::optional<COutPoint>& op) -> std::string {
                if (!op) return "unset";
                return strprintf("%s:%u", op->hash.ToString(), op->n);
            };

            LogPrintf("forward.build_coop_close[%s]: post-EnsureForwardVaultState long=%s short=%s\n",
                      contract_id->GetHex(),
                      fmt_outpoint(record.long_margin_vault),
                      fmt_outpoint(record.short_margin_vault));

            if (!record.long_margin_vault) {
                if (auto located = locate_vault(ForwardSide::LONG)) {
                    record.long_margin_vault = located->first;
                    record.long_margin_value = located->second;
                    pwallet->SetForwardMarginVault(*contract_id, ForwardSide::LONG, located->first, located->second);
                }
            }
            if (!record.short_margin_vault) {
                if (auto located = locate_vault(ForwardSide::SHORT)) {
                    record.short_margin_vault = located->first;
                    record.short_margin_value = located->second;
                    pwallet->SetForwardMarginVault(*contract_id, ForwardSide::SHORT, located->first, located->second);
                }
            }

            // If vaults are still missing, try to extract them from the blockchain
            if (!record.long_margin_vault || !record.short_margin_vault) {
                // Attempt to find the open transaction in the wallet
                // This could happen if the short party accepted but didn't persist vaults
                LogPrintf("forward.build_coop_close[%s]: Missing vault data after recovery (long=%s short=%s)\n",
                         contract_id->GetHex(),
                         fmt_outpoint(record.long_margin_vault),
                         fmt_outpoint(record.short_margin_vault));

                // Try to locate the open transaction
                // For now, we'll still require overrides if the automatic recovery fails
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Contract must have vaults established. If you are the short party, "
                    "please provide vault overrides via options parameter with "
                    "long_vault_txid, long_vault_vout, short_vault_txid, short_vault_vout");
            }

            record = pwallet->RegisterForwardContract(std::move(record));
            CacheForwardVaultScripts(*pwallet, record);

            const COutPoint long_vault = *record.long_margin_vault;
            const COutPoint short_vault = *record.short_margin_vault;

            tx.vin.emplace_back(long_vault);
            tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;
            tx.vin.emplace_back(short_vault);
            tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;

            const auto parse_native_amount = [](const UniValue& val) -> CAmount {
                if (val.isNum()) {
                    int64_t sat;
                    if (!ParseInt64(val.getValStr(), &sat)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be numeric");
                    }
                    if (!MoneyRange(sat)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount out of range");
                    }
                    return sat;
                }
                if (val.isStr()) {
                    CAmount sat = AmountFromValue(val);
                    if (!MoneyRange(sat)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount out of range");
                    }
                    return sat;
                }
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be number or string");
            };

            const auto parse_asset_units = [](const UniValue& val) -> uint64_t {
                if (!val.isNum() && !val.isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset amount must be number or string");
                }
                uint64_t units;
                if (!ParseUInt64(val.getValStr(), &units)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset amount must be non-negative integer");
                }
                return units;
            };

            struct SettlementOutputCandidate {
                CTxDestination dest;
                CAmount amount;
                bool is_native;
                std::optional<uint256> asset_id;
                uint64_t asset_units{0};
                CScript script;
                bool needs_external_funds{true};
            };
            std::vector<SettlementOutputCandidate> settlement_outputs;

            const auto append_outputs = [&](const UniValue& arr,
                                            const CTxDestination& default_dest,
                                            const std::vector<bool>* needs_flags) {
                for (size_t i = 0; i < arr.size(); ++i) {
                    const UniValue& out_obj = arr[i].get_obj();
                    const UniValue& amount_val = out_obj.find_value("amount");
                    const UniValue& asset_id_val = out_obj.find_value("asset_id");
                    const UniValue& address_val = out_obj.find_value("address");

                    CTxDestination dest = address_val.isNull() ? default_dest : DecodeDestination(address_val.get_str());
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid settlement address");
                    }

                    CTxOut out;
                    out.scriptPubKey = GetScriptForDestination(dest);

                    bool needs_funding = needs_flags ? needs_flags->at(i) : true;

                    if (!asset_id_val.isNull()) {
                        auto asset_id_opt = uint256::FromHex(asset_id_val.get_str());
                        if (!asset_id_opt) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id");
                        }
                        const uint64_t units = parse_asset_units(amount_val);
                        out.nValue = DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                        out.vExt = BuildAssetTagTlv(*asset_id_opt, units);
                        settlement_outputs.push_back({dest, out.nValue, /*is_native=*/false, asset_id_opt, units, out.scriptPubKey, needs_funding});
                    } else {
                        const CAmount sat = parse_native_amount(amount_val);
                        out.nValue = sat;
                        settlement_outputs.push_back({dest, sat, /*is_native=*/true, std::nullopt, 0, out.scriptPubKey, needs_funding});
                    }
                }
            };

            append_outputs(to_long, record.terms.long_party.settlement_receive_dest, to_long_needs_flags);
            append_outputs(to_short, record.terms.short_party.settlement_receive_dest, to_short_needs_flags);

            struct CoopSkeletonContribution {
                size_t settlement_index;
                ForwardAssetSkeletonResult skeleton;
            };
            std::vector<CoopSkeletonContribution> skeleton_contribs;

            struct SkeletonChangeRecipient {
                CTxDestination dest;
                CTxOut out;
                bool is_asset;
            };
            std::vector<SkeletonChangeRecipient> skeleton_change_recipients;
            std::set<COutPoint> skeleton_inputs;

            // Prepare asset contribution tracking for settlement outputs
            struct AssetInputSpec {
                COutPoint outpoint;
            };
            std::vector<AssetInputSpec> asset_input_specs;

            struct AssetChangeSpec {
                CTxDestination dest;
                uint256 asset_id;
                uint64_t units;
            };
            std::vector<AssetChangeSpec> asset_change_specs;
            std::set<COutPoint> used_asset_outpoints;
            for (size_t i = 0; i < settlement_outputs.size(); ++i) {
                SettlementOutputCandidate& cand = settlement_outputs[i];
                if (split_funding) {
                    cand.needs_external_funds = false; // contributions added via forward.coop_contrib
                }
                if (!cand.needs_external_funds || cand.is_native || !cand.asset_id) {
                    continue;
                }

                AssetLeg leg;
                leg.is_native = false;
                leg.asset_id = *cand.asset_id;
                leg.units = cand.asset_units;

                std::string context = strprintf("forward.build_coop_close[%zu]", i);
                ForwardAssetSkeletonResult skeleton = BuildForwardAssetSkeleton(
                    *pwallet,
                    request,
                    leg,
                    cand.dest,
                    std::nullopt,
                    context.c_str());

                for (const CTxIn& vin : skeleton.tx.vin) {
                    skeleton_inputs.insert(vin.prevout);
                }

                for (size_t change_idx : skeleton.change_indices) {
                    if (change_idx >= skeleton.tx.vout.size()) continue;
                    const CTxOut& change_out = skeleton.tx.vout[change_idx];
                    CTxDestination change_dest;
                    if (!ExtractDestination(change_out.scriptPubKey, change_dest)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to extract change destination from sendasset skeleton");
                    }
                    skeleton_change_recipients.push_back({
                        change_dest,
                        change_out,
                        static_cast<bool>(assets::ParseAssetTag(change_out.vExt))
                    });
                }

                skeleton_contribs.push_back({i, std::move(skeleton)});
                cand.needs_external_funds = false; // already funded via sendasset
            }

            const auto select_asset_inputs = [&](const SettlementOutputCandidate& cand) {
                if (cand.is_native || !cand.asset_id) {
                    return;
                }

                CCoinControl asset_cc;
                asset_cc.m_avoid_asset_utxos = false;
                asset_cc.m_required_asset_id = *cand.asset_id;
                asset_cc.m_include_unsafe_inputs = true;

                CoinsResult asset_candidates;
                {
                    LOCK(pwallet->cs_wallet);
                    asset_candidates = AvailableCoins(*pwallet, &asset_cc);
                }

                uint64_t accumulated_units{0};
                for (const COutput& candidate : asset_candidates.All()) {
                    if (!candidate.spendable) continue;
                    if (used_asset_outpoints.count(candidate.outpoint)) continue;
                    auto tag = assets::ParseAssetTag(candidate.txout.vExt);
                    if (!tag || tag->id != *cand.asset_id) continue;

                    asset_input_specs.push_back({candidate.outpoint});
                    used_asset_outpoints.insert(candidate.outpoint);
                    accumulated_units += tag->amount;
                    if (accumulated_units >= cand.asset_units) {
                        break;
                    }
                }

                if (accumulated_units < cand.asset_units) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        strprintf("Insufficient units for asset %s (need %s, have %s)",
                                  cand.asset_id->GetHex(),
                                  util::ToString(cand.asset_units),
                                  util::ToString(accumulated_units)));
                }

                const uint64_t change_units = accumulated_units - cand.asset_units;
                if (change_units > 0) {
                    EnsureWalletIsUnlocked(*pwallet);
                    auto dest_res = pwallet->GetNewDestination(OutputType::BECH32M, "forward-asset-change");
                    if (!dest_res) {
                        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(dest_res).original);
                    }
                    asset_change_specs.push_back({*dest_res, *cand.asset_id, change_units});
                }
            };

            for (const SettlementOutputCandidate& cand : settlement_outputs) {
                if (!cand.needs_external_funds) continue;
                select_asset_inputs(cand);
            }

            // Build recipient list (settlement + asset change outputs)
            std::vector<CRecipient> recipients;
            recipients.reserve(settlement_outputs.size() + asset_change_specs.size());
            for (const SettlementOutputCandidate& cand : settlement_outputs) {
                recipients.push_back({cand.dest, cand.amount, /*subtract_fee=*/false});
            }
            for (const AssetChangeSpec& change_spec : asset_change_specs) {
                recipients.push_back({change_spec.dest, DEFAULT_REPO_ASSET_OUTPUT_VALUE, /*subtract_fee=*/false});
            }
            for (const SkeletonChangeRecipient& change : skeleton_change_recipients) {
                recipients.push_back({change.dest, change.out.nValue, /*subtract_fee=*/false});
            }

            wallet::CCoinControl coin_control;
            coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
            coin_control.m_version = tx.version;
            coin_control.m_locktime = tx.nLockTime;

            const auto seed_vault_coin = [&](const COutPoint& outpoint, ForwardSide side) {
                const CTxDestination& margin_dest = (side == ForwardSide::LONG)
                    ? record.terms.long_party.margin_dest
                    : record.terms.short_party.margin_dest;
                const CScript margin_spk = GetScriptForDestination(margin_dest);
                LogPrintf("forward.build_coop_close[%s]: seeding %s vault coin %s (margin_spk=%s)\n",
                          contract_id->GetHex(),
                          side == ForwardSide::LONG ? "long" : "short",
                          outpoint.ToString(),
                          HexStr(margin_spk));
                auto meta = GetForwardVaultMetadataForOutpoint(*pwallet, outpoint, margin_spk);
                if (!meta) {
                    VaultRole role = (side == ForwardSide::LONG) ? VaultRole::FORWARD_LONG : VaultRole::FORWARD_SHORT;
                    LogPrintf("forward.build_coop_close[%s]: metadata by outpoint failed for %s vault, falling back to role lookup\n",
                              contract_id->GetHex(), side == ForwardSide::LONG ? "long" : "short");
                    meta = GetVaultMetadataByContractRole(*pwallet, record.contract_id, role);
                }
                if (!meta) {
                    LogPrintf("forward.build_coop_close[%s]: metadata still missing for %s vault after fallback\n",
                              contract_id->GetHex(), side == ForwardSide::LONG ? "long" : "short");
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        side == ForwardSide::LONG ? "Long vault not registered in wallet registry - run forward.build_open first"
                                                   : "Short vault not registered in wallet registry - run forward.build_open first");
                }

                const AssetLeg& margin_leg = (side == ForwardSide::LONG)
                    ? record.terms.long_party.margin_leg
                    : record.terms.short_party.margin_leg;
                const CAmount vault_value = (side == ForwardSide::LONG)
                    ? (record.long_margin_value != 0 ? record.long_margin_value : static_cast<CAmount>(margin_leg.units))
                    : (record.short_margin_value != 0 ? record.short_margin_value : static_cast<CAmount>(margin_leg.units));

                CTxOut vault_utxo;
                vault_utxo.scriptPubKey = meta->GetScriptPubKey();
                vault_utxo.nValue = margin_leg.is_native ? vault_value : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                if (!margin_leg.is_native) {
                    vault_utxo.vExt = BuildAssetTagTlv(margin_leg.asset_id, margin_leg.units);
                }
                LogPrintf("forward.build_coop_close[%s]: seeded %s vault utxo script=%s value=%s\n",
                          contract_id->GetHex(),
                          side == ForwardSide::LONG ? "long" : "short",
                          HexStr(vault_utxo.scriptPubKey), FormatMoney(vault_utxo.nValue));
                coin_control.Select(outpoint).SetTxOut(vault_utxo);
            };

            seed_vault_coin(long_vault, ForwardSide::LONG);
            seed_vault_coin(short_vault, ForwardSide::SHORT);

            std::vector<CTxIn> vault_inputs = tx.vin;

            CMutableTransaction tx_to_fund;
            tx_to_fund.version = tx.version;
            tx_to_fund.nLockTime = tx.nLockTime;
            tx_to_fund.vin.clear();
            if (!split_funding) {
                for (const AssetInputSpec& spec : asset_input_specs) {
                    tx_to_fund.vin.emplace_back(spec.outpoint);
                }
                for (const COutPoint& outpoint : skeleton_inputs) {
                    bool exists = std::any_of(tx_to_fund.vin.begin(), tx_to_fund.vin.end(),
                        [&](const CTxIn& in){ return in.prevout == outpoint; });
                    if (!exists) {
                        tx_to_fund.vin.emplace_back(outpoint);
                    }
                }
            }

            CMutableTransaction funded_tx;
            CAmount fee_amount{0};
            std::optional<CreatedTransactionResult> base_result;
            if (!split_funding) {
                auto fund_res = FundTransaction(*pwallet, tx_to_fund, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
                if (!fund_res) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(fund_res).original);
                }
                base_result = fund_res.value();
                funded_tx = CMutableTransaction(*base_result->tx);
                fee_amount = base_result->fee;
            } else {
                // Base transaction only: vault inputs + settlement outputs. Contributions will be added by each party.
                funded_tx = tx_to_fund;
                // Populate settlement outputs deterministically from settlement_outputs vector
                funded_tx.vout.clear();
                funded_tx.vout.reserve(settlement_outputs.size());
                for (const SettlementOutputCandidate& cand : settlement_outputs) {
                    CTxOut out;
                    out.scriptPubKey = cand.script;
                    out.nValue = cand.amount;
                    if (!cand.is_native && cand.asset_id) {
                        out.vExt = BuildAssetTagTlv(*cand.asset_id, cand.asset_units);
                    }
                    funded_tx.vout.push_back(std::move(out));
                }
            }

            // Prepend vault inputs so they occupy the first positions in the final transaction
            funded_tx.vin.insert(funded_tx.vin.begin(), vault_inputs.begin(), vault_inputs.end());

            std::vector<size_t> change_indices;
            if (base_result && base_result->change_pos) {
                change_indices.push_back(*base_result->change_pos);
            }

            const size_t skeleton_change_offset = settlement_outputs.size() + asset_change_specs.size();
            for (const CoopSkeletonContribution& contrib : skeleton_contribs) {
                const ForwardAssetSkeletonResult& skeleton = contrib.skeleton;
                if (!skeleton.deliver_output_index.has_value()) continue;
                const CTxOut& deliver_out = skeleton.tx.vout[skeleton.deliver_output_index.value()];
                if (contrib.settlement_index >= funded_tx.vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Sendasset deliver output index out of range");
                }
                funded_tx.vout[contrib.settlement_index] = deliver_out;
            }

            for (size_t i = 0; i < skeleton_change_recipients.size(); ++i) {
                const size_t output_index = skeleton_change_offset + i;
                if (output_index >= funded_tx.vout.size()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Sendasset change output index out of range");
                }
                funded_tx.vout[output_index] = skeleton_change_recipients[i].out;
                change_indices.push_back(output_index);
            }

            // Restore asset metadata on funded outputs
            std::vector<bool> asset_matched(funded_tx.vout.size(), false);
            const auto match_asset_output = [&](const CScript& script, CAmount value, const uint256& asset_id, uint64_t units) {
                for (size_t i = 0; i < funded_tx.vout.size(); ++i) {
                    if (asset_matched[i]) continue;
                    CTxOut& out = funded_tx.vout[i];
                    if (out.scriptPubKey == script && out.nValue == value) {
                        out.vExt = BuildAssetTagTlv(asset_id, units);
                        asset_matched[i] = true;
                        return true;
                    }
                }
                return false;
            };

            for (const SettlementOutputCandidate& cand : settlement_outputs) {
                if (cand.is_native || !cand.asset_id) continue;
                if (!match_asset_output(cand.script, cand.amount, *cand.asset_id, cand.asset_units)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate funded settlement asset output");
                }
            }
            for (const AssetChangeSpec& change_spec : asset_change_specs) {
                const CScript change_spk = GetScriptForDestination(change_spec.dest);
                if (!match_asset_output(change_spk, DEFAULT_REPO_ASSET_OUTPUT_VALUE, change_spec.asset_id, change_spec.units)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unable to locate funded asset change output");
                }
            }

            // Identify vault input indices within funded transaction
            size_t long_vault_input_idx = SIZE_MAX;
            size_t short_vault_input_idx = SIZE_MAX;
            for (size_t i = 0; i < funded_tx.vin.size(); ++i) {
                const COutPoint& prevout = funded_tx.vin[i].prevout;
                if (prevout == long_vault) {
                    long_vault_input_idx = i;
                } else if (prevout == short_vault) {
                    short_vault_input_idx = i;
                }
            }
            if (long_vault_input_idx == SIZE_MAX || short_vault_input_idx == SIZE_MAX) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Funded cooperative close transaction missing margin vault inputs");
            }
            funded_tx.vin[long_vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;
            funded_tx.vin[short_vault_input_idx].nSequence = CTxIn::SEQUENCE_FINAL - 1;

            PartiallySignedTransaction psbt(funded_tx);

            const auto stash_spend = [](PSBTInput& input, const TaprootSpendData& spend) {
                if (!spend.internal_key.IsNull()) {
                    input.m_tap_internal_key = spend.internal_key;
                }
                if (!spend.merkle_root.IsNull()) {
                    input.m_tap_merkle_root = spend.merkle_root;
                }
                for (const auto& [leaf, control_blocks] : spend.scripts) {
                    auto& dest_set = input.m_tap_scripts[leaf];
                    dest_set.insert(control_blocks.begin(), control_blocks.end());
                }
            };

            // CRITICAL: Retrieve vault spenddata from registry (not rebuild from builder)
            // Vaults are registered under the margin destination script, not the vault covenant script
            const CTxDestination& long_margin_dest = record.terms.long_party.margin_dest;
            const CScript long_margin_spk = GetScriptForDestination(long_margin_dest);
            auto long_vault_meta = GetForwardVaultMetadataForOutpoint(*pwallet, long_vault, long_margin_spk);
            if (!long_vault_meta) {
                LogPrintf("forward.build_coop_close[%s]: long vault metadata missing during PSBT annotation, falling back to role lookup\n",
                          contract_id->GetHex());
                long_vault_meta = GetVaultMetadataByContractRole(*pwallet, record.contract_id, VaultRole::FORWARD_LONG);
            }
            if (!long_vault_meta) {
                LogPrintf("forward.build_coop_close[%s]: long vault metadata still missing during PSBT annotation\n",
                          contract_id->GetHex());
                throw JSONRPCError(RPC_WALLET_ERROR, "Long vault not registered in wallet registry - run forward.build_open first");
            }
            EnsureForwardKeyCached(*pwallet, long_margin_dest, long_vault_meta->spenddata.internal_key);
            {
                PSBTInput& psbt_in = psbt.inputs.at(long_vault_input_idx);
                stash_spend(psbt_in, long_vault_meta->spenddata);
                AnnotateForwardLeafBip32(*pwallet, long_margin_dest, *long_vault_meta, "cooperative", psbt_in);
                // Also expose all cooperative leaf signers so the counterparty wallet
                // can resolve its key from PSBT alone.
                if (const VaultLeafDescriptor* coop = FindForwardLeafByPurpose(*long_vault_meta, "cooperative")) {
                    AnnotateAllLeafSigners(*pwallet, coop->script, coop->leaf_version, psbt_in);

                    // CRITICAL: Embed vault signing intent to prevent wrong-leaf selection
                    VaultSigningIntent intent = CreateIntentFromLeaf(*coop, long_vault_meta->spenddata);
                    EmbedVaultIntent(psbt_in, intent);
                }
            }

            const CTxDestination& short_margin_dest = record.terms.short_party.margin_dest;
            const CScript short_margin_spk = GetScriptForDestination(short_margin_dest);
            auto short_vault_meta = GetForwardVaultMetadataForOutpoint(*pwallet, short_vault, short_margin_spk);
            if (!short_vault_meta) {
                LogPrintf("forward.build_coop_close[%s]: short vault metadata missing during PSBT annotation, falling back to role lookup\n",
                          contract_id->GetHex());
                short_vault_meta = GetVaultMetadataByContractRole(*pwallet, record.contract_id, VaultRole::FORWARD_SHORT);
            }
            if (!short_vault_meta) {
                LogPrintf("forward.build_coop_close[%s]: short vault metadata still missing during PSBT annotation\n",
                          contract_id->GetHex());
                throw JSONRPCError(RPC_WALLET_ERROR, "Short vault not registered in wallet registry - run forward.build_open first");
            }
            EnsureForwardKeyCached(*pwallet, short_margin_dest, short_vault_meta->spenddata.internal_key);
            {
                PSBTInput& psbt_in = psbt.inputs.at(short_vault_input_idx);
                stash_spend(psbt_in, short_vault_meta->spenddata);
                AnnotateForwardLeafBip32(*pwallet, short_margin_dest, *short_vault_meta, "cooperative", psbt_in);
                if (const VaultLeafDescriptor* coop = FindForwardLeafByPurpose(*short_vault_meta, "cooperative")) {
                    AnnotateAllLeafSigners(*pwallet, coop->script, coop->leaf_version, psbt_in);

                    // CRITICAL: Embed vault signing intent to prevent wrong-leaf selection
                    VaultSigningIntent intent = CreateIntentFromLeaf(*coop, short_vault_meta->spenddata);
                    EmbedVaultIntent(psbt_in, intent);
                }
            }

            // Annotate with Fair-Sign metadata
            FeePolicySnapshot fee_snapshot;
            fee_snapshot.rbf = pwallet->m_signal_rbf;

            // Build outputmatch specs for covenant verification (§4.4)
            // For coop_close, extract specs from user-negotiated settlement outputs
            std::vector<OutputMatchSpec> outputmatches;
            outputmatches.reserve(settlement_outputs.size());
            for (const SettlementOutputCandidate& cand : settlement_outputs) {
                if (cand.is_native) {
                    outputmatches.push_back({cand.dest, true, static_cast<uint64_t>(cand.amount), uint256{}});
                } else {
                    outputmatches.push_back({cand.dest, false, cand.asset_units, *cand.asset_id});
                }
            }

            AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
            AnnotateForwardOutputs(psbt, change_indices);

            bool complete = false;
            // Don't sign yet - adaptor ceremony will handle signing
            // But do request BIP32 derivations to populate metadata
            const auto fill_err = pwallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, false, true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            if (!skeleton_contribs.empty()) {
                LOCK(pwallet->cs_wallet);
                for (const CoopSkeletonContribution& contrib : skeleton_contribs) {
                    for (const COutPoint& outpoint : contrib.skeleton.inputs_to_lock) {
                        pwallet->LockCoin(outpoint);
                    }
                }
            }

            // Attach vault UTXOs to identify wallet-controlled inputs
            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* long_wtx = pwallet->GetWalletTx(long_vault.hash);
                if (long_wtx && long_vault.n < long_wtx->tx->vout.size()) {
                    psbt.inputs.at(long_vault_input_idx).witness_utxo = long_wtx->tx->vout[long_vault.n];
                }
                const CWalletTx* short_wtx = pwallet->GetWalletTx(short_vault.hash);
                if (short_wtx && short_vault.n < short_wtx->tx->vout.size()) {
                    psbt.inputs.at(short_vault_input_idx).witness_utxo = short_wtx->tx->vout[short_vault.n];
                }
            }

            // Annotate wallet-owned Taproot inputs with internal keys for adaptor ceremony
            AnnotateTaprootInputsWithInternalKeys(*pwallet, psbt);

            // Return PSBT
            UniValue result(UniValue::VOBJ);
            DataStream ssTx{};
            ssTx << psbt;
            result.pushKV("psbt", EncodeBase64(ssTx.str()));
            result.pushKV("fee", ValueFromAmount(fee_amount));
            int native_change_index = -1;
            if (base_result && base_result->change_pos) {
                native_change_index = static_cast<int>(*base_result->change_pos);
            }
            if (native_change_index == -1) {
                for (size_t idx : change_indices) {
                    if (idx < psbt.tx->vout.size() && !assets::ParseAssetTag(psbt.tx->vout[idx].vExt)) {
                        native_change_index = static_cast<int>(idx);
                        break;
                    }
                }
            }
            result.pushKV("changepos", native_change_index);
            result.pushKV("complete", complete);

            if (!opts.isNull()) {
                const UniValue& roll_opt = opts.find_value("roll");
                if (!roll_opt.isNull()) {
                    if (!roll_opt.isObject()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "roll must be an object");
                    }
                    ForwardTerms rolled_terms = record.terms;

                    const UniValue& roll_ds = roll_opt.find_value("deadline_short");
                    if (!roll_ds.isNull()) {
                        rolled_terms.deadline_short = static_cast<uint32_t>(ParseSignedInt64(roll_ds, "roll.deadline_short"));
                    }
                    const UniValue& roll_dl = roll_opt.find_value("deadline_long");
                    if (!roll_dl.isNull()) {
                        rolled_terms.deadline_long = static_cast<uint32_t>(ParseSignedInt64(roll_dl, "roll.deadline_long"));
                    }
                    const UniValue& roll_s = roll_opt.find_value("safety_k");
                    if (!roll_s.isNull()) {
                        rolled_terms.safety_k = static_cast<uint32_t>(ParseSignedInt64(roll_s, "roll.safety_k"));
                    }
                    const UniValue& roll_r = roll_opt.find_value("reorg_conf");
                    if (!roll_r.isNull()) {
                        rolled_terms.reorg_conf = static_cast<uint32_t>(ParseSignedInt64(roll_r, "roll.reorg_conf"));
                    }

                    result.pushKV("roll_terms", ForwardTermsToJSON(rolled_terms));
                }
            }
            return result;
        }
    );
}

RPCHelpMan forward_coop_contrib()
{
    return RPCHelpMan(
        "forward.coop_contrib",
        "Contribute this wallet's deliver funding inputs to a cooperative close PSBT. "
        "Use after forward.build_coop_close(split_funding=true). Adds ONLY this wallet's inputs and change for its deliver leg, "
        "without introducing unilateral builder inputs.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded cooperative close PSBT (base)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Updated Base64-encoded PSBT with local funding inputs and change appended"},
                {RPCResult::Type::NUM, "inputs_added", "Number of inputs added by this wallet"},
                {RPCResult::Type::NUM, "change_added", "Number of change outputs appended by this wallet"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.coop_contrib", "\"" + std::string(64, 'a') + "\" \"cHNidP8BA...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            const ForwardContractRecord& record = *record_opt;
            const ForwardTerms& terms = record.terms;

            PartiallySignedTransaction psbt;
            std::string error;
            if (!DecodeBase64PSBT(psbt, request.params[1].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("PSBT decode failed: %s", error));
            }
            if (!psbt.tx) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT is missing unsigned transaction");
            }

            // Identify my deliver leg
            bool i_am_long = (record.local_side == ForwardSide::LONG);
            AssetLeg my_leg = i_am_long ? terms.long_party.deliver_leg : terms.short_party.deliver_leg;
            CTxDestination their_recv = i_am_long ? terms.short_party.settlement_receive_dest : terms.long_party.settlement_receive_dest;
            const CScript their_recv_spk = GetScriptForDestination(their_recv);

            // NOTE: We do not strictly require locating the deliver output here.
            // The base PSBT already contains settlement outputs; this call contributes
            // ONLY local inputs and change for funding. We still build skeletons
            // targeted at 'their_recv' with 'my_leg.units' to ensure change and
            // selection match our deliver amount.

            // Build skeletons for my deliver leg(s)
            std::vector<ForwardAssetSkeletonResult> my_skeletons;
            if (my_leg.is_native) {
                ForwardAssetSkeletonResult sk = BuildForwardNativeSkeleton(
                    *pwallet,
                    request,
                    their_recv,
                    static_cast<CAmount>(my_leg.units),
                    std::nullopt,
                    "forward.coop_contrib(native)");
                my_skeletons.push_back(std::move(sk));
            } else {
                ForwardAssetSkeletonResult sk = BuildForwardAssetSkeleton(
                    *pwallet,
                    request,
                    my_leg,
                    their_recv,
                    std::nullopt,
                    "forward.coop_contrib(asset)");
                my_skeletons.push_back(std::move(sk));
            }

            // Merge skeleton inputs and change outputs into PSBT
            CMutableTransaction merged_tx(*psbt.tx);
            int inputs_added = 0;
            int changes_added = 0;

            auto has_input = [&](const COutPoint& prev) {
                for (const CTxIn& vin : merged_tx.vin) {
                    if (vin.prevout == prev) return true;
                }
                return false;
            };

            for (const ForwardAssetSkeletonResult& sk : my_skeletons) {
                for (const CTxIn& vin : sk.tx.vin) {
                    if (!has_input(vin.prevout)) {
                        merged_tx.vin.push_back(vin);
                        ++inputs_added;
                    }
                }
                for (size_t change_idx : sk.change_indices) {
                    if (change_idx >= sk.tx.vout.size()) continue;
                    merged_tx.vout.push_back(sk.tx.vout[change_idx]);
                    ++changes_added;
                }
            }

        // Rebuild PSBT to include new inputs/outputs
        PartiallySignedTransaction out_psbt(merged_tx);

            // Carry over prior PSBT input/output maps where indices overlap
            const size_t old_in_count = psbt.inputs.size();
            const size_t old_out_count = psbt.outputs.size();
            out_psbt.inputs.resize(merged_tx.vin.size());
            out_psbt.outputs.resize(merged_tx.vout.size());
            for (size_t i = 0; i < std::min(old_in_count, out_psbt.inputs.size()); ++i) {
                out_psbt.inputs[i] = psbt.inputs[i];
            }
            for (size_t i = 0; i < std::min(old_out_count, out_psbt.outputs.size()); ++i) {
                out_psbt.outputs[i] = psbt.outputs[i];
            }

            // Preserve PSBT global proprietary/unknown entries (fs/contract_meta, policy, etc.)
            out_psbt.unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
            out_psbt.m_proprietary.insert(psbt.m_proprietary.begin(), psbt.m_proprietary.end());

            // Stash witness_utxo for new inputs (if available)
            {
                LOCK(pwallet->cs_wallet);
                for (size_t i = old_in_count; i < out_psbt.inputs.size(); ++i) {
                    const COutPoint& prev = merged_tx.vin[i].prevout;
                    const CWalletTx* wtx = pwallet->GetWalletTx(prev.hash);
                    if (wtx && prev.n < wtx->tx->vout.size()) {
                        out_psbt.inputs[i].witness_utxo = wtx->tx->vout[prev.n];
                    }
                }
            }

        // Annotate BIP32 derivations for new inputs; do not sign
        bool complete = false;
        if (const auto err = pwallet->FillPSBT(out_psbt, complete, SIGHASH_DEFAULT, false, true)) {
            throw JSONRPCPSBTError(*err);
        }

        // Re-stash vault spenddata for cooperative leaf so both parties reliably pick the coop path.
        // This guards against losing tap_scripts metadata during PSBT rebuilds.
        auto restash_vault = [&](const COutPoint& vault_op, const CTxDestination& margin_dest) {
            // Locate input index for this vault
            for (size_t i = 0; i < merged_tx.vin.size(); ++i) {
                if (merged_tx.vin[i].prevout != vault_op) continue;
                const CScript margin_spk = GetScriptForDestination(margin_dest);
                auto meta_opt = GetForwardVaultMetadataForOutpoint(*pwallet, vault_op, margin_spk);
                if (!meta_opt) continue;
                // Stash spenddata (internal key, merkle, leaves)
                PSBTInput& in = out_psbt.inputs[i];
                if (!meta_opt->spenddata.internal_key.IsNull()) in.m_tap_internal_key = meta_opt->spenddata.internal_key;
                if (!meta_opt->spenddata.merkle_root.IsNull()) in.m_tap_merkle_root = meta_opt->spenddata.merkle_root;
                for (const auto& [leaf, cbs] : meta_opt->spenddata.scripts) {
                    auto& dest_set = in.m_tap_scripts[leaf];
                    dest_set.insert(cbs.begin(), cbs.end());
                }
                // Add cooperative leaf BIP32 derivation to help counterparty resolve keys
                AnnotateForwardLeafBip32(*pwallet, margin_dest, *meta_opt, "cooperative", in);
                break;
            }
        };

        if (record.long_margin_vault && record.long_margin_internal_key) {
            restash_vault(*record.long_margin_vault, terms.long_party.margin_dest);
        }
        if (record.short_margin_vault && record.short_margin_internal_key) {
            restash_vault(*record.short_margin_vault, terms.short_party.margin_dest);
        }

        // Return updated PSBT
        UniValue result(UniValue::VOBJ);
            DataStream ss{};
            ss << out_psbt;
            result.pushKV("psbt", EncodeBase64(ss.str()));
            result.pushKV("inputs_added", inputs_added);
            result.pushKV("change_added", changes_added);
            return result;
        }
    );
}


RPCHelpMan forward_build_self_delivery()
{
    return RPCHelpMan(
        "forward.build_self_delivery",
        "Construct Bob's self-delivery PSBT. Bob (short party) spends his IM vault via the SELF-DELIVER leaf before deadline T, pays asset B to Alice, and creates the B_ESCROW output.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"short_vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override short vault outpoint txid"},
                    {"short_vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override short vault outpoint index"},
                    {"manual_inputs", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Disable automatic asset input selection"},
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Manual additional inputs for asset B",
                        std::vector<RPCArg>{
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                std::vector<RPCArg>{
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Input txid"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input vout"},
                                }
                            }
                        }
                    },
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "side", "Self-delivery side ('short' or 'long')"},
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::NUM, "fee", "Wallet-computed fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the IM vault input being spent"},
                {RPCResult::Type::NUM, "short_vault_input_index", /*optional=*/true, "Index of Bob's vault input (present when side='short')"},
                {RPCResult::Type::NUM, "long_vault_input_index", /*optional=*/true, "Index of Alice's vault input (present when side='long')"},
                {RPCResult::Type::NUM, "delivery_output_index", /*optional=*/true, "Index of the direct delivery output (only present when side='short' and such output exists)"},
                {RPCResult::Type::NUM, "escrow_output_index", "Index of the escrow output that is created"},
                {RPCResult::Type::NUM, "margin_output_index", "Index of the IM refund output"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet change output or -1"},
                {RPCResult::Type::ARR, "locked_inputs", /*optional=*/true, "Wallet inputs reserved for this build",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "Locked input transaction id"},
                                {RPCResult::Type::NUM, "vout", "Locked input output index"},
                            }
                        },
                    }
                },
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT contains all signatures"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Signed transaction hex (present when complete=true)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (present when complete=true)"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.build_self_delivery", "\"" + std::string(64, 'a') + "\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            ForwardContractRecord record = *record_opt;

            bool updated_keys = false;
            if (!record.long_margin_internal_key) {
                record.long_margin_internal_key = LookupTaprootInternalKey(*pwallet, record.terms.long_party.margin_dest);
                if (record.long_margin_internal_key) updated_keys = true;
            }
            if (!record.short_margin_internal_key) {
                record.short_margin_internal_key = LookupTaprootInternalKey(*pwallet, record.terms.short_party.margin_dest);
                if (record.short_margin_internal_key) updated_keys = true;
            }

            if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Forward contract missing margin internal keys - re-import counterparty payloads");
            }

            if (updated_keys) {
                record = pwallet->RegisterForwardContract(std::move(record));
                CacheForwardVaultScripts(*pwallet, record);
            }

            const UniValue opts = request.params.size() > 1 && request.params[1].isObject()
                ? request.params[1].get_obj()
                : UniValue::VNULL;

            ForwardSide action_side = record.local_side;
            if (!opts.isNull()) {
                const UniValue& side_val = opts.find_value("side");
                if (!side_val.isNull()) {
                    const std::string side_str = ToLower(side_val.get_str());
                    if (side_str == "short") {
                        action_side = ForwardSide::SHORT;
                    } else if (side_str == "long") {
                        action_side = ForwardSide::LONG;
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.side must be 'short' or 'long'");
                    }
                }
            }

            if (action_side != record.local_side) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Wallet role does not match requested self-delivery side");
            }

            bool manual_inputs = false;
            if (!opts.isNull()) {
                const UniValue& manual_val = opts.find_value("manual_inputs");
                if (!manual_val.isNull()) {
                    manual_inputs = manual_val.get_bool();
                }
            }

            std::optional<uint32_t> locktime_override;
            if (!opts.isNull()) {
                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    int64_t locktime64 = ParseSignedInt64(locktime_val, "options.locktime");
                    if (locktime64 < 0 || locktime64 > std::numeric_limits<uint32_t>::max()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.locktime out of range");
                    }
                    locktime_override = static_cast<uint32_t>(locktime64);
                }
            }

            if (action_side == ForwardSide::SHORT) {
                return BuildForwardSelfDeliveryShort(*pwallet, record, *contract_id, opts, manual_inputs, locktime_override, request);
            }
            return BuildForwardSelfDeliveryLong(*pwallet, record, *contract_id, opts, manual_inputs, locktime_override, request);
        }
    );
}

RPCHelpMan forward_build_escrow_claim()
{
    return RPCHelpMan(
        "forward.build_escrow_claim",
        "Construct Alice's escrow claim PSBT. Alice (long party) claims asset B from the B_ESCROW by paying asset A to Bob in the same transaction (BE-CLAIM leaf).",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"escrow_outpoint", RPCArg::Type::OBJ, RPCArg::Optional::NO, "B_ESCROW outpoint",
                std::vector<RPCArg>{
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "B_ESCROW transaction ID"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "B_ESCROW output index"},
                }
            },
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"manual_inputs", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Disable automatic asset input selection"},
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Manual additional inputs",
                        std::vector<RPCArg>{
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                std::vector<RPCArg>{
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Input txid"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input vout"},
                                }
                            }
                        }
                    },
                    {"long_vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Long party's IM vault txid (for B escrow claim: margin recovery + multi-asset support)"},
                    {"long_vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Long party's IM vault vout"},
                    {"short_vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Short party's IM vault txid (for A escrow claim: margin recovery + multi-asset support)"},
                    {"short_vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Short party's IM vault vout"},
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::NUM, "fee", "Wallet-computed fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "escrow_input_index", "Index of the B_ESCROW input"},
                {RPCResult::Type::NUM, "payment_output_index", "Index of asset A payment to Bob"},
                {RPCResult::Type::NUM, "claim_output_index", "Index of asset B claim to Alice"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the IM vault input, or -1 if not included"},
                {RPCResult::Type::NUM, "margin_output_index", "Index of the margin recovery output, or -1 if not included"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet change output or -1"},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT contains all signatures"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Signed transaction hex (present when complete=true)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (present when complete=true)"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.build_escrow_claim", "\"" + std::string(64, 'a') + "\" \"{\\\"txid\\\":\\\"...\\\", \\\"vout\\\":0}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            ForwardContractRecord record = *record_opt;

            const UniValue opts = request.params.size() > 2 && request.params[2].isObject()
                ? request.params[2].get_obj()
                : UniValue::VNULL;
            const UniValue& escrow_obj = request.params[1].get_obj();
            UniValue opts_for_builder = opts;

            // Copy fee_rate from escrow_obj if not present in opts (for 2-argument calls)
            const UniValue& fee_rate_val = escrow_obj.find_value("fee_rate");
            if (!fee_rate_val.isNull()) {
                if (opts_for_builder.isNull()) {
                    opts_for_builder = UniValue(UniValue::VOBJ);
                }
                if (opts_for_builder.find_value("fee_rate").isNull()) {
                    opts_for_builder.pushKV("fee_rate", fee_rate_val);
                }
            }

            enum class EscrowKind : uint8_t { A, B };
            EscrowKind escrow_kind = record.local_side == ForwardSide::LONG ? EscrowKind::B : EscrowKind::A;
            if (!opts_for_builder.isNull()) {
                const UniValue& escrow_val = opts_for_builder.find_value("escrow");
                if (!escrow_val.isNull()) {
                    const std::string esc = ToLower(escrow_val.get_str());
                    if (esc == "a") {
                        escrow_kind = EscrowKind::A;
                    } else if (esc == "b") {
                        escrow_kind = EscrowKind::B;
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.escrow must be 'A' or 'B'");
                    }
                }
            }

            if (escrow_kind == EscrowKind::B && record.local_side != ForwardSide::LONG) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Escrow claim for leg B must be executed by the long party");
            }
            if (escrow_kind == EscrowKind::A && record.local_side != ForwardSide::SHORT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Escrow claim for leg A must be executed by the short party");
            }

            const std::string escrow_txid_hex = escrow_obj.find_value("txid").get_str();
            const uint32_t escrow_vout = escrow_obj.find_value("vout").getInt<uint32_t>();
            auto escrow_txid_opt = uint256::FromHex(escrow_txid_hex);
            if (!escrow_txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid escrow txid");
            }
            COutPoint escrow_outpoint(Txid::FromUint256(*escrow_txid_opt), escrow_vout);

            bool manual_inputs = false;
            if (!opts_for_builder.isNull()) {
                const UniValue& manual_val = opts_for_builder.find_value("manual_inputs");
                if (!manual_val.isNull()) {
                    manual_inputs = manual_val.get_bool();
                }
            }

            std::optional<uint32_t> locktime_override;
            if (!opts_for_builder.isNull()) {
                const UniValue& locktime_val = opts_for_builder.find_value("locktime");
                if (!locktime_val.isNull()) {
                    locktime_override = locktime_val.getInt<uint32_t>();
                }
            }

            // Parse vault outpoint if provided (needed for margin recovery + multi-asset contracts)
            // Vault hints may be passed even when the UTXO is already spent (e.g., after restart for metadata lookup).
            // Only include the vault input if the UTXO is actually unspent.
            std::optional<COutPoint> vault_outpoint;
            if (!opts_for_builder.isNull()) {
                // For long claim (B escrow), look for long_vault_txid/vout
                // For short claim (A escrow), look for short_vault_txid/vout
                const char* vault_txid_key = (escrow_kind == EscrowKind::B) ? "long_vault_txid" : "short_vault_txid";
                const char* vault_vout_key = (escrow_kind == EscrowKind::B) ? "long_vault_vout" : "short_vault_vout";

                const UniValue& vault_txid_val = opts_for_builder.find_value(vault_txid_key);
                const UniValue& vault_vout_val = opts_for_builder.find_value(vault_vout_key);
                if (!vault_txid_val.isNull() && !vault_vout_val.isNull()) {
                    const std::string vault_txid_hex = vault_txid_val.get_str();
                    auto vault_txid_opt = uint256::FromHex(vault_txid_hex);
                    if (!vault_txid_opt) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid ") + vault_txid_key);
                    }
                    const uint32_t vault_vout = vault_vout_val.getInt<uint32_t>();
                    COutPoint candidate(Txid::FromUint256(*vault_txid_opt), vault_vout);

                    // Only set vault_outpoint if the UTXO is actually unspent
                    {
                        LOCK(pwallet->cs_wallet);
                        if (!pwallet->IsSpent(candidate)) {
                            vault_outpoint = candidate;
                        }
                    }
                }
            }

            // If no vault provided in options, automatically use vault from contract record (if available and unspent)
            if (!vault_outpoint) {
                std::optional<COutPoint> record_vault = (escrow_kind == EscrowKind::B)
                    ? record.long_margin_vault
                    : record.short_margin_vault;

                if (record_vault) {
                    LOCK(pwallet->cs_wallet);
                    if (!pwallet->IsSpent(*record_vault)) {
                        vault_outpoint = record_vault;
                        pwallet->WalletLogPrintf("forward.build_escrow_claim: Auto-detected %s vault %s for IM recovery\n",
                            (escrow_kind == EscrowKind::B) ? "long" : "short",
                            record_vault->ToString());
                    }
                }
            }

            if (escrow_kind == EscrowKind::B) {
                return BuildForwardEscrowClaimLong(*pwallet, request, record, escrow_outpoint, vault_outpoint, manual_inputs, locktime_override, opts_for_builder);
            }
            return BuildForwardEscrowClaimShort(*pwallet, request, record, escrow_outpoint, vault_outpoint, manual_inputs, locktime_override, opts_for_builder);
        }
    );
}

RPCHelpMan forward_build_escrow_refund()
{
    return RPCHelpMan(
        "forward.build_escrow_refund",
        "Construct escrow refund PSBT. Either party can reclaim their escrowed asset after the appropriate deadline if the counterparty failed to claim (refund leaf).",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"escrow_outpoint", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Escrow outpoint",
                std::vector<RPCArg>{
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Escrow transaction ID"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Escrow output index"},
                }
            },
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"escrow", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Which escrow to refund: 'A' (long party) or 'B' (short party). Defaults based on local_side."},
                    {"refund_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination for refunded asset (defaults to party's settlement address)"},
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime (must be >= deadline_long)"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB (overrides wallet's fee estimation)"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::NUM, "fee", "Wallet-computed fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "escrow_input_index", "Index of the escrow input"},
                {RPCResult::Type::NUM, "refund_output_index", "Index of the refund output"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet change output or -1"},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT contains all signatures"},
                {RPCResult::Type::STR, "escrow", "Which escrow was refunded: 'A' or 'B'"},
                {RPCResult::Type::STR, "side", "Which side refunded: 'short' or 'long'"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Signed transaction hex (present when complete=true)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction identifier (present when complete=true)"},
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.build_escrow_refund", "\"" + std::string(64, 'a') + "\" \"{\\\"txid\\\":\\\"...\\\", \\\"vout\\\":0}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            ForwardContractRecord record = *record_opt;

            const UniValue& escrow_obj = request.params[1].get_obj();
            const std::string escrow_txid_hex = escrow_obj.find_value("txid").get_str();
            const uint32_t escrow_vout = escrow_obj.find_value("vout").getInt<uint32_t>();
            auto escrow_txid_opt = uint256::FromHex(escrow_txid_hex);
            if (!escrow_txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid escrow txid");
            }
            COutPoint escrow_outpoint(Txid::FromUint256(*escrow_txid_opt), escrow_vout);

            const UniValue opts = request.params.size() > 2 && request.params[2].isObject()
                ? request.params[2].get_obj()
                : UniValue::VNULL;

            enum class EscrowKind : uint8_t { A, B };
            EscrowKind escrow_kind = record.local_side == ForwardSide::LONG ? EscrowKind::A : EscrowKind::B;
            if (!opts.isNull()) {
                const UniValue& escrow_val = opts.find_value("escrow");
                if (!escrow_val.isNull()) {
                    const std::string esc = ToLower(escrow_val.get_str());
                    if (esc == "a") {
                        escrow_kind = EscrowKind::A;
                    } else if (esc == "b") {
                        escrow_kind = EscrowKind::B;
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.escrow must be 'A' or 'B'");
                    }
                }
            }

            if (escrow_kind == EscrowKind::B && record.local_side != ForwardSide::SHORT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Escrow refund for leg B must be executed by the short party");
            }
            if (escrow_kind == EscrowKind::A && record.local_side != ForwardSide::LONG) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Escrow refund for leg A must be executed by the long party");
            }

            std::optional<uint32_t> locktime_override;
            if (!opts.isNull()) {
                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    locktime_override = locktime_val.getInt<uint32_t>();
                }
            }

            if (escrow_kind == EscrowKind::B) {
                return BuildForwardEscrowRefundShort(*pwallet, record, escrow_outpoint, locktime_override, opts);
            }
            return BuildForwardEscrowRefundLong(*pwallet, record, escrow_outpoint, locktime_override, opts);
        }
    );
}

RPCHelpMan forward_build_im_timeout()
{
    return RPCHelpMan(
        "forward.build_im_timeout",
        "Construct IM timeout sweep PSBT. Alice sweeps Bob's IM vault after deadline T if Bob failed to self-deliver. Bob sweeps Alice's IM vault after deadline T+K if Alice failed to pay asset A.",
        std::vector<RPCArg>{
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Forward contract identifier"},
            {"vault_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Which vault to sweep: 'bob' (Alice sweeps after T) or 'alice' (Bob sweeps after T+K)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional builder settings",
                std::vector<RPCArg>{
                    {"vault_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Override vault outpoint txid"},
                    {"vault_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override vault outpoint index"},
                    {"sweep_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination for swept IM (defaults to party's settlement address)"},
                    {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Override transaction nLockTime"},
                }
            }
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
                {RPCResult::Type::STR, "hex", /*optional=*/true, "Hex-encoded signed transaction (when complete=true in hot wallet)"},
                {RPCResult::Type::STR, "txid", /*optional=*/true, "Transaction ID (when complete=true in hot wallet)"},
                {RPCResult::Type::NUM, "fee", "Wallet-computed fee (in " + CURRENCY_UNIT + ")"},
                {RPCResult::Type::NUM, "vault_input_index", "Index of the IM vault input"},
                {RPCResult::Type::NUM, "sweep_output_index", "Index of the sweep output"},
                {RPCResult::Type::NUM, "changepos", "Index of wallet change output or -1"},
                {RPCResult::Type::BOOL, "complete", "Whether the PSBT contains all signatures"},
                {RPCResult::Type::OBJ, "signing_info", /*optional=*/true, "Info for external signers (when complete=false)",
                    {
                        {RPCResult::Type::STR_HEX, "timeout_pubkey", "Timeout leaf signing public key"},
                        {RPCResult::Type::STR_HEX, "timeout_leaf_hash", "Timeout leaf hash"},
                        {RPCResult::Type::NUM, "timeout_height", "Timeout block height"},
                    }
                },
            }
        },
        RPCExamples{
            "\n" + HelpExampleCli("forward.build_im_timeout", "\"" + std::string(64, 'a') + "\" \"bob\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            const std::string id_hex = request.params[0].get_str();
            if (!IsHex(id_hex) || id_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id must be 32-byte hex");
            }
            const auto contract_id = uint256::FromHex(id_hex);
            if (!contract_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "id invalid");
            }

            auto record_opt = pwallet->FindForwardContract(*contract_id);
            if (!record_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown forward contract id");
            }
            ForwardContractRecord record = *record_opt;

            // Ensure vault metadata is cached before evaluating sweep options
            EnsureForwardVaultState(*pwallet, request, record);
            if (auto refreshed = pwallet->FindForwardContract(*contract_id)) {
                record = *refreshed;
            }

            const std::string vault_type = request.params[1].get_str();
            bool sweep_bob_vault;  // true = Alice sweeps Bob's vault, false = Bob sweeps Alice's vault
            if (vault_type == "bob") {
                sweep_bob_vault = true;
                if (record.local_side != ForwardSide::LONG) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Sweeping Bob's vault can only be executed by Alice (long party)");
                }
                if (!record.short_margin_vault) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Bob's vault not established");
                }
            } else if (vault_type == "alice") {
                sweep_bob_vault = false;
                if (record.local_side != ForwardSide::SHORT) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Sweeping Alice's vault can only be executed by Bob (short party)");
                }
                if (!record.long_margin_vault) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Alice's vault not established");
                }
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vault_type must be 'bob' or 'alice'");
            }

            // Determine vault outpoint and default sweep destination
            COutPoint vault_outpoint = sweep_bob_vault ? *record.short_margin_vault : *record.long_margin_vault;
            CTxDestination sweep_dest = sweep_bob_vault
                ? record.terms.long_party.settlement_receive_dest
                : record.terms.short_party.settlement_receive_dest;
            const AssetLeg& margin_leg = sweep_bob_vault
                ? record.terms.short_party.margin_leg
                : record.terms.long_party.margin_leg;

            // Set locktime based on which vault is being swept
            uint32_t locktime = sweep_bob_vault ? record.terms.deadline_short : record.terms.deadline_long;

            // Parse options (declare opts outside if block for later use)
            const UniValue opts = (request.params.size() > 2 && request.params[2].isObject())
                                   ? request.params[2].get_obj()
                                   : UniValue::VNULL;

            if (!opts.isNull()) {

                const UniValue& vault_txid_val = opts.find_value("vault_txid");
                const UniValue& vault_vout_val = opts.find_value("vault_vout");
                if (!vault_txid_val.isNull() && !vault_vout_val.isNull()) {
                    auto txid_opt = uint256::FromHex(vault_txid_val.get_str());
                    if (!txid_opt) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vault_txid");
                    }
                    vault_outpoint = COutPoint(Txid::FromUint256(*txid_opt), vault_vout_val.getInt<uint32_t>());
                }

                const UniValue& sweep_addr_val = opts.find_value("sweep_address");
                if (!sweep_addr_val.isNull()) {
                    sweep_dest = DecodeDestination(sweep_addr_val.get_str());
                    if (!IsValidDestination(sweep_dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid sweep_address");
                    }
                }

                const UniValue& locktime_val = opts.find_value("locktime");
                if (!locktime_val.isNull()) {
                    uint32_t custom_locktime = locktime_val.getInt<uint32_t>();
                    uint32_t min_locktime = sweep_bob_vault ? record.terms.deadline_short : record.terms.deadline_long;
                    if (custom_locktime < min_locktime) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "locktime must be >= " + std::to_string(min_locktime) + " for this timeout sweep");
                    }
                    locktime = custom_locktime;
                }
            }

            // Build transaction with vault input (covenant tx: 1 input, 1 output, fees deducted)
            CMutableTransaction tx;
            tx.version = 2;
            tx.nLockTime = locktime;
            tx.vin.emplace_back(vault_outpoint);
            tx.vin.back().nSequence = CTxIn::SEQUENCE_FINAL - 1;
            const size_t vault_input_idx = 0;

            // Estimate fee
            std::optional<double> fee_rate_override = ParseFeeRateOverride(opts);
            CFeeRate fee_rate;
            if (fee_rate_override) {
                fee_rate = CFeeRate(static_cast<CAmount>(*fee_rate_override * 1000)); // sat/vB -> sat/kB
            } else if (pwallet->m_pay_tx_fee != CFeeRate(0)) {
                fee_rate = pwallet->m_pay_tx_fee;
            } else {
                fee_rate = CFeeRate(1000);  // 1 sat/vB fallback
            }
            const CAmount estimated_fee = fee_rate.GetFee(204);  // ~204 vB for Taproot script-path spend

            // Determine sweep amount (deduct fees from native BTC, preserve asset units)
            const CAmount vault_sats = margin_leg.is_native ? static_cast<CAmount>(margin_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
            CAmount sweep_sats = vault_sats;

            if (margin_leg.is_native) {
                sweep_sats = vault_sats - estimated_fee;
                if (sweep_sats <= 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Vault value insufficient to cover fees");
                }
            }

            // Add sweep output
            CTxOut sweep_out;
            sweep_out.scriptPubKey = GetScriptForDestination(sweep_dest);
            sweep_out.nValue = sweep_sats;
            if (!margin_leg.is_native) {
                sweep_out.vExt = BuildAssetTagTlv(margin_leg.asset_id, margin_leg.units);
            }
            tx.vout.push_back(sweep_out);
            const size_t sweep_output_idx = 0;

            // Create PSBT
            PartiallySignedTransaction psbt(tx);

            // Annotate metadata
            FeePolicySnapshot fee_snapshot;
            fee_snapshot.rbf = pwallet->m_signal_rbf;

            std::vector<OutputMatchSpec> outputmatches;
            outputmatches.push_back({
                sweep_dest,
                margin_leg.is_native,
                margin_leg.units,
                margin_leg.asset_id
            });

            AnnotateForwardGlobalMetadata(psbt, record, fee_snapshot, outputmatches);
            AnnotateForwardOutputs(psbt, {});

            [[maybe_unused]] bool fill_complete = false;
            const auto fill_err = pwallet->FillPSBT(psbt, fill_complete, SIGHASH_DEFAULT, true, true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            // Get keys from contract record
            if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Contract missing margin internal keys");
            }
            const ForwardTerms& terms = record.terms;

            // CRITICAL: Retrieve vault metadata from registry (not rebuild from builder)
            // Vaults are registered under the vault owner's margin destination script
            const CScript margin_spk = sweep_bob_vault
                ? GetScriptForDestination(terms.short_party.margin_dest)  // Bob's vault
                : GetScriptForDestination(terms.long_party.margin_dest);  // Alice's vault

            std::optional<VaultMetadata> vault_meta;
            CScript vault_spk;  // Will be populated from wallet tx or vault metadata
            {
                std::set<ScriptPubKeyMan*> managers = pwallet->GetScriptPubKeyMans(margin_spk);
                if (managers.empty()) {
                    for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                        if (manager && dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                            managers.insert(manager);
                        }
                    }
                }
                for (ScriptPubKeyMan* manager : managers) {
                    if (auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager)) {
                        // GetVaultMetadata uses the vault covenant script as the lookup key
                        // Try to get vault_spk from wallet transaction first
                        {
                            LOCK(pwallet->cs_wallet);
                            const CWalletTx* vault_wtx = pwallet->GetWalletTx(Txid::FromUint256(vault_outpoint.hash));
                            if (vault_wtx && vault_outpoint.n < vault_wtx->tx->vout.size()) {
                                vault_spk = vault_wtx->tx->vout[vault_outpoint.n].scriptPubKey;
                            }
                        }
                        if (!vault_spk.empty()) {
                            vault_meta = desc_spkm->GetVaultMetadata(vault_spk);
                            if (vault_meta) break;
                        }
                    }
                }
            }

            if (!vault_meta) {
                VaultRole role = sweep_bob_vault ? VaultRole::FORWARD_SHORT : VaultRole::FORWARD_LONG;
                LogPrintf("forward.build_im_timeout[%s]: vault metadata missing for outpoint %s, falling back to role %s\n",
                          contract_id->GetHex(),
                          vault_outpoint.ToString(),
                          role == VaultRole::FORWARD_SHORT ? "short" : "long");
                vault_meta = GetVaultMetadataByContractRole(*pwallet, record.contract_id, role);
            }
            if (!vault_meta) {
                LogPrintf("forward.build_im_timeout[%s]: vault metadata still missing after fallback (sweep=%s)\n",
                          contract_id->GetHex(), sweep_bob_vault ? "bob" : "alice");
                throw JSONRPCError(RPC_WALLET_ERROR, "Vault not registered in wallet registry - run forward.build_open first");
            }

            // If we didn't get vault_spk from the wallet transaction, construct it from vault metadata
            if (vault_spk.empty()) {
                vault_spk = vault_meta->GetScriptPubKey();
            }

            // CRITICAL: Always populate witness_utxo for Taproot signing
            // Without this, SignatureHashSchnorr will fail and no signature will be produced
            // Try to get from wallet transaction first, otherwise construct from metadata
            {
                LOCK(pwallet->cs_wallet);
                const CWalletTx* vault_wtx = pwallet->GetWalletTx(Txid::FromUint256(vault_outpoint.hash));
                if (vault_wtx && vault_outpoint.n < vault_wtx->tx->vout.size()) {
                    // Use actual UTXO from wallet if available
                    psbt.inputs[vault_input_idx].witness_utxo = vault_wtx->tx->vout[vault_outpoint.n];
                } else {
                    // Construct witness_utxo from vault metadata when sweeping counterparty's vault
                    // The sweeping wallet doesn't have the opening transaction, but we know the vault structure
                    CTxOut vault_utxo;
                    vault_utxo.scriptPubKey = vault_spk;
                    vault_utxo.nValue = margin_leg.is_native
                        ? static_cast<CAmount>(margin_leg.units)
                        : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
                    if (!margin_leg.is_native) {
                        vault_utxo.vExt = BuildAssetTagTlv(margin_leg.asset_id, margin_leg.units);
                    }
                    psbt.inputs[vault_input_idx].witness_utxo = vault_utxo;
                }
            }

            // Use spenddata from registered vault (not freshly built)
            const TaprootSpendData& spenddata = vault_meta->spenddata;
            auto& psbt_in = psbt.inputs[vault_input_idx];
            psbt_in.m_tap_internal_key = spenddata.internal_key;
            psbt_in.m_tap_merkle_root = spenddata.merkle_root;
            for (const auto& [script_key, control_blocks] : spenddata.scripts) {
                auto& entry = psbt_in.m_tap_scripts[script_key];
                entry.insert(control_blocks.begin(), control_blocks.end());
            }

            // Find timeout leaf in vault metadata and use its EXACT script for leaf hash
            // This ensures the leaf hash matches what was registered, avoiding subtle mismatches
            const VaultLeafDescriptor* timeout_leaf = nullptr;
            for (const auto& leaf : vault_meta->leaves) {
                if (leaf.purpose == "timeout") {
                    timeout_leaf = &leaf;
                    break;
                }
            }
            if (!timeout_leaf) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Timeout leaf not found in vault metadata");
            }

            // Compute leaf hash from the EXACT script stored in vault metadata
            const uint256 timeout_leaf_hash = ComputeTapleafHash(
                timeout_leaf->leaf_version,
                std::span<const unsigned char>(timeout_leaf->script.data(), timeout_leaf->script.size()));

            // Prune tapscripts to the timeout leaf only
            {
                auto script_iter = psbt_in.m_tap_scripts.begin();
                while (script_iter != psbt_in.m_tap_scripts.end()) {
                    const auto& [leaf_key, _] = *script_iter;
                    const auto& script_bytes = leaf_key.first;
                    const uint8_t leaf_ver = leaf_key.second;
                    const uint256 leaf_hash = ComputeTapleafHash(
                        leaf_ver,
                        std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));
                    if (leaf_hash == timeout_leaf_hash) {
                        ++script_iter;
                        continue;
                    }
                    script_iter = psbt_in.m_tap_scripts.erase(script_iter);
                }
                // Sanity: ensure timeout leaf remains
                if (psbt_in.m_tap_scripts.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Timeout tapscript metadata missing in PSBT");
                }
            }

            // Clear and rebuild BIP32 derivations for ONLY the timeout key
            const XOnlyPubKey& timeout_signing_key = timeout_leaf->signing_key;
            psbt_in.m_tap_bip32_paths.clear();

            // Add derivation info for the timeout signing key
            {
                const CTxDestination our_margin_dest = sweep_bob_vault
                    ? terms.long_party.margin_dest   // Alice sweeping Bob's vault
                    : terms.short_party.margin_dest; // Bob sweeping Alice's vault

                std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(
                    GetScriptForDestination(our_margin_dest));
                if (!provider) {
                    provider = pwallet->GetSolvingProvider(
                        GetScriptForDestination(sweep_bob_vault
                            ? terms.long_party.settlement_receive_dest
                            : terms.short_party.settlement_receive_dest));
                }

                KeyOriginInfo origin;
                if (provider && provider->GetKeyOriginByXOnly(timeout_signing_key, origin)) {
                    auto& derivation = psbt_in.m_tap_bip32_paths[timeout_signing_key];
                    derivation.first.insert(timeout_leaf_hash);
                    derivation.second = origin;
                }
            }

            // Detect if we have the private key for timeout signing
            CKey timeout_priv;
            bool have_timeout_key = false;
            for (ScriptPubKeyMan* manager : pwallet->GetAllScriptPubKeyMans()) {
                auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(manager);
                if (!desc_spkm) continue;

                // GetKeyByXOnly returns false for watch-only descriptors
                if (desc_spkm->GetKeyByXOnly(timeout_signing_key, timeout_priv)) {
                    have_timeout_key = true;
                    LogPrintLevel(BCLog::RPC, BCLog::Level::Debug,
                                  "forward.build_im_timeout: found timeout key in descriptor %s\n",
                                  desc_spkm->GetID().ToString());
                    break;
                }
            }

            if (have_timeout_key) {
                LogPrintLevel(BCLog::RPC, BCLog::Level::Debug,
                              "forward.build_im_timeout: hot wallet path - signing timeout leaf\n");

                const uint32_t timeout_height = sweep_bob_vault
                    ? terms.deadline_short   // Bob's deadline (Alice sweeping)
                    : terms.deadline_long;    // Alice's deadline (Bob sweeping)

                auto& chain = pwallet->chain();
                const int current_height = chain.getHeight().value_or(0);
                if (current_height < static_cast<int>(timeout_height)) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        strprintf("Timeout not yet valid: current height %d < timeout %u",
                                  current_height, timeout_height));
                }

                if (psbt.tx->vin[vault_input_idx].nSequence == CTxIn::SEQUENCE_FINAL) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Transaction sequence must not be final for CLTV timeout");
                }

                FinalizeVaultTaprootLeafWitness(*pwallet,
                                                psbt,
                                                vault_input_idx,
                                                *vault_meta,
                                                *timeout_leaf,
                                                timeout_priv,
                                                "forward.build_im_timeout");

                CMutableTransaction mtx(*psbt.tx);
                for (size_t i = 0; i < psbt.inputs.size(); ++i) {
                    if (!psbt.inputs[i].final_script_witness.IsNull()) {
                        mtx.vin[i].scriptWitness = psbt.inputs[i].final_script_witness;
                    }
                }

                CTransaction final_tx(mtx);

                UniValue result(UniValue::VOBJ);
                result.pushKV("hex", EncodeHexTx(final_tx));
                result.pushKV("complete", true);
                result.pushKV("txid", final_tx.GetHash().GetHex());
                result.pushKV("fee", ValueFromAmount(estimated_fee));
                result.pushKV("vault_input_index", static_cast<int>(vault_input_idx));
                result.pushKV("sweep_output_index", static_cast<int>(sweep_output_idx));
                result.pushKV("changepos", -1);

                DataStream signed_psbt{};
                signed_psbt << psbt;
                result.pushKV("psbt", EncodeBase64(signed_psbt.str()));

                return result;

            } else {
                // WATCH-ONLY PATH: Return clean PSBT for external signing
                LogPrintLevel(BCLog::RPC, BCLog::Level::Debug,
                              "forward.build_im_timeout: watch-only path - returning PSBT for external signing\n");

                // The PSBT is already pruned to just the timeout leaf
                // and has clean BIP32 derivations for only the timeout key

                // Return PSBT (not complete)
                UniValue result(UniValue::VOBJ);
                DataStream ssTx{};
                ssTx << psbt;
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
                result.pushKV("complete", false);
                result.pushKV("fee", ValueFromAmount(estimated_fee));
                result.pushKV("vault_input_index", static_cast<int>(vault_input_idx));
                result.pushKV("sweep_output_index", static_cast<int>(sweep_output_idx));
                result.pushKV("changepos", -1);

                // Add signing info for external signers
                UniValue signing_info(UniValue::VOBJ);
                signing_info.pushKV("timeout_pubkey", HexStr(timeout_signing_key));
                signing_info.pushKV("timeout_leaf_hash", HexStr(timeout_leaf_hash));
                signing_info.pushKV("timeout_height", sweep_bob_vault ? terms.deadline_short : terms.deadline_long);
                result.pushKV("signing_info", signing_info);

                return result;
            }
        }
    );
}

/**
 * Derive a script-only (no-owner) Taproot internal key as an x-only pubkey.
 * Deterministic per (tag, contract_id). Loops a counter until a valid x-only
 * point is found. No private key is known or stored.
 */
static XOnlyPubKey DeriveScriptOnlyInternalKey(const std::string& tag,
                                               const uint256& contract_id)
{
    // Domain separation string
    std::string domain = std::string("tensorcash-taproot-nums:v1||") + tag + "||" + contract_id.GetHex();
    // Try counters until secp256k1 parses the x-only pubkey
    for (uint32_t ctr = 0; ctr < 100000; ++ctr) {
        HashWriter hw{};
        hw << domain;
        hw << ctr;
        uint256 h = hw.GetSHA256();
        XOnlyPubKey xonly(std::span<const unsigned char>(h.begin(), 32));
        if (xonly.IsFullyValid()) return xonly;
    }
    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive script-only internal key");
}

// ============================================================================
// SETTLEMENT PROFILE AND CROSS-CHAIN RECORD RPCs
// ============================================================================

RPCHelpMan settlement_profile_add()
{
    return RPCHelpMan{"settlement_profile.add",
        "Add or update an external settlement profile.",
        {
            {"profile_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Unique profile identifier"},
            {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "Human-readable label"},
            {"chain", RPCArg::Type::STR, RPCArg::Optional::NO, "External chain: btc|ethereum|tron"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Settlement address on external chain"},
            {"signer_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "Signing reference (derived:auto or imported:<key-id>)"},
            {"preferred_asset", RPCArg::Type::STR, RPCArg::Optional::NO, "Preferred asset (BTC|ETH|USDT)"},
            {"fee_speed", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Fee speed: normal|fast|urgent (default: normal)"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "true if profile was saved"},
        RPCExamples{
            HelpExampleCli("settlement_profile.add", "\"btc-cold\" \"My BTC\" \"btc\" \"bc1q...\" \"derived:auto\" \"BTC\" \"normal\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
            CWallet* const wallet_ptr = const_cast<CWallet*>(pwallet.get());

            SettlementProfile profile;
            profile.label = request.params[1].get_str();

            const std::string chain_str = request.params[2].get_str();
            if (chain_str == "btc") profile.chain = CrossChainKind::BTC;
            else if (chain_str == "ethereum") profile.chain = CrossChainKind::ETHEREUM;
            else if (chain_str == "tron") profile.chain = CrossChainKind::TRON;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain: " + chain_str);

            profile.address = request.params[3].get_str();
            if (profile.address.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Address must not be empty");
            }

            // Structural address validation per chain (prefix, length, charset)
            if (chain_str == "btc") {
                const auto& a = profile.address;
                const std::string lower = [&]{
                    std::string s = a;
                    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
                    return s;
                }();
                if (lower.substr(0, 3) == "bc1" || lower.substr(0, 3) == "tb1" || lower.substr(0, 4) == "bcrt") {
                    // Bech32: check length, separator, and charset
                    auto sep = lower.rfind('1');
                    if (sep == std::string::npos || sep < 2) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC bech32: missing separator");
                    }
                    std::string data = lower.substr(sep + 1);
                    if (data.size() < 6 || a.size() > 90) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC bech32: invalid length");
                    }
                    static const std::string bech32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
                    for (char c : data) {
                        if (bech32_chars.find(c) == std::string::npos) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC bech32: invalid character '" + std::string(1, c) + "'");
                        }
                    }
                } else if (!a.empty() && (a[0] == '1' || a[0] == '3' || a[0] == 'm' || a[0] == 'n' || a[0] == '2')) {
                    // Base58Check: length 25-34, charset
                    if (a.size() < 25 || a.size() > 34) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC base58: invalid length " + std::to_string(a.size()));
                    }
                    static const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
                    for (char c : a) {
                        if (base58_chars.find(c) == std::string::npos) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC base58: invalid character '" + std::string(1, c) + "'");
                        }
                    }
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid BTC address format: " + a);
                }
            } else if (chain_str == "ethereum") {
                // ETH: 0x-prefixed, 42 chars total, hex content
                if (profile.address.size() != 42 || profile.address.substr(0, 2) != "0x") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "ETH address must be 0x-prefixed 40-char hex");
                }
                const std::string hex_part = profile.address.substr(2);
                bool has_upper = false, has_lower = false;
                for (char c : hex_part) {
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "ETH address contains non-hex character '" + std::string(1, c) + "'");
                    }
                    if (c >= 'a' && c <= 'f') has_lower = true;
                    if (c >= 'A' && c <= 'F') has_upper = true;
                }
                // EIP-55: mixed-case requires checksum validation.
                // The wallet does not have keccak256 (the bridge Rust side does).
                // Reject mixed-case here; the bridge payload validator enforces
                // full EIP-55 with real keccak on the cross-chain offer path.
                // Users should supply all-lowercase or all-uppercase addresses.
                if (has_upper && has_lower) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Mixed-case ETH addresses require EIP-55 checksum validation. "
                        "Use all-lowercase (0x prefix + lowercase hex) for settlement profiles.");
                }
            } else if (chain_str == "tron") {
                if (profile.address[0] == 'T') {
                    // TRON base58: T-prefix, 34 chars, base58 charset
                    if (profile.address.size() != 34) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "TRON base58 address must be 34 characters");
                    }
                    static const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
                    for (char c : profile.address) {
                        if (base58_chars.find(c) == std::string::npos) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "TRON base58: invalid character '" + std::string(1, c) + "'");
                        }
                    }
                } else if (profile.address.substr(0, 2) == "41" && profile.address.size() == 42) {
                    // TRON hex: 41-prefix, 42 hex chars
                    for (char c : profile.address) {
                        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "TRON hex: non-hex character '" + std::string(1, c) + "'");
                        }
                    }
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid TRON address format");
                }
            }

            profile.signer_ref = request.params[4].get_str();
            if (profile.signer_ref.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "signer_ref must not be empty");
            }
            // signer_ref must be "derived:auto" or "imported:<key-id>"
            if (profile.signer_ref.substr(0, 8) != "derived:" && profile.signer_ref.substr(0, 9) != "imported:") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "signer_ref must start with 'derived:' or 'imported:'");
            }

            profile.preferred_asset = request.params[5].get_str();
            if (profile.preferred_asset.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "preferred_asset must not be empty");
            }

            profile.fee_speed = request.params[6].isNull() ? "normal" : request.params[6].get_str();
            if (profile.fee_speed != "normal" && profile.fee_speed != "fast" && profile.fee_speed != "urgent") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_speed must be normal|fast|urgent");
            }

            bool ok = wallet_ptr->AddSettlementProfile(request.params[0].get_str(), std::move(profile));
            if (!ok) throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist settlement profile");
            return UniValue(true);
        }
    };
}

RPCHelpMan settlement_profile_remove()
{
    return RPCHelpMan{"settlement_profile.remove",
        "Remove a settlement profile.",
        {
            {"profile_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Profile identifier to remove"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "true if removed"},
        RPCExamples{HelpExampleCli("settlement_profile.remove", "\"btc-cold\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
            CWallet* const wallet_ptr = const_cast<CWallet*>(pwallet.get());

            bool ok = wallet_ptr->RemoveSettlementProfile(request.params[0].get_str());
            if (!ok) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Profile not found");
            return UniValue(true);
        }
    };
}

RPCHelpMan settlement_profile_list()
{
    return RPCHelpMan{"settlement_profile.list",
        "List all settlement profiles.",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "profile_id", "Profile identifier"},
                        {RPCResult::Type::STR, "label", "Human-readable label"},
                        {RPCResult::Type::STR, "chain", "External chain"},
                        {RPCResult::Type::STR, "address", "Settlement address"},
                        {RPCResult::Type::STR, "signer_ref", "Signing reference"},
                        {RPCResult::Type::STR, "preferred_asset", "Preferred asset"},
                        {RPCResult::Type::STR, "fee_speed", "Fee speed"},
                    }
                },
            }
        },
        RPCExamples{HelpExampleCli("settlement_profile.list", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            UniValue result(UniValue::VARR);
            for (const auto& [id, profile] : pwallet->ListSettlementProfiles()) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("profile_id", id);
                entry.pushKV("label", profile.label);
                const char* chain_str = profile.chain == CrossChainKind::BTC ? "btc"
                    : profile.chain == CrossChainKind::ETHEREUM ? "ethereum" : "tron";
                entry.pushKV("chain", std::string(chain_str));
                entry.pushKV("address", profile.address);
                entry.pushKV("signer_ref", profile.signer_ref);
                entry.pushKV("preferred_asset", profile.preferred_asset);
                entry.pushKV("fee_speed", profile.fee_speed);
                result.push_back(entry);
            }
            return result;
        }
    };
}

/// Helper: serialize a CrossChainRecord to UniValue (shared by list and get).
static UniValue CrossChainRecordToJSON(const CrossChainRecord& record)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("swap_id", record.swap_id);
    entry.pushKV("offer_id", record.offer_id);
    entry.pushKV("state", static_cast<int>(record.state));
    entry.pushKV("payload_json", record.payload_json);
    entry.pushKV("local_role", record.local_role);
    entry.pushKV("counterparty_pubkey", record.counterparty_pubkey);
    const char* chain_str = record.external_chain == CrossChainKind::BTC ? "btc"
        : record.external_chain == CrossChainKind::ETHEREUM ? "ethereum" : "tron";
    entry.pushKV("external_chain", std::string(chain_str));
    const char* adapter_str = record.adapter == CrossChainAdapter::BTC_SCRIPTLESS_V1 ? "btc_scriptless_v1"
        : record.adapter == CrossChainAdapter::ETH_HTLC_V1 ? "eth_htlc_v1" : "tron_htlc_v1";
    entry.pushKV("adapter", std::string(adapter_str));
    entry.pushKV("created_time", record.created_time);
    entry.pushKV("updated_time", record.updated_time);
    entry.pushKV("external_conf_depth", static_cast<int>(record.external_conf_depth));
    entry.pushKV("tsc_conf_depth", static_cast<int>(record.tsc_conf_depth));
    entry.pushKV("fee_escalation_level", static_cast<int>(record.fee_escalation_level));
    if (record.tsc_funding_txid) entry.pushKV("tsc_funding_txid", record.tsc_funding_txid->GetHex());
    if (record.external_funding_txid) entry.pushKV("external_funding_txid", record.external_funding_txid->GetHex());
    if (!record.adaptor_secret_ref.empty()) entry.pushKV("adaptor_secret_ref", record.adaptor_secret_ref);
    if (!record.oracle_attestation.empty()) entry.pushKV("oracle_attestation", record.oracle_attestation);
    // HTLC execution artifacts (V2 fields)
    if (!record.htlc_contract_address.empty()) entry.pushKV("htlc_contract_address", record.htlc_contract_address);
    if (!record.htlc_swap_id.empty()) entry.pushKV("htlc_swap_id", record.htlc_swap_id);
    if (!record.external_signer_ref.empty()) entry.pushKV("external_signer_ref", record.external_signer_ref);
    if (!record.claim_tx_hash.empty()) entry.pushKV("claim_tx_hash", record.claim_tx_hash);
    if (!record.refund_tx_hash.empty()) entry.pushKV("refund_tx_hash", record.refund_tx_hash);
    if (!record.external_lock_tx_hash.empty()) entry.pushKV("external_lock_tx_hash", record.external_lock_tx_hash);
    if (record.htlc_timelock > 0) entry.pushKV("htlc_timelock", record.htlc_timelock);
    return entry;
}

RPCHelpMan crosschain_list()
{
    return RPCHelpMan{"crosschain.list",
        "List cross-chain execution records (full detail).",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "swap_id", "Swap identifier"},
                        {RPCResult::Type::STR, "offer_id", "Bulletin board offer ID"},
                        {RPCResult::Type::NUM, "state", "Current state (numeric)"},
                        {RPCResult::Type::STR, "payload_json", "Full agreed payload"},
                        {RPCResult::Type::STR, "local_role", "Our role (maker/taker)"},
                        {RPCResult::Type::STR, "counterparty_pubkey", "Counterparty Nostr pubkey"},
                        {RPCResult::Type::STR, "external_chain", "External chain"},
                        {RPCResult::Type::STR, "adapter", "Adapter kind"},
                        {RPCResult::Type::NUM, "created_time", "Creation timestamp"},
                        {RPCResult::Type::NUM, "updated_time", "Last update timestamp"},
                        {RPCResult::Type::NUM, "external_conf_depth", "External chain conf depth"},
                        {RPCResult::Type::NUM, "tsc_conf_depth", "TSC conf depth"},
                        {RPCResult::Type::NUM, "fee_escalation_level", "Fee escalation level"},
                    }
                },
            }
        },
        RPCExamples{HelpExampleCli("crosschain.list", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            UniValue result(UniValue::VARR);
            for (const auto& record : pwallet->ListCrossChainRecords()) {
                result.push_back(CrossChainRecordToJSON(record));
            }
            return result;
        }
    };
}

RPCHelpMan crosschain_get()
{
    return RPCHelpMan{"crosschain.get",
        "Get a specific cross-chain execution record.",
        {
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Swap identifier"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "swap_id", "Swap identifier"},
                {RPCResult::Type::STR, "offer_id", "Bulletin board offer ID"},
                {RPCResult::Type::NUM, "state", "Current state (numeric)"},
                {RPCResult::Type::STR, "payload_json", "Full agreed payload"},
                {RPCResult::Type::STR, "local_role", "Our role"},
                {RPCResult::Type::STR, "counterparty_pubkey", "Counterparty Nostr pubkey"},
                {RPCResult::Type::STR, "external_chain", "External chain"},
            }
        },
        RPCExamples{HelpExampleCli("crosschain.get", "\"swap-uuid-1234\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            const std::string swap_id = request.params[0].get_str();
            auto record = pwallet->FindCrossChainRecord(swap_id);
            if (!record) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Cross-chain record not found: " + swap_id);

            return CrossChainRecordToJSON(*record);
        }
    };
}

RPCHelpMan crosschain_set_htlc_params()
{
    return RPCHelpMan{"crosschain.set_htlc_params",
        "Set HTLC execution parameters on a cross-chain record.\n"
        "Used by the session layer after negotiation, or manually for testnet.\n"
        "All fields are persisted via write-before-mutate.\n"
        "\nThe expected_* fields are used by v1 trusted-RPC verification to\n"
        "validate on-chain HTLC facts against negotiated terms before advancing.",
        {
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Swap identifier"},
            {"htlc_contract_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Deployed HTLC contract address (0x...)"},
            {"htlc_swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte hex swap ID used on the HTLC contract"},
            {"external_signer_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "Signer ref (raw hex key for testnet, or derived:auto)"},
            {"claim_secret", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte hex secret preimage (set when we are the claimer)"},
            {"expected_secret_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Expected sha256(secret) on the HTLC (for direct verification)"},
            {"expected_recipient", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Expected recipient address on the HTLC"},
            {"expected_amount", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Expected amount locked (hex wei)"},
            {"expected_token_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Expected ERC-20 token address (0x0...0 for native ETH)"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the params were persisted"},
        RPCExamples{HelpExampleCli("crosschain.set_htlc_params",
            "\"swap-uuid\" \"0xHTLC_ADDR\" \"0xSWAP_ID_32\" \"signing_key_hex\" \"secret_hex\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            const std::string swap_id = request.params[0].get_str();
            const std::string htlc_addr = request.params[1].get_str();
            const std::string htlc_sid = request.params[2].get_str();
            const std::string signer_ref = request.params[3].get_str();
            const std::string claim_secret = (request.params.size() > 4 && !request.params[4].isNull())
                ? request.params[4].get_str() : "";
            const std::string exp_secret_hash = (request.params.size() > 5 && !request.params[5].isNull())
                ? request.params[5].get_str() : "";
            const std::string exp_recipient = (request.params.size() > 6 && !request.params[6].isNull())
                ? request.params[6].get_str() : "";
            const std::string exp_amount = (request.params.size() > 7 && !request.params[7].isNull())
                ? request.params[7].get_str() : "";
            const std::string exp_token = (request.params.size() > 8 && !request.params[8].isNull())
                ? request.params[8].get_str() : "";

            auto record = pwallet->FindCrossChainRecord(swap_id);
            if (!record) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Cross-chain record not found: " + swap_id);

            if (!pwallet->UpdateCrossChainHtlcArtifacts(
                    swap_id, htlc_addr, htlc_sid, signer_ref, claim_secret,
                    record->claim_tx_hash, record->refund_tx_hash,
                    record->external_lock_tx_hash, record->htlc_timelock)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist HTLC params for swap " + swap_id);
            }

            // Persist expected values for direct RPC verification (v1)
            if (!exp_secret_hash.empty() || !exp_recipient.empty() ||
                !exp_amount.empty() || !exp_token.empty()) {
                if (!pwallet->UpdateCrossChainExpectedValues(
                        swap_id, exp_secret_hash, exp_recipient, exp_amount, exp_token)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist expected values for swap " + swap_id);
                }
            }

            return true;
        }
    };
}

RPCHelpMan crosschain_create_record()
{
    return RPCHelpMan{"crosschain.create_record",
        "Create a cross-chain execution record for testnet.\n"
        "In production, records are created by the session layer after offer acceptance.\n"
        "This RPC allows manual record creation for testing the swap manager.",
        {
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Unique swap identifier"},
            {"offer_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Bulletin board offer ID"},
            {"external_chain", RPCArg::Type::STR, RPCArg::Optional::NO, "Chain: btc|ethereum|tron"},
            {"adapter", RPCArg::Type::STR, RPCArg::Optional::NO, "Adapter: btc_scriptless_v1|eth_htlc_v1|tron_htlc_v1"},
            {"funding_order", RPCArg::Type::STR, RPCArg::Optional::NO, "Funding order: tsc_first|external_first"},
            {"local_role", RPCArg::Type::STR, RPCArg::Optional::NO, "Our role: maker|taker"},
            {"payload_json", RPCArg::Type::STR, RPCArg::Optional::NO, "Full cross_chain_spot_v1 payload JSON"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "swap_id", "Created swap ID"},
            {RPCResult::Type::NUM, "state", "Initial state (5 = FUNDING_PREPARED)"},
        }},
        RPCExamples{HelpExampleCli("crosschain.create_record",
            "\"swap-1\" \"offer-1\" \"ethereum\" \"eth_htlc_v1\" \"external_first\" \"taker\" \"{...}\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            CrossChainRecord record;
            record.swap_id = request.params[0].get_str();
            record.offer_id = request.params[1].get_str();

            const std::string chain_str = request.params[2].get_str();
            if (chain_str == "btc") record.external_chain = CrossChainKind::BTC;
            else if (chain_str == "ethereum") record.external_chain = CrossChainKind::ETHEREUM;
            else if (chain_str == "tron") record.external_chain = CrossChainKind::TRON;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain: " + chain_str);

            const std::string adapter_str = request.params[3].get_str();
            if (adapter_str == "btc_scriptless_v1") record.adapter = CrossChainAdapter::BTC_SCRIPTLESS_V1;
            else if (adapter_str == "eth_htlc_v1") record.adapter = CrossChainAdapter::ETH_HTLC_V1;
            else if (adapter_str == "tron_htlc_v1") record.adapter = CrossChainAdapter::TRON_HTLC_V1;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid adapter: " + adapter_str);

            const std::string order_str = request.params[4].get_str();
            if (order_str == "tsc_first") record.funding_order = CrossChainFundingOrder::TSC_FIRST;
            else if (order_str == "external_first") record.funding_order = CrossChainFundingOrder::EXTERNAL_FIRST;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid funding_order: " + order_str);

            record.local_role = request.params[5].get_str();
            record.payload_json = request.params[6].get_str();

            // Start at FUNDING_PREPARED — ready for the manager to detect counterparty lock
            record.state = CrossChainState::FUNDING_PREPARED;
            record.created_time = GetTime();
            record.updated_time = GetTime();

            pwallet->RegisterCrossChainRecord(record);

            // NOTE: Do NOT auto-register with the swap manager here.
            // The caller must explicitly call crosschain.register_swap after
            // confirming that session messages were delivered successfully.
            // This prevents one-sided registrations where the peer never
            // received the protocol message.

            UniValue result(UniValue::VOBJ);
            result.pushKV("swap_id", record.swap_id);
            result.pushKV("state", static_cast<int>(record.state));
            return result;
        }
    };
}

RPCHelpMan crosschain_set_oracle_attestation()
{
    return RPCHelpMan{"crosschain.set_oracle_attestation",
        "Persist a verified oracle attestation for a cross-chain swap.\n"
        "Called by the session/watcher layer after obtaining and verifying\n"
        "the attestation via cosign.eth_verify_attestation.",
        {
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Swap identifier"},
            {"attestation_json", RPCArg::Type::STR, RPCArg::Optional::NO, "Full attestation JSON (already verified)"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the attestation was persisted"},
        RPCExamples{HelpExampleCli("crosschain.set_oracle_attestation",
            "\"swap-uuid\" \"{...}\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            const std::string swap_id = request.params[0].get_str();
            const std::string attestation_json = request.params[1].get_str();

            if (!pwallet->UpdateCrossChainOracleAttestation(swap_id, attestation_json)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist oracle attestation for swap " + swap_id);
            }

            return true;
        }
    };
}

RPCHelpMan crosschain_register_swap()
{
    return RPCHelpMan{"crosschain.register_swap",
        "Register an existing cross-chain record with the swap manager.\n"
        "The record must already exist (via crosschain.create_record).\n"
        "The manager will begin monitoring this swap in its background loop.",
        {
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Swap identifier"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the swap was registered"},
        RPCExamples{HelpExampleCli("crosschain.register_swap", "\"swap-uuid\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            const std::string swap_id = request.params[0].get_str();

            auto record = pwallet->FindCrossChainRecord(swap_id);
            if (!record) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Cross-chain record not found: " + swap_id);

            auto& manager = pwallet->GetOrCreateSwapManager();
            if (!manager.RegisterSwap(swap_id)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to register swap " + swap_id + " with manager");
            }

            return true;
        }
    };
}

RPCHelpMan crosschain_set_session_addresses()
{
    return RPCHelpMan{"crosschain.set_session_addresses",
        "Persist session-negotiated TSC and external addresses on a cross-chain record.",
        {
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Swap identifier"},
            {"taker_tsc_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Taker's TSC address"},
            {"taker_refund_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Taker's external refund address"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the addresses were persisted"},
        RPCExamples{HelpExampleCli("crosschain.set_session_addresses",
            "\"swap-uuid\" \"tsc1q...\" \"0xTakerETH\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            if (!pwallet->UpdateCrossChainSessionAddresses(
                    request.params[0].get_str(),
                    request.params[1].get_str(),
                    request.params[2].get_str())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist session addresses");
            }
            return true;
        }
    };
}

RPCHelpMan crosschain_start_manager()
{
    return RPCHelpMan{"crosschain.start_manager",
        "Start the cross-chain swap manager with an ETH HTLC backend.\n"
        "\nv1 uses trusted-RPC mode: the wallet verifies HTLC state directly\n"
        "against the configured ETH provider(s). If a secondary RPC URL is\n"
        "provided, critical state transitions require both providers to agree\n"
        "on on-chain facts before advancing.\n"
        "\nOracle mode (phase 3) is available by providing an oracle_pubkey,\n"
        "but is not required for v1 operation.",
        {
            {"eth_rpc_url", RPCArg::Type::STR, RPCArg::Optional::NO,
                "Primary Ethereum JSON-RPC endpoint URL (e.g. Infura, Alchemy, local node)"},
            {"eth_rpc_url_secondary", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                "Secondary ETH RPC endpoint for dual-provider verification"},
            {"oracle_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                "Oracle x-only pubkey (32-byte hex) — only needed for oracle mode (phase 3)"},
            {"eth_derivation_seed", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                "32-byte hex seed for derived:auto ETH key derivation. "
                "If omitted, derived:auto signer refs will not work (raw hex keys only)."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "Whether the manager started"},
            {RPCResult::Type::NUM, "active_swaps", "Number of active swaps loaded"},
            {RPCResult::Type::STR, "mode", "Verification mode: trusted_rpc or oracle"},
            {RPCResult::Type::BOOL, "dual_provider", "Whether dual-provider mode is active"},
        }},
        RPCExamples{
            HelpExampleCli("crosschain.start_manager",
                "\"https://mainnet.infura.io/v3/KEY\"") +
            HelpExampleCli("crosschain.start_manager",
                "\"https://mainnet.infura.io/v3/KEY\" \"https://eth-mainnet.g.alchemy.com/v2/KEY\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

            const std::string eth_rpc_url = request.params[0].get_str();
            const std::string eth_rpc_url_secondary =
                (request.params.size() > 1 && !request.params[1].isNull())
                    ? request.params[1].get_str() : "";
            const std::string oracle_pubkey =
                (request.params.size() > 2 && !request.params[2].isNull())
                    ? request.params[2].get_str() : "";
            const std::string eth_derivation_seed =
                (request.params.size() > 3 && !request.params[3].isNull())
                    ? request.params[3].get_str() : "";

            if (!IsCosignBridgeEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");

            // Initialize primary ETH RPC in the bridge
            {
                UniValue p(UniValue::VOBJ);
                p.pushKV("rpc_url", eth_rpc_url);
                if (!eth_derivation_seed.empty()) {
                    p.pushKV("derivation_seed", eth_derivation_seed);
                }
                UniValue resp = SendCosignBridgeCommand("eth_init", p);
                if (!resp.exists("success") || !resp["success"].get_bool())
                    throw JSONRPCError(RPC_MISC_ERROR, "eth_init failed for primary RPC");
            }

            // Create primary ETH HTLC backend
            auto eth_backend = std::make_shared<EthHtlcBackend>(
                [](const std::string& cmd, const UniValue& params) -> UniValue {
                    return SendCosignBridgeCommand(cmd, params);
                });

            auto& manager = pwallet->GetOrCreateSwapManager();
            manager.RegisterHtlcBackend(CrossChainKind::ETHEREUM, eth_backend);

            // Optional: secondary provider for dual-provider verification
            bool dual_provider = false;
            if (!eth_rpc_url_secondary.empty()) {
                // Initialize secondary RPC in the bridge (uses eth_init_secondary)
                UniValue p2(UniValue::VOBJ);
                p2.pushKV("rpc_url", eth_rpc_url_secondary);
                UniValue resp2 = SendCosignBridgeCommand("eth_init_secondary", p2);
                if (resp2.exists("success") && resp2["success"].get_bool()) {
                    auto eth_backend_secondary = std::make_shared<EthHtlcBackend>(
                        [](const std::string& cmd, const UniValue& params) -> UniValue {
                            // Secondary backend prefixes commands with "secondary_"
                            return SendCosignBridgeCommand("secondary_" + cmd, params);
                        });
                    manager.RegisterSecondaryHtlcBackend(CrossChainKind::ETHEREUM, eth_backend_secondary);
                    dual_provider = true;
                    LogPrintf("crosschain.start_manager: Dual-provider mode enabled\n");
                } else {
                    LogPrintf("crosschain.start_manager: WARNING — secondary RPC init failed, "
                              "proceeding with single provider\n");
                }
            }

            // Optional: oracle mode (phase 3)
            std::string mode = "trusted_rpc";
            if (!oracle_pubkey.empty()) {
                manager.SetOraclePubkey(oracle_pubkey);
                mode = "oracle";
            }

            manager.Start();
            auto active_ids = manager.GetActiveSwapIds();

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", true);
            result.pushKV("active_swaps", static_cast<int>(active_ids.size()));
            result.pushKV("mode", mode);
            result.pushKV("dual_provider", dual_provider);
            return result;
        }
    };
}

} // namespace wallet
