// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/contract.h>
#include <wallet/wallet.h>

#include <assets/asset.h>
#include <key_io.h>
#include <script/solver.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <hash.h>

#include <cassert>
#include <cstring>

namespace wallet {

static std::string ScriptHex(const CTxDestination& dest)
{
    const CScript spk = GetScriptForDestination(dest);
    return HexStr(spk);
}

static UniValue AssetLegToJSON(const AssetLeg& leg)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("is_native", leg.is_native);
    obj.pushKV("units", UniValue(static_cast<int64_t>(leg.units)));
    if (!leg.is_native) {
        obj.pushKV("asset_id", leg.asset_id.GetHex());
    }
    return obj;
}

UniValue SpotTermsToJSON(const SpotTerms& terms)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("alice_leg", AssetLegToJSON(terms.alice_deliver));
    obj.pushKV("bob_leg", AssetLegToJSON(terms.bob_deliver));
    // Only include flag when true to keep JSON compact and backwards compatible.
    if (terms.require_commitment_proof) {
        obj.pushKV("require_commitment_proof", true);
    }
    return obj;
}

uint256 ComputeAssetDeliveryCommitment(bool is_native,
                                       const uint256& asset_id,
                                       uint64_t units,
                                       const CScript& script_pubkey,
                                       const std::vector<unsigned char>& vext)
{
    CSHA256 hasher;
    uint8_t native_flag = is_native ? 1 : 0;
    hasher.Write(&native_flag, sizeof(native_flag));

    hasher.Write(asset_id.begin(), asset_id.size());

    unsigned char units_le[sizeof(uint64_t)];
    WriteLE64(units_le, units);
    hasher.Write(units_le, sizeof(units_le));

    hasher.Write(script_pubkey.data(), script_pubkey.size());
    if (!vext.empty()) {
        hasher.Write(vext.data(), vext.size());
    }

    uint256 result;
    hasher.Finalize(result.begin());
    return result;
}

uint256 ComputeAssetDeliveryCommitment(const AssetDeliveryTemplate& tmpl)
{
    return ComputeAssetDeliveryCommitment(
        tmpl.is_native,
        tmpl.asset_id,
        tmpl.units,
        tmpl.script_pubkey,
        tmpl.vext);
}

UniValue RepoOfferCanonicalJson(const RepoOfferRecord& record, const CTxDestination& repay_dest)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", 1);
    obj.pushKV("contract_type", "repo");
    obj.pushKV("id", record.offer_id.GetHex());
    obj.pushKV("terms", RepoTermsToJSON(record.terms));

    UniValue sinks(UniValue::VOBJ);
    sinks.pushKV("collateral_spk", ScriptHex(record.borrower_dest));
    sinks.pushKV("repay_spk", ScriptHex(repay_dest));
    obj.pushKV("sinks", std::move(sinks));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("require_adaptor", record.fs_policy.require_adaptor);
    policy.pushKV("reveal_lockstep", record.fs_policy.reveal_lockstep);
    obj.pushKV("fs_policy", std::move(policy));

    obj.pushKV("fs_tx_adaptor_point", HexStr(record.fs_tx_adaptor_point));
    return obj;
}

UniValue RepoAcceptanceCanonicalJson(const RepoOfferRecord& offer,
                                     const RepoAcceptanceRecord& acceptance)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", 1);
    obj.pushKV("contract_type", "repo");
    obj.pushKV("offer_id", offer.offer_id.GetHex());
    obj.pushKV("id", acceptance.acceptance_id.GetHex());

    UniValue sinks(UniValue::VOBJ);
    sinks.pushKV("repay_spk", ScriptHex(acceptance.repay_dest_ack));
    obj.pushKV("sinks_ack", std::move(sinks));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("require_adaptor", acceptance.fs_policy.require_adaptor);
    policy.pushKV("reveal_lockstep", acceptance.fs_policy.reveal_lockstep);
    obj.pushKV("fs_policy_ack", std::move(policy));

    obj.pushKV("fs_tx_adaptor_point", HexStr(acceptance.fs_tx_adaptor_point));

    const auto template_to_json = [](const AssetDeliveryTemplate& tmpl, const std::string& purpose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("purpose", purpose);
        entry.pushKV("is_native", tmpl.is_native);
        entry.pushKV("units", UniValue(static_cast<int64_t>(tmpl.units)));
        entry.pushKV("script_pubkey", HexStr(tmpl.script_pubkey));
        entry.pushKV("commitment", tmpl.commitment.GetHex());
        if (!tmpl.is_native) {
            entry.pushKV("asset_id", tmpl.asset_id.GetHex());
            entry.pushKV("vext", HexStr(tmpl.vext));
        }
        return entry;
    };

    if (acceptance.repay_principal_template || acceptance.repay_interest_template) {
        UniValue templates(UniValue::VARR);
        const bool merged = acceptance.repay_principal_template && !acceptance.repay_interest_template;
        if (acceptance.repay_principal_template) {
            templates.push_back(template_to_json(*acceptance.repay_principal_template, merged ? "repay_merged" : "repay_principal"));
        }
        if (acceptance.repay_interest_template) {
            templates.push_back(template_to_json(*acceptance.repay_interest_template, "repay_interest"));
        }
        obj.pushKV("repay_templates", std::move(templates));
    }

    if (acceptance.default_collateral_template) {
        UniValue collateral = template_to_json(*acceptance.default_collateral_template, "default_collateral");
        obj.pushKV("default_collateral_template", std::move(collateral));
    }

    return obj;
}

UniValue SpotOfferCanonicalJson(const SpotOfferRecord& record)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", 1);
    obj.pushKV("contract_type", "spot");
    obj.pushKV("id", record.offer_id.GetHex());
    obj.pushKV("terms", SpotTermsToJSON(record.terms));

    UniValue sinks(UniValue::VOBJ);
    sinks.pushKV("alice_recv_spk", ScriptHex(record.alice_recv_dest));
    if (record.bob_recv_dest_hint) {
        sinks.pushKV("bob_recv_spk", ScriptHex(*record.bob_recv_dest_hint));
    }
    obj.pushKV("sinks", std::move(sinks));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("require_adaptor", record.fs_policy.require_adaptor);
    policy.pushKV("reveal_lockstep", record.fs_policy.reveal_lockstep);
    obj.pushKV("fs_policy", std::move(policy));

    obj.pushKV("fs_tx_adaptor_point", HexStr(record.fs_tx_adaptor_point));
    return obj;
}

UniValue SpotAcceptanceCanonicalJson(const SpotOfferRecord& offer,
                                     const SpotAcceptanceRecord& acceptance)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", 1);
    obj.pushKV("contract_type", "spot");
    obj.pushKV("offer_id", offer.offer_id.GetHex());
    obj.pushKV("id", acceptance.acceptance_id.GetHex());

    UniValue sinks(UniValue::VOBJ);
    sinks.pushKV("bob_recv_spk", ScriptHex(acceptance.bob_recv_dest));
    obj.pushKV("sinks_ack", std::move(sinks));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("require_adaptor", acceptance.fs_policy.require_adaptor);
    policy.pushKV("reveal_lockstep", acceptance.fs_policy.reveal_lockstep);
    obj.pushKV("fs_policy_ack", std::move(policy));

    obj.pushKV("fs_tx_adaptor_point", HexStr(acceptance.fs_tx_adaptor_point));
    return obj;
}

std::pair<uint256, XOnlyPubKey> GenerateFairSignAdaptor()
{
    CKey secret;
    secret.MakeNewKey(/* fCompressed = */ true);

    CPubKey pub = secret.GetPubKey();
    XOnlyPubKey xonly(pub);

    uint256 scalar;
    static_assert(sizeof(uint256) == 32, "uint256 size must be 32 bytes");
    assert(secret.size() == 32 && "CKey keydata must be 32 bytes");
    std::memcpy(scalar.data(), secret.data(), 32);
    return {scalar, xonly};
}

uint256 ComputeRepoOfferCommitment(const RepoOfferRecord& record,
                                   const CTxDestination& repay_dest)
{
    UniValue canonical = RepoOfferCanonicalJson(record, repay_dest);
    std::string canon_str = canonical.write();

    uint256 result;
    CSHA256 hasher;
    hasher.Write(record.salt.begin(), record.salt.size());
    hasher.Write(UCharCast(canon_str.data()), canon_str.size());
    hasher.Finalize(result.begin());
    return result;
}

std::string RepoOfferCommitmentHex(const RepoOfferRecord& record,
                                   const CTxDestination& repay_dest)
{
    return ComputeRepoOfferCommitment(record, repay_dest).GetHex();
}

uint256 ComputeRepoAcceptanceCommitment(const RepoOfferRecord& offer,
                                        const RepoAcceptanceRecord& acceptance)
{
    UniValue canonical = RepoAcceptanceCanonicalJson(offer, acceptance);
    std::string canon_str = canonical.write();

    auto offer_commitment_opt = uint256::FromHex(offer.commitment_hex);
    if (!offer_commitment_opt) {
        throw std::runtime_error("Invalid offer commitment hex");
    }
    uint256 offer_commitment = *offer_commitment_opt;

    uint256 result;
    CSHA256 hasher;
    hasher.Write(acceptance.salt.begin(), acceptance.salt.size());
    hasher.Write(offer_commitment.begin(), offer_commitment.size());
    hasher.Write(UCharCast(canon_str.data()), canon_str.size());
    hasher.Finalize(result.begin());
    return result;
}

std::string RepoAcceptanceCommitmentHex(const RepoOfferRecord& offer,
                                        const RepoAcceptanceRecord& acceptance)
{
    return ComputeRepoAcceptanceCommitment(offer, acceptance).GetHex();
}

uint256 ComputeRepoContractMeta(const RepoOfferRecord& record,
                                const CTxDestination& repay_dest)
{
    CSHA256 hasher;
    std::string offer_json = RepoOfferCanonicalJson(record, repay_dest).write();
    hasher.Write(UCharCast(offer_json.data()), offer_json.size());
    if (record.acceptance) {
        std::string acceptance_json = RepoAcceptanceCanonicalJson(record, *record.acceptance).write();
        hasher.Write(UCharCast(acceptance_json.data()), acceptance_json.size());
    }
    uint256 meta;
    hasher.Finalize(meta.begin());
    return meta;
}

uint256 ComputeSpotOfferCommitment(const SpotOfferRecord& record)
{
    UniValue canonical = SpotOfferCanonicalJson(record);
    std::string canon_str = canonical.write();

    uint256 result;
    CSHA256 hasher;
    hasher.Write(record.salt.begin(), record.salt.size());
    hasher.Write(UCharCast(canon_str.data()), canon_str.size());
    hasher.Finalize(result.begin());
    return result;
}

std::string SpotOfferCommitmentHex(const SpotOfferRecord& record)
{
    return ComputeSpotOfferCommitment(record).GetHex();
}

uint256 ComputeSpotAcceptanceCommitment(const SpotOfferRecord& offer,
                                        const SpotAcceptanceRecord& acceptance)
{
    UniValue canonical = SpotAcceptanceCanonicalJson(offer, acceptance);
    std::string canon_str = canonical.write();

    auto offer_commitment_opt = uint256::FromHex(offer.commitment_hex);
    if (!offer_commitment_opt) {
        throw std::runtime_error("Invalid spot offer commitment hex");
    }
    const uint256 offer_commitment = *offer_commitment_opt;

    uint256 result;
    CSHA256 hasher;
    hasher.Write(acceptance.salt.begin(), acceptance.salt.size());
    hasher.Write(offer_commitment.begin(), offer_commitment.size());
    hasher.Write(UCharCast(canon_str.data()), canon_str.size());
    hasher.Finalize(result.begin());
    return result;
}

std::string SpotAcceptanceCommitmentHex(const SpotOfferRecord& offer,
                                        const SpotAcceptanceRecord& acceptance)
{
    return ComputeSpotAcceptanceCommitment(offer, acceptance).GetHex();
}

uint256 ComputeSpotContractMeta(const SpotOfferRecord& offer,
                                const SpotAcceptanceRecord* acceptance)
{
    CSHA256 hasher;
    std::string offer_json = SpotOfferCanonicalJson(offer).write();
    hasher.Write(UCharCast(offer_json.data()), offer_json.size());
    if (acceptance) {
        std::string acceptance_json = SpotAcceptanceCanonicalJson(offer, *acceptance).write();
        hasher.Write(UCharCast(acceptance_json.data()), acceptance_json.size());
    }
    uint256 meta;
    hasher.Finalize(meta.begin());
    return meta;
}

UniValue SpotOfferToJSON(const SpotOfferRecord& record)
{
    UniValue obj = SpotOfferCanonicalJson(record);
    obj.pushKV("salt", record.salt.GetHex());
    obj.pushKV("commitment", record.commitment_hex);
    obj.pushKV("created_height", record.created_height);
    obj.pushKV("created_time", record.created_time);
    obj.pushKV("alice_address", EncodeDestination(record.alice_recv_dest));
    if (record.bob_recv_dest_hint) {
        obj.pushKV("bob_address_hint", EncodeDestination(*record.bob_recv_dest_hint));
    }
    if (record.acceptance) {
        obj.pushKV("acceptance", SpotAcceptanceToJSON(record, *record.acceptance));
    }
    return obj;
}

UniValue SpotAcceptanceToJSON(const SpotOfferRecord& offer,
                              const SpotAcceptanceRecord& acceptance)
{
    UniValue obj = SpotAcceptanceCanonicalJson(offer, acceptance);
    obj.pushKV("salt", acceptance.salt.GetHex());
    obj.pushKV("commitment", acceptance.commitment_hex);
    return obj;
}

uint256 ComputeForwardOfferCommitment(const ForwardTerms& terms,
                                      ForwardSide proposer_side,
                                      const uint256& salt)
{
    DataStream ss;
    ss << salt;
    ss << static_cast<uint8_t>(proposer_side);

    const auto encode_leg = [&ss](const AssetLeg& leg) {
        ss << leg.asset_id;
        ss << leg.is_native;
        ss << leg.units;
    };

    encode_leg(terms.long_party.deliver_leg);
    encode_leg(terms.short_party.deliver_leg);
    encode_leg(terms.long_party.margin_leg);
    encode_leg(terms.short_party.margin_leg);

    ss << EncodeDestination(terms.long_party.margin_dest);
    ss << EncodeDestination(terms.short_party.margin_dest);
    ss << EncodeDestination(terms.long_party.settlement_receive_dest);
    ss << EncodeDestination(terms.short_party.settlement_receive_dest);

    ss << terms.deadline_short;
    ss << terms.deadline_long;

    // Premium leg
    encode_leg(terms.premium_leg);
    if (terms.premium_leg.units > 0) {
        ss << EncodeDestination(terms.premium_dest);
    }

    ss << terms.safety_k;
    ss << terms.reorg_conf;

    uint256 result;
    CSHA256().Write(UCharCast(ss.data()), ss.size()).Finalize(result.begin());
    return result;
}

std::string ForwardOfferCommitmentHex(const ForwardTerms& terms,
                                      ForwardSide proposer_side,
                                      const uint256& salt)
{
    return ComputeForwardOfferCommitment(terms, proposer_side, salt).GetHex();
}

std::optional<XOnlyPubKey> ExtractTaprootKey(const CTxDestination& dest)
{
    if (const auto* tap = std::get_if<WitnessV1Taproot>(&dest)) {
        return static_cast<const XOnlyPubKey&>(*tap);
    }
    if (const auto* unknown = std::get_if<WitnessUnknown>(&dest)) {
        if (unknown->GetWitnessVersion() == 1 && unknown->GetWitnessProgram().size() == 32) {
            return XOnlyPubKey(std::span<const unsigned char>{unknown->GetWitnessProgram()});
        }
    }
    return std::nullopt;
}

std::vector<unsigned char> EncodeLE64(uint64_t value)
{
    std::vector<unsigned char> out(sizeof(uint64_t));
    WriteLE64(out.data(), value);
    return out;
}

std::vector<unsigned char> BuildAssetTagTlv(const uint256& asset_id, uint64_t units)
{
    // Forwards to assets::BuildAssetTagTlv (moved to bitcoin_common so non-wallet code can build the
    // tag). Kept as a wallet:: alias so existing call sites are unchanged.
    return assets::BuildAssetTagTlv(asset_id, units);
}

uint256 ComputeForwardContractMeta(const ForwardContractRecord& record)
{
    CSHA256 hasher;
    // Hash offer commitment
    auto commitment_opt = uint256::FromHex(record.commitment_hex);
    if (!commitment_opt) {
        throw std::runtime_error("Invalid forward offer commitment hex");
    }
    hasher.Write(commitment_opt->begin(), commitment_opt->size());

    // Include acceptance commitment if present
    if (record.acceptance_commitment_hex) {
        auto acceptance_commitment_opt = uint256::FromHex(*record.acceptance_commitment_hex);
        if (!acceptance_commitment_opt) {
            throw std::runtime_error("Invalid forward acceptance commitment hex");
        }
        hasher.Write(acceptance_commitment_opt->begin(), acceptance_commitment_opt->size());
    }

    uint256 meta;
    hasher.Finalize(meta.begin());
    return meta;
}

uint256 ComputeForwardAcceptanceCommitment(const ForwardContractRecord& offer,
                                           const XOnlyPubKey& counterparty_adaptor_point,
                                           const uint256& acceptance_salt)
{
    auto offer_commitment_opt = uint256::FromHex(offer.commitment_hex);
    if (!offer_commitment_opt) {
        throw std::runtime_error("Invalid forward offer commitment hex");
    }
    uint256 offer_commitment = *offer_commitment_opt;

    uint256 result;
    CSHA256 hasher;
    hasher.Write(acceptance_salt.begin(), acceptance_salt.size());
    hasher.Write(offer_commitment.begin(), offer_commitment.size());
    hasher.Write(counterparty_adaptor_point.begin(), counterparty_adaptor_point.size());
    hasher.Finalize(result.begin());
    return result;
}

std::string ForwardAcceptanceCommitmentHex(const ForwardContractRecord& offer,
                                           const XOnlyPubKey& counterparty_adaptor_point,
                                           const uint256& acceptance_salt)
{
    return ComputeForwardAcceptanceCommitment(offer, counterparty_adaptor_point, acceptance_salt).GetHex();
}

RepoContractState RepoOfferRecord::DerivedState(const CWallet* wallet) const
{
    if (default_txid.has_value()) {
        return RepoContractState::DEFAULTED;
    }
    if (repay_txid.has_value()) {
        return RepoContractState::REPAID;
    }
    if (acceptance.has_value()) {
        if (vault_outpoint.has_value()) {
            // Only consider "opened" if vault transaction is actually in wallet/mempool/chain
            if (wallet) {
                LOCK(wallet->cs_wallet);
                const auto* wtx = wallet->GetWalletTx(vault_outpoint->hash);
                // If transaction exists and is in mempool or confirmed, it's opened
                // If transaction doesn't exist or is only in wallet (not broadcast), stay in "accepted"
                if (wtx && (wtx->InMempool() || wtx->isConfirmed())) {
                    return RepoContractState::OPENED;
                }
            } else {
                // Fallback if wallet not provided (shouldn't happen in practice)
                return RepoContractState::OPENED;
            }
        }
        return RepoContractState::ACCEPTED;
    }
    return RepoContractState::PROPOSED;
}

// ---------------------------------------------------------------------------
// Cross-chain state transition validation
// ---------------------------------------------------------------------------

bool IsValidCrossChainTransition(CrossChainState from, CrossChainState to)
{
    using S = CrossChainState;

    switch (from) {
    // Pre-funding: safe to abort outright
    case S::DRAFT:                      return to == S::POSTED || to == S::ABORTED;
    case S::POSTED:                     return to == S::MATCHED || to == S::ABORTED;
    case S::MATCHED:                    return to == S::SESSION_ESTABLISHED || to == S::ABORTED;
    case S::SESSION_ESTABLISHED:        return to == S::TERMS_FINALIZED || to == S::ABORTED;
    case S::TERMS_FINALIZED:            return to == S::FUNDING_PREPARED || to == S::ABORTED;
    case S::FUNDING_PREPARED:           return to == S::COUNTERPARTY_LOCK_SEEN || to == S::LOCAL_LOCK_CONFIRMED || to == S::ABORTED;

    // Counterparty-only funded: we haven't funded, safe to abort
    case S::COUNTERPARTY_LOCK_SEEN:     return to == S::COUNTERPARTY_LOCK_CONFIRMED || to == S::ABORTED;
    case S::COUNTERPARTY_LOCK_CONFIRMED: return to == S::LOCAL_LOCK_CONFIRMED || to == S::CLAIM_READY || to == S::REFUND_READY || to == S::ABORTED;

    // We-funded: must go through refund path, no direct Aborted
    case S::LOCAL_LOCK_CONFIRMED:       return to == S::COUNTERPARTY_LOCK_SEEN || to == S::CLAIM_READY || to == S::REFUND_READY;
    case S::CLAIM_READY:                return to == S::CLAIM_BROADCAST || to == S::REFUND_READY;

    // Secret revealed: no abort, no refund — only forward or emergency
    case S::CLAIM_BROADCAST:            return to == S::CLAIM_CONFIRMED || to == S::EMERGENCY_CLAIM || to == S::COMPLETED;
    case S::EMERGENCY_CLAIM:            return to == S::CLAIM_CONFIRMED || to == S::COMPLETED;
    case S::CLAIM_CONFIRMED:            return to == S::COMPLETED;

    // Refund path: must complete through Refunded
    case S::REFUND_READY:               return to == S::REFUND_BROADCAST;
    case S::REFUND_BROADCAST:           return to == S::REFUNDED;

    // Terminal states — no successors
    case S::REFUNDED:
    case S::COMPLETED:
    case S::ABORTED:
        return false;
    }
    return false; // unknown state
}

} // namespace wallet
