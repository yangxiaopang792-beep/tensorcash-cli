// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/ethhtlcbackend.h>
#include <logging.h>

namespace wallet {

EthHtlcBackend::EthHtlcBackend(BridgeCommandFn bridge_fn)
    : m_bridge_fn(std::move(bridge_fn))
{
}

bool EthHtlcBackend::Init(const std::string& rpc_url)
{
    try {
        UniValue params(UniValue::VOBJ);
        params.pushKV("rpc_url", rpc_url);
        UniValue response = m_bridge_fn("eth_init", params);
        m_initialized = response.exists("success") && response["success"].get_bool();
        if (m_initialized) {
            LogPrintf("EthHtlcBackend: Initialized with RPC URL %s\n", rpc_url);
        }
        return m_initialized;
    } catch (const std::exception& e) {
        LogPrintf("EthHtlcBackend: Init failed: %s\n", e.what());
        return false;
    }
}

HtlcBackend::HtlcStatus EthHtlcBackend::GetSwapStatus(
    const std::string& htlc_address,
    const std::string& swap_id,
    const std::string& lock_tx_hash)
{
    HtlcStatus status;
    try {
        UniValue params(UniValue::VOBJ);
        params.pushKV("htlc_address", htlc_address);
        params.pushKV("swap_id", swap_id);
        if (!lock_tx_hash.empty()) {
            params.pushKV("lock_tx_hash", lock_tx_hash);
        }

        UniValue response = m_bridge_fn("eth_get_swap_status", params);
        if (!response.exists("success") || !response["success"].get_bool()) {
            return status;
        }

        if (response.exists("state")) status.state = response["state"].getInt<int>();
        if (response.exists("state_name")) status.state_name = response["state_name"].get_str();
        if (response.exists("sender")) status.sender = response["sender"].get_str();
        if (response.exists("recipient")) status.recipient = response["recipient"].get_str();
        if (response.exists("token_address")) status.token_address = response["token_address"].get_str();
        if (response.exists("amount")) status.amount = response["amount"].get_str();
        if (response.exists("secret_hash")) status.secret_hash = response["secret_hash"].get_str();
        if (response.exists("timelock")) status.timelock = response["timelock"].getInt<int64_t>();
        if (response.exists("confirmation_depth") && !response["confirmation_depth"].isNull()) {
            status.confirmation_depth = response["confirmation_depth"].getInt<int64_t>();
        }
        if (response.exists("lock_tx_hash") && !response["lock_tx_hash"].isNull()) {
            status.lock_tx_hash = response["lock_tx_hash"].get_str();
        }

    } catch (const std::exception& e) {
        LogPrintf("EthHtlcBackend: GetSwapStatus failed for %s: %s\n",
                  swap_id, e.what());
    }
    return status;
}

HtlcBackend::HtlcTxResult EthHtlcBackend::LockHTLC(
    const std::string& htlc_address,
    const std::string& swap_id,
    const std::string& recipient,
    const std::string& secret_hash,
    int64_t timelock,
    const std::string& amount_wei,
    const std::string& signing_key,
    const std::string& token_address,
    int64_t gas_limit,
    int64_t max_fee_gwei,
    int64_t max_priority_fee_gwei)
{
    HtlcTxResult result;
    try {
        UniValue params(UniValue::VOBJ);
        params.pushKV("htlc_address", htlc_address);
        params.pushKV("swap_id", swap_id);
        params.pushKV("recipient", recipient);
        params.pushKV("secret_hash", secret_hash);
        params.pushKV("timelock", timelock);
        params.pushKV("amount_wei", amount_wei);
        params.pushKV("signing_key", signing_key);
        if (!token_address.empty()) {
            params.pushKV("token_address", token_address);
        }
        params.pushKV("gas_limit", gas_limit);
        params.pushKV("max_fee_gwei", max_fee_gwei);
        params.pushKV("max_priority_fee_gwei", max_priority_fee_gwei);

        UniValue response = m_bridge_fn("eth_lock_htlc", params);
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("tx_hash")) result.tx_hash = response["tx_hash"].get_str();
        if (response.exists("from")) result.from_address = response["from"].get_str();

    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? e["message"].get_str() : e.write();
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

HtlcBackend::HtlcTxResult EthHtlcBackend::ClaimHTLC(
    const std::string& htlc_address,
    const std::string& swap_id,
    const std::string& secret,
    const std::string& signing_key,
    int64_t gas_limit,
    int64_t max_fee_gwei,
    int64_t max_priority_fee_gwei)
{
    HtlcTxResult result;

    // Resolve signer ref to raw key
    std::string resolved_key = ResolveSignerRef(signing_key);
    if (resolved_key.empty()) {
        result.error = "Failed to resolve signer_ref: " + signing_key;
        return result;
    }

    try {
        UniValue params(UniValue::VOBJ);
        params.pushKV("htlc_address", htlc_address);
        params.pushKV("swap_id", swap_id);
        params.pushKV("secret", secret);
        params.pushKV("signing_key", resolved_key);
        params.pushKV("gas_limit", gas_limit);
        params.pushKV("max_fee_gwei", max_fee_gwei);
        params.pushKV("max_priority_fee_gwei", max_priority_fee_gwei);

        UniValue response = m_bridge_fn("eth_claim_htlc", params);
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("tx_hash")) result.tx_hash = response["tx_hash"].get_str();
        if (response.exists("from")) result.from_address = response["from"].get_str();

    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? e["message"].get_str() : e.write();
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

HtlcBackend::HtlcTxResult EthHtlcBackend::RefundHTLC(
    const std::string& htlc_address,
    const std::string& swap_id,
    const std::string& signing_key,
    int64_t gas_limit,
    int64_t max_fee_gwei,
    int64_t max_priority_fee_gwei)
{
    HtlcTxResult result;

    std::string resolved_key = ResolveSignerRef(signing_key);
    if (resolved_key.empty()) {
        result.error = "Failed to resolve signer_ref: " + signing_key;
        return result;
    }
    try {
        UniValue params(UniValue::VOBJ);
        params.pushKV("htlc_address", htlc_address);
        params.pushKV("swap_id", swap_id);
        params.pushKV("signing_key", resolved_key);
        params.pushKV("gas_limit", gas_limit);
        params.pushKV("max_fee_gwei", max_fee_gwei);
        params.pushKV("max_priority_fee_gwei", max_priority_fee_gwei);

        UniValue response = m_bridge_fn("eth_refund_htlc", params);
        result.success = response.exists("success") && response["success"].get_bool();
        if (response.exists("tx_hash")) result.tx_hash = response["tx_hash"].get_str();
        if (response.exists("from")) result.from_address = response["from"].get_str();

    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? e["message"].get_str() : e.write();
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

HtlcBackend::AttestationResult EthHtlcBackend::VerifyAttestation(
    const std::string& oracle_pubkey,
    const std::string& attestation_json)
{
    AttestationResult result;
    try {
        UniValue params(UniValue::VOBJ);
        params.pushKV("oracle_pubkey", oracle_pubkey);

        // Parse attestation_json into a UniValue object for the bridge
        UniValue att_obj;
        if (!att_obj.read(attestation_json)) {
            result.error = "Failed to parse attestation JSON";
            return result;
        }
        params.pushKV("attestation", att_obj);

        UniValue response = m_bridge_fn("eth_verify_attestation", params);
        result.valid = response.exists("valid") && response["valid"].get_bool();
        if (response.exists("swap_id")) result.swap_id = response["swap_id"].get_str();
        if (response.exists("confirmation_depth"))
            result.confirmation_depth = response["confirmation_depth"].getInt<int64_t>();
        if (response.exists("error")) result.error = response["error"].get_str();

    } catch (const UniValue& e) {
        result.error = e.isObject() && e.exists("message")
            ? e["message"].get_str() : e.write();
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

std::string EthHtlcBackend::ResolveSignerRef(const std::string& signer_ref)
{
    if (signer_ref.empty()) return {};

    // Raw hex key (64 hex chars = 32 bytes) — pass through for testnet
    if (signer_ref.size() == 64 || (signer_ref.size() == 66 && signer_ref.substr(0, 2) == "0x")) {
        return signer_ref;
    }

    // derived:auto — derive ETH key from wallet seed via bridge
    if (signer_ref.find("derived:") == 0) {
        try {
            UniValue params(UniValue::VOBJ);
            params.pushKV("signer_ref", signer_ref);
            UniValue response = m_bridge_fn("eth_resolve_signer", params);
            if (response.exists("signing_key")) {
                return response["signing_key"].get_str();
            }
            LogPrintf("EthHtlcBackend: eth_resolve_signer returned no key for %s\n",
                      signer_ref);
        } catch (const std::exception& e) {
            LogPrintf("EthHtlcBackend: Failed to resolve signer_ref %s: %s\n",
                      signer_ref, e.what());
        }
        return {};
    }

    // imported:<key-id> — look up in bridge keystore
    if (signer_ref.find("imported:") == 0) {
        try {
            UniValue params(UniValue::VOBJ);
            params.pushKV("signer_ref", signer_ref);
            UniValue response = m_bridge_fn("eth_resolve_signer", params);
            if (response.exists("signing_key")) {
                return response["signing_key"].get_str();
            }
        } catch (const std::exception& e) {
            LogPrintf("EthHtlcBackend: Failed to resolve signer_ref %s: %s\n",
                      signer_ref, e.what());
        }
        return {};
    }

    LogPrintf("EthHtlcBackend: Unknown signer_ref format: %s\n", signer_ref);
    return {};
}

} // namespace wallet
