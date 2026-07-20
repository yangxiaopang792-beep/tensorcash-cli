// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/proof_verify.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <logging.h>
#include <tinyformat.h>
#include <univalue.h>

#include <any>
#include <string>
#include <vector>

namespace proof_verify {

VerifyResult VerifyOwnershipProof(
    CRPCTable& rpc,
    const std::any& context,
    const std::string& utxo_ref,
    const std::string& address,
    const std::string& message,
    const std::string& signature,
    const std::string& asset_id,
    uint64_t claimed_units)
{
    VerifyResult result;

    // 1. Parse utxo_ref (format: "txid:vout")
    size_t colon_pos = utxo_ref.find(':');
    if (colon_pos == std::string::npos) {
        result.error = "Invalid utxo_ref format (expected 'txid:vout')";
        return result;
    }

    std::string txid_str = utxo_ref.substr(0, colon_pos);
    std::string vout_str = utxo_ref.substr(colon_pos + 1);
    int vout;
    try {
        vout = std::stoi(vout_str);
    } catch (...) {
        result.error = "Invalid vout in utxo_ref";
        return result;
    }

    // 2. gettxout — confirmed UTXOs only (include_mempool = false)
    JSONRPCRequest gettxout_req;
    gettxout_req.context = context;
    gettxout_req.strMethod = "gettxout";
    gettxout_req.params = UniValue(UniValue::VARR);
    gettxout_req.params.push_back(txid_str);
    gettxout_req.params.push_back(vout);
    gettxout_req.params.push_back(false); // include_mempool = false (strict)

    UniValue utxo_result;
    try {
        utxo_result = rpc.execute(gettxout_req);
    } catch (const std::exception& e) {
        result.error = strprintf("Failed to query UTXO: %s", e.what());
        return result;
    }

    if (utxo_result.isNull()) {
        result.error = "UTXO does not exist or has been spent";
        return result;
    }

    // 3. Require at least 1 confirmation
    int confirmations = 0;
    if (utxo_result.exists("confirmations") && utxo_result["confirmations"].isNum()) {
        confirmations = utxo_result["confirmations"].getInt<int>();
    }
    if (confirmations < 1) {
        result.error = strprintf("UTXO has %d confirmations, require at least 1", confirmations);
        return result;
    }

    // 4. Check asset value
    bool isNative = (asset_id.empty() || asset_id == "TSC");
    uint64_t actual_units = 0;

    if (isNative) {
        if (!utxo_result.exists("value") || !utxo_result["value"].isNum()) {
            result.error = "UTXO does not contain value field for native coin";
            return result;
        }
        double value_btc = utxo_result["value"].get_real();
        actual_units = static_cast<uint64_t>(value_btc * 100000000);
    } else {
        if (!utxo_result.exists("asset_id") || !utxo_result.exists("asset_units")) {
            result.error = "UTXO does not contain asset data";
            return result;
        }
        std::string actual_asset_id = utxo_result["asset_id"].get_str();
        actual_units = utxo_result["asset_units"].getInt<uint64_t>();

        if (actual_asset_id != asset_id) {
            result.error = strprintf("UTXO contains different asset: %s", actual_asset_id);
            return result;
        }
    }

    // 5. Extract and verify address from scriptPubKey
    std::string actual_address;
    if (utxo_result.exists("scriptPubKey") && utxo_result["scriptPubKey"].isObject()) {
        const UniValue& spk = utxo_result["scriptPubKey"];
        if (spk.exists("address") && spk["address"].isStr()) {
            actual_address = spk["address"].get_str();
        }
    }

    if (!actual_address.empty() && actual_address != address) {
        result.error = strprintf("UTXO is at address %s, not claimed address %s", actual_address, address);
        return result;
    }
    result.actual_address = actual_address;

    // 6. Verify claimed_units <= actual_units
    if (actual_units < claimed_units) {
        result.error = strprintf("UTXO contains only %llu units, but %llu units were claimed",
            (unsigned long long)actual_units, (unsigned long long)claimed_units);
        return result;
    }

    // 7. Verify bestblock exists in current chain
    std::string bestblock;
    if (utxo_result.exists("bestblock") && utxo_result["bestblock"].isStr()) {
        bestblock = utxo_result["bestblock"].get_str();
    }

    if (!bestblock.empty()) {
        try {
            JSONRPCRequest header_req;
            header_req.context = context;
            header_req.strMethod = "getblockheader";
            header_req.params = UniValue(UniValue::VARR);
            header_req.params.push_back(bestblock);

            UniValue block_header = rpc.execute(header_req);
            if (block_header.isNull()) {
                result.error = strprintf("UTXO's bestblock %s not found in current chain", bestblock.substr(0, 16));
                return result;
            }
        } catch (const std::exception& e) {
            result.error = strprintf("UTXO's bestblock %s not found in current chain: %s", bestblock.substr(0, 16), e.what());
            return result;
        }
    }
    result.bestblock = bestblock;

    // 8. Verify BIP-322 signature
    JSONRPCRequest verify_req;
    verify_req.context = context;
    verify_req.strMethod = "verifymessagebip322";
    verify_req.params = UniValue(UniValue::VARR);
    verify_req.params.push_back(address);
    verify_req.params.push_back(signature);
    verify_req.params.push_back(message);

    try {
        UniValue verify_result = rpc.execute(verify_req);
        if (!verify_result.isBool() || !verify_result.get_bool()) {
            result.error = "BIP-322 signature verification failed";
            return result;
        }
    } catch (const std::exception& e) {
        result.error = strprintf("BIP-322 verification failed: %s", e.what());
        return result;
    }

    result.verified = true;
    result.actual_units = actual_units;
    return result;
}

std::string ParseDiscussionProofMessage(
    const std::string& message,
    std::string& network,
    std::string& scope_type,
    std::string& scope_id,
    std::string& nostr_pubkey,
    int& expiry_height)
{
    // Expected: TENSORCASH_DISCUSS:v1:<network>:<scope_type>:<scope_id>:<nostr_pubkey>:<expiry_height>
    const std::string prefix = "TENSORCASH_DISCUSS:v1:";
    if (message.substr(0, prefix.size()) != prefix) {
        return "Message does not start with TENSORCASH_DISCUSS:v1:";
    }

    std::string remainder = message.substr(prefix.size());

    // Split by ':'
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < remainder.size()) {
        size_t next = remainder.find(':', pos);
        if (next == std::string::npos) {
            parts.push_back(remainder.substr(pos));
            break;
        }
        parts.push_back(remainder.substr(pos, next - pos));
        pos = next + 1;
    }

    if (parts.size() != 5) {
        return strprintf("Expected 5 fields after prefix, got %d", parts.size());
    }

    network = parts[0];
    scope_type = parts[1];
    scope_id = parts[2];
    nostr_pubkey = parts[3];

    // Validate network — must match a ChainTypeToString() value from util/chaintype.cpp
    if (network != "main" && network != "test" && network != "testnet4" &&
        network != "signet" && network != "regtest" &&
        network != "tensor" && network != "tensor-test" && network != "tensor-reg") {
        return strprintf("Invalid network: %s", network);
    }

    // Validate scope_type
    if (scope_type != "model_prealert" && scope_type != "model_challenge") {
        return strprintf("Invalid scope_type: %s", scope_type);
    }

    // Validate scope_id (must be 64 hex chars — uint256 hash: model_hash or challenge_block_hash)
    if (scope_id.size() != 64) {
        return strprintf("scope_id must be 64 hex chars (uint256), got %d", scope_id.size());
    }
    for (char c : scope_id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return strprintf("scope_id contains non-hex character: '%c'", c);
        }
    }

    // Validate nostr_pubkey (must be non-empty hex string, 64 chars for secp256k1 x-only pubkey)
    if (nostr_pubkey.empty()) {
        return "Empty nostr_pubkey";
    }
    if (nostr_pubkey.size() != 64) {
        return strprintf("nostr_pubkey must be 64 hex chars, got %d", nostr_pubkey.size());
    }
    for (char c : nostr_pubkey) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return strprintf("nostr_pubkey contains non-hex character: '%c'", c);
        }
    }

    // Parse expiry_height
    try {
        expiry_height = std::stoi(parts[4]);
        if (expiry_height <= 0) {
            return strprintf("expiry_height must be positive, got %d", expiry_height);
        }
    } catch (...) {
        return strprintf("Invalid expiry_height: %s", parts[4]);
    }

    return ""; // success
}

} // namespace proof_verify
