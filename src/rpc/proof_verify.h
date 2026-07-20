// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RPC_PROOF_VERIFY_H
#define BITCOIN_RPC_PROOF_VERIFY_H

#include <any>
#include <cstdint>
#include <string>

class CRPCTable;

namespace proof_verify {

struct VerifyResult {
    bool verified{false};
    std::string error;
    uint64_t actual_units{0};
    std::string actual_address;
    std::string bestblock;
};

/**
 * Verify a BIP-322 ownership proof against the blockchain (strict rules).
 *
 * Checks performed:
 * 1. Parse utxo_ref -> txid + vout
 * 2. gettxout(txid, vout, false) — confirmed UTXOs only, no mempool
 * 3. Require confirmations >= 1
 * 4. For native TSC: check 'value' field; for registered assets: check asset_id + asset_units
 * 5. Verify UTXO address matches claimed address
 * 6. Verify actual_units >= claimed_units
 * 7. Verify bestblock exists in current chain (getblockheader)
 * 8. verifymessagebip322(address, signature, message) -> true
 *
 * @param rpc        Reference to the global RPC table (::tableRPC)
 * @param context    RPC request context (for node access)
 * @param utxo_ref   UTXO reference in "txid:vout" format
 * @param address    Bitcoin address that should control the UTXO
 * @param message    The signed message (e.g. TENSORCASH_DISCUSS:v1:...)
 * @param signature  BIP-322 signature
 * @param asset_id   Asset ID (empty or "TSC" for native coin)
 * @param claimed_units  Minimum units the proof must cover
 * @return VerifyResult with verified flag, error string, and metadata
 */
VerifyResult VerifyOwnershipProof(
    CRPCTable& rpc,
    const std::any& context,
    const std::string& utxo_ref,
    const std::string& address,
    const std::string& message,
    const std::string& signature,
    const std::string& asset_id,
    uint64_t claimed_units);

/**
 * Validate the canonical discussion proof message format.
 *
 * Expected: TENSORCASH_DISCUSS:v1:<network>:<scope_type>:<scope_id>:<nostr_pubkey>:<expiry_height>
 *
 * @param message  The message string to validate
 * @param[out] network      Extracted network (main/signet/testnet3/regtest)
 * @param[out] scope_type   Extracted scope type (model_prealert/model_challenge)
 * @param[out] scope_id     Extracted scope ID (model_hash or challenge_block_hash)
 * @param[out] nostr_pubkey Extracted Nostr pubkey (hex)
 * @param[out] expiry_height Extracted expiry block height
 * @return Empty string on success, error description on failure
 */
std::string ParseDiscussionProofMessage(
    const std::string& message,
    std::string& network,
    std::string& scope_type,
    std::string& scope_id,
    std::string& nostr_pubkey,
    int& expiry_height);

} // namespace proof_verify

#endif // BITCOIN_RPC_PROOF_VERIFY_H
