// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PSBT_MLDSA_H
#define BITCOIN_NODE_PSBT_MLDSA_H

#include <psbt.h>
#include <script/signingprovider.h>

class CMLDSAKey;
struct PrecomputedTransactionData;

namespace node {

/**
 * Error types that can occur during ML-DSA PSBT operations.
 */
enum class MLDSAPSBTError {
    OK,                      // No error
    MISSING_WITNESS_UTXO,    // PSBT input missing witness_utxo or non_witness_utxo
    INVALID_PARAM_SET,       // Invalid ML-DSA parameter set (not 44, 65, or 87)
    KEY_NOT_FOUND,           // ML-DSA key not found in signing provider
    METADATA_MISSING,        // Required Taproot metadata not found
    SIGNATURE_INVALID,       // ML-DSA signature verification failed
    WALLET_LOCKED,           // Wallet is locked, cannot access secret key
    WRONG_KEY_TYPE,          // Input is not a witness v2 ML-DSA input
    ALREADY_SIGNED,          // Input already has a signature
    INCOMPLETE_PSBT,         // PSBT missing required fields for finalization
    INDEX_OUT_OF_RANGE,      // Input index out of range
    SIGNING_FAILED,          // ML-DSA signature generation failed
    INVALID_SIGHASH,         // Sighash computation failed
    NO_TAPSCRIPT,            // Missing tapscript for witness v2 input
    NO_CONTROL_BLOCK,        // Missing control block for script-path spending
    INTERNAL_ERROR           // Unexpected internal error
};

/**
 * Convert MLDSAPSBTError to a human-readable error message.
 */
std::string MLDSAPSBTErrorString(MLDSAPSBTError error, int input_index = -1, const std::string& details = "");

/**
 * PSBT error state container for detailed error reporting.
 */
struct MLDSAPSBTErrorState {
    MLDSAPSBTError error{MLDSAPSBTError::OK};
    int input_index{-1};
    std::string details;

    MLDSAPSBTErrorState() = default;
    MLDSAPSBTErrorState(MLDSAPSBTError err, int idx, std::string det = "")
        : error(err), input_index(idx), details(std::move(det)) {}

    bool IsOK() const { return error == MLDSAPSBTError::OK; }
    std::string ToString() const { return MLDSAPSBTErrorString(error, input_index, details); }
};

/**
 * Update a PSBT input with ML-DSA witness v2 information from the SigningProvider.
 *
 * This function populates ML-DSA-specific fields for witness v2 inputs:
 * - m_mldsa_pubkey: The encoded ML-DSA public key
 * - m_mldsa_param_set: The security level (44/65/87)
 * - m_tap_internal_key: The Taproot internal key
 * - m_tap_merkle_root: The Merkle root of the script tree
 * - m_v2_tap_parity: The output key parity bit
 * - m_tap_scripts: The Taproot script-path leaf scripts
 *
 * @param provider     The signing provider with ML-DSA keys and metadata
 * @param psbt         The PSBT to update
 * @param index        The input index to update
 * @return true if the input was successfully updated with ML-DSA data
 */
bool UpdatePSBTInputMLDSA(
    const SigningProvider& provider,
    PartiallySignedTransaction& psbt,
    int index
);

/**
 * Sign a PSBT input with an ML-DSA signature for witness v2.
 *
 * This function:
 * 1. Checks if the input is an ML-DSA witness v2 input
 * 2. Retrieves the ML-DSA secret key from the provider
 * 3. Computes the Taproot sighash for witness v2
 * 4. Signs the sighash with ML-DSA
 * 5. Stores the signature in m_mldsa_signature
 *
 * @param provider     The signing provider with ML-DSA secret keys
 * @param psbt         The PSBT containing the input to sign
 * @param index        The input index to sign
 * @param txdata       Precomputed transaction data (nullptr for dummy signatures)
 * @param sighash_type The sighash type (default: SIGHASH_ALL)
 * @return true if the input was successfully signed
 */
bool SignPSBTInputMLDSA(
    const SigningProvider& provider,
    PartiallySignedTransaction& psbt,
    int index,
    const PrecomputedTransactionData* txdata,
    int sighash_type = SIGHASH_ALL
);

/**
 * Finalize a PSBT input with ML-DSA witness v2 script-path spending.
 *
 * This function:
 * 1. Checks if the input has an ML-DSA signature
 * 2. Constructs the witness stack for script-path spending:
 *    - [signature + sighash_byte]
 *    - [tapscript]
 *    - [control_block]
 * 3. Sets the final_script_witness
 * 4. Clears temporary ML-DSA fields
 *
 * @param input        The PSBT input to finalize
 * @param sighash_type The sighash type used (appended to signature)
 * @return true if the input was successfully finalized
 */
bool FinalizePSBTInputMLDSA(
    PSBTInput& input,
    int sighash_type = SIGHASH_ALL
);

/**
 * Check if a PSBT input is an ML-DSA witness v2 input.
 *
 * An input is considered ML-DSA if:
 * - It has a witness_utxo or non_witness_utxo
 * - The UTXO scriptPubKey is witness v2 (OP_2 <32 bytes>)
 *
 * @param psbt         The PSBT to check
 * @param index        The input index to check
 * @return true if the input is a witness v2 ML-DSA input
 */
bool IsMLDSAInput(
    const PartiallySignedTransaction& psbt,
    int index
);

} // namespace node

#endif // BITCOIN_NODE_PSBT_MLDSA_H
