// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/psbt_mldsa.h>

#include <consensus/amount.h>
#include <logging.h>
#include <mldsakey.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <sstream>

namespace node {

std::string MLDSAPSBTErrorString(MLDSAPSBTError error, int input_index, const std::string& details)
{
    std::ostringstream oss;

    if (input_index >= 0) {
        oss << "PSBT input " << input_index << ": ";
    }

    switch (error) {
        case MLDSAPSBTError::OK:
            return "No error";
        case MLDSAPSBTError::MISSING_WITNESS_UTXO:
            oss << "Missing witness_utxo or non_witness_utxo";
            break;
        case MLDSAPSBTError::INVALID_PARAM_SET:
            oss << "Invalid ML-DSA parameter set";
            if (!details.empty()) oss << " (" << details << ", expected 44, 65, or 87)";
            break;
        case MLDSAPSBTError::KEY_NOT_FOUND:
            oss << "ML-DSA key not found in wallet";
            if (!details.empty()) oss << " (output key: " << details << ")";
            break;
        case MLDSAPSBTError::METADATA_MISSING:
            oss << "Required Taproot metadata not found";
            if (!details.empty()) oss << " (" << details << ")";
            break;
        case MLDSAPSBTError::SIGNATURE_INVALID:
            oss << "ML-DSA signature verification failed";
            break;
        case MLDSAPSBTError::WALLET_LOCKED:
            oss << "Wallet is locked, cannot sign ML-DSA input";
            break;
        case MLDSAPSBTError::WRONG_KEY_TYPE:
            oss << "Input is not a witness v2 ML-DSA input";
            if (!details.empty()) oss << " (" << details << ")";
            break;
        case MLDSAPSBTError::ALREADY_SIGNED:
            oss << "Input already has an ML-DSA signature";
            break;
        case MLDSAPSBTError::INCOMPLETE_PSBT:
            oss << "PSBT missing required fields for finalization";
            if (!details.empty()) oss << " (" << details << ")";
            break;
        case MLDSAPSBTError::INDEX_OUT_OF_RANGE:
            oss << "Input index out of range";
            if (!details.empty()) oss << " (max: " << details << ")";
            break;
        case MLDSAPSBTError::SIGNING_FAILED:
            oss << "ML-DSA signature generation failed";
            if (!details.empty()) oss << ": " << details;
            break;
        case MLDSAPSBTError::INVALID_SIGHASH:
            oss << "Sighash computation failed";
            break;
        case MLDSAPSBTError::NO_TAPSCRIPT:
            oss << "Missing tapscript for witness v2 input";
            break;
        case MLDSAPSBTError::NO_CONTROL_BLOCK:
            oss << "Missing control block for script-path spending";
            break;
        case MLDSAPSBTError::INTERNAL_ERROR:
            oss << "Internal error";
            if (!details.empty()) oss << ": " << details;
            break;
    }

    return oss.str();
}

bool IsMLDSAInput(const PartiallySignedTransaction& psbt, int index)
{
    if (index < 0 || static_cast<size_t>(index) >= psbt.inputs.size()) {
        return false;
    }

    // Get the UTXO
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, index)) {
        return false;
    }

    // Check if scriptPubKey is witness v2: OP_2 <32 bytes>
    if (utxo.scriptPubKey.size() != 34) {
        return false;
    }
    if (utxo.scriptPubKey[0] != OP_2 || utxo.scriptPubKey[1] != 0x20) {
        return false;
    }

    return true;
}

bool UpdatePSBTInputMLDSA(
    const SigningProvider& provider,
    PartiallySignedTransaction& psbt,
    int index)
{
    if (index < 0 || static_cast<size_t>(index) >= psbt.inputs.size()) {
        return false;
    }

    PSBTInput& input = psbt.inputs[index];

    // Check if this is an ML-DSA witness v2 input
    if (!IsMLDSAInput(psbt, index)) {
        return false;
    }

    // Get the UTXO
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, index)) {
        return false;
    }

    // Extract the 32-byte output key from scriptPubKey (OP_2 <32 bytes>)
    std::vector<unsigned char> output_key_bytes(
        utxo.scriptPubKey.begin() + 2,
        utxo.scriptPubKey.end()
    );
    XOnlyPubKey output_key{output_key_bytes};

    // Try to get ML-DSA key and Taproot spend data from provider
    CMLDSAKey mldsa_key;
    if (provider.GetMLDSAKey(output_key, mldsa_key)) {
        // Store ML-DSA public key (encoded format)
        input.m_mldsa_pubkey = mldsa_key.GetEncodedPubKey();

        // Store parameter set
        input.m_mldsa_param_set = static_cast<uint8_t>(mldsa_key.GetLevel());

        // Get Taproot spend data (internal key, merkle root, scripts, parity)
        TaprootSpendData spenddata;
        uint8_t parity = 0;
        if (provider.GetMLDSATaprootSpendData(output_key, spenddata, parity)) {
            input.m_tap_internal_key = spenddata.internal_key;
            input.m_tap_merkle_root = spenddata.merkle_root;
            input.m_v2_tap_parity = parity;

            // Store tapscripts
            for (const auto& [leaf_script, control_blocks] : spenddata.scripts) {
                input.m_tap_scripts[leaf_script] = control_blocks;
            }

            return true;
        }
    }

    return false;
}

bool SignPSBTInputMLDSA(
    const SigningProvider& provider,
    PartiallySignedTransaction& psbt,
    int index,
    const PrecomputedTransactionData* txdata,
    int sighash_type)
{
    if (index < 0 || static_cast<size_t>(index) >= psbt.inputs.size()) {
        return false;
    }

    PSBTInput& input = psbt.inputs[index];

    // Check if this is an ML-DSA input with the required data
    if (input.m_mldsa_pubkey.empty()) {
        return false;
    }

    // Check if already signed
    if (!input.m_mldsa_signature.empty()) {
        return true; // Already signed
    }

    // Get UTXO
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, index)) {
        return false;
    }

    // Extract output key
    std::vector<unsigned char> output_key_bytes(
        utxo.scriptPubKey.begin() + 2,
        utxo.scriptPubKey.end()
    );
    XOnlyPubKey output_key{output_key_bytes};

    // Get ML-DSA secret key from provider
    CMLDSAKey mldsa_key;
    if (!provider.GetMLDSAKey(output_key, mldsa_key)) {
        return false; // Provider doesn't have the secret key
    }

    // Get the tapscript from PSBT
    if (input.m_tap_scripts.empty()) {
        return false;
    }
    const auto& [leaf_script_pair, control_blocks] = *input.m_tap_scripts.begin();
    const auto& [tapscript_bytes, leaf_ver] = leaf_script_pair;
    CScript tapscript(tapscript_bytes.begin(), tapscript_bytes.end());

    // Compute Taproot sighash for witness v2
    // We use the BIP 341 sighash computation with SigVersion::TAPSCRIPT
    uint256 sighash;
    if (txdata == nullptr) {
        // For dummy signatures (e.g., in analysis), return false
        // We don't produce dummy ML-DSA signatures as they're expensive
        return false;
    }

    // Get the transaction and compute the sighash
    const CMutableTransaction& tx = *psbt.tx;

    // Compute leaf hash for the tapscript
    uint256 tapleaf_hash = ComputeTapleafHash(leaf_ver, tapscript);

    // Create ScriptExecutionData for ML-DSA signing
    ScriptExecutionData execdata;
    execdata.m_tapleaf_hash = tapleaf_hash;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;  // No OP_CODESEPARATOR executed
    execdata.m_codeseparator_pos_init = true;
    execdata.m_witness_version = 2;  // Witness v2 output
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;  // No annex

    // Compute the ML-DSA sighash
    if (!SignatureHashMLDSA(sighash, execdata, tx, index, sighash_type, SigVersion::TAPSCRIPT, *txdata, MissingDataBehavior::FAIL)) {
        return false;
    }

    // Sign with ML-DSA
    std::vector<unsigned char> signature;
    if (!mldsa_key.Sign(sighash, signature)) {
        return false;
    }

    // Store signature in PSBT (without sighash byte - we add it during finalization)
    input.m_mldsa_signature = signature;

    return true;
}

bool FinalizePSBTInputMLDSA(PSBTInput& input, int sighash_type)
{
    // Check if we have an ML-DSA signature
    if (input.m_mldsa_signature.empty()) {
        return false;
    }

    // Check if we have the required Taproot data
    if (input.m_tap_scripts.empty() || input.m_tap_internal_key.IsNull()) {
        return false;
    }

    // Get the tapscript and control block
    const auto& [leaf_script_pair, control_blocks] = *input.m_tap_scripts.begin();
    if (control_blocks.empty()) {
        return false;
    }

    const auto& [tapscript_bytes, leaf_ver] = leaf_script_pair;
    const auto& control_block = *control_blocks.begin();

    // Build witness stack for witness v2 script-path spending:
    // Stack: [signature_with_sighash] [tapscript] [control_block]
    CScriptWitness witness;

    // Add signature with sighash byte appended
    std::vector<unsigned char> sig_with_sighash = input.m_mldsa_signature;
    sig_with_sighash.push_back(static_cast<unsigned char>(sighash_type));
    witness.stack.push_back(sig_with_sighash);

    // Add tapscript
    witness.stack.push_back(tapscript_bytes);

    // Add control block
    witness.stack.push_back(control_block);

    // Set final witness
    input.final_script_witness = witness;

    // Clear partial ML-DSA data (keep pubkey for reference, clear signature)
    input.m_mldsa_signature.clear();

    return true;
}

} // namespace node
