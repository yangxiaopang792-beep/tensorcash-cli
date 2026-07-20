// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <hash.h>
#include <key_io.h>
#include <mldsakey.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/crypter.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <univalue.h>

namespace wallet {

/**
 * Generate a Taproot v2 ML-DSA address (experimental).
 *
 * This RPC generates an ML-DSA keypair and creates a witness v2 address
 * suitable for post-quantum signatures. The address uses a simple tapscript:
 *
 *   <encoded_pk> OP_CHECKMLSIGVERIFY OP_TRUE
 *
 * IMPORTANT: This is an experimental feature. ML-DSA keys are stored in the wallet
 * database and encrypted when the wallet is encrypted. Wallets must be unlocked
 * when generating new ML-DSA keys if encryption is enabled. The secret key is
 * also returned in the RPC response for backup purposes.
 *
 * Returns:
 * - address: The witness v2 (bech32m) address
 * - pubkey: ML-DSA public key (hex, raw FIPS 204 format)
 * - seckey: ML-DSA secret key (hex) - KEEP THIS SECRET!
 * - level: Parameter set (44/65/87)
 * - tapscript: The spending script (hex)
 */
RPCHelpMan generatemldsaaddress()
{
    return RPCHelpMan{"generatemldsaaddress",
                "\nGenerate a Taproot v2 ML-DSA address for post-quantum signatures.\n"
                "\nEXPERIMENTAL: ML-DSA keys are stored in wallet database.\n"
                "Backup your wallet to preserve ML-DSA keys.\n",
                {
                    {"level", RPCArg::Type::NUM, RPCArg::Default{65}, "ML-DSA parameter set: 44 (weak), 65 (standard), or 87 (high security)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The witness v2 address (bech32m)"},
                        {RPCResult::Type::STR_HEX, "pubkey", "ML-DSA public key (raw FIPS 204, hex)"},
                        {RPCResult::Type::STR_HEX, "seckey", "ML-DSA secret key (hex) - KEEP SECRET!"},
                        {RPCResult::Type::NUM, "level", "Parameter set (44/65/87)"},
                        {RPCResult::Type::STR_HEX, "tapscript", "The tapscript spending condition"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The scriptPubKey (witness v2 program)"},
                        {RPCResult::Type::STR_HEX, "encoded_pubkey", "Encoded ML-DSA public key for script (includes alg_id, param_set, and varint length)"},
                        {RPCResult::Type::STR_HEX, "internal_pubkey", "Internal pubkey (wallet-owned key for Taproot construction)"},
                        {RPCResult::Type::STR_HEX, "leaf_hash", "Tapleaf hash of the spending script"},
                        {RPCResult::Type::STR_HEX, "merkle_root", "Merkle root (same as leaf_hash for single-leaf tree)"},
                        {RPCResult::Type::STR_HEX, "output_pubkey", "Output pubkey (tweaked pubkey in scriptPubKey)"},
                        {RPCResult::Type::BOOL, "parity", "Parity bit of the output pubkey (needed for control block)"},
                        {RPCResult::Type::STR, "warning", "Warning about experimental nature"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("generatemldsaaddress", "")
                    + HelpExampleCli("generatemldsaaddress", "87")
                    + HelpExampleRpc("generatemldsaaddress", "65")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
#ifndef ENABLE_MLDSA
    throw JSONRPCError(RPC_INTERNAL_ERROR, "ML-DSA support not enabled (liboqs not available)");
#endif

    // Parse parameter set level
    int level_int = 65;  // Default to ML-DSA-65
    if (!request.params[0].isNull()) {
        level_int = request.params[0].getInt<int>();
        if (level_int != 44 && level_int != 65 && level_int != 87) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid level. Must be 44, 65, or 87.");
        }
    }

    mldsa::ParamSet level;
    switch (level_int) {
        case 44: level = mldsa::ParamSet::MLDSA_44; break;
        case 65: level = mldsa::ParamSet::MLDSA_65; break;
        case 87: level = mldsa::ParamSet::MLDSA_87; break;
        default: throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid level");
    }

    // Generate ML-DSA keypair
    CMLDSAKey mldsa_key;
    if (!mldsa_key.MakeNewKey(level)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate ML-DSA keypair");
    }

    // Get encoded public key for tapscript
    std::vector<uint8_t> encoded_pk = mldsa_key.GetEncodedPubKey();

    // Create tapscript: <encoded_pk> OP_CHECKMLSIGVERIFY OP_TRUE
    // This is a simple script that requires an ML-DSA signature over the sighash
    CScript tapscript;
    tapscript << encoded_pk << OP_CHECKMLSIGVERIFY << OP_TRUE;

    // Compute tapleaf hash using BIP-341 tagged hash
    uint256 leaf_hash = ComputeTapleafHash(0xc0, tapscript);

    // Generate a wallet key for the internal pubkey
    // (Key-path spend is disabled by consensus for v2, but we still need a key for wallet tracking)
    std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

    LOCK(wallet->cs_wallet);

    const bool wallet_encrypted = wallet->IsCrypted();
    if (wallet_encrypted) {
        EnsureWalletIsUnlocked(*wallet);
    }

    // Generate a new BECH32M destination to get a fresh key
    auto dest_result = wallet->GetNewDestination(OutputType::BECH32M, "ml-dsa-internal");
    if (!dest_result) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(dest_result).original);
    }

    // Extract the XOnlyPubKey from the destination
    // For witness v1 taproot addresses, the destination is already an XOnlyPubKey
    XOnlyPubKey internal_pubkey;
    if (auto* tap = std::get_if<WitnessV1Taproot>(&(*dest_result))) {
        internal_pubkey = *tap;
    } else {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to generate taproot key");
    }

    // For a single-script tree, the merkle root is just the leaf hash
    uint256 merkle_root = leaf_hash;

    // Compute Taproot tweak: output_pubkey = internal_pubkey + tagged_hash("TapTweak", internal_pubkey || merkle_root)
    auto tweak_result = internal_pubkey.CreateTapTweak(&merkle_root);
    if (!tweak_result) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute Taproot tweak");
    }
    XOnlyPubKey output_pubkey = tweak_result->first;
    bool parity = tweak_result->second;

    // Create witness v2 program: OP_2 <32-byte output_pubkey>
    CScript scriptPubKey;
    scriptPubKey << OP_2 << ToByteVector(output_pubkey);

    // Encode witness v2 bech32m address
    std::string address = EncodeDestination(WitnessV2Taproot(output_pubkey));

    // Store ML-DSA key in wallet database
    uint256 pk_hash = Hash(mldsa_key.GetPubKey());
    CKeyMetadata metadata;
    metadata.nCreateTime = GetTime();
    metadata.nVersion = CKeyMetadata::CURRENT_VERSION;

    const MLDSASecretKey& secure_seckey = mldsa_key.GetSecretKey();
    WalletBatch batch(wallet->GetDatabase());

    if (wallet_encrypted) {
        CKeyingMaterial secret(secure_seckey.begin(), secure_seckey.end());
        std::vector<unsigned char> crypted_secret;
        bool encrypted_ok = wallet->WithEncryptionKey([&](const CKeyingMaterial& master_key) {
            return EncryptSecret(master_key, secret, pk_hash, crypted_secret);
        });
        if (!encrypted_ok) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to encrypt ML-DSA key (wallet locked?)");
        }
        if (!batch.WriteCryptedMLDSAKey(pk_hash, mldsa_key.GetPubKey(), crypted_secret,
                                        static_cast<uint8_t>(level_int), metadata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to store encrypted ML-DSA key in wallet");
        }
    } else {
        std::vector<uint8_t> seckey(secure_seckey.begin(), secure_seckey.end());
        if (!batch.WriteMLDSAKey(pk_hash, mldsa_key.GetPubKey(), seckey,
                                 static_cast<uint8_t>(level_int), metadata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to store ML-DSA key in wallet");
        }
    }

    // Store Taproot construction metadata for PSBT signing
    MLDSATaprootMetadata taproot_metadata;
    taproot_metadata.internal_key = internal_pubkey;
    taproot_metadata.merkle_root = merkle_root;
    taproot_metadata.parity = parity;
    taproot_metadata.tapscript = tapscript;
    taproot_metadata.leaf_hash = leaf_hash;

    if (!batch.WriteMLDSATaprootData(output_pubkey, taproot_metadata)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to store ML-DSA Taproot metadata in wallet");
    }

    // Store reverse index: output_key → pk_hash (for PSBT key lookup)
    if (!batch.WriteMLDSAOutputIndex(output_pubkey, pk_hash)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to store ML-DSA output index in wallet");
    }

    // Add the scriptPubKey to the wallet so it tracks incoming transactions
    // For descriptor wallets, create a raw() descriptor
    // For legacy wallets, add to watch-only set
    if (wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        // Descriptor wallet: import as raw() descriptor
        std::string desc_str = "raw(" + HexStr(scriptPubKey) + ")";

        FlatSigningProvider keys;
        std::string error;
        auto parsed_descs = Parse(desc_str, keys, error, /*require_checksum=*/false);
        if (parsed_descs.empty()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Failed to parse ML-DSA descriptor: %s", error));
        }

        // Use timestamp=1 (not 0, as 0 has special meaning) to ensure we scan from early blockchain
        // This makes sure the wallet detects both past and future transactions to this address
        int64_t timestamp = 1;
        WalletDescriptor w_desc(std::move(parsed_descs[0]), timestamp, 0, 1, 0);

        auto spk_manager_res = wallet->AddWalletDescriptor(w_desc, keys, "ml-dsa", /*internal=*/false);
        if (!spk_manager_res) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to add ML-DSA descriptor: %s",
                util::ErrorString(spk_manager_res).original));
        }

        // Connect notifiers so wallet will detect transactions to this descriptor
        wallet->ConnectScriptPubKeyManNotifiers();

        WitnessV2Taproot dest(output_pubkey);
        wallet->SetAddressBook(dest, "ml-dsa", AddressPurpose::RECEIVE);
    } else {
        // Legacy wallet: add to watch-only set
        auto spk_man = wallet->GetLegacyDataSPKM();
        if (!spk_man) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not have legacy script pubkey manager");
        }
        if (!spk_man->LoadWatchOnly(scriptPubKey)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to add ML-DSA script to watch-only set");
        }
        if (!batch.WriteWatchOnly(scriptPubKey, metadata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to write ML-DSA watch-only script to database");
        }
        WitnessV2Taproot dest(output_pubkey);
        wallet->SetAddressBook(dest, "ml-dsa", AddressPurpose::RECEIVE);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", address);
    result.pushKV("pubkey", HexStr(mldsa_key.GetPubKey()));
    result.pushKV("seckey", HexStr(mldsa_key.GetSecretKey()));
    result.pushKV("level", level_int);
    result.pushKV("tapscript", HexStr(tapscript));
    result.pushKV("scriptPubKey", HexStr(scriptPubKey));
    result.pushKV("leaf_hash", leaf_hash.GetHex());
    result.pushKV("merkle_root", merkle_root.GetHex());
    result.pushKV("internal_pubkey", HexStr(internal_pubkey));
    result.pushKV("output_pubkey", HexStr(output_pubkey));
    result.pushKV("parity", parity);
    result.pushKV("encoded_pubkey", HexStr(encoded_pk));
    result.pushKV("warning", wallet_encrypted ?
        "ML-DSA key stored encrypted in wallet. Backup wallet to preserve keys. Secret key also returned for reference." :
        "ML-DSA key stored in wallet. Backup wallet to preserve keys. Secret key also returned for reference.");

    return result;
},
    };
}

/**
 * Sign a transaction input with ML-DSA secret key.
 *
 * This RPC signs a specific input of a transaction using an ML-DSA secret key.
 * The transaction must spend from a witness v2 output with an ML-DSA tapscript.
 *
 * Returns the signed transaction hex.
 */
RPCHelpMan signmldsatransaction()
{
    return RPCHelpMan{"signmldsatransaction",
                "\nSign a transaction input with ML-DSA secret key.\n"
                "For multi-input transactions, use prevout_values and prevout_scriptpubkeys arrays to provide info for ALL inputs.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw transaction hex string"},
                    {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The input index to sign"},
                    {"seckey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-DSA secret key (hex)"},
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-DSA public key (hex, raw FIPS 204)"},
                    {"level", RPCArg::Type::NUM, RPCArg::Optional::NO, "ML-DSA parameter set (44/65/87)"},
                    {"tapscript", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The tapscript being spent"},
                    {"prevout_value", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "The value of the output being spent (in BTC). For single-input transactions only."},
                    {"prevout_scriptpubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The scriptPubKey of the output being spent. For single-input transactions only."},
                    {"internal_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The internal pubkey (from generatemldsaaddress)"},
                    {"merkle_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The merkle root (from generatemldsaaddress)"},
                    {"parity", RPCArg::Type::BOOL, RPCArg::Optional::NO, "The parity bit (from generatemldsaaddress)"},
                    {"sighash_type", RPCArg::Type::STR, RPCArg::Default{"ALL"}, "The sighash type (ALL, NONE, SINGLE, ALL|ANYONECANPAY, etc.)"},
                    {"prevout_values", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of prevout values for ALL inputs (in BTC). Required for multi-input transactions.",
                        {
                            {"value", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Prevout value in BTC"},
                        }
                    },
                    {"prevout_scriptpubkeys", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of prevout scriptPubKeys for ALL inputs (hex). Required for multi-input transactions.",
                        {
                            {"scriptpubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Prevout scriptPubKey (hex)"},
                        }
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The signed transaction hex"},
                        {RPCResult::Type::BOOL, "complete", "Whether the transaction is fully signed"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signmldsatransaction", "\"<hex>\" 0 \"<seckey>\" \"<pubkey>\" 65 \"<tapscript>\" 0.01 \"<scriptpubkey>\" \"<internal_pubkey>\" \"<merkle_root>\" true")
                    + HelpExampleRpc("signmldsatransaction", "\"<hex>\", 0, \"<seckey>\", \"<pubkey>\", 65, \"<tapscript>\", 0.01, \"<scriptpubkey>\", \"<internal_pubkey>\", \"<merkle_root>\", true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
#ifndef ENABLE_MLDSA
    throw JSONRPCError(RPC_INTERNAL_ERROR, "ML-DSA support not enabled (liboqs not available)");
#endif

    // Parse transaction hex
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Parse input index
    int input_index = request.params[1].getInt<int>();
    if (input_index < 0 || input_index >= (int)tx.vin.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Input index out of range");
    }

    // Parse secret key
    std::vector<uint8_t> sk_bytes = ParseHex(request.params[2].get_str());

    // Parse public key
    std::vector<uint8_t> pk_bytes = ParseHex(request.params[3].get_str());

    // Parse parameter set level
    int level_int = request.params[4].getInt<int>();
    if (level_int != 44 && level_int != 65 && level_int != 87) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid level. Must be 44, 65, or 87.");
    }

    mldsa::ParamSet level;
    switch (level_int) {
        case 44: level = mldsa::ParamSet::MLDSA_44; break;
        case 65: level = mldsa::ParamSet::MLDSA_65; break;
        case 87: level = mldsa::ParamSet::MLDSA_87; break;
        default: throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid level");
    }

    // Load secret key into CMLDSAKey
    CMLDSAKey mldsa_key;
    if (!mldsa_key.SetSecretKey(sk_bytes, level)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid secret key size");
    }

    // Parse tapscript
    std::vector<uint8_t> tapscript_bytes = ParseHex(request.params[5].get_str());
    CScript tapscript(tapscript_bytes.begin(), tapscript_bytes.end());

    // Build spent_outputs vector for ALL inputs
    std::vector<CTxOut> spent_outputs;

    // Check if array parameters are provided (for multi-input transactions)
    bool use_arrays = !request.params[12].isNull() && !request.params[13].isNull();

    if (use_arrays) {
        // Multi-input transaction: use array parameters
        const UniValue& prevout_values_arr = request.params[12].get_array();
        const UniValue& prevout_scriptpubkeys_arr = request.params[13].get_array();

        if (prevout_values_arr.size() != tx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "prevout_values array size must match number of inputs");
        }
        if (prevout_scriptpubkeys_arr.size() != tx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "prevout_scriptpubkeys array size must match number of inputs");
        }

        // Build spent_outputs for ALL inputs
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            CAmount value = AmountFromValue(prevout_values_arr[i]);
            std::vector<uint8_t> spk_bytes = ParseHex(prevout_scriptpubkeys_arr[i].get_str());
            CScript scriptpubkey(spk_bytes.begin(), spk_bytes.end());
            spent_outputs.emplace_back(value, scriptpubkey);
        }
    } else {
        // Single-input transaction: use single prevout parameters (backwards compatible)
        if (tx.vin.size() != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Multi-input transactions require prevout_values and prevout_scriptpubkeys arrays (params 12 and 13)");
        }

        CAmount prevout_value = AmountFromValue(request.params[6]);
        std::vector<uint8_t> scriptpubkey_bytes = ParseHex(request.params[7].get_str());
        CScript prevout_scriptpubkey(scriptpubkey_bytes.begin(), scriptpubkey_bytes.end());
        spent_outputs.emplace_back(prevout_value, prevout_scriptpubkey);
    }

    // Parse internal pubkey
    std::vector<uint8_t> internal_pubkey_bytes = ParseHex(request.params[8].get_str());
    if (internal_pubkey_bytes.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "internal_pubkey must be 32 bytes");
    }

    // Parse merkle root
    std::vector<uint8_t> merkle_root_bytes = ParseHex(request.params[9].get_str());
    if (merkle_root_bytes.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "merkle_root must be 32 bytes");
    }

    // Parse parity
    bool parity = request.params[10].get_bool();

    // Parse sighash type
    int nHashType = SIGHASH_ALL;
    if (!request.params[11].isNull()) {
        std::string sighash_str = request.params[11].get_str();
        nHashType = ParseSighashString(sighash_str);
    }

    // Build PrecomputedTransactionData with ALL spent outputs
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), /* force=*/ true);

    // Set up ScriptExecutionData with tapleaf hash
    ScriptExecutionData execdata;
    execdata.m_tapleaf_hash = ComputeTapleafHash(0xc0, tapscript);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;  // No OP_CODESEPARATOR executed
    execdata.m_codeseparator_pos_init = true;
    execdata.m_witness_version = 2;  // Witness v2 output
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;  // No annex

    // Compute ML-DSA sighash using consensus function
    uint256 mldsa_sighash;
    if (!SignatureHashMLDSA(mldsa_sighash, execdata, tx, input_index, nHashType, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute ML-DSA sighash");
    }

    // Sign with ML-DSA
    std::vector<uint8_t> signature;
    if (!mldsa_key.Sign(mldsa_sighash, signature)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign with ML-DSA");
    }

    // Append sighash flag to signature
    signature.push_back(static_cast<uint8_t>(nHashType));

    // Build witness stack: [signature, script, control_block]
    // Control block format: (leaf_version | parity) || internal_pubkey || merkle_branch
    // For a single-leaf tree, merkle_branch is empty
    std::vector<uint8_t> control_block;
    uint8_t leaf_version_with_parity = 0xc0 | (parity ? 1 : 0);  // TAPROOT_LEAF_TAPSCRIPT with parity
    control_block.push_back(leaf_version_with_parity);
    control_block.insert(control_block.end(), internal_pubkey_bytes.begin(), internal_pubkey_bytes.end());

    // Set witness stack: [signature, script, control_block]
    // Note: pubkey is NOT in witness because it's embedded in the tapscript itself
    tx.vin[input_index].scriptWitness.stack.clear();
    tx.vin[input_index].scriptWitness.stack.push_back(signature);
    tx.vin[input_index].scriptWitness.stack.push_back(tapscript_bytes);
    tx.vin[input_index].scriptWitness.stack.push_back(control_block);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(tx)));
    result.pushKV("complete", true);  // Single input signing always completes that input

    return result;
},
    };
}

RPCHelpMan signmldsatransactionwithwallet()
{
    return RPCHelpMan{"signmldsatransactionwithwallet",
                "\nSign ML-DSA transaction inputs using keys from wallet.\n"
                "This RPC automatically looks up ML-DSA signing data in the wallet for all ML-DSA (witness v2) inputs.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw transaction hex string"},
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Previous transaction outputs being spent",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "scriptPubKey of output"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Output value in BTC"},
                                },
                            },
                        }
                    },
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"ALL"}, "The sighash type (ALL, NONE, SINGLE, etc.)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The signed transaction hex"},
                        {RPCResult::Type::BOOL, "complete", "Whether the transaction is fully signed"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Signing errors",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::NUM, "input_index", "Input index that failed"},
                                    {RPCResult::Type::STR, "error", "Error message"},
                                }},
                            }
                        },
                    }
                },
                RPCExamples{
                    HelpExampleCli("signmldsatransactionwithwallet", "\"<hex>\" '[{\"txid\":\"...\",\"vout\":0,\"scriptPubKey\":\"...\",\"amount\":0.01}]'")
                    + HelpExampleRpc("signmldsatransactionwithwallet", "\"<hex>\", [{\"txid\":\"...\",\"vout\":0,\"scriptPubKey\":\"...\",\"amount\":0.01}]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
#ifndef ENABLE_MLDSA
    throw JSONRPCError(RPC_INTERNAL_ERROR, "ML-DSA support not enabled (liboqs not available)");
#endif

    std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found");

    LOCK(wallet->cs_wallet);

    // Parse transaction
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Parse prevtxs array
    const UniValue& prevTxs = request.params[1].get_array();
    std::map<COutPoint, std::pair<CScript, CAmount>> prevouts;

    for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
        const UniValue& p = prevTxs[idx];
        if (!p.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "prevtxs entry must be an object");
        }

        uint256 txid_hash = ParseHashO(p, "txid");
        int nOut = p["vout"].getInt<int>();
        if (nOut < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "vout cannot be negative");
        }

        COutPoint out(Txid::FromUint256(txid_hash), nOut);
        std::vector<unsigned char> pkData(ParseHexO(p, "scriptPubKey"));
        CScript scriptPubKey(pkData.begin(), pkData.end());
        CAmount amount = AmountFromValue(p["amount"]);

        prevouts[out] = {scriptPubKey, amount};
    }

    // Parse sighash type
    int nHashType = ParseSighashString(request.params[2]);

    // Build arrays for prevout values and scriptPubKeys (for multi-input signing)
    std::vector<CAmount> prevout_values;
    std::vector<CScript> prevout_scripts;
    prevout_values.reserve(mtx.vin.size());
    prevout_scripts.reserve(mtx.vin.size());

    for (const auto& inp : mtx.vin) {
        auto it = prevouts.find(inp.prevout);
        if (it == prevouts.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Missing prevout data for input %s:%d", inp.prevout.hash.ToString(), inp.prevout.n));
        }
        prevout_scripts.push_back(it->second.first);
        prevout_values.push_back(it->second.second);
    }

    // Sign each ML-DSA input
    WalletBatch batch(wallet->GetDatabase());
    UniValue errors(UniValue::VARR);
    bool complete = true;

    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        const CScript& scriptPubKey = prevout_scripts[i];

        // Check if this is a witness v2 (ML-DSA) output
        CTxDestination dest;
        if (!ExtractDestination(scriptPubKey, dest) || !std::holds_alternative<WitnessV2Taproot>(dest)) {
            // Not an ML-DSA input, skip
            complete = false;  // Can't sign non-ML-DSA inputs here
            continue;
        }

        const WitnessV2Taproot& taproot_dest = std::get<WitnessV2Taproot>(dest);
        XOnlyPubKey output_pubkey = static_cast<XOnlyPubKey>(taproot_dest);

        // Look up ML-DSA key data in wallet
        uint256 pk_hash;
        if (!batch.ReadMLDSAOutputIndex(output_pubkey, pk_hash)) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "ML-DSA key not found in wallet for this output");
            errors.push_back(err);
            complete = false;
            continue;
        }

        // Read taproot metadata
        MLDSATaprootMetadata tap_metadata;
        if (!batch.ReadMLDSATaprootData(output_pubkey, tap_metadata)) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "ML-DSA Taproot metadata not found");
            errors.push_back(err);
            complete = false;
            continue;
        }

        // Read ML-DSA key (handle both encrypted and unencrypted)
        std::vector<uint8_t> pubkey, seckey;
        uint8_t level_byte;
        CKeyMetadata keyMeta;

        // Try encrypted key first
        if (wallet->IsCrypted()) {
            if (!wallet->IsLocked()) {
                // Wallet is encrypted but unlocked - we need to decrypt the key
                // This requires accessing the master key through wallet's encryption infrastructure
                UniValue err(UniValue::VOBJ);
                err.pushKV("input_index", (int)i);
                err.pushKV("error", "ML-DSA encrypted key signing not yet fully implemented - use RPC directly");
                errors.push_back(err);
                complete = false;
                continue;
            } else {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked. Unlock it to sign ML-DSA transactions.");
            }
        }

        // Read unencrypted key from database
        std::pair<std::vector<unsigned char>, uint256> key_data;

        if (!batch.ReadFromBatch(std::make_pair(DBKeys::MLDSA_KEY, pk_hash), key_data)) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "Failed to read ML-DSA key from wallet");
            errors.push_back(err);
            complete = false;
            continue;
        }

        std::vector<unsigned char>& vchData = key_data.first;
        uint256& checksum = key_data.second;

        // Verify checksum
        if (Hash(vchData) != checksum) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "ML-DSA key checksum mismatch");
            errors.push_back(err);
            complete = false;
            continue;
        }

        // Parse vchData: level || pk_len || pubkey || sk_len || seckey
        if (vchData.size() < 9) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "ML-DSA key data too short");
            errors.push_back(err);
            complete = false;
            continue;
        }

        size_t pos = 0;
        level_byte = vchData[pos++];

        // Read public key
        uint32_t pk_len = static_cast<uint32_t>(vchData[pos]) |
                         (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                         (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                         (static_cast<uint32_t>(vchData[pos + 3]) << 24);
        pos += 4;

        if (pos + pk_len + 4 > vchData.size()) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "Invalid public key length");
            errors.push_back(err);
            complete = false;
            continue;
        }

        pubkey = std::vector<uint8_t>(vchData.begin() + pos, vchData.begin() + pos + pk_len);
        pos += pk_len;

        // Read secret key
        uint32_t sk_len = static_cast<uint32_t>(vchData[pos]) |
                         (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                         (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                         (static_cast<uint32_t>(vchData[pos + 3]) << 24);
        pos += 4;

        if (pos + sk_len != vchData.size()) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "Invalid secret key length");
            errors.push_back(err);
            complete = false;
            continue;
        }

        seckey = std::vector<uint8_t>(vchData.begin() + pos, vchData.begin() + pos + sk_len);

        // Load the key
        mldsa::ParamSet level;
        switch (level_byte) {
            case 44: level = mldsa::ParamSet::MLDSA_44; break;
            case 65: level = mldsa::ParamSet::MLDSA_65; break;
            case 87: level = mldsa::ParamSet::MLDSA_87; break;
            default:
                UniValue err(UniValue::VOBJ);
                err.pushKV("input_index", (int)i);
                err.pushKV("error", strprintf("Invalid ML-DSA level: %d", level_byte));
                errors.push_back(err);
                complete = false;
                continue;
        }

        CMLDSAKey mldsa_key;
        if (!mldsa_key.SetSecretKey(seckey, level)) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "Failed to load ML-DSA secret key");
            errors.push_back(err);
            complete = false;
            continue;
        }

        // Sign this input
        PrecomputedTransactionData txdata;
        txdata.Init(mtx, std::vector<CTxOut>{}, /*force=*/true);

        // Build spent_outputs for sighash computation
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(mtx.vin.size());
        for (size_t j = 0; j < mtx.vin.size(); ++j) {
            spent_outputs.emplace_back(prevout_values[j], prevout_scripts[j]);
        }
        txdata.Init(mtx, std::move(spent_outputs), /*force=*/true);

        ScriptExecutionData execdata;
        execdata.m_tapleaf_hash = tap_metadata.leaf_hash;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_witness_version = 2;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;

        uint256 mldsa_sighash;
        if (!SignatureHashMLDSA(mldsa_sighash, execdata, mtx, i, nHashType, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "Failed to compute ML-DSA sighash");
            errors.push_back(err);
            complete = false;
            continue;
        }

        std::vector<uint8_t> signature;
        if (!mldsa_key.Sign(mldsa_sighash, signature)) {
            UniValue err(UniValue::VOBJ);
            err.pushKV("input_index", (int)i);
            err.pushKV("error", "Failed to sign with ML-DSA");
            errors.push_back(err);
            complete = false;
            continue;
        }

        signature.push_back(static_cast<uint8_t>(nHashType));

        // Build control block
        std::vector<uint8_t> control_block;
        uint8_t leaf_version_with_parity = 0xc0 | (tap_metadata.parity ? 1 : 0);
        control_block.push_back(leaf_version_with_parity);
        std::vector<uint8_t> internal_key_bytes(tap_metadata.internal_key.begin(), tap_metadata.internal_key.end());
        control_block.insert(control_block.end(), internal_key_bytes.begin(), internal_key_bytes.end());

        // Set witness
        std::vector<uint8_t> tapscript_bytes(tap_metadata.tapscript.begin(), tap_metadata.tapscript.end());
        mtx.vin[i].scriptWitness.stack.clear();
        mtx.vin[i].scriptWitness.stack.push_back(signature);
        mtx.vin[i].scriptWitness.stack.push_back(tapscript_bytes);
        mtx.vin[i].scriptWitness.stack.push_back(control_block);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", complete);
    if (!errors.empty()) {
        result.pushKV("errors", errors);
    }

    return result;
},
    };
}

} // namespace wallet
