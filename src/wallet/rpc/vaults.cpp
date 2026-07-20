// Copyright (c) 2024-present TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/vaultregistry.h>
#include <key_io.h>
#include <script/descriptor.h>

namespace wallet {

RPCHelpMan vaultinfo()
{
    return RPCHelpMan{"vaultinfo",
                "\nReturns detailed information about a registered vault.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The taproot address of the vault"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "registered", "Whether the vault is registered"},
                        {RPCResult::Type::STR, "address", "The vault address"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The vault scriptPubKey"},
                        {RPCResult::Type::STR_HEX, "output_key", "The taproot output key (32-byte x-only pubkey)"},
                        {RPCResult::Type::STR_HEX, "internal_key", "The taproot internal key"},
                        {RPCResult::Type::STR_HEX, "merkle_root", "The tapscript merkle root"},
                        {RPCResult::Type::STR_HEX, "contract_id", "The contract or offer ID"},
                        {RPCResult::Type::STR, "role", "The vault role (REPO_BORROWER, REPO_LENDER, etc.)"},
                        {RPCResult::Type::NUM, "version", "Vault metadata version"},
                        {RPCResult::Type::ARR, "leaves", "Array of tapscript leaves",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "script", "The leaf script"},
                                {RPCResult::Type::NUM, "leaf_version", "The leaf version (usually 0xc0 for tapscript)"},
                                {RPCResult::Type::STR_HEX, "signing_key", "The x-only pubkey that signs this leaf; all-zero means none (covenant-only)"},
                                {RPCResult::Type::BOOL, "covenant_only", "True if the leaf is signatureless / keeper-spendable (no signing key)"},
                                {RPCResult::Type::STR, "purpose", "Human-readable purpose (repay, default, timeout, difficulty-settle, etc.)"},
                                {RPCResult::Type::NUM, "timelock", /*optional=*/true, "CLTV/CSV timelock value if applicable"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("vaultinfo", "\"bcrt1p...\"")
            + HelpExampleRpc("vaultinfo", "\"bcrt1p...\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    // Parse address
    const std::string address_str = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(address_str);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    CScript script_pubkey = GetScriptForDestination(dest);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", address_str);
    result.pushKV("scriptPubKey", HexStr(script_pubkey));

    // Check all SPKMs for vault registration
    std::optional<VaultMetadata> vault_meta;
    for (ScriptPubKeyMan* spkm : pwallet->GetAllScriptPubKeyMans()) {
        if (auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)) {
            vault_meta = desc_spkm->GetVaultMetadata(script_pubkey);
            if (vault_meta) break;
        }
    }

    if (!vault_meta) {
        result.pushKV("registered", false);
        return result;
    }

    result.pushKV("registered", true);

    // Output key
    XOnlyPubKey output_key = vault_meta->GetOutputKey();
    result.pushKV("output_key", HexStr(output_key));

    // Taproot spend data
    result.pushKV("internal_key", HexStr(vault_meta->spenddata.internal_key));
    result.pushKV("merkle_root", HexStr(vault_meta->spenddata.merkle_root));

    // Contract info
    result.pushKV("contract_id", vault_meta->contract_id.ToString());
    result.pushKV("role", VaultRoleToString(vault_meta->role));
    result.pushKV("version", (int)vault_meta->version);

    // Leaves
    UniValue leaves(UniValue::VARR);
    for (const auto& leaf : vault_meta->leaves) {
        UniValue leaf_obj(UniValue::VOBJ);
        leaf_obj.pushKV("script", HexStr(leaf.script));
        leaf_obj.pushKV("leaf_version", (int)leaf.leaf_version);
        leaf_obj.pushKV("signing_key", HexStr(leaf.signing_key));
        leaf_obj.pushKV("covenant_only", leaf.IsCovenantOnly());
        leaf_obj.pushKV("purpose", leaf.purpose);
        if (leaf.timelock.has_value()) {
            leaf_obj.pushKV("timelock", (int)*leaf.timelock);
        }
        leaves.push_back(leaf_obj);
    }
    result.pushKV("leaves", leaves);

    return result;
},
    };
}

RPCHelpMan vaultsigndryrun()
{
    return RPCHelpMan{"vaultsigndryrun",
                "\nDry-run vault signing without actually signing the PSBT.\n"
                "This is useful for debugging vault signing issues.\n",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The base64-encoded PSBT"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "num_inputs", "Total number of inputs in the PSBT"},
                        {RPCResult::Type::NUM, "num_vault_inputs", "Number of inputs that are vault scripts"},
                        {RPCResult::Type::ARR, "vault_inputs", "Details of vault inputs",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "index", "Input index"},
                                {RPCResult::Type::STR_HEX, "scriptPubKey", "The scriptPubKey being spent"},
                                {RPCResult::Type::BOOL, "is_registered", "Whether this vault is registered"},
                                {RPCResult::Type::BOOL, "can_sign", "Whether wallet can provide signing data"},
                                {RPCResult::Type::STR_HEX, "output_key", /*optional=*/true, "Vault output key if registered"},
                                {RPCResult::Type::STR, "contract_id", /*optional=*/true, "Contract ID if registered"},
                                {RPCResult::Type::STR, "role", /*optional=*/true, "Vault role if registered"},
                                {RPCResult::Type::NUM, "num_leaves", /*optional=*/true, "Number of tapscript leaves"},
                                {RPCResult::Type::BOOL, "has_spenddata", /*optional=*/true, "Whether tr_spenddata is available"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("vaultsigndryrun", "\"cHNidP8BAH...\"")
            + HelpExampleRpc("vaultsigndryrun", "\"cHNidP8BAH...\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    // Decode PSBT
    std::string psbt_str = request.params[0].get_str();
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, psbt_str, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("PSBT decode failed: %s", error));
    }

    const CMutableTransaction& tx = *psbtx.tx;

    UniValue result(UniValue::VOBJ);
    result.pushKV("num_inputs", (int)tx.vin.size());

    UniValue vault_inputs(UniValue::VARR);
    int num_vault_inputs = 0;

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CTxIn& txin = tx.vin[i];
        const PSBTInput& input = psbtx.inputs[i];

        // Get the scriptPubKey
        CScript script_pubkey;
        if (!input.witness_utxo.IsNull()) {
            script_pubkey = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (txin.prevout.n < input.non_witness_utxo->vout.size()) {
                script_pubkey = input.non_witness_utxo->vout[txin.prevout.n].scriptPubKey;
            }
        }

        if (script_pubkey.empty()) continue;

        // Check if this is a vault
        std::optional<VaultMetadata> vault_meta;
        for (ScriptPubKeyMan* spkm : pwallet->GetAllScriptPubKeyMans()) {
            if (auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)) {
                vault_meta = desc_spkm->GetVaultMetadata(script_pubkey);
                if (vault_meta) {
                    break;
                }
            }
        }

        if (!vault_meta) continue;  // Not a vault input

        num_vault_inputs++;

        UniValue input_obj(UniValue::VOBJ);
        input_obj.pushKV("index", (int)i);
        input_obj.pushKV("scriptPubKey", HexStr(script_pubkey));
        input_obj.pushKV("is_registered", true);

        // Check if we can sign
        auto provider = pwallet->GetSolvingProvider(script_pubkey);
        bool can_sign = (provider != nullptr);
        input_obj.pushKV("can_sign", can_sign);

        // Vault details
        XOnlyPubKey output_key = vault_meta->GetOutputKey();
        input_obj.pushKV("output_key", HexStr(output_key));
        input_obj.pushKV("contract_id", vault_meta->contract_id.ToString());
        input_obj.pushKV("role", VaultRoleToString(vault_meta->role));
        input_obj.pushKV("num_leaves", (int)vault_meta->leaves.size());

        // Check if spenddata is available in the vault metadata
        bool has_spenddata = !vault_meta->spenddata.scripts.empty();
        input_obj.pushKV("has_spenddata", has_spenddata);

        vault_inputs.push_back(input_obj);
    }

    result.pushKV("num_vault_inputs", num_vault_inputs);
    result.pushKV("vault_inputs", vault_inputs);

    return result;
},
    };
}

RPCHelpMan vaultlist()
{
    return RPCHelpMan{"vaultlist",
                "\nLists all registered vaults, optionally filtered by contract ID.\n",
                {
                    {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional contract ID to filter by"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "address", "The vault address"},
                            {RPCResult::Type::STR_HEX, "scriptPubKey", "The vault scriptPubKey"},
                            {RPCResult::Type::STR_HEX, "output_key", "The taproot output key"},
                            {RPCResult::Type::STR_HEX, "contract_id", "The contract or offer ID"},
                            {RPCResult::Type::STR, "role", "The vault role"},
                            {RPCResult::Type::NUM, "num_leaves", "Number of tapscript leaves"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("vaultlist", "")
            + HelpExampleCli("vaultlist", "\"abc123...\"")
            + HelpExampleRpc("vaultlist", "")
            + HelpExampleRpc("vaultlist", "\"abc123...\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    // Parse optional contract_id filter
    std::optional<uint256> filter_contract_id;
    if (!request.params[0].isNull()) {
        filter_contract_id = ParseHashV(request.params[0], "contract_id");
    }

    UniValue result(UniValue::VARR);

    // Iterate through all SPKMs to find vaults
    for (ScriptPubKeyMan* spkm : pwallet->GetAllScriptPubKeyMans()) {
        auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        if (!desc_spkm) continue;

        // Get all scripts from this SPKM
        auto scripts = desc_spkm->GetScriptPubKeys();
        for (const CScript& script : scripts) {
            auto vault_meta = desc_spkm->GetVaultMetadata(script);
            if (!vault_meta) continue;

            // Apply contract_id filter if specified
            if (filter_contract_id && vault_meta->contract_id != *filter_contract_id) {
                continue;
            }

            UniValue vault_obj(UniValue::VOBJ);

            // Get address
            CTxDestination dest;
            if (ExtractDestination(script, dest)) {
                vault_obj.pushKV("address", EncodeDestination(dest));
            }

            vault_obj.pushKV("scriptPubKey", HexStr(script));

            XOnlyPubKey output_key = vault_meta->GetOutputKey();
            vault_obj.pushKV("output_key", HexStr(output_key));
            vault_obj.pushKV("contract_id", vault_meta->contract_id.ToString());
            vault_obj.pushKV("role", VaultRoleToString(vault_meta->role));
            vault_obj.pushKV("num_leaves", (int)vault_meta->leaves.size());

            result.push_back(vault_obj);
        }
    }

    return result;
},
    };
}

} // namespace wallet
